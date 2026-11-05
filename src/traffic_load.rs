//! Reads the Traffic tab's data on a worker thread, so the window never waits on the database.
//! One load runs at a time; requests that arrive meanwhile merge into one pending query.

use crate::data::*;
use std::sync::{Arc, Mutex};

/// What to read. `history`/`figures` say which parts; the rest is the state they depend on.
#[derive(Clone)]
pub struct Query {
    pub range: TimeRange,
    pub window: (f32, f32),
    pub filter: TrafficFilter,
    /// Push `filter` to the backend first (it changed, or it names a network whose lookups may have finished since).
    pub apply_filter: bool,
    /// The highlighted span as (start, end) minutes of day.
    pub sel: Option<(f32, f32)>,
    /// Start minute and length of the history on screen, for turning `sel` into fractions when no new history is read.
    pub basis: (f32, f32),
    /// The history graph and the map.
    pub history: bool,
    /// Totals and the lists for `window`.
    pub figures: bool,
    /// Refresh the filter panel's app list even while an app is picked (scope or direction changed).
    pub app_list: bool,
}

impl Query {
    /// The later query wins on values; the parts to read add up.
    fn merge(self, newer: Query) -> Query {
        Query {
            apply_filter: self.apply_filter || newer.apply_filter,
            history: self.history || newer.history,
            figures: self.figures || newer.figures,
            app_list: self.app_list || newer.app_list,
            ..newer
        }
    }
}

#[derive(Default)]
pub struct Load {
    pub range: Option<TimeRange>,
    /// Unix seconds the history was read at; the live graph scrolls from its last bucket.
    pub loaded_at: f64,
    pub history: Option<TrafficHistory>,
    pub map: Option<MapData>,
    pub totals: Option<Totals>,
    pub breakdown: Option<UsageBreakdown>,
    pub app_list: Option<Vec<UsageRow>>,
    pub sel_data: Option<UsageBreakdown>,
}

/// The highlighted span as fractions of the loaded history.
pub fn sel_fractions(sel: (f32, f32), start: f32, span: f32) -> Option<(f32, f32)> {
    if span <= 0.0 {
        return None;
    }
    let f = |m: f32| ((m - start) / span).clamp(0.0, 1.0);
    Some((f(sel.0), f(sel.1)))
}

pub fn run(b: &dyn Backend, q: &Query) -> Load {
    if q.apply_filter {
        b.set_traffic_filter(&q.filter);
    }
    let mut load = Load { range: Some(q.range), ..Load::default() };
    let mut basis = q.basis;
    if q.history {
        let h = b.traffic_history(q.range);
        basis = (h.start_minute, h.span_minutes());
        load.loaded_at = crate::clock::now_unix() as f64;
        load.history = Some(h);
        load.map = Some(b.map_data(q.range));
    }
    if q.figures {
        let breakdown = b.breakdown(q.range, q.window);
        load.totals = Some(b.totals(q.range, q.window));
        // The panel keeps listing every app while one is picked, so only an unpicked load replaces the list.
        if q.filter.app.is_none() {
            load.app_list = Some(breakdown.apps.clone());
        }
        load.breakdown = Some(breakdown);
    }
    if q.app_list && q.filter.app.is_some() {
        b.set_traffic_filter(&TrafficFilter { app: None, ..q.filter.clone() });
        load.app_list = Some(b.breakdown(q.range, q.window).apps);
        b.set_traffic_filter(&q.filter);
    }
    if let Some(w) = q.sel.and_then(|s| sel_fractions(s, basis.0, basis.1)) {
        load.sel_data = Some(b.breakdown(q.range, w));
    }
    load
}

type Slot = Arc<Mutex<Option<Result<Load, String>>>>;

pub struct Loader {
    ctx: egui::Context,
    slot: Slot,
    busy: bool,
    pending: Option<Query>,
    applied: Option<TrafficFilter>,
    /// True after a failed load, so the error is shown once rather than every second.
    pub failing: bool,
}

impl Loader {
    pub fn new(ctx: egui::Context) -> Self {
        Self { ctx, slot: Arc::default(), busy: false, pending: None, applied: None, failing: false }
    }

    /// Starts the load now, or keeps it until the running one lands.
    pub fn request(&mut self, backend: &Arc<dyn Backend>, mut q: Query) {
        let changed = self.applied.as_ref() != Some(&q.filter);
        q.apply_filter = changed || !q.filter.network.trim().is_empty();
        if changed {
            self.applied = Some(q.filter.clone());
        }
        if self.busy {
            self.pending = Some(match self.pending.take() {
                Some(old) => old.merge(q),
                None => q,
            });
        } else {
            self.spawn(backend, q);
        }
    }

    /// The finished load, if there is one; the pending query then starts.
    pub fn poll(&mut self, backend: &Arc<dyn Backend>) -> Option<Result<Load, String>> {
        let done = self.slot.lock().unwrap_or_else(|e| e.into_inner()).take()?;
        self.busy = false;
        if let Some(q) = self.pending.take() {
            self.spawn(backend, q);
        }
        Some(done)
    }

    fn spawn(&mut self, backend: &Arc<dyn Backend>, q: Query) {
        self.busy = true;
        let (backend, slot, ctx) = (backend.clone(), self.slot.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&*backend, &q))).map_err(|_| "the data worker stopped unexpectedly".to_owned());
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(done);
            ctx.request_repaint();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Query {
        Query { range: TimeRange::OneHour, window: (0.0, 0.15), filter: TrafficFilter::default(), apply_filter: false, sel: None, basis: (0.0, 60.0), history: false, figures: false, app_list: false }
    }

    #[test]
    fn merge_adds_parts_and_takes_the_newer_values() {
        let old = Query { history: true, window: (0.0, 0.5), ..query() };
        let merged = old.merge(Query { figures: true, window: (0.2, 0.4), ..query() });
        assert!(merged.history && merged.figures && !merged.app_list);
        assert_eq!(merged.window, (0.2, 0.4));
    }

    #[test]
    fn selection_fractions_follow_the_history_span() {
        assert_eq!(sel_fractions((15.0, 45.0), 0.0, 60.0), Some((0.25, 0.75)));
        assert_eq!(sel_fractions((-10.0, 90.0), 0.0, 60.0), Some((0.0, 1.0)));
        assert_eq!(sel_fractions((1.0, 2.0), 0.0, 0.0), None);
    }

    #[test]
    fn run_reads_only_what_was_asked() {
        let b = crate::demo::MockBackend::new();
        let only_sel = run(&b, &Query { sel: Some((10.0, 20.0)), ..query() });
        assert!(only_sel.history.is_none() && only_sel.breakdown.is_none() && only_sel.sel_data.is_some());
        let all = run(&b, &Query { history: true, figures: true, ..query() });
        assert!(all.history.is_some() && all.map.is_some() && all.totals.is_some() && all.app_list.is_some());
    }
}
