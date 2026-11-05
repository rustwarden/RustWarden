//! Time bucketing for the traffic history. Pure, so it is tested without a database.
//!
//! The recovered `traffic_stats.proto` has three resolutions: 1 s, 30 s and 600 s.
//! Every second's traffic is written to all three; a [`TimeRange`] reads the coarsest
//! one that still gives enough points for the graph.

use crate::data::{TimeRange, TrafficSample};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scale {
    S1,
    S30,
    S600,
}

impl Scale {
    pub const ALL: [Scale; 3] = [Scale::S1, Scale::S30, Scale::S600];

    pub fn secs(self) -> i64 {
        match self {
            Scale::S1 => 1,
            Scale::S30 => 30,
            Scale::S600 => 600,
        }
    }

    /// How long rows of this resolution are kept. Fine data is short-lived; only the
    /// coarsest scale follows the user's retention setting.
    pub fn retention_secs(self, retention_days: u32) -> i64 {
        let user = i64::from(retention_days) * 86_400;
        match self {
            Scale::S1 => 3600.min(user),
            Scale::S30 => (3 * 86_400).min(user),
            Scale::S600 => user,
        }
    }
}

pub fn scale_for(range: TimeRange) -> Scale {
    match range {
        TimeRange::OneMinute | TimeRange::FiveMinutes | TimeRange::TenMinutes | TimeRange::FifteenMinutes | TimeRange::ThirtyMinutes => Scale::S1,
        TimeRange::OneHour | TimeRange::ThreeHours => Scale::S30,
        TimeRange::Day => Scale::S600,
    }
}

pub fn align(ts: i64, scale: Scale) -> i64 {
    ts - ts.rem_euclid(scale.secs())
}

/// The buckets a range covers: (scale, timestamp of the first bucket, bucket count).
/// The last bucket is the one containing `now`.
pub fn range_buckets(now: i64, range: TimeRange) -> (Scale, i64, usize) {
    let scale = scale_for(range);
    let n = (range.minutes() as i64 * 60 / scale.secs()) as usize;
    (scale, align(now, scale) - (n as i64 - 1) * scale.secs(), n)
}

/// Bucket indexes (inclusive) the UI draws for a selection `window` of fractions.
/// Mirrors the slicing in `ui::traffic` so totals match what the graph shows.
pub fn selected_indices(n: usize, window: (f32, f32)) -> (usize, usize) {
    let last = n.saturating_sub(1);
    // Zero or one bucket: the only index there is.
    if last == 0 {
        return (0, 0);
    }
    let i0 = ((window.0 * last as f32).floor() as usize).min(last - 1);
    let i1 = ((window.1 * last as f32).ceil() as usize).clamp(i0 + 1, last);
    (i0, i1)
}

/// Timestamp interval `[t0, t1)` for the selected buckets.
pub fn selection_interval(first: i64, n: usize, scale: Scale, window: (f32, f32)) -> (i64, i64) {
    let (i0, i1) = selected_indices(n, window);
    (first + i0 as i64 * scale.secs(), first + (i1 as i64 + 1) * scale.secs())
}

/// Turns sparse `(bucket ts, down bytes, up bytes)` rows into `n` rate samples
/// (bytes per second), zero where nothing was recorded.
pub fn fill(rows: &[(i64, f64, f64)], first: i64, n: usize, scale: Scale) -> Vec<TrafficSample> {
    let mut out = vec![TrafficSample::default(); n];
    let secs = scale.secs() as f64;
    for &(ts, down, up) in rows {
        let idx = (ts - first).div_euclid(scale.secs());
        if (0..n as i64).contains(&idx) {
            let s = &mut out[idx as usize];
            s.down += (down / secs) as f32;
            s.up += (up / secs) as f32;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_map_to_scales() {
        assert_eq!(scale_for(TimeRange::FiveMinutes), Scale::S1);
        assert_eq!(scale_for(TimeRange::ThreeHours), Scale::S30);
        assert_eq!(scale_for(TimeRange::Day), Scale::S600);
    }

    #[test]
    fn range_ends_in_the_current_bucket() {
        let now = 1_000_000_007;
        let (scale, first, n) = range_buckets(now, TimeRange::OneHour);
        assert_eq!((scale, n), (Scale::S30, 120));
        assert_eq!(first + (n as i64 - 1) * 30, align(now, Scale::S30));
        assert_eq!(first % 30, 0);
    }

    #[test]
    fn selection_matches_ui_slice() {
        assert_eq!(selected_indices(180, (0.0, 0.15)), (0, 27));
        let (i0, i1) = selected_indices(180, (0.5, 0.5));
        assert!(i1 > i0);
        assert_eq!(selected_indices(2, (0.0, 1.0)), (0, 1));
        assert_eq!(selected_indices(1, (0.0, 1.0)), (0, 0));
        assert_eq!(selected_indices(0, (0.0, 1.0)), (0, 0));
        let (t0, t1) = selection_interval(1000, 120, Scale::S30, (0.0, 1.0));
        assert_eq!((t0, t1), (1000, 1000 + 120 * 30));
    }

    #[test]
    fn fill_pads_and_converts_to_rates() {
        let s = fill(&[(30, 300.0, 60.0), (90, 30.0, 0.0), (9999, 1.0, 1.0)], 0, 4, Scale::S30);
        assert_eq!(s.len(), 4);
        assert_eq!((s[1].down, s[1].up), (10.0, 2.0));
        assert_eq!(s[3].down, 1.0);
        assert_eq!(s[0].down, 0.0);
    }

    #[test]
    fn retention_per_scale() {
        assert_eq!(Scale::S1.retention_secs(30), 3600);
        assert_eq!(Scale::S30.retention_secs(30), 3 * 86_400);
        assert_eq!(Scale::S600.retention_secs(30), 30 * 86_400);
        assert_eq!(Scale::S30.retention_secs(1), 86_400);
    }
}
