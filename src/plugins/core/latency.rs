//! Latency and packet-loss charts shared by the Broadband Quality (thinkbroadband) and Ping tabs:
//! the samples, the tab's layout (toolbar, day picker, charts, scrubber) and the drawing. Each tab
//! supplies its data and wording through a [`Feed`], so neither plugin depends on the other.

use crate::clock::{self, PeriodKind};
use crate::live::db::Db;
use crate::util::fmt_clock_secs;
use crate::{theme, widgets};
use egui::{Align2, Color32, Rect, Sense, Stroke, Ui, pos2, vec2};
use std::time::{Duration, Instant};

/// One poll result: latency in milliseconds, packet loss in percent.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample {
    pub ts: i64,
    pub min: f32,
    pub avg: f32,
    pub max: f32,
    pub loss: f32,
}

/// One chart: a thinkbroadband monitor or a pinged host.
#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    pub id: u32,
    pub name: String,
}

const BLUE: Color32 = Color32::from_rgb(0x22, 0x10, 0xff);
/// Charts per page in the grid layout (2 x 2).
const GRID: usize = 4;
const RANGES: [(i64, &str); 3] = [(3 * 3600, "3 Hours"), (24 * 3600, "24 Hours"), (7 * 86_400, "7 Days")];
const FOOTER_H: f32 = 124.0;
/// The least height of one chart before the area scrolls.
const MIN_CHART_H: f32 = 240.0;
const FLASH_SECS: f32 = 3.0;

/// What a tab plugs into the shared layout.
pub trait Feed {
    /// A download or ping round is running (the Refresh button shows it).
    fn refreshing(&self) -> bool;
    /// Asks for a round now.
    fn sync_now(&self);
    /// Unix time of the last round that worked; 0 if none yet.
    fn last_ok(&self) -> i64;
    /// Samples of one line from `since` on, oldest first.
    fn load(&self, db: &Db, id: u32, since: i64) -> rusqlite::Result<Vec<Sample>>;
    /// Made-up samples of one line from `since` to `until`, for Demo mode; `None` when the feed has no demo data.
    fn demo(&self, _id: u32, _since: i64, _until: i64) -> Option<Vec<Sample>> {
        None
    }
    /// Hover text of the Refresh button.
    fn refresh_hint(&self) -> &'static str;
    /// What the chart area says when there is nothing to draw.
    fn empty(&self, live: bool, no_lines: bool, day: bool) -> &'static str;
    /// Rounds are on hold until the user signs in.
    fn paused(&self) -> bool {
        false
    }
    /// Older data is being fetched for the day view; the charts fade out meanwhile.
    fn loading(&self) -> bool {
        false
    }
    /// Called with the lines that have nothing stored for the selected day.
    fn missing(&self, _ctx: &egui::Context, _ids: Vec<u32>, _view: (i64, i64)) {}
    /// Draws a full-width banner in `at`; returns its height, 0 for none.
    fn banner(&self, _ui: &mut Ui, _at: Rect) -> f32 {
        0.0
    }
}

pub struct State {
    /// Line ids shown; empty means all of them.
    selected: Vec<u32>,
    range: usize,
    /// 0 side by side, 1 stacked, 2 grid of `GRID` charts per page.
    layout: usize,
    page: usize,
    /// `layout` and `range` have been loaded from the settings.
    restored: bool,
    /// Visible slice of the range as fractions (start, end); the scrubber and the charts' Ctrl + scroll zoom change it.
    window: (f32, f32),
    data: Vec<(Line, Vec<Sample>)>,
    /// Kept open: opening the database runs its schema checks, too slow to repeat every 15 s on the UI thread.
    db: Option<Db>,
    loaded: Option<(Instant, Vec<u32>, usize, Option<i64>)>,
    was_refreshing: bool,
    /// Local midnight of the day being looked at; `None` follows the live range.
    day: Option<i64>,
    /// Month shown in the calendar popup (year, 1..=12).
    cal: (i64, u32),
    /// Chart an alert asked to show: its title, when it started flashing, and whether it still has to be paged to.
    flash: Option<(String, Instant, bool)>,
    /// The camera button was pressed: the next chart clicked is saved as a high-resolution picture.
    pick: bool,
    /// Outcome of the last export, for the app to announce.
    saved: Option<String>,
}

impl State {
    /// Bring the chart titled `name` into view and flash it for a few seconds.
    pub fn show(&mut self, name: String) {
        self.flash = Some((name, Instant::now(), true));
    }

    /// The message about a finished export, once.
    pub fn take_saved(&mut self) -> Option<String> {
        self.saved.take()
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            selected: Vec::new(),
            range: 1,
            layout: 0,
            page: 0,
            restored: false,
            window: (0.0, 1.0),
            data: Vec::new(),
            db: None,
            loaded: None,
            was_refreshing: false,
            day: None,
            cal: (1970, 1),
            flash: None,
            pick: false,
            saved: None,
        }
    }
}

/// The whole tab. `prefs` is the saved (layout, range); returns true when they changed and need saving.
/// `tools` adds the tab's own buttons at the left of the toolbar.
pub fn tab(ui: &mut Ui, st: &mut State, lines: &[Line], feed: &dyn Feed, live: bool, prefs: (&mut usize, &mut usize), tools: impl FnOnce(&mut Ui)) -> bool {
    let full = ui.max_rect();
    let (saved_layout, saved_range) = prefs;
    if !st.restored {
        (st.layout, st.range, st.restored) = ((*saved_layout).min(2), (*saved_range).min(2), true);
    }
    if let Some((name, _, pending @ true)) = &mut st.flash {
        // Show every chart, on the page that holds this one.
        *pending = false;
        if let Some(i) = lines.iter().position(|m| m.name == *name) {
            st.selected.clear();
            st.page = i / GRID;
        }
    }
    if st.flash.as_ref().is_some_and(|f| f.1.elapsed().as_secs_f32() > FLASH_SECS) {
        st.flash = None;
    }
    let mut shown: Vec<Line> = lines.iter().filter(|m| st.selected.contains(&m.id)).cloned().collect();
    if shown.is_empty() {
        shown = lines.to_vec();
    }
    let refreshing = feed.refreshing();
    // Charts are drawn from the database in Live mode, and from the feed's made-up samples in Demo mode if it has any.
    let active = live || feed.demo(0, 0, 0).is_some();

    let card = Rect::from_min_size(full.min + vec2(12.0, 12.0), vec2(full.width() - 24.0, 48.0));
    ui.painter().rect_filled(card, 8, theme::card());
    ui.painter().rect_stroke(card, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
    let toolbar = card.shrink2(vec2(12.0, 0.0));
    let mut picked: Option<Vec<u32>> = None;
    crate::ui::row_in(ui, toolbar, |ui| {
        tools(ui);
        if lines.len() < 2 {
            camera(ui, &mut st.pick);
            return;
        }
        let label = match shown.len() {
            n if n == lines.len() => "All graphs".to_owned(),
            1 => shown[0].name.clone(),
            n => format!("{n} graphs"),
        };
        let resp = widgets::pill_button(ui, None, &label, true, 140.0);
        widgets::dropdown(ui, None, &mut st.layout, &[0, 1, 2], |i| ["Side by side", "Stacked", "Grid"][i].into(), 130.0);
        camera(ui, &mut st.pick);
        let pages = if st.layout == 2 { shown.len().div_ceil(GRID) } else { 1 };
        st.page = st.page.min(pages - 1);
        if pages > 1 {
            if widgets::pill_button(ui, None, "<", false, 36.0).clicked() {
                st.page = (st.page + pages - 1) % pages;
            }
            ui.label(format!("{} / {pages}", st.page + 1));
            if widgets::pill_button(ui, None, ">", false, 36.0).clicked() {
                st.page = (st.page + 1) % pages;
            }
        }
        egui::Popup::menu(&resp).width(220.0).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
            for m in lines {
                let on = shown.iter().any(|s| s.id == m.id);
                if widgets::check_item(ui, on, &m.name).clicked() {
                    let mut cur: Vec<u32> = shown.iter().map(|s| s.id).collect();
                    if !on {
                        cur.push(m.id);
                    } else if cur.len() > 1 {
                        cur.retain(|id| *id != m.id);
                    }
                    picked = Some(cur);
                }
            }
        });
    });
    if let Some(cur) = picked {
        st.selected = if cur.len() == lines.len() { Vec::new() } else { cur };
        shown = lines.iter().filter(|m| st.selected.is_empty() || st.selected.contains(&m.id)).cloned().collect();
    }
    let now = clock::now_unix();
    let today = clock::period_start(now, PeriodKind::Day);
    let centre = Rect::from_center_size(pos2(full.center().x, toolbar.center().y), vec2(300.0, toolbar.height()));
    let mut moved = false;
    crate::ui::row_in(ui, centre, |ui| {
        if widgets::pill_button(ui, None, "<", false, 36.0).on_hover_text("Previous day").clicked() {
            st.day = Some(day_shift(st.day.unwrap_or(today), -1));
            moved = true;
        }
        let label = match st.day {
            Some(d) => clock::fmt_date(d),
            None if st.range == 2 => format!("{} – {}", clock::day_label(now - 6 * 86_400, now), clock::day_label(now, now)),
            None => "Today".to_owned(),
        };
        let resp = widgets::pill_button(ui, None, &label, true, 170.0).on_hover_text("Pick a day");
        if resp.clicked() {
            let (y, m, _) = clock::civil_from_days(clock::to_local(st.day.unwrap_or(today)).div_euclid(86_400));
            st.cal = (y, m);
        }
        let selected = clock::to_local(st.day.unwrap_or(today)).div_euclid(86_400);
        let today_days = clock::to_local(today).div_euclid(86_400);
        egui::Popup::menu(&resp).width(250.0).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
            if let Some(d) = calendar(ui, &mut st.cal, selected, today_days) {
                st.day = (d != today_days).then(|| day_shift(d * 86_400 - clock::local_offset_at(d * 86_400), 0));
                moved = true;
                ui.close();
            }
        });
        if ui.add_enabled(st.day.is_some(), egui::Button::new(">")).on_hover_text("Next day").clicked()
            && let Some(d) = st.day
        {
            let n = day_shift(d, 1);
            st.day = (n < today).then_some(n);
            moved = true;
        }
    });
    if moved {
        st.window = (0.0, 1.0);
    }
    let right = Rect::from_min_max(pos2(full.right() - 620.0, toolbar.top()), toolbar.right_bottom());
    crate::ui::row_in(ui, right, |ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            widgets::dropdown(ui, None, &mut st.range, &[0, 1, 2], |i| RANGES[i].1.into(), 110.0);
            if widgets::pill_button(ui, None, if refreshing { "Refreshing…" } else { "Refresh" }, false, 100.0).on_hover_text(feed.refresh_hint()).clicked() && !refreshing {
                feed.sync_now();
            }
            ui.add_space(8.0);
            ui.label(egui::RichText::new(refresh_status(refreshing, feed)).color(theme::text_dim()));
        });
    });
    let changed = (*saved_layout, *saved_range) != (st.layout, st.range);
    (*saved_layout, *saved_range) = (st.layout, st.range);
    if active {
        reload(st, &shown, feed);
    }

    let view = view_of(st.day, RANGES[st.range].0, now);
    // A day with nothing stored may be fetched by the feed; the charts fade in when it lands.
    if live && st.day.is_some() && st.loaded.is_some() {
        let missing: Vec<u32> = st.data.iter().filter(|(_, s)| !s.iter().any(|x| x.ts >= view.0 && x.ts < view.1)).map(|(m, _)| m.id).collect();
        if !missing.is_empty() {
            feed.missing(ui.ctx(), missing, view);
        }
    }
    let fade = ui.ctx().animate_bool_with_time(egui::Id::unique("tbb_fade"), !feed.loading(), 0.5);

    let p = ui.painter().clone();
    let mut top = card.bottom() + 12.0;
    let banner = feed.banner(ui, Rect::from_min_size(pos2(full.left() + 12.0, top), vec2(full.width() - 24.0, 44.0)));
    if banner > 0.0 {
        top += banner + 8.0;
    }

    // Legend, centred.
    let legend = [(theme::green(), "Minimum Latency (ms)"), (BLUE, "Average Latency (ms)"), (theme::yellow(), "Maximum Latency (ms)"), (theme::red(), "Dropped Packets (%)")];
    let widths: Vec<f32> = legend.iter().map(|(_, t)| p.layout_no_wrap((*t).into(), theme::font(14.0), theme::text()).size().x + 38.0).collect();
    let mut x = full.center().x - widths.iter().sum::<f32>() / 2.0;
    for ((c, t), w) in legend.iter().zip(&widths) {
        p.rect_filled(Rect::from_center_size(pos2(x + 8.0, top + 12.0), vec2(14.0, 14.0)), 3, *c);
        p.text(pos2(x + 22.0, top + 12.0), Align2::LEFT_CENTER, t, theme::font(14.0), theme::text());
        x += w;
    }

    let footer = Rect::from_min_max(pos2(full.left() + 12.0, full.bottom() - FOOTER_H), full.max - vec2(12.0, 12.0));
    let body = Rect::from_min_max(pos2(full.left() + 12.0, top + 32.0), pos2(full.right() - 12.0, footer.top() - 12.0));
    if !active || st.data.iter().all(|(_, s)| !s.iter().any(|x| x.ts >= view.0 && x.ts < view.1)) {
        p.text(body.center(), Align2::CENTER_CENTER, feed.empty(active, lines.is_empty(), st.day.is_some()), theme::font(16.0), theme::text_dim());
        return changed;
    }
    // Charts side by side, stacked, or in pages of a grid.
    let page: &[(Line, Vec<Sample>)] = if st.layout == 2 { st.data.chunks(GRID).nth(st.page).unwrap_or_default() } else { &st.data };
    let n = page.len();
    let gap = 10.0;
    let (cols, rows) = match st.layout {
        0 => (n, 1),
        1 => (1, n),
        _ => (n.min(2), n.div_ceil(2)),
    };
    let mut window = st.window;
    ui.set_opacity(fade);
    let pointer = ui.input(|i| i.pointer.hover_pos());
    if st.pick {
        ui.set_cursor_icon(egui::CursorIcon::Crosshair);
        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            st.pick = false;
        }
    }
    let mut grab = None;
    let (pick, flash, slice) = (st.pick, st.flash.clone(), st.window);
    let mut draw = |ui: &mut Ui, area: Rect| {
        let (w, h) = ((area.width() - gap * (cols - 1) as f32) / cols as f32, (area.height() - gap * (rows - 1) as f32) / rows as f32);
        for (i, (m, samples)) in page.iter().enumerate() {
            let at = pos2(area.left() + (i % cols) as f32 * (w + gap), area.top() + (i / cols) as f32 * (h + gap));
            let r = Rect::from_min_size(at, vec2(w, h));
            ui.painter().rect_filled(r, 8, theme::card());
            ui.painter().rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
            if let Some(nw) = graph(ui, r, &m.name, samples, view, slice, i) {
                window = nw;
            }
            if pick && pointer.is_some_and(|p| r.contains(p)) {
                ui.painter().rect_stroke(r, 0, Stroke::new(4.0, Color32::from_rgb(255, 170, 0)), egui::StrokeKind::Inside);
                if ui.input(|i| i.pointer.primary_pressed()) {
                    grab = Some(i);
                }
            }
            if let Some((_, t, _)) = flash.as_ref().filter(|f| f.0 == m.name) {
                let a = (0.5 + 0.5 * (t.elapsed().as_secs_f32() * 6.0).cos()) * 255.0;
                ui.painter().rect_stroke(r, 0, Stroke::new(4.0, Color32::from_rgba_unmultiplied(255, 170, 0, a as u8)), egui::StrokeKind::Inside);
                ui.ctx().request_repaint();
            }
        }
    };
    // In a small window the charts keep a readable height and the area scrolls instead of squashing them.
    let needed = rows as f32 * MIN_CHART_H + gap * (rows - 1) as f32 + 8.0;
    if needed > body.height() {
        ui.scope_builder(egui::UiBuilder::new().max_rect(body), |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                let (area, _) = ui.allocate_exact_size(vec2(ui.available_width(), needed), Sense::hover());
                draw(ui, area);
            });
        });
    } else {
        draw(ui, body);
    }
    if let Some(i) = grab {
        st.pick = false;
        let (m, samples) = &page[i];
        st.saved = export(&m.name, samples, view, st.window);
    }
    window = timeline(ui, footer, &st.data, view, window);
    ui.set_opacity(1.0);
    st.window = window;
    changed
}

/// The toolbar's camera button: toggles picking a chart to save as a picture.
fn camera(ui: &mut Ui, pick: &mut bool) {
    let tip = if *pick { "Click a graph to save it (Esc cancels)" } else { "Save a graph as a high-resolution picture" };
    if widgets::pill_button(ui, Some(crate::icons::Icon::Camera), "", false, 36.0).on_hover_text(tip).clicked() {
        *pick = !*pick;
    }
}

/// Asks where to save, then renders one chart at 3x on a 1400 x 600 pt canvas from the raw samples.
/// Returns the message to announce, `None` if the user cancelled.
fn export(title: &str, samples: &[Sample], view: (i64, i64), window: (f32, f32)) -> Option<String> {
    let name: String = title.chars().map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' }).collect();
    let path = crate::sys::save_dialog("Save graph", &format!("{name}-{}.png", clock::file_stamp()), "PNG image", "png")?;
    let size = vec2(1400.0, 600.0);
    let key_h = 64.0;
    let image = super::render::scene(size + vec2(0.0, key_h), 3.0, |ui| {
        let p = ui.painter().clone();
        p.rect_filled(Rect::from_min_size(egui::Pos2::ZERO, size + vec2(0.0, key_h)), 0, theme::surface_solid());
        graph(ui, Rect::from_min_size(egui::Pos2::ZERO, size), title, samples, view, window, 0);
        // Key for people who don't read latency graphs.
        let items = [
            (theme::yellow(), "Worst delay", "the slowest reply in that moment"),
            (BLUE, "Typical delay", "the average, what you'd usually feel"),
            (theme::green(), "Best delay", "the fastest reply (lower is better)"),
            (theme::red(), "Lost data", "red bars: data that never arrived"),
        ];
        let mut x = 14.0;
        for (color, name, what) in items {
            let y = size.y + key_h / 2.0;
            p.rect_filled(Rect::from_center_size(pos2(x + 7.0, y), vec2(14.0, 14.0)), 3, color);
            let r = p.text(pos2(x + 22.0, y - 9.0), Align2::LEFT_CENTER, name, theme::bold(14.0), theme::text());
            p.text(pos2(x + 22.0, y + 9.0), Align2::LEFT_CENTER, what, theme::font(13.0), theme::text_dim());
            x += 340.0f32.max(r.width() + 40.0);
        }
    });
    Some(match crate::snapshot::save(&image, path) {
        Ok(path) => format!("Graph saved: {}", path.display()),
        Err(e) => format!("Graph export failed: {e}"),
    })
}

/// Re-reads the shown lines' samples: when the selection, range or day changes, after a round ends, and every 15 s.
fn reload(st: &mut State, shown: &[Line], feed: &dyn Feed) {
    let ids: Vec<u32> = shown.iter().map(|m| m.id).collect();
    let refreshing = feed.refreshing() || feed.loading();
    let just_refreshed = st.was_refreshing && !refreshing;
    st.was_refreshing = refreshing;
    if !just_refreshed && st.loaded.as_ref().is_some_and(|(at, k, r, d)| *k == ids && *r == st.range && *d == st.day && at.elapsed() < Duration::from_secs(15)) {
        return;
    }
    let since = view_of(st.day, RANGES[st.range].0, clock::now_unix()).0;
    if st.db.is_none() {
        st.db = Db::open(&crate::live::db_path()).ok();
    }
    let (db, now) = (&st.db, clock::now_unix());
    st.data = shown
        .iter()
        .map(|m| {
            let samples = feed.demo(m.id, since, now).unwrap_or_else(|| db.as_ref().and_then(|db| feed.load(db, m.id, since).ok()).unwrap_or_default());
            (m.clone(), samples)
        })
        .collect();
    st.loaded = Some((Instant::now(), ids, st.range, st.day));
}

/// "Updated 12:41 am", plus "refreshing…" or "paused until you sign in" when that applies.
fn refresh_status(refreshing: bool, feed: &dyn Feed) -> String {
    let last = feed.last_ok();
    let updated = if last > 0 { format!("Updated {}", clock::fmt_time_lower(last)) } else { "Not updated yet".to_owned() };
    let then = if refreshing {
        "refreshing…"
    } else if feed.paused() {
        "paused until you sign in"
    } else {
        return updated;
    };
    format!("{updated} · {then}")
}

/// Folds samples into `n` columns across [t0, t1]: (min, avg, max, loss) per column, `None` where nothing arrived.
/// A round with every echo lost has no latency, so it only counts towards loss (latency 0 if that's all there is).
fn columns(data: &[Sample], t0: i64, t1: i64, n: usize) -> Vec<Option<[f32; 4]>> {
    let mut cols: Vec<Option<([f32; 4], u32)>> = vec![None; n];
    for s in data.iter().filter(|s| s.ts >= t0 && s.ts <= t1) {
        let i = (((s.ts - t0) as f64 / (t1 - t0) as f64) * (n - 1) as f64).round() as usize;
        let c = cols[i].get_or_insert(([f32::MAX, 0.0, 0.0, 0.0], 0));
        c.0[3] = c.0[3].max(s.loss);
        if s.loss < 100.0 {
            c.0 = [c.0[0].min(s.min), c.0[1] + s.avg, c.0[2].max(s.max), c.0[3]];
            c.1 += 1;
        }
    }
    cols.into_iter().map(|c| c.map(|(v, k)| if k == 0 { [0.0, 0.0, 0.0, v[3]] } else { [v[0], v[1] / k as f32, v[2], v[3]] })).collect()
}

/// Columns for [t0, t1] in `width` px: one per poll round (100 s) at most, so zooming in never leaves gaps.
fn column_count(t0: i64, t1: i64, width: f32) -> usize {
    let bucket = (((t1 - t0) as f32 / (width / 2.0).max(1.0)) as i64).max(100);
    ((t1 - t0) / bucket) as usize + 1
}

/// Tick positions (fraction of the span) and labels in local time, spaced to leave room for the labels.
fn time_ticks(t0: i64, t1: i64, width: f32) -> Vec<(f32, String)> {
    let span = t1 - t0;
    let tick = [60, 300, 900, 1800, 3600, 7200, 14_400, 21_600, 43_200, 86_400].into_iter().find(|t| (span / t) as f32 * 70.0 <= width).unwrap_or(86_400);
    let off = clock::local_offset_at(t0);
    let mut out = Vec::new();
    let mut t = ((t0 + off) / tick + 1) * tick - off;
    while t <= t1 {
        let local = clock::to_local(t);
        let label = if tick >= 86_400 {
            let (_, m, d) = clock::civil_from_days(local.div_euclid(86_400));
            format!("{d}/{m}")
        } else {
            fmt_clock_secs(local, false)
        };
        out.push(((t - t0) as f32 / span as f32, label));
        t += tick;
    }
    out
}

/// Top of the latency scale: the peak rounded up to a multiple of 20 ms.
fn y_top(peak: f32) -> f32 {
    ((peak / 20.0).ceil() * 20.0).max(20.0)
}

/// Local midnight `days` days from the one containing `from` (aims at mid-day so DST changes can't skip a day).
fn day_shift(from: i64, days: i64) -> i64 {
    clock::period_start(from + days * 86_400 + 43_200, PeriodKind::Day)
}

/// The shown window: the selected day, or the last `span` seconds up to `now`.
fn view_of(day: Option<i64>, span: i64, now: i64) -> (i64, i64) {
    day.map_or((now - span, now), |d| (d, day_shift(d, 1)))
}

/// A month grid; returns the picked day as a day count since 1970-01-01. Days after `today` are off.
fn calendar(ui: &mut Ui, cal: &mut (i64, u32), selected: i64, today: i64) -> Option<i64> {
    let mut picked = None;
    ui.horizontal(|ui| {
        if ui.button("<").clicked() {
            *cal = if cal.1 == 1 { (cal.0 - 1, 12) } else { (cal.0, cal.1 - 1) };
        }
        ui.label(clock::month_name(cal.0, cal.1));
        if ui.button(">").clicked() {
            *cal = if cal.1 == 12 { (cal.0 + 1, 1) } else { (cal.0, cal.1 + 1) };
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Today").clicked() {
                picked = Some(today);
            }
        });
    });
    let first = clock::days_from_civil(cal.0, cal.1, 1);
    let next = if cal.1 == 12 { clock::days_from_civil(cal.0 + 1, 1, 1) } else { clock::days_from_civil(cal.0, cal.1 + 1, 1) };
    egui::Grid::new("tbb_calendar").spacing(vec2(4.0, 4.0)).show(ui, |ui| {
        for d in ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"] {
            ui.label(egui::RichText::new(d).color(theme::text_dim()));
        }
        ui.end_row();
        let lead = (first + 3).rem_euclid(7); // 1970-01-01 was a Thursday
        for cell in 0..7 * (lead + next - first + 6).div_euclid(7) {
            let day = first + cell - lead;
            if (first..next).contains(&day) {
                let b = egui::Button::new((day - first + 1).to_string()).selected(day == selected).min_size(vec2(30.0, 26.0));
                if ui.add_enabled(day <= today, b).clicked() {
                    picked = Some(day);
                }
            } else {
                ui.label("");
            }
            if (cell + 1) % 7 == 0 {
                ui.end_row();
            }
        }
    });
    picked
}

/// The scrubber under the charts, like the Traffic tab's: an overview of the whole range with a
/// selected slice (drag it to slide, drag the knobs to resize). Returns the new slice.
fn timeline(ui: &mut Ui, footer: Rect, data: &[(Line, Vec<Sample>)], (t0, t1): (i64, i64), window: (f32, f32)) -> (f32, f32) {
    let p = ui.painter().clone();
    p.rect_filled(footer, 8, theme::card());
    p.rect_stroke(footer, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
    let band = Rect::from_min_max(pos2(footer.left() + 30.0, footer.top() + 14.0), pos2(footer.right() - 36.0, footer.top() + 48.0));
    let (wa, wb) = window;
    let (xa, xb) = (band.left() + wa * band.width(), band.left() + wb * band.width());
    p.rect_filled(band, 0, theme::teal_dark());
    p.rect_filled(Rect::from_min_max(pos2(xa, band.top()), pos2(xb, band.bottom())), 0, theme::teal_bg());

    // Worst latency of any chart per column, scaled to the highest of them.
    let n = column_count(t0, t1, band.width());
    let mut peak = vec![0.0_f32; n];
    let mut loss = vec![0.0_f32; n];
    for (_, s) in data {
        for ((p, l), c) in peak.iter_mut().zip(loss.iter_mut()).zip(columns(s, t0, t1, n)) {
            *p = p.max(c.map_or(0.0, |c| c[2]));
            *l = l.max(c.map_or(0.0, |c| c[3]));
        }
    }
    let top = peak.iter().copied().fold(1.0, f32::max);
    let mini: Vec<f32> = peak.iter().map(|v| (v / top).sqrt() * 0.9).collect();
    widgets::area(&p, band.shrink2(vec2(0.0, 2.0)), &mini, Color32::from_rgb(0xdf, 0xb4, 0x1f), None);
    for (i, l) in loss.iter().enumerate().filter(|(_, l)| **l > 0.0) {
        let x = band.left() + i as f32 / (n - 1) as f32 * band.width();
        p.rect_filled(Rect::from_min_max(pos2(x - 1.0, band.top()), pos2(x + 1.0, band.top() + (l / 100.0 * band.height()).max(4.0))), 0, theme::red());
    }
    p.rect_stroke(band, 0, Stroke::new(1.0, Color32::from_black_alpha(50)), egui::epaint::StrokeKind::Inside);
    for (f, label) in time_ticks(t0, t1, band.width() / 1.4) {
        p.text(pos2(band.left() + f * band.width(), band.bottom() + 16.0), Align2::CENTER_CENTER, label, theme::font(13.5), theme::text_dim());
    }

    let track_y = footer.top() + 92.0;
    p.rect_filled(Rect::from_min_max(pos2(band.left(), track_y - 2.0), pos2(band.right(), track_y + 2.0)), 2, theme::track());
    p.rect_filled(Rect::from_min_max(pos2(xa, track_y - 2.0), pos2(xb, track_y + 2.0)), 2, theme::accent().gamma_multiply(0.45));
    let mut new = window;
    let sel = ui.interact(Rect::from_min_max(pos2(xa, band.top()), pos2(xb, band.bottom())), ui.scope_id().with("tbb_slide"), Sense::drag()).on_hover_cursor(egui::CursorIcon::Grab);
    if sel.dragged() {
        let s = (sel.drag_delta().x / band.width()).clamp(-wa, 1.0 - wb);
        new = (wa + s, wb + s);
    }
    for (idx, hx) in [xa, xb].into_iter().enumerate() {
        let resp = ui.interact(Rect::from_center_size(pos2(hx, track_y), vec2(28.0, 28.0)), ui.scope_id().with(("tbb_handle", idx)), Sense::drag()).on_hover_cursor(egui::CursorIcon::PointingHand);
        if let (true, Some(pos)) = (resp.dragged(), resp.interact_pointer_pos()) {
            let f = ((pos.x - band.left()) / band.width()).clamp(0.0, 1.0);
            if idx == 0 {
                new.0 = f.min(new.1 - 0.02);
            } else {
                new.1 = f.max(new.0 + 0.02);
            }
        }
        p.circle_filled(pos2(hx, track_y + 1.0), 11.0, Color32::from_black_alpha(25));
        p.circle_filled(pos2(hx, track_y), 11.0, theme::WHITE);
        p.circle_stroke(pos2(hx, track_y), 11.0, Stroke::new(1.0, theme::border()));
    }
    new
}

/// One chart of the visible slice `window` of the range; returns the slice after a Ctrl + scroll zoom or right-drag pan.
fn graph(ui: &mut Ui, body: Rect, title: &str, data: &[Sample], view: (i64, i64), window: (f32, f32), idx: usize) -> Option<(f32, f32)> {
    let p = ui.painter().with_clip_rect(body);
    let axis_h = 40.0;
    let chart = Rect::from_min_max(body.min, pos2(body.right(), body.bottom() - axis_h));
    p.hline(body.x_range(), chart.bottom(), Stroke::new(1.0, theme::border()));
    p.text(chart.left_top() + vec2(14.0, 14.0), Align2::LEFT_CENTER, title, theme::bold(16.0), theme::text());
    let plot = Rect::from_min_max(pos2(chart.left() + 60.0, chart.top() + 34.0), pos2(chart.right() - 56.0, chart.bottom()));

    let full_span = view.1 - view.0;
    let (t0, t1) = (view.0 + (full_span as f32 * window.0) as i64, view.0 + (full_span as f32 * window.1) as i64);
    let span = t1 - t0;
    let cols = columns(data, t0, t1, column_count(t0, t1, plot.width()));
    let y_max = y_top(cols.iter().flatten().map(|c| c[2]).fold(0.0, f32::max));

    // Latency scale on the left, packet-loss scale on the right (0% at the top, as thinkbroadband draws it).
    for k in 0..=4 {
        let y = plot.bottom() - plot.height() * k as f32 / 4.0;
        p.hline(plot.x_range(), y, Stroke::new(1.0, Color32::from_black_alpha(25)));
        p.text(pos2(plot.left() - 8.0, y), Align2::RIGHT_CENTER, format!("{:.0} ms", y_max * k as f32 / 4.0), theme::font(14.0), theme::text_dim());
        p.text(pos2(plot.right() + 8.0, plot.top() + plot.height() * k as f32 / 4.0), Align2::LEFT_CENTER, format!("{}%", k * 25), theme::font(14.0), theme::text_dim());
    }

    let series = |i: usize| cols.iter().map(|c| c.map_or(0.0, |c| c[i] / y_max)).collect::<Vec<f32>>();
    widgets::area(&p, plot, &series(2), theme::yellow(), None);
    widgets::area(&p, plot, &series(1), BLUE, None);
    widgets::area(&p, plot, &series(0), theme::green(), None);
    let step = plot.width() / (cols.len() - 1) as f32;
    for (i, c) in cols.iter().enumerate() {
        if let Some(c) = c.filter(|c| c[3] > 0.0) {
            let x = plot.left() + i as f32 * step;
            p.rect_filled(Rect::from_min_max(pos2(x - 1.0, plot.top()), pos2(x + 1.0, plot.top() + (c[3] / 100.0 * plot.height()).max(4.0))), 0, theme::red());
        }
    }

    // Time axis in local time.
    for (f, label) in time_ticks(t0, t1, plot.width()) {
        let x = plot.left() + f * plot.width();
        p.vline(x, chart.bottom()..=chart.bottom() + 5.0, Stroke::new(1.0, theme::text_dim()));
        p.text(pos2(x, chart.bottom() + 22.0), Align2::CENTER_CENTER, label, theme::font(14.0), theme::text_dim());
    }

    // Hover: the column under the pointer.
    let resp = ui.interact(plot, ui.scope_id().with(("tbb_hover", idx)), Sense::drag());
    if let Some(pos) = resp.hover_pos() {
        let i = (((pos.x - plot.left()) / step).round() as usize).min(cols.len() - 1);
        let x = plot.left() + i as f32 * step;
        p.vline(x, plot.y_range(), Stroke::new(1.0, theme::text_dim()));
        if let Some(c) = cols[i] {
            let ts = t0 + (span as f64 * i as f64 / (cols.len() - 1) as f64) as i64;
            let text = format!("{}\nMin {:.1} ms\nAvg {:.1} ms\nMax {:.1} ms\nLoss {:.1}%", clock::fmt_stamp(ts), c[0], c[1], c[2], c[3]);
            let g = p.layout(text, theme::font(14.0), theme::text(), 200.0);
            let at = pos2(if x + g.size().x + 30.0 > plot.right() { x - g.size().x - 20.0 } else { x + 10.0 }, plot.top() + 40.0);
            p.rect_filled(Rect::from_min_size(at - vec2(8.0, 6.0), g.size() + vec2(16.0, 12.0)), 6, theme::surface());
            p.galley(at, g, theme::text());
        }
    }
    // Right-drag pans, Ctrl + scroll zooms the time scale; plain scrolling is left to the page.
    let w = window.1 - window.0;
    let (mut nw, mut na) = (w, window.0);
    if resp.dragged_by(egui::PointerButton::Secondary) {
        na -= resp.drag_delta().x / plot.width() * w;
    }
    let zoom = ui.input(|i| i.zoom_delta());
    if let (true, Some(pos)) = (resp.hovered() && zoom != 1.0, resp.hover_pos()) {
        nw = (w / zoom).clamp(0.02, 1.0);
        na = window.0 + (pos.x - plot.left()) / plot.width() * (w - nw);
    }
    na = na.clamp(0.0, 1.0 - nw);
    ((na, na + nw) != window).then_some((na, na + nw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_keep_the_extremes_and_average_the_rest() {
        let s = |ts, min, avg, max, loss| Sample { ts, min, avg, max, loss };
        let data = [s(0, 5.0, 10.0, 20.0, 0.0), s(1, 3.0, 20.0, 40.0, 7.0), s(100, 1.0, 1.0, 1.0, 0.0)];
        let c = columns(&data, 0, 100, 3);
        assert_eq!(c[0], Some([3.0, 15.0, 40.0, 7.0]));
        assert_eq!((c[1], c[2].map(|c| c[3])), (None, Some(0.0)));
        // A fully lost round doesn't drag the latency down to 0.
        let lost = [s(0, 10.0, 12.0, 14.0, 0.0), s(1, 0.0, 0.0, 0.0, 100.0)];
        assert_eq!(columns(&lost, 0, 100, 3)[0], Some([10.0, 12.0, 14.0, 100.0]));
        assert_eq!(columns(&lost[1..], 0, 100, 3)[0], Some([0.0, 0.0, 0.0, 100.0]));
        assert_eq!(y_top(21.0), 40.0);
        assert_eq!(y_top(0.0), 20.0);
    }
}
