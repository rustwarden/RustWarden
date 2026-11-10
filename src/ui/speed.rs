//! The Speedtest page a plugin asks for with `UiTree::Speedtest`: latest figures on a dial, the route map, a history
//! chart and a list of recent tests. The plugin sends what is happening (live readings, whether a test runs);
//! the finished tests are read from the plugin's own tables.

use crate::plugins::wasm::manager::query_speed;
use crate::plugins::wasm::ui_tree::Env;
use crate::{clock, theme, widgets};
use egui::{Align2, Color32, Mesh, Rect, Sense, Shape, Stroke, Ui, pos2, vec2};
use plugin_sdk::{Event, SPEED_INSTALL, SPEED_RANGE, SPEED_RUN, SpeedLive, SpeedPage, SpeedPhase};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const RANGES: [(i64, &str); 3] = [(86_400, "24 Hours"), (7 * 86_400, "7 Days"), (30 * 86_400, "30 Days")];
const RELOAD: Duration = Duration::from_secs(10);
const ROWS: usize = 50;
/// The dial's labels, evenly spaced around it like speedtest.net's.
const MARKS: [f32; 9] = [0.0, 5.0, 10.0, 50.0, 100.0, 250.0, 500.0, 750.0, 1000.0];
/// The dial starts at the bottom left (135 degrees, y pointing down) and sweeps clockwise.
const DIAL_START: f32 = 135.0;
const DIAL_SWEEP: f32 = 270.0;

/// One finished test.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpeedResult {
    pub ts: i64,
    pub ping_ms: f32,
    pub jitter_ms: f32,
    pub down_mbps: f32,
    pub up_mbps: f32,
    /// Packet loss in percent; negative when the server didn't report it.
    pub loss: f32,
    pub server: String,
    pub isp: String,
    /// Link to the result on speedtest.net.
    pub url: String,
    /// Addresses of the test server and of this connection, for the route map; empty when unknown.
    pub server_ip: String,
    pub client_ip: String,
}

/// Where a test went, as (lon, lat) pairs for the map.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SpeedRoute {
    pub home: (f32, f32),
    pub server: (f32, f32),
}

type Slot = Arc<Mutex<Option<(usize, Vec<SpeedResult>, Option<SpeedRoute>)>>>;

#[derive(Default)]
struct SpeedUi {
    results: Vec<SpeedResult>,
    /// Where the latest test went, when the GeoIP database knows both ends.
    route: Option<SpeedRoute>,
    slot: Slot,
    loading: bool,
    loaded: Option<(Instant, usize)>,
    was_busy: bool,
    /// The licence warning before the download is open.
    confirm: bool,
}

/// The page's own state (the stored tests, the licence window), kept between frames.
static STATES: Mutex<BTreeMap<String, SpeedUi>> = Mutex::new(BTreeMap::new());

/// A soft card like the other tabs'.
fn card_frame() -> egui::Frame {
    egui::Frame::NONE.fill(theme::card()).stroke(Stroke::new(1.0, theme::card_edge())).corner_radius(8).inner_margin(egui::Margin::symmetric(14, 10))
}

pub fn mbps(v: f32) -> String {
    if v >= 100.0 { format!("{v:.0}") } else { format!("{v:.1}") }
}

/// Draws the page; what the user pressed comes back as events for the plugin.
pub fn show(ui: &mut Ui, page: &mut SpeedPage, env: &Env, ev: &mut Vec<Event>) {
    let mut states = STATES.lock().unwrap_or_else(|e| e.into_inner());
    let st = states.entry(env.key.clone()).or_default();
    reload(st, ui.ctx(), page, env);
    let busy = page.running || page.installing;
    if busy {
        // Fast enough for the needle to look smooth; the plugin also redraws on every reading.
        ui.ctx().request_repaint_after(Duration::from_millis(50));
    }
    let mut range = page.range.min(2);
    let (mut run, mut install) = (false, false);
    // The whole page scrolls, so nothing is cut off in a small window.
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        egui::Frame::NONE.inner_margin(egui::Margin::same(12)).show(ui, |ui| {
            card_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let label = if page.running { "Testing…" } else { "Run test" };
                    ui.add_enabled_ui(page.cli_ready && !busy, |ui| {
                        if widgets::pill_button(ui, Some(crate::icons::Icon::Wave), label, false, 0.0).on_hover_text("Run a speed test now").clicked() {
                            run = true;
                        }
                    });
                    widgets::dropdown(ui, None, &mut range, &[0, 1, 2], |i| RANGES[i].1.to_owned(), 110.0);
                    let note = if !page.error.is_empty() {
                        page.error.clone()
                    } else if page.running {
                        "Running a test, about 30 seconds…".to_owned()
                    } else if page.last_ok > 0 {
                        format!("Last test {}", clock::fmt_time_lower(page.last_ok))
                    } else {
                        String::new()
                    };
                    let color = if page.error.is_empty() { theme::text_dim() } else { theme::red() };
                    ui.label(egui::RichText::new(note).font(theme::font(14.0)).color(color));
                });
            });
            ui.add_space(12.0);
            if !page.cli_ready {
                st.confirm |= setup_card(ui, page);
                return;
            }
            let latest = st.results.last().cloned();
            if latest.is_none() && page.live.is_empty() {
                ui.label(egui::RichText::new("No tests yet. Press Run test to measure your connection.").color(theme::text_dim()));
                return;
            }
            top_row(ui, st.route, latest.as_ref(), page);
            ui.add_space(12.0);
            let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 220.0), Sense::hover());
            if page.running {
                live_chart(ui, rect, &page.live);
            } else {
                chart(ui, rect, &st.results, range);
            }
            ui.add_space(12.0);
            table(ui, &st.results);
        });
    });
    if st.confirm {
        let open = widgets::dialog(if page.install_title.is_empty() { "Download" } else { page.install_title.as_str() }).show(ui.ctx(), |ui| {
            ui.set_width(420.0);
            ui.label(egui::RichText::new("Before you download").font(theme::bold(16.0)));
            for (i, line) in page.install_text.iter().enumerate() {
                ui.add_space(if i == 0 { 6.0 } else { 4.0 });
                ui.label(line.as_str());
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Accept and download").clicked() {
                    install = true;
                }
                if ui.button("Cancel").clicked() {
                    st.confirm = false;
                }
            });
        });
        if install || !open {
            st.confirm = false;
        }
    }
    if range != page.range {
        page.range = range;
        ev.push(Event::Index { id: SPEED_RANGE.into(), index: range });
    }
    if run {
        ev.push(Event::Click { id: SPEED_RUN.into() });
    }
    if install {
        ev.push(Event::Click { id: SPEED_INSTALL.into() });
    }
}

/// Reads the stored tests on a worker: when the range changes, after a test ends and every few seconds.
fn reload(st: &mut SpeedUi, ctx: &egui::Context, page: &SpeedPage, env: &Env) {
    if let Some((range, rows, route)) = st.slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
        if range == page.range.min(2) {
            st.results = rows;
            st.route = route;
        }
        st.loading = false;
    }
    let range = page.range.min(2);
    let busy = page.running || page.installing;
    let just_ended = st.was_busy && !busy;
    st.was_busy = busy;
    let stale = st.loaded.is_none_or(|(at, r)| r != range || at.elapsed() > RELOAD);
    if st.loading || page.sql.is_empty() || !(stale || just_ended) {
        return;
    }
    st.loading = true;
    st.loaded = Some((Instant::now(), range));
    let (slot, ctx, sql, plugin, demo, backend) = (st.slot.clone(), ctx.clone(), page.sql.clone(), env.plugin.to_owned(), env.demo, env.backend.clone());
    let since = clock::now_unix() - RANGES[range].0;
    std::thread::spawn(move || {
        let rows = query_speed(&plugin, demo, &sql, since).unwrap_or_default();
        let route = rows.last().and_then(|r| backend.as_ref()?.speedtest_route(&r.server_ip, &r.client_ip));
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((range, rows, route));
        ctx.request_repaint();
    });
}

/// Explains the program and offers the download; true when the button was pressed.
fn setup_card(ui: &mut Ui, page: &SpeedPage) -> bool {
    let mut clicked = false;
    ui.label(egui::RichText::new("Speedtest needs Ookla's speedtest-cli").font(theme::bold(18.0)));
    ui.add_space(6.0);
    ui.label("Speedtest.net has no public API, so RustWarden runs Ookla's own command-line tool and reads its results.");
    ui.label("It is downloaded from install.speedtest.net only when you press the button, and runs only when you start a test or set a schedule in the plugin's settings.");
    ui.label("By downloading it you accept Ookla's license and privacy policy (speedtest.net/about).");
    ui.add_space(10.0);
    let label = if page.installing { "Downloading…" } else { "Download speedtest-cli" };
    ui.add_enabled_ui(!page.installing, |ui| {
        clicked = widgets::pill_button(ui, None, label, false, 0.0).clicked();
    });
    clicked
}

/// How far round the dial `v` Mbps sits, 0 to 1. The labels are evenly spaced, so the scale is linear between them.
fn dial_frac(v: f32) -> f32 {
    let v = v.clamp(0.0, MARKS[MARKS.len() - 1]);
    let i = MARKS.iter().rposition(|m| *m <= v).unwrap_or(0).min(MARKS.len() - 2);
    (i as f32 + (v - MARKS[i]) / (MARKS[i + 1] - MARKS[i])) / (MARKS.len() - 1) as f32
}

/// The gauge on the left and the route map on the right.
fn top_row(ui: &mut Ui, route: Option<SpeedRoute>, latest: Option<&SpeedResult>, page: &SpeedPage) {
    let last = page.live.last().filter(|_| page.running);
    let (name, value) = match last {
        Some(p) if p.phase == SpeedPhase::Upload => ("Upload", p.mbps),
        Some(p) if p.phase == SpeedPhase::Download => ("Download", p.mbps),
        Some(_) => ("Ping", 0.0),
        // A test that has not reported yet starts the needle at 0, not at the last result.
        None if page.running => ("Ping", 0.0),
        None => ("Download", latest.map_or(0.0, |r| r.down_mbps)),
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        let (dial, _) = ui.allocate_exact_size(vec2((ui.available_width() * 0.4).clamp(220.0, 320.0), 250.0), Sense::hover());
        match latest.filter(|_| !page.running) {
            Some(r) => {
                // Park the needle at 0, so the next test's dial doesn't swing back from this result.
                ui.ctx().animate_value_with_time(ui.scope_id().with("speed_gauge"), 0.0, 0.0);
                results_card(ui, dial, r);
            }
            None => gauge(ui, dial, name, value),
        }
        let (map, _) = ui.allocate_exact_size(vec2(ui.available_width(), 250.0), Sense::hover());
        let p = ui.painter();
        match route {
            Some(r) => {
                // The test's server is named "Provider, Town"; the town is what fits on the map.
                let town = latest.map_or("Server", |l| l.server.rsplit(", ").next().unwrap_or("Server"));
                // Download packets travel from the server to you, upload ones from you to the server.
                let flow = page.running.then(|| match last.map(|p| p.phase) {
                    Some(SpeedPhase::Download) => (false, theme::accent_text()),
                    Some(SpeedPhase::Upload) => (true, theme::up()),
                    _ => (true, theme::text_dim()),
                });
                crate::ui::map::route_map(ui, map, r.home, r.server, ("You", town), flow);
            }
            None => {
                p.rect_filled(map, 8, theme::card());
                p.text(
                    map.center(),
                    Align2::CENTER_CENTER,
                    "The test server's location isn't known yet.\nIt needs a GeoIP database (see Settings) and a finished test.",
                    theme::font(13.0),
                    theme::text_dim(),
                );
            }
        }
        p.rect_stroke(map, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
    });
}

/// A strip of the dial between two positions (0 to 1), shaded by `color` at each position.
fn arc_mesh(c: egui::Pos2, radii: (f32, f32), span: (f32, f32), color: impl Fn(f32) -> Color32) -> Shape {
    let steps = (((span.1 - span.0) * 96.0).ceil() as u32).max(1);
    let mut mesh = Mesh::default();
    for i in 0..=steps {
        let f = span.0 + (span.1 - span.0) * i as f32 / steps as f32;
        let a = (DIAL_START + DIAL_SWEEP * f).to_radians();
        let dir = vec2(a.cos(), a.sin());
        mesh.colored_vertex(c + dir * radii.0, color(f));
        mesh.colored_vertex(c + dir * radii.1, color(f));
        if i > 0 {
            let k = 2 * i;
            mesh.indices.extend([k - 2, k - 1, k, k - 1, k + 1, k]);
        }
    }
    Shape::mesh(mesh)
}

/// A speedometer: the arc fills and the needle swings to `value` Mbps, easing between readings.
fn gauge(ui: &Ui, rect: Rect, name: &str, value: f32) {
    let shown = ui.ctx().animate_value_with_time(ui.scope_id().with("speed_gauge"), value, 0.25);
    let p = ui.painter();
    p.rect_filled(rect, 8, theme::card());
    p.rect_stroke(rect, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
    let r = rect.width().min(rect.height()) / 2.0 - 14.0;
    let c = rect.center() + vec2(0.0, -4.0);
    let frac = dial_frac(shown);
    p.add(arc_mesh(c, (r - 14.0, r), (0.0, 1.0), |_| theme::border()));
    let (from, to) = (theme::accent_text(), theme::up());
    p.add(arc_mesh(c, (r - 14.0, r), (0.0, frac), |f| from.lerp_to_gamma(to, f)));
    for (i, m) in MARKS.iter().enumerate() {
        let a = (DIAL_START + DIAL_SWEEP * i as f32 / (MARKS.len() - 1) as f32).to_radians();
        let color = if *m <= shown { theme::text() } else { theme::text_dim() };
        p.text(c + vec2(a.cos(), a.sin()) * (r - 30.0), Align2::CENTER_CENTER, format!("{m}"), theme::font(12.0), color);
    }
    let a = (DIAL_START + DIAL_SWEEP * frac).to_radians();
    let dir = vec2(a.cos(), a.sin());
    let side = vec2(-dir.y, dir.x) * 4.0;
    p.add(Shape::convex_polygon(vec![c + dir * (r - 44.0), c + side, c - side], theme::text(), Stroke::NONE));
    p.circle_filled(c, 6.0, theme::text());
    p.text(c + vec2(0.0, r * 0.62), Align2::CENTER_CENTER, mbps(shown), theme::bold(30.0), theme::text());
    p.text(c + vec2(0.0, r * 0.62 + 24.0), Align2::CENTER_CENTER, format!("{name} · Mbps"), theme::font(13.0), theme::text_dim());
}

/// Speed over the running test, drawn like the traffic graph: one time axis (how far through the test), download and upload
/// as two soft areas that grow from the left.
fn live_chart(ui: &Ui, rect: Rect, live: &[SpeedLive]) {
    let p = ui.painter();
    p.rect_filled(rect, 8, theme::card());
    p.rect_stroke(rect, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
    let plot = Rect::from_min_max(rect.min + vec2(52.0, 14.0), rect.max - vec2(14.0, 28.0));
    let top = nice_ceil(live.iter().map(|s| s.mbps).fold(1.0, f32::max));
    for i in 0..=4 {
        let y = plot.bottom() - plot.height() * i as f32 / 4.0;
        p.hline(plot.x_range(), y, Stroke::new(1.0, theme::border()));
        p.text(pos2(plot.left() - 8.0, y), Align2::RIGHT_CENTER, mbps(top * i as f32 / 4.0), theme::font(12.0), theme::text_dim());
    }
    for (i, label) in ["Start", "", "Halfway", "", "End"].into_iter().enumerate() {
        p.text(pos2(plot.left() + plot.width() * i as f32 / 4.0, plot.bottom() + 6.0), Align2::CENTER_TOP, label, theme::font(12.0), theme::text_dim());
    }
    for (phase, color) in [(SpeedPhase::Download, theme::accent_text()), (SpeedPhase::Upload, theme::up())] {
        let mine: Vec<&SpeedLive> = live.iter().filter(|s| s.phase == phase).collect();
        let (Some(last), true) = (mine.last(), mine.len() >= 2) else { continue };
        let values: Vec<f32> = mine.iter().map(|s| s.mbps / top).collect();
        widgets::area_soft_to(p, plot, &values, color, false, None, last.progress.clamp(0.05, 1.0));
    }
    p.text(rect.right_top() + vec2(-14.0, 12.0), Align2::RIGHT_TOP, "Download", theme::font(12.0), theme::accent_text());
    p.text(rect.right_top() + vec2(-90.0, 12.0), Align2::RIGHT_TOP, "Upload", theme::font(12.0), theme::up());
    p.text(rect.left_top() + vec2(14.0, 12.0), Align2::LEFT_TOP, "Live test", theme::font(12.0), theme::text_dim());
}

/// The latest test as text: the four figures, then the server and ISP.
fn results_card(ui: &Ui, rect: Rect, r: &SpeedResult) {
    let p = ui.painter();
    p.rect_filled(rect, 8, theme::card());
    p.rect_stroke(rect, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
    p.text(rect.left_top() + vec2(18.0, 16.0), Align2::LEFT_TOP, "Latest result", theme::font(13.0), theme::text_dim());
    let rows = [
        ("Download", format!("{} Mbps", mbps(r.down_mbps)), theme::accent_text()),
        ("Upload", format!("{} Mbps", mbps(r.up_mbps)), theme::up()),
        ("Ping", format!("{:.0} ms", r.ping_ms), theme::text()),
        ("Jitter", format!("{:.1} ms", r.jitter_ms), theme::text()),
    ];
    for (i, (name, value, color)) in rows.into_iter().enumerate() {
        let y = rect.top() + 56.0 + 36.0 * i as f32;
        p.text(pos2(rect.left() + 18.0, y), Align2::LEFT_CENTER, name, theme::font(15.0), theme::text_dim());
        p.text(pos2(rect.right() - 18.0, y), Align2::RIGHT_CENTER, value, theme::bold(20.0), color);
    }
    let loss = if r.loss >= 0.0 { format!(" · {:.1}% loss", r.loss) } else { String::new() };
    let info = format!("{} · {}{loss}", r.server, r.isp);
    widgets::text_fit(p, pos2(rect.left() + 18.0, rect.bottom() - 20.0), Align2::LEFT_CENTER, &info, theme::font(13.0), theme::text_dim(), rect.width() - 36.0);
}

/// Download and upload over the range: a line per series with a dot per test.
fn chart(ui: &Ui, rect: Rect, results: &[SpeedResult], range: usize) {
    let p = ui.painter();
    p.rect_filled(rect, 8, theme::card());
    p.rect_stroke(rect, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
    let plot = Rect::from_min_max(rect.min + vec2(52.0, 14.0), rect.max - vec2(14.0, 28.0));
    let (t1, span) = (clock::now_unix(), RANGES[range.min(2)].0);
    let top = nice_ceil(results.iter().map(|r| r.down_mbps.max(r.up_mbps)).fold(1.0, f32::max));
    for i in 0..=4 {
        let y = plot.bottom() - plot.height() * i as f32 / 4.0;
        p.hline(plot.x_range(), y, Stroke::new(1.0, theme::border()));
        p.text(pos2(plot.left() - 8.0, y), Align2::RIGHT_CENTER, mbps(top * i as f32 / 4.0), theme::font(12.0), theme::text_dim());
    }
    for i in 0..=4 {
        let ts = t1 - span + span * i / 4;
        let x = plot.left() + plot.width() * i as f32 / 4.0;
        let label = if span > 86_400 { clock::day_label(ts, t1) } else { clock::fmt_time_lower(ts) };
        p.text(pos2(x, plot.bottom() + 6.0), Align2::CENTER_TOP, label, theme::font(12.0), theme::text_dim());
    }
    let at = |r: &SpeedResult, v: f32| pos2(plot.left() + plot.width() * (r.ts - (t1 - span)) as f32 / span as f32, plot.bottom() - plot.height() * v / top);
    for (get, color) in [(down as fn(&SpeedResult) -> f32, theme::accent_text()), (up, theme::up())] {
        let pts: Vec<_> = results.iter().filter(|r| r.ts >= t1 - span).map(|r| at(r, get(r))).collect();
        p.add(egui::Shape::line(pts.clone(), Stroke::new(2.0, color)));
        for pt in pts {
            p.circle_filled(pt, 3.0, color);
        }
    }
    p.text(rect.right_top() + vec2(-14.0, 12.0), Align2::RIGHT_TOP, "Download", theme::font(12.0), theme::accent_text());
    p.text(rect.right_top() + vec2(-90.0, 12.0), Align2::RIGHT_TOP, "Upload", theme::font(12.0), theme::up());
}

fn down(r: &SpeedResult) -> f32 {
    r.down_mbps
}

fn up(r: &SpeedResult) -> f32 {
    r.up_mbps
}

/// Rounds up to 1, 2, 5 times a power of ten, so the grid labels stay readable.
fn nice_ceil(v: f32) -> f32 {
    let pow = 10f32.powf(v.max(1.0).log10().floor());
    [1.0, 2.0, 5.0, 10.0].into_iter().map(|m| m * pow).find(|c| *c >= v).unwrap_or(10.0 * pow)
}

fn table(ui: &mut Ui, results: &[SpeedResult]) {
    card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::Grid::new("speedtest_rows").num_columns(7).spacing([20.0, 6.0]).striped(true).show(ui, |ui| {
            for h in ["Time", "Server", "ISP", "Download", "Upload", "Ping", ""] {
                ui.label(egui::RichText::new(h).font(theme::font(13.0)).color(theme::text_dim()));
            }
            ui.end_row();
            let now = clock::now_unix();
            for r in results.iter().rev().take(ROWS) {
                ui.label(format!("{} {}", clock::day_label(r.ts, now), clock::fmt_time_lower(r.ts)));
                ui.label(&r.server);
                ui.label(&r.isp);
                ui.label(egui::RichText::new(format!("{} Mbps", mbps(r.down_mbps))).color(theme::accent_text()));
                ui.label(egui::RichText::new(format!("{} Mbps", mbps(r.up_mbps))).color(theme::up()));
                ui.label(format!("{:.0} ms", r.ping_ms));
                if r.url.starts_with("https://") && ui.link("Result").clicked() {
                    crate::sys::open_url(&r.url);
                }
                ui.end_row();
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_tops_round_up_to_1_2_5() {
        assert_eq!(nice_ceil(0.4), 1.0);
        assert_eq!(nice_ceil(87.0), 100.0);
        assert_eq!(nice_ceil(140.0), 200.0);
        assert_eq!(nice_ceil(300.0), 500.0);
        assert_eq!(nice_ceil(940.0), 1000.0);
    }

    #[test]
    fn dial_positions_follow_the_evenly_spaced_labels() {
        assert_eq!(dial_frac(0.0), 0.0);
        assert_eq!(dial_frac(10.0), 2.0 / 8.0);
        assert_eq!(dial_frac(100.0), 4.0 / 8.0);
        assert_eq!(dial_frac(1000.0), 1.0);
        assert_eq!(dial_frac(5000.0), 1.0);
        assert!((dial_frac(75.0) - 3.5 / 8.0).abs() < 1e-6);
        assert!(dial_frac(-3.0) == 0.0);
    }

    #[test]
    fn speeds_keep_a_decimal_below_100() {
        assert_eq!((mbps(9.87), mbps(94.0), mbps(940.2)), ("9.9".into(), "94.0".into(), "940".into()));
    }
}
