//! Draws a plugin's `UiTree` with egui. Edits are applied to the tree in place (so typing shows at
//! once) and also returned as events for the plugin, which answers with a fresh tree.

use super::manager::{intern, query_samples};
use crate::live::db::Db;
use crate::plugins::core::latency::{self, Feed, Line, Sample};
use egui::Ui;
use plugin_sdk::{CHART_DIALOG_CLOSE, CHART_LAYOUT, CHART_RANGE, CHART_REFRESH, CHART_SIGNIN, Event, LatencyChart, UiTree};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// Who is drawing: the plugin, whether Demo mode is on, and a key for this page (chart state lives under it).
pub struct Env<'a> {
    pub plugin: &'a str,
    pub demo: bool,
    pub key: String,
    /// For pages that need what only the app knows (a place on the map for an address).
    pub backend: Option<std::sync::Arc<dyn crate::data::Backend>>,
}

/// The latency charts' own state (selected graphs, day, scrubber), kept between frames per page.
static CHARTS: Mutex<BTreeMap<String, latency::State>> = Mutex::new(BTreeMap::new());

/// (page, chart, day start) already reported as having no data, so a day the site doesn't have isn't asked for every frame.
static TRIED: Mutex<BTreeSet<(String, u32, i64)>> = Mutex::new(BTreeSet::new());

/// Brings the chart titled `name` on a plugin's chart page (`key` is "<plugin>/<tab>") into view and flashes it, as an alert's jump does.
pub fn flash_chart(key: &str, name: &str) {
    CHARTS.lock().unwrap_or_else(|e| e.into_inner()).entry(key.to_owned()).or_default().show(name.to_owned());
}

/// A warning line: the app's own warning icon (the font has no ⚠ glyph) and the text in `color`, wrapping beside it.
pub fn flag(ui: &mut Ui, color: egui::Color32, text: &str) {
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 18.0), egui::Sense::hover());
        crate::icons::paint(ui.painter(), crate::icons::Icon::Warning, egui::Rect::from_center_size(rect.center(), egui::vec2(15.0, 15.0)), color);
        ui.add(egui::Label::new(egui::RichText::new(text).color(color)).wrap());
    });
}

pub fn show(ui: &mut Ui, tree: &mut UiTree, env: &Env) -> Vec<Event> {
    let mut events = Vec::new();
    draw(ui, tree, env, &mut events);
    events
}

fn draw(ui: &mut Ui, tree: &mut UiTree, env: &Env, ev: &mut Vec<Event>) {
    match tree {
        UiTree::Label(t) => match t.strip_prefix('⚠') {
            Some(rest) => flag(ui, crate::theme::orange(), rest.trim_start()),
            None => {
                ui.label(t.as_str());
            }
        },
        UiTree::Heading(t) => {
            ui.heading(t.as_str());
        }
        UiTree::Weak(t) => {
            ui.weak(t.as_str());
        }
        UiTree::Button { id, text } => {
            if ui.button(text.as_str()).clicked() {
                ev.push(Event::Click { id: id.clone() });
            }
        }
        UiTree::TextField { id, value } => text(ui, id, value, false, ev),
        UiTree::Password { id, value } => text(ui, id, value, true, ev),
        UiTree::Switch { id, text, on } => {
            if crate::widgets::switch(ui, on, text.as_str()).changed() {
                ev.push(Event::Bool { id: id.clone(), on: *on });
            }
        }
        UiTree::Dropdown { id, options, selected } => {
            let before = *selected;
            egui::ComboBox::from_id_salt(id.as_str()).selected_text(options.get(*selected).map(String::as_str).unwrap_or("")).show_ui(ui, |ui| {
                for (i, o) in options.iter().enumerate() {
                    ui.selectable_value(selected, i, o.as_str());
                }
            });
            if *selected != before {
                ev.push(Event::Index { id: id.clone(), index: *selected });
            }
        }
        UiTree::Number { id, value, min, max } => {
            if ui.add(egui::DragValue::new(value).range(*min..=*max)).changed() {
                ev.push(Event::Number { id: id.clone(), value: *value });
            }
        }
        UiTree::Link { text, url } => {
            // A plugin must not open file: or other local schemes.
            if url.starts_with("https://") || url.starts_with("http://") {
                crate::ui::dialogs::link(ui, text.as_str(), url.as_str());
            } else {
                ui.label(text.as_str());
            }
        }
        UiTree::Grid { columns, children } => {
            let n = (*columns).max(1);
            egui::Grid::new(ui.next_auto_id()).num_columns(n).spacing([16.0, 8.0]).show(ui, |ui| {
                for (i, c) in children.iter_mut().enumerate() {
                    draw(ui, c, env, ev);
                    if (i + 1) % n == 0 {
                        ui.end_row();
                    }
                }
            });
        }
        UiTree::Row(children) => {
            ui.horizontal(|ui| children.iter_mut().for_each(|c| draw(ui, c, env, ev)));
        }
        UiTree::Column(children) => {
            ui.vertical(|ui| children.iter_mut().for_each(|c| draw(ui, c, env, ev)));
        }
        UiTree::Info(text) => {
            egui::Frame::NONE
                .fill(crate::theme::accent_soft())
                .stroke(egui::Stroke::new(1.0, crate::theme::accent().gamma_multiply(0.4)))
                .corner_radius(8)
                .inner_margin(egui::Margin::symmetric(14, 12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_top(|ui| {
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                        crate::icons::paint(ui.painter(), crate::icons::Icon::Info, rect, crate::theme::accent_text());
                        ui.add_space(6.0);
                        ui.add(egui::Label::new(egui::RichText::new(text.as_str()).font(crate::theme::font(14.0)).color(crate::theme::text())).wrap());
                    });
                });
            ui.add_space(12.0);
        }
        UiTree::Card { title, rows } => {
            ui.scope(|ui| {
                crate::ui::fluent::style(ui);
                crate::ui::fluent::group(ui, title, |c| {
                    for r in rows.iter_mut() {
                        match r {
                            UiTree::Setting { title, sub, control } => c.row(title, sub, |ui| draw(ui, control, env, ev)),
                            other => c.block(|ui| draw(ui, other, env, ev)),
                        }
                    }
                });
            });
            ui.add_space(12.0);
        }
        UiTree::Setting { control, .. } => draw(ui, control, env, ev),
        UiTree::Copy { label, value } => {
            if ui.button(label.as_str()).clicked() {
                ui.ctx().copy_text(value.chars().take(500).collect());
            }
        }
        UiTree::FileButton { id, text, accept } => file_button(ui, id, text, accept, ev),
        UiTree::Separator => {
            ui.separator();
        }
        UiTree::Image(png) => {
            let key = format!("plugin-img-{}", crate::plugins::wasm::loader::hash_of(png));
            if let Some(t) = crate::plugins::core::texture(ui.ctx(), &key, png) {
                ui.add(egui::Image::new((t.id(), t.size_vec2().min(egui::vec2(256.0, 256.0)))));
            }
        }
        UiTree::Disabled(inner) => {
            // Whatever the control would report is dropped: it can't be used.
            let mut ignored = Vec::new();
            ui.add_enabled_ui(false, |ui| draw(ui, inner, env, &mut ignored));
        }
        UiTree::Speedtest(p) => crate::ui::speed::show(ui, p, env, ev),
        UiTree::LatencyChart(c) => chart(ui, c, env, ev),
    }
}

/// What a file dialog left behind: the file's name and text, or why it couldn't be read.
type Picked = std::sync::Arc<std::sync::Mutex<Option<Result<(String, String), String>>>>;

/// A button that opens the file dialog on its own thread. The chosen file is read there (the plugin never sees a path)
/// and arrives as `Event::File` on a later frame.
fn file_button(ui: &mut Ui, id: &str, text: &str, accept: &str, ev: &mut Vec<Event>) {
    let slot: Picked = ui.data_mut(|d| d.get_temp_mut_or_insert_with::<Picked>(egui::Id::NULL.with(("plugin_file", id)), Default::default).clone());
    if let Some(r) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
        ev.push(match r {
            Ok((name, content)) => Event::File { id: id.to_owned(), name, content, error: String::new() },
            Err(error) => Event::File { id: id.to_owned(), name: String::new(), content: String::new(), error },
        });
    }
    if ui.button(text).clicked() {
        let patterns = crate::sys::filedialog::patterns(accept);
        let filters = if patterns.is_empty() { Vec::new() } else { vec![("Supported files".to_owned(), patterns)] };
        crate::sys::filedialog::open_async(ui.ctx(), "Choose a file", filters, move |p| {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(crate::sys::filedialog::read_text(&p));
        });
    }
}

fn text(ui: &mut Ui, id: &str, value: &mut String, password: bool, ev: &mut Vec<Event>) {
    if ui.add(egui::TextEdit::singleline(value).password(password)).changed() {
        ev.push(Event::Text { id: id.to_owned(), value: value.clone() });
    }
}

/// Charts with nothing stored for the day on screen: their ids and the day's start and end.
type Missing = (Vec<u32>, (i64, i64));

/// Feeds the shared latency page from the plugin's own tables, read with the SQL the plugin declared.
struct PluginFeed<'a> {
    plugin: &'a str,
    key: &'a str,
    demo: bool,
    sql: String,
    last_ok: i64,
    refreshing: bool,
    paused: bool,
    loading: bool,
    wants_missing: bool,
    signin_text: String,
    signin_button: String,
    hint: &'static str,
    texts: [&'static str; 4],
    /// The Refresh button was pressed during this frame.
    refresh: Cell<bool>,
    /// The banner's sign-in button was pressed.
    signin: Cell<bool>,
    /// Charts with nothing stored for the day on screen: (ids, (day start, day end)).
    missing: RefCell<Option<Missing>>,
}

impl Feed for PluginFeed<'_> {
    fn refreshing(&self) -> bool {
        self.refreshing
    }
    fn sync_now(&self) {
        self.refresh.set(true);
    }
    fn last_ok(&self) -> i64 {
        self.last_ok
    }
    fn load(&self, _db: &Db, id: u32, since: i64) -> rusqlite::Result<Vec<Sample>> {
        query_samples(self.plugin, false, &self.sql, id, since)
    }
    fn demo(&self, id: u32, since: i64, _until: i64) -> Option<Vec<Sample>> {
        self.demo.then(|| query_samples(self.plugin, true, &self.sql, id, since).unwrap_or_default())
    }
    fn refresh_hint(&self) -> &'static str {
        self.hint
    }
    fn empty(&self, live: bool, no_lines: bool, day: bool) -> &'static str {
        match (live, no_lines, day) {
            (false, ..) => self.texts[0],
            (true, true, _) => self.texts[1],
            (true, false, true) if self.loading => "Loading…",
            (true, false, true) => self.texts[2],
            (true, false, false) => self.texts[3],
        }
    }
    fn paused(&self) -> bool {
        self.paused || crate::sys::webview::CHECK.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn loading(&self) -> bool {
        self.loading
    }
    /// A day with nothing stored is reported to the plugin, once per chart and day.
    fn missing(&self, _ctx: &egui::Context, ids: Vec<u32>, view: (i64, i64)) {
        if !self.wants_missing || self.loading || self.paused() {
            return;
        }
        let mut tried = TRIED.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<u32> = ids.into_iter().filter(|id| !tried.contains(&(self.key.to_owned(), *id, view.0))).collect();
        if !ids.is_empty() {
            tried.extend(ids.iter().map(|id| (self.key.to_owned(), *id, view.0)));
            *self.missing.borrow_mut() = Some((ids, view));
        }
    }
    /// The session is gone (or the site wants an extra check): say so, with the way back in.
    fn banner(&self, ui: &mut Ui, bar: egui::Rect) -> f32 {
        if !self.paused() {
            return 0.0;
        }
        let p = ui.painter();
        p.rect_filled(bar, 8, crate::theme::red_soft());
        if crate::sys::webview::CHECK.load(std::sync::atomic::Ordering::Relaxed) {
            p.text(
                bar.left_center() + egui::vec2(14.0, 0.0),
                egui::Align2::LEFT_CENTER,
                "thinkbroadband is asking for an extra check. Complete it in the browser window that just opened.",
                crate::theme::font(15.0),
                crate::theme::red(),
            );
            return bar.height();
        }
        if self.signin_text.is_empty() {
            return 0.0;
        }
        p.text(bar.left_center() + egui::vec2(14.0, 0.0), egui::Align2::LEFT_CENTER, self.signin_text.as_str(), crate::theme::font(15.0), crate::theme::red());
        if !self.signin_button.is_empty() {
            crate::ui::row_in(ui, egui::Rect::from_min_size(egui::pos2(bar.right() - 140.0, bar.top() + 4.0), egui::vec2(130.0, 36.0)), |ui| {
                if crate::widgets::pill_button(ui, None, &self.signin_button, false, 110.0).clicked() {
                    self.signin.set(true);
                }
            });
        }
        bar.height()
    }
}

fn chart(ui: &mut Ui, c: &mut LatencyChart, env: &Env, ev: &mut Vec<Event>) {
    let lines: Vec<Line> = c.lines.iter().map(|l| Line { id: l.id, name: l.name.clone() }).collect();
    let feed = PluginFeed {
        plugin: env.plugin,
        key: &env.key,
        demo: env.demo,
        sql: c.sql.clone(),
        last_ok: c.last_ok,
        refreshing: c.refreshing,
        paused: c.paused,
        loading: c.loading,
        wants_missing: c.wants_missing,
        signin_text: c.signin_text.clone(),
        signin_button: c.signin_button.clone(),
        signin: Cell::new(false),
        missing: RefCell::new(None),
        hint: intern(&c.refresh_hint),
        texts: [intern(&c.text_not_live), intern(&c.text_no_lines), intern(&c.text_no_data_day), intern(&c.text_no_data)],
        refresh: Cell::new(false),
    };
    let mut tools = std::mem::take(&mut c.tools);
    let before = (c.layout, c.range);
    {
        let mut states = CHARTS.lock().unwrap_or_else(|e| e.into_inner());
        let st = states.entry(env.key.clone()).or_default();
        latency::tab(ui, st, &lines, &feed, !env.demo, (&mut c.layout, &mut c.range), |ui| tools.iter_mut().for_each(|t| draw(ui, t, env, ev)));
        if let Some(m) = st.take_saved() {
            super::manager::note(env.plugin, m);
        }
    }
    c.tools = tools;
    if let Some(dialog) = c.dialog.as_mut() {
        let title = if c.dialog_title.is_empty() { "Plugin" } else { c.dialog_title.as_str() };
        let open = crate::widgets::dialog(title).show(ui.ctx(), |ui| {
            ui.set_width(420.0);
            draw(ui, dialog, env, ev);
        });
        if !open {
            ev.push(Event::Click { id: CHART_DIALOG_CLOSE.into() });
        }
    }
    if feed.refresh.get() {
        ev.push(Event::Click { id: CHART_REFRESH.into() });
    }
    if feed.signin.get() {
        ev.push(Event::Click { id: CHART_SIGNIN.into() });
    }
    if let Some((ids, (from, to))) = feed.missing.take() {
        ev.push(Event::ChartMissing { ids, from, to });
    }
    if c.layout != before.0 {
        ev.push(Event::Index { id: CHART_LAYOUT.into(), index: c.layout });
    }
    if c.range != before.1 {
        ev.push(Event::Index { id: CHART_RANGE.into(), index: c.range });
    }
}
