//! thinkbroadband's pieces of the interface: its row and editor in Settings > Integrations, and
//! the Broadband tab, which is the shared latency charts fed from the downloaded samples.

use super::{Integration, Monitor, Sample, browser, client, worker};
use crate::app::RustWarden;
use crate::live::db::Db;
use crate::plugins::core::latency::{self, Feed, Line};
use crate::settings::{Mode, Settings};
use crate::{theme, widgets};
use egui::{Align2, Rect, Sense, Ui, pos2, vec2};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Index the Integrations table uses for "editing thinkbroadband" (Home Assistant rows use their position).
pub const EDIT: usize = usize::MAX;

// ---- Settings > Integrations ----

/// thinkbroadband's favicon, from https://www.thinkbroadband.com/assets/favicons/favicon-192x192.png.
const LOGO: &[u8] = include_bytes!("assets/thinkbroadband.png");

/// The icon cell of the Integrations table and the add menu.
pub fn mark(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::hover());
    crate::plugins::core::png(ui.painter(), rect, "tbb_logo", LOGO);
}

/// The thinkbroadband row of the Integrations table.
pub fn row(ui: &mut Ui, s: &mut Settings, edit: &mut Option<usize>) {
    let Some(it) = &mut s.thinkbroadband else { return };
    mark(ui);
    ui.label(&it.name);
    ui.label("thinkbroadband");
    crate::widgets::switch(ui, &mut it.enabled, "");
    if ui.button("Edit").clicked() {
        *edit = Some(EDIT);
    }
    if ui.button("Remove").clicked() {
        s.thinkbroadband = None;
        *edit = None;
    }
    ui.end_row();
}

/// The graphs found, and whether the saved sign-in already worked.
type Import = Arc<Mutex<Option<Result<(Vec<Monitor>, bool), String>>>>;

/// The connection window; false once closed.
pub fn editor(ctx: &egui::Context, id: egui::Id, it: &mut Integration) -> bool {
    let mut open = true;
    let slot: Option<Import> = ctx.data_mut(|d| d.get_temp::<Option<Import>>(id)).flatten();
    let finished = slot.as_ref().and_then(|s| s.lock().ok()?.take());
    let busy = slot.is_some() && finished.is_none();
    if let Some(r) = finished {
        ctx.data_mut(|d| {
            d.insert_temp(id, None::<Import>);
            match r {
                Ok((list, was_signed_in)) => {
                    let how = if was_signed_in { "You're already signed in, nothing to do." } else { "Signed in." };
                    d.insert_temp(id.with("info"), format!("{how} Found {} graph(s); tick the ones to include.", list.len()));
                    d.insert_temp(id.with("list"), list);
                    d.remove_temp::<String>(id.with("msg"));
                }
                Err(e) => {
                    d.insert_temp(id.with("msg"), e);
                    d.remove_temp::<String>(id.with("info"));
                }
            }
        });
    }
    if !crate::widgets::dialog("thinkbroadband").show(ctx, |ui| {
        ui.set_width(440.0);
        ui.spacing_mut().item_spacing.y = 6.0;
        ui.label("Signing in opens a browser window (thinkbroadband checks visitors with Cloudflare), so RustWarden never sees your password.");
        if busy && browser::CHECK.load(Ordering::Relaxed) {
            ui.colored_label(theme::red(), "thinkbroadband is asking for an extra check. Complete it in the browser window that opened.");
        }
        if ui.add_enabled(!busy, egui::Button::new(if busy { "Importing…" } else { "Sign in and import graphs" })).clicked() {
            let slot: Import = Default::default();
            ui.data_mut(|d| d.insert_temp(id, Some(slot.clone())));
            let ctx = ui.ctx().clone();
            std::thread::spawn(move || {
                // Already signed in from before: the list comes straight back; otherwise sign in once and retry.
                let r = match client::list_monitors() {
                    Ok(l) => Ok((l, true)),
                    Err(e) if e == browser::NEED_LOGIN => browser::sign_in().and_then(|()| client::list_monitors()).map(|l| (l, false)),
                    Err(e) => Err(e),
                };
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
                ctx.request_repaint();
            });
        }
        if let Some(m) = ui.data_mut(|d| d.get_temp::<String>(id.with("msg"))) {
            ui.colored_label(theme::red(), m);
        }
        if let Some(m) = ui.data_mut(|d| d.get_temp::<String>(id.with("info"))) {
            ui.label(m);
        }
        // Graphs found on the account, plus any already chosen that the last import didn't list.
        let mut list: Vec<Monitor> = ui.data_mut(|d| d.get_temp(id.with("list"))).unwrap_or_default();
        for m in &it.monitors {
            if !list.iter().any(|l| l.id == m.id) {
                list.push(m.clone());
            }
        }
        if list.is_empty() {
            ui.label("Import to choose which reliability graphs to include.");
        } else {
            ui.label("Graphs to include:");
        }
        for m in list {
            let mut on = it.monitors.iter().any(|x| x.id == m.id);
            if crate::widgets::switch(ui, &mut on, format!("{} ({})", m.name, m.id)).changed() {
                it.monitors.retain(|x| x.id != m.id);
                if on {
                    it.monitors.push(m);
                }
            }
        }
        if it.monitors.is_empty() {
            ui.colored_label(theme::red(), "Tick at least one graph; the Broadband tab appears after you press OK in Settings.");
        }
        ui.add_space(4.0);
        loss_levels(ui, it);
        ui.add_space(4.0);
        crate::widgets::switch(ui, &mut it.show_tab, "Show the Broadband tab");
        ui.horizontal(|ui| {
            ui.label("Download every");
            crate::widgets::num_field(ui, &mut it.interval_mins, 1..=1440, " min");
        });
        ui.separator();
        let confirm = id.with("reset");
        if ui.data_mut(|d| d.get_temp::<bool>(confirm)).unwrap_or(false) {
            ui.colored_label(theme::red(), "Sign out, forget the graphs and delete the downloaded samples?");
            ui.horizontal(|ui| {
                if ui.button("Yes, reset").clicked() {
                    // Deleting the browser profile and the samples takes a moment: off the UI thread.
                    it.monitors.clear();
                    worker::NEEDS_LOGIN.store(false, Ordering::Relaxed);
                    ui.data_mut(|d| {
                        d.insert_temp(confirm, false);
                        d.remove_temp::<Vec<Monitor>>(id.with("list"));
                        d.remove_temp::<String>(id.with("msg"));
                        d.insert_temp(id.with("info"), "Signing out and deleting data…".to_owned());
                    });
                    let ctx = ui.ctx().clone();
                    std::thread::spawn(move || {
                        let db = Db::open(&crate::live::db_path()).ok();
                        let result = browser::sign_out().map_err(|e| e.to_string()).and_then(|()| db.ok_or("Can't open the database.".to_owned())?.tbb_clear().map(drop).map_err(|e| e.to_string()));
                        ctx.data_mut(|d| {
                            d.remove_temp::<String>(id.with("info"));
                            match result {
                                Ok(()) => d.insert_temp(id.with("info"), "Signed out and data deleted. Import again to reconnect.".to_owned()),
                                Err(e) => d.insert_temp(id.with("msg"), format!("Reset incomplete: {e}")),
                            }
                        });
                        ctx.request_repaint();
                    });
                }
                if ui.button("Cancel").clicked() {
                    ui.data_mut(|d| d.insert_temp(confirm, false));
                }
            });
        } else {
            ui.horizontal(|ui| {
                if ui.button("Sync now").on_hover_text("Download the graphs again (press OK first to apply saved settings).").clicked() {
                    worker::SYNC_NOW.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                if ui.button("Sign out and reset data").clicked() {
                    ui.data_mut(|d| d.insert_temp(confirm, true));
                }
            });
        }
        if ui.button("Done").clicked() {
            open = false;
        }
    }) {
        open = false;
    }
    open
}

/// The packet-loss levels, shown on the thinkbroadband page of Settings > Alerts.
pub fn alert_options(ui: &mut Ui, s: &mut Settings) {
    match &mut s.thinkbroadband {
        Some(it) => loss_levels(ui, it),
        None => {
            ui.label("Add the thinkbroadband integration (Settings > Integrations) to set these.");
        }
    }
}

/// The packet-loss level, also shown in the integration's own editor. Delivery (desktop, External
/// Notifications) is the alert's own settings under Settings > Alerts.
fn loss_levels(ui: &mut Ui, it: &mut Integration) {
    ui.horizontal(|ui| {
        ui.label("Alert at packet loss of");
        crate::widgets::num_field(ui, &mut it.alert_pct, 0.0..=100.0, " %");
    });
}

// ---- Broadband tab ----

static SIGNING: AtomicBool = AtomicBool::new(false);
/// An older day is being downloaded for the day view.
static LOADING: AtomicBool = AtomicBool::new(false);
/// "Later" was pressed on the sign-in prompt; it stays away until the next sign-in failure.
static DISMISSED: AtomicBool = AtomicBool::new(false);
/// (monitor, day start) already asked for this run, so a day thinkbroadband doesn't have isn't retried every frame.
static TRIED: Mutex<Vec<(u32, i64)>> = Mutex::new(Vec::new());

/// Downloads the missing day for these monitors on a thread and stores it; the tab reloads when it ends.
fn backfill(ctx: &egui::Context, ids: Vec<u32>, (t0, t1): (i64, i64)) {
    if LOADING.swap(true, Ordering::Relaxed) {
        return;
    }
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        // thinkbroadband's days are UTC, so a local day can touch two of them.
        let days: std::collections::BTreeSet<String> = [t0, t1 - 1].iter().map(|t| client::date(*t)).collect();
        let requests: Vec<(u32, String)> = ids.iter().flat_map(|id| days.iter().map(move |d| (*id, d.clone()))).collect();
        if let Ok(answers) = client::fetch_days(&requests)
            && let Ok(db) = Db::open(&crate::live::db_path())
        {
            for id in &ids {
                let all: Vec<Sample> = requests.iter().zip(&answers).filter(|(r, _)| r.0 == *id).filter_map(|(_, a)| a.as_ref().ok()).flatten().cloned().collect();
                let _ = db.tbb_put(*id, &all);
            }
        }
        LOADING.store(false, Ordering::Relaxed);
        ctx.request_repaint();
    });
}

/// Opens the sign-in window on a thread; the downloads resume once it succeeds.
fn start_sign_in(ctx: &egui::Context) {
    if SIGNING.swap(true, Ordering::Relaxed) {
        return;
    }
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        if browser::sign_in().is_ok() {
            worker::SYNC_NOW.store(true, Ordering::Relaxed);
        }
        SIGNING.store(false, Ordering::Relaxed);
        ctx.request_repaint();
    });
}

/// The downloaded samples, the download worker's state, and the sign-in banner.
struct Tbb;

impl Feed for Tbb {
    fn refreshing(&self) -> bool {
        worker::REFRESHING.load(Ordering::Relaxed)
    }
    fn sync_now(&self) {
        worker::SYNC_NOW.store(true, Ordering::Relaxed);
    }
    fn last_ok(&self) -> i64 {
        worker::LAST_OK.load(Ordering::Relaxed)
    }
    fn load(&self, db: &Db, id: u32, since: i64) -> rusqlite::Result<Vec<Sample>> {
        db.tbb_since(id, since)
    }
    fn refresh_hint(&self) -> &'static str {
        "Download the latest samples now"
    }
    fn empty(&self, live: bool, _no_lines: bool, day: bool) -> &'static str {
        match (live, day) {
            (false, _) => "thinkbroadband data is downloaded in Live mode.",
            (true, true) if self.loading() => "Loading…",
            (true, true) => "thinkbroadband has no data for this day.",
            (true, false) => "No samples yet. Press Refresh to download them.",
        }
    }
    fn paused(&self) -> bool {
        worker::NEEDS_LOGIN.load(Ordering::Relaxed) || browser::CHECK.load(Ordering::Relaxed)
    }
    fn loading(&self) -> bool {
        LOADING.load(Ordering::Relaxed)
    }
    /// A day with nothing stored is fetched from thinkbroadband, once per run.
    fn missing(&self, ctx: &egui::Context, ids: Vec<u32>, view: (i64, i64)) {
        if self.loading() || self.paused() {
            return;
        }
        let mut tried = TRIED.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<u32> = ids.into_iter().filter(|id| !tried.contains(&(*id, view.0))).collect();
        if !ids.is_empty() {
            tried.extend(ids.iter().map(|id| (*id, view.0)));
            backfill(ctx, ids, view);
        }
    }
    /// The session is gone: say so, with the way back in.
    fn banner(&self, ui: &mut Ui, bar: Rect) -> f32 {
        if !self.paused() {
            return 0.0;
        }
        if browser::CHECK.load(Ordering::Relaxed) {
            let p = ui.painter();
            p.rect_filled(bar, 8, theme::red_soft());
            p.text(
                bar.left_center() + vec2(14.0, 0.0),
                Align2::LEFT_CENTER,
                "thinkbroadband is asking for an extra check. Complete it in the browser window that just opened.",
                theme::font(15.0),
                theme::red(),
            );
            return bar.height();
        }
        let p = ui.painter();
        p.rect_filled(bar, 8, theme::red_soft());
        p.text(bar.left_center() + vec2(14.0, 0.0), Align2::LEFT_CENTER, "Your thinkbroadband session has expired. Sign in again to keep these graphs up to date.", theme::font(15.0), theme::red());
        crate::ui::row_in(ui, Rect::from_min_size(pos2(bar.right() - 140.0, bar.top() + 4.0), vec2(130.0, 36.0)), |ui| {
            let signing = SIGNING.load(Ordering::Relaxed);
            if widgets::pill_button(ui, None, if signing { "Signing in…" } else { "Sign in" }, false, 110.0).clicked() && !signing {
                start_sign_in(ui.ctx());
            }
        });
        bar.height()
    }
}

impl RustWarden {
    /// Asks the user to sign in again when the downloads found the session gone (the Broadband tab has its own banner).
    pub(crate) fn show_tbb_login(&mut self, ctx: &egui::Context) {
        static CHECK_SEEN: AtomicBool = AtomicBool::new(false);
        if browser::CHECK.load(Ordering::Relaxed) {
            if !CHECK_SEEN.swap(true, Ordering::Relaxed) {
                self.notify("thinkbroadband is asking for an extra check. Complete it in the browser window that opened.");
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        } else {
            CHECK_SEEN.store(false, Ordering::Relaxed);
        }
        if !worker::NEEDS_LOGIN.load(Ordering::Relaxed) {
            DISMISSED.store(false, Ordering::Relaxed);
            return;
        }
        if DISMISSED.load(Ordering::Relaxed) || SIGNING.load(Ordering::Relaxed) || self.tab == crate::app::Tab::Broadband {
            return;
        }
        if !crate::widgets::dialog("thinkbroadband").show(ctx, |ui| {
            ui.set_width(380.0);
            ui.label("RustWarden can't reach your thinkbroadband account any more. Sign in again to keep the Broadband graph up to date.");
            ui.horizontal(|ui| {
                if ui.button("Sign in").clicked() {
                    start_sign_in(ctx);
                }
                if ui.button("Later").clicked() {
                    DISMISSED.store(true, Ordering::Relaxed);
                }
            });
        }) {
            DISMISSED.store(true, Ordering::Relaxed);
        }
    }

    pub(crate) fn broadband_tab(&mut self, ui: &mut Ui) {
        let live = self.settings.mode == Mode::Live;
        let Some(it) = &mut self.settings.thinkbroadband else { return };
        // Names saved before the import cleaned them still carry escapes.
        let lines: Vec<Line> = it.monitors.iter().map(|m| Line { id: m.id, name: client::unescape(&m.name) }).collect();
        if lines.is_empty() {
            return;
        }
        if latency::tab(ui, &mut self.tbb, &lines, &Tbb, live, (&mut it.layout, &mut it.range), |_| {})
            && let Err(e) = self.settings.save()
        {
            self.notify(&format!("Couldn't save settings: {e}"));
        }
        if let Some(m) = self.tbb.take_saved() {
            self.notify(&m);
        }
    }
}
