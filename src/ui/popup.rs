//! Desktop popups for alerts: small borderless always-on-top windows stacked above the taskbar.

use crate::app::RustWarden;
use crate::data::{Answer, Backend, Direction, ThreatAct, Vt};
use crate::icons;
use crate::live::alerts::AlertKind;
use crate::theme;
use crate::ui::toast;
use crate::util::fit_text;
use crate::widgets::text_fit;
use egui::{Align2, Color32, Rect, Sense, Stroke, ViewportId, pos2, vec2};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// VirusTotal verdicts for the popups, read on threads: a popup asks every frame, and each read is a database query.
#[derive(Default)]
pub(crate) struct VtCache {
    seen: Arc<Mutex<HashMap<String, (Instant, Vt)>>>,
    inflight: Arc<Mutex<HashSet<String>>>,
}

impl VtCache {
    const TTL: Duration = Duration::from_secs(2);

    /// What is known for `who` (an app name or a hash), `Vt::None` until the first read lands; refreshed every `TTL`.
    pub fn get(&self, backend: &Arc<dyn Backend>, who: &str) -> Vt {
        let known = self.seen.lock().unwrap_or_else(|e| e.into_inner()).get(who).cloned();
        if known.as_ref().is_none_or(|(at, _)| at.elapsed() >= Self::TTL) && self.inflight.lock().unwrap_or_else(|e| e.into_inner()).insert(who.to_owned()) {
            let (backend, seen, inflight, who) = (backend.clone(), self.seen.clone(), self.inflight.clone(), who.to_owned());
            std::thread::spawn(move || {
                // A panic still frees the name, so the next frame can ask again.
                if let Ok(vt) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend.virustotal(&who))) {
                    seen.lock().unwrap_or_else(|e| e.into_inner()).insert(who.clone(), (Instant::now(), vt));
                }
                inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&who);
            });
        }
        known.map_or(Vt::None, |(_, vt)| vt)
    }
}

/// What the banner windows report back. They are deferred viewports (an immediate one isn't drawn while the
/// main window is hidden in the tray, and egui panics), so they can't borrow `self`; each `show_*` reads this first.
#[derive(Default)]
pub(crate) struct BannerEv {
    hovered: Vec<u64>,
    closed: Option<u64>,
    /// The kind (title) of the popup whose gear was clicked, so Settings opens on that alert's entry.
    open_settings: Option<String>,
    /// A popup body was clicked: the alert whose source to show.
    open_source: Option<crate::data::Alert>,
    popup_info: Option<u64>,
    ask_info: Option<u64>,
    /// The key of a program the info panel asked to scan with VirusTotal.
    vt_scan: Option<String>,
    ask_done: Option<(u64, Option<Answer>)>,
    /// The chevron of an Ask prompt's Allow or Block button was clicked: open (or close) its menu.
    ask_menu: Option<(u64, AskMenu)>,
    /// A row of an Ask prompt's menu was picked.
    ask_pick: Option<(u64, AskMenu, usize)>,
    /// With an Allow answer: block again after this many minutes.
    ask_delay: Option<u64>,
    ask_local: Option<u64>,
    threat_done: Option<(u64, Option<ThreatAct>)>,
    threat_confirm: Option<(u64, Option<ThreatAct>)>,
    /// "Mark as normal" was clicked on this popup.
    mark_normal: Option<u64>,
}

#[derive(Clone, Default)]
pub(crate) struct Banners(Arc<Mutex<BannerEv>>);

impl Banners {
    fn get(&self) -> MutexGuard<'_, BannerEv> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

const SIZE: egui::Vec2 = vec2(400.0, 150.0);
/// A popup that can be marked as normal grows to fit the button.
const MARK_SIZE: egui::Vec2 = vec2(400.0, 194.0);
const ALERT_TITLE: &str = "RustWarden alert";
const ALERT_INFO_TITLE: &str = "RustWarden app info";
const ASK_W: f32 = 400.0;
const ASK_TITLE: &str = "RustWarden connection request";
const ASK_INFO_TITLE: &str = "RustWarden connection info";
const GAP: f32 = 10.0;
/// Index of "Alerts" in the Settings sidebar.
const ALERTS_SECTION: usize = 4;

/// The screen the popups stack in, in points. When egui doesn't know the window's monitor (hidden in the tray),
/// the primary monitor's size is used rather than a guessed 1080p.
pub(super) fn screen_size(ctx: &egui::Context) -> egui::Vec2 {
    if let Some(size) = ctx.input(|i| i.viewport().monitor_size) {
        return size;
    }
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
    let (w, h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    if w > 0 && h > 0 { vec2(w as f32, h as f32) / ctx.pixels_per_point() } else { vec2(1920.0, 1080.0) }
}

/// Which half of a Prompt prompt's buttons has its menu open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AskMenu {
    Allow,
    Block,
}

/// The prompt grows by a line when the connection has extra info to show.
fn ask_size(ask: &crate::data::ConnectAsk) -> egui::Vec2 {
    vec2(ASK_W, if ask.info.is_empty() { 204.0 } else { 226.0 })
}

fn popup_size(alert: &crate::data::Alert) -> egui::Vec2 {
    if alert.anomaly { MARK_SIZE } else { SIZE }
}

/// The Allow and Block buttons, relative to the prompt's top left.
fn ask_buttons(size: egui::Vec2) -> (Rect, Rect) {
    let w = (size.x - 32.0 - 8.0) / 2.0;
    let y = size.y - 16.0 - 32.0;
    (Rect::from_min_size(pos2(16.0, y), vec2(w, 32.0)), Rect::from_min_size(pos2(16.0 + w + 8.0, y), vec2(w, 32.0)))
}

impl RustWarden {
    /// Height the Malicious IP popups take next to the corner, which the Ask prompts and banners stack beyond.
    fn threat_stack_height(&self) -> f32 {
        self.threats.len() as f32 * (THREAT_SIZE.y + GAP)
    }

    /// Height the Prompt prompts take, after the threats.
    fn ask_stack_height(&self) -> f32 {
        self.asks.iter().map(|(_, a)| ask_size(a).y + GAP).sum()
    }

    pub(crate) fn show_popups(&mut self, ctx: &egui::Context) {
        let now = self.started.elapsed().as_secs_f64();
        let (hovered, closed, open_settings, info_click, open_source) = {
            let mut g = self.banners.get();
            (std::mem::take(&mut g.hovered), g.closed.take(), std::mem::take(&mut g.open_settings), g.popup_info.take(), g.open_source.take())
        };
        let scan = self.banners.get().vt_scan.take();
        let mark = self.banners.get().mark_normal.take();
        if let Some(at) = mark.and_then(|id| self.popups.iter().position(|(i, _, _)| *i == id)) {
            let (_, alert, _) = self.popups.remove(at);
            // A test alert (id 0) was never stored, so there is nothing to mark.
            if alert.id == 0 {
                self.notify("This was a test alert, so there is nothing to mark as normal.");
            } else {
                self.mark_alert_normal(alert.id);
            }
        }
        if let Some(key) = scan {
            self.backend.scan_virustotal(&key);
        }
        // The timeout only runs while the pointer is off a popup: hovering restarts it in full.
        for (id, _, until) in &mut self.popups {
            if hovered.contains(id) {
                *until = now + self.settings.popup_secs as f64;
            }
        }
        if let Some(id) = closed {
            self.popups.retain(|(i, _, _)| *i != id);
        }
        if let Some(kind) = open_settings {
            self.open_settings();
            if matches!(self.dialog, Some(crate::app::Dialog::Settings(_))) {
                self.settings_section = Some(ALERTS_SECTION);
                if let Some(i) = AlertKind::ALL.iter().position(|k| k.title() == kind) {
                    ctx.data_mut(|d| d.insert_temp(egui::Id::unique(super::dialogs::ALERT_JUMP), i));
                }
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if let Some(alert) = open_source {
            // The window may be hidden in the tray.
            self.show_window(ctx, true);
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            self.show_alert_source(&alert);
        }
        if let Some(id) = info_click {
            self.popup_info = if self.popup_info.as_ref().is_some_and(|(i, _)| *i == id) {
                None
            } else {
                self.popups.iter().find(|(i, _, _)| *i == id).filter(|(_, a, _)| !a.app.is_empty()).map(|(_, a, _)| {
                    let app = self.backend.firewall_apps().into_iter().find(|f| f.name == a.app).unwrap_or_else(|| crate::data::FirewallApp::from_alert(a));
                    (id, app)
                })
            };
        }
        for alert in self.backend.take_popups(true) {
            self.popup_seq += 1;
            self.popups.push((self.popup_seq, alert, now + self.settings.popup_secs as f64));
        }
        self.popups.retain(|(_, _, until)| now < *until);
        if self.popup_info.as_ref().is_some_and(|(id, _)| !self.popups.iter().any(|(i, _, _)| i == id)) {
            self.popup_info = None;
        }
        let most = self.settings.popup_max as usize;
        if self.popups.len() > most {
            self.popups.drain(..self.popups.len() - most);
        }
        if self.popups.is_empty() {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(250));

        let corner = self.settings.popup_corner;
        let work = toast::work_area(ctx);
        let mut info_at: Option<Rect> = None;
        // Threats sit nearest the corner, then Prompt prompts, then these banners (newest nearest).
        let before = self.threat_stack_height() + self.ask_stack_height();
        let sizes: Vec<egui::Vec2> = self.popups.iter().rev().map(|(_, a, _)| popup_size(a)).collect();
        let homes = toast::stack(work, corner, &sizes, before);
        for (slot, (id, alert, _)) in self.popups.iter().rev().enumerate() {
            let (id, alert, ev) = (*id, alert.clone(), self.banners.clone());
            let info_open = self.popup_info.as_ref().is_some_and(|(i, _)| *i == id);
            let has_source = self.alert_source(&alert).is_some();
            let kind = &alert.kind;
            let vt = if *kind == AlertKind::FirstActivity.title() || *kind == AlertKind::AppChanged.title() { self.vt_cache.get(&self.backend, &alert.app) } else { Vt::None };
            let (size, home) = (sizes[slot], homes[slot]);
            let pos = home + vec2(toast::slide_offset(corner, toast::age(id)), 0.0);
            if info_open {
                info_at = Some(Rect::from_min_size(home, size));
            }
            let vid = ViewportId::from_hash_of(("popup", id));
            ctx.show_viewport_deferred(vid, toast::window_builder(ALERT_TITLE, size, pos), move |ui, _class| {
                let r = toast::chrome(ui);
                let p = ui.painter().clone();
                if ui.input(|i| i.pointer.has_pointer() && i.pointer.hover_pos().is_some()) {
                    ev.get().hovered.push(id);
                }
                // Added first, so the buttons drawn after it win where they overlap. Clicking the body goes to the alert's source.
                if has_source && ui.interact(r, ui.scope_id().with("body"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    let mut g = ev.get();
                    g.open_source = Some(alert.clone());
                    g.closed = Some(id);
                }

                let head = toast::header(ui, r, true);
                if head.gear {
                    let mut g = ev.get();
                    g.open_settings = Some(alert.kind.clone());
                    g.closed = Some(id);
                } else if head.close {
                    ev.get().closed = Some(id);
                }

                toast::app_tile(&p, pos2(r.left() + 16.0, r.top() + 44.0), alert.icon);
                let left = r.left() + 76.0;
                text_fit(&p, pos2(left, r.top() + 54.0), Align2::LEFT_CENTER, &alert.kind, theme::bold(15.0), theme::text(), r.right() - left - 16.0);

                // The app's name, its Info link and whether it is signed.
                let (text, signed) = alert.text_and_signature();
                let y2 = r.top() + 78.0;
                let name = fit_text(&p, &alert.app, &theme::bold(14.0), (r.right() - 16.0 - left - if signed.is_some() { 136.0 } else { 60.0 }).max(16.0));
                let g = p.layout_no_wrap(name, theme::bold(14.0), theme::text());
                let name_end = left + g.size().x;
                p.galley(pos2(left, y2 - g.size().y / 2.0), g, theme::text());
                let mut x = name_end + 10.0;
                if toast::pill(ui, pos2(x, y2), "info", "Info", info_open) {
                    ev.get().popup_info = Some(id);
                }
                x += toast::PILL_W + 8.0;
                if let Some(signed) = signed {
                    let (label, color) = if signed { ("Signed", Color32::from_rgb(0x6c, 0xc5, 0x4a)) } else { ("Unsigned", Color32::from_rgb(0xe0, 0x7a, 0x3a)) };
                    let sig = Rect::from_min_size(pos2(x, y2 - 9.0), vec2(if signed { 50.0 } else { 62.0 }, 18.0));
                    p.rect_filled(sig, 9, color.gamma_multiply(0.22));
                    p.text(sig.center(), Align2::CENTER_CENTER, label, theme::font(12.0), color);
                }

                let reserve = if vt_bubble(&p, pos2(r.right() - 46.0, r.bottom() - 22.0), &vt) { 84.0 } else { 0.0 };
                let room = (r.right() - 16.0 - reserve - left).max(16.0);
                // The message, then the target on one line (cropped; the Info panel shows it in full).
                let mut y = r.top() + 96.0;
                if alert.country.is_none() {
                    let n = crate::widgets::text_wrap(&p, pos2(left, y), text, theme::font(14.0), theme::text_dim(), room, 18.0, 1);
                    y += 18.0 * n as f32 + 2.0;
                }
                let mut x = left;
                if let Some(country) = alert.country {
                    icons::flag(&p, country, Rect::from_min_size(pos2(x, y + 1.0), vec2(24.0, 16.0)));
                    x += 32.0;
                }
                text_fit(&p, pos2(x, y + 9.0), Align2::LEFT_CENTER, &alert.target, theme::bold(14.0), theme::text(), room - (x - left));
                // Same action as in the Alerts log.
                if alert.anomaly && toast::button(ui, Rect::from_min_size(pos2(left, r.bottom() - 48.0), vec2(150.0, 32.0)), "mark_normal", "Mark as normal", toast::Look::Standard) {
                    ev.get().mark_normal = Some(id);
                }
            });
            ctx.request_repaint_of(vid);
        }
        if let (Some((id, app)), Some(anchor)) = (&self.popup_info, info_at) {
            let (id, app, ev) = (*id, app.clone(), self.banners.clone());
            let can_scan = self.caps.live && !crate::live::vt::key().is_empty();
            let target = self.popups.iter().find(|(i, _, _)| *i == id).map(|(_, a, _)| a.target.clone()).unwrap_or_default();
            const INFO: egui::Vec2 = vec2(460.0, 290.0);
            let pos = toast::flyout_pos(anchor, work, INFO);
            ctx.show_viewport_deferred(ViewportId::from_hash_of(("popup_info", id)), toast::window_builder(ALERT_INFO_TITLE, INFO, pos), move |ui, _class| {
                let r = toast::chrome(ui);
                let p = ui.painter().clone();
                if ui.input(|i| i.pointer.has_pointer() && i.pointer.hover_pos().is_some()) {
                    ev.get().hovered.push(id);
                }
                icons::app_icon(&p, app.icon, Rect::from_center_size(pos2(r.left() + 24.0, r.top() + 24.0), vec2(20.0, 20.0)));
                text_fit(&p, pos2(r.left() + 44.0, r.top() + 24.0), Align2::LEFT_CENTER, &app.name, theme::bold(15.0), theme::text(), r.width() - 64.0);
                p.hline(r.x_range(), r.top() + 48.0, Stroke::new(1.0, theme::border()));
                let or_unknown = |s: &str| if s.is_empty() { "Unknown".to_owned() } else { s.to_owned() };
                let exe = if app.path.is_empty() { app.name.clone() } else { app.path.rsplit(['\\', '/']).next().unwrap_or(&app.name).to_owned() };
                let (vt_text, vt_color) = super::protect::vt_label(&app.virustotal);
                for (i, (k, v, color)) in [
                    ("Name:", exe, theme::text()),
                    ("Path:", or_unknown(&app.path), theme::text()),
                    ("Version:", or_unknown(&app.version), theme::text()),
                    ("Publisher:", or_unknown(&app.publisher), theme::text()),
                    ("VirusTotal:", vt_text, vt_color),
                ]
                .into_iter()
                .enumerate()
                {
                    let y = r.top() + 70.0 + 28.0 * i as f32;
                    p.text(pos2(r.left() + 16.0, y), Align2::LEFT_CENTER, k, theme::font(14.0), theme::text_dim());
                    text_fit(&p, pos2(r.left() + 100.0, y), Align2::LEFT_CENTER, &v, theme::font(14.0), color, r.width() - 116.0);
                }
                let y = r.top() + 70.0 + 28.0 * 5.0;
                p.text(pos2(r.left() + 16.0, y), Align2::LEFT_CENTER, "Target:", theme::font(14.0), theme::text_dim());
                crate::widgets::text_wrap(&p, pos2(r.left() + 100.0, y - 8.0), &target, theme::font(14.0), theme::text(), r.width() - 116.0, 17.0, 2);
                // VirusTotal: open the program's page, or scan it.
                let has_page = matches!(app.virustotal, Vt::Result { .. }) && !app.hash.is_empty();
                let scan_ok = can_scan && !app.path.is_empty() && matches!(app.virustotal, Vt::None | Vt::Failed);
                let row = r.bottom() - 48.0;
                if toast::button(ui, Rect::from_min_size(pos2(r.left() + 16.0, row), vec2(190.0, 32.0)), "vt_open", "Open on VirusTotal", toast::Look::Standard) && has_page {
                    crate::sys::open_url(&format!("https://www.virustotal.com/gui/file/{}", app.hash));
                }
                if scan_ok
                    && toast::button(
                        ui,
                        Rect::from_min_size(pos2(r.left() + 214.0, row), vec2(110.0, 32.0)),
                        "vt_scan",
                        if app.virustotal == Vt::None { "Scan" } else { "Rescan" },
                        toast::Look::Standard,
                    )
                {
                    ev.get().vt_scan = Some(app.key.clone());
                }
            });
        }
    }

    /// "First Network Connection" prompts from Prompt. They stay until answered or closed.
    pub(crate) fn show_asks(&mut self, ctx: &egui::Context) {
        let (info_click, local_toggled, toggled, picked, mut finished, mut delay) = {
            let mut g = self.banners.get();
            (g.ask_info.take(), g.ask_local.take(), g.ask_menu.take(), g.ask_pick.take(), g.ask_done.take(), g.ask_delay.take())
        };
        if let Some(id) = info_click {
            self.ask_info = if self.ask_info == Some(id) { None } else { Some(id) };
        }
        if let Some(id) = local_toggled
            && let Some((_, ask)) = self.asks.iter_mut().find(|(i, _)| *i == id)
        {
            ask.local = !ask.local;
        }
        if let Some(open) = toggled {
            self.ask_flyout = if self.ask_flyout == Some(open) { None } else { Some(open) };
        }
        if let Some((id, menu, row)) = picked
            && let Some((_, ask)) = self.asks.iter().find(|(i, _)| *i == id)
        {
            match menu {
                // Row 0 of the Allow menu is its caption.
                AskMenu::Allow => {
                    if let Some(mins) = row.checked_sub(1).and_then(|i| crate::app::BLOCK_AFTER_MINS.get(i)) {
                        delay = Some(*mins);
                        finished = Some((id, Some(Answer::Allow { local: ask.local })));
                    }
                }
                AskMenu::Block => {
                    if let Some(direction) = [None, Some(Direction::In), Some(Direction::Out)].get(row) {
                        finished = Some((id, Some(Answer::Block(*direction))));
                    }
                }
            }
        }
        if let Some((id, answer)) = finished
            && let Some(at) = self.asks.iter().position(|(i, _)| *i == id)
        {
            let (_, ask) = self.asks.remove(at);
            if self.ask_info == Some(id) {
                self.ask_info = None;
            }
            if self.ask_flyout.is_some_and(|(i, _)| i == id) {
                self.ask_flyout = None;
            }
            if let Some(answer) = answer.filter(|_| !ask.path.is_empty()) {
                let msg = format!("{} {}", if matches!(answer, Answer::Allow { .. }) { "Allowed" } else { "Blocked" }, ask.app);
                let path = ask.path.clone();
                self.run_bg(move |b| b.answer_ask(&path, answer).map(|()| msg));
                // The ping prompt stands for no program, so there is nothing to block later.
                if let Some(mins) = delay.filter(|_| !ask.path.starts_with("icmp:")) {
                    self.schedule_block(&ask.path.to_lowercase(), &ask.app, &[Direction::In, Direction::Out], mins);
                }
            }
        }
        for ask in self.backend.take_asks() {
            if ask.update {
                if let Some((_, open)) = self.asks.iter_mut().find(|(_, o)| o.path == ask.path) {
                    (open.target, open.info, open.hash) = (ask.target, ask.info, ask.hash);
                }
                continue;
            }
            self.popup_seq += 1;
            self.asks.push((self.popup_seq, ask));
        }
        if self.asks.is_empty() {
            self.ask_flyout = None;
            return;
        }
        let corner = self.settings.popup_corner;
        let work = toast::work_area(ctx);
        let sizes: Vec<egui::Vec2> = self.asks.iter().rev().map(|(_, a)| ask_size(a)).collect();
        let homes = toast::stack(work, corner, &sizes, self.threat_stack_height());
        let mut info_at: Option<Rect> = None;
        let mut hit_zones: Vec<Rect> = Vec::new();
        for (slot, (id, ask)) in self.asks.iter().rev().enumerate() {
            let (id, ask, ev) = (*id, ask.clone(), self.banners.clone());
            let vt = if ask.hash.is_empty() { Vt::None } else { self.vt_cache.get(&self.backend, &ask.hash) };
            let info_open = self.ask_info == Some(id);
            let menu = self.ask_flyout.filter(|(i, _)| *i == id).map(|(_, m)| m);
            let (size, home) = (sizes[slot], homes[slot]);
            let rect = Rect::from_min_size(home, size);
            hit_zones.push(rect);
            if info_open {
                info_at = Some(rect);
            }
            // Slides in from the screen edge while it fades in (see `theme::toast_window`).
            let pos = home + vec2(toast::slide_offset(corner, toast::age(id)), 0.0);
            let (allow_btn, block_btn) = ask_buttons(size);
            let vid = ViewportId::from_hash_of(("ask", id));
            ctx.show_viewport_deferred(vid, toast::window_builder(ASK_TITLE, size, pos), move |ui, _class| {
                let r = toast::chrome(ui);
                let p = ui.painter().clone();

                // Header (who is speaking, the close button), then the app's tile.
                if toast::header(ui, r, false).close {
                    // Prompt denies by default, so an ignored prompt is a block; recording it lists the app in Protect.
                    ev.get().ask_done = Some((id, Some(Answer::Block(None))));
                }
                toast::app_tile(&p, pos2(r.left() + 16.0, r.top() + 44.0), ask.icon);

                let left = r.left() + 76.0;
                p.text(pos2(left, r.top() + 54.0), Align2::LEFT_CENTER, "First Network Connection", theme::bold(15.0), theme::text());
                let max_w = if vt_bubble(&p, pos2(r.right() - 48.0, r.top() + 78.0), &vt) { r.right() - 96.0 } else { r.right() - 16.0 };
                let name = fit_text(&p, &ask.app, &theme::bold(14.0), (max_w - left - 44.0).max(16.0));
                let g = p.layout_no_wrap(name, theme::bold(14.0), theme::text());
                let name_end = left + g.size().x;
                p.galley(pos2(left, r.top() + 78.0 - g.size().y / 2.0), g, theme::text());
                if toast::pill(ui, pos2(name_end + 10.0, r.top() + 78.0), "info", "Info", info_open) {
                    ev.get().ask_info = Some(id);
                }
                let y3 = r.top() + 102.0;
                let mut x = left;
                if let Some(country) = ask.country {
                    icons::flag(&p, country, Rect::from_min_size(pos2(x, y3 - 8.0), vec2(24.0, 16.0)));
                    x += 32.0;
                }
                // One line each, cropped with an ellipsis; the Info panel shows the host in full.
                text_fit(&p, pos2(x, y3), Align2::LEFT_CENTER, &format!("Outgoing to {}", ask.target), theme::font(14.0), theme::text(), r.right() - 16.0 - x);
                if !ask.info.is_empty() {
                    text_fit(&p, pos2(left, y3 + 22.0), Align2::LEFT_CENTER, &ask.info, theme::font(13.0), theme::text_dim(), r.right() - 16.0 - left);
                }

                let boxy = r.top() + if ask.info.is_empty() { 122.0 } else { 144.0 };
                if toast::checkbox(ui, pos2(left, boxy), "local", "Allow local network access", ask.local, r.right() - 16.0 - left) {
                    ev.get().ask_local = Some(id);
                }

                let at = r.min.to_vec2();
                match toast::split_button(ui, allow_btn.translate(at), "allow", "Allow", toast::Look::Primary, menu == Some(AskMenu::Allow)) {
                    Some(toast::Split::Main) => ev.get().ask_done = Some((id, Some(Answer::Allow { local: ask.local }))),
                    Some(toast::Split::Chevron) => ev.get().ask_menu = Some((id, AskMenu::Allow)),
                    None => {}
                }
                match toast::split_button(ui, block_btn.translate(at), "block", "Block", toast::Look::Standard, menu == Some(AskMenu::Block)) {
                    Some(toast::Split::Main) => ev.get().ask_done = Some((id, Some(Answer::Block(None)))),
                    Some(toast::Split::Chevron) => ev.get().ask_menu = Some((id, AskMenu::Block)),
                    None => {}
                }
            });
            ctx.request_repaint_of(vid);

            if let Some(menu) = menu {
                let (button, rows) = match menu {
                    AskMenu::Allow => {
                        let mut rows = vec![toast::Row::header("Allow, then block again after")];
                        rows.extend(crate::app::BLOCK_AFTER_MINS.iter().map(|m| toast::Row::item(format!("{m} minutes"))));
                        (allow_btn, rows)
                    }
                    AskMenu::Block => (block_btn, ["Block all connections", "Block incoming connections", "Block outgoing connections"].into_iter().map(toast::Row::item).collect()),
                };
                let (_, chevron) = toast::split_zones(button.translate(home.to_vec2()));
                let ev = self.banners.clone();
                hit_zones.push(toast::flyout(ctx, id, chevron, work, rows, move |row| ev.get().ask_pick = Some((id, menu, row))));
            }
        }
        // The popups never have focus, so a click elsewhere is found by reading the mouse.
        if self.ask_flyout.is_some() && toast::clicked_outside(ctx, &hit_zones) {
            self.ask_flyout = None;
        }
        if let (Some(id), Some(anchor)) = (self.ask_info, info_at)
            && let Some((_, ask)) = self.asks.iter().find(|(i, _)| *i == id)
        {
            let ask = ask.clone();
            let vt = if ask.hash.is_empty() { Vt::None } else { self.vt_cache.get(&self.backend, &ask.hash) };
            const INFO: egui::Vec2 = vec2(460.0, 252.0);
            let pos = toast::flyout_pos(anchor, work, INFO);
            ctx.show_viewport_deferred(ViewportId::from_hash_of(("ask_info", id)), toast::window_builder(ASK_INFO_TITLE, INFO, pos), move |ui, _class| {
                let r = toast::chrome(ui);
                let p = ui.painter().clone();
                icons::app_icon(&p, ask.icon, Rect::from_center_size(pos2(r.left() + 24.0, r.top() + 24.0), vec2(20.0, 20.0)));
                text_fit(&p, pos2(r.left() + 44.0, r.top() + 24.0), Align2::LEFT_CENTER, &ask.app, theme::bold(15.0), theme::text(), r.width() - 64.0);
                p.hline(r.x_range(), r.top() + 48.0, Stroke::new(1.0, theme::border()));
                let or_unknown = |s: &str| if s.is_empty() { "Unknown".to_owned() } else { s.to_owned() };
                let exe = ask.path.rsplit(['\\', '/']).next().unwrap_or(&ask.app).to_owned();
                for (i, (k, v)) in
                    [("Name:", exe), ("Path:", or_unknown(&ask.path)), ("Version:", or_unknown(&ask.version)), ("Publisher:", or_unknown(&ask.publisher)), ("Target:", ask.target.clone())]
                        .into_iter()
                        .enumerate()
                {
                    let y = r.top() + 72.0 + 28.0 * i as f32;
                    p.text(pos2(r.left() + 16.0, y), Align2::LEFT_CENTER, k, theme::font(14.0), theme::text_dim());
                    text_fit(&p, pos2(r.left() + 100.0, y), Align2::LEFT_CENTER, &v, theme::font(14.0), theme::text(), r.width() - 116.0);
                }
                // VirusTotal, when the program has a result; its page opens from here.
                let y = r.top() + 72.0 + 28.0 * 5.0;
                let (vt_text, vt_color) = super::protect::vt_label(&vt);
                p.text(pos2(r.left() + 16.0, y), Align2::LEFT_CENTER, "VirusTotal:", theme::font(14.0), theme::text_dim());
                text_fit(&p, pos2(r.left() + 100.0, y), Align2::LEFT_CENTER, &vt_text, theme::font(14.0), vt_color, 150.0);
                if matches!(vt, Vt::Result { .. }) {
                    let b = Rect::from_center_size(pos2(r.right() - 100.0, y), vec2(170.0, 28.0));
                    if toast::button(ui, b, "vt_open", "Open on VirusTotal", toast::Look::Standard) {
                        crate::sys::open_url(&format!("https://www.virustotal.com/gui/file/{}", ask.hash));
                    }
                }
            });
        }
    }
}

/// VirusTotal badge: a blue "VT" followed by the score ("2/70"), red when any engine flags the file.
/// Centred on `c`. Returns whether anything was drawn; failed lookups and files VirusTotal has no score for draw nothing.
fn vt_bubble(p: &egui::Painter, c: egui::Pos2, vt: &Vt) -> bool {
    let (text, color) = match vt {
        Vt::Result { bad, total } => (format!("{bad}/{total}"), if *bad > 0 { theme::red() } else { theme::green() }),
        Vt::NotFound => ("?".into(), theme::text_dim()),
        Vt::Pending | Vt::Analysing => ("…".into(), theme::text_dim()),
        Vt::None | Vt::Failed | Vt::Skipped | Vt::OnHold => return false,
    };
    let g = p.layout_no_wrap(text, theme::bold(17.0), color);
    let mark = p.layout_no_wrap("VT".into(), theme::bold(17.0), Color32::from_rgb(0x5a, 0x72, 0xff));
    let w = mark.size().x + 8.0 + g.size().x;
    let x = c.x - w / 2.0;
    let right = x + mark.size().x + 8.0;
    p.galley(pos2(x, c.y - mark.size().y / 2.0), mark, theme::text());
    p.galley(pos2(right, c.y - g.size().y / 2.0), g, color);
    true
}

const THREAT_SIZE: egui::Vec2 = vec2(400.0, 196.0);
const THREAT_TITLE: &str = "RustWarden malicious IP warning";

impl RustWarden {
    /// "Malicious IP detected" banners, stacked down from the top right. They stay until the
    /// user closes them or picks an action; unblocking and whitelisting ask for confirmation first.
    pub(crate) fn show_threats(&mut self, ctx: &egui::Context) {
        let (done, confirm) = {
            let mut g = self.banners.get();
            (g.threat_done.take(), g.threat_confirm.take())
        };
        if let Some((id, act)) = confirm
            && let Some((_, _, pending)) = self.threats.iter_mut().find(|(i, _, _)| *i == id)
        {
            *pending = act;
        }
        if let Some((id, act)) = done
            && let Some(at) = self.threats.iter().position(|(i, _, _)| *i == id)
        {
            let ip = self.threats[at].1.ip.clone();
            let is_test = self.threats[at].1.is_test();
            if let Some(act) = act {
                // Shown as done at once; a failure arrives as a toast from the thread.
                if act == ThreatAct::Block {
                    let t = &mut self.threats[at];
                    (t.1.blocked, t.1.error, t.2) = (true, None, None);
                } else {
                    self.threats.remove(at);
                }
                let msg = format!(
                    "{} {ip}",
                    match act {
                        ThreatAct::Block => "Blocked",
                        ThreatAct::Unblock => "Unblocked",
                        ThreatAct::Whitelist => "Whitelisted",
                        ThreatAct::Unwhitelist => "Removed from whitelist:",
                    }
                );
                // A test popup only changes itself.
                if !is_test {
                    self.run_bg(move |b| b.threat_act(&ip, act).map(|()| msg));
                }
            } else {
                self.threats.remove(at);
            }
        }
        for t in self.backend.take_threats() {
            self.popup_seq += 1;
            self.threats.push((self.popup_seq, t, None));
        }
        if self.threats.is_empty() {
            return;
        }
        let corner = self.settings.popup_corner;
        let work = toast::work_area(ctx);
        let homes = toast::stack(work, corner, &vec![THREAT_SIZE; self.threats.len()], 0.0);
        for (slot, (id, t, pending)) in self.threats.iter().enumerate() {
            let (id, t, pending, ev) = (*id, t.clone(), *pending, self.banners.clone());
            let pos = homes[slot] + vec2(toast::slide_offset(corner, toast::age(id)), 0.0);
            let vid = ViewportId::from_hash_of(("threat", id));
            ctx.show_viewport_deferred(vid, toast::window_builder(THREAT_TITLE, THREAT_SIZE, pos), move |ui, _class| {
                let red = theme::red();
                let r = toast::chrome_edged(ui, Stroke::new(1.5, red));
                let p = ui.painter().clone();
                if toast::header(ui, r, false).close {
                    ev.get().threat_done = Some((id, None));
                }
                toast::mark_tile(&p, pos2(r.left() + 16.0, r.top() + 44.0), "!", red);

                let left = r.left() + 76.0;
                let w = r.right() - left - 16.0;
                text_fit(&p, pos2(left, r.top() + 54.0), Align2::LEFT_CENTER, "Malicious IP detected", theme::bold(15.0), red, w);
                text_fit(&p, pos2(left, r.top() + 78.0), Align2::LEFT_CENTER, &format!("{} connected to {}", t.app, t.ip), theme::font(14.0), theme::text(), w);
                let (sig, sig_color) = match t.signed {
                    Some(true) => ("Signed", theme::green()),
                    Some(false) => ("Unsigned", Color32::from_rgb(0xe0, 0x7a, 0x3a)),
                    None => ("Signature unknown", theme::text_dim()),
                };
                let g = p.layout_no_wrap(sig.into(), theme::bold(13.0), sig_color);
                let sig_w = g.size().x;
                p.galley(pos2(left, r.top() + 102.0 - g.size().y / 2.0), g, sig_color);
                let status = match (&t.error, t.blocked) {
                    (_, true) => "Blocked automatically".to_owned(),
                    (Some(e), _) => format!("Not blocked: {e}"),
                    _ => "Not blocked".to_owned(),
                };
                if let Some(act) = pending {
                    let what = if act == ThreatAct::Whitelist { "Whitelisting" } else { "Unblocking" };
                    crate::widgets::text_wrap(
                        &p,
                        pos2(left, r.top() + 94.0),
                        &format!("{what} this address lets it reach your computer. It is on a malicious-IP list."),
                        theme::font(13.0),
                        red,
                        w,
                        16.0,
                        3,
                    );
                } else {
                    crate::widgets::text_wrap(&p, pos2(left + sig_w + 10.0, r.top() + 102.0), &status, theme::font(13.0), theme::text_dim(), w - sig_w - 10.0, 16.0, 2);
                }

                let (first, second) = ask_buttons(THREAT_SIZE);
                let at = r.min.to_vec2();
                if let Some(act) = pending {
                    if toast::button(ui, first.translate(at), "confirm", "I'm sure", toast::Look::Danger) {
                        ev.get().threat_done = Some((id, Some(act)));
                    }
                    if toast::button(ui, second.translate(at), "cancel", "Cancel", toast::Look::Standard) {
                        ev.get().threat_confirm = Some((id, None));
                    }
                } else {
                    let (label, act, look) = if t.blocked { ("Unblock", ThreatAct::Unblock, toast::Look::Standard) } else { ("Block", ThreatAct::Block, toast::Look::Danger) };
                    if toast::button(ui, first.translate(at), "primary", label, look) {
                        if act == ThreatAct::Block { ev.get().threat_done = Some((id, Some(act))) } else { ev.get().threat_confirm = Some((id, Some(act))) }
                    }
                    if toast::button(ui, second.translate(at), "allow", "Whitelist", toast::Look::Standard) {
                        ev.get().threat_confirm = Some((id, Some(ThreatAct::Whitelist)));
                    }
                }
            });
            ctx.request_repaint_of(vid);
        }
    }
}
