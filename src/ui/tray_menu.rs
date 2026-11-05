//! The tray icon's right-click menu: a borderless always-on-top window drawn with the same rows as the
//! File menu, since a native Windows menu can't be styled or follow the UI scale.

use crate::app::{Dialog, RustWarden};
use crate::data::{FirewallMode, PROMPT_FOR, prompt_for_label};
use crate::icons::Icon;
use crate::settings::Theme;
use crate::theme;
use crate::widgets::{MENU_ROW_H, MENU_SEP_H, menu_row, menu_sep};
use egui::{Rect, Stroke, UiBuilder, ViewportBuilder, ViewportCommand, ViewportId, pos2, vec2};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WIDTH: f32 = 264.0;
const PAD: f32 = 6.0;
const GAP: f32 = 8.0;

pub struct TrayMenu {
    /// Where the tray was clicked, in physical pixels.
    at: (f32, f32),
    opened: Instant,
    focused: bool,
    themes_open: bool,
    protect_open: bool,
    prompt_open: bool,
    /// Talks to the menu window, which is a deferred viewport (an immediate one can't be drawn while the
    /// main window is hidden in the tray): `show_tray_menu` fills `snap`, the window fills `out`.
    shared: Arc<Mutex<Shared>>,
}

#[derive(Default)]
struct Shared {
    snap: Snap,
    out: Out,
}

#[derive(Default, Clone)]
struct Snap {
    themes_open: bool,
    protect_open: bool,
    prompt_open: bool,
    prompt_mins: u32,
    snoozed: bool,
    live: bool,
    /// The chosen theme; `None` is System.
    theme: Option<Theme>,
    /// The active mode; `None` while the firewall is disabled.
    fw_mode: Option<FirewallMode>,
    modes: [bool; 3],
}

#[derive(Default)]
struct Out {
    act: Option<TrayAct>,
    expand_themes: bool,
    expand_protect: bool,
    expand_prompt: bool,
    esc: bool,
    focused: bool,
}

impl TrayMenu {
    pub fn new(x: f32, y: f32) -> Self {
        Self { at: (x, y), opened: Instant::now(), focused: false, themes_open: false, protect_open: false, prompt_open: false, shared: Arc::default() }
    }
}

/// The work area (monitor minus taskbar) and DPI scale of the monitor under the click, in physical pixels.
/// Asked of Windows directly: egui's own scale can be stale while the main window is hidden.
fn monitor_at(x: f32, y: f32) -> (Rect, f32) {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint};
    use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
    unsafe {
        let mon = MonitorFromPoint(POINT { x: x as i32, y: y as i32 }, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO { cbSize: std::mem::size_of::<MONITORINFO>() as u32, ..Default::default() };
        let (mut dx, mut dy) = (96, 96);
        let _ = GetDpiForMonitor(mon, MDT_EFFECTIVE_DPI, &mut dx, &mut dy);
        if !GetMonitorInfoW(mon, &mut info).as_bool() {
            return (Rect::EVERYTHING, dx as f32 / 96.0);
        }
        let r = info.rcWork;
        (Rect::from_min_max(pos2(r.left as f32, r.top as f32), pos2(r.right as f32, r.bottom as f32)), dx as f32 / 96.0)
    }
}

pub(crate) enum TrayAct {
    Toggle,
    /// `None` is System (follow Windows).
    Theme(Option<Theme>),
    Settings,
    Alerts,
    Snooze,
    Restart,
    Exit,
    Mode(FirewallMode),
    Disable,
    PromptFor(u32),
}

impl RustWarden {
    pub(crate) fn show_tray_menu(&mut self, ctx: &egui::Context) {
        // A picked item runs one frame after the menu window is gone, not in the same pass that closes it.
        if let Some(act) = self.tray_act.take() {
            self.apply_tray_act(ctx, act);
        }
        let Some(menu) = &mut self.tray_menu else { return };
        let z = self.settings.text_scale;

        // What the window reported since the last frame.
        // `focused` stays as last reported: the window only redraws when something changes.
        let out = {
            let mut g = menu.shared.lock().unwrap_or_else(|e| e.into_inner());
            let focused = g.out.focused;
            Out { focused, ..std::mem::take(&mut g.out) }
        };
        menu.shared.lock().unwrap_or_else(|e| e.into_inner()).out.focused = out.focused;
        if out.expand_themes {
            menu.themes_open = !menu.themes_open;
        }
        if out.expand_protect {
            menu.protect_open = !menu.protect_open;
        }
        if out.expand_prompt {
            menu.prompt_open = !menu.prompt_open;
        }
        menu.focused |= out.focused;
        // Closes when it loses focus (a click elsewhere), or if it never got focus at all.
        let lost = !out.focused && (menu.focused || menu.opened.elapsed() > Duration::from_secs(1));
        if out.act.is_some() || out.esc || lost {
            self.tray_act = out.act;
            self.tray_menu = None;
            ctx.request_repaint();
            return;
        }

        let snap = Snap {
            themes_open: menu.themes_open,
            protect_open: menu.protect_open,
            prompt_open: menu.prompt_open,
            prompt_mins: self.settings.prompt_minutes,
            snoozed: self.backend.alerts_snoozed(),
            live: self.caps.live,
            theme: self.settings.theme_choice(),
            fw_mode: self.protect.info.enabled.then_some(self.protect.info.mode),
            modes: FirewallMode::ALL.map(|m| self.caps.mode_enabled(m)),
        };
        let rows = 9 + if snap.prompt_open { PROMPT_FOR.len() } else { 0 } + if snap.themes_open { 3 } else { 0 } + if snap.protect_open { FirewallMode::ALL.len() + 1 } else { 0 };
        let size = vec2(WIDTH, MENU_ROW_H * rows as f32 + MENU_SEP_H * 3.0 + PAD * 2.0) * z;
        menu.shared.lock().unwrap_or_else(|e| e.into_inner()).snap = snap;

        // Hangs above the click, clear of the taskbar: kept inside the work area (screen minus taskbar).
        let (work, native) = monitor_at(menu.at.0, menu.at.1);
        let (cx, cy) = (menu.at.0 / native, menu.at.1 / native);
        let work = Rect::from_min_max(work.min / native, work.max / native);
        let x = (cx - size.x / 2.0).clamp(work.left(), (work.right() - size.x).max(work.left()));
        let above = (cy - size.y).min(work.bottom() - size.y) - GAP;
        let y = if above >= work.top() { above } else { work.top() + GAP }; // taskbar at the top

        let id = ViewportId::from_hash_of("tray_menu");
        let builder = ViewportBuilder::default()
            .with_title("RustWarden menu")
            // egui multiplies by the zoom itself, so size and position go in as points, not screen pixels.
            .with_inner_size(size / z)
            .with_position(pos2(x, y) / z)
            .with_decorations(false)
            .with_resizable(false)
            .with_always_on_top()
            .with_taskbar(false)
            .with_transparent(true);
        let shared = menu.shared.clone();
        ctx.show_viewport_deferred(id, builder, move |ui, _class| {
            let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
            let Shared { snap, out } = &mut *g;
            out.focused = ui.input(|i| i.focused);
            out.esc |= ui.input(|i| i.key_pressed(egui::Key::Escape));
            let r = ui.max_rect();
            ui.painter().rect_filled(r, 10, theme::surface().to_opaque());
            ui.painter().rect_stroke(r, 10, Stroke::new(1.0, theme::border()), egui::epaint::StrokeKind::Inside);
            ui.scope_builder(UiBuilder::new().max_rect(r.shrink(PAD)), |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                if menu_row(ui, Some(Icon::Laptop), "Show/Hide RustWarden", "", false, true).clicked() {
                    out.act = Some(TrayAct::Toggle);
                }
                menu_sep(ui);
                out.expand_themes |= menu_row(ui, Some(Icon::Bulb), "Theme", "", true, true).clicked();
                if snap.themes_open {
                    for t in [None, Some(Theme::Light), Some(Theme::Dark)] {
                        let icon = (t == snap.theme).then_some(Icon::Check);
                        if menu_row(ui, icon, t.map_or("System", Theme::label), "", false, true).clicked() {
                            out.act = Some(TrayAct::Theme(t));
                        }
                    }
                }
                menu_sep(ui);
                if menu_row(ui, Some(Icon::Warning), "Alerts", "", false, true).clicked() {
                    out.act = Some(TrayAct::Alerts);
                }
                if menu_row(ui, Some(Icon::Sliders), "Settings...", "", false, true).clicked() {
                    out.act = Some(TrayAct::Settings);
                }
                if menu_row(ui, Some(Icon::Bell), "Snooze alerts", if snap.snoozed { "On" } else { "Off" }, false, snap.live).clicked() {
                    out.act = Some(TrayAct::Snooze);
                }
                out.expand_protect |= menu_row(ui, Some(Icon::Shield), "Firewall", "", true, true).clicked();
                if snap.protect_open {
                    for (m, on) in FirewallMode::ALL.into_iter().zip(snap.modes) {
                        let icon = (Some(m) == snap.fw_mode).then_some(Icon::Check);
                        if menu_row(ui, icon, m.label(), "", false, on).clicked() {
                            out.act = Some(TrayAct::Mode(m));
                        }
                    }
                    let icon = snap.fw_mode.is_none().then_some(Icon::Check);
                    if menu_row(ui, icon, "Disable", "", false, true).clicked() {
                        out.act = Some(TrayAct::Disable);
                    }
                }
                out.expand_prompt |= menu_row(ui, Some(Icon::Click), "Prompt for", &prompt_for_label(snap.prompt_mins), true, true).clicked();
                if snap.prompt_open {
                    for m in PROMPT_FOR {
                        let icon = (m == snap.prompt_mins).then_some(Icon::Check);
                        if menu_row(ui, icon, &prompt_for_label(m), "", false, true).clicked() {
                            out.act = Some(TrayAct::PromptFor(m));
                        }
                    }
                }
                menu_sep(ui);
                if menu_row(ui, Some(Icon::Restart), "Restart service", "", false, true).clicked() {
                    out.act = Some(TrayAct::Restart);
                }
                if menu_row(ui, Some(Icon::Close), "Exit", "", false, true).clicked() {
                    out.act = Some(TrayAct::Exit);
                }
            });
            // The main window does the work and may be hidden in the tray, so wake it.
            ui.ctx().request_repaint_of(ViewportId::ROOT);
        });
        if !menu.focused {
            ctx.send_viewport_cmd_to(id, ViewportCommand::Focus);
        }
        ctx.request_repaint_after(Duration::from_millis(100));
    }

    fn apply_tray_act(&mut self, ctx: &egui::Context, act: TrayAct) {
        let snoozed = self.backend.alerts_snoozed();
        match act {
            TrayAct::Toggle => {
                // A minimised window is still "visible"; clicking should bring it back.
                let minimized = ctx.input(|i| i.viewport().minimized.unwrap_or(false));
                self.show_window(ctx, !self.window_visible || minimized);
            }
            TrayAct::Theme(theme) => {
                let mut s = self.settings.clone();
                s.set_theme_choice(theme);
                self.apply_settings(ctx, s);
                // An open Settings dialog would put its old theme back on OK.
                if let Some(Dialog::Settings(draft)) = &mut self.dialog {
                    draft.set_theme_choice(theme);
                }
            }
            TrayAct::Alerts => {
                self.show_window(ctx, true);
                self.tab = crate::app::Tab::Log;
            }
            TrayAct::Settings => {
                self.show_window(ctx, true);
                self.open_settings();
            }
            TrayAct::Snooze if snoozed => {
                self.backend.snooze_alerts(0);
                self.notify("Alert snooze ended");
            }
            TrayAct::Snooze => {
                self.backend.snooze_alerts(60);
                self.notify("Alerts snoozed for 1 hour");
            }
            TrayAct::Mode(mode) => {
                self.change_mode(mode);
                // A confirmation dialog lives in the main window.
                if self.dialog.is_some() {
                    self.show_window(ctx, true);
                }
            }
            TrayAct::Disable => {
                if self.protect.info.enabled {
                    self.toggle_firewall(false);
                }
                // A confirmation dialog lives in the main window.
                if self.dialog.is_some() {
                    self.show_window(ctx, true);
                }
            }
            TrayAct::PromptFor(m) => self.set_prompt_minutes(m),
            TrayAct::Restart => {
                self.restart_app(ctx);
                self.show_password(ctx);
            }
            TrayAct::Exit => {
                self.request_exit(ctx);
                self.show_password(ctx);
            }
        }
    }
}
