//! The Ping tab (the shared latency charts fed from `ping_samples`) and its Add host and Manage hosts windows.

use super::worker;
use crate::app::RustWarden;
use crate::live::db::Db;
use crate::plugins::core::latency::{self, Feed, Line, Sample};
use crate::settings::Mode;
use crate::widgets;
use std::sync::atomic::Ordering;

#[derive(Default)]
pub struct Dlg {
    /// The Add host window with its (host, name) fields.
    pub add: Option<(String, String)>,
    pub manage: bool,
}

/// The stored ping rounds and the ping worker's state; in Demo mode, made-up rounds instead.
struct Pings {
    demo: bool,
}

impl Feed for Pings {
    fn refreshing(&self) -> bool {
        worker::REFRESHING.load(Ordering::Relaxed)
    }
    fn sync_now(&self) {
        worker::SYNC_NOW.store(true, Ordering::Relaxed);
    }
    fn last_ok(&self) -> i64 {
        if self.demo { crate::clock::now_unix() } else { worker::LAST_OK.load(Ordering::Relaxed) }
    }
    fn demo(&self, id: u32, since: i64, until: i64) -> Option<Vec<Sample>> {
        self.demo.then(|| super::demo_samples(id, since, until))
    }
    fn load(&self, db: &Db, id: u32, since: i64) -> rusqlite::Result<Vec<Sample>> {
        db.ping_since(id, since)
    }
    fn refresh_hint(&self) -> &'static str {
        "Ping the hosts now"
    }
    fn empty(&self, live: bool, no_lines: bool, day: bool) -> &'static str {
        match (live, no_lines, day) {
            (false, ..) => "Ping data is collected in Live mode.",
            (true, true, _) => "No hosts yet. Press Add host to start pinging one.",
            (true, false, true) => "No pings were recorded on this day.",
            (true, false, false) => "No pings yet; the first result appears within a few seconds.",
        }
    }
}

impl RustWarden {
    pub(crate) fn ping_tab(&mut self, ui: &mut egui::Ui) {
        let live = self.settings.mode == Mode::Live;
        let lines: Vec<Line> = self.settings.ping.hosts.iter().map(|h| Line { id: h.id, name: h.label().to_owned() }).collect();
        let cfg = &mut self.settings.ping;
        let dlg = &mut self.ping_dlg;
        let tools = |ui: &mut egui::Ui| {
            if widgets::pill_button(ui, None, "+", false, 36.0).on_hover_text("Add host").clicked() {
                dlg.add = Some(Default::default());
            }
            if widgets::pill_button(ui, Some(crate::icons::Icon::Sliders), "", false, 36.0).on_hover_text("Manage hosts").clicked() {
                dlg.manage = true;
            }
        };
        if latency::tab(ui, &mut self.ping_view, &lines, &Pings { demo: !live }, live, (&mut cfg.layout, &mut cfg.range), tools)
            && let Err(e) = self.settings.save()
        {
            self.notify(&format!("Couldn't save settings: {e}"));
        }
        if let Some(m) = self.ping_view.take_saved() {
            self.notify(&m);
        }
    }

    pub(crate) fn show_ping_dialogs(&mut self, ctx: &egui::Context) {
        let mut changed = false;
        if let Some((address, name)) = &mut self.ping_dlg.add {
            let mut done = false;
            let open = crate::widgets::dialog("Add host").show(ctx, |ui| {
                ui.set_width(320.0);
                ui.label("Host name or IP address");
                let r = ui.add(egui::TextEdit::singleline(address).desired_width(f32::INFINITY));
                widgets::edit_menu(ui, &r, address, false);
                if ui.memory(|m| m.focused().is_none()) {
                    r.request_focus(); // only the first frame, so clicking the label box keeps its focus
                }
                ui.label("Label (optional)");
                let rn = ui.add(egui::TextEdit::singleline(name).desired_width(f32::INFINITY));
                widgets::edit_menu(ui, &rn, name, false);
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let ready = !address.trim().is_empty();
                if (ui.add_enabled(ready, egui::Button::new("Add")).clicked() || enter) && ready {
                    self.settings.ping.add(name, address);
                    (changed, done) = (true, true);
                }
            });
            if done || !open {
                self.ping_dlg.add = None;
            }
        }
        if self.ping_dlg.manage {
            let open = crate::widgets::dialog("Manage hosts").show(ctx, |ui| {
                ui.set_width(420.0);
                if self.settings.ping.hosts.is_empty() {
                    ui.label("No hosts yet.");
                }
                let mut remove = None;
                for (i, h) in self.settings.ping.hosts.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        let ra = ui.add(egui::TextEdit::singleline(&mut h.address).desired_width(160.0));
                        widgets::edit_menu(ui, &ra, &mut h.address, false);
                        let rl = ui.add(egui::TextEdit::singleline(&mut h.name).hint_text("Label").desired_width(140.0));
                        widgets::edit_menu(ui, &rl, &mut h.name, false);
                        changed |= ra.changed() | rl.changed();
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                    });
                }
                if let Some(i) = remove {
                    self.settings.ping.hosts.remove(i);
                    changed = true;
                }
                if ui.button("Add host").clicked() {
                    self.ping_dlg.add = Some(Default::default());
                }
            });
            self.ping_dlg.manage = open && self.ping_dlg.manage;
        }
        if changed {
            if let Err(e) = self.settings.save() {
                self.notify(&format!("Couldn't save settings: {e}"));
            }
            self.backend.apply_settings(&self.settings);
        }
    }
}
