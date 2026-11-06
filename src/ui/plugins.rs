//! Settings > Plugins: System and Notification plugins. The built-in ones keep their tables until they
//! are ported; `.wasm` plugin files are listed below them, with approve, enable, settings and remove.

use crate::plugins::core;
use crate::plugins::wasm::manager::{self, Found};
use crate::settings::{PluginState, Settings};
use crate::widgets;
use egui::{Ui, vec2};
use plugin_sdk::Kind;
use std::path::PathBuf;

/// The one dialog open on this page, kept in egui's temp data.
#[derive(Clone)]
enum Modal {
    Approve { id: String, grant: Vec<bool> },
    Settings(String),
    Permissions(String),
    Remove { path: Option<PathBuf>, id: Option<String>, name: String, data: bool },
    Install(String),
}

fn modal_id() -> egui::Id {
    egui::Id::NULL.with("plugins_modal")
}

fn set_modal(ctx: &egui::Context, m: Option<Modal>) {
    ctx.data_mut(|d| d.insert_temp(modal_id(), m));
}

pub fn section(ui: &mut Ui, s: &mut Settings) {
    let id = ui.scope_id().with("plugins_tab");
    let mut tab: usize = ui.data_mut(|d| d.get_temp(id).unwrap_or(0));
    ui.horizontal(|ui| {
        widgets::segmented_text(ui, &mut tab, &["System Plugins", "Notification Plugins"]);
    });
    ui.add_space(6.0);
    ui.data_mut(|d| d.insert_temp(id, tab));
    if tab == 0 {
        ui.label("Connect other systems to RustWarden. Built-in plugins are switched on here; your own .wasm plugins are added with Install from file.");
    } else {
        notification_options(ui, s)
    }
    ui.add_space(12.0);
    files(ui, s, if tab == 0 { Kind::System } else { Kind::Notification });
    modal(ui.ctx(), s);
}

/// What an opt-in permission lets the plugin do, in the words of the approval dialog.
fn perm_text(p: &str) -> &'static str {
    match p {
        "ping" => "Send pings (ICMP) to addresses you enter",
        "alerts.read" => "Read your alerts, and send them on to the sites it may contact",
        "devices.annotate" => "Read the devices found by the network scan and add names or badges to them",
        "programs.hash" => "See the file hash and name of programs that use the network",
        "helper.exe" => "Download a helper program and run it",
        "browser.session" => "Open a sign-in window for its site and fetch pages from it",
        "firewall.blocks.read" => "Read RustWarden's list of blocked addresses",
        _ => "A permission this version of RustWarden doesn't know",
    }
}

/// The `.wasm` plugins of one kind: the built-in ones, then files from the plugin folder.
fn files(ui: &mut Ui, s: &mut Settings, kind: Kind) {
    let view = manager::view();
    let query_id = ui.scope_id().with("plugin_search");
    let mut query: String = ui.data_mut(|d| d.get_temp(query_id).unwrap_or_default());
    let q = query.trim().to_lowercase();
    let gone = |f: &Found| s.plugins.get(&f.manifest.id).is_some_and(|x| x.removed);
    let mut mine: Vec<&Found> = view.found.iter().filter(|f| f.manifest.kind == kind && !gone(f)).collect();
    mine.sort_by_cached_key(|f| f.manifest.name.to_lowercase());
    let removed: Vec<&Found> = view.found.iter().filter(|f| f.manifest.kind == kind && gone(f)).collect();
    let total = mine.len();
    mine.retain(|f| q.is_empty() || f.manifest.name.to_lowercase().contains(&q) || f.manifest.id.contains(&q));
    let mut open: Option<Modal> = None;
    ui.add(egui::TextEdit::singleline(&mut query).hint_text("Search plugins").desired_width(260.0));
    ui.data_mut(|d| d.insert_temp(query_id, query));
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(if kind == Kind::System { "System plugins" } else { "Notification plugins" }).strong());
        if view.scanning {
            ui.weak("Scanning…");
        }
        if ui.button("Refresh").clicked() {
            manager::scan();
        }
        if ui.button("Install from file…").clicked() {
            open = Some(Modal::Install(String::new()));
        }
    });
    if !view.message.is_empty() {
        ui.label(&view.message);
    }
    if mine.is_empty() {
        ui.weak(if view.scanning {
            "Looking for plugins…"
        } else if total > 0 {
            "No plugin matches your search."
        } else {
            "No plugins of this kind are installed."
        });
    }
    for f in &mine {
        let m = &f.manifest;
        let first_party = f.first_party();
        let approved = first_party || s.plugins.get(&m.id).is_some_and(|x| x.approved_hash == f.hash);
        // Approved once, but the file is a different one now.
        let changed = !approved && s.plugins.get(&m.id).is_some_and(|x| !x.approved_hash.is_empty());
        ui.horizontal(|ui| {
            match core::texture(ui.ctx(), &format!("plugin-icon-{}", f.hash), &m.icon) {
                Some(t) => {
                    ui.add(egui::Image::new((t.id(), vec2(20.0, 20.0))));
                }
                None => {
                    ui.allocate_space(vec2(20.0, 20.0));
                }
            }
            ui.vertical(|ui| {
                ui.set_width(250.0);
                ui.label(egui::RichText::new(&m.name).strong());
                ui.weak(if first_party { format!("v{} · built in", m.version) } else { format!("v{} by {}", m.version, m.author) });
                if changed {
                    ui.colored_label(crate::theme::orange(), "⚠ The file changed: approve it again");
                } else if !approved {
                    ui.colored_label(crate::theme::orange(), "⚠ Third-party plugin: needs your approval");
                }
            });
            if approved {
                let mut on = s.plugins.get(&m.id).is_some_and(|x| x.enabled);
                ui.scope(|ui| {
                    ui.set_min_width(110.0);
                    if widgets::switch(ui, &mut on, if manager::running(&m.id) { "Running" } else { "Off" }).changed() {
                        s.plugins.entry(m.id.clone()).or_default().enabled = on;
                        // Starts (or stops) it now, so its settings can be opened before Save.
                        manager::preview(&s.plugins);
                    }
                });
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(path) = f.path() {
                    if ui.button("Remove").clicked() {
                        open = Some(Modal::Remove { path: Some(path.to_owned()), id: Some(m.id.clone()), name: m.name.clone(), data: false });
                    }
                } else if ui.button("Uninstall").on_hover_text("Hides it and switches it off. It can be restored from the list at the bottom.").clicked() {
                    open = Some(Modal::Remove { path: None, id: Some(m.id.clone()), name: m.name.clone(), data: false });
                }
                if !approved && ui.button("Review…").clicked() {
                    open = Some(Modal::Approve { id: m.id.clone(), grant: vec![false; m.permissions.len()] });
                }
                if approved && m.settings_page && ui.add_enabled(manager::running(&m.id), egui::Button::new("Settings")).clicked() {
                    open = Some(Modal::Settings(m.id.clone()));
                }
                if ui.button("Permissions").clicked() {
                    open = Some(Modal::Permissions(m.id.clone()));
                }
            });
        });
        ui.separator();
    }
    if !removed.is_empty() {
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Uninstalled").strong());
        for f in removed {
            ui.horizontal(|ui| {
                ui.label(&f.manifest.name);
                if ui.button("Restore").clicked() {
                    s.plugins.entry(f.manifest.id.clone()).or_default().removed = false;
                    manager::preview(&s.plugins);
                }
            });
        }
    }
    // Files that didn't load: shown once, under the System page only.
    if kind == Kind::System {
        for (path, err) in &view.bad {
            ui.horizontal(|ui| {
                ui.colored_label(crate::theme::red(), format!("⚠ {}: {err}", path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
                if ui.button("Remove").clicked() {
                    open = Some(Modal::Remove { path: Some(path.clone()), id: None, name: path.display().to_string(), data: false });
                }
            });
        }
    }
    if open.is_some() {
        set_modal(ui.ctx(), open);
    }
}

/// What every notification plugin shares: when alerts are sent, the weekly summary and a test alert.
fn notification_options(ui: &mut Ui, s: &mut Settings) {
    ui.label("Alerts are sent to every notification plugin that is switched on, for each alert type that has \"Send External Notifications\" ticked. Keys and webhook addresses are stored encrypted for your Windows account.");
    ui.add_space(8.0);
    widgets::switch(ui, &mut s.api_in_snooze, "Keep sending to these services while alerts are snoozed");
    widgets::switch(ui, &mut s.report, "Send a weekly summary to these services");
    ui.add_enabled_ui(s.report, |ui| {
        ui.horizontal(|ui| {
            const DAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
            egui::ComboBox::from_id_salt("report_weekday").selected_text(DAYS[usize::from(s.report_weekday.min(6))]).show_ui(ui, |ui| {
                for (i, day) in DAYS.iter().enumerate() {
                    ui.selectable_value(&mut s.report_weekday, i as u8, *day);
                }
            });
            ui.label("at");
            ui.add(egui::DragValue::new(&mut s.report_hour).range(0..=23).suffix(":00"));
        });
    });
    if ui.button("Send test alert").clicked() {
        manager::broadcast_alert(false, "RustWarden test", "This is a test alert from RustWarden.");
    }
    ui.add_space(12.0);
}

/// The dialog windows are see-through (like the main window), so their content sits on a card.
fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    egui::Frame::NONE.fill(crate::theme::card()).stroke(egui::Stroke::new(1.0, crate::theme::card_edge())).corner_radius(8).inner_margin(egui::Margin::same(14)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui);
    });
}

fn modal(ctx: &egui::Context, s: &mut Settings) {
    let Some(mut m) = ctx.data(|d| d.get_temp::<Option<Modal>>(modal_id())).flatten() else { return };
    let view = manager::view();
    let mut close = false;
    match &mut m {
        Modal::Approve { id, grant } => match view.found.iter().find(|f| f.manifest.id == *id) {
            None => close = true,
            Some(f) => {
                let man = &f.manifest;
                let mut approve = false;
                if !widgets::dialog(&format!("Approve {}", man.name)).show(ctx, |ui| {
                    ui.set_width(460.0);
                    ui.spacing_mut().item_spacing.y = 6.0;
                    ui.heading(&man.name);
                    ui.weak(format!("Version {} by {}", man.version, man.author));
                    ui.colored_label(crate::theme::orange(), "⚠ This plugin isn't from RustWarden. It runs in a sandbox and can only do what is listed here.");
                    ui.label(if man.http_hosts.is_empty() {
                        "It can't contact any website.".to_owned()
                    } else if man.http_hosts.iter().any(|h| h == "*") {
                        "It can contact any website whose address you give it (for a server you run yourself).".to_owned()
                    } else {
                        format!("It can contact: {}", man.http_hosts.join(", "))
                    });
                    if man.allow_insecure_tls {
                        ui.colored_label(
                            crate::theme::orange(),
                            "⚠ It can accept a server's own (self-signed) certificate, which anyone on that network could imitate. Only for a router or server you run yourself.",
                        );
                    }
                    if man.permissions.is_empty() {
                        ui.label("It asks for no extra permissions.");
                    } else {
                        ui.label("Extra permissions it asks for (tick the ones you allow):");
                        for (i, p) in man.permissions.iter().enumerate() {
                            ui.checkbox(&mut grant[i], format!("{p}: {}", perm_text(p)));
                        }
                    }
                    ui.label("File fingerprint (SHA-256):");
                    ui.monospace(&f.hash);
                    ui.horizontal(|ui| {
                        if ui.button("Approve and turn on").clicked() {
                            approve = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }) {
                    close = true;
                }
                if approve {
                    let granted = man.permissions.iter().zip(grant.iter()).filter(|(_, g)| **g).map(|(p, _)| p.clone()).collect();
                    s.plugins.insert(man.id.clone(), PluginState { enabled: true, approved_hash: f.hash.clone(), granted, removed: false });
                    close = true;
                }
            }
        },
        Modal::Settings(id) => {
            let name = view.found.iter().find(|f| f.manifest.id == *id).map(|f| f.manifest.name.clone()).unwrap_or_default();
            if !widgets::dialog(&format!("{name} settings")).show(ctx, |ui| {
                ui.set_width(460.0);
                card(ui, |ui| manager::page(ui, id, manager::SETTINGS_KEY, None));
                ui.add_space(6.0);
                if ui.button("Close").clicked() {
                    close = true;
                }
            }) {
                close = true;
            }
        }
        Modal::Permissions(id) => match view.found.iter().find(|f| f.manifest.id == *id) {
            None => close = true,
            Some(f) => {
                let man = &f.manifest;
                let granted: Vec<String> = if f.first_party() { man.permissions.clone() } else { s.plugins.get(&man.id).map(|x| x.granted.clone()).unwrap_or_default() };
                if !widgets::dialog(&format!("{} permissions", man.name)).show(ctx, |ui| {
                    ui.set_width(460.0);
                    card(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 6.0;
                        ui.label(if man.http_hosts.is_empty() {
                            "It can't contact any website.".to_owned()
                        } else if man.http_hosts.iter().any(|h| h == "*") {
                            "It can contact any website whose address you give it.".to_owned()
                        } else {
                            format!("It can contact: {}", man.http_hosts.join(", "))
                        });
                        if man.allow_insecure_tls {
                            ui.colored_label(crate::theme::orange(), "⚠ It can accept a server's own (self-signed) certificate.");
                        }
                        if man.permissions.is_empty() {
                            ui.label("It uses no extra permissions.");
                        }
                        for p in &man.permissions {
                            let on = granted.contains(p);
                            ui.label(format!("{} {p}: {}", if on { "✔" } else { "✖" }, perm_text(p)));
                        }
                    });
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                }) {
                    close = true;
                }
            }
        },
        Modal::Remove { path, id, name, data } => {
            let mut remove = false;
            if !widgets::dialog("Remove plugin").show(ctx, |ui| {
                ui.set_width(440.0);
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.label(if path.is_some() { format!("Remove {name}? Its file is deleted.") } else { format!("Uninstall {name}? It is switched off and hidden; you can restore it later.") });
                if id.is_some() {
                    ui.checkbox(data, "Remove Plugin Data (its settings, saved secrets and stored data)");
                }
                if path.is_some() {
                    ui.weak("Removing needs administrator rights.");
                }
                ui.horizontal(|ui| {
                    if ui.button(if path.is_some() { "Remove" } else { "Uninstall" }).clicked() {
                        remove = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            }) {
                close = true;
            }
            if remove {
                match (path, id) {
                    (Some(path), id) => {
                        manager::remove(path.clone(), id.clone(), *data);
                        if let Some(id) = id {
                            s.plugins.remove(id);
                        }
                    }
                    // A built-in plugin has no file: hide it, and clear its data if asked.
                    (None, Some(id)) => {
                        let e = s.plugins.entry(id.clone()).or_default();
                        (e.removed, e.enabled) = (true, false);
                        manager::preview(&s.plugins);
                        if *data {
                            manager::erase(id.clone());
                        }
                    }
                    (None, None) => {}
                }
                close = true;
            }
        }
        Modal::Install(path) => {
            let mut install = false;
            if !widgets::dialog("Install plugin").show(ctx, |ui| {
                ui.set_width(460.0);
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.label("Path of the plugin (.wasm file) to install:");
                ui.add(egui::TextEdit::singleline(path).desired_width(440.0).hint_text(r"C:\Users\you\Downloads\plugin.wasm"));
                ui.weak("It is copied into the plugin folder (administrator rights needed) and then waits for your approval. Nothing runs until you approve it.");
                ui.horizontal(|ui| {
                    if ui.add_enabled(!path.trim().is_empty(), egui::Button::new("Install")).clicked() {
                        install = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            }) {
                close = true;
            }
            if install {
                manager::install(path);
                close = true;
            }
        }
    }
    set_modal(ctx, if close { None } else { Some(m) });
}
