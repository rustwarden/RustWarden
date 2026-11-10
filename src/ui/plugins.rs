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
    Approve {
        id: String,
        grant: Vec<bool>,
    },
    Settings(String),
    Permissions(String),
    Remove {
        path: Option<PathBuf>,
        id: Option<String>,
        name: String,
        data: bool,
    },
    Install(String),
    /// Uninstalled built-in plugins to bring back: (id, name, ticked).
    Reinstall(Vec<(String, String, bool)>),
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

/// Logo for a built-in plugin that ships no image: the old painted marks (the app carries no image assets for them).
/// Third-party plugins with no icon get a plug.
fn mark(ui: &mut Ui, id: &str) {
    use crate::icons::{self, Icon};
    use egui::{Color32, Rect, Shape, Stroke};
    let (rect, _) = ui.allocate_exact_size(vec2(20.0, 20.0), egui::Sense::hover());
    let p = ui.painter();
    let (s, c) = (rect.width(), rect.center());
    let u = |x: f32, y: f32| rect.min + vec2(x * s, y * s);
    let rgb = Color32::from_rgb;
    let white = Color32::WHITE;
    let stroke = Stroke::new(s * 0.1, white);
    match id {
        "discord" => {
            let blurple = rgb(0x58, 0x65, 0xF2);
            p.rect_filled(rect, 5.0, blurple);
            p.rect_filled(Rect::from_min_max(u(0.15, 0.28), u(0.85, 0.72)), s * 0.2, white);
            for x in [0.36, 0.64] {
                p.circle_filled(u(x, 0.5), s * 0.08, blurple);
            }
        }
        "slack" => {
            for (x, y, col) in [(0.3, 0.2, rgb(0x36, 0xC5, 0xF0)), (0.8, 0.3, rgb(0x2E, 0xB6, 0x7D)), (0.7, 0.8, rgb(0xEC, 0xB2, 0x2E)), (0.2, 0.7, rgb(0xE0, 0x1E, 0x5A))] {
                p.rect_filled(Rect::from_center_size(u(x, y), vec2(s * 0.22, s * 0.22)), s * 0.11, col);
            }
            for (x, y, w, h, col) in
                [(0.5, 0.35, 0.4, 0.2, rgb(0x36, 0xC5, 0xF0)), (0.65, 0.5, 0.2, 0.4, rgb(0x2E, 0xB6, 0x7D)), (0.5, 0.65, 0.4, 0.2, rgb(0xEC, 0xB2, 0x2E)), (0.35, 0.5, 0.2, 0.4, rgb(0xE0, 0x1E, 0x5A))]
            {
                p.rect_filled(Rect::from_center_size(u(x, y), vec2(s * w, s * h)), s * 0.1, col);
            }
        }
        "pushbullet" => {
            p.circle_filled(c, s * 0.5, rgb(0x4A, 0xB3, 0x67));
            p.rect_filled(Rect::from_min_max(u(0.3, 0.25), u(0.42, 0.75)), 1.0, white);
            p.rect_filled(Rect::from_min_max(u(0.5, 0.25), u(0.7, 0.75)), s * 0.1, white);
        }
        "ntfy" => {
            p.rect_filled(rect, 5.0, rgb(0x33, 0x85, 0x74));
            p.add(Shape::line(vec![u(0.24, 0.3), u(0.46, 0.5), u(0.24, 0.7)], stroke));
            p.line_segment([u(0.52, 0.72), u(0.78, 0.72)], stroke);
        }
        "gotify" => {
            p.circle_filled(c, s * 0.5, rgb(0x3F, 0x8C, 0xBF));
            icons::paint(p, Icon::Bell, Rect::from_center_size(c, vec2(s * 0.6, s * 0.6)), white);
        }
        "webhook" => icons::paint(p, Icon::Globe, rect, crate::theme::accent()),
        "ping" => icons::paint(p, Icon::Wave, rect, crate::theme::accent()),
        "speedtest" => icons::paint(p, Icon::Traffic, rect, crate::theme::accent()),
        "virustotal" => icons::paint(p, Icon::Shield, rect, crate::theme::red()),
        "opnsense" => icons::paint(p, Icon::Shield, rect, crate::theme::brand_orange()),
        _ => icons::paint(p, Icon::Plug, rect, crate::theme::accent()),
    }
}

/// What an opt-in permission lets the plugin do, in the words of the approval dialog.
fn perm_text(p: &str) -> &'static str {
    match p {
        "ping" => "Send pings (ICMP) to addresses you enter",
        "alerts.read" => "Read your alerts, and send them on to the sites it may contact",
        "alerts.write" => "Raise alerts of its own (shown, logged and sent on like RustWarden's own)",
        "devices.annotate" => "Read the devices found by the network scan and add names or badges to them",
        "upnp" => "Find your router and open or close ports on it with UPnP",
        "metrics.serve" => "Serve RustWarden's metrics on this computer (127.0.0.1) at the port you set",
        "programs.hash" => "See the file hash and name of programs that use the network",
        "helper.exe" => "Download a helper program and run it",
        "browser.session" => "Open a sign-in window for its site and fetch pages from it",
        "firewall.blocks.read" => "Read RustWarden's list of blocked addresses",
        _ => "A permission this version of RustWarden doesn't know",
    }
}

/// The plugin SDK walkthrough on GitHub (Settings > Plugins > Create a Plugin).
const CREATE_URL: &str = "https://github.com/rustwarden/RustWarden/blob/main/plugin-sdk/CREATING_A_PLUGIN.md";

fn beta_hidden(f: &Found) -> bool {
    f.manifest.hidden && f.first_party()
}

/// Hidden (beta) plugins are listed once "beta" is typed; one already switched on stays listed so it can be managed.
fn listed(f: &Found, s: &Settings) -> bool {
    !beta_hidden(f) || s.beta_plugins || s.plugins.get(&f.manifest.id).is_some_and(|x| x.enabled)
}

/// "beta" + Enter in a search box: brings the hidden plugins back, or uninstalls and hides them again.
fn toggle_beta(s: &mut Settings, found: &[Found]) {
    s.beta_plugins = !s.beta_plugins;
    let on = s.beta_plugins;
    for f in found.iter().filter(|f| beta_hidden(f)) {
        let e = s.plugins.entry(f.manifest.id.clone()).or_default();
        if on {
            e.removed = false;
        } else {
            (e.removed, e.enabled) = (true, false);
        }
    }
}

/// The `.wasm` plugins of one kind: the built-in ones, then files from the plugin folder.
fn files(ui: &mut Ui, s: &mut Settings, kind: Kind) {
    let view = manager::view();
    let query_id = ui.scope_id().with("plugin_search");
    let mut query: String = ui.data_mut(|d| d.get_temp(query_id).unwrap_or_default());
    let q = query.trim().to_lowercase();
    let gone = |f: &Found| s.plugins.get(&f.manifest.id).is_some_and(|x| x.removed);
    let mut mine: Vec<&Found> = view.found.iter().filter(|f| f.manifest.kind == kind && !gone(f) && listed(f, s)).collect();
    mine.sort_by_cached_key(|f| f.manifest.name.to_lowercase());
    let removed: Vec<&Found> = view.found.iter().filter(|f| f.manifest.kind == kind && gone(f) && listed(f, s)).collect();
    let total = mine.len();
    mine.retain(|f| q.is_empty() || f.manifest.name.to_lowercase().contains(&q) || f.manifest.id.contains(&q));
    let mut open: Option<Modal> = None;
    let resp = ui.add(egui::TextEdit::singleline(&mut query).hint_text("Search plugins").desired_width(260.0));
    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && query.trim().eq_ignore_ascii_case("beta") {
        toggle_beta(s, &view.found);
        manager::preview(&s.plugins);
        query.clear();
        ui.ctx().request_repaint();
    }
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
        if ui.button("Create a Plugin").on_hover_text(CREATE_URL).clicked() {
            crate::sys::open_url(CREATE_URL);
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
                    mark(ui, &m.id);
                }
            }
            ui.vertical(|ui| {
                ui.set_width(250.0);
                ui.label(egui::RichText::new(&m.name).strong());
                ui.weak(if first_party { format!("v{} · built in", m.version) } else { format!("v{} by {}", m.version, m.author) });
                if changed {
                    crate::plugins::wasm::ui_tree::flag(ui, crate::theme::orange(), "The file changed: approve it again");
                } else if !approved {
                    crate::plugins::wasm::ui_tree::flag(ui, crate::theme::orange(), "Third-party plugin: needs your approval");
                }
            });
            if approved {
                let mut on = s.plugins.get(&m.id).is_some_and(|x| x.enabled);
                ui.scope(|ui| {
                    if widgets::switch(ui, &mut on, "").changed() {
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
        ui.horizontal(|ui| {
            ui.weak(format!("{} built-in plugin(s) uninstalled", removed.len()));
            if ui.button("Reinstall default plugins…").clicked() {
                open = Some(Modal::Reinstall(removed.iter().map(|f| (f.manifest.id.clone(), f.manifest.name.clone(), true)).collect()));
            }
        });
    }
    // Files that didn't load: shown once, under the System page only.
    if kind == Kind::System {
        for (path, err) in &view.bad {
            ui.horizontal(|ui| {
                crate::plugins::wasm::ui_tree::flag(ui, crate::theme::red(), &format!("{}: {err}", path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
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
    ui.label("Alerts are sent to every notification plugin that is switched on, for each alert type that has \"Send to Notification Plugins\" ticked. Keys and webhook addresses are stored encrypted for your Windows account.");
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
                    crate::plugins::wasm::ui_tree::flag(ui, crate::theme::orange(), "This plugin isn't from RustWarden. It runs in a sandbox and can only do what is listed here.");
                    ui.label(if man.http_hosts.is_empty() {
                        "It can't contact any website.".to_owned()
                    } else if man.http_hosts.iter().any(|h| h == "*") {
                        "It can contact any website whose address you give it (for a server you run yourself).".to_owned()
                    } else {
                        format!("It can contact: {}", man.http_hosts.join(", "))
                    });
                    if man.allow_insecure_tls {
                        crate::plugins::wasm::ui_tree::flag(
                            ui,
                            crate::theme::orange(),
                            "It can accept a server's own (self-signed) certificate, which anyone on that network could imitate. Only for a router or server you run yourself.",
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
                            crate::plugins::wasm::ui_tree::flag(ui, crate::theme::orange(), "It can accept a server's own (self-signed) certificate.");
                        }
                        if man.permissions.is_empty() {
                            ui.label("It uses no extra permissions.");
                        }
                        for p in &man.permissions {
                            let on = granted.contains(p);
                            ui.label(format!("{p}: {} ({})", perm_text(p), if on { "allowed" } else { "not allowed" }));
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
        Modal::Reinstall(items) => {
            let mut go = false;
            if !widgets::dialog("Reinstall default plugins").show(ctx, |ui| {
                ui.set_width(420.0);
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.label("These built-in plugins were uninstalled. Tick the ones to bring back; they return switched off, with the settings and data they had if you kept them.");
                egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                    for (_, name, on) in items.iter_mut() {
                        widgets::switch(ui, on, name.as_str());
                    }
                });
                ui.horizontal(|ui| {
                    let all = items.iter().all(|i| i.2);
                    if ui.button(if all { "Select none" } else { "Select all" }).clicked() {
                        items.iter_mut().for_each(|i| i.2 = !all);
                    }
                    if ui.add_enabled(items.iter().any(|i| i.2), egui::Button::new("Reinstall")).clicked() {
                        go = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            }) {
                close = true;
            }
            if go {
                for (id, _, _) in items.iter().filter(|i| i.2) {
                    s.plugins.entry(id.clone()).or_default().removed = false;
                }
                manager::preview(&s.plugins);
                close = true;
            }
        }
        Modal::Install(path) => {
            let mut install = false;
            if !widgets::dialog("Install plugin").show(ctx, |ui| {
                ui.set_width(460.0);
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.label("Path of the plugin (.wasm file) to install:");
                // The file dialog runs on its own thread and leaves the choice here for the next frame.
                let chosen: std::sync::Arc<std::sync::Mutex<Option<String>>> =
                    ui.data_mut(|d| d.get_temp_mut_or_insert_with::<std::sync::Arc<std::sync::Mutex<Option<String>>>>(egui::Id::NULL.with("plugin_install_pick"), Default::default).clone());
                if let Some(p) = chosen.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    *path = p;
                }
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(path).desired_width(350.0).hint_text(r"C:\Users\you\Downloads\plugin.wasm"));
                    if ui.button("Browse…").clicked() {
                        let slot = chosen.clone();
                        crate::sys::filedialog::open_async(ui.ctx(), "Choose a plugin", vec![("Plugins".into(), "*.wasm".into())], move |p| {
                            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(p.to_string_lossy().into_owned());
                        });
                    }
                });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::wasm::manager::Source;

    #[test]
    fn beta_shows_hidden_plugins_and_locking_uninstalls_them() {
        let found = |id: &str, hidden: bool, source: Source| Found { source, hash: String::new(), manifest: plugin_sdk::Manifest { id: id.into(), hidden, ..Default::default() } };
        let tbb = found("tbb", true, Source::Bundled(&[]));
        // A third-party file can't hide itself.
        let file = found("x", true, Source::File("x.wasm".into()));
        let mut s = Settings::default();
        assert!(!listed(&tbb, &s) && listed(&file, &s));
        toggle_beta(&mut s, std::slice::from_ref(&tbb));
        assert!(listed(&tbb, &s) && !s.plugins["tbb"].removed);
        s.plugins.get_mut("tbb").unwrap().enabled = true;
        toggle_beta(&mut s, std::slice::from_ref(&tbb));
        let e = &s.plugins["tbb"];
        assert!(!s.beta_plugins && e.removed && !e.enabled && !listed(&tbb, &s));
        // Switched on before it was hidden (an existing install): still listed so it can be managed.
        s.plugins.get_mut("tbb").unwrap().enabled = true;
        assert!(listed(&tbb, &s));
    }

    #[test]
    fn every_permission_the_host_knows_has_a_description() {
        for p in ["alerts.read", "alerts.write", "ping", "devices.annotate", "programs.hash", "metrics.serve", "upnp", "helper.exe", "browser.session", "firewall.blocks.read"] {
            assert!(!perm_text(p).starts_with("A permission this version"), "{p}");
        }
    }
}
