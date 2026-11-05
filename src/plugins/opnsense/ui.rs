//! OPNsense's pieces of the interface: its row and editor in Settings > Integrations. The editor
//! probes the API key first; the options below it unlock only for what the key was shown to allow.

use super::{Caps, Integration, client};
use crate::icons::{self, Icon};
use crate::{theme, widgets};
use egui::{Sense, Ui, vec2};
use std::sync::{Arc, Mutex};

/// Index the Integrations table uses for "editing OPNsense" (Home Assistant rows use their position).
pub const EDIT: usize = usize::MAX - 2;

/// The icon cell of the Integrations table and the add menu.
pub fn mark(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::hover());
    icons::paint(ui.painter(), Icon::Shield, rect, theme::brand_orange());
}

/// The OPNsense row of the Integrations table.
pub fn row(ui: &mut Ui, s: &mut crate::settings::Settings, edit: &mut Option<usize>) {
    let Some(it) = &mut s.opnsense else { return };
    mark(ui);
    ui.label(&it.name);
    ui.label("OPNsense");
    widgets::switch(ui, &mut it.enabled, "");
    if ui.button("Edit").clicked() {
        *edit = Some(EDIT);
    }
    if ui.button("Remove").clicked() {
        s.opnsense = None;
        *edit = None;
    }
    ui.end_row();
}

/// The probe's answer, with the address and key it was run for.
type Probe = Arc<Mutex<Option<(String, Result<Caps, String>)>>>;

fn badge(ui: &mut Ui, on: bool, label: &str) {
    ui.colored_label(if on { theme::green() } else { theme::red() }, format!("{} {label}", if on { "✓" } else { "✕" }));
}

/// The connection window; false once closed. It edits a copy: Save checks the fields and stores it in
/// `saved` (which is None while adding), Cancel or closing the window throws it away.
/// `demo` swaps the real router for a made-up one.
pub fn editor(ctx: &egui::Context, id: egui::Id, saved: &mut Option<Integration>, demo: bool) -> bool {
    let draft_id = id.with("draft");
    let mut draft: Integration = ctx.data_mut(|d| d.get_temp(draft_id)).unwrap_or_else(|| saved.clone().unwrap_or_default());
    let it = &mut draft;
    // None while editing; Some(true) to save, Some(false) to cancel.
    let mut done: Option<bool> = None;
    let slot: Option<Probe> = ctx.data_mut(|d| d.get_temp::<Option<Probe>>(id)).flatten();
    let finished = slot.as_ref().and_then(|s| s.lock().ok()?.take());
    let busy = slot.is_some() && finished.is_none();
    if let Some((fp, result)) = finished {
        ctx.data_mut(|d| {
            d.insert_temp(id, None::<Probe>);
            match result {
                // An answer for an address or key that has been edited since is no use.
                Ok(caps) if fp == it.fingerprint() => {
                    it.caps = Some(caps);
                    it.caps_for = fp;
                    it.gate();
                    d.remove_temp::<String>(id.with("msg"));
                }
                Ok(_) => {}
                Err(e) => {
                    it.caps = None;
                    d.insert_temp(id.with("msg"), e);
                }
            }
        });
    }
    if !widgets::dialog("OPNsense").show(ctx, |ui| {
        ui.set_width(460.0);
        ui.spacing_mut().item_spacing.y = 6.0;
        ui.label("Name");
        ui.text_edit_singleline(&mut it.name);
        ui.label("Address of the web interface");
        let r = ui.add(egui::TextEdit::singleline(&mut it.url).hint_text("https://192.168.1.1").desired_width(f32::INFINITY));
        widgets::edit_menu(ui, &r, &mut it.url, false);
        let url = it.url.trim();
        if !url.is_empty() && !crate::plugins::external_notifications::valid(url, &[]) {
            ui.colored_label(theme::red(), "The address must start with http:// or https://");
        }
        ui.label("API key (System > Access > Users > API keys)");
        let r = ui.add(egui::TextEdit::singleline(&mut it.key).password(true).desired_width(f32::INFINITY));
        widgets::edit_menu(ui, &r, &mut it.key, true);
        ui.label("API secret");
        let r = ui.add(egui::TextEdit::singleline(&mut it.secret).password(true).desired_width(f32::INFINITY));
        widgets::edit_menu(ui, &r, &mut it.secret, true);
        widgets::switch(ui, &mut it.allow_self_signed, "Allow self-signed certificate");
        ui.weak("OPNsense uses its own certificate by default. Only turn this on for a router on your own network.");
        it.gate(); // editing the address or key drops what the last probe found

        ui.separator();
        let launch = |ui: &mut Ui, write: bool| {
            let slot: Probe = Default::default();
            ui.data_mut(|d| d.insert_temp(id, Some(slot.clone())));
            let (cfg, ctx) = (Integration { url: it.url.trim().to_owned(), key: it.key.trim().to_owned(), secret: it.secret.trim().to_owned(), ..it.clone() }, ui.ctx().clone());
            let keep = it.caps().and_then(|c| c.write);
            std::thread::spawn(move || {
                let r = if demo { Ok(client::demo_probe(&cfg, write, keep)) } else { client::probe(&cfg, write, keep) };
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((cfg.fingerprint(), r));
                ctx.request_repaint();
            });
        };
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy && it.ready(), egui::Button::new(if busy { "Checking…" } else { "Test connection" }))
                .on_hover_text("Signs in and finds out which parts of OPNsense this key can read.")
                .clicked()
            {
                launch(ui, false);
            }
            if ui
                .add_enabled(!busy && it.ready() && it.caps().is_some(), egui::Button::new("Check write access"))
                .on_hover_text(format!(
                    "Creates and removes an alias called {} on the router, to see whether this key can change it. Nothing is applied. Run Test connection first.",
                    client::PROBE_ALIAS
                ))
                .on_disabled_hover_text("Run Test connection first.")
                .clicked()
            {
                launch(ui, true);
            }
        });
        if let Some(m) = ui.data_mut(|d| d.get_temp::<String>(id.with("msg"))) {
            ui.colored_label(theme::red(), m);
        }
        let caps = it.caps().cloned();
        match &caps {
            None => {
                ui.weak("Test the connection to unlock the options below.");
            }
            Some(c) => {
                if !c.version.is_empty() {
                    ui.label(format!("OPNsense {}", c.version));
                }
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 14.0;
                    badge(ui, c.leases, "DHCP leases");
                    badge(ui, c.arp, "ARP table");
                    badge(ui, c.log, "Firewall log");
                    badge(ui, c.gateway, "Gateways");
                    badge(ui, c.traffic, "Traffic");
                });
                match c.write {
                    Some(true) => ui.colored_label(theme::green(), "✓ This key can change firewall aliases (read and write)."),
                    Some(false) => ui.colored_label(theme::brand_orange(), "Read only: this key can't change aliases, so pushing blocks stays off."),
                    None => ui.weak("Write access hasn't been checked."),
                };
                if !c.warning.is_empty() {
                    ui.colored_label(theme::brand_orange(), &c.warning);
                }
            }
        }

        ui.separator();
        ui.label(egui::RichText::new("Bring in from OPNsense").strong());
        let (dev, log, gw, push) = (it.can_pull_devices(), it.can_pull_log(), it.can_pull_gateway(), it.can_push());
        let why = |ok: bool, denied: &'static str| {
            if caps.is_none() {
                "Test the connection first."
            } else if ok {
                ""
            } else {
                denied
            }
        };
        gated(ui, &mut it.pull_devices, dev, "Device names and addresses (DHCP leases, ARP)", why(dev, "This key can't read leases or the ARP table."));
        gated(ui, &mut it.pull_log, log, "Router firewall log", why(log, "This key can't read the firewall log."));
        gated(ui, &mut it.pull_gateway, gw, "Gateway status and traffic", why(gw, "This key can't read gateways or traffic."));
        ui.add_space(2.0);
        ui.label(egui::RichText::new("Send to OPNsense").strong());
        let denied = if caps.as_ref().is_some_and(|c| c.write.is_none()) { "Press Check write access first." } else { "This key is read only." };
        gated(ui, &mut it.push_blocks, push, "Blocked addresses (a RustWarden alias on the router)", why(push, denied));
        ui.weak("Everything RustWarden creates on the router is named RustWarden, so it can be found and removed.");

        ui.separator();
        let problem = it.problem();
        if let Some(p) = problem {
            ui.colored_label(theme::red(), p);
        }
        ui.horizontal(|ui| {
            if ui.add_enabled(problem.is_none(), egui::Button::new("Save")).on_disabled_hover_text(problem.unwrap_or_default()).clicked() {
                done = Some(true);
            }
            if ui.button("Cancel").clicked() {
                done = Some(false);
            }
        });
    }) {
        done = Some(false);
    }
    match done {
        None => {
            ctx.data_mut(|d| d.insert_temp(draft_id, draft));
            true
        }
        Some(save) => {
            if save {
                *saved = Some(draft);
            }
            ctx.data_mut(|d| {
                d.remove_temp::<Integration>(draft_id);
                d.insert_temp(id, None::<Probe>);
                d.remove_temp::<String>(id.with("msg"));
            });
            false
        }
    }
}

/// A switch that can't be turned on until `allowed`; the hover text says why.
fn gated(ui: &mut Ui, on: &mut bool, allowed: bool, label: &str, reason: &str) {
    if !allowed {
        *on = false;
    }
    ui.add_enabled_ui(allowed, |ui| widgets::switch(ui, on, label)).response.on_disabled_hover_text(reason);
}
