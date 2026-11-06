//! The first-run wizard: a short setup shown on a new install and once after an update that adds it
//! (`Settings::wizard_seen`). Settings > Other > Run the first-run wizard opens it again on the Dev channel.

use crate::data::FirewallMode;
use crate::live::alerts::AlertKind;
use crate::settings::{Mode, Settings};
use egui::{Context, Ui};

pub struct Wizard {
    step: usize,
    /// The choices so far; applied only on Finish.
    pub draft: Settings,
    pub firewall: FirewallMode,
    /// Wants the ASN database (destination rules on an AS number); there is no setting for it.
    asn: bool,
}

pub enum Step {
    Keep,
    Skip,
    Finish,
}

const STEPS: [&str; 4] = ["Welcome", "Firewall", "Alerts", "Databases"];

impl Wizard {
    pub fn new(draft: Settings) -> Self {
        Self { step: 0, draft, firewall: FirewallMode::ClickToBlock, asn: false }
    }
}

fn firewall_note(mode: FirewallMode) -> &'static str {
    match mode {
        FirewallMode::ClickToBlock => "You choose which programs to block. Nothing is blocked until you say so. The gentlest start.",
        FirewallMode::AskToConnect => "A program RustWarden hasn't seen before is stopped and you are asked to allow or block it. Windows can't pause a connection, so its first attempt fails.",
        FirewallMode::BlockAll => "Everything except RustWarden and the network basics is blocked, until you switch the mode back. For lockdowns.",
    }
}

/// Draws the wizard; the caller turns the answer into Settings changes.
pub fn show(ctx: &Context, w: &mut Wizard) -> Step {
    let mut out = Step::Keep;
    if !crate::widgets::dialog("Welcome to RustWarden").show(ctx, |ui| {
        ui.set_width(520.0);
        ui.label(egui::RichText::new(format!("Step {} of {}: {}", w.step + 1, STEPS.len(), STEPS[w.step])).weak());
        ui.add_space(6.0);
        egui::ScrollArea::vertical().max_height((ctx.content_rect().height() - 260.0).clamp(240.0, 460.0)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            match w.step {
                0 => welcome(ui),
                1 => firewall(ui, w),
                2 => alerts(ui, &mut w.draft),
                _ => databases(ui, w),
            }
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Skip setup").clicked() {
                out = Step::Skip;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if w.step + 1 == STEPS.len() {
                    if ui.button("Finish").clicked() {
                        out = Step::Finish;
                    }
                } else if ui.button("Next").clicked() {
                    w.step += 1;
                }
                if w.step > 0 && ui.button("Back").clicked() {
                    w.step -= 1;
                }
            });
        });
    }) {
        out = Step::Skip;
    }
    out
}

fn welcome(ui: &mut Ui) {
    ui.label(egui::RichText::new("RustWarden, in short").font(crate::theme::bold(20.0)));
    for line in [
        "Shows which programs use your network, live, with the country each connection goes to.",
        "Blocks programs with Windows Firewall rules that RustWarden tags as its own, and can remove them all again.",
        "Warns you about odd things: new programs going online, changed DNS or proxy settings, malicious addresses and more.",
        "Stays on this PC: it makes no outbound calls for a feature until you switch that feature on.",
    ] {
        ui.label(format!("• {line}"));
    }
    ui.add_space(6.0);
    ui.label("This takes a minute: how it should block, which alerts you want, and the databases your choices need. Everything can be changed later in Settings.");
}

fn firewall(ui: &mut Ui, w: &mut Wizard) {
    let mut live = w.draft.mode == Mode::Live;
    if crate::widgets::switch(ui, &mut live, "Measure this PC (Live mode); off shows placeholder demo data").changed() {
        w.draft.mode = if live { Mode::Live } else { Mode::Demo };
    }
    ui.add_space(8.0);
    ui.label(egui::RichText::new("Firewall mode").strong());
    for mode in FirewallMode::ALL {
        crate::widgets::radio(ui, &mut w.firewall, mode, mode.label());
        ui.weak(firewall_note(mode));
    }
    if w.firewall != FirewallMode::ClickToBlock {
        ui.add_space(4.0);
        ui.label("You are asked to confirm this when you finish.");
    }
}

fn alerts(ui: &mut Ui, s: &mut Settings) {
    ui.label("Alerts are off on a new install so you aren't flooded. Turn on the ones you want; Settings > Alerts has the delivery options for each.");
    ui.add_space(4.0);
    for kind in AlertKind::ALL {
        // Needs the driver, so it only appears in Driver mode.
        if kind == AlertKind::InboundScan && s.app_mode != crate::settings::AppMode::Driver {
            continue;
        }
        let mut on = kind.enabled(&s.alerts);
        if crate::widgets::switch(ui, &mut on, kind.title()).changed() {
            *kind.switch_mut(&mut s.alerts) = on;
        }
    }
}

fn databases(ui: &mut Ui, w: &mut Wizard) {
    ui.label("Pick what you will use; RustWarden downloads only the databases those need.");
    ui.add_space(4.0);
    crate::widgets::switch(ui, &mut w.draft.geoip_city, "Place connections at their city on the map");
    crate::widgets::switch(ui, &mut w.asn, "Destination rules on an AS number");
    crate::widgets::switch(ui, &mut w.draft.threat_protect, "Warn about malicious IPs (downloads blocklists)");
    crate::widgets::switch(ui, &mut w.draft.dns_block_alerts, "Warn about malicious domains (downloads blocklists)");
    ui.add_space(6.0);
    ui.label("Flags and countries always use the country database.");
    ui.add_space(6.0);
    let mut editions = vec!["country"];
    if w.draft.geoip_city {
        editions.push("city");
    }
    if w.asn {
        editions.push("asn");
    }
    super::dialogs::databases_panel(ui, &mut w.draft, &editions);
}
