//! The first-run wizard: a short setup shown on a new install and once after an update that adds it
//! (`Settings::wizard_seen`). Settings > Other > Run the first-run wizard opens it again on the Dev channel.

use crate::data::FirewallMode;
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
        FirewallMode::ClickToBlock => "You block programs yourself. Recommended.",
        FirewallMode::AskToConnect => "Asks you about each new program.",
        FirewallMode::BlockAll => "Blocks everything. For lockdowns.",
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
                0 => welcome(ui, &mut w.draft),
                1 => firewall(ui, w),
                2 => alerts(ui),
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

fn welcome(ui: &mut Ui, s: &mut Settings) {
    ui.label(egui::RichText::new("Quick setup").font(crate::theme::bold(20.0)));
    ui.label("RustWarden shows which programs use your network and lets you block them. Three quick choices; you can change everything later in Settings.");
    ui.add_space(6.0);
    let mut live = s.mode == Mode::Live;
    if crate::widgets::switch(ui, &mut live, "Monitor this PC (off shows demo data)").changed() {
        s.mode = if live { Mode::Live } else { Mode::Demo };
    }
}

fn firewall(ui: &mut Ui, w: &mut Wizard) {
    for mode in FirewallMode::ALL {
        crate::widgets::radio(ui, &mut w.firewall, mode, mode.label());
        ui.weak(firewall_note(mode));
    }
}

fn alerts(ui: &mut Ui) {
    ui.label("Alerts are off for now, so you aren't flooded.");
    ui.label("To turn any on, go to Settings > Alerts.");
}

fn databases(ui: &mut Ui, w: &mut Wizard) {
    ui.label("Turn on what you want. Flags always use the country database.");
    ui.add_space(4.0);
    crate::widgets::switch(ui, &mut w.draft.geoip_city, "City map");
    crate::widgets::switch(ui, &mut w.asn, "Rules by AS number");
    crate::widgets::switch(ui, &mut w.draft.threat_protect, "Warn about malicious IPs");
    crate::widgets::switch(ui, &mut w.draft.dns_block_alerts, "Warn about malicious domains");
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
