//! VirusTotal: checks each program that uses the network by file hash. The key and the
//! auto-scan switch stay in `Settings` (the lookups in `live::vt` read them there); this is
//! only the row and editor in Settings > Integrations.

use crate::icons::{self, Icon};
use crate::settings::Settings;
use crate::theme;
use egui::{Ui, vec2};

/// Index the Integrations table uses for "editing VirusTotal".
pub const EDIT: usize = usize::MAX - 1;

/// Shown once added, and always for a key saved before VirusTotal became an integration.
pub fn present(s: &Settings) -> bool {
    s.virustotal_added || !s.virustotal_key.trim().is_empty()
}

pub fn mark(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(20.0, 20.0), egui::Sense::hover());
    icons::paint(ui.painter(), Icon::Shield, rect, theme::red());
}

pub fn row(ui: &mut Ui, s: &mut Settings, edit: &mut Option<usize>) {
    if !present(s) {
        return;
    }
    mark(ui);
    ui.label("VirusTotal");
    ui.label("VirusTotal");
    ui.label("");
    if ui.button("Edit").clicked() {
        *edit = Some(EDIT);
    }
    if ui.button("Remove").clicked() {
        s.virustotal_key.clear();
        s.virustotal_auto = false;
        s.virustotal_added = false;
        *edit = None;
    }
    ui.end_row();
}

/// The connection window; false once closed.
pub fn editor(ctx: &egui::Context, s: &mut Settings) -> bool {
    let mut open = true;
    if !crate::widgets::dialog("VirusTotal").show(ctx, |ui| {
        ui.set_width(440.0);
        ui.spacing_mut().item_spacing.y = 6.0;
        ui.label("Checks each program that uses the network against VirusTotal. Only the SHA-256 of each file is sent. A file is uploaded (up to 32 MB) only when you choose \"Upload to VirusTotal…\" for that program and confirm it.");
        crate::ui::dialogs::link(ui, "Get a free API key", "https://www.virustotal.com/gui/my-apikey");
        ui.label("API key");
        let r = ui.add(egui::TextEdit::singleline(&mut s.virustotal_key).password(true).desired_width(420.0));
        crate::widgets::edit_menu(ui, &r, &mut s.virustotal_key, true);
        s.virustotal_key = s.virustotal_key.trim().to_owned();
        let has_key = !s.virustotal_key.is_empty();
        ui.add_enabled(has_key, egui::Checkbox::new(&mut s.virustotal_auto, "Scan new programs automatically"));
        ui.label(if has_key {
            "The free key allows 4 lookups a minute, so a long list takes a while."
        } else {
            "Enter a key to turn on the VirusTotal column on the Firewall tab."
        });
        if ui.button("Close").clicked() {
            open = false;
        }
    }) {
        open = false;
    }
    open
}
