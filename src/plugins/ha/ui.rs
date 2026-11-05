//! Home Assistant's pieces of the interface: its editor window, and the name and icons shown on the
//! Scanner tab.

use super::HaInfo;
use super::{Integration, active, client, worker};
use crate::data::Device;
use crate::icons::{self, Icon};
use crate::settings::Settings;
use crate::theme;
use egui::{Color32, Painter, Pos2, Ui, pos2, vec2};
use std::sync::{Arc, Mutex};

/// The official logo, rasterised from assets/home-assistant.svg (egui has no SVG support here).
const LOGO: &[u8] = include_bytes!("assets/home-assistant.png");
const ICON: f32 = 20.0;

/// Draws the Home Assistant logo.
pub fn logo(p: &Painter, rect: egui::Rect) {
    crate::plugins::core::png(p, rect, "ha_logo", LOGO);
}

/// What a device is. Home Assistant's entity types alone mislead (a plug's LED is a "light", a Hue
/// Bridge exposes switches, Tuya bulbs have no entities), so the names and the vendor are tried first.
pub fn device_kind<'a>(description: &str, ha: &'a HaInfo) -> &'a str {
    let hay = format!("{} {}", ha.name, ha.model).to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| hay.contains(w));
    if has(&["gateway", "hub", "bridge"]) {
        "hub"
    } else if has(&["cam", "doorbell"]) {
        "camera"
    } else if has(&["plug", "socket", "mss3"]) {
        "switch"
    } else if has(&["router", "archer"]) {
        "router"
    } else if has(&["desktop", "laptop"]) {
        "computer"
    } else if has(&["presence", "motion"]) {
        "sensor"
    } else if has(&["bulb", "lamp", "lepro"]) || (ha.kind == "other" && description.to_lowercase().contains("tuya")) {
        "light"
    } else {
        &ha.kind
    }
}

/// Icon and its colour for a Home Assistant device type.
fn type_icon(kind: &str) -> (Icon, Color32) {
    match kind {
        "light" => (Icon::Bulb, Color32::from_rgb(250, 190, 40)),
        "switch" => (Icon::Plug, Color32::from_rgb(60, 170, 90)),
        "sensor" => (Icon::Sensor, Color32::from_rgb(40, 170, 200)),
        "media" => (Icon::Wave, Color32::from_rgb(170, 90, 220)),
        "camera" => (Icon::Camera, Color32::from_rgb(230, 80, 80)),
        "lock" => (Icon::Lock, Color32::from_rgb(240, 130, 40)),
        "hub" => (Icon::House, Color32::from_rgb(90, 150, 240)),
        "router" => (Icon::Wifi, Color32::from_rgb(40, 190, 210)),
        "computer" => (Icon::Laptop, Color32::from_rgb(170, 100, 230)),
        _ => (Icon::Chip, Color32::from_rgb(120, 130, 220)),
    }
}

/// The Home Assistant name (with its area) when the option is on and the device was matched.
pub fn display_name(d: &Device, s: &Settings) -> Option<String> {
    let (cfg, ha) = (active(s)?, d.ha.as_ref()?);
    if !cfg.prefer_name {
        return None;
    }
    Some(if ha.area.is_empty() || ha.name.starts_with(&ha.area) { ha.name.clone() } else { format!("{} {}", ha.area, ha.name) })
}

/// The device's page in Home Assistant, when it is enabled and the device was matched.
pub fn device_url(d: &Device, s: &Settings) -> Option<String> {
    let (cfg, ha) = (active(s)?, d.ha.as_ref()?);
    (!ha.device_id.is_empty()).then(|| format!("{}/config/devices/device/{}", cfg.url.trim_end_matches('/'), ha.device_id))
}

/// The Home Assistant mark and the device type icon, centred in the HA column. Returns the mark's
/// rectangle so the caller can make it a link.
pub fn paint_badges(p: &Painter, d: &Device, s: &Settings, centre: Pos2) -> Option<egui::Rect> {
    let (Some(cfg), Some(ha)) = (active(s), &d.ha) else { return None };
    let n = if cfg.show_type { 2.0 } else { 1.0 };
    let mut x = centre.x - (n * ICON + (n - 1.0) * 10.0) / 2.0;
    let mark = egui::Rect::from_min_size(pos2(x, centre.y - ICON / 2.0), vec2(ICON, ICON));
    logo(p, mark);
    if cfg.show_type {
        x += ICON + 10.0;
        let (icon, color) = type_icon(device_kind(&d.description, ha));
        icons::paint(p, icon, egui::Rect::from_min_size(pos2(x, centre.y - ICON / 2.0), vec2(ICON, ICON)), color);
    }
    Some(mark)
}

pub fn mark(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(ICON, ICON), egui::Sense::hover());
    logo(ui.painter(), rect);
}

type Test = Arc<Mutex<Option<Result<(), String>>>>;

/// The connection window for one Home Assistant; false once closed.
pub fn editor(ctx: &egui::Context, test_id: egui::Id, it: &mut Integration) -> bool {
    let mut open = true;
    let slot: Option<Test> = ctx.data_mut(|d| d.get_temp::<Option<Test>>(test_id)).flatten();
    let finished = slot.as_ref().and_then(|s| s.lock().ok()?.take());
    let busy = slot.is_some() && finished.is_none();
    if let Some(r) = finished {
        ctx.data_mut(|d| {
            d.insert_temp(test_id, None::<Test>);
            d.insert_temp(test_id.with("msg"), r.map_or_else(|e| e, |()| "Connected.".to_owned()));
        });
    }
    if !crate::widgets::dialog("Home Assistant").show(ctx, |ui| {
        ui.set_width(440.0);
        ui.spacing_mut().item_spacing.y = 6.0;
        ui.label("Name");
        ui.text_edit_singleline(&mut it.name);
        ui.label("Address");
        let r = ui.add(egui::TextEdit::singleline(&mut it.url).hint_text("http://homeassistant.local:8123").desired_width(f32::INFINITY));
        crate::widgets::edit_menu(ui, &r, &mut it.url, false);
        let url = it.url.trim();
        if !url.is_empty() && !crate::plugins::external_notifications::valid(url, &[]) {
            ui.colored_label(theme::red(), "The address must start with http:// or https://");
        }
        ui.label("Long-lived access token (Home Assistant profile > Security)");
        let r = ui.add(egui::TextEdit::singleline(&mut it.token).password(true).desired_width(f32::INFINITY));
        crate::widgets::edit_menu(ui, &r, &mut it.token, true);
        crate::widgets::switch(ui, &mut it.prefer_name, "Prefer HA entity name");
        ui.label("Shows the Home Assistant name (with its area) instead of the network name on the Scanner tab.");
        crate::widgets::switch(ui, &mut it.show_type, "Show device type");
        ui.label("Shows an icon for light, plug, sensor and so on beside matched devices.");
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy && it.ready(), egui::Button::new(if busy { "Testing…" } else { "Test connection" })).clicked() {
                let slot: Test = Default::default();
                ui.data_mut(|d| {
                    d.insert_temp(test_id, Some(slot.clone()));
                    d.remove_temp::<String>(test_id.with("msg"));
                });
                let (url, token, ctx) = (it.url.trim().to_owned(), it.token.trim().to_owned(), ui.ctx().clone());
                std::thread::spawn(move || {
                    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(client::test(&url, &token));
                    ctx.request_repaint();
                });
            }
            if ui.button("Sync now").on_hover_text("Look every scanned device up again (applies the saved settings, so press OK first).").clicked() {
                worker::SYNC_NOW.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        if let Some(m) = ui.data_mut(|d| d.get_temp::<String>(test_id.with("msg"))) {
            ui.label(m);
        }
        if ui.button("Done").clicked() {
            open = false;
        }
    }) {
        open = false;
    }
    open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_beat_entity_types() {
        let ha = |name: &str, model: &str, kind: &str| HaInfo { name: name.into(), model: model.into(), kind: kind.into(), ..Default::default() };
        assert_eq!(device_kind("", &ha("The 46 Lights", "Hue Bridge", "switch")), "hub");
        assert_eq!(device_kind("", &ha("Spare Plug", "mss310", "light")), "switch");
        assert_eq!(device_kind("", &ha("Bedroom", "Stick Up Cam (3rd Gen)", "switch")), "camera");
    }
}
