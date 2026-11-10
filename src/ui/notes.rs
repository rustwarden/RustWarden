//! The names and marks a device-annotating plugin (Home Assistant) puts on the Scanner tab: its logo,
//! an icon for what the device is, its own name for the device, and a link to the device's page.

use crate::data::{Device, DeviceNote};
use crate::icons::{self, Icon};
use crate::plugins::wasm::manager::Annotator;
use egui::{Color32, Painter, Pos2, pos2, vec2};

const ICON: f32 = 20.0;

/// What a device is. Entity types alone mislead (a plug's LED is a "light", a Hue Bridge exposes switches,
/// Tuya bulbs have no entities), so the names and the vendor are tried first.
pub fn device_kind<'a>(description: &str, note: &'a DeviceNote) -> &'a str {
    let hay = format!("{} {}", note.name, note.model).to_lowercase();
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
    } else if has(&["bulb", "lamp", "lepro"]) || (note.kind == "other" && description.to_lowercase().contains("tuya")) {
        "light"
    } else {
        &note.kind
    }
}

/// Icon and its colour for a device type.
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

/// A plugin option stored as "1" or "0", on when it was never set.
fn flag(src: &Annotator, key: &str) -> bool {
    src.config.get(key).is_none_or(|v| v != "0")
}

/// The plugin's name for the device (with its area) when the option is on and the device was matched.
pub fn display_name(d: &Device, src: &Annotator) -> Option<String> {
    let note = d.note.as_ref()?;
    if !flag(src, "prefer_name") {
        return None;
    }
    Some(if note.area.is_empty() || note.name.starts_with(&note.area) { note.name.clone() } else { format!("{} {}", note.area, note.name) })
}

/// The device's page in the plugin's service, when it has one.
pub fn device_url(d: &Device) -> Option<String> {
    d.note.as_ref().map(|n| n.url.clone()).filter(|u| u.starts_with("https://") || u.starts_with("http://"))
}

/// The plugin's mark and the device type icon, centred in the column. Returns the mark's rectangle so the caller can make it a link.
pub fn paint_badges(p: &Painter, d: &Device, src: &Annotator, centre: Pos2) -> Option<egui::Rect> {
    let note = d.note.as_ref()?;
    let show_type = flag(src, "show_type");
    let n = if show_type { 2.0 } else { 1.0 };
    let mut x = centre.x - (n * ICON + (n - 1.0) * 10.0) / 2.0;
    let mark = egui::Rect::from_min_size(pos2(x, centre.y - ICON / 2.0), vec2(ICON, ICON));
    crate::plugins::core::png(p, mark, &format!("plugin-icon-{}", src.id), &src.icon);
    if show_type {
        x += ICON + 10.0;
        let (icon, color) = type_icon(device_kind(&d.description, note));
        icons::paint(p, icon, egui::Rect::from_min_size(pos2(x, centre.y - ICON / 2.0), vec2(ICON, ICON)), color);
    }
    Some(mark)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_beat_entity_types() {
        let note = |name: &str, model: &str, kind: &str| DeviceNote { name: name.into(), model: model.into(), kind: kind.into(), ..Default::default() };
        assert_eq!(device_kind("", &note("The 46 Lights", "Hue Bridge", "switch")), "hub");
        assert_eq!(device_kind("", &note("Spare Plug", "mss310", "light")), "switch");
        assert_eq!(device_kind("", &note("Bedroom", "Stick Up Cam (3rd Gen)", "switch")), "camera");
    }

    #[test]
    fn options_default_on_and_a_zero_turns_them_off() {
        let mut src = Annotator { id: "ha".into(), name: "Home Assistant".into(), icon: Default::default(), config: Default::default() };
        assert!(flag(&src, "prefer_name"));
        src.config.insert("prefer_name".into(), "0".into());
        assert!(!flag(&src, "prefer_name"));
    }
}
