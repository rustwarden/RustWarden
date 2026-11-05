//! One file per tab; each adds `impl RustWarden` methods that draw it.

pub mod alert_rules;
pub(crate) mod connections;
pub(crate) mod dialogs;
mod dns;
pub(crate) mod fluent;
mod hardware;
mod log;
pub(crate) mod map;
pub(crate) mod popup;
pub(crate) use popup::Banners;
pub(crate) mod protect;
pub(crate) mod scanner;
pub(crate) mod toast;
mod traffic;
mod tray_menu;

pub(crate) use tray_menu::{TrayAct, TrayMenu};

use egui::{Rect, Ui, UiBuilder};

/// Runs `add` in a sub-ui limited to `rect` with a left-to-right, vertically centred layout.
pub fn row_in<R>(ui: &mut Ui, rect: Rect, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.scope_builder(UiBuilder::new().max_rect(rect).layout(egui::Layout::left_to_right(egui::Align::Center)), add).inner
}

/// Centred moving average over `k` samples (edges average what exists), so dense data can be drawn without aliasing.
pub fn box_blur(v: Vec<f32>, k: usize) -> Vec<f32> {
    if k <= 1 {
        return v;
    }
    let r = k / 2;
    (0..v.len())
        .map(|i| {
            let w = &v[i.saturating_sub(r)..(i + r + 1).min(v.len())];
            w.iter().sum::<f32>() / w.len() as f32
        })
        .collect()
}

/// Picks a tick spacing (in minutes) that gives at most `max_ticks` ticks over `span`.
pub fn tick_step(span: f32, max_ticks: f32) -> f32 {
    const STEPS: [f32; 11] = [0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 30.0, 60.0, 120.0, 240.0];
    STEPS.into_iter().find(|s| span / s <= max_ticks).unwrap_or(480.0)
}

#[cfg(test)]
mod tests {
    use super::box_blur;

    #[test]
    fn blur_averages_and_keeps_length() {
        assert_eq!(box_blur(vec![1.0, 2.0], 1), vec![1.0, 2.0]);
        let b = box_blur(vec![0.0, 0.0, 9.0, 0.0, 0.0], 3);
        assert_eq!(b, vec![0.0, 3.0, 3.0, 3.0, 0.0]);
    }
}
