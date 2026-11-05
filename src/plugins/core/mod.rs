//! The Settings > Integrations page: one table for every integration, with the add menu and each
//! integration's editor window. The integrations themselves live in their own plugin folders.

pub mod latency;
pub mod render;

use crate::icons::Icon;
use crate::plugins::{ha, virustotal as vt};
use crate::settings::Settings;
use crate::widgets;
use egui::{Color32, Painter, Ui, pos2};

/// Draws a PNG (RGB or RGBA) stretched into `rect`; the decoded texture is cached in the egui context under `key`.
pub fn png(p: &Painter, rect: egui::Rect, key: &'static str, bytes: &'static [u8]) {
    let ctx = p.ctx();
    let id = egui::Id::NULL.with(key);
    let tex = ctx.data(|d| d.get_temp::<Option<egui::TextureHandle>>(id)).unwrap_or_else(|| {
        let mut reader = png::Decoder::new(std::io::Cursor::new(bytes)).read_info().ok();
        let tex = reader.as_mut().and_then(|r| {
            let mut buf = vec![0; r.output_buffer_size()?];
            let info = r.next_frame(&mut buf).ok()?;
            let size = [info.width as usize, info.height as usize];
            let image = match info.color_type {
                png::ColorType::Rgb => egui::ColorImage::from_rgb(size, &buf[..info.buffer_size()]),
                _ => egui::ColorImage::from_rgba_unmultiplied(size, &buf[..info.buffer_size()]),
            };
            Some(ctx.load_texture(key, image, egui::TextureOptions::LINEAR))
        });
        ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
        tex
    });
    if let Some(t) = tex {
        p.image(t.id(), rect, egui::Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
    }
}

/// Integrations / External Notifications tabs, like Settings > Privacy.
pub fn section(ui: &mut Ui, s: &mut Settings) {
    let id = ui.scope_id().with("integrations_tab");
    let mut tab: usize = ui.data_mut(|d| d.get_temp(id).unwrap_or(0));
    ui.horizontal(|ui| {
        widgets::segmented_text(ui, &mut tab, &["Integrations", "External Notifications"]);
    });
    ui.add_space(6.0);
    ui.data_mut(|d| d.insert_temp(id, tab));
    if tab == 0 { table(ui, s) } else { crate::plugins::external_notifications::ui::section(ui, s) }
}

fn table(ui: &mut Ui, s: &mut Settings) {
    ui.label("Connect other systems to RustWarden.");
    crate::widgets::switch(ui, &mut s.metrics, "Serve Prometheus metrics to programs on this computer");
    ui.add_enabled_ui(s.metrics, |ui| {
        ui.horizontal(|ui| {
            ui.label("Port");
            ui.add(egui::DragValue::new(&mut s.metrics_port).range(1024..=65535));
            ui.weak(format!("http://127.0.0.1:{}/metrics", s.metrics_port));
        });
    });
    ui.add_space(8.0);
    let edit_id = ui.scope_id().with("integration_edit");
    let mut edit: Option<usize> = ui.data_mut(|d| d.get_temp::<Option<usize>>(edit_id)).flatten();
    let mut remove = None;
    egui::Grid::new("integrations").num_columns(6).spacing([16.0, 8.0]).striped(true).show(ui, |ui| {
        for h in ["", "Integration", "Type", "On", "", ""] {
            ui.label(egui::RichText::new(h).strong());
        }
        ui.end_row();
        for (i, it) in s.integrations.iter_mut().enumerate() {
            ha::ui::mark(ui);
            ui.label(&it.name);
            ui.label("Home Assistant");
            crate::widgets::switch(ui, &mut it.enabled, "");
            if ui.button("Edit").clicked() {
                edit = Some(i);
            }
            if ui.button("Remove").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
        crate::plugins::thinkbroadband::ui::row(ui, s, &mut edit);
        vt::row(ui, s, &mut edit);
    });
    if s.integrations.is_empty() && s.thinkbroadband.is_none() && !vt::present(s) {
        ui.label("No integrations yet.");
    }
    let add = widgets::icon_button(ui, Icon::Plus, 34.0, "Add an integration");
    egui::Popup::menu(&add).show(|ui| {
        ui.set_min_width(180.0);
        ui.horizontal(|ui| {
            ha::ui::mark(ui);
            if ui.button("Home Assistant").clicked() {
                s.integrations.push(ha::Integration::default());
                edit = Some(s.integrations.len() - 1);
                ui.close();
            }
        });
        if s.thinkbroadband.is_none() {
            ui.horizontal(|ui| {
                crate::plugins::thinkbroadband::ui::mark(ui);
                if ui.button("thinkbroadband").clicked() {
                    s.thinkbroadband = Some(Default::default());
                    edit = Some(crate::plugins::thinkbroadband::ui::EDIT);
                    ui.close();
                }
            });
        }
        if !vt::present(s) {
            ui.horizontal(|ui| {
                vt::mark(ui);
                if ui.button("VirusTotal").clicked() {
                    s.virustotal_added = true;
                    edit = Some(vt::EDIT);
                    ui.close();
                }
            });
        }
    });
    if let Some(i) = remove {
        s.integrations.remove(i);
        edit = None;
    }
    if edit == Some(vt::EDIT) {
        if !vt::editor(ui.ctx(), s) {
            edit = None;
        }
    } else if edit == Some(crate::plugins::thinkbroadband::ui::EDIT) {
        let keep = s.thinkbroadband.as_mut().is_some_and(|it| crate::plugins::thinkbroadband::ui::editor(ui.ctx(), edit_id.with("tbb"), it));
        if !keep {
            edit = None;
        }
    } else if let Some(i) = edit.filter(|i| *i < s.integrations.len()) {
        if !ha::ui::editor(ui.ctx(), edit_id.with("test"), &mut s.integrations[i]) {
            edit = None;
        }
    } else {
        edit = None;
    }
    ui.data_mut(|d| d.insert_temp(edit_id, edit));
}
