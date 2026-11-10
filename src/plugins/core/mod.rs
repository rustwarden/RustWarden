//! What the plugins and the plugin host share: the latency charts, the scene renderer and PNG drawing.

pub mod latency;
pub mod render;

use egui::{Color32, Painter, pos2};

/// Decodes a PNG (RGB or RGBA) into a texture cached in the egui context under `key`.
pub fn texture(ctx: &egui::Context, key: &str, bytes: &[u8]) -> Option<egui::TextureHandle> {
    let id = egui::Id::NULL.with(key);
    ctx.data(|d| d.get_temp::<Option<egui::TextureHandle>>(id)).unwrap_or_else(|| {
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
    })
}

/// Draws a PNG stretched into `rect`.
pub fn png(p: &Painter, rect: egui::Rect, key: &str, bytes: &[u8]) {
    if let Some(t) = texture(p.ctx(), key, bytes) {
        p.image(t.id(), rect, egui::Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
    }
}
