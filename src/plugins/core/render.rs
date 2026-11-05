//! Renders a UI scene off-screen at any resolution: runs egui in a private context, tessellates the
//! shapes and rasterises the triangles on the CPU. Used for high-resolution chart exports.

use egui::epaint::{ImageData, Primitive};
use egui::{Color32, ColorImage, Pos2, Rect, TextureId, Ui, vec2};
use std::collections::HashMap;

/// Draws `scene` into a `size` (points) area at `scale` pixels per point and returns the picture.
pub fn scene(size: egui::Vec2, scale: f32, scene: impl Fn(&mut Ui)) -> ColorImage {
    let ctx = egui::Context::default();
    crate::theme::apply(&ctx);
    let mut input = egui::RawInput { screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)), ..Default::default() };
    input.viewports.entry(egui::ViewportId::ROOT).or_default().native_pixels_per_point = Some(scale);
    // The first pass only installs the fonts; the second draws with them.
    let mut textures: HashMap<TextureId, ColorImage> = HashMap::new();
    let mut take = |out: &mut egui::FullOutput| {
        for (id, delta) in out.textures_delta.set.iter().flat_map(|(id, ds)| ds.iter().map(move |d| (id, d))) {
            let ImageData::Color(img) = &delta.image;
            match delta.pos {
                None => {
                    textures.insert(*id, (**img).clone());
                }
                Some([x0, y0]) => {
                    if let Some(t) = textures.get_mut(id) {
                        for y in 0..img.height() {
                            let at = (y0 + y) * t.width() + x0;
                            t.pixels[at..at + img.width()].copy_from_slice(&img.pixels[y * img.width()..][..img.width()]);
                        }
                    }
                }
            }
        }
        out.textures_delta.clear();
    };
    take(&mut ctx.run_ui(input.clone(), |_| {}));
    let mut out = ctx.run_ui(input, |ui| scene(ui));
    take(&mut out);

    let (w, h) = ((size.x * scale).round() as usize, (size.y * scale).round() as usize);
    let mut image = ColorImage::filled([w, h], Color32::WHITE);
    for prim in ctx.tessellate(out.shapes, scale) {
        let Primitive::Mesh(mesh) = prim.primitive else { continue };
        let Some(tex) = textures.get(&mesh.texture_id) else { continue };
        let clip = prim.clip_rect;
        let bounds = (
            (clip.min.x * scale).floor().max(0.0) as usize,
            (clip.min.y * scale).floor().max(0.0) as usize,
            ((clip.max.x * scale).ceil().max(0.0) as usize).min(w),
            ((clip.max.y * scale).ceil().max(0.0) as usize).min(h),
        );
        for t in mesh.indices.as_chunks::<3>().0 {
            let v = [mesh.vertices[t[0] as usize], mesh.vertices[t[1] as usize], mesh.vertices[t[2] as usize]];
            triangle(&mut image, tex, &v, scale, bounds);
        }
    }
    image
}

/// Fills one textured, vertex-coloured triangle (premultiplied colours, source-over blending).
fn triangle(img: &mut ColorImage, tex: &ColorImage, v: &[egui::epaint::Vertex; 3], scale: f32, (cx0, cy0, cx1, cy1): (usize, usize, usize, usize)) {
    let p = v.map(|v| v.pos * scale);
    let area = (p[1].x - p[0].x) * (p[2].y - p[0].y) - (p[2].x - p[0].x) * (p[1].y - p[0].y);
    if area.abs() < 1e-6 {
        return;
    }
    let x0 = (p.iter().map(|p| p.x).fold(f32::MAX, f32::min).floor().max(cx0 as f32)) as usize;
    let y0 = (p.iter().map(|p| p.y).fold(f32::MAX, f32::min).floor().max(cy0 as f32)) as usize;
    let x1 = (p.iter().map(|p| p.x).fold(f32::MIN, f32::max).ceil().min(cx1 as f32)) as usize;
    let y1 = (p.iter().map(|p| p.y).fold(f32::MIN, f32::max).ceil().min(cy1 as f32)) as usize;
    let (tw, th) = (tex.width(), tex.height());
    let w = img.width();
    for y in y0..y1 {
        for x in x0..x1 {
            let q = vec2(x as f32 + 0.5, y as f32 + 0.5);
            let edge = |a: Pos2, b: Pos2| ((b.x - a.x) * (q.y - a.y) - (b.y - a.y) * (q.x - a.x)) / area;
            let (w0, w1, w2) = (edge(p[1], p[2]), edge(p[2], p[0]), edge(p[0], p[1]));
            if w0 < 0.0 || w1 < 0.0 || w2 < 0.0 {
                continue;
            }
            let u = v[0].uv.x * w0 + v[1].uv.x * w1 + v[2].uv.x * w2;
            let t = v[0].uv.y * w0 + v[1].uv.y * w1 + v[2].uv.y * w2;
            let s = tex.pixels[((t * th as f32) as usize).min(th - 1) * tw + ((u * tw as f32) as usize).min(tw - 1)].to_array();
            let c: [[u8; 4]; 3] = [v[0].color.to_array(), v[1].color.to_array(), v[2].color.to_array()];
            let mut src = [0.0_f32; 4];
            for k in 0..4 {
                let vc = (c[0][k] as f32 * w0 + c[1][k] as f32 * w1 + c[2][k] as f32 * w2) / 255.0;
                src[k] = s[k] as f32 * vc;
            }
            let dst = &mut img.pixels[y * w + x];
            let d = dst.to_array();
            let inv = 1.0 - src[3] / 255.0;
            let o = |k: usize| (src[k] + d[k] as f32 * inv).round().clamp(0.0, 255.0) as u8;
            *dst = Color32::from_rgba_premultiplied(o(0), o(1), o(2), o(3));
        }
    }
}
