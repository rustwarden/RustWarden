//! Vector icons, flags, and app icons drawn with the painter, so the app needs no image assets.

use crate::data::{AppIcon, Country, Glyph};
use crate::theme;
use egui::epaint::{CornerRadius, PathShape, StrokeKind};
use egui::{Color32, Painter, Pos2, Rect, Shape, Stroke, pos2, vec2};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Traffic,
    Shield,
    Alerts,
    Scanner,
    Chip,
    Filter,
    Wave,
    Globe,
    Bell,
    ArrowDown,
    ArrowUp,
    Chevron,
    ChevronRight,
    Search,
    Export,
    Info,
    Sliders,
    Palette,
    Check,
    Wifi,
    Laptop,
    Raspberry,
    House,
    Bulb,
    Plug,
    Sensor,
    Camera,
    Lock,
    Click,
    Minimize,
    Maximize,
    Close,
    Privacy,
    Reset,
    Restart,
    /// A shield with an exclamation mark.
    ShieldAlert,
    /// Three dots.
    More,
    /// An hourglass: something is counting down.
    Hourglass,
    /// A warning triangle.
    Warning,
}

/// A full circle for a closed outline: without the repeated end point, whose zero-length closing segment
/// the tessellator draws as a long stray line.
fn ring(c: Pos2, r: f32, n: usize) -> Vec<Pos2> {
    let mut pts = arc_points(c, r, 0.0, 360.0, n);
    pts.pop();
    pts
}

/// Points on a circle arc; angles in degrees, counter-clockwise from +x (screen y points down).
pub fn arc_points(c: Pos2, r: f32, a0: f32, a1: f32, n: usize) -> Vec<Pos2> {
    (0..=n)
        .map(|i| {
            let a = (a0 + (a1 - a0) * i as f32 / n as f32).to_radians();
            c + vec2(a.cos(), -a.sin()) * r
        })
        .collect()
}

/// A sun (shown while dark, to switch to light) or a crescent moon (shown while light), as thin outlines.
pub fn theme_toggle(p: &Painter, dark_now: bool, rect: Rect, color: Color32) {
    let s = rect.width().min(rect.height());
    let c = rect.center();
    let st = Stroke::new((s * 0.08).max(1.4), color);
    if dark_now {
        p.add(Shape::closed_line(ring(c, 0.22 * s, 24), st));
        for i in 0..8 {
            let a = i as f32 * std::f32::consts::TAU / 8.0;
            let d = vec2(a.cos(), a.sin());
            p.add(Shape::line(vec![c + d * 0.36 * s, c + d * 0.48 * s], st));
        }
    } else {
        // Outer arc the long way round, then an inner arc back: a crescent opening to the right.
        let r = 0.42 * s;
        let (x0, rho) = (0.9 * r, 0.733 * r);
        let at = |centre: Pos2, rad: f32, deg: f32| centre + vec2(deg.to_radians().cos(), deg.to_radians().sin()) * rad;
        let mut pts: Vec<Pos2> = (0..=24).map(|i| at(c, r, -45.0 - 270.0 * i as f32 / 24.0)).collect();
        pts.extend((0..=12).map(|i| at(c + vec2(x0, 0.0), rho, -254.7 + 149.4 * i as f32 / 12.0)));
        p.add(Shape::closed_line(pts, st));
    }
}

/// Thin outline versions of the header tab icons (the rest fall back to [`paint`]).
pub fn outline(p: &Painter, icon: Icon, rect: Rect, color: Color32) {
    let s = rect.width().min(rect.height());
    let r = Rect::from_center_size(rect.center(), vec2(s, s));
    let u = |x: f32, y: f32| r.min + vec2(x * s, y * s);
    let st = Stroke::new((s * 0.07).max(1.4), color);
    let line = |pts: Vec<Pos2>| {
        p.add(Shape::line(pts, st));
    };
    let closed = |pts: Vec<Pos2>| {
        p.add(Shape::closed_line(pts, st));
    };
    match icon {
        Icon::Traffic => {
            line(vec![u(0.06, 0.74), u(0.28, 0.5), u(0.46, 0.64), u(0.72, 0.24), u(0.94, 0.46)]);
            line(vec![u(0.06, 0.92), u(0.94, 0.92)]);
        }
        Icon::Shield => closed(vec![u(0.5, 0.08), u(0.86, 0.22), u(0.84, 0.54), u(0.5, 0.92), u(0.16, 0.54), u(0.14, 0.22)]),
        Icon::ShieldAlert => {
            closed(vec![u(0.5, 0.08), u(0.86, 0.22), u(0.84, 0.54), u(0.5, 0.92), u(0.16, 0.54), u(0.14, 0.22)]);
            line(vec![u(0.5, 0.3), u(0.5, 0.56)]);
            p.circle_filled(u(0.5, 0.7), s * 0.045, color);
        }
        Icon::Alerts => {
            closed(vec![u(0.2, 0.08), u(0.6, 0.08), u(0.82, 0.3), u(0.82, 0.92), u(0.2, 0.92)]);
            line(vec![u(0.34, 0.52), u(0.68, 0.52)]);
            line(vec![u(0.34, 0.7), u(0.68, 0.7)]);
        }
        Icon::Scanner => {
            closed(ring(u(0.5, 0.5), 0.42 * s, 40));
            line(vec![u(0.08, 0.5), u(0.92, 0.5)]);
            closed((0..32).map(|i| u(0.5 + 0.18 * (i as f32 / 32.0 * std::f32::consts::TAU).cos(), 0.5 + 0.42 * (i as f32 / 32.0 * std::f32::consts::TAU).sin())).collect());
        }
        Icon::Chip => {
            closed(vec![u(0.26, 0.26), u(0.74, 0.26), u(0.74, 0.74), u(0.26, 0.74)]);
            for x in [0.4, 0.6] {
                line(vec![u(x, 0.1), u(x, 0.26)]);
                line(vec![u(x, 0.74), u(x, 0.9)]);
                line(vec![u(0.1, x), u(0.26, x)]);
                line(vec![u(0.74, x), u(0.9, x)]);
            }
        }
        other => paint(p, other, rect, color),
    }
}

pub fn paint(p: &Painter, icon: Icon, rect: Rect, color: Color32) {
    // The filled tab icons share the header's thin outline look wherever they appear (menus, buttons).
    if matches!(icon, Icon::Traffic | Icon::Shield | Icon::ShieldAlert | Icon::Alerts | Icon::Chip | Icon::Scanner) {
        return outline(p, icon, rect, color);
    }
    let s = rect.width().min(rect.height());
    let r = Rect::from_center_size(rect.center(), vec2(s, s));
    let u = |x: f32, y: f32| r.min + vec2(x * s, y * s);
    let st = Stroke::new((s * 0.07).max(1.4), color);
    let line = |pts: Vec<Pos2>| {
        p.add(Shape::line(pts, st));
    };
    match icon {
        Icon::Traffic => {
            p.add(Shape::convex_polygon(vec![u(0.08, 0.9), u(0.28, 0.1), u(0.36, 0.1), u(0.5, 0.9)], color, Stroke::NONE));
            p.add(Shape::convex_polygon(vec![u(0.42, 0.9), u(0.66, 0.32), u(0.74, 0.32), u(0.92, 0.9)], color, Stroke::NONE));
        }
        Icon::Shield | Icon::ShieldAlert => {
            let pts = vec![u(0.5, 0.06), u(0.88, 0.2), u(0.86, 0.52), u(0.5, 0.94), u(0.14, 0.52), u(0.12, 0.2)];
            p.add(Shape::convex_polygon(pts, color, Stroke::NONE));
            p.add(Shape::line(vec![u(0.33, 0.5), u(0.46, 0.63), u(0.68, 0.38)], Stroke::new(st.width, Color32::WHITE)));
        }
        Icon::Alerts => {
            let pts: Vec<Pos2> = (0..48)
                .map(|i| {
                    let t = i as f32 / 48.0 * std::f32::consts::TAU;
                    let x = 16.0 * t.sin().powi(3);
                    let y = 13.0 * t.cos() - 5.0 * (2.0 * t).cos() - 2.0 * (3.0 * t).cos() - (4.0 * t).cos();
                    u(0.5 + x / 38.0, 0.48 - y / 38.0)
                })
                .collect();
            p.add(PathShape::closed_line(pts, st));
        }
        Icon::Scanner => {
            for (x, y) in [(0.25, 0.3), (0.72, 0.5), (0.25, 0.75)] {
                p.circle_stroke(u(x, y), s * 0.13, st);
            }
            line(vec![u(0.37, 0.35), u(0.6, 0.45)]);
            line(vec![u(0.37, 0.7), u(0.6, 0.56)]);
        }
        Icon::Chip => {
            p.rect_stroke(Rect::from_min_max(u(0.22, 0.22), u(0.78, 0.78)), 2.0, st, StrokeKind::Middle);
            p.rect_filled(Rect::from_min_max(u(0.38, 0.38), u(0.62, 0.62)), 1.0, color);
            for k in [0.36, 0.5, 0.64] {
                line(vec![u(k, 0.06), u(k, 0.22)]);
                line(vec![u(k, 0.78), u(k, 0.94)]);
                line(vec![u(0.06, k), u(0.22, k)]);
                line(vec![u(0.78, k), u(0.94, k)]);
            }
        }
        Icon::Filter => {
            line(vec![u(0.12, 0.3), u(0.88, 0.3)]);
            line(vec![u(0.24, 0.5), u(0.76, 0.5)]);
            line(vec![u(0.38, 0.7), u(0.62, 0.7)]);
        }
        Icon::Wave => line(vec![u(0.02, 0.55), u(0.22, 0.55), u(0.34, 0.25), u(0.48, 0.8), u(0.6, 0.38), u(0.7, 0.55), u(0.98, 0.55)]),
        Icon::Globe => {
            p.circle_stroke(u(0.5, 0.5), s * 0.42, st);
            let ell: Vec<Pos2> = (0..=32)
                .map(|i| {
                    let a = i as f32 / 32.0 * std::f32::consts::TAU;
                    u(0.5 + 0.18 * a.cos(), 0.5 + 0.42 * a.sin())
                })
                .collect();
            line(ell);
            line(vec![u(0.08, 0.5), u(0.92, 0.5)]);
            line(vec![u(0.16, 0.3), u(0.84, 0.3)]);
            line(vec![u(0.16, 0.7), u(0.84, 0.7)]);
        }
        Icon::Bell => {
            let mut pts = vec![u(0.14, 0.74)];
            pts.extend(arc_points(u(0.44, 0.42), s * 0.22, 180.0, 0.0, 12));
            pts.push(u(0.74, 0.74));
            pts.push(u(0.14, 0.74));
            line(pts);
            line(arc_points(u(0.44, 0.78), s * 0.08, 0.0, -180.0, 6));
            let plus = Stroke::new(st.width * 0.8, color);
            p.line_segment([u(0.8, 0.5), u(1.0, 0.5)], plus);
            p.line_segment([u(0.9, 0.4), u(0.9, 0.6)], plus);
        }
        Icon::ArrowDown | Icon::ArrowUp => {
            let (a, b) = if icon == Icon::ArrowDown { (0.1, 0.9) } else { (0.9, 0.1) };
            line(vec![u(0.5, a), u(0.5, b)]);
            let back = if icon == Icon::ArrowDown { b - 0.28 } else { b + 0.28 };
            line(vec![u(0.25, back), u(0.5, b), u(0.75, back)]);
        }
        Icon::Chevron => line(vec![u(0.22, 0.36), u(0.5, 0.64), u(0.78, 0.36)]),
        Icon::ChevronRight => line(vec![u(0.38, 0.22), u(0.64, 0.5), u(0.38, 0.78)]),
        Icon::Search => {
            p.circle_stroke(u(0.42, 0.42), s * 0.28, st);
            line(vec![u(0.63, 0.63), u(0.9, 0.9)]);
        }
        // Fedora over a pair of glasses.
        Icon::Privacy => {
            p.add(Shape::convex_polygon(vec![u(0.3, 0.46), u(0.34, 0.14), u(0.66, 0.14), u(0.7, 0.46)], color, Stroke::NONE));
            line(vec![u(0.04, 0.5), u(0.96, 0.5)]);
            for x in [0.32, 0.68] {
                p.circle_stroke(u(x, 0.76), s * 0.12, st);
            }
            line(vec![u(0.44, 0.74), u(0.56, 0.74)]);
        }
        Icon::Reset => {
            // Circular arrow: an open ring whose upper-right end carries a head pointing clockwise.
            let ring = arc_points(u(0.5, 0.5), s * 0.34, 60.0, 340.0, 20);
            let (tip, d) = (ring[0], vec2(0.866, 0.5));
            let (n, h) = (vec2(-d.y, d.x), s * 0.2);
            line(ring);
            line(vec![tip - d * h + n * h * 0.7, tip, tip - d * h - n * h * 0.7]);
        }
        // Power symbol: a ring open at the top with a bar through the gap.
        Icon::Restart => {
            line(arc_points(u(0.5, 0.55), s * 0.34, 125.0, 415.0, 24));
            line(vec![u(0.5, 0.08), u(0.5, 0.5)]);
        }
        Icon::Export => {
            line(vec![u(0.45, 0.15), u(0.15, 0.15), u(0.15, 0.85), u(0.85, 0.85), u(0.85, 0.55)]);
            line(vec![u(0.45, 0.55), u(0.88, 0.12)]);
            line(vec![u(0.6, 0.12), u(0.88, 0.12), u(0.88, 0.4)]);
        }
        Icon::Info => {
            p.circle_stroke(u(0.5, 0.5), s * 0.42, st);
            p.circle_filled(u(0.5, 0.3), st.width * 0.8, color);
            line(vec![u(0.5, 0.44), u(0.5, 0.74)]);
        }
        Icon::Palette => {
            p.circle_stroke(u(0.5, 0.5), s * 0.42, st);
            for (x, y) in [(0.34, 0.4), (0.52, 0.3), (0.68, 0.45), (0.4, 0.66)] {
                p.circle_filled(u(x, y), s * 0.07, color);
            }
        }
        Icon::More => {
            for x in [0.2, 0.5, 0.8] {
                p.circle_filled(u(x, 0.5), s * 0.08, color);
            }
        }
        Icon::Hourglass => {
            line(vec![u(0.22, 0.1), u(0.78, 0.1)]);
            line(vec![u(0.22, 0.9), u(0.78, 0.9)]);
            p.add(Shape::closed_line(vec![u(0.3, 0.1), u(0.7, 0.1), u(0.5, 0.5)], st));
            p.add(Shape::closed_line(vec![u(0.5, 0.5), u(0.7, 0.9), u(0.3, 0.9)], st));
            // The sand left in the top.
            p.add(Shape::convex_polygon(vec![u(0.4, 0.2), u(0.6, 0.2), u(0.5, 0.38)], color, Stroke::NONE));
        }
        Icon::Warning => {
            p.add(Shape::closed_line(vec![u(0.5, 0.12), u(0.94, 0.86), u(0.06, 0.86)], st));
            line(vec![u(0.5, 0.4), u(0.5, 0.62)]);
            p.circle_filled(u(0.5, 0.75), s * 0.04, color);
        }
        Icon::Sliders => {
            for (y, x) in [(0.3, 0.65), (0.7, 0.35)] {
                line(vec![u(0.08, y), u(0.92, y)]);
                p.circle_filled(u(x, y), s * 0.11, color);
            }
        }
        Icon::Check => line(vec![u(0.18, 0.52), u(0.42, 0.74), u(0.84, 0.28)]),
        Icon::Wifi => {
            for k in [0.28, 0.5, 0.72] {
                line(arc_points(u(0.5, 0.82), s * k, 45.0, 135.0, 10));
            }
            p.circle_filled(u(0.5, 0.8), s * 0.06, color);
        }
        Icon::Laptop => {
            p.rect_stroke(Rect::from_min_max(u(0.18, 0.22), u(0.82, 0.66)), 2.0, st, StrokeKind::Middle);
            line(vec![u(0.04, 0.78), u(0.96, 0.78)]);
        }
        Icon::Raspberry => {
            for (x, y) in [(0.5, 0.32), (0.3, 0.45), (0.7, 0.45), (0.38, 0.66), (0.62, 0.66), (0.5, 0.84)] {
                p.circle_stroke(u(x, y), s * 0.12, st);
            }
            line(vec![u(0.35, 0.08), u(0.5, 0.2), u(0.65, 0.08)]);
        }
        Icon::House => {
            line(vec![u(0.1, 0.5), u(0.5, 0.15), u(0.9, 0.5)]);
            line(vec![u(0.22, 0.42), u(0.22, 0.85), u(0.78, 0.85), u(0.78, 0.42)]);
            p.rect_stroke(Rect::from_min_max(u(0.42, 0.58), u(0.58, 0.85)), 0.0, st, StrokeKind::Middle);
        }
        Icon::Bulb => {
            line(arc_points(u(0.5, 0.4), s * 0.27, -50.0, 230.0, 16));
            line(vec![u(0.4, 0.75), u(0.6, 0.75)]);
            line(vec![u(0.43, 0.88), u(0.57, 0.88)]);
        }
        Icon::Plug => {
            line(vec![u(0.38, 0.1), u(0.38, 0.35)]);
            line(vec![u(0.62, 0.1), u(0.62, 0.35)]);
            p.rect_stroke(Rect::from_min_max(u(0.25, 0.35), u(0.75, 0.62)), 3.0, st, StrokeKind::Middle);
            line(vec![u(0.5, 0.62), u(0.5, 0.9)]);
        }
        Icon::Sensor => {
            p.circle_filled(u(0.5, 0.62), s * 0.08, color);
            line(arc_points(u(0.5, 0.62), s * 0.25, 20.0, 160.0, 10));
            line(arc_points(u(0.5, 0.62), s * 0.42, 20.0, 160.0, 12));
        }
        Icon::Camera => {
            p.rect_stroke(Rect::from_min_max(u(0.1, 0.3), u(0.9, 0.78)), 3.0, st, StrokeKind::Middle);
            p.circle_stroke(u(0.5, 0.54), s * 0.14, st);
            line(vec![u(0.3, 0.3), u(0.36, 0.2), u(0.64, 0.2), u(0.7, 0.3)]);
        }
        Icon::Lock => {
            p.rect_stroke(Rect::from_min_max(u(0.22, 0.45), u(0.78, 0.88)), 3.0, st, StrokeKind::Middle);
            line(arc_points(u(0.5, 0.45), s * 0.2, 0.0, 180.0, 12));
        }
        Icon::Click => {
            line(vec![u(0.42, 0.9), u(0.42, 0.3)]);
            line(vec![u(0.42, 0.3), u(0.5, 0.22), u(0.58, 0.3), u(0.58, 0.55), u(0.78, 0.6), u(0.78, 0.9)]);
            line(vec![u(0.42, 0.6), u(0.28, 0.55), u(0.28, 0.72), u(0.42, 0.9)]);
            line(arc_points(u(0.5, 0.3), s * 0.24, 20.0, 160.0, 8));
        }
        Icon::Minimize => line(vec![u(0.2, 0.5), u(0.8, 0.5)]),
        Icon::Maximize => {
            p.rect_stroke(Rect::from_min_max(u(0.22, 0.22), u(0.78, 0.78)), 0.0, Stroke::new(1.2, color), StrokeKind::Middle);
        }
        Icon::Close => {
            let thin = Stroke::new(1.2, color);
            p.line_segment([u(0.22, 0.22), u(0.78, 0.78)], thin);
            p.line_segment([u(0.78, 0.22), u(0.22, 0.78)], thin);
        }
    }
}

/// Tiny flag, about 3:2. `Local` and `Other` get generic tiles.
/// The bundled flag image for an ISO code, decoded once and cached in the egui context.
fn flag_texture(ctx: &egui::Context, code: [u8; 2]) -> Option<egui::TextureHandle> {
    let id = egui::Id::NULL.with(("flag_texture", code));
    if let Some(cached) = ctx.data(|d| d.get_temp::<Option<egui::TextureHandle>>(id)) {
        return cached;
    }
    let name = String::from_utf8_lossy(&code).to_lowercase();
    let tex = crate::flag_data::FLAGS.iter().find(|(n, _)| *n == name).and_then(|(_, bytes)| {
        let mut decoder = png::Decoder::new(std::io::Cursor::new(*bytes));
        decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
        let mut reader = decoder.read_info().ok()?;
        let mut buf = vec![0; reader.output_buffer_size()?];
        let info = reader.next_frame(&mut buf).ok()?;
        let (w, h) = (info.width as usize, info.height as usize);
        let data = &buf[..info.buffer_size()];
        let image = match info.color_type {
            png::ColorType::Rgba => egui::ColorImage::from_rgba_unmultiplied([w, h], data),
            png::ColorType::Rgb => egui::ColorImage::from_rgb([w, h], data),
            png::ColorType::GrayscaleAlpha => {
                let rgba: Vec<u8> = data.as_chunks::<2>().0.iter().flat_map(|&[l, a]| [l, l, l, a]).collect();
                egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba)
            }
            png::ColorType::Grayscale => {
                let rgb: Vec<u8> = data.iter().flat_map(|g| [*g, *g, *g]).collect();
                egui::ColorImage::from_rgb([w, h], &rgb)
            }
            png::ColorType::Indexed => return None,
        };
        Some(ctx.load_texture(format!("flag-{name}"), image, egui::TextureOptions::LINEAR))
    });
    ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
    tex
}

pub fn flag(p: &Painter, country: Country, rect: Rect) {
    let r = Rect::from_center_size(rect.center(), vec2(rect.width(), rect.width() * 0.66));
    let vstripes = |cols: [Color32; 3]| {
        for (i, c) in cols.iter().enumerate() {
            let w = r.width() / 3.0;
            p.rect_filled(Rect::from_min_size(r.min + vec2(w * i as f32, 0.0), vec2(w, r.height())), 0.0, *c);
        }
    };
    let hstripes = |cols: [Color32; 3]| {
        for (i, c) in cols.iter().enumerate() {
            let h = r.height() / 3.0;
            p.rect_filled(Rect::from_min_size(r.min + vec2(0.0, h * i as f32), vec2(r.width(), h)), 0.0, *c);
        }
    };
    let rgb = Color32::from_rgb;
    match country {
        Country::Local => {
            p.rect_filled(r, 1.0, rgb(0xd3, 0xdc, 0xe8));
            for i in 0..3 {
                let y = r.top() + r.height() * (0.25 + 0.25 * i as f32);
                p.line_segment([pos2(r.left(), y), pos2(r.right(), y)], Stroke::new(1.5, rgb(0xa7, 0xb8, 0xd0)));
            }
        }
        Country::Other => {
            p.rect_filled(r, 1.0, rgb(0x9a, 0xe6, 0xc0));
            p.circle_filled(r.center() + vec2(-r.width() * 0.15, 0.0), r.height() * 0.3, rgb(0x5a, 0xc3, 0x9c));
            p.circle_filled(r.center() + vec2(r.width() * 0.22, -r.height() * 0.1), r.height() * 0.2, rgb(0x5a, 0xc3, 0x9c));
        }
        Country::Iso(code) if flag_texture(p.ctx(), code).is_some() => {
            let tex = flag_texture(p.ctx(), code).expect("checked above");
            // Keep the flag's own proportions inside the slot (Nepal is taller than wide).
            let [w, h] = tex.size();
            let k = (r.width() / w as f32).min(r.height() / h as f32);
            let fr = Rect::from_center_size(r.center(), vec2(w as f32 * k, h as f32 * k));
            p.image(tex.id(), fr, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
            p.rect_stroke(fr, 0.0, Stroke::new(1.0, Color32::from_black_alpha(40)), StrokeKind::Inside);
        }
        Country::Iso(code) => {
            // No bundled or hand-drawn flag: a tile tinted from the code, with the code on it.
            let h = (code[0] as u32 * 31 + code[1] as u32 * 17) % 6;
            let tint = [rgb(0xb7, 0xd7, 0xf5), rgb(0xf5, 0xd7, 0xb7), rgb(0xc9, 0xeb, 0xc4), rgb(0xe6, 0xc9, 0xf0), rgb(0xf3, 0xe5, 0xa8), rgb(0xc4, 0xe4, 0xe8)][h as usize];
            p.rect_filled(r, 1.0, tint);
            p.text(r.center(), egui::Align2::CENTER_CENTER, String::from_utf8_lossy(&code), egui::FontId::proportional((r.height() * 0.62).max(7.0)), rgb(0x3a, 0x44, 0x55));
        }
        Country::Ireland => vstripes([rgb(0x16, 0x9b, 0x62), Color32::WHITE, rgb(0xff, 0x88, 0x3e)]),
        Country::France => vstripes([rgb(0x00, 0x55, 0xa4), Color32::WHITE, rgb(0xef, 0x41, 0x35)]),
        Country::Germany => hstripes([rgb(0x22, 0x22, 0x22), rgb(0xdd, 0x00, 0x00), rgb(0xff, 0xce, 0x00)]),
        Country::Netherlands => hstripes([rgb(0xae, 0x1c, 0x28), Color32::WHITE, rgb(0x21, 0x46, 0x8b)]),
        Country::Sweden => {
            p.rect_filled(r, 0.0, rgb(0x00, 0x6a, 0xa7));
            let y = r.center().y;
            let x = r.left() + r.width() * 0.38;
            p.line_segment([pos2(r.left(), y), pos2(r.right(), y)], Stroke::new(r.height() * 0.22, rgb(0xfe, 0xcc, 0x00)));
            p.line_segment([pos2(x, r.top()), pos2(x, r.bottom())], Stroke::new(r.height() * 0.22, rgb(0xfe, 0xcc, 0x00)));
        }
        Country::UnitedKingdom => {
            p.rect_filled(r, 0.0, rgb(0x01, 0x21, 0x69));
            let white = Stroke::new(r.height() * 0.2, Color32::WHITE);
            p.line_segment([r.left_top(), r.right_bottom()], white);
            p.line_segment([r.right_top(), r.left_bottom()], white);
            let red_d = Stroke::new(r.height() * 0.08, rgb(0xc8, 0x10, 0x2e));
            p.line_segment([r.left_top(), r.right_bottom()], red_d);
            p.line_segment([r.right_top(), r.left_bottom()], red_d);
            let c = r.center();
            p.line_segment([pos2(r.left(), c.y), pos2(r.right(), c.y)], Stroke::new(r.height() * 0.32, Color32::WHITE));
            p.line_segment([pos2(c.x, r.top()), pos2(c.x, r.bottom())], Stroke::new(r.height() * 0.32, Color32::WHITE));
            p.line_segment([pos2(r.left(), c.y), pos2(r.right(), c.y)], Stroke::new(r.height() * 0.18, rgb(0xc8, 0x10, 0x2e)));
            p.line_segment([pos2(c.x, r.top()), pos2(c.x, r.bottom())], Stroke::new(r.height() * 0.18, rgb(0xc8, 0x10, 0x2e)));
        }
        Country::UnitedStates => {
            let h = r.height() / 7.0;
            for i in 0..7 {
                let c = if i % 2 == 0 { rgb(0xb2, 0x22, 0x34) } else { Color32::WHITE };
                p.rect_filled(Rect::from_min_size(r.min + vec2(0.0, h * i as f32), vec2(r.width(), h)), 0.0, c);
            }
            p.rect_filled(Rect::from_min_size(r.min, vec2(r.width() * 0.42, h * 4.0)), 0.0, rgb(0x3c, 0x3b, 0x6e));
        }
    }
    p.rect_stroke(r, 0.0, Stroke::new(0.5, Color32::from_black_alpha(30)), StrokeKind::Inside);
}

enum IconState {
    Loading,
    Done(Option<egui::TextureHandle>),
}

/// Shell icons by path. One worker extracts them, so a slow disk or a dead network share never stalls a frame.
struct IconCache {
    map: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, IconState>>>,
    ask: std::sync::mpsc::Sender<String>,
}

impl IconCache {
    fn start(ctx: egui::Context) -> Self {
        let map: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, IconState>>> = Default::default();
        let (ask, asked) = std::sync::mpsc::channel::<String>();
        let done = map.clone();
        std::thread::spawn(move || {
            for path in asked {
                // A panic in the shell call still ends the wait; the stand-in is drawn.
                let tex = std::panic::catch_unwind(|| crate::sys::apps::file_icon_rgba(&path))
                    .ok()
                    .flatten()
                    .map(|(px, side)| ctx.load_texture(&path, egui::ColorImage::from_rgba_unmultiplied([side, side], &px), egui::TextureOptions::LINEAR));
                done.lock().unwrap_or_else(|e| e.into_inner()).insert(path, IconState::Done(tex));
                ctx.request_repaint();
            }
        });
        Self { map, ask }
    }

    /// The icon if it has been extracted; the first ask for a path queues it.
    fn get(&self, path: &str) -> Option<egui::TextureHandle> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(path) {
            Some(IconState::Done(tex)) => tex.clone(),
            Some(IconState::Loading) => None,
            None => {
                map.insert(path.to_owned(), IconState::Loading);
                let _ = self.ask.send(path.to_owned());
                None
            }
        }
    }
}

/// The program's own icon when the shell has one for `path` (cached per path), else the drawn stand-in.
pub fn app_icon_for(p: &Painter, icon: AppIcon, path: &str, rect: Rect) {
    static ICONS: std::sync::OnceLock<IconCache> = std::sync::OnceLock::new();
    if !path.is_empty() {
        let tex = ICONS.get_or_init(|| IconCache::start(p.ctx().clone())).get(path);
        if let Some(t) = tex {
            let s = rect.width().min(rect.height());
            p.image(t.id(), Rect::from_center_size(rect.center(), vec2(s, s)), Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), Color32::WHITE);
            return;
        }
    }
    app_icon(p, icon, rect);
}

/// Stand-ins for executable icons. Real code would load the icon from the binary.
pub fn app_icon(p: &Painter, icon: AppIcon, rect: Rect) {
    let s = rect.width().min(rect.height());
    let r = Rect::from_center_size(rect.center(), vec2(s, s));
    let c = r.center();
    let rgb = Color32::from_rgb;
    match icon {
        AppIcon::Generic | AppIcon::Installer => {
            let body = r.shrink2(vec2(s * 0.05, s * 0.15));
            p.rect_filled(body, 2.0, Color32::WHITE);
            p.rect_stroke(body, 2.0, Stroke::new(1.0, rgb(0xa9, 0xc4, 0xe8)), StrokeKind::Inside);
            let bar = Rect::from_min_size(body.min, vec2(body.width(), body.height() * 0.28));
            p.rect_filled(bar, CornerRadius { nw: 2, ne: 2, sw: 0, se: 0 }, rgb(0xd2, 0xe3, 0xf6));
            if icon == AppIcon::Installer {
                p.circle_filled(body.center() + vec2(0.0, s * 0.08), s * 0.18, rgb(0x2b, 0x8a, 0xd8));
            }
        }
        AppIcon::Gear => {
            p.rect_filled(r, 2.0, rgb(0x35, 0x9a, 0xe0));
            p.circle_stroke(c + vec2(-s * 0.1, s * 0.08), s * 0.16, Stroke::new(2.0, Color32::WHITE));
            p.circle_stroke(c + vec2(s * 0.2, -s * 0.18), s * 0.09, Stroke::new(1.5, Color32::WHITE));
        }
        AppIcon::Chrome => {
            let segs = [rgb(0xea, 0x43, 0x35), rgb(0xfb, 0xbc, 0x05), rgb(0x34, 0xa8, 0x53)];
            for (i, col) in segs.iter().enumerate() {
                let a0 = 90.0 + 120.0 * i as f32;
                let mut pts = vec![c];
                pts.extend(arc_points(c, s * 0.48, a0, a0 + 120.0, 10));
                p.add(Shape::convex_polygon(pts, *col, Stroke::NONE));
            }
            p.circle_filled(c, s * 0.22, Color32::WHITE);
            p.circle_filled(c, s * 0.16, rgb(0x42, 0x85, 0xf4));
        }
        AppIcon::VsCode => {
            let blue = rgb(0x00, 0x7a, 0xcc);
            let u = |x: f32, y: f32| r.min + vec2(x * s, y * s);
            p.add(Shape::convex_polygon(vec![u(0.68, 0.05), u(0.92, 0.18), u(0.92, 0.82), u(0.68, 0.95)], blue, Stroke::NONE));
            p.add(Shape::line(vec![u(0.75, 0.15), u(0.12, 0.68)], Stroke::new(s * 0.16, blue)));
            p.add(Shape::line(vec![u(0.75, 0.85), u(0.12, 0.32)], Stroke::new(s * 0.16, rgb(0x1f, 0x9c, 0xf0))));
        }
        AppIcon::Drive => {
            let u = |x: f32, y: f32| r.min + vec2(x * s, y * s);
            p.add(Shape::convex_polygon(vec![u(0.35, 0.1), u(0.65, 0.1), u(0.4, 0.55), u(0.25, 0.3)], rgb(0x00, 0xac, 0x47), Stroke::NONE));
            p.add(Shape::convex_polygon(vec![u(0.65, 0.1), u(0.95, 0.62), u(0.65, 0.62), u(0.5, 0.36)], rgb(0xff, 0xba, 0x00), Stroke::NONE));
            p.add(Shape::convex_polygon(vec![u(0.25, 0.62), u(0.95, 0.62), u(0.8, 0.88), u(0.1, 0.88)], rgb(0x26, 0x84, 0xfc), Stroke::NONE));
        }
        AppIcon::Claude | AppIcon::ClaudeCode => {
            let (bg, fg) = if icon == AppIcon::Claude { (rgb(0xe0, 0x7a, 0x5f), Color32::WHITE) } else { (rgb(0x1f, 0x1f, 0x1f), rgb(0xe0, 0x7a, 0x5f)) };
            p.rect_filled(r, 3.0, bg);
            for i in 0..6 {
                let a = (i as f32 * 30.0).to_radians();
                let d = vec2(a.cos(), a.sin()) * s * 0.32;
                p.line_segment([c - d, c + d], Stroke::new(s * 0.09, fg));
            }
        }
        AppIcon::Bitwarden => {
            let blue = rgb(0x17, 0x5d, 0xdc);
            p.rect_filled(r, 2.0, blue);
            paint(p, Icon::Shield, r.shrink(s * 0.15), Color32::WHITE);
        }
        AppIcon::RemoteDesktop => {
            p.circle_stroke(c, s * 0.36, Stroke::new(s * 0.14, rgb(0x02, 0x4e, 0xff)));
            p.rect_filled(Rect::from_center_size(c + vec2(s * 0.3, -s * 0.1), vec2(s * 0.2, s * 0.25)), 0.0, Color32::WHITE);
        }
        AppIcon::Monitor => {
            p.rect_filled(Rect::from_min_max(r.min + vec2(s * 0.08, s * 0.12), r.max - vec2(s * 0.08, s * 0.3)), 1.0, rgb(0x1e, 0x88, 0xe5));
            p.rect_filled(Rect::from_center_size(c + vec2(0.0, s * 0.34), vec2(s * 0.4, s * 0.08)), 0.0, rgb(0x15, 0x65, 0xc0));
        }
    }
}

pub fn glyph(p: &Painter, g: Glyph, rect: Rect) {
    match g {
        Glyph::App(icon) => app_icon(p, icon, rect),
        Glyph::Flag(country) => flag(p, country, rect),
        Glyph::Window => app_icon(p, AppIcon::Generic, rect),
        Glyph::More => {
            let s = rect.height() * 0.38;
            for (dx, dy) in [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)] {
                let min = rect.center() - vec2(s + 1.0, s + 1.0) + vec2(dx, dy) * (s + 2.0);
                p.rect_filled(Rect::from_min_size(min, vec2(s, s)), 1.0, theme::accent_soft().gamma_multiply(1.0));
                p.rect_stroke(Rect::from_min_size(min, vec2(s, s)), 1.0, Stroke::new(1.0, theme::accent()), StrokeKind::Inside);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ring_has_no_repeated_end_point() {
        let pts = ring(pos2(10.0, 10.0), 5.0, 24);
        assert_eq!(pts.len(), 24);
        assert!(pts.first().unwrap().distance(*pts.last().unwrap()) > 0.1);
    }
}
