use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, Stroke};
use std::sync::Arc;

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering::Relaxed};

/// The chosen accent colour as `1 << 24 | 0xRRGGBB`; 0 keeps the built-in teal and orange look.
static ACCENT: AtomicU32 = AtomicU32::new(0);
static DARK: AtomicBool = AtomicBool::new(false);
/// Opacity of the big surfaces; below 255 the acrylic backdrop shines through.
static MICA: AtomicBool = AtomicBool::new(false);
static ALPHA: AtomicU8 = AtomicU8::new(255);
/// Opacity floor of popups (Settings > Appearance), 0..=255.
static POPUP_MIN: AtomicU8 = AtomicU8::new(230);

/// Pure white ink (text on accents, knobs); the same in both themes.
pub const WHITE: Color32 = Color32::WHITE;

/// Whether the windows use Mica (true) or grey acrylic, as last asked of [`acrylic`].
pub fn mica() -> bool {
    MICA.load(Relaxed)
}

pub fn is_dark() -> bool {
    DARK.load(Relaxed)
}

pub fn pick(light: Color32, dark: Color32) -> Color32 {
    if is_dark() { dark } else { light }
}

const fn rgb(c: u32) -> Color32 {
    Color32::from_rgb((c >> 16) as u8, (c >> 8) as u8, c as u8)
}

/// A color that stays solid: `fn name() -> Color32` from a light and a dark hex value.
macro_rules! colors {
    ($($name:ident $light:literal $dark:literal),* $(,)?) => {$(
        pub fn $name() -> Color32 { pick(rgb($light), rgb($dark)) }
    )*};
}

/// Like `colors!` but see-through by the acrylic setting.
macro_rules! surfaces {
    ($($name:ident $light:literal $dark:literal),* $(,)?) => {$(
        pub fn $name() -> Color32 {
            let c = pick(rgb($light), rgb($dark));
            Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), ALPHA.load(Relaxed))
        }
    )*};
}

colors! {
    text 0x22262e 0xe6e8eb, text_dim 0x8c929b 0x9aa0a8, text_faint 0xb4b9c0 0x6b7178,
    row_hover 0xeef3fc 0x34383d,
    // The cream of the logo's "Warden".
    brand_cream 0x2a2118 0xf8f3e6,
    yellow 0xfcd016 0xfcd016, orange 0xfa7a2a 0xfa7a2a,
    green 0x1da75a 0x2fc274,
    red 0xf03a2e 0xf03a2e, red_soft 0xfde4e4 0x4a2a2a,
    banner_bg 0xe9fbb9 0x3a4220,
    // Inputs and tracks that sit on a surface.
    field 0xecedf1 0x3a3e44, surface_solid 0xffffff 0x2b2d30, track_off 0x8793b8 0x5a6275,
}

surfaces! {
    surface 0xffffff 0x2b2d30, panel_bg 0xf4f5f7 0x232527,
    row_alt 0xf7f8f9 0x2f3134,
}

fn glass(light: [u8; 4], dark: [u8; 4]) -> Color32 {
    let c = if is_dark() { dark } else { light };
    Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3])
}

/// Fluent layers that sit on a Mica or acrylic window: a settings card, its edge, a control on it, the selected nav item, the footer bar.
pub fn card() -> Color32 {
    glass([255, 255, 255, 178], [255, 255, 255, 13])
}
/// Dividers and outlines: the same soft edge as the cards, so they sit lightly on the backdrop.
pub fn border() -> Color32 {
    card_edge()
}
/// The sheet of an alert popup: the surface colour, but never less than ~90% opaque, so a small popup stays readable at any Acrylic setting.
pub fn popup_surface() -> Color32 {
    let c = pick(rgb(0xffffff), rgb(0x2b2d30));
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), ALPHA.load(Relaxed).max(POPUP_MIN.load(Relaxed)))
}

/// Sets (or, with `None`, clears) the accent colour that replaces the built-in teal, the logo's orange and the traffic graph's colours.
pub fn set_accent(c: Option<[u8; 3]>) {
    ACCENT.store(c.map_or(0, |[r, g, b]| 1 << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32), Relaxed);
}

/// The accent colour in force, if one was chosen.
pub fn accent_rgb() -> Option<[u8; 3]> {
    let v = ACCENT.load(Relaxed);
    (v != 0).then_some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

fn custom() -> Option<Color32> {
    accent_rgb().map(|[r, g, b]| Color32::from_rgb(r, g, b))
}

fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

fn luma(c: Color32) -> f32 {
    (0.299 * c.r() as f32 + 0.587 * c.g() as f32 + 0.114 * c.b() as f32) / 255.0
}

/// The built-in teal, for the colour picker to start from.
pub fn accent_default() -> [u8; 3] {
    let c = pick(rgb(0x16857d), rgb(0x5ccfc3));
    [c.r(), c.g(), c.b()]
}

/// The accent as a fill: kept dark enough to carry white on the light theme, bright enough to show on the dark one.
pub fn accent() -> Color32 {
    let Some(c) = custom() else { return pick(rgb(0x16857d), rgb(0x5ccfc3)) };
    if is_dark() {
        if luma(c) < 0.45 { mix(c, WHITE, 0.45) } else { c }
    } else if luma(c) > 0.6 {
        mix(c, Color32::BLACK, 0.35)
    } else {
        c
    }
}

/// The accent as text and thin lines.
pub fn accent_text() -> Color32 {
    if custom().is_none() {
        return pick(rgb(0x0f6b64), rgb(0x7fe0d6));
    }
    if is_dark() { mix(accent(), WHITE, 0.3) } else { mix(accent(), Color32::BLACK, 0.2) }
}

/// A wash of the accent for selected rows.
pub fn accent_soft() -> Color32 {
    let Some(c) = custom() else { return pick(rgb(0xdcefec), rgb(0x1f3f3d)) };
    if is_dark() { mix(rgb(0x2b2d30), c, 0.3) } else { mix(WHITE, c, 0.16) }
}

/// Text and icons on an accent fill: white or near-black, whichever reads better.
pub fn on_accent() -> Color32 {
    if custom().is_some() {
        return if luma(accent()) > 0.6 { rgb(0x0c1a19) } else { WHITE };
    }
    pick(WHITE, rgb(0x0c1a19))
}

pub fn teal_dark() -> Color32 {
    custom().map_or_else(|| pick(rgb(0xd3d7de), rgb(0x3a4244)), |c| mix(pick(rgb(0xd5d5d5), rgb(0x3a3d40)), c, 0.18))
}

/// The Traffic tab's backdrop: the panel colour with a hint of the accent.
pub fn teal_bg() -> Color32 {
    let c = pick(rgb(0xedf0f5), rgb(0x25292b));
    let c = custom().map_or(c, |a| mix(pick(rgb(0xf0f1f3), rgb(0x25282a)), a, 0.1));
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), ALPHA.load(Relaxed))
}

/// The "Rust" of the logo: orange, or the accent.
pub fn brand_orange() -> Color32 {
    custom().map_or(rgb(0xf76c2e), |_| if is_dark() { accent() } else { accent_text() })
}

/// The logo's rim yellow: a lighter accent.
pub fn brand_yellow() -> Color32 {
    custom().map_or(rgb(0xfbbe31), |_| mix(accent(), WHITE, 0.45))
}

pub fn brand_wash() -> Color32 {
    custom().map_or_else(|| pick(rgb(0xfdeadd), rgb(0x3a2a20)), |_| accent_soft())
}

/// The accent turned a third of the way round the colour wheel: what upload gets when download takes the accent.
fn partner(c: Color32) -> Color32 {
    let (r, g, b) = (c.r() as f32, c.g() as f32, c.b() as f32);
    // Rotating RGB by 120 degrees about the grey axis.
    let (cs, sn) = ((-0.5f32), 0.866_025_4f32);
    let k = (1.0 - cs) / 3.0;
    let (a, d) = (k + cs, k - sn / 3f32.sqrt());
    let e = k + sn / 3f32.sqrt();
    let f = |x: f32| x.clamp(0.0, 255.0) as u8;
    Color32::from_rgb(f(r * a + g * e + b * d), f(r * d + g * a + b * e), f(r * e + g * d + b * a))
}

/// Download in the traffic graph, stats and bars: sky blue, or the accent.
pub fn down() -> Color32 {
    custom().map_or(rgb(0x2f9bff), |_| accent())
}

/// Upload in the stats, bars and arrows: orange, or a colour a third of the way round the wheel from the accent.
pub fn up() -> Color32 {
    custom().map_or(rgb(0xfa7a2a), |_| partner(accent()))
}

/// Upload in the traffic graph itself: orange, or the same partner colour.
pub fn up_chart() -> Color32 {
    custom().map_or_else(|| rgb(0xfa7a2a), |_| partner(accent()))
}

/// The empty part of a slider or scrubber rail.
pub fn track() -> Color32 {
    glass([0, 0, 0, 40], [255, 255, 255, 44])
}
pub fn card_edge() -> Color32 {
    glass([0, 0, 0, 24], [255, 255, 255, 16])
}
pub fn ctl() -> Color32 {
    glass([255, 255, 255, 210], [255, 255, 255, 15])
}
pub fn ctl_hover() -> Color32 {
    glass([255, 255, 255, 240], [255, 255, 255, 24])
}
pub fn nav_on() -> Color32 {
    glass([0, 0, 0, 14], [255, 255, 255, 16])
}
pub fn footer() -> Color32 {
    glass([243, 243, 243, 190], [0, 0, 0, 44])
}

/// Line of the hardware charts: blue, or the accent.
pub fn chart_line() -> Color32 {
    custom().map_or_else(|| pick(rgb(0x4a78e8), rgb(0x6a9bf5)), |_| accent())
}

pub fn chart_fill() -> Color32 {
    if custom().is_some() {
        let c = chart_line();
        return Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), pick(Color32::from_gray(40), Color32::from_gray(60)).r());
    }
    pick(Color32::from_rgba_premultiplied(12, 19, 36, 40), Color32::from_rgba_premultiplied(20, 30, 60, 60))
}

/// Sets theme and acrylic strength (0..=1 -> surfaces 255..~110 alpha).
pub fn set(dark: bool, acrylic: f32) {
    DARK.store(dark, Relaxed);
    ALPHA.store((255.0 - acrylic.clamp(0.0, 1.0) * 145.0) as u8, Relaxed);
}

/// Sets how opaque popups are at the least (0.5..=1).
pub fn set_popup_opacity(v: f32) {
    POPUP_MIN.store((v.clamp(0.5, 1.0) * 255.0).round() as u8, Relaxed);
}

pub fn font(size: f32) -> FontId {
    FontId::proportional(size)
}

pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("bold".into()))
}

/// Fonts, plus Segoe UI from the system when it exists (falls back to egui's fonts).
pub fn apply(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let mut bold_family = fonts.families[&FontFamily::Proportional].clone();
    for (name, path, is_bold) in [("segoe", r"C:\Windows\Fonts\segoeui.ttf", false), ("segoe-bold", r"C:\Windows\Fonts\seguisb.ttf", true)] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(name.into(), Arc::new(FontData::from_owned(bytes)));
            if is_bold {
                bold_family.insert(0, name.into());
            } else {
                fonts.families.get_mut(&FontFamily::Proportional).unwrap().insert(0, name.into());
            }
        }
    }
    fonts.families.insert(FontFamily::Name("bold".into()), bold_family);
    ctx.set_fonts(fonts);
    restyle(ctx);
    ctx.global_style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.text_styles.insert(egui::TextStyle::Body, font(14.0));
        style.text_styles.insert(egui::TextStyle::Button, font(14.0));
    });
}

/// Re-applies the egui visuals for the current theme; call after `set`.
pub fn restyle(ctx: &egui::Context) {
    ctx.set_visuals(if is_dark() { egui::Visuals::dark() } else { egui::Visuals::light() });
    ctx.global_style_mut(|style| {
        style.visuals.panel_fill = surface();
        style.visuals.window_fill = surface_solid(); // dialogs float over content, so they stay readable
        style.visuals.extreme_bg_color = panel_bg();
        style.visuals.selection.stroke.color = accent_text();
        style.visuals.widgets.noninteractive.fg_stroke.color = text();
        style.visuals.widgets.inactive.fg_stroke.color = text();
        // Buttons, combo boxes and slider knobs share one flat, softly rounded look.
        let (base, hover, press) = (ctl(), ctl_hover(), ctl_hover());
        let edge = Stroke::new(1.0, card_edge());
        style.visuals.text_edit_bg_color = Some(ctl());
        for (w, fill) in [(&mut style.visuals.widgets.inactive, base), (&mut style.visuals.widgets.hovered, hover), (&mut style.visuals.widgets.active, press)] {
            w.weak_bg_fill = fill;
            w.bg_fill = accent(); // slider knob
            w.bg_stroke = edge;
            w.corner_radius = 4.into();
            w.expansion = 0.0;
        }
        style.visuals.widgets.open.weak_bg_fill = base;
        style.visuals.widgets.open.corner_radius = 4.into();
        style.visuals.slider_trailing_fill = true;
        style.visuals.selection.bg_fill = accent();
        style.visuals.handle_shape = egui::style::HandleShape::Circle;
        style.spacing.slider_rail_height = 3.0;
        style.spacing.button_padding = egui::vec2(16.0, 6.0);
        // Right-click and drop-down menus: rounded soft sheet with roomy rows.
        style.visuals.menu_corner_radius = 8.into();
        style.visuals.window_corner_radius = 8.into();
        style.visuals.window_stroke = edge;
        style.visuals.popup_shadow = egui::Shadow { offset: [0, 4], blur: 16, spread: 0, color: Color32::from_black_alpha(60) };
        style.spacing.menu_margin = egui::Margin::same(6);
    });
}

/// Asks DWM for the Windows 11 acrylic backdrop behind the whole window (ignored before 22H2).
/// The extended DWM frame makes Windows paint its own caption buttons under ours. They come with the
/// system-menu style, which the window toolkit puts back whenever it refreshes the window, so this is
/// checked every frame and only touches the window when the style is back.
pub fn hide_caption_buttons(hwnd: isize) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{GWL_STYLE, GetWindowLongPtrW, SWP_FRAMECHANGED, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SetWindowLongPtrW, SetWindowPos, WS_SYSMENU};
    let hwnd = HWND(hwnd as *mut _);
    // SAFETY: plain style calls on our own window.
    unsafe {
        let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        if style & WS_SYSMENU.0 as isize != 0 {
            SetWindowLongPtrW(hwnd, GWL_STYLE, style & !(WS_SYSMENU.0 as isize));
            let _ = SetWindowPos(hwnd, None, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
        }
    }
}

/// Which sizing handle (a WM_NCHITTEST code) a point on the window's outer border belongs to.
/// `edge` is the border width and corners get twice that along each side. `rect` is (left, top, right, bottom).
fn border_hit(rect: (i32, i32, i32, i32), x: i32, y: i32, edge: i32) -> Option<isize> {
    let (l, t, r, b) = rect;
    if x < l || x >= r || y < t || y >= b {
        return None;
    }
    let corner = edge * 2;
    let (left, right, top, bottom) = (x - l < edge, r - x <= edge, y - t < edge, b - y <= edge);
    let (cl, cr, ct, cb) = (x - l < corner, r - x <= corner, y - t < corner, b - y <= corner);
    Some(match (left, right, top, bottom) {
        (true, _, _, _) if ct => 13,
        (true, _, _, _) if cb => 16,
        (_, true, _, _) if ct => 14,
        (_, true, _, _) if cb => 17,
        (_, _, true, _) if cl => 13,
        (_, _, true, _) if cr => 14,
        (_, _, _, true) if cl => 16,
        (_, _, _, true) if cr => 17,
        (true, ..) => 10,
        (_, true, ..) => 11,
        (_, _, true, _) => 12,
        (_, _, _, true) => 15,
        _ => return None,
    })
}

unsafe extern "system" fn resize_proc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wp: windows::Win32::Foundation::WPARAM,
    lp: windows::Win32::Foundation::LPARAM,
    _id: usize,
    _data: usize,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Foundation::{LRESULT, RECT};
    use windows::Win32::UI::HiDpi::GetDpiForWindow;
    use windows::Win32::UI::Shell::DefSubclassProc;
    use windows::Win32::UI::WindowsAndMessaging::{GetWindowRect, IsZoomed};
    const WM_NCHITTEST: u32 = 0x0084;
    // SAFETY: called by Windows on our own window with valid arguments.
    unsafe {
        let res = DefSubclassProc(hwnd, msg, wp, lp);
        // Only the client area is ours to reclaim; leave the caption and system areas alone, and a maximized window has no border to drag.
        if msg == WM_NCHITTEST && res.0 == 1 && !IsZoomed(hwnd).as_bool() {
            let mut rc = RECT::default();
            if GetWindowRect(hwnd, &mut rc).is_ok() {
                let (x, y) = (i32::from(lp.0 as i16), i32::from((lp.0 >> 16) as i16));
                let edge = (8 * GetDpiForWindow(hwnd) as i32 / 96).max(6);
                if let Some(code) = border_hit((rc.left, rc.top, rc.right, rc.bottom), x, y, edge) {
                    return LRESULT(code);
                }
            }
        }
        res
    }
}

/// The window has no frame of its own, so its whole outer border is made a sizing handle: Windows then
/// shows the resize cursor and runs the resize itself, wherever the pointer is on any edge or corner.
/// Call once, from the thread that owns the window.
pub fn install_resize_border(hwnd: isize) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::SetWindowSubclass;
    // SAFETY: subclassing our own window; the procedure lives for the whole process.
    unsafe {
        let _ = SetWindowSubclass(HWND(hwnd as *mut _), Some(resize_proc), 1, 0);
    }
}

/// `tint` swaps acrylic for Mica, which Windows colours from the wallpaper.
pub fn acrylic(hwnd: isize, dark: bool, tint: bool) {
    MICA.store(tint, Relaxed);
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Dwm::{DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_USE_IMMERSIVE_DARK_MODE, DwmExtendFrameIntoClientArea, DwmSetWindowAttribute};
    use windows::Win32::UI::Controls::MARGINS;
    let hwnd = HWND(hwnd as *mut _);
    // 3 = DWMSBT_TRANSIENTWINDOW (acrylic), 2 = DWMSBT_MAINWINDOW (Mica)
    let (dark, acrylic) = (dark as i32, if tint { 2i32 } else { 3 });
    let sheet = MARGINS { cxLeftWidth: -1, cxRightWidth: -1, cyTopHeight: -1, cyBottomHeight: -1 };
    // SAFETY: plain DWM calls on our own window with correctly sized i32 values.
    unsafe {
        let _ = DwmExtendFrameIntoClientArea(hwnd, &sheet);
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark as *const _ as _, 4);
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &acrylic as *const _ as _, 4);
    }
}

/// Sets up the notification windows titled `title` (see `ui::toast`): rounded corners and a soft shadow from the
/// system, no activation and no Alt-Tab entry, and, with `fade`, a fade-in while the window is new. Info panels and
/// menus pass `false`: they appear at once. A faded window stays layered at full opacity once it has settled, since
/// switching the style off redraws the window as a visible flash. Safe to call every frame; each window is set up once.
pub fn toast_window(title: &str, fade: bool) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;
    use windows::Win32::Foundation::{COLORREF, HWND};
    use windows::Win32::Graphics::Dwm::{DWMWA_WINDOW_CORNER_PREFERENCE, DwmExtendFrameIntoClientArea, DwmSetWindowAttribute};
    use windows::Win32::UI::Controls::MARGINS;
    use windows::Win32::UI::WindowsAndMessaging::{GWL_EXSTYLE, GetWindowLongPtrW, LWA_ALPHA, SetLayeredWindowAttributes, SetWindowLongPtrW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW};
    /// Per window: (title, when first seen, whether the fade has finished)
    type Seen = (String, Instant, bool);
    static SEEN: Mutex<Option<HashMap<isize, Seen>>> = Mutex::new(None);
    let found = crate::sys::modal::find_all(title);
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let seen = seen.get_or_insert_with(HashMap::new);
    // Forget windows that are gone, so a recycled handle starts fresh.
    seen.retain(|h, (t, ..)| t != title || found.contains(h));
    for hwnd in found {
        let new = !seen.contains_key(&hwnd);
        let (_, born, done) = seen.entry(hwnd).or_insert_with(|| (title.to_owned(), Instant::now(), false));
        let h = HWND(hwnd as *mut _);
        // SAFETY: plain DWM and user32 calls on our own window with correctly sized values.
        unsafe {
            if new {
                let round = 2i32; // DWMWCP_ROUND
                let _ = DwmSetWindowAttribute(h, DWMWA_WINDOW_CORNER_PREFERENCE, &round as *const _ as _, 4);
                // A one pixel frame extension is what gives a borderless window the system shadow.
                let _ = DwmExtendFrameIntoClientArea(h, &MARGINS { cxLeftWidth: 1, cxRightWidth: 1, cyTopHeight: 1, cyBottomHeight: 1 });
            }
            let style = GetWindowLongPtrW(h, GWL_EXSTYLE);
            let wanted = WS_EX_NOACTIVATE.0 as isize | WS_EX_TOOLWINDOW.0 as isize;
            let age = born.elapsed().as_secs_f32();
            if *done {
                if style & wanted != wanted {
                    SetWindowLongPtrW(h, GWL_EXSTYLE, style | wanted);
                }
                continue;
            }
            if fade && crate::ui::toast::animating(age) {
                SetWindowLongPtrW(h, GWL_EXSTYLE, style | wanted | WS_EX_LAYERED.0 as isize);
                let _ = SetLayeredWindowAttributes(h, COLORREF(0), crate::ui::toast::fade(age), LWA_ALPHA);
            } else {
                // Settled: fully opaque, and still layered (see above).
                SetWindowLongPtrW(h, GWL_EXSTYLE, style | wanted);
                if fade && style & WS_EX_LAYERED.0 as isize != 0 {
                    let _ = SetLayeredWindowAttributes(h, COLORREF(0), 255, LWA_ALPHA);
                }
                *done = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn border_hits_edges_corners_and_not_the_middle() {
        let r = (0, 0, 1000, 700);
        let h = |x, y| super::border_hit(r, x, y, 8);
        assert_eq!(h(0, 350), Some(10));
        assert_eq!(h(999, 350), Some(11));
        assert_eq!(h(500, 0), Some(12));
        assert_eq!(h(500, 699), Some(15));
        assert_eq!(h(0, 0), Some(13));
        assert_eq!(h(12, 0), Some(13));
        assert_eq!(h(999, 0), Some(14));
        assert_eq!(h(0, 699), Some(16));
        assert_eq!(h(999, 699), Some(17));
        assert_eq!(h(500, 350), None);
        assert_eq!(h(-1, 350), None);
    }

    use super::*;

    #[test]
    fn accent_replaces_the_defaults_and_clears() {
        let teal = accent();
        set_accent(Some([0xd1, 0x34, 0x38]));
        assert_ne!(accent(), teal);
        assert_eq!(down(), accent());
        assert_ne!(up(), down());
        assert_eq!(accent_rgb(), Some([0xd1, 0x34, 0x38]));
        set_accent(None);
        assert_eq!(accent(), teal);
        assert_eq!(accent_rgb(), None);
    }
}
