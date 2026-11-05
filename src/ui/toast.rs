//! A small kit for Windows 11 style notification windows: placement in the work area, slide-in timing, the card
//! chrome, buttons (plain, accent, split), a checkbox, and flyout menus that live in their own small window so they
//! aren't clipped by the notification. The popups in `popup.rs` are built from these.

use crate::icons::{self, Icon};
use crate::theme;
use egui::epaint::{CornerRadius, StrokeKind};
use egui::{Align2, Color32, Rect, Response, Sense, Stroke, Ui, ViewportBuilder, ViewportId, pos2, vec2};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Which corner of the work area the notifications stack in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Corner {
    #[default]
    BottomRight,
    BottomLeft,
    TopRight,
    TopLeft,
}

impl Corner {
    pub const ALL: [Corner; 4] = [Corner::BottomRight, Corner::BottomLeft, Corner::TopRight, Corner::TopLeft];

    pub fn label(self) -> &'static str {
        match self {
            Corner::BottomRight => "Bottom right",
            Corner::BottomLeft => "Bottom left",
            Corner::TopRight => "Top right",
            Corner::TopLeft => "Top left",
        }
    }

    fn right(self) -> bool {
        matches!(self, Corner::BottomRight | Corner::TopRight)
    }

    fn bottom(self) -> bool {
        matches!(self, Corner::BottomRight | Corner::BottomLeft)
    }
}

/// Space between a notification and the work area's edge, and between stacked notifications (points).
pub const MARGIN: f32 = 16.0;
pub const GAP: f32 = 10.0;
/// How far a notification starts off to the side, and how long it takes to settle.
const SLIDE: f32 = 28.0;
const ANIM_SECS: f32 = 0.22;

/// Top-left positions (points) for notifications of `sizes`, the first one nearest the corner. `skip` is room
/// already taken next to the corner by something else (another stack).
pub fn stack(work: Rect, corner: Corner, sizes: &[egui::Vec2], skip: f32) -> Vec<egui::Pos2> {
    let mut used = skip;
    sizes
        .iter()
        .map(|s| {
            let x = if corner.right() { work.right() - MARGIN - s.x } else { work.left() + MARGIN };
            let y = if corner.bottom() { work.bottom() - MARGIN - used - s.y } else { work.top() + MARGIN + used };
            used += s.y + GAP;
            pos2(x, y)
        })
        .collect()
}

pub fn ease_out(t: f32) -> f32 {
    1.0 - (1.0 - t.clamp(0.0, 1.0)).powi(3)
}

/// How far a notification that is `age` seconds old still has to slide (points, towards its screen edge, so
/// a right-hand corner gives a positive offset to add to x).
pub fn slide_offset(corner: Corner, age: f32) -> f32 {
    let left = SLIDE * (1.0 - ease_out(age / ANIM_SECS));
    if corner.right() { left } else { -left }
}

/// 0..=255 opacity of a notification that is `age` seconds old.
pub fn fade(age: f32) -> u8 {
    (ease_out(age / ANIM_SECS) * 255.0).round() as u8
}

/// Whether a notification of this age is still moving or fading.
pub fn animating(age: f32) -> bool {
    age < ANIM_SECS
}

/// Seconds since `key` was first asked about; the key is whatever identifies a notification.
pub fn age(key: u64) -> f32 {
    static BORN: Mutex<Option<HashMap<u64, Instant>>> = Mutex::new(None);
    let mut born = BORN.lock().unwrap_or_else(|e| e.into_inner());
    born.get_or_insert_with(HashMap::new).entry(key).or_insert_with(Instant::now).elapsed().as_secs_f32()
}

/// The area notifications may use: the primary monitor without the taskbar, in points. Without an answer from
/// Windows, the screen less a bottom taskbar's worth.
pub fn work_area(ctx: &egui::Context) -> Rect {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::UI::WindowsAndMessaging::{SPI_GETWORKAREA, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SystemParametersInfoW};
    let mut r = RECT::default();
    // SAFETY: SPI_GETWORKAREA writes one RECT through the pointer, which outlives the call.
    let ok = unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, Some(&mut r as *mut RECT as *mut _), SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0)) }.is_ok();
    let ppp = ctx.pixels_per_point();
    if ok && r.right > r.left && r.bottom > r.top {
        Rect::from_min_max(pos2(r.left as f32 / ppp, r.top as f32 / ppp), pos2(r.right as f32 / ppp, r.bottom as f32 / ppp))
    } else {
        Rect::from_min_size(pos2(0.0, 0.0), super::popup::screen_size(ctx) - vec2(0.0, 48.0))
    }
}

/// True once per left-button press that lands outside every rect in `inside` (points). The windows here are
/// never active, so they can't be told about clicks elsewhere; this reads the mouse directly.
pub fn clicked_outside(ctx: &egui::Context, inside: &[Rect]) -> bool {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON};
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
    static WAS_DOWN: AtomicBool = AtomicBool::new(false);
    // SAFETY: plain user32 reads; `at` outlives the call.
    let (down, at) = unsafe {
        let mut at = POINT::default();
        let ok = GetCursorPos(&mut at).is_ok();
        (GetAsyncKeyState(VK_LBUTTON.0 as i32) < 0, ok.then_some(at))
    };
    let pressed = down && !WAS_DOWN.swap(down, Ordering::Relaxed);
    if !down {
        WAS_DOWN.store(false, Ordering::Relaxed);
    }
    let ppp = ctx.pixels_per_point();
    pressed && at.is_some_and(|p| !inside.iter().any(|r| r.contains(pos2(p.x as f32 / ppp, p.y as f32 / ppp))))
}

/// The window of a notification or flyout: borderless, always on top, off the taskbar, opaque (the OS rounds
/// its corners and gives it a shadow, see `theme::toast_window`).
pub fn window_builder(title: &str, size: egui::Vec2, pos: egui::Pos2) -> ViewportBuilder {
    ViewportBuilder::default().with_title(title).with_inner_size(size).with_position(pos).with_decorations(false).with_resizable(false).with_always_on_top().with_taskbar(false).with_active(false)
}

/// Paints the card (solid surface, soft edge) over the whole window and returns its rect.
pub fn chrome(ui: &Ui) -> Rect {
    chrome_edged(ui, Stroke::new(1.0, theme::card_edge()))
}

/// [`chrome`] with another edge, for a card that wants attention (a red one for a threat).
pub fn chrome_edged(ui: &Ui, edge: Stroke) -> Rect {
    let r = ui.max_rect();
    let p = ui.painter();
    // Square fill: the OS clips the window's corners; the edge follows the same curve.
    p.rect_filled(r, 0, theme::surface_solid());
    p.rect_stroke(r, 8, edge, StrokeKind::Inside);
    r
}

/// What was clicked in a card's [`header`].
#[derive(Default)]
pub struct HeaderClicks {
    pub gear: bool,
    pub close: bool,
}

/// The top line of a card: the app's mark and name on the left, an optional settings gear and the close button on the right.
pub fn header(ui: &Ui, r: Rect, gear: bool) -> HeaderClicks {
    let c = r.top() + 18.0;
    icons::paint(ui.painter(), Icon::Shield, Rect::from_center_size(pos2(r.left() + 24.0, c), vec2(14.0, 14.0)), theme::accent());
    ui.painter().text(pos2(r.left() + 38.0, c), Align2::LEFT_CENTER, "RustWarden", theme::font(12.0), theme::text_dim());
    let mut out = HeaderClicks { close: close_button(ui, pos2(r.right() - 22.0, c)), ..HeaderClicks::default() };
    if gear {
        out.gear = icon_button(ui, pos2(r.right() - 52.0, c), "gear", Icon::Sliders, "Settings for this alert");
    }
    out
}

/// A 48px tile holding an app's icon, with a green "NEW" pill under it.
pub fn app_tile(p: &egui::Painter, at: egui::Pos2, icon: crate::data::AppIcon) {
    let tile = Rect::from_min_size(at, vec2(48.0, 48.0));
    p.rect_filled(tile, 10, theme::card());
    p.rect_stroke(tile, 10, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
    icons::app_icon(p, icon, Rect::from_center_size(tile.center(), vec2(30.0, 30.0)));
    let new = Rect::from_center_size(pos2(tile.center().x, tile.bottom() + 14.0), vec2(40.0, 16.0));
    p.rect_filled(new, 8, Color32::from_rgb(0x6c, 0xc5, 0x4a));
    p.text(new.center(), Align2::CENTER_CENTER, "NEW", theme::bold(10.0), theme::WHITE);
}

/// A 48px solid tile with one character in it, for warnings ("!").
pub fn mark_tile(p: &egui::Painter, at: egui::Pos2, mark: &str, color: Color32) {
    let tile = Rect::from_min_size(at, vec2(48.0, 48.0));
    p.rect_filled(tile, 10, color);
    p.text(tile.center(), Align2::CENTER_CENTER, mark, theme::bold(26.0), theme::WHITE);
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Look {
    Primary,
    Standard,
    /// A red fill, for blocking a threat or confirming something risky.
    Danger,
}

fn button_colors(look: Look, resp: &Response) -> (Color32, Color32) {
    let pressed = resp.is_pointer_button_down_on();
    match look {
        Look::Primary | Look::Danger => {
            let (f, ink) = if look == Look::Danger { (theme::red(), theme::WHITE) } else { (theme::accent(), theme::on_accent()) };
            (
                if pressed {
                    f.gamma_multiply(0.8)
                } else if resp.hovered() {
                    f.gamma_multiply(0.92)
                } else {
                    f
                },
                ink,
            )
        }
        Look::Standard => (
            if pressed {
                theme::card_edge()
            } else if resp.hovered() {
                theme::ctl_hover()
            } else {
                theme::ctl()
            },
            theme::text(),
        ),
    }
}

fn hand(r: Response) -> Response {
    r.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A 32px button; true when clicked.
pub fn button(ui: &Ui, rect: Rect, id: &str, label: &str, look: Look) -> bool {
    let resp = hand(ui.interact(rect, ui.scope_id().with(id), Sense::click()));
    let (fill, ink) = button_colors(look, &resp);
    let p = ui.painter();
    p.rect_filled(rect, 6, fill);
    if look == Look::Standard {
        p.rect_stroke(rect, 6, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
    }
    p.text(rect.center(), Align2::CENTER_CENTER, label, theme::font(14.0), ink);
    resp.clicked()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Split {
    Main,
    Chevron,
}

/// Width of a split button's chevron half.
pub const CHEVRON_W: f32 = 32.0;

/// The two halves of a split button: the label part and the chevron part (a 1px seam apart).
pub fn split_zones(rect: Rect) -> (Rect, Rect) {
    let seam = rect.right() - CHEVRON_W;
    (Rect::from_min_max(rect.min, pos2(seam - 0.5, rect.bottom())), Rect::from_min_max(pos2(seam + 0.5, rect.top()), rect.max))
}

/// A button with a chevron half that opens a menu. `open` keeps the chevron half lit while its flyout is up.
pub fn split_button(ui: &Ui, rect: Rect, id: &str, label: &str, look: Look, open: bool) -> Option<Split> {
    let (main, chev) = split_zones(rect);
    let r_main = hand(ui.interact(main, ui.scope_id().with((id, "main")), Sense::click()));
    let r_chev = hand(ui.interact(chev, ui.scope_id().with((id, "chev")), Sense::click()));
    let p = ui.painter();
    let (left, right) = (CornerRadius { nw: 6, sw: 6, ne: 0, se: 0 }, CornerRadius { nw: 0, sw: 0, ne: 6, se: 6 });
    let (f1, ink) = button_colors(look, &r_main);
    let (mut f2, _) = button_colors(look, &r_chev);
    if open {
        f2 = if look == Look::Primary { theme::accent().gamma_multiply(0.8) } else { theme::card_edge() };
    }
    p.rect_filled(main, left, f1);
    p.rect_filled(chev, right, f2);
    if look == Look::Standard {
        p.rect_stroke(rect, 6, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
    }
    let seam = if look == Look::Primary { theme::on_accent().gamma_multiply(0.35) } else { theme::card_edge() };
    p.vline(rect.right() - CHEVRON_W, rect.y_range().shrink(6.0), Stroke::new(1.0, seam));
    p.text(main.center(), Align2::CENTER_CENTER, label, theme::font(14.0), ink);
    icons::paint(p, Icon::Chevron, Rect::from_center_size(chev.center(), vec2(12.0, 12.0)), ink);
    if r_chev.clicked() {
        Some(Split::Chevron)
    } else if r_main.clicked() {
        Some(Split::Main)
    } else {
        None
    }
}

/// A checkbox with its label to the right; true when toggled. The whole row is the target.
pub fn checkbox(ui: &Ui, at: egui::Pos2, id: &str, label: &str, checked: bool, width: f32) -> bool {
    let row = Rect::from_min_size(at, vec2(width, 22.0));
    let resp = hand(ui.interact(row, ui.scope_id().with(id), Sense::click()));
    let p = ui.painter();
    let b = Rect::from_min_size(pos2(row.left(), row.center().y - 9.0), vec2(18.0, 18.0));
    if checked {
        p.rect_filled(b, 4, theme::accent());
        icons::paint(p, Icon::Check, b.shrink(3.0), theme::on_accent());
    } else {
        p.rect_filled(b, 4, if resp.hovered() { theme::ctl_hover() } else { theme::ctl() });
        p.rect_stroke(b, 4, Stroke::new(1.2, theme::text_dim()), StrokeKind::Inside);
    }
    p.text(pos2(b.right() + 10.0, row.center().y), Align2::LEFT_CENTER, label, theme::font(14.0), theme::text());
    resp.clicked()
}

/// Width of a [`pill`].
pub const PILL_W: f32 = 44.0;

/// A small outlined pill with its left-centre at `at` ("Info"); lit while `open` or hovered. True when clicked.
pub fn pill(ui: &Ui, at: egui::Pos2, id: &str, text: &str, open: bool) -> bool {
    let rect = Rect::from_min_size(pos2(at.x, at.y - 10.0), vec2(PILL_W, 20.0));
    let resp = hand(ui.interact(rect, ui.scope_id().with(id), Sense::click()));
    let lit = resp.hovered() || open;
    let p = ui.painter();
    p.rect_filled(rect, 10, if lit { theme::ctl_hover() } else { theme::ctl() });
    p.rect_stroke(rect, 10, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
    p.text(rect.center(), Align2::CENTER_CENTER, text, theme::font(12.0), if lit { theme::text() } else { theme::text_dim() });
    resp.clicked()
}

/// The close (X) button centred on `c`; true when clicked.
pub fn close_button(ui: &Ui, c: egui::Pos2) -> bool {
    icon_button(ui, c, "close", Icon::Close, "")
}

/// A small square icon button centred on `c`; true when clicked.
pub fn icon_button(ui: &Ui, c: egui::Pos2, id: &str, icon: Icon, tip: &str) -> bool {
    let rect = Rect::from_center_size(c, vec2(28.0, 28.0));
    let mut resp = hand(ui.interact(rect, ui.scope_id().with(id), Sense::click()));
    if !tip.is_empty() {
        resp = resp.on_hover_text(tip);
    }
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(rect, 4, theme::row_hover());
    }
    let size = if icon == Icon::Close { 11.0 } else { 14.0 };
    icons::paint(p, icon, Rect::from_center_size(c, vec2(size, size)), if resp.hovered() { theme::text() } else { theme::text_dim() });
    resp.clicked()
}

/// One line of a flyout menu.
pub struct Row {
    pub label: String,
    pub checked: bool,
    /// A caption that can't be picked.
    pub header: bool,
}

impl Row {
    pub fn item(label: impl Into<String>) -> Self {
        Row { label: label.into(), checked: false, header: false }
    }

    pub fn header(label: impl Into<String>) -> Self {
        Row { label: label.into(), checked: false, header: true }
    }
}

const FLY_W: f32 = 236.0;
const ROW_H: f32 = 32.0;
const FLY_PAD: f32 = 4.0;

pub fn flyout_size(rows: usize) -> egui::Vec2 {
    vec2(FLY_W, rows as f32 * ROW_H + FLY_PAD * 2.0)
}

/// Where a flyout of `size` goes for the button at `anchor`: above it, right edges aligned, or below when there
/// isn't room above, and never outside `work`.
pub fn flyout_pos(anchor: Rect, work: Rect, size: egui::Vec2) -> egui::Pos2 {
    let x = (anchor.right() - size.x).clamp(work.left(), (work.right() - size.x).max(work.left()));
    let above = anchor.top() - 6.0 - size.y;
    let y = if above >= work.top() { above } else { anchor.bottom() + 6.0 };
    pos2(x, y.min(work.bottom() - size.y))
}

/// Shows a flyout menu of `rows` as its own window next to `anchor`. `on_pick` gets the index of the row clicked;
/// it runs on the popup's viewport, so it should only leave a note for the main thread to act on.
pub fn flyout(ctx: &egui::Context, key: u64, anchor: Rect, work: Rect, rows: Vec<Row>, on_pick: impl Fn(usize) + Send + Sync + 'static) -> Rect {
    let size = flyout_size(rows.len());
    let pos = flyout_pos(anchor, work, size);
    let vid = ViewportId::from_hash_of(("flyout", key));
    ctx.show_viewport_deferred(vid, window_builder(FLYOUT_TITLE, size, pos), move |ui, _class| {
        let r = chrome(ui);
        for (i, row) in rows.iter().enumerate() {
            let line = Rect::from_min_size(r.min + vec2(FLY_PAD, FLY_PAD + i as f32 * ROW_H), vec2(FLY_W - FLY_PAD * 2.0, ROW_H));
            let p = ui.painter();
            if row.header {
                p.text(pos2(line.left() + 10.0, line.center().y), Align2::LEFT_CENTER, &row.label, theme::font(12.0), theme::text_dim());
                continue;
            }
            let resp = hand(ui.interact(line, ui.scope_id().with(i), Sense::click()));
            if resp.hovered() {
                p.rect_filled(line, 4, theme::row_hover());
            }
            if row.checked {
                icons::paint(p, Icon::Check, Rect::from_center_size(pos2(line.left() + 16.0, line.center().y), vec2(12.0, 12.0)), theme::text());
            }
            p.text(pos2(line.left() + 34.0, line.center().y), Align2::LEFT_CENTER, &row.label, theme::font(14.0), theme::text());
            if resp.clicked() {
                on_pick(i);
            }
        }
    });
    ctx.request_repaint_of(vid);
    Rect::from_min_size(pos, size)
}

/// Title of flyout windows, which `theme::toast_window` looks them up by.
pub const FLYOUT_TITLE: &str = "RustWarden menu";

#[cfg(test)]
mod tests {
    use super::*;

    fn work() -> Rect {
        // 1920x1080 with a 48px taskbar at the bottom
        Rect::from_min_max(pos2(0.0, 0.0), pos2(1920.0, 1032.0))
    }

    #[test]
    fn stacks_up_from_the_bottom_right() {
        let sizes = [vec2(400.0, 200.0), vec2(400.0, 100.0)];
        let at = stack(work(), Corner::BottomRight, &sizes, 0.0);
        assert_eq!(at[0], pos2(1920.0 - MARGIN - 400.0, 1032.0 - MARGIN - 200.0));
        assert_eq!(at[1].y, at[0].y - GAP - 100.0);
        assert_eq!(at[1].x, at[0].x);
    }

    #[test]
    fn stacks_down_from_the_top_left_and_honours_skip() {
        let sizes = [vec2(300.0, 90.0), vec2(300.0, 90.0)];
        let at = stack(work(), Corner::TopLeft, &sizes, 50.0);
        assert_eq!(at[0], pos2(MARGIN, MARGIN + 50.0));
        assert_eq!(at[1].y, at[0].y + 90.0 + GAP);
    }

    #[test]
    fn work_area_on_another_edge_is_respected() {
        // taskbar on the left: the work area starts at x = 60
        let left_bar = Rect::from_min_max(pos2(60.0, 0.0), pos2(1920.0, 1080.0));
        assert_eq!(stack(left_bar, Corner::BottomLeft, &[vec2(100.0, 100.0)], 0.0)[0].x, 60.0 + MARGIN);
        assert_eq!(stack(left_bar, Corner::BottomRight, &[vec2(100.0, 100.0)], 0.0)[0].y, 1080.0 - MARGIN - 100.0);
    }

    #[test]
    fn slide_settles_and_points_at_the_nearest_edge() {
        assert!(slide_offset(Corner::BottomRight, 0.0) > 0.0);
        assert!(slide_offset(Corner::TopLeft, 0.0) < 0.0);
        assert_eq!(slide_offset(Corner::BottomRight, ANIM_SECS), 0.0);
        assert_eq!(fade(0.0), 0);
        assert_eq!(fade(10.0), 255);
        assert!(animating(0.0) && !animating(ANIM_SECS));
        let mut last = 0.0;
        for i in 0..=10 {
            let e = ease_out(i as f32 / 10.0);
            assert!(e >= last);
            last = e;
        }
        assert_eq!(ease_out(2.0), 1.0);
    }

    #[test]
    fn split_halves_cover_the_button_without_overlap() {
        let r = Rect::from_min_size(pos2(10.0, 10.0), vec2(200.0, 32.0));
        let (main, chev) = split_zones(r);
        assert_eq!(chev.width(), CHEVRON_W - 0.5);
        assert!(main.right() <= chev.left());
        assert_eq!(main.left(), r.left());
        assert_eq!(chev.right(), r.right());
    }

    #[test]
    fn flyout_goes_above_the_button_and_stays_on_screen() {
        let size = flyout_size(4);
        let anchor = Rect::from_min_size(pos2(1700.0, 900.0), vec2(32.0, 32.0));
        let at = flyout_pos(anchor, work(), size);
        assert_eq!(at.y, anchor.top() - 6.0 - size.y);
        assert!(at.x + size.x <= work().right());
        // no room above: it opens below
        let top = Rect::from_min_size(pos2(100.0, 10.0), vec2(32.0, 32.0));
        let at = flyout_pos(top, work(), size);
        assert_eq!(at.y, top.bottom() + 6.0);
        assert!(at.x >= work().left());
    }
}
