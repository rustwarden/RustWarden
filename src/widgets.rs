//! Reusable controls styled like the reference UI.

use crate::icons::{self, Icon};
use crate::theme;
use crate::util::fit_text;
use egui::epaint::StrokeKind;
use egui::{Align2, Color32, Id, Mesh, Painter, Pos2, Rect, Response, Sense, Shape, Stroke, Ui, pos2, vec2};

const PILL_H: f32 = 32.0;

pub fn shadowed_pill(p: &Painter, rect: Rect, fill: Color32) {
    let r = 4;
    p.rect_filled(rect, r, fill);
    p.rect_stroke(rect, r, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
}

/// White rounded button: optional icon, label, optional chevron.
pub fn pill_button(ui: &mut Ui, icon: Option<Icon>, label: &str, chevron: bool, min_width: f32) -> Response {
    let font = theme::font(14.0);
    let galley = ui.painter().layout_no_wrap(label.to_owned(), font, theme::text());
    let icon_w = if icon.is_none() {
        0.0
    } else if label.is_empty() {
        18.0
    } else {
        26.0
    }; // icon-only pills centre the icon
    let chev_w = if chevron { 24.0 } else { 0.0 };
    let w = (16.0 + icon_w + galley.size().x + chev_w + 16.0).max(min_width);
    let (rect, resp) = ui.allocate_exact_size(vec2(w, PILL_H), Sense::click());
    let p = ui.painter();
    shadowed_pill(p, rect, if resp.hovered() { theme::ctl_hover() } else { theme::ctl() });
    let content_w = icon_w + galley.size().x;
    let mut x = if chevron { rect.left() + 18.0 } else { rect.center().x - content_w / 2.0 };
    if let Some(icon) = icon {
        icons::paint(p, icon, Rect::from_center_size(pos2(x + 9.0, rect.center().y), vec2(18.0, 18.0)), theme::text());
        x += icon_w;
    }
    p.galley(pos2(x, rect.center().y - galley.size().y / 2.0), galley, theme::text());
    if chevron {
        let c = pos2(rect.right() - 22.0, rect.center().y);
        icons::paint(p, Icon::Chevron, Rect::from_center_size(c, vec2(14.0, 14.0)), theme::text());
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Menu row with a check mark in the left gutter when `checked`.
pub fn check_item(ui: &mut Ui, checked: bool, label: &str) -> Response {
    check_item_icon(ui, checked, label, None)
}

/// `check_item` with an app's icon (and its executable path, for the real icon) between the tick and the name.
pub fn check_item_icon(ui: &mut Ui, checked: bool, label: &str, app: Option<(crate::data::AppIcon, &str)>) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(rect, 4, theme::nav_on());
    }
    if checked {
        icons::paint(p, Icon::Check, Rect::from_center_size(pos2(rect.left() + 22.0, rect.center().y), vec2(18.0, 18.0)), theme::text_dim());
    }
    let font = theme::font(15.0);
    match app {
        Some((icon, path)) => {
            icons::app_icon_for(p, icon, path, Rect::from_center_size(pos2(rect.left() + 58.0, rect.center().y), vec2(20.0, 20.0)));
            let text = fit_text(p, label, &font, rect.width() - 90.0);
            p.text(pos2(rect.left() + 76.0, rect.center().y), Align2::LEFT_CENTER, text, font, theme::text());
        }
        None => fit_label(p, rect, label, font),
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn fit_label(p: &Painter, rect: Rect, label: &str, font: egui::FontId) {
    let text = fit_text(p, label, &font, rect.width() - 56.0);
    p.text(pos2(rect.left() + 48.0, rect.center().y), Align2::LEFT_CENTER, text, font, theme::text());
}

/// Dropdown rendered as a pill; returns true when the value changed.
pub fn dropdown<T: Copy + PartialEq>(ui: &mut Ui, icon: Option<Icon>, current: &mut T, options: &[T], label: impl Fn(T) -> String, min_width: f32) -> bool {
    let resp = pill_button(ui, icon, &label(*current), true, min_width);
    let mut changed = false;
    egui::Popup::menu(&resp).width(resp.rect.width().max(220.0)).show(|ui| {
        for &opt in options {
            if check_item(ui, opt == *current, &label(opt)).clicked() {
                changed = opt != *current;
                *current = opt;
                ui.close();
            }
        }
    });
    changed
}

/// Segmented switch with text labels (Privacy tabs): same bar as [`segmented`], sized to its labels.
pub fn segmented_text(ui: &mut Ui, selected: &mut usize, labels: &[&str]) -> bool {
    let widths: Vec<f32> = labels.iter().map(|l| ui.painter().layout_no_wrap((*l).to_owned(), theme::font(14.0), theme::text()).size().x + 32.0).collect();
    let (rect, _) = ui.allocate_exact_size(vec2(widths.iter().sum(), PILL_H), Sense::hover());
    shadowed_pill(ui.painter(), rect, theme::ctl());
    let mut changed = false;
    let mut x = rect.left();
    for (i, (label, w)) in labels.iter().zip(widths).enumerate() {
        let seg = Rect::from_min_size(pos2(x, rect.top()), vec2(w, PILL_H));
        x += w;
        let resp = ui.interact(seg, ui.scope_id().with(("segtext", labels, i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
        if resp.clicked() && *selected != i {
            *selected = i;
            changed = true;
        }
        let active = *selected == i;
        if active {
            ui.painter().rect_filled(seg.shrink(3.0), 3, theme::accent());
        } else if resp.hovered() {
            ui.painter().rect_filled(seg.shrink(3.0), 3, theme::nav_on());
        }
        ui.painter().text(seg.center(), Align2::CENTER_CENTER, label, theme::font(14.0), if active { theme::on_accent() } else { theme::text() });
    }
    changed
}

/// Windows 11 toggle: an outlined track with a small knob when off, accent-filled with a larger knob when on.
pub fn small_toggle(ui: &mut Ui, on: &mut bool) -> Response {
    let (rect, mut resp) = ui.allocate_exact_size(vec2(40.0, 20.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool(resp.id, *on);
    let p = ui.painter();
    let accent = theme::accent();
    p.rect_filled(rect, 10, Color32::TRANSPARENT.lerp_to_gamma(accent, t));
    p.rect_stroke(rect, 10, Stroke::new(1.0, theme::text_dim().lerp_to_gamma(accent, t)), StrokeKind::Inside);
    let knob = theme::text_dim().lerp_to_gamma(theme::pick(theme::WHITE, Color32::from_rgb(0x10, 0x15, 0x1f)), t);
    let x = egui::lerp(rect.left() + 10.0..=rect.right() - 10.0, t);
    let hot = if resp.hovered() { 1.0 } else { 0.0 };
    p.circle_filled(pos2(x, rect.center().y), egui::lerp(5.0..=6.0, t) + hot * 0.5, knob);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Settings switch: a `small_toggle` followed by a clickable, wrapping label. Replaces `ui.checkbox`.
pub fn switch(ui: &mut Ui, on: &mut bool, label: impl Into<egui::WidgetText>) -> Response {
    let label = label.into();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        let mut r = small_toggle(ui, on);
        if label.is_empty() {
            return r;
        }
        let l = ui.add(egui::Label::new(label).wrap().sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand);
        if l.clicked() {
            *on = !*on;
            r.mark_changed();
        }
        r | l
    })
    .inner
}

/// Round radio button with an accent dot, and a clickable label. Replaces `ui.radio_value`.
pub fn radio<T: PartialEq>(ui: &mut Ui, current: &mut T, value: T, label: impl Into<egui::WidgetText>) -> Response {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        let (rect, dot) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::click());
        let l = ui.add(egui::Label::new(label).wrap().sense(Sense::click()));
        let id = dot.id;
        let mut r = (dot | l).on_hover_cursor(egui::CursorIcon::PointingHand);
        let selected = *current == value;
        if r.clicked() && !selected {
            *current = value;
            r.mark_changed();
        }
        let t = ui.ctx().animate_bool(id, selected || r.changed());
        let p = ui.painter();
        let c = rect.center();
        let ring = if r.hovered() { theme::accent() } else { theme::border().lerp_to_gamma(theme::text_dim(), 0.5) };
        p.circle(c, 8.0, theme::surface_solid(), Stroke::new(1.5, ring.lerp_to_gamma(theme::accent(), t)));
        if t > 0.0 {
            p.circle_filled(c, 4.5 * t, theme::accent());
        }
        r
    })
    .inner
}

/// Windows 11-style slider: thin track filled with the accent up to a small white knob with an
/// accent centre, then the current value (`text`) to the right. Arrow keys step it when focused.
pub fn slider(ui: &mut Ui, value: &mut f32, range: std::ops::RangeInclusive<f32>, step: f32, text: impl Fn(f32) -> String) -> Response {
    let (lo, hi) = (*range.start(), *range.end());
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        let (rect, mut r) = ui.allocate_exact_size(vec2(240.0, 22.0), Sense::click_and_drag());
        let (x0, x1) = (rect.left() + 9.0, rect.right() - 9.0);
        let snap = |v: f32| (lo + ((v - lo) / step).round() * step).clamp(lo, hi);
        let mut v = *value;
        if let Some(p) = r.interact_pointer_pos() {
            v = snap(lo + ((p.x - x0) / (x1 - x0)).clamp(0.0, 1.0) * (hi - lo));
        }
        if r.has_focus() {
            let (left, right) = ui.input(|i| (i.key_pressed(egui::Key::ArrowLeft), i.key_pressed(egui::Key::ArrowRight)));
            v = snap(v + step * (right as i32 - left as i32) as f32);
        }
        if v != *value {
            *value = v;
            r.mark_changed();
        }
        let t = ((*value - lo) / (hi - lo)).clamp(0.0, 1.0);
        let c = pos2(egui::lerp(x0..=x1, t), rect.center().y);
        let p = ui.painter();
        let track = |a: f32, b: f32| Rect::from_min_max(pos2(a, c.y - 2.0), pos2(b, c.y + 2.0));
        p.rect_filled(track(x0, x1), 2, theme::track());
        p.rect_filled(track(x0, c.x), 2, theme::accent());
        p.circle_filled(c + vec2(0.0, 1.0), 9.0, Color32::from_black_alpha(30));
        p.circle(c, 9.0, theme::surface_solid(), Stroke::new(1.0, theme::border()));
        let hot = r.hovered() || r.dragged() || r.has_focus();
        p.circle_filled(c, if hot { 5.0 } else { 4.0 }, theme::accent());
        ui.label(egui::RichText::new(text(*value)).strong());
        r.on_hover_cursor(egui::CursorIcon::PointingHand)
    })
    .inner
}

/// Typed number box with a dim unit after it. Only values inside `range` are stored; anything else
/// outlines the box red and names the limits, and leaving the box puts the last good value back.
pub fn num_field<T: egui::emath::Numeric>(ui: &mut Ui, value: &mut T, range: std::ops::RangeInclusive<T>, unit: &str) -> Response {
    let (lo, hi) = (range.start().to_f64(), range.end().to_f64());
    ui.horizontal(|ui| {
        let id = ui.auto_id_with("num_field");
        let mut text = ui.data(|d| d.get_temp::<String>(id)).unwrap_or_else(|| fmt_num(value.to_f64(), T::INTEGRAL));
        let bad = parse_num(&text, lo, hi, T::INTEGRAL).is_none();
        if bad {
            let red = Stroke::new(1.5, theme::red());
            let v = ui.visuals_mut();
            (v.widgets.inactive.bg_stroke, v.widgets.hovered.bg_stroke, v.selection.stroke) = (red, red, red);
        }
        let r = ui.add(egui::TextEdit::singleline(&mut text).id(id.with("edit")).desired_width(84.0).align(Align2::RIGHT_CENTER));
        if r.changed()
            && let Some(v) = parse_num(&text, lo, hi, T::INTEGRAL)
        {
            *value = T::from_f64(v);
        }
        if r.has_focus() {
            ui.data_mut(|d| d.insert_temp(id, text));
        } else {
            ui.data_mut(|d| d.remove_temp::<String>(id));
        }
        let limits = format!("{} – {}", fmt_num(lo, T::INTEGRAL), fmt_num(hi, T::INTEGRAL));
        ui.label(egui::RichText::new(unit.trim()).color(theme::text_dim()));
        if bad {
            ui.label(egui::RichText::new(format!("Enter {}{limits}", if T::INTEGRAL { "a whole number " } else { "" })).color(theme::red()));
        }
        r.on_hover_text(format!("Allowed: {limits}"))
    })
    .inner
}

fn fmt_num(v: f64, integral: bool) -> String {
    if integral { format!("{v:.0}") } else { format!("{}", (v * 100.0).round() / 100.0) }
}

/// The value of `text` when it is a number inside `lo..=hi` (and whole, when `integral`).
fn parse_num(text: &str, lo: f64, hi: f64, integral: bool) -> Option<f64> {
    text.trim().parse::<f64>().ok().filter(|v| (lo..=hi).contains(v) && (!integral || v.fract() == 0.0))
}

#[test]
fn parse_num_limits() {
    assert_eq!(parse_num(" 30 ", 1.0, 1440.0, true), Some(30.0));
    assert_eq!(parse_num("0", 1.0, 1440.0, true), None);
    assert_eq!(parse_num("1441", 1.0, 1440.0, true), None);
    assert_eq!(parse_num("2.5", 1.0, 1440.0, true), None);
    assert_eq!(parse_num("2.5", 0.1, 100.0, false), Some(2.5));
    assert_eq!(parse_num("abc", 0.0, 1.0, false), None);
    assert_eq!(parse_num("NaN", 0.0, 1.0, false), None);
    assert_eq!(fmt_num(0.1f32 as f64, false), "0.1");
}

/// Rounded grey search field.
pub fn search_box(ui: &mut Ui, text: &mut String, width: f32) -> Response {
    let (rect, _) = ui.allocate_exact_size(vec2(width, PILL_H), Sense::hover());
    ui.painter().rect_filled(rect, 4, theme::ctl());
    ui.painter().rect_stroke(rect, 4, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
    let icon_rect = Rect::from_center_size(pos2(rect.left() + 22.0, rect.center().y), vec2(17.0, 17.0));
    icons::paint(ui.painter(), Icon::Search, icon_rect, theme::text_dim());
    // Room on the right for the clear button while there is something to clear.
    let clear = (!text.is_empty()).then(|| Rect::from_center_size(pos2(rect.right() - 20.0, rect.center().y), vec2(20.0, 20.0)));
    let right = clear.map_or(rect.right() - 14.0, |c| c.left() - 2.0);
    let edit_rect = Rect::from_min_max(pos2(rect.left() + 40.0, rect.top() + 7.0), pos2(right, rect.bottom() - 7.0));
    // new_child, not `put`: `put` would allocate edit_rect in the parent again and pull the
    // next widget's cursor back inside this box, overlapping the neighbouring button.
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(edit_rect));
    let resp = child.add(egui::TextEdit::singleline(text).frame(egui::Frame::NONE).hint_text("Search").font(theme::font(15.0)).align(egui::Align2::LEFT_CENTER));
    edit_menu(ui, &resp, text, false);
    if let Some(c) = clear {
        let x = ui.interact(c, resp.id.with("clear"), Sense::click());
        let color = if x.hovered() { theme::text() } else { theme::text_dim() };
        icons::paint(ui.painter(), Icon::Close, c.shrink(4.0), color);
        if x.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            text.clear();
            resp.request_focus();
        }
    }
    resp
}

/// Standard right-click menu for a text field: Cut, Copy, Paste, Select all. `secret` fields (passwords) can't be cut or copied.
pub fn edit_menu(_ui: &mut Ui, resp: &Response, text: &mut String, secret: bool) {
    let (ctx, id) = (resp.ctx.clone(), resp.id);
    resp.context_menu(|ui| {
        let mut state = egui::TextEdit::load_state(&ctx, id).unwrap_or_default();
        let (lo, hi) = state.cursor.char_range().map_or((0, 0), |r| (r.primary.index.0.min(r.secondary.index.0), r.primary.index.0.max(r.secondary.index.0)));
        let selected = hi > lo;
        let bytes = |n: usize| text.char_indices().nth(n).map_or(text.len(), |(b, _)| b);
        let (b_lo, b_hi) = (bytes(lo), bytes(hi));
        let mut caret = None;
        if ui.add_enabled(selected && !secret, egui::Button::new("Cut")).clicked() {
            ctx.copy_text(text[b_lo..b_hi].to_owned());
            text.replace_range(b_lo..b_hi, "");
            caret = Some(lo);
        }
        if ui.add_enabled(selected && !secret, egui::Button::new("Copy")).clicked() {
            ctx.copy_text(text[b_lo..b_hi].to_owned());
        }
        if ui.button("Paste").clicked()
            && let Some(clip) = arboard::Clipboard::new().and_then(|mut c| c.get_text()).ok()
        {
            let clip: String = clip.chars().filter(|c| !c.is_control()).collect();
            text.replace_range(b_lo..b_hi, &clip);
            caret = Some(lo + clip.chars().count());
        }
        if ui.button("Select all").clicked() {
            state.cursor.set_char_range(Some(egui::text::CCursorRange::two(egui::text::CCursor::new(0usize), egui::text::CCursor::new(text.chars().count()))));
        }
        if let Some(c) = caret {
            state.cursor.set_char_range(Some(egui::text::CCursorRange::one(egui::text::CCursor::new(c))));
        }
        egui::TextEdit::store_state(&ctx, id, state);
    });
}

/// Square-ish icon-only button (info, sliders, export).
pub fn icon_button(ui: &mut Ui, icon: Icon, size: f32, tooltip: &str) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(size, size), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 6, theme::panel_bg());
    }
    icons::paint(ui.painter(), icon, rect.shrink(size * 0.22), theme::text());
    resp.on_hover_text(tooltip).on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Thin usage bar: yellow for download, pink tail for upload.
pub fn usage_bar(p: &Painter, rect: Rect, fraction: f32, up_share: f32) {
    let w = (rect.width() * fraction.clamp(0.0, 1.0)).max(3.0);
    let full = Rect::from_min_size(rect.min, vec2(w, rect.height()));
    let split = full.left() + w * (1.0 - up_share.clamp(0.0, 1.0));
    p.rect_filled(Rect::from_min_max(full.min, pos2(split, full.bottom())), 1, theme::down());
    p.rect_filled(Rect::from_min_max(pos2(split, full.top()), full.max), 1, theme::up());
}

/// Text that is clipped with an ellipsis to `max_width`, left-anchored at `pos`.
pub fn text_fit(p: &Painter, pos: Pos2, anchor: Align2, text: &str, font: egui::FontId, color: Color32, max_width: f32) -> Rect {
    let fitted = fit_text(p, text, &font, max_width);
    p.text(pos, anchor, fitted, font, color)
}

/// Left-anchored text that stops at `max_width`, its last `fade` pixels fading out instead of ending in an ellipsis.
/// Returns the width drawn. Text that fits is drawn whole.
pub fn text_faded(p: &Painter, pos: Pos2, text: &str, font: egui::FontId, color: Color32, max_width: f32, fade: f32) -> f32 {
    let width = |s: &str| p.layout_no_wrap(s.to_owned(), font.clone(), Color32::WHITE).size().x;
    let full = width(text);
    if full <= max_width {
        p.text(pos, Align2::LEFT_CENTER, text, font, color);
        return full;
    }
    let mut prefix = String::new();
    for c in text.chars() {
        let x = width(&prefix);
        if x >= max_width {
            break;
        }
        let alpha = ((max_width - x) / fade).clamp(0.0, 1.0);
        p.text(pos2(pos.x + x, pos.y), Align2::LEFT_CENTER, c, font.clone(), color.gamma_multiply(alpha));
        prefix.push(c);
    }
    max_width
}

/// Text wrapped onto up to `max_lines` lines of `line_h`, the first line centred vertically on `pos.y`
/// and left-anchored at `pos.x`. Breaks at a space or punctuation when one is near, else mid-word (hosts,
/// paths); the last line is ellipsised if the text still doesn't fit. Returns the lines drawn.
#[allow(clippy::too_many_arguments)]
pub fn text_wrap(p: &Painter, pos: Pos2, text: &str, font: egui::FontId, color: Color32, max_width: f32, line_h: f32, max_lines: usize) -> usize {
    let width = |s: &str| p.layout_no_wrap(s.to_owned(), font.clone(), Color32::WHITE).size().x;
    let mut rest: Vec<char> = text.chars().collect();
    let mut lines = 0;
    while !rest.is_empty() && lines < max_lines {
        let y = pos.y + line_h * lines as f32;
        lines += 1;
        let s: String = rest.iter().collect();
        if lines == max_lines || width(&s) <= max_width {
            p.text(pos2(pos.x, y), Align2::LEFT_CENTER, fit_text(p, &s, &font, max_width), font.clone(), color);
            break;
        }
        let mut n = (1..=rest.len()).take_while(|&n| width(&rest[..n].iter().collect::<String>()) <= max_width).count().max(1);
        if let Some(b) = rest[..n].iter().rposition(|c| matches!(c, ' ' | '/' | '\\' | '-' | '.' | ',' | '_'))
            && b * 2 > n
        {
            n = b + 1;
        }
        let line: String = rest[..n].iter().collect();
        p.text(pos2(pos.x, y), Align2::LEFT_CENTER, line.trim_end(), font.clone(), color);
        rest.drain(..n);
        while rest.first() == Some(&' ') {
            rest.remove(0);
        }
    }
    lines
}

/// Filled area under `values` (0..=1 normalised) inside `rect`, smoothed between samples.
pub fn area(p: &Painter, rect: Rect, values: &[f32], fill: Color32, line: Option<Stroke>) {
    area_faded(p, rect, values, fill, line, None);
}

/// [`area`] that fades to transparent over `fade` = (x where the fade starts, its width), in one mesh.
pub fn area_faded(p: &Painter, rect: Rect, values: &[f32], fill: Color32, line: Option<Stroke>, fade: Option<(f32, f32)>) {
    area_faded_to(p, rect, values, fill, line, fade, 1.0);
}

/// [`area_faded`] drawn only up to `end` (0..=1 of `rect`'s width), so the curve can stop part-way through a segment and its end move
/// continuously instead of jumping a whole column when a sample arrives.
pub fn area_faded_to(p: &Painter, rect: Rect, values: &[f32], fill: Color32, line: Option<Stroke>, fade: Option<(f32, f32)>, end: f32) {
    area_impl(p, rect, values, fill, line, fade, end, Look::Solid);
}

/// How [`area_impl`] fills: opaque up from the bottom, or a line with a see-through gradient under it, optionally hanging from the top edge.
#[derive(Clone, Copy, PartialEq)]
enum Look {
    Solid,
    Soft { hang: bool },
}

/// The traffic graph's series: a crest line over a gradient that thins toward the baseline. `hang` mirrors it below its top edge.
pub fn area_soft_to(p: &Painter, rect: Rect, values: &[f32], color: Color32, hang: bool, fade: Option<(f32, f32)>, end: f32) {
    area_impl(p, rect, values, color, None, fade, end, Look::Soft { hang });
}

#[allow(clippy::too_many_arguments)]
fn area_impl(p: &Painter, rect: Rect, values: &[f32], fill: Color32, line: Option<Stroke>, fade: Option<(f32, f32)>, end: f32, look: Look) {
    if values.len() < 2 || rect.width() <= 1.0 {
        return;
    }
    let n = values.len() - 1;
    let steps = ((rect.width() * end / 2.0).ceil() as usize).max(1);
    // Light [1,2,1] low-pass against sample jitter, then a monotone cubic (Fritsch-Carlson) so curves never overshoot.
    let v: Vec<f32> = (0..=n).map(|i| if i == 0 || i == n { values[i] } else { (values[i - 1] + 2.0 * values[i] + values[i + 1]) / 4.0 }).collect();
    let d: Vec<f32> = v.windows(2).map(|w| w[1] - w[0]).collect();
    let m: Vec<f32> = (0..=n)
        .map(|i| {
            if i == 0 {
                d[0]
            } else if i == n {
                d[n - 1]
            } else if d[i - 1] * d[i] <= 0.0 {
                0.0
            } else {
                (d[i - 1] + d[i]) / 2.0
            }
        })
        .collect();
    let sample = |x: f32| {
        let f = (x * n as f32).clamp(0.0, n as f32);
        let i = (f.floor() as usize).min(n - 1);
        let t = f - i as f32;
        let (t2, t3) = (t * t, t * t * t);
        (2.0 * t3 - 3.0 * t2 + 1.0) * v[i] + (t3 - 2.0 * t2 + t) * m[i] + (-2.0 * t3 + 3.0 * t2) * v[i + 1] + (t3 - t2) * m[i + 1]
    };
    let hang = look == Look::Soft { hang: true };
    let (base_y, dir) = if hang { (rect.top(), 1.0) } else { (rect.bottom(), -1.0) };
    let pts: Vec<Pos2> = (0..=steps)
        .map(|k| {
            let x = k as f32 / steps as f32 * end;
            pos2(rect.left() + x * rect.width(), base_y + dir * sample(x).clamp(0.0, 1.0) * rect.height())
        })
        .collect();
    let color_at = move |x: f32| fade.map_or(fill, |(x0, w)| fill.gamma_multiply((1.0 - (x - x0) / w).clamp(0.0, 1.0)));
    // Soft fills run from a translucent crest to almost nothing at the baseline.
    let (crest, foot) = if matches!(look, Look::Soft { .. }) { (0.45, 0.04) } else { (1.0, 1.0) };
    let mut mesh = Mesh::default();
    for w in pts.windows(2) {
        let base = mesh.vertices.len() as u32;
        let (c0, c1) = (color_at(w[0].x), color_at(w[1].x));
        mesh.colored_vertex(w[0], c0.gamma_multiply(crest));
        mesh.colored_vertex(w[1], c1.gamma_multiply(crest));
        mesh.colored_vertex(pos2(w[1].x, base_y), c1.gamma_multiply(foot));
        mesh.colored_vertex(pos2(w[0].x, base_y), c0.gamma_multiply(foot));
        mesh.add_triangle(base, base + 1, base + 2);
        mesh.add_triangle(base, base + 2, base + 3);
    }
    p.add(Shape::mesh(mesh));
    // The mesh edge isn't anti-aliased; an egui line (which is) in the fill color softens the crest.
    let stroke = line.unwrap_or(Stroke::new(1.5, fill));
    if fade.is_some() {
        p.add(Shape::line(pts, egui::epaint::PathStroke::new_uv(stroke.width, move |_, pos| color_at(pos.x))));
    } else {
        p.add(Shape::line(pts, stroke));
    }
}

/// Red "9+" style badge.
pub fn count_badge(p: &Painter, center: Pos2, count: usize) {
    let text = if count > 9 { "9+".to_owned() } else { count.to_string() };
    p.circle_filled(center, 9.0, theme::red());
    p.circle_stroke(center, 9.0, Stroke::new(1.5, theme::WHITE));
    p.text(center, Align2::CENTER_CENTER, text, theme::bold(10.0), theme::WHITE);
}

/// A dialog in its own native window: it opens centred on the window that opened it, can be dragged
/// anywhere, and that window is disabled until it closes. Esc or the title bar's X closes it.
pub struct Dialog<'a> {
    title: &'a str,
    decorated: bool,
    flush: bool,
    backdrop: bool,
}

pub fn dialog(title: &str) -> Dialog<'_> {
    Dialog { title, decorated: true, flush: false, backdrop: true }
}

#[derive(Clone, Copy, Default)]
struct DialogState {
    shown_frame: u64,
    pos: Option<Pos2>,
    size: Option<egui::Vec2>,
    hwnd: isize,
    /// The size has held for a frame; until then the window stays hidden while it settles.
    shown: bool,
    /// Resizes in a row without a frame where the size held.
    steps: u8,
}

impl Dialog<'_> {
    /// The window itself is Mica or acrylic (like the main window) instead of a solid sheet, so the content draws its own cards.
    pub fn backdrop(mut self) -> Self {
        self.backdrop = true;
        self
    }

    /// No padding around the content, so it can touch the window edges.
    pub fn flush(mut self) -> Self {
        self.flush = true;
        self
    }

    /// Draws the dialog this frame; false once the user closed it (X or Esc).
    pub fn show(self, ctx: &egui::Context, add: impl FnOnce(&mut Ui)) -> bool {
        let id = egui::ViewportId::from_hash_of(("dialog", self.title));
        let frame = ctx.cumulative_frame_nr();
        let mut st: DialogState = ctx.data(|d| d.get_temp(id.0)).unwrap_or_default();
        if st.shown_frame + 1 < frame {
            st = DialogState::default(); // closed since last shown: open fresh
        }
        st.shown_frame = frame;
        let parent = ctx.input(|i| i.viewport().outer_rect).unwrap_or(ctx.content_rect());
        // A dialog opened from another dialog (a plugin's settings) is solid: its see-through backdrop over a see-through owner went clear.
        let backdrop = self.backdrop && ctx.viewport_id() == egui::ViewportId::ROOT;
        let size = st.size.unwrap_or(vec2(420.0, 160.0));
        let pos = *st.pos.get_or_insert(parent.center() - size / 2.0);
        let builder = egui::ViewportBuilder::default()
            .with_title(self.title)
            .with_visible(st.shown)
            .with_inner_size(size)
            .with_position(pos)
            .with_decorations(self.decorated)
            .with_resizable(false)
            .with_minimize_button(false)
            .with_maximize_button(false)
            .with_transparent(backdrop)
            .with_taskbar(false);
        let builder = if self.backdrop {
            static ICON: std::sync::OnceLock<std::sync::Arc<egui::IconData>> = std::sync::OnceLock::new();
            builder.with_icon(ICON.get_or_init(|| std::sync::Arc::new(egui::IconData { rgba: crate::util::app_icon_rgba().0, width: 256, height: 256 })).clone())
        } else {
            builder
        };
        let (mut add, mut measured, mut open) = (Some(add), None, true);
        let no_margin = self.flush || !self.decorated;
        ctx.show_viewport_immediate(id, builder, |ui, _| {
            // Esc first closes an open dropdown, then the dialog.
            let esc = !egui::Popup::is_any_open(ui.ctx()) && ui.input(|i| i.key_pressed(egui::Key::Escape));
            open = !(esc || ui.input(|i| i.viewport().close_requested()));
            // A backdrop window gets the main window's own sheet, so it is as opaque as the main window (the Acrylic setting).
            ui.painter().rect_filled(ui.max_rect(), 0.0, if backdrop { theme::surface() } else { theme::surface_solid() });
            dialog_style(ui);
            let margin = if no_margin { egui::Margin::ZERO } else { egui::Margin::same(14) };
            let r = egui::Frame::NONE.inner_margin(margin).show(ui, |ui| add.take().map(|add| add(ui)));
            measured = Some(r.response.rect.size());
        });
        if let Some(m) = measured {
            // Content whose size depends on the window's (wrapping text, a grid still learning its column
            // widths, DPI rounding) can push back on every resize; after a run of them the window only grows,
            // which has to stop.
            // Capped at the screen: unbounded growth resized the GL surface every frame, which can hang an iGPU driver.
            let screen = ctx.input(|i| i.viewport().monitor_size).unwrap_or(vec2(4096.0, 4096.0)) * 0.9;
            let target = if st.steps >= 8 { m.max(st.size.unwrap_or(m)) } else { m }.min(screen);
            if st.size.is_none_or(|s| (s - target).length() > 0.5) {
                st.pos = Some(parent.center() - target / 2.0); // keep it centred as its content settles or changes
                st.size = Some(target);
                st.steps = st.steps.saturating_add(1);
                ctx.request_repaint();
            } else {
                (st.shown, st.steps) = (true, 0);
            }
        }
        // Win32 side: the dialog is owned by, and disables, the window it was opened from.
        let owner = if ctx.viewport_id() == egui::ViewportId::ROOT { crate::sys::modal::main() } else { ctx.data(|d| d.get_temp::<DialogState>(ctx.viewport_id().0)).map_or(0, |p| p.hwnd) };
        if st.hwnd == 0
            && owner != 0
            && let Some(h) = crate::sys::modal::find(self.title)
        {
            st.hwnd = h;
            crate::sys::modal::adopt(h, owner, theme::is_dark());
            crate::sys::modal::use_exe_icons(h); // the tuned small icons, not one 256 px picture scaled down
            if backdrop {
                theme::acrylic(h, theme::is_dark(), theme::mica());
            }
        }
        if owner != 0 && open {
            crate::sys::modal::hold(owner);
        }
        ctx.data_mut(|d| d.insert_temp(id.0, st));
        open
    }
}

/// Dialog-only look (the main window keeps its own): taller controls, filled rounded text fields
/// with a stronger ring when focused.
fn dialog_style(ui: &mut Ui) {
    let s = ui.style_mut();
    s.spacing.interact_size.y = 30.0;
    s.spacing.item_spacing.y = 8.0;
    s.visuals.text_edit_bg_color = Some(theme::ctl());
    s.visuals.selection.stroke.width = 1.5; // colour stays: it is also the text on selected items
    s.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, theme::border());
    s.visuals.widgets.noninteractive.corner_radius = 4.into();
}

/// Toast for placeholder actions.
pub fn toast(ctx: &egui::Context, message: &str) {
    egui::Area::new(Id::unique("toast")).anchor(Align2::CENTER_BOTTOM, vec2(0.0, -48.0)).order(egui::Order::Tooltip).show(ctx, |ui| {
        egui::Frame::new().fill(Color32::from_rgb(0x2b, 0x30, 0x3a)).corner_radius(8).inner_margin(egui::Margin::symmetric(16, 10)).show(ui, |ui| {
            ui.label(egui::RichText::new(message).color(theme::WHITE).font(theme::font(14.0)));
        });
    });
}

/// Small "i" button that asks for whois details of an address; `true` when clicked.
pub fn whois_icon(ui: &mut Ui, center: Pos2, id: impl std::hash::Hash + std::fmt::Debug) -> bool {
    let r = Rect::from_center_size(center, vec2(18.0, 18.0));
    let resp = ui.interact(r, ui.scope_id().with(("whois", id)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Whois");
    icons::paint(ui.painter(), Icon::Info, r, if resp.hovered() { theme::text() } else { theme::text_dim() });
    resp.clicked()
}

/// Chevron for `ComboBox::icon`, matching the pill dropdowns.
pub fn combo_icon(ui: &Ui, rect: Rect, _: &egui::style::WidgetVisuals, _open: bool) {
    icons::paint(ui.painter(), Icon::Chevron, Rect::from_center_size(rect.center(), vec2(14.0, 14.0)), theme::text_dim());
}

pub const MENU_ROW_H: f32 = 40.0;
pub const MENU_SEP_H: f32 = 13.0;

/// Row of the styled menus (File menu, tray menu): icon in the left gutter, label, then an optional dim
/// value and a right chevron.
pub fn menu_row(ui: &mut Ui, icon: Option<Icon>, label: &str, value: &str, chevron: bool, enabled: bool) -> Response {
    menu_row_tinted(ui, icon, label, value, chevron, enabled, None)
}

/// A `menu_row` with an orange wash on hover and orange icons: the RustWarden brand menu.
pub fn brand_menu_row(ui: &mut Ui, icon: Icon, label: &str) -> Response {
    menu_row_tinted(ui, Some(icon), label, "", false, true, Some(theme::brand_orange()))
}

fn menu_row_tinted(ui: &mut Ui, icon: Option<Icon>, label: &str, value: &str, chevron: bool, enabled: bool, brand: Option<Color32>) -> Response {
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), MENU_ROW_H), sense);
    let p = ui.painter();
    let ink = if enabled { theme::text() } else { theme::text_dim() };
    if enabled && resp.hovered() {
        p.rect_filled(rect, 4, if brand.is_some() { theme::brand_wash() } else { theme::nav_on() });
    }
    if let Some(icon) = icon {
        icons::paint(p, icon, Rect::from_center_size(pos2(rect.left() + 26.0, rect.center().y), vec2(20.0, 20.0)), brand.unwrap_or(ink));
    }
    p.text(pos2(rect.left() + 54.0, rect.center().y), Align2::LEFT_CENTER, label, theme::font(15.0), ink);
    let mut right = rect.right() - 14.0;
    if chevron {
        icons::paint(p, Icon::ChevronRight, Rect::from_center_size(pos2(right - 6.0, rect.center().y), vec2(14.0, 14.0)), theme::text_dim());
        right -= 24.0;
    }
    if !value.is_empty() {
        p.text(pos2(right, rect.center().y), Align2::RIGHT_CENTER, value, theme::font(14.0), theme::text_dim());
    }
    if enabled { resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp }
}

/// Hairline between groups of `menu_row`s.
pub fn menu_sep(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), MENU_SEP_H), Sense::hover());
    ui.painter().hline(rect.x_range().shrink(10.0), rect.center().y, Stroke::new(1.0, theme::border()));
}

/// Progress bar of a data quota with its figures, coloured by how far it is used.
pub fn quota_bar(ui: &mut Ui, st: &crate::data::QuotaStatus, width: f32) {
    use crate::data::QuotaLevel;
    let color = match st.level {
        QuotaLevel::Ok => theme::accent(),
        QuotaLevel::Warn => theme::orange(),
        QuotaLevel::Over => theme::red(),
    };
    let (rect, _) = ui.allocate_exact_size(vec2(width, 8.0), Sense::hover());
    ui.painter().rect_filled(rect, 4, theme::field());
    let fill = Rect::from_min_size(rect.min, vec2(rect.width() * st.fraction(), rect.height()));
    ui.painter().rect_filled(fill, 4, color);
    let pct = if st.limit > 0.0 { (st.used / st.limit * 100.0).round() } else { 0.0 };
    let mut text = format!("{} of {} ({pct}%)", crate::util::fmt_bytes(st.used), crate::util::fmt_bytes(st.limit));
    if st.blocked {
        text.push_str(" · blocked");
    } else if st.throttled {
        text.push_str(&format!(" · upload limited to {}", crate::qos::fmt_rate(st.quota.throttle_kbps)));
    }
    ui.label(egui::RichText::new(text).font(theme::font(13.0)).color(if st.level == QuotaLevel::Ok { theme::text_dim() } else { color }));
}

/// Moves border `i` of `edges` (fractions of the table width, ascending) by `delta`, keeping `min` clear of its
/// neighbours. `lo` and `hi` bound the first and last border. The limits always include where the border is now,
/// so one that starts squeezed (narrow window, odd saved value) can still be dragged out and never sticks.
pub fn move_edge(edges: &mut [f32], i: usize, delta: f32, min: f32, lo: f32, hi: f32) {
    let prev = if i == 0 { lo } else { edges[i - 1] };
    let next = if i + 1 == edges.len() { hi } else { edges[i + 1] };
    let at = edges[i];
    edges[i] = (at + delta).min((next - min).max(at)).max((prev + min).min(at));
}

/// Drag handles on the borders between a table header's columns; `edges` are the inner borders as fractions of
/// `head`'s width. Draws the dividers too. Call before laying the rows out so they use this frame's widths.
pub fn column_handles(ui: &mut Ui, id: &str, head: Rect, edges: &mut [f32], lo: f32, hi: f32) {
    let w = head.width().max(1.0);
    for i in 0..edges.len() {
        let x = head.left() + edges[i] * w;
        ui.painter().vline(x, (head.top() + 1.0)..=(head.bottom() - 1.0), Stroke::new(1.0, theme::border()));
        let handle = Rect::from_center_size(pos2(x, head.center().y), vec2(8.0, head.height()));
        let resp = ui.interact(handle, ui.scope_id().with((id, i)), Sense::drag()).on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
        if resp.dragged() {
            move_edge(edges, i, resp.drag_delta().x / w, 48.0 / w, lo, hi);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dragged_border_stays_between_neighbours_and_never_sticks() {
        let mut e = [0.2, 0.5];
        super::move_edge(&mut e, 0, 0.5, 0.1, 0.0, 1.0);
        assert!((e[0] - 0.4).abs() < 1e-6, "{e:?}");
        super::move_edge(&mut e, 0, -0.9, 0.1, 0.0, 1.0);
        assert!((e[0] - 0.1).abs() < 1e-6);
        // Already squeezed below the minimum: it can be dragged out, and is not thrown anywhere when dragged further in.
        let mut e = [0.02, 0.05];
        super::move_edge(&mut e, 1, 0.3, 0.1, 0.0, 1.0);
        assert!(e[1] > 0.3);
        let mut e = [0.02, 0.05];
        super::move_edge(&mut e, 1, -0.3, 0.1, 0.0, 1.0);
        assert!((e[1] - 0.05).abs() < 1e-6, "{e:?}");
    }
}
