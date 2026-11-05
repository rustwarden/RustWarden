//! Windows 11 Settings look: a group title over a card of rows, each with its title and description at the
//! left and its control at the right, on a Mica or acrylic window.

use crate::theme;
use egui::{Align, Frame, Layout, Margin, RichText, Stroke, Ui, vec2};

/// A titled card (no title when empty); fill it with rows and blocks through the [`Card`].
pub fn group<R>(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Card) -> R) -> R {
    let gap = ui.spacing().item_spacing.y;
    if !title.is_empty() {
        ui.label(RichText::new(title).font(theme::bold(14.0)).color(theme::text_dim()));
        ui.spacing_mut().item_spacing.y = 6.0; // the title belongs to its card
    }
    let r = Frame::NONE
        .fill(theme::card())
        .stroke(Stroke::new(1.0, theme::card_edge()))
        .corner_radius(6)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            add(&mut Card { ui, first: true, enabled: true })
        })
        .inner;
    ui.spacing_mut().item_spacing.y = gap;
    r
}

pub struct Card<'a> {
    ui: &'a mut Ui,
    first: bool,
    enabled: bool,
}

impl Card<'_> {
    /// An id scope for keeping state of the rows' controls.
    pub fn ui_id(&self) -> egui::Id {
        self.ui.scope_id()
    }

    /// Greys out the rows that follow until called again.
    pub fn enable(&mut self, on: bool) {
        self.enabled = on;
    }

    /// A hairline between rows.
    fn gap(&mut self) {
        if !self.first {
            let r = self.ui.max_rect();
            self.ui.painter().hline(r.x_range(), self.ui.cursor().min.y, Stroke::new(1.0, theme::card_edge()));
        }
        self.first = false;
    }

    /// `title` (and a dim `sub` line under it) at the left, `control` at the right.
    pub fn row<R>(&mut self, title: &str, sub: &str, control: impl FnOnce(&mut Ui) -> R) -> R {
        self.gap();
        let enabled = self.enabled;
        Frame::NONE
            .inner_margin(Margin::symmetric(16, 10))
            .show(self.ui, |ui| {
                ui.add_enabled_ui(enabled, |ui| {
                    let w = ui.available_width();
                    ui.set_width(w);
                    // Tall enough for the text at a typical wrap width; the control is centred in that height.
                    let wrap = w * 0.6;
                    let title_h = ui.painter().layout(title.to_owned(), theme::font(14.0), theme::text(), wrap).size().y;
                    let sub_h = if sub.is_empty() { 0.0 } else { ui.painter().layout(sub.to_owned(), theme::font(12.0), theme::text_dim(), wrap).size().y + 2.0 };
                    let h = (title_h + sub_h).max(32.0);
                    ui.allocate_ui_with_layout(vec2(w, h), Layout::right_to_left(Align::Center), |ui| {
                        // The control goes first so the text wraps in what is left, never under it.
                        let r = control(ui);
                        ui.add_space(12.0);
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.label(RichText::new(title).font(theme::font(14.0)));
                                if !sub.is_empty() {
                                    ui.label(RichText::new(sub).font(theme::font(12.0)).color(theme::text_dim()));
                                }
                            });
                        });
                        r
                    })
                    .inner
                })
                .inner
            })
            .inner
    }

    /// Free-form content (lists, text, several controls) padded like a row.
    pub fn block<R>(&mut self, add: impl FnOnce(&mut Ui) -> R) -> R {
        self.gap();
        let enabled = self.enabled;
        Frame::NONE
            .inner_margin(Margin::symmetric(16, 12))
            .show(self.ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing = vec2(10.0, 10.0);
                ui.add_enabled_ui(enabled, add).inner
            })
            .inner
    }
}

/// Controls on a card: filled with a hair of white and a soft edge instead of the main window's grey.
pub fn style(ui: &mut Ui) {
    let v = ui.visuals_mut();
    v.text_edit_bg_color = Some(theme::ctl());
    for (w, fill) in [(&mut v.widgets.inactive, theme::ctl()), (&mut v.widgets.hovered, theme::ctl_hover()), (&mut v.widgets.active, theme::ctl_hover()), (&mut v.widgets.open, theme::ctl())] {
        w.weak_bg_fill = fill;
        w.bg_stroke = Stroke::new(1.0, theme::card_edge());
        w.corner_radius = 4.into();
    }
    v.widgets.inactive.bg_fill = theme::track_off();
    ui.spacing_mut().interact_size.y = 32.0;
}
