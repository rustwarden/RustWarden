//! Alerts > Rules: what happens to an alert after it is raised (mute, escalate, keep on this PC, limit repeats),
//! by alert kind, app, words, time of day and weekday. The model and matching live in `crate::alertrules`.

use super::row_in;
use crate::alertrules::{ALL_DAYS, AlertRule, DAY_NAMES, MAX_RULES, RuleAction, parse_minute};
use crate::app::RustWarden;
use crate::live::alerts::AlertKind;
use crate::theme;
use crate::widgets;
use egui::{Rect, Ui, pos2, vec2};

/// The new-rule form.
pub struct RuleDraft {
    pub action: RuleAction,
    /// 0 for any alert kind, otherwise one more than the index in `AlertKind::ALL`.
    pub kind: usize,
    pub app: String,
    pub contains: String,
    pub timed: bool,
    pub from: String,
    pub to: String,
    pub days: u8,
    pub limit_min: u32,
    pub error: String,
}

impl Default for RuleDraft {
    fn default() -> Self {
        Self {
            action: RuleAction::Mute,
            kind: 0,
            app: String::new(),
            contains: String::new(),
            timed: false,
            from: "22:00".into(),
            to: "07:00".into(),
            days: ALL_DAYS,
            limit_min: 60,
            error: String::new(),
        }
    }
}

impl RuleDraft {
    /// The rule this form describes, or what is wrong with it.
    fn build(&self, id: u32) -> Result<AlertRule, &'static str> {
        let (from, to) = if self.timed {
            (parse_minute(&self.from).ok_or("Enter the start time as HH:MM, such as 22:00.")?, parse_minute(&self.to).ok_or("Enter the end time as HH:MM, such as 07:00.")?)
        } else {
            (0, 0)
        };
        if self.days & ALL_DAYS == 0 {
            return Err("Pick at least one day.");
        }
        Ok(AlertRule {
            id,
            enabled: true,
            action: self.action,
            kinds: AlertKind::ALL.get(self.kind.wrapping_sub(1)).map(|k| vec![k.key().to_owned()]).unwrap_or_default(),
            app: self.app.clone(),
            contains: self.contains.trim().to_owned(),
            from,
            to,
            days: self.days & ALL_DAYS,
            limit_min: self.limit_min.clamp(1, 10_080),
        })
    }
}

fn kind_title(key: &str) -> String {
    AlertKind::ALL.iter().find(|k| k.key() == key).map_or_else(|| key.to_owned(), |k| k.title().to_owned())
}

fn labelled(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 4.0;
        ui.label(egui::RichText::new(label).font(theme::font(12.5)).color(theme::text_dim()));
        add(ui);
    });
}

impl RustWarden {
    pub(crate) fn alert_rules_tab(&mut self, ui: &mut Ui) {
        let mut d = std::mem::take(&mut self.rule_draft);
        let mut rules = self.settings.alert_rules.clone();
        let (mut add, mut remove, mut toggled) = (false, None, None);
        let apps: Vec<(String, String, crate::data::AppIcon)> = self.protect.apps.iter().filter(|a| !a.locked).map(|a| (a.name.clone(), a.path.clone(), a.icon)).collect();
        let kinds: Vec<usize> = (0..=AlertKind::ALL.len()).collect();
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            egui::Frame::NONE.inner_margin(egui::Margin::same(12)).show(ui, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 12.0);
                let edge = egui::Stroke::new(1.0, theme::card_edge());

                egui::Frame::NONE.fill(theme::accent_soft()).stroke(egui::Stroke::new(1.0, theme::accent().gamma_multiply(0.4))).corner_radius(8).inner_margin(egui::Margin::symmetric(14, 12)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_top(|ui| {
                        let (icon, _) = ui.allocate_exact_size(vec2(18.0, 18.0), egui::Sense::hover());
                        crate::icons::paint(ui.painter(), crate::icons::Icon::Info, icon, theme::accent_text());
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(
                                    "Rules decide what happens to an alert after it is raised: mute it, make it Important, keep it off your phone, or notify only once in a while. The first rule in the list that matches an alert is the one that applies. Every alert is still recorded in the Alerts log, even a muted one.",
                                )
                                .font(theme::font(14.0))
                                .color(theme::text()),
                            )
                            .wrap(),
                        );
                    });
                });

                egui::Frame::NONE.fill(theme::card()).stroke(edge).corner_radius(8).inner_margin(egui::Margin::same(14)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(egui::RichText::new("New rule").font(theme::bold(15.0)).color(theme::text()));
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        labelled(ui, "Action", |ui| {
                            widgets::dropdown(ui, None, &mut d.action, &RuleAction::ALL, |a| a.label().into(), 140.0);
                        });
                        labelled(ui, "Alert type", |ui| {
                            widgets::dropdown(ui, None, &mut d.kind, &kinds, |i| if i == 0 { "Any alert".into() } else { AlertKind::ALL[i - 1].title().to_owned() }, 200.0);
                        });
                        labelled(ui, "App", |ui| {
                            let shown = crate::util::fit_text(ui.painter(), if d.app.is_empty() { "Any app" } else { &d.app }, &theme::font(14.0), 150.0);
                            let resp = widgets::pill_button(ui, None, &shown, true, 180.0);
                            egui::Popup::menu(&resp).width(280.0).show(|ui| {
                                ui.set_max_height(340.0);
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    if widgets::check_item(ui, d.app.is_empty(), "Any app").clicked() {
                                        d.app.clear();
                                        ui.close();
                                    }
                                    for (name, path, icon) in &apps {
                                        if widgets::check_item_icon(ui, d.app == *name, name, Some((*icon, path))).clicked() {
                                            d.app = name.clone();
                                            ui.close();
                                        }
                                    }
                                });
                            });
                        });
                        labelled(ui, "Text contains", |ui| {
                            ui.add(egui::TextEdit::singleline(&mut d.contains).hint_text("optional").font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(150.0));
                        });
                    });
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        widgets::switch(ui, &mut d.timed, "Only between");
                        if d.timed {
                            ui.add(egui::TextEdit::singleline(&mut d.from).font(theme::font(14.0)).desired_width(56.0));
                            ui.label("and");
                            ui.add(egui::TextEdit::singleline(&mut d.to).font(theme::font(14.0)).desired_width(56.0));
                        }
                        for (i, name) in DAY_NAMES.iter().enumerate() {
                            // Themed chip: the stock selected style puts light text on the accent fill, unreadable in either theme.
                            let on = d.days & (1 << i) != 0;
                            let (rect, resp) = ui.allocate_exact_size(vec2(56.0, 30.0), egui::Sense::click());
                            let (fill, stroke, text) = match (on, resp.hovered()) {
                                (true, _) => (theme::accent_soft(), theme::accent().gamma_multiply(0.6), theme::accent_text()),
                                (false, true) => (theme::nav_on(), theme::card_edge(), theme::text()),
                                (false, false) => (theme::field(), theme::card_edge(), theme::text_dim()),
                            };
                            ui.painter().rect(rect, 6, fill, egui::Stroke::new(1.0, stroke), egui::StrokeKind::Inside);
                            ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, *name, theme::font(14.0), text);
                            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                d.days ^= 1 << i;
                            }
                        }
                    });
                    if d.action == RuleAction::Limit {
                        ui.horizontal(|ui| {
                            ui.label("Notify at most once every");
                            widgets::num_field(ui, &mut d.limit_min, 1..=10_080, " min");
                        });
                    }
                    ui.label(egui::RichText::new(d.action.hint()).font(theme::font(13.0)).color(theme::text_dim()));
                    if !d.error.is_empty() {
                        ui.colored_label(theme::red(), &d.error);
                    }
                    if widgets::pill_button(ui, None, "Add rule", false, 100.0).clicked() {
                        add = true;
                    }
                });

                egui::Frame::NONE.fill(theme::card()).stroke(edge).corner_radius(8).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let w = ui.available_width();
                    if rules.is_empty() {
                        let (r, _) = ui.allocate_exact_size(vec2(w, 64.0), egui::Sense::hover());
                        ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "No alert rules yet.", theme::font(14.5), theme::text_dim());
                    }
                    for (i, rule) in rules.iter().enumerate() {
                        let (r, resp) = ui.allocate_exact_size(vec2(w, 48.0), egui::Sense::hover());
                        let p = ui.painter();
                        if resp.hovered() {
                            p.rect_filled(r, 0, theme::row_hover());
                        }
                        if i > 0 {
                            p.hline(r.x_range(), r.top(), egui::Stroke::new(1.0, theme::border().gamma_multiply(0.5)));
                        }
                        let cy = r.center().y;
                        let color = if rule.enabled { theme::text() } else { theme::text_dim() };
                        widgets::text_fit(p, pos2(r.left() + 76.0, cy), egui::Align2::LEFT_CENTER, &rule.summary(kind_title), theme::font(14.0), color, (w - 76.0 - 130.0).max(60.0));
                        let mut on = rule.enabled;
                        if row_in(ui, Rect::from_min_size(pos2(r.left() + 16.0, cy - 12.0), vec2(44.0, 24.0)), |ui| widgets::small_toggle(ui, &mut on)).clicked() {
                            toggled = Some((i, on));
                        }
                        let btn = Rect::from_min_max(pos2(r.right() - 108.0, r.top()), pos2(r.right() - 14.0, r.bottom()));
                        ui.scope_builder(egui::UiBuilder::new().max_rect(btn).layout(egui::Layout::right_to_left(egui::Align::Center)), |ui| {
                            if widgets::pill_button(ui, None, "Remove", false, 0.0).clicked() {
                                remove = Some(i);
                            }
                        });
                    }
                });
            });
        });

        let mut changed = false;
        if add {
            if rules.len() >= MAX_RULES {
                d.error = format!("At most {MAX_RULES} rules.");
            } else {
                match d.build(rules.iter().map(|r| r.id).max().unwrap_or(0) + 1) {
                    Ok(rule) => {
                        d.error.clear();
                        rules.push(rule);
                        changed = true;
                    }
                    Err(e) => d.error = e.into(),
                }
            }
        }
        if let Some((i, on)) = toggled {
            rules[i].enabled = on;
            changed = true;
        }
        if let Some(i) = remove {
            rules.remove(i);
            changed = true;
        }
        self.rule_draft = d;
        if changed {
            self.settings.alert_rules = rules;
            if let Err(e) = self.settings.save() {
                self.notify(&format!("Couldn't save settings: {e}"));
            }
            self.backend.apply_settings(&self.settings);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_becomes_a_rule_or_says_why_not() {
        let mut d = RuleDraft { kind: 1, app: "steam.exe".into(), contains: " :443 ".into(), ..RuleDraft::default() };
        let r = d.build(4).unwrap();
        assert_eq!((r.id, r.kinds.clone(), r.contains.as_str(), r.from, r.to), (4, vec![AlertKind::ALL[0].key().to_owned()], ":443", 0, 0));
        d.timed = true;
        d.from = "25:00".into();
        assert!(d.build(1).is_err());
        d.from = "22:00".into();
        let r = d.build(1).unwrap();
        assert_eq!((r.from, r.to), (22 * 60, 7 * 60));
        d.days = 0;
        assert!(d.build(1).is_err());
        assert!(RuleDraft::default().build(1).unwrap().kinds.is_empty(), "kind 0 means any");
    }
}
