//! The External Notifications page: a table of the services added, with an add menu listing the rest.

use super::{SERVICES, present};
use crate::icons::{self, Icon};
use crate::settings::Settings;
use crate::widgets;
use egui::{Color32, Rect, Shape, Stroke, Ui, vec2};

/// One credential field; `prefixes` (see `valid`) flags a URL the service wouldn't take.
pub(super) fn field(ui: &mut Ui, label: &str, hint: &str, value: &mut String, prefixes: Option<&[&str]>) {
    ui.label(label);
    let r = ui.add(egui::TextEdit::singleline(value).password(true).hint_text(hint).desired_width(420.0));
    crate::widgets::edit_menu(ui, &r, value, true);
    *value = value.trim().to_owned();
    if let Some(p) = prefixes
        && !value.is_empty()
        && !super::valid(value, p)
    {
        ui.colored_label(crate::theme::red(), "This isn't a valid URL for this service.");
    }
}

/// Simplified logo of the service, painted (the app ships no image assets); unknown ids get a plug.
fn mark(ui: &mut Ui, id: &str) {
    let (rect, _) = ui.allocate_exact_size(vec2(20.0, 20.0), egui::Sense::hover());
    let p = ui.painter();
    let (s, c) = (rect.width(), rect.center());
    let u = |x: f32, y: f32| rect.min + vec2(x * s, y * s);
    let rgb = Color32::from_rgb;
    let white = Color32::WHITE;
    let stroke = Stroke::new(s * 0.1, white);
    match id {
        "discord" => {
            let blurple = rgb(0x58, 0x65, 0xF2);
            p.rect_filled(rect, 5.0, blurple);
            p.rect_filled(Rect::from_min_max(u(0.15, 0.28), u(0.85, 0.72)), s * 0.2, white);
            for x in [0.36, 0.64] {
                p.circle_filled(u(x, 0.5), s * 0.08, blurple);
            }
        }
        "slack" => {
            for (x, y, col) in [(0.3, 0.2, rgb(0x36, 0xC5, 0xF0)), (0.8, 0.3, rgb(0x2E, 0xB6, 0x7D)), (0.7, 0.8, rgb(0xEC, 0xB2, 0x2E)), (0.2, 0.7, rgb(0xE0, 0x1E, 0x5A))] {
                p.rect_filled(Rect::from_center_size(u(x, y), vec2(s * 0.22, s * 0.22)), s * 0.11, col);
            }
            for (x, y, w, h, col) in
                [(0.5, 0.35, 0.4, 0.2, rgb(0x36, 0xC5, 0xF0)), (0.65, 0.5, 0.2, 0.4, rgb(0x2E, 0xB6, 0x7D)), (0.5, 0.65, 0.4, 0.2, rgb(0xEC, 0xB2, 0x2E)), (0.35, 0.5, 0.2, 0.4, rgb(0xE0, 0x1E, 0x5A))]
            {
                p.rect_filled(Rect::from_center_size(u(x, y), vec2(s * w, s * h)), s * 0.1, col);
            }
        }
        "pushbullet" => {
            p.circle_filled(c, s * 0.5, rgb(0x4A, 0xB3, 0x67));
            p.rect_filled(Rect::from_min_max(u(0.3, 0.25), u(0.42, 0.75)), 1.0, white);
            p.rect_filled(Rect::from_min_max(u(0.5, 0.25), u(0.7, 0.75)), s * 0.1, white);
        }
        "ntfy" => {
            p.rect_filled(rect, 5.0, rgb(0x33, 0x85, 0x74));
            p.add(Shape::line(vec![u(0.24, 0.3), u(0.46, 0.5), u(0.24, 0.7)], stroke));
            p.line_segment([u(0.52, 0.72), u(0.78, 0.72)], stroke);
        }
        "gotify" => {
            p.circle_filled(c, s * 0.5, rgb(0x3F, 0x8C, 0xBF));
            icons::paint(p, Icon::Bell, Rect::from_center_size(c, vec2(s * 0.6, s * 0.6)), white);
        }
        "webhook" => icons::paint(p, Icon::Globe, rect, crate::theme::accent()),
        _ => icons::paint(p, Icon::Plug, rect, crate::theme::accent()),
    }
}

pub fn section(ui: &mut Ui, s: &mut Settings) {
    ui.label("Alerts are posted to every service added here, for each alert type that has \"Send External Notifications\" ticked. Red alerts are sent red and the rest green where the service supports colors. Keys and webhook addresses are stored encrypted for your Windows account.");
    let edit_id = ui.scope_id().with("notification_edit");
    let mut edit: Option<usize> = ui.data_mut(|d| d.get_temp::<Option<usize>>(edit_id)).flatten();
    let mut remove = None;
    egui::Grid::new("notification_services").num_columns(4).spacing([16.0, 8.0]).striped(true).show(ui, |ui| {
        for (i, v) in SERVICES.iter().enumerate().filter(|(_, v)| present(s, **v)) {
            mark(ui, v.id());
            ui.label(v.name());
            if ui.button("Edit").clicked() {
                edit = Some(i);
            }
            if ui.button("Remove").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if SERVICES.iter().all(|v| !present(s, *v)) {
        ui.label("No services yet.");
    }
    let add = widgets::icon_button(ui, Icon::Plus, 34.0, "Add a service");
    let mut added = None;
    egui::Popup::menu(&add).show(|ui| {
        ui.set_min_width(180.0);
        for (i, v) in SERVICES.iter().enumerate().filter(|(_, v)| !present(s, **v)) {
            ui.horizontal(|ui| {
                mark(ui, v.id());
                if ui.button(v.name()).clicked() {
                    added = Some(i);
                    ui.close();
                }
            });
        }
    });
    if let Some(i) = added {
        s.notify_added.push(SERVICES[i].id().to_owned());
        edit = Some(i);
    }
    if let Some(i) = remove {
        SERVICES[i].clear(s);
        s.notify_added.retain(|id| id != SERVICES[i].id());
        edit = None;
    }
    if let Some(v) = edit.and_then(|i| SERVICES.get(i)) {
        let mut open = true;
        if !crate::widgets::dialog(v.name()).show(ui.ctx(), |ui| {
            ui.set_width(440.0);
            ui.spacing_mut().item_spacing.y = 6.0;
            v.fields(ui, s);
            if ui.button("Close").clicked() {
                open = false;
            }
        }) {
            open = false;
        }
        if !open {
            edit = None;
        }
    } else {
        edit = None;
    }
    ui.add_space(8.0);
    crate::widgets::switch(ui, &mut s.api_in_snooze, "Keep sending to these services while alerts are snoozed");
    crate::widgets::switch(ui, &mut s.report, "Send a weekly summary to these services");
    ui.add_enabled_ui(s.report, |ui| {
        ui.horizontal(|ui| {
            const DAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
            egui::ComboBox::from_id_salt("report_weekday").selected_text(DAYS[usize::from(s.report_weekday.min(6))]).show_ui(ui, |ui| {
                for (i, day) in DAYS.iter().enumerate() {
                    ui.selectable_value(&mut s.report_weekday, i as u8, *day);
                }
            });
            ui.label("at");
            ui.add(egui::DragValue::new(&mut s.report_hour).range(0..=23).suffix(":00"));
        });
    });
    if ui.button("Send test alert").clicked() {
        super::send_all(s, false, "RustWarden test", "This is a test alert from RustWarden.");
    }
    ui.data_mut(|d| d.insert_temp(edit_id, edit));
}
