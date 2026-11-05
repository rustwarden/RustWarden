use super::row_in;
use crate::app::{Dialog, RustWarden, Tab};
use crate::data::*;
use crate::icons;
use crate::theme;
use crate::widgets;
use egui::{Align2, Rect, Sense, Stroke, Ui, pos2, vec2};

/// Whether `alert` passes the filter, period and search box.
pub fn alert_visible(alert: &Alert, filter: AlertFilter, period: AlertPeriod, query: &str, extra: &LogFilter, now: i64) -> bool {
    let by_filter = match filter {
        AlertFilter::Important => alert.important,
        AlertFilter::All => true,
        AlertFilter::Unread => alert.unread,
    };
    // Demo alerts have no timestamp; they only carry a day label.
    let by_period = match period {
        AlertPeriod::AllTime => true,
        AlertPeriod::Today => alert.day == "Today",
        AlertPeriod::Week => alert.ts == 0 || now - alert.ts < 7 * 86_400,
    };
    let by_query = query.is_empty() || [&alert.app, &alert.target, &alert.kind, &alert.text].iter().any(|s| s.to_lowercase().contains(query));
    let by_extra = (extra.categories.is_empty() || extra.categories.contains(&AppCategory::of(&alert.app, alert.icon)))
        && (extra.kinds.is_empty() || extra.kinds.contains(&alert.kind))
        && match extra.dest {
            AlertDest::Any => true,
            AlertDest::Remote => alert.country.is_some_and(|c| c != Country::Local),
            AlertDest::Local => alert.country == Some(Country::Local),
        }
        && match extra.signed {
            AlertSigned::Any => true,
            AlertSigned::Signed => alert.text_and_signature().1 == Some(true),
            AlertSigned::Unsigned => alert.text_and_signature().1 == Some(false),
        };
    by_filter && by_period && by_query && by_extra
}

/// A pill that opens a multi-select checklist; `none` is the label when nothing is ticked.
fn multi_pick<T: Clone + Eq + std::hash::Hash>(ui: &mut Ui, none: &str, set: &mut std::collections::HashSet<T>, items: &[(T, String)]) {
    let label = match set.len() {
        0 => none.to_owned(),
        1 => items.iter().find(|(k, _)| set.contains(k)).map_or(none.to_owned(), |(_, l)| l.clone()),
        n => format!("{n} selected"),
    };
    let resp = widgets::pill_button(ui, None, &label, true, 150.0);
    egui::Popup::menu(&resp).width(240.0).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
        for (k, l) in items {
            if widgets::check_item(ui, set.contains(k), l).clicked() && !set.remove(k) {
                set.insert(k.clone());
            }
        }
    });
}

/// Occurrence counts per key, in order of first appearance or biggest first, cut to `limit`.
fn counts<'a>(keys: impl Iterator<Item = &'a str>, by_size: bool, limit: usize) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    for k in keys {
        match out.iter_mut().find(|(n, _)| n == k) {
            Some(e) => e.1 += 1,
            None => out.push((k.to_owned(), 1)),
        }
    }
    if by_size {
        out.sort_by_key(|e| std::cmp::Reverse(e.1));
    }
    out.truncate(limit);
    out
}

/// A titled list of horizontal bars, scaled to the largest count.
fn stat_bars(ui: &mut Ui, title: &str, rows: Vec<(String, usize)>) {
    ui.add_space(18.0);
    ui.label(egui::RichText::new(title).font(theme::bold(15.0)).color(theme::text()));
    ui.add_space(4.0);
    let max = rows.iter().map(|r| r.1).max().unwrap_or(1) as f32;
    for (name, n) in rows {
        let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 24.0), Sense::hover());
        let p = ui.painter();
        let bar = Rect::from_min_size(r.min + vec2(0.0, 2.0), vec2(r.width() * n as f32 / max, 20.0));
        p.rect_filled(bar, 4, theme::accent().gamma_multiply(0.3));
        widgets::text_fit(p, pos2(r.left() + 6.0, r.center().y), Align2::LEFT_CENTER, &name, theme::font(14.0), theme::text(), (r.width() - 40.0).max(0.0));
        p.text(pos2(r.right() - 4.0, r.center().y), Align2::RIGHT_CENTER, n.to_string(), theme::font(14.0), theme::text_dim());
    }
}

impl RustWarden {
    pub(crate) fn log_tab(&mut self, ui: &mut Ui) {
        let full = ui.max_rect();
        // Control card on top, then the list and the stats as cards below it.
        let card = |ui: &Ui, r: Rect| {
            ui.painter().rect_filled(r, 8, theme::card());
            ui.painter().rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::epaint::StrokeKind::Inside);
        };
        let bar = Rect::from_min_size(full.min + vec2(12.0, 12.0), vec2(full.width() - 24.0, 56.0));
        card(ui, bar);

        row_in(ui, bar.shrink2(vec2(14.0, 0.0)), |ui| {
            if widgets::pill_button(ui, Some(icons::Icon::Filter), "Filter", false, 0.0).clicked() {
                self.log.filter_open = !self.log.filter_open;
            }
            widgets::dropdown(ui, None, &mut self.log.filter, &AlertFilter::ALL, |f| f.label().into(), 130.0);
            widgets::dropdown(ui, None, &mut self.log.period, &AlertPeriod::ALL, |f| f.label().into(), 130.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.caps.live {
                    let snoozed = self.backend.alerts_snoozed();
                    if widgets::pill_button(ui, None, if snoozed { "Unsnooze" } else { "Snooze 1 h" }, false, 0.0).clicked() {
                        self.backend.snooze_alerts(if snoozed { 0 } else { 60 });
                        self.notify(if snoozed { "Alerts unsnoozed" } else { "Alerts snoozed for 1 hour" });
                    }
                }
                if widgets::pill_button(ui, None, "Verify log", false, 0.0).clicked() {
                    self.verify_alert_log(ui.ctx());
                }
                if widgets::pill_button(ui, None, "Weekly report", false, 0.0).clicked() {
                    self.view_weekly_report(ui.ctx());
                }
                if widgets::pill_button(ui, None, "Export log", false, 0.0).clicked() {
                    self.export_history(ui.ctx(), HistoryData::Alerts, "RustWarden alert log.csv", None);
                }
                // Give the search box what is left after the two dropdowns and the buttons.
                // (dropdowns + "Mark all as read" + "Verify log" + "Export log" + "Weekly report" + gaps are reserved on the left)
                // Same width as the Firewall tab's search box, shrinking only when the window is too narrow.
                let search_w = (full.width() * 0.17).max(160.0).min(ui.available_width() - 190.0).max(120.0);
                widgets::search_box(ui, &mut self.log.search, search_w);
                ui.add_space(6.0);
                // Only while something is unread; after a click it brightens briefly, then fades out.
                const HOLD: f64 = 0.35;
                const FADE: f64 = 0.45;
                let id = egui::Id::unique("mark_read_clicked_at");
                let now = ui.input(|i| i.time);
                let clicked_at: Option<f64> = ui.data(|d| d.get_temp(id));
                let since = clicked_at.map(|t| now - t).filter(|s| *s < HOLD + FADE);
                if self.unread_count() > 0 || since.is_some() {
                    let alpha = since.map_or(1.0, |s| (1.0 - (s - HOLD) / FADE).clamp(0.0, 1.0) as f32);
                    ui.set_opacity(alpha);
                    let resp = widgets::pill_button(ui, None, "Mark all as read", false, 0.0);
                    if since.is_some_and(|s| s < HOLD) {
                        ui.painter().rect_filled(resp.rect, 6, theme::accent().gamma_multiply(0.25));
                    }
                    if since.is_some() {
                        ui.ctx().request_repaint();
                    } else if resp.clicked() {
                        ui.data_mut(|d| d.insert_temp(id, now));
                        self.run_bg(|b| {
                            b.mark_read(None);
                            Ok(String::new())
                        });
                    }
                }
            });
        });

        let mut top = bar.bottom() + 12.0;
        if self.log.filter_open {
            let bar2 = Rect::from_min_size(pos2(bar.left(), top), vec2(bar.width(), 52.0));
            card(ui, bar2);
            let mut kinds: Vec<String> = self.log.alerts.iter().map(|a| a.kind.clone()).collect();
            kinds.sort();
            kinds.dedup();
            let kinds: Vec<(String, String)> = kinds.into_iter().map(|k| (k.clone(), k)).collect();
            let cats: Vec<(AppCategory, String)> = AppCategory::ALL.iter().map(|c| (*c, c.label().to_owned())).collect();
            let ex = &mut self.log.extra;
            let mut clear = false;
            row_in(ui, bar2.shrink2(vec2(14.0, 0.0)), |ui| {
                multi_pick(ui, "All categories", &mut ex.categories, &cats);
                multi_pick(ui, "All monitors", &mut ex.kinds, &kinds);
                widgets::dropdown(ui, None, &mut ex.dest, &AlertDest::ALL, |f| f.label().into(), 150.0);
                widgets::dropdown(ui, None, &mut ex.signed, &AlertSigned::ALL, |f| f.label().into(), 150.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    clear = widgets::pill_button(ui, None, "Clear filters", false, 0.0).clicked();
                });
            });
            if clear {
                *ex = LogFilter::default();
            }
            top = bar2.bottom() + 12.0;
        }

        let body = Rect::from_min_max(pos2(bar.left(), top), full.max - vec2(12.0, 12.0));
        let query = self.log.search.to_lowercase();
        let (filter, period) = (self.log.filter, self.log.period);
        let extra = self.log.extra.clone();
        let now = crate::clock::now_unix();
        let alerts = std::mem::take(&mut self.log.alerts);
        let mut read: Option<u64> = None;
        let mut whois: Option<String> = None;
        let mut app_info: Option<(String, egui::Pos2)> = None;
        let mut go: Option<Alert> = None;
        let mut normal: Option<u64> = None;
        let known: std::collections::HashMap<&str, (&str, &str)> = self.protect.apps.iter().map(|a| (a.name.as_str(), (a.key.as_str(), a.path.as_str()))).collect();

        // Stats sidebar: 30% on the right, counting exactly what the list shows.
        let side = Rect::from_min_max(pos2(body.right() - body.width() * 0.3, body.top()), body.max);
        let list = Rect::from_min_max(body.min, pos2(side.left() - 12.0, body.bottom()));
        let visible: Vec<&Alert> = alerts.iter().filter(|a| alert_visible(a, filter, period, &query, &extra, now)).collect();
        card(ui, side);
        ui.scope_builder(egui::UiBuilder::new().max_rect(side.shrink2(vec2(18.0, 0.0))), |ui| {
            egui::ScrollArea::vertical().id_salt("log_stats").auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(14.0);
                ui.label(egui::RichText::new(format!("{} alerts", visible.len())).font(theme::bold(20.0)).color(theme::text()));
                let unread = visible.iter().filter(|a| a.unread).count();
                ui.label(egui::RichText::new(format!("{unread} unread")).font(theme::font(14.0)).color(theme::text_dim()));
                stat_bars(ui, "By monitor", counts(visible.iter().map(|a| a.kind.as_str()), true, 6));
                stat_bars(ui, "Top apps", counts(visible.iter().map(|a| a.app.as_str()), true, 6));
                stat_bars(ui, "By day", counts(visible.iter().map(|a| a.day.as_str()), false, 7));
            });
        });

        ui.scope_builder(egui::UiBuilder::new().max_rect(list.shrink2(vec2(2.0, 0.0))), |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(14.0);
                let mut day = "";
                let mut shown = 0;
                for alert in alerts.iter() {
                    if !alert_visible(alert, filter, period, &query, &extra, now) {
                        continue;
                    }
                    shown += 1;
                    if alert.day != day {
                        day = &alert.day;
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new(day).font(theme::font(17.0)).color(theme::text_dim()));
                        ui.add_space(8.0);
                    }
                    let (r, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 104.0), Sense::click());
                    // Hundreds of cards can be loaded; only the ones on screen are laid out.
                    if !ui.is_rect_visible(r) {
                        ui.add_space(8.0);
                        continue;
                    }
                    let resp = if self.alert_source(alert).is_some() { resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp };
                    let p = ui.painter().clone();
                    // Soft card; the badge, not the fill, carries unread.
                    p.rect_filled(r, 8, if resp.hovered() { theme::ctl_hover() } else { theme::card() });
                    p.rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::epaint::StrokeKind::Inside);
                    let cy = r.center().y;
                    let badge = pos2(r.left() + 58.0, cy);
                    // Clicking the NEW badge only marks the alert read; it doesn't navigate.
                    let mut badge_clicked = false;
                    if alert.unread {
                        let br = ui.interact(Rect::from_center_size(badge, vec2(56.0, 56.0)), ui.scope_id().with(("badge", alert.id)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                        if br.clicked() {
                            badge_clicked = true;
                            read = Some(alert.id);
                        }
                        p.circle_filled(badge, 28.0, theme::accent());
                        p.text(badge, Align2::CENTER_CENTER, "NEW", theme::bold(15.0), theme::on_accent());
                    } else {
                        p.circle_filled(badge, 28.0, theme::panel_bg());
                        icons::paint(&p, icons::Icon::Check, egui::Rect::from_center_size(badge, vec2(26.0, 26.0)), theme::text_dim());
                    }

                    // Title is the monitor; below it "<icon> **App** initiated its first network connection to <flag> **target**"
                    let left = r.left() + 112.0;
                    let width = |text: &str, bold: bool| p.layout_no_wrap(text.to_owned(), if bold { theme::bold(15.0) } else { theme::font(15.0) }, theme::text()).size().x;
                    let app = known.get(alert.app.as_str());
                    // Everything up to and including the target; if it doesn't fit, the target moves to a second line.
                    let lead = left + 28.0 + width(&alert.app, true) + 5.0 + width(&alert.text, false) + 5.0;
                    // Invisible wall left of the time column: the line wraps rather than touch it.
                    let wall = r.right() - 104.0;
                    let info = self.backend.net_info(&alert.target);
                    let is_ip = alert.target.parse::<std::net::IpAddr>().is_ok();
                    let info_w = if info.is_empty() { 0.0 } else { 4.0 + p.layout_no_wrap(info.clone(), theme::font(14.0), theme::text_dim()).size().x };
                    let wrapped = lead + if alert.country.is_some() { 28.0 } else { 0.0 } + width(&alert.target, true) + if is_ip { 22.0 } else { 0.0 } + info_w > wall;
                    let (title_y, ly) = if wrapped { (cy - 26.0, cy + 6.0) } else { (cy - 18.0, cy + 16.0) };
                    p.text(pos2(left, title_y), Align2::LEFT_CENTER, &alert.kind, theme::bold(22.0), theme::text());
                    let mut x = left;
                    icons::app_icon_for(&p, alert.icon, app.map_or("", |a| a.1), Rect::from_center_size(pos2(x + 10.0, ly), vec2(20.0, 20.0)));
                    x += 28.0;
                    let put = |x: f32, ly: f32, text: &str, bold: bool| -> f32 {
                        let font = if bold { theme::bold(15.0) } else { theme::font(15.0) };
                        let g = p.layout_no_wrap(text.to_owned(), font, theme::text());
                        let w = g.size().x;
                        p.galley(pos2(x, ly - g.size().y / 2.0), g, theme::text());
                        x + w + 5.0
                    };
                    // Clicking a known app's name opens the same popup as clicking it in the Firewall tab.
                    if let Some((key, _)) = app {
                        let b = Rect::from_min_size(pos2(x, ly - 10.0), vec2(width(&alert.app, true), 20.0));
                        let br = ui.interact(b, ui.scope_id().with(("app_info", alert.id)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                        if br.hovered() {
                            p.hline(b.x_range(), b.bottom(), Stroke::new(1.0, theme::text()));
                        }
                        if br.clicked() {
                            app_info = Some((key.to_string(), b.left_bottom()));
                        }
                    }
                    x = put(x, ly, &alert.app, true);
                    x = put(x, ly, &alert.text, false);
                    let ly = if wrapped {
                        x = left;
                        ly + 22.0
                    } else {
                        ly
                    };
                    if let Some(country) = alert.country {
                        icons::flag(&p, country, Rect::from_min_size(pos2(x, ly - 7.0), vec2(22.0, 15.0)));
                        x += 28.0;
                    }
                    x = if wrapped {
                        let w = widgets::text_fit(&p, pos2(x, ly), Align2::LEFT_CENTER, &alert.target, theme::bold(15.0), theme::text(), (wall - x).max(0.0)).width();
                        x + w + 5.0
                    } else {
                        put(x, ly, &alert.target, true)
                    };
                    if is_ip {
                        if widgets::whois_icon(ui, pos2(x + 8.0, ly), alert.id) {
                            whois = Some(alert.target.clone());
                        }
                        x += 22.0;
                    }
                    if !info.is_empty() {
                        widgets::text_fit(&p, pos2(x + 4.0, ly), Align2::LEFT_CENTER, &info, theme::font(14.0), theme::text_dim(), (wall - x - 4.0).max(0.0));
                    }

                    p.text(pos2(r.right() - 26.0, title_y), Align2::RIGHT_CENTER, &alert.time, theme::font(15.0), theme::text_dim());
                    // Same action as on the Traffic graph's alert popup.
                    if alert.anomaly {
                        let g = p.layout_no_wrap("Mark as normal".into(), theme::font(14.0), theme::text_dim());
                        let b = Rect::from_min_size(pos2(r.right() - 26.0 - g.size().x, r.bottom() - 30.0), g.size());
                        let br = ui.interact(b, ui.scope_id().with(("normal", alert.id)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                        let ink = if br.hovered() { theme::text() } else { theme::text_dim() };
                        p.galley(b.min, g, ink);
                        if br.hovered() {
                            p.hline(b.x_range(), b.bottom(), Stroke::new(1.0, ink));
                        }
                        if br.clicked() {
                            normal = Some(alert.id);
                        }
                    }
                    if resp.clicked() && !badge_clicked && whois.is_none() && app_info.is_none() && normal.is_none() {
                        if alert.unread {
                            read = Some(alert.id);
                        }
                        go = Some(alert.clone());
                    }
                    ui.add_space(8.0);
                }
                if shown == 0 {
                    ui.add_space(30.0);
                    let msg = if alerts.is_empty() { "No alerts yet. They appear here as the monitors notice something." } else { "No alerts match the current filter." };
                    ui.label(egui::RichText::new(msg).font(theme::font(16.0)).color(theme::text_dim()));
                }
            });
        });
        self.log.alerts = alerts;
        let opened = app_info.is_some();
        if let Some((key, pos)) = app_info {
            let name = self.protect.apps.iter().find(|a| a.key == key).map(|a| a.name.clone()).unwrap_or_default();
            self.protect.selected_alerts = self.log.alerts.iter().filter(|a| a.app == name).cloned().collect();
            self.protect.selected = Some((key, pos));
            self.protect.show_alerts = false;
        }
        let can_scan = self.caps.live && !self.settings.virustotal_key.is_empty();
        self.app_popup(ui.ctx(), can_scan, opened);
        if let Some(ip) = whois {
            self.open_whois(ui.ctx(), &ip);
        }
        // The reload after a background job shows the change.
        if let Some(id) = normal {
            self.run_bg(move |b| {
                b.mark_alert_normal(id);
                Ok(String::new())
            });
        }
        if let Some(id) = read {
            self.run_bg(move |b| {
                b.mark_read(Some(id));
                Ok(String::new())
            });
        }
        if let Some(alert) = go {
            self.show_alert_source(&alert);
        }
    }

    /// Walks the alert log's hash chain on a thread, since it reads every entry; `poll_alert_check` shows the answer.
    pub(crate) fn verify_alert_log(&mut self, ctx: &egui::Context) {
        if !matches!(self.dialog, None | Some(Dialog::Info { .. })) {
            self.notify("Close the open dialog, then verify the alert log.");
            return;
        }
        let (slot, ctx, backend) = (self.alert_check_result.clone(), ctx.clone(), self.backend.clone());
        std::thread::spawn(move || {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(backend.verify_alerts());
            ctx.request_repaint();
        });
    }

    /// Builds the weekly report on a thread; `poll_weekly_report` shows it.
    pub(crate) fn view_weekly_report(&mut self, ctx: &egui::Context) {
        if !matches!(self.dialog, None | Some(Dialog::Info { .. } | Dialog::Report(_))) {
            self.notify("Close the open dialog, then open the weekly report.");
            return;
        }
        let (slot, ctx, backend) = (self.report_result.clone(), ctx.clone(), self.backend.clone());
        std::thread::spawn(move || {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(backend.weekly_report());
            ctx.request_repaint();
        });
    }

    pub(crate) fn poll_weekly_report(&mut self) {
        let done = self.report_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(result) = done else { return };
        match result {
            Ok(report) if matches!(self.dialog, None | Some(Dialog::Info { .. } | Dialog::Report(_))) => self.dialog = Some(Dialog::Report(Box::new(report))),
            Ok(_) => self.notify("The weekly report is ready: close the open dialog and open it again."),
            Err(e) => self.notify(&format!("Couldn't build the weekly report: {e}")),
        }
    }

    /// Shows the check's result as a dialog, or as a toast's first line when another dialog is open.
    pub(crate) fn poll_alert_check(&mut self) {
        let done = self.alert_check_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(result) = done else { return };
        let body = match result {
            Ok(check) => check.summary(),
            Err(e) => format!("Could not check the alert log: {e}"),
        };
        match self.dialog {
            None | Some(Dialog::Info { .. }) => self.dialog = Some(Dialog::Info { title: "Alert log".into(), body }),
            _ => self.notify(body.lines().next().unwrap_or_default()),
        }
    }

    /// The tab an alert is about, or `None` when there is nowhere to go (so the card isn't drawn as a link).
    pub(super) fn alert_source(&self, alert: &Alert) -> Option<Tab> {
        source_tab(&alert.kind, self.protect.apps.iter().any(|a| a.name == alert.app), crate::plugins::thinkbroadband::tab_visible(&self.settings))
    }

    /// Jump to the part of the UI an alert is about, flashing the app, graph or device; alerts with nowhere to go do nothing.
    pub(super) fn show_alert_source(&mut self, alert: &Alert) {
        let Some(tab) = self.alert_source(alert) else { return };
        self.tab = tab;
        match tab {
            Tab::Protect if alert.kind != "Firewall rules" => {
                self.protect.search.clear();
                self.protect.open_groups = [true; 4];
                self.protect.flash = Some((alert.app.clone(), std::time::Instant::now(), true));
            }
            Tab::Broadband => self.tbb.show(crate::plugins::thinkbroadband::client::unescape(&alert.app)),
            // The target reads "<ip> (<mac>) – <name>"; the search box matches the address.
            Tab::Scanner => self.scanner.search = alert.target.split_whitespace().next().unwrap_or_default().to_owned(),
            _ => {}
        }
    }
}

/// Where an alert of this kind leads: app alerts only when the app is known, packet loss only while the Broadband tab shows.
fn source_tab(kind: &str, app_known: bool, broadband: bool) -> Option<Tab> {
    match kind {
        "First network activity" | "App info changed" | "Malicious IP" | "New country or network" | "Traffic spike" | "Unusual hour" if app_known => Some(Tab::Protect),
        "Firewall rules" => Some(Tab::Protect),
        "Packet loss" if broadband => Some(Tab::Broadband),
        "New device" | "Device spoofing" | "Device returned" => Some(Tab::Scanner),
        "Malicious domain" => Some(Tab::Dns),
        "Data plan" | "Data quota" => Some(Tab::Traffic),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_source_only_for_kinds_with_somewhere_to_go() {
        assert!(matches!(source_tab("New device", false, false), Some(Tab::Scanner)));
        assert!(matches!(source_tab("Traffic spike", true, false), Some(Tab::Protect)));
        assert!(source_tab("Traffic spike", false, false).is_none());
        assert!(source_tab("Packet loss", false, false).is_none());
        assert!(source_tab("Hosts file", true, true).is_none());
    }

    fn alert(app: &str, unread: bool, important: bool, ts: i64) -> Alert {
        Alert {
            id: 1,
            app: app.into(),
            icon: AppIcon::Generic,
            text: "did a thing".into(),
            target: "example.com".into(),
            country: None,
            kind: "Kind".into(),
            time: String::new(),
            day: "Today".into(),
            ts,
            unread,
            important,
            anomaly: false,
        }
    }

    #[test]
    fn counts_order_and_limit() {
        let keys = ["a", "b", "b", "c", "b", "a"];
        assert_eq!(counts(keys.into_iter(), false, 2), vec![("a".into(), 2), ("b".into(), 3)]);
        assert_eq!(counts(keys.into_iter(), true, 2), vec![("b".into(), 3), ("a".into(), 2)]);
    }

    #[test]
    fn filters_combine() {
        let now = 10_000_000;
        let a = alert("Chrome", true, false, now - 100);
        assert!(alert_visible(&a, AlertFilter::All, AlertPeriod::AllTime, "", &LogFilter::default(), now));
        assert!(!alert_visible(&a, AlertFilter::Important, AlertPeriod::AllTime, "", &LogFilter::default(), now));
        assert!(alert_visible(&a, AlertFilter::Unread, AlertPeriod::AllTime, "chrome", &LogFilter::default(), now));
        assert!(!alert_visible(&a, AlertFilter::All, AlertPeriod::AllTime, "firefox", &LogFilter::default(), now));
        let old = alert("Chrome", false, true, now - 8 * 86_400);
        assert!(!alert_visible(&old, AlertFilter::All, AlertPeriod::Week, "", &LogFilter::default(), now));
        let only = |c| LogFilter { categories: [c].into(), ..Default::default() };
        assert!(alert_visible(&a, AlertFilter::All, AlertPeriod::AllTime, "", &only(AppCategory::Browsers), now));
        assert!(!alert_visible(&a, AlertFilter::All, AlertPeriod::AllTime, "", &only(AppCategory::Security), now));
        let remote = LogFilter { dest: AlertDest::Remote, ..Default::default() };
        assert!(!alert_visible(&a, AlertFilter::All, AlertPeriod::AllTime, "", &remote, now)); // no country
    }
}
