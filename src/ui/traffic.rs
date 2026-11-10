use super::{box_blur, row_in, tick_step};
use crate::app::RustWarden;
use crate::data::*;
use crate::icons::{self, Icon};
use crate::theme;
use crate::util::{fmt_bytes, fmt_clock, fmt_rate};
use crate::widgets;
use egui::{Align2, Color32, Pos2, Rect, Sense, Stroke, Ui, pos2, vec2};

/// Where each command card was last drawn, so the map under it can tell the pointer is on a bar.
pub(super) fn command_card_id(ui: &Ui, rtl: bool) -> egui::Id {
    ui.scope_id().with(("command_card", rtl))
}

/// A rounded card behind a row of controls floating over the graph or map; `rtl` packs the row against the right edge.
/// The icon inside a graph pin for an alert that has no app icon, chosen by the monitor's label.
fn kind_icon(label: &str) -> Icon {
    match label {
        "Malicious IP" | "Malicious domain" | "Port scan or flood" | "Program fingerprint mismatch" => Icon::ShieldAlert,
        "Internet access" | "DNS server settings" | "DNS leak" | "Public IP address" | "Proxy settings" | "New country or network" | "DNS tunnelling" => Icon::Globe,
        "New device" | "Device spoofing" | "Device returned" | "ARP table" | "Second DHCP server" => Icon::Wifi,
        "Firewall rules" | "Computer unlocked" | "User account" | "Root certificate" => Icon::Lock,
        "Packet loss" => Icon::Wave,
        "Data plan" | "Data quota" | "Traffic spike" => Icon::Traffic,
        "Microphone or camera" => Icon::Camera,
        "Remote Desktop" => Icon::Laptop,
        "Startup entry" | "New service" => Icon::Chip,
        "Scheduled task" | "Unusual hour" | "While you were away" | "Regular check-ins" => Icon::Hourglass,
        "New listening port" => Icon::Plug,
        "Hosts file" => Icon::Alerts,
        "First network activity" | "App info changed" => Icon::Info,
        _ => Icon::Bell,
    }
}

fn command_card<R>(ui: &mut Ui, rect: Rect, rtl: bool, add: impl FnOnce(&mut Ui) -> R) -> R {
    let bg = ui.painter().add(egui::Shape::Noop);
    let layout = if rtl { egui::Layout::right_to_left(egui::Align::Center) } else { egui::Layout::left_to_right(egui::Align::Center) };
    let out = ui.scope_builder(egui::UiBuilder::new().max_rect(rect).layout(layout), |ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        add(ui)
    });
    let card = out.response.rect.expand2(vec2(6.0, 4.0));
    let shapes = vec![egui::Shape::rect_filled(card, 8, theme::popup_surface()), egui::Shape::rect_stroke(card, 8, Stroke::new(1.0, theme::card_edge()), egui::epaint::StrokeKind::Inside)];
    ui.painter().set(bg, egui::Shape::Vec(shapes));
    ui.data_mut(|d| d.insert_temp(command_card_id(ui, rtl), card));
    out.inner
}

impl RustWarden {
    pub(crate) fn traffic_tab(&mut self, ui: &mut Ui) {
        let full = ui.max_rect();
        let toolbar = Rect::from_min_size(full.min + vec2(14.0, 10.0), vec2(full.width() - 28.0, 40.0));
        // The map and the graph fill the whole area; the command bars float over them (the usage lists start below).
        if self.traffic.view == 2 {
            self.traffic_map(ui, full);
        }
        let body = if self.traffic.view == 0 { full } else { Rect::from_min_max(pos2(full.left(), toolbar.bottom() + 10.0), full.max) };
        match self.traffic.view {
            0 => self.traffic_graph(ui, body),
            1 => {
                let strip = Rect::from_min_max(full.min, pos2(full.right(), body.top()));
                ui.painter().rect_filled(strip, 0, theme::surface());
                ui.painter().hline(full.x_range(), strip.bottom(), Stroke::new(1.0, theme::border()));
                self.traffic_lists(ui, body);
            }
            _ => {}
        }

        // Left bar: the view switch, then Filter and Display.
        command_card(ui, toolbar, false, |ui| {
            widgets::segmented_text(ui, &mut self.traffic.view, &["Graph", "Usage", "Map"]);
            if !self.traffic.filter_open {
                let resp = widgets::pill_button(ui, Some(Icon::Filter), "Filter", false, 0.0);
                if self.traffic.filter != TrafficFilter::default() {
                    // Dot on the corner: a filter is narrowing every view.
                    let c = resp.rect.right_top() + vec2(-6.0, 6.0);
                    ui.painter().circle_filled(c, 6.0, theme::surface());
                    ui.painter().circle_filled(c, 4.5, theme::accent());
                }
                if resp.clicked() {
                    self.traffic.filter_open = true;
                }
            }
            if self.traffic.view == 0 {
                let resp = widgets::pill_button(ui, None, "Display", true, 0.0);
                let mut hidden = self.settings.graph_hidden.clone();
                egui::Popup::menu(&resp).width(240.0).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
                    for k in crate::live::alerts::AlertKind::ALL {
                        let label = crate::live::alerts::AlertKind::label_for_key(k.key());
                        let shown = !hidden.iter().any(|h| h == label);
                        if widgets::check_item(ui, shown, label).clicked() {
                            if shown { hidden.push(label.to_owned()) } else { hidden.retain(|h| h != label) }
                        }
                    }
                });
                if hidden != self.settings.graph_hidden {
                    self.settings.graph_hidden = hidden;
                    if let Err(e) = self.settings.save() {
                        self.notify(&format!("Couldn't save settings: {e}"));
                    }
                }
            }
            if self.traffic.view == 2 {
                let resp = widgets::pill_button(ui, None, "Display", true, 0.0);
                let s = &self.settings;
                let (mut names, mut flags, mut anim, mut allowed, mut blocked) = (s.map_names, s.map_flags, s.map_animate, s.map_allowed, s.map_blocked);
                egui::Popup::menu(&resp).width(220.0).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
                    names ^= widgets::check_item(ui, names, "Country names").clicked();
                    flags ^= widgets::check_item(ui, flags, "Country flags").clicked();
                    anim ^= widgets::check_item(ui, anim, "Animated traffic lines").clicked();
                    ui.separator();
                    allowed ^= widgets::check_item(ui, allowed, "Allowed traffic").clicked();
                    blocked ^= widgets::check_item(ui, blocked, "Blocked traffic").clicked();
                    // Same red as the blocked arcs and bubbles on the map.
                    ui.colored_label(super::map::blocked_color(), "Red dashed lines are blocked attempts");
                });
                if (names, flags, anim, allowed, blocked) != (s.map_names, s.map_flags, s.map_animate, s.map_allowed, s.map_blocked) {
                    (self.settings.map_names, self.settings.map_flags, self.settings.map_animate, self.settings.map_allowed, self.settings.map_blocked) = (names, flags, anim, allowed, blocked);
                    if let Err(e) = self.settings.save() {
                        self.notify(&format!("Couldn't save settings: {e}"));
                    }
                }
            }
        });

        // Right bar: the usual ranges as chips, the rest under "More". The usage view also has an Export menu.
        let right = Rect::from_min_max(pos2((toolbar.right() - 760.0).max(toolbar.left()), toolbar.top()), toolbar.right_bottom());
        let mut range_changed = false;
        command_card(ui, right, true, |ui| {
            const CHIPS: [TimeRange; 4] = [TimeRange::FiveMinutes, TimeRange::ThirtyMinutes, TimeRange::OneHour, TimeRange::Day];
            const OTHERS: [TimeRange; 4] = [TimeRange::OneMinute, TimeRange::TenMinutes, TimeRange::FifteenMinutes, TimeRange::ThreeHours];
            let cur = self.traffic.range;
            let more = widgets::pill_button(ui, None, if OTHERS.contains(&cur) { cur.label() } else { "More" }, true, 0.0);
            egui::Popup::menu(&more).width(190.0).show(|ui| {
                for o in OTHERS {
                    if widgets::check_item(ui, o == cur, o.label()).clicked() {
                        self.traffic.range = o;
                        range_changed = true;
                        ui.close();
                    }
                }
            });
            let mut idx = CHIPS.iter().position(|c| *c == cur).unwrap_or(usize::MAX);
            if widgets::segmented_text(ui, &mut idx, &["5 min", "30 min", "1 hour", "24 hours"]) && idx < CHIPS.len() {
                self.traffic.range = CHIPS[idx];
                range_changed = true;
            }
            if self.traffic.view == 1 {
                let export = widgets::pill_button(ui, Some(Icon::Export), "Export", true, 0.0);
                egui::Popup::menu(&export).width(220.0).show(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    if widgets::brand_menu_row(ui, Icon::Export, "Current usage (CSV)").clicked() {
                        self.export_usage();
                        ui.close();
                    }
                    if widgets::brand_menu_row(ui, Icon::Export, "Usage history (CSV)").clicked() {
                        self.export_history(ui.ctx(), HistoryData::Traffic, "RustWarden traffic history.csv", Some(30));
                        ui.close();
                    }
                });
            }
            if self.traffic.view == 2 {
                // Key for the home marker, right beside the range chips.
                ui.add_space(10.0);
                let (key, resp) = ui.allocate_exact_size(vec2(96.0, 32.0), Sense::click());
                widgets::shadowed_pill(ui.painter(), key, theme::surface());
                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    let (lon, lat) = self.traffic.map.home;
                    self.traffic.map_center_to = Some((lon, crate::geo::mercator_y(lat)));
                    self.traffic.map_zoom_to = 1.0;
                    // Stays "touched": clearing it snapped the zoom to 1.0 the moment the pan finished.
                    self.traffic.map_touched = true;
                }
                ui.painter().circle_filled(pos2(key.left() + 22.0, key.center().y), 5.0, super::map::home_dot());
                ui.painter().text(pos2(key.left() + 36.0, key.center().y), Align2::LEFT_CENTER, "Home", theme::font(15.0), theme::text());
            }
        });
        if range_changed {
            self.settings.traffic_range = self.traffic.range;
            if let Err(e) = self.settings.save() {
                self.notify(&format!("Couldn't save settings: {e}"));
            }
            self.traffic.detail = None;
            self.traffic.sel = None;
            self.reload_traffic();
        }

        if self.traffic.filter_open {
            self.filter_panel(ui, full);
        }
    }

    /// Filter panel over the left edge: dropdowns, then the apps with their usage.
    fn filter_panel(&mut self, ui: &mut Ui, full: Rect) {
        let panel = Rect::from_min_size(full.min, vec2(460.0_f32.min(full.width()), full.height()));
        let p = ui.painter();
        p.rect_filled(panel, 0, theme::surface_solid());
        p.vline(panel.right(), panel.y_range(), Stroke::new(1.0, theme::border()));
        ui.interact(panel, ui.scope_id().with("filter_panel"), Sense::click_and_drag());

        let mut filter = self.traffic.filter.clone();
        let bar = Rect::from_min_size(panel.min + vec2(14.0, 8.0), vec2(panel.width() - 28.0, 44.0));
        row_in(ui, bar, |ui| {
            let app_label = filter.app.as_ref().map_or("Apps", |(_, name)| name.as_str());
            let shown = crate::util::fit_text(ui.painter(), app_label, &theme::font(15.0), 90.0);
            let resp = widgets::pill_button(ui, None, &shown, true, 0.0);
            egui::Popup::menu(&resp).width(260.0).show(|ui| {
                ui.set_max_height(360.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    if widgets::check_item(ui, filter.app.is_none(), "All apps").clicked() {
                        filter.app = None;
                        ui.close();
                    }
                    // The Firewall tab's list, refreshed every second, rather than a fresh query per frame.
                    for a in &self.protect.apps {
                        let on = filter.app.as_ref().is_some_and(|(k, _)| *k == a.usage_key);
                        if widgets::check_item_icon(ui, on, &a.name, Some((a.icon, &a.path))).clicked() {
                            filter.app = Some((a.usage_key.clone(), a.name.clone()));
                            ui.close();
                        }
                    }
                });
            });
            widgets::dropdown(ui, None, &mut filter.scope, &Scope::ALL, |s| s.label().into(), 0.0);
            widgets::dropdown(ui, None, &mut filter.dir, &TrafficDir::ALL, |d| d.short().into(), 0.0);
        });

        // The close button shares the search row, not the pill row, which is full once an app name is shown.
        let net = Rect::from_min_size(pos2(bar.left(), bar.bottom() + 4.0), vec2(bar.width() - 42.0, 30.0));
        let close_rect = Rect::from_min_size(pos2(bar.right() - 36.0, net.center().y - 18.0), vec2(36.0, 36.0));
        if ui.put(close_rect, |ui: &mut Ui| widgets::icon_button(ui, Icon::Close, 36.0, "Close filters")).clicked() {
            self.traffic.filter_open = false;
        }
        let r = ui.put(net, egui::TextEdit::singleline(&mut filter.network).hint_text("Company or ASN (needs the AS lookup in Settings)").desired_width(net.width()));
        crate::widgets::edit_menu(ui, &r, &mut filter.network, false);

        // Table: "All apps" total, then each app; clicking a row filters to it.
        let top = net.bottom() + 8.0;
        let (col_down, col_up) = (panel.right() - 120.0, panel.right() - 24.0);
        let p = ui.painter();
        p.hline(panel.x_range(), top, Stroke::new(1.0, theme::border()));
        // Clickable headers: first click sorts (A-Z / largest first), second reverses, third resets.
        let heads = [(0u8, pos2(panel.left() + 90.0, top + 16.0), 120.0), (1, pos2(col_down - 30.0, top + 16.0), 40.0), (2, pos2(col_up - 30.0, top + 16.0), 40.0)];
        for (col, c, w) in heads {
            let hr = Rect::from_center_size(c, vec2(w, 32.0));
            let resp = ui.interact(hr, ui.scope_id().with(("sort_head", col)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            let cur = self.traffic.app_sort.filter(|s| s.0 == col);
            if resp.clicked() {
                let first = col == 0;
                self.traffic.app_sort = match cur {
                    None => Some((col, first)),
                    Some((_, asc)) if asc == first => Some((col, !first)),
                    _ => None,
                };
            }
            let color = if cur.is_some() || resp.hovered() { theme::text() } else { theme::text_dim() };
            let p = ui.painter();
            match col {
                0 => {
                    p.text(c, Align2::CENTER_CENTER, "App", theme::font(14.0), color);
                }
                1 => icons::paint(p, Icon::ArrowDown, Rect::from_center_size(c, vec2(14.0, 14.0)), color),
                _ => icons::paint(p, Icon::ArrowUp, Rect::from_center_size(c, vec2(14.0, 14.0)), color),
            }
            if let Some((_, asc)) = cur {
                // Small caret beside the label: points up for ascending.
                let (x, y) = (c.x + w / 2.0 - 4.0, c.y);
                let d = if asc { -3.0 } else { 3.0 };
                p.add(egui::Shape::convex_polygon(vec![pos2(x - 4.0, y + d), pos2(x + 4.0, y + d), pos2(x, y - d)], color, Stroke::NONE));
            }
        }
        let p = ui.painter();
        p.hline(panel.x_range(), top + 32.0, Stroke::new(1.0, theme::border()));

        let t = self.traffic.totals;
        let mut apps: Vec<_> =
            self.traffic.app_list.iter().map(|r| (Some((r.key.clone(), r.label.clone())), r.label.clone(), r.left, r.bytes * (1.0 - f64::from(r.up_share)), r.bytes * f64::from(r.up_share))).collect();
        if let Some((col, asc)) = self.traffic.app_sort {
            apps.sort_by(|a, b| {
                let o = match col {
                    0 => a.1.to_lowercase().cmp(&b.1.to_lowercase()),
                    1 => a.3.total_cmp(&b.3),
                    _ => a.4.total_cmp(&b.4),
                };
                if asc { o } else { o.reverse() }
            });
        }
        let all = std::iter::once((None, "All apps".to_owned(), Glyph::Window, t.down, t.up)).chain(apps);
        for (i, (app, label, glyph, down, up)) in all.enumerate() {
            let rr = Rect::from_min_size(pos2(panel.left(), top + 34.0 + 38.0 * i as f32), vec2(panel.width(), 38.0));
            let resp = ui.interact(rr, ui.scope_id().with(("filter_row", i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            let selected = filter.app.as_ref().map(|a| &a.0) == app.as_ref().map(|a| &a.0);
            let p = ui.painter();
            if selected {
                p.rect_filled(rr, 0, theme::accent().gamma_multiply(0.12));
            } else if resp.hovered() {
                p.rect_filled(rr, 0, theme::row_hover());
            }
            icons::glyph(p, glyph, Rect::from_center_size(pos2(rr.left() + 26.0, rr.center().y), vec2(22.0, 20.0)));
            let font = if i == 0 { theme::bold(15.0) } else { theme::font(15.0) };
            widgets::text_fit(p, pos2(rr.left() + 48.0, rr.center().y), Align2::LEFT_CENTER, &label, font.clone(), theme::text(), col_down - 70.0 - rr.left() - 48.0);
            p.text(pos2(col_down, rr.center().y), Align2::RIGHT_CENTER, fmt_bytes(down), font.clone(), theme::text());
            p.text(pos2(col_up, rr.center().y), Align2::RIGHT_CENTER, fmt_bytes(up), font, theme::text());
            if resp.clicked() {
                filter.app = app;
            }
        }

        if filter != self.traffic.filter {
            // The app list is only reloaded while no app is picked; refresh it for a new scope/direction.
            let reslice = filter.app.is_some() && (filter.scope, filter.dir) != (self.traffic.filter.scope, self.traffic.filter.dir);
            self.traffic.filter = filter;
            self.traffic.detail = None;
            self.traffic.sel = None;
            self.request_traffic(true, true, reslice);
        }
    }

    fn traffic_graph(&mut self, ui: &mut Ui, body: Rect) {
        let p = ui.painter().with_clip_rect(body);
        let axis_h = 40.0;
        let chart = Rect::from_min_max(pos2(body.left(), body.top()), pos2(body.right(), body.bottom() - axis_h));
        p.rect_filled(Rect::from_min_max(pos2(body.left(), chart.bottom()), body.max), 0, theme::surface());
        p.hline(body.x_range(), chart.bottom(), Stroke::new(1.0, theme::border()));

        let h = &self.traffic.history;
        let (wa, wb) = self.traffic.window;
        let n = h.samples.len();
        if n < 2 {
            return;
        }
        let i0 = ((wa * (n - 1) as f32).floor() as usize).min(n - 2);
        let i1 = ((wb * (n - 1) as f32).ceil() as usize).clamp(i0 + 1, n - 1);
        let slice = &h.samples[i0..=i1];

        // The newest bucket is still filling (and the database lags it), so drawing it makes the edge grow and flicker like a slow
        // download; leave it out and let the plot slide over it instead.
        let live = self.settings.mode == crate::settings::Mode::Live;
        // With 1 s buckets the database lags by about two of them, so the newest two read low and form a cliff at the edge.
        let lag = if h.step_minutes <= 1.0 / 30.0 { 2 } else { 1 };
        let cut = if live && i1 == n - 1 && slice.len() > lag + 2 { lag } else { 0 };
        let shown = &slice[..slice.len() - cut];
        // The 1 Minute view draws the curve continuously: it stops part-way between two known samples and that end slides along the
        // curve with the clock, instead of holding a value and swapping it for the real one when the second lands. The price is that
        // the picture trails the clock by `delay` seconds: the database lag plus the samples the smoothing at the end still leans on.
        let smooth = live && self.traffic.range == TimeRange::OneMinute && cut > 0 && shown.len() > 8;
        let delay = lag + 3;
        // Long ranges have several samples per drawn step; average them so a spike doesn't blink in and out as the plot scrolls.
        let k = (shown.len() as f32 / (body.width() / 2.0).max(1.0)).ceil().max(1.0) as usize;
        let mut down = box_blur(shown.iter().map(|s| s.down).collect(), k);
        let mut up = box_blur(shown.iter().map(|s| s.up).collect(), k);
        // Values still hidden past the drawn end shouldn't rescale the graph early.
        let seen = if smooth { down.len() - 2 } else { down.len() };
        let peak_of = |v: &[f32]| v[..seen].iter().copied().fold(0.0_f32, f32::max);
        let unit = 10.0 * 1024.0;
        let d_target = ((peak_of(&down) / unit).ceil().max(1.0)) * unit;
        // Upload usually runs far below download, so its half is sized from its own peak (never under a fifth of download's range)
        // and the centre line sits where the two ranges meet; both halves keep the same pixels per byte.
        let u_target = ((peak_of(&up) / unit).ceil().max(1.0) * unit).max(d_target * 0.2);
        // Ease each range so a new peak doesn't make the whole graph jump: exponentially, quicker up (so a burst isn't clipped for long)
        // than down (so the graph doesn't swell the moment a peak scrolls off). The label follows the eased value.
        let ease = |key: &str, target: f32| {
            let id = ui.scope_id().with(key);
            let dt = ui.input(|i| i.stable_dt).min(0.1);
            let cur = ui.ctx().data_mut(|d| *d.get_temp_mut_or(id, target));
            let tau = if target > cur { 0.45 } else { 2.5 };
            let next = if (target - cur).abs() < 1.0 { target } else { cur + (target - cur) * (1.0 - (-dt / tau).exp()) };
            ui.ctx().data_mut(|d| d.insert_temp(id, next));
            if next != target {
                ui.ctx().request_repaint();
            }
            next
        };
        let (y_max, u_max) = (ease("ymax", d_target), ease("ymax_up", u_target));
        let plot = Rect::from_min_max(pos2(chart.left() + 4.0, chart.top() + 86.0), pos2(chart.right() - 4.0, chart.bottom()));
        // Live history gains a column each time the wall clock crosses a bucket edge (buckets sit on multiples of their length);
        // slide the plot by how far into the current bucket we are so it scrolls smoothly. Demo data never advances.
        let frac = if live {
            let bucket_secs = (h.step_minutes * 60.0) as f64;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
            // Measured from the last bucket in `history`, so a reload landing after a bucket edge doesn't make the plot jump back.
            ((now - (self.traffic.loaded_at - self.traffic.loaded_at.rem_euclid(bucket_secs))) / bucket_secs).clamp(0.0, 2.0) as f32
        } else {
            0.0
        };
        let hit = plot;
        // The smooth view stops `delay` buckets short of the newest, so the plot spans that many columns fewer.
        let cols = (i1 - i0 - if smooth { delay } else { 0 }) as f32;
        let colw = plot.width() / cols;
        let plot = plot.translate(vec2(-frac * colw, 0.0));
        if live {
            // The plot scrolls under a pixel per second on long ranges, but the spikes are thinner than a pixel, so each sub-pixel
            // step re-draws them differently: repainted only every half pixel (about once a second at 30 minutes) the graph
            // pops in jerks like a slideshow. Repainting at 15 to 30 fps makes that drift gradual. Painting every vsync frame
            // kept the GPU busy and starved other apps (video players), so it is never faster than ~30 fps either.
            let px_per_sec = colw as f64 / (h.step_minutes as f64 * 60.0);
            let every = (0.5 / px_per_sec.max(1e-6)).clamp(0.033, 0.066);
            if px_per_sec >= 8.0 {
                // Fast scroll (1 minute): a 30 fps timer beats against the display and the plot moves 0, 1 or 2 px per frame. Paint with vsync.
                ui.ctx().request_repaint();
            } else {
                ui.ctx().request_repaint_after(std::time::Duration::from_secs_f64(every));
            }
        }

        // Y-axis scale label and guide line.
        let label = Rect::from_min_size(chart.min + vec2(16.0, 58.0), vec2(90.0, 26.0));
        p.text(label.left_center(), Align2::LEFT_CENTER, crate::util::fmt_rate((y_max / unit).round().max(1.0) as f64 * unit as f64), theme::font(16.0), theme::text_dim());
        p.hline((chart.left() + 100.0)..=(chart.right() - 14.0), label.center().y, Stroke::new(1.0, Color32::from_black_alpha(25)));

        // Hold the last complete value across the slide so the right edge never shows a gap.
        let m = down.len();
        if !smooth && cut > 0 {
            for (v, id) in [(&mut down, "hold_down"), (&mut up, "hold_up")] {
                // Ease the held value so a newly arrived second glides in instead of popping at the edge.
                let last = ui.ctx().animate_value_with_time(ui.scope_id().with(id), *v.last().unwrap_or(&0.0), 0.6);
                v.extend(std::iter::repeat_n(last, cut + 1));
            }
        }
        down.iter_mut().for_each(|v| *v /= y_max);
        up.iter_mut().for_each(|v| *v /= u_max);
        // The smooth curve ends `frac` of the way into the segment `delay` buckets before the newest, at the plot's right edge.
        let end = if smooth { ((m - 4) as f32 + frac) / (m - 1) as f32 } else { 1.0 };
        // Download rises above a centre line and upload hangs below it, both on the same scale.
        let mid = plot.top() + plot.height() * y_max / (y_max + u_max);
        let right = plot.left() + (down.len() - 1) as f32 * colw;
        let (curve_down, curve_up) = (Rect::from_min_max(plot.min, pos2(right, mid)), Rect::from_min_max(pos2(plot.left(), mid), pos2(right, plot.bottom())));
        p.hline(chart.left()..=chart.right(), mid, Stroke::new(1.0, theme::text_faint()));
        p.text(pos2(chart.left() + 16.0, mid + 14.0), Align2::LEFT_CENTER, crate::util::fmt_rate((u_max / unit).round().max(1.0) as f64 * unit as f64), theme::font(14.0), theme::text_faint());
        // The newest tenth fades out toward the right edge so columns entering there don't pop. One mesh per series, not strips.
        let fade_w = (chart.width() / 10.0).max((cut + 4) as f32 * colw);
        let fade = Some((chart.right() - fade_w, fade_w));
        widgets::area_soft_to(&p, curve_down, &down, theme::down(), false, fade, end);
        widgets::area_soft_to(&p, curve_up, &up, theme::up_chart(), true, fade, end);

        // Time axis.
        let t0 = h.start_minute + h.step_minutes * i0 as f32;
        let t1 = h.start_minute + h.step_minutes * (i1 - if smooth { delay } else { 0 }) as f32;
        let step = tick_step(t1 - t0, 14.0);
        let mut t = (t0 / step).ceil() * step;
        while t <= t1 {
            let x = plot.left() + (t - t0) / (t1 - t0) * plot.width();
            p.vline(x, chart.bottom()..=chart.bottom() + 5.0, Stroke::new(1.0, theme::text_dim()));
            p.text(pos2(x, chart.bottom() + 22.0), Align2::CENTER_CENTER, crate::util::fmt_clock_secs((t * 60.0).round() as i64, step < 1.0), theme::font(14.0), theme::text_dim());
            t += step;
        }

        // Drag highlights a span; right-drag pans, scroll zooms the time scale.
        let resp = ui.interact(hit, ui.scope_id().with("pan"), Sense::click_and_drag()).on_hover_cursor(egui::CursorIcon::Crosshair);
        // Alert pins: one per stored alert inside the visible span, click for details.
        if live {
            let bucket_secs = f64::from(h.step_minutes) * 60.0;
            let first = self.traffic.loaded_at - self.traffic.loaded_at.rem_euclid(bucket_secs) - (n - 1) as f64 * bucket_secs;
            let mut clicked = None;
            for a in self.log.alerts.iter().filter(|a| a.ts > 0 && !self.settings.graph_hidden.contains(&a.kind)) {
                let m = h.start_minute + ((a.ts as f64 - first) / 60.0) as f32;
                if m < t0 || m > t1 {
                    continue;
                }
                let x = plot.left() + (m - t0) / (t1 - t0) * plot.width();
                let tip = pos2(x, chart.bottom() - 4.0);
                let head = pos2(x, tip.y - 190.0);
                p.vline(x, head.y..=tip.y, Stroke::new(1.0, Color32::from_white_alpha(40)));
                let col = if a.anomaly {
                    Color32::from_rgb(0xb3, 0x7d, 0xff)
                } else if a.important {
                    Color32::from_rgb(0xff, 0xa6, 0x00)
                } else {
                    theme::text_dim()
                };
                // A hollow downward-pointing triangle with rounded corners, with the app's icon, or one for the alert kind, inside.
                const B: f32 = 61.5;
                let u = |x: f32, y: f32| head + vec2(x - 0.5, y - 0.5) * B;
                let corners = [(0.08, 0.14), (0.92, 0.14), (0.5, 0.96)];
                let mut triangle = Vec::new();
                for i in 0..3 {
                    let (prev, cur, next) = (corners[(i + 2) % 3], corners[i], corners[(i + 1) % 3]);
                    // Each corner is a curve between the points 0.16 along its two edges.
                    let along = |to: (f32, f32)| {
                        let (dx, dy) = (to.0 - cur.0, to.1 - cur.1);
                        let len = dx.hypot(dy);
                        (cur.0 + dx / len * 0.16, cur.1 + dy / len * 0.16)
                    };
                    let (a, b) = (along(prev), along(next));
                    for k in 0..=6 {
                        let t = k as f32 / 6.0;
                        let (wa, wc, wb) = ((1.0 - t) * (1.0 - t), 2.0 * t * (1.0 - t), t * t);
                        triangle.push(u(a.0 * wa + cur.0 * wc + b.0 * wb, a.1 * wa + cur.1 * wc + b.1 * wb));
                    }
                }
                p.add(egui::Shape::convex_polygon(triangle, theme::track(), Stroke::new(4.0, col)));
                let inner = Rect::from_center_size(head + vec2(0.0, -0.15 * B), vec2(0.29 * B, 0.29 * B));
                if a.icon != AppIcon::Generic {
                    icons::glyph(&p, Glyph::App(a.icon), inner);
                } else {
                    icons::paint(&p, if a.anomaly { Icon::Warning } else { kind_icon(&a.kind) }, inner, col);
                }
                let r = Rect::from_center_size(head, vec2(B * 0.74, B * 0.86));
                if ui.interact(r, ui.scope_id().with(("alertpin", a.id)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    clicked = Some((a.id, r.left_bottom() + vec2(-20.0, 4.0)));
                }
            }
            if clicked.is_some() {
                self.traffic.alert_popup = clicked;
            }
        }
        self.alert_popup(ui.ctx());

        let time_at = |x: f32| t0 + (x - plot.left()) / plot.width() * (t1 - t0);
        let x_at = |t: f32| plot.left() + (t - t0) / (t1 - t0) * plot.width();
        let mut sel_changed = false;
        if let (true, Some(pos), Some(origin)) = (resp.dragged_by(egui::PointerButton::Primary), resp.interact_pointer_pos(), ui.input(|i| i.pointer.press_origin())) {
            let (a, b) = (time_at(origin.x).clamp(t0, t1), time_at(pos.x).clamp(t0, t1));
            self.traffic.sel = Some((a.min(b), a.max(b)));
            sel_changed = true;
        } else if resp.secondary_clicked() {
            self.traffic.sel = None;
            self.traffic.sel_popup = None;
        }
        if let Some((sa, sb)) = self.traffic.sel {
            let (xa, xb) = (x_at(sa).clamp(plot.left(), plot.right()), x_at(sb).clamp(plot.left(), plot.right()));
            p.rect_filled(Rect::from_min_max(pos2(xa, chart.top()), pos2(xb, chart.bottom())), 0, Color32::from_rgba_unmultiplied(40, 160, 100, 45));
            let mut x = chart.left() + 130.0;
            let mut open = None;
            for (i, rows) in [&self.traffic.sel_data.apps, &self.traffic.sel_data.hosts].into_iter().enumerate() {
                let Some(top) = rows.first() else { continue };
                let text = if rows.len() > 1 { format!("{}  +{} more", top.label, rows.len() - 1) } else { top.label.clone() };
                let g = p.layout_no_wrap(text, theme::font(14.5), theme::text_dim());
                let r = Rect::from_min_size(pos2(x, label.center().y - 14.0), vec2(g.size().x + 44.0, 28.0));
                p.rect_filled(r, 4, theme::ctl());
                icons::glyph(&p, top.left, Rect::from_center_size(pos2(r.left() + 18.0, r.center().y), vec2(22.0, 20.0)));
                p.galley(pos2(r.left() + 34.0, r.center().y - g.size().y / 2.0), g, theme::text_dim());
                if ui.interact(r, ui.scope_id().with(("selitem", i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    open = Some((i, r.left_bottom() + vec2(0.0, 4.0)));
                }
                x = r.right() + 12.0;
            }
            if open.is_some() {
                self.traffic.sel_popup = open;
            }
        }
        if sel_changed {
            self.reload_sel();
        }
        self.sel_popup(ui.ctx());
        self.traffic_detail(ui.ctx());

        let (wa, wb) = self.traffic.window;
        let w = wb - wa;
        let (mut nw, mut na) = (w, wa);
        if resp.dragged_by(egui::PointerButton::Secondary) {
            na = wa - resp.drag_delta().x / plot.width() * w;
        }
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        if let (true, Some(pos)) = (resp.hovered() && scroll != 0.0, resp.hover_pos()) {
            nw = (w * (1.0 - scroll * 0.002)).clamp(0.02, 1.0);
            let f = (pos.x - plot.left()) / plot.width();
            na = wa + f * (w - nw);
        }
        na = na.clamp(0.0, 1.0 - nw);
        if (na, na + nw) != (wa, wb) {
            self.traffic.window = (na, na + nw);
            self.reload_window();
        }
    }

    /// Details of the alert behind a clicked graph pin.
    fn alert_popup(&mut self, ctx: &egui::Context) {
        let Some((id, pos)) = self.traffic.alert_popup else { return };
        let Some(a) = self.log.alerts.iter().find(|a| a.id == id) else { return };
        let mut normal = false;
        let area = egui::Area::new(egui::Id::unique("alert_popup")).order(egui::Order::Foreground).fixed_pos(pos).show(ctx, |ui| {
            egui::Frame::popup(ui.style()).inner_margin(14).show(ui, |ui| {
                ui.set_width(380.0);
                ui.label(egui::RichText::new(&a.kind).font(theme::bold(16.0)).color(theme::text()));
                ui.label(egui::RichText::new(format!("{} {}", a.day, a.time)).font(theme::font(14.0)).color(theme::text_dim()));
                ui.add_space(6.0);
                ui.label(egui::RichText::new(format!("{} {} {}", a.app, a.text, a.target)).font(theme::font(14.5)).color(theme::text()));
                if a.anomaly {
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("Usual for this program? Mark it normal and the baseline learns it.").font(theme::font(13.5)).color(theme::text_dim()));
                    normal = crate::widgets::pill_button(ui, None, "Mark as normal", false, 0.0).clicked();
                }
            });
        });
        if normal {
            self.run_bg(move |b| {
                b.mark_alert_normal(id);
                Ok(String::new())
            });
            self.traffic.alert_popup = None;
            return;
        }
        let outside = ctx.input(|i| i.pointer.any_pressed() && i.pointer.interact_pos().is_some_and(|p| !area.response.rect.contains(p)));
        if outside || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.traffic.alert_popup = None;
        }
    }

    /// List behind a highlight-strip item: every app or host in the highlighted span.
    fn sel_popup(&mut self, ctx: &egui::Context) {
        let Some((kind, pos)) = self.traffic.sel_popup else { return };
        let data = &self.traffic.sel_data;
        let rows = if kind == 0 { data.apps.clone() } else { data.hosts.clone() };
        let mut clicked: Option<(String, Pos2)> = None;
        let (y, list_h) = popup_fit(ctx.content_rect(), pos.y, 45.0, 32.0 * rows.len() as f32);
        let pos = pos2(pos.x, y);
        let area = egui::Area::new(egui::Id::unique("sel_popup")).order(egui::Order::Foreground).fixed_pos(pos).show(ctx, |ui| {
            egui::Frame::popup(ui.style()).inner_margin(0).show(ui, |ui| {
                ui.set_width(420.0);
                ui.horizontal(|ui| {
                    ui.set_height(32.0);
                    ui.add_space(14.0);
                    ui.label(egui::RichText::new(if kind == 0 { "App" } else { "Host" }).font(theme::bold(14.0)).color(theme::text()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(14.0);
                        for h in ["Upload", "Download"] {
                            ui.add_sized([70.0, 20.0], egui::Label::new(egui::RichText::new(h).font(theme::font(14.0)).color(theme::text_dim())));
                        }
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical().max_height(list_h).min_scrolled_height(list_h).show(ui, |ui| {
                    for (ri, r) in rows.iter().enumerate() {
                        let hover_bg = ui.painter().add(egui::Shape::Noop);
                        let row = ui.horizontal(|ui| {
                            ui.set_height(32.0);
                            ui.add_space(14.0);
                            let (gr, _) = ui.allocate_exact_size(vec2(22.0, 20.0), Sense::hover());
                            icons::glyph(ui.painter(), r.left, gr);
                            let (lr, _) = ui.allocate_exact_size(vec2(220.0, 20.0), Sense::hover());
                            widgets::text_fit(ui.painter(), lr.left_center(), Align2::LEFT_CENTER, &r.label, theme::font(14.5), theme::text(), 220.0);
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.add_space(14.0);
                                let up = r.bytes * f64::from(r.up_share);
                                for v in [up, r.bytes - up] {
                                    ui.add_sized([70.0, 20.0], egui::Label::new(egui::RichText::new(fmt_bytes(v)).font(theme::font(14.5)).color(theme::text())));
                                }
                            });
                        });
                        if !r.key.is_empty() {
                            let resp = ui.interact(row.response.rect, ui.scope_id().with(("sel_row", ri)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                            if resp.hovered() {
                                ui.painter().set(hover_bg, egui::Shape::rect_filled(row.response.rect, 0, theme::row_hover()));
                            }
                            if resp.clicked() {
                                clicked = Some((r.key.clone(), row.response.rect.left_bottom()));
                            }
                        }
                    }
                });
            });
        });
        if let (Some((key, at)), Some(w)) = (clicked, self.sel_window()) {
            let kind = if kind == 0 { UsageKind::App } else { UsageKind::Host };
            self.traffic.detail = self.backend.usage_detail(self.traffic.range, w, kind, &key).map(|d| (at, d));
            self.traffic.detail_back.clear();
            self.traffic.sel_popup = None;
            return;
        }
        let outside = ctx.input(|i| i.pointer.any_pressed() && i.pointer.interact_pos().is_some_and(|p| !area.response.rect.contains(p)));
        if outside || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.traffic.sel_popup = None;
        }
    }

    /// Writes the four usage lists to a CSV the user picks (opens in any spreadsheet).
    fn export_usage(&mut self) {
        // Quoted so labels containing commas or quotes stay one cell.
        let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let name = format!("RustWarden usage {}.csv", self.traffic.range.label());
        let Some(path) = crate::sys::save_dialog("Export usage", &name, "CSV file", "csv") else { return };
        let b = &self.traffic.breakdown;
        let mut csv = String::from("\u{feff}List,Name,Downloaded (bytes),Uploaded (bytes),Total (bytes)\r\n");
        for (list, rows) in [("Apps", &b.apps), ("Hosts", &b.hosts), ("Traffic Type", &b.traffic_types), ("Countries", &b.countries)] {
            for r in rows {
                let up = r.bytes * f64::from(r.up_share);
                csv += &format!("{list},{},{:.0},{up:.0},{:.0}\r\n", q(&r.label), r.bytes - up, r.bytes);
            }
        }
        match std::fs::write(&path, csv) {
            Ok(()) => self.notify(&format!("Exported to {}", path.display())),
            Err(e) => self.notify(&format!("Couldn't export: {e}")),
        }
    }

    /// Saves stored history as CSV, or as JSON when the chosen name ends in .json. Reading and writing run on a thread.
    pub(crate) fn export_history(&mut self, ctx: &egui::Context, data: HistoryData, name: &str, days: Option<u32>) {
        let Some(path) = crate::sys::save_dialog("Export history", name, "CSV file", "csv") else { return };
        let format = if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("json")) { HistoryFormat::Json } else { HistoryFormat::Csv };
        let (slot, backend, ctx) = (self.history_result.clone(), self.backend.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = backend.export_history(data, format, days).and_then(|text| std::fs::write(&path, text).map(|()| path.clone()).map_err(|e| e.to_string()));
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
            ctx.request_repaint();
        });
    }

    fn traffic_lists(&mut self, ui: &mut Ui, body: Rect) {
        let p = ui.painter().with_clip_rect(body);
        p.rect_filled(body, 0, theme::surface());
        let b = self.traffic.breakdown.clone();
        let columns: [(&str, &Vec<UsageRow>); 4] = [("Apps", &b.apps), ("Hosts", &b.hosts), ("Traffic Type", &b.traffic_types), ("Countries", &b.countries)];
        let col_w = body.width() / 4.0;
        let mut clicked: Option<(usize, String, Pos2)> = None;
        for (ci, (title, rows)) in columns.iter().enumerate() {
            let x0 = body.left() + col_w * ci as f32;
            let inner = Rect::from_min_max(pos2(x0, body.top()), pos2(x0 + col_w, body.bottom()));
            if ci > 0 {
                p.vline(x0, body.y_range(), Stroke::new(1.0, theme::border()));
            }
            // Header: name on the left, Download / Upload arrows on the right. First click sorts (A-Z / largest first), second reverses, third resets.
            // Each figure column is as wide as its widest value (never under the arrow), so large sizes can't run into each other.
            let widest = |f: &dyn Fn(&UsageRow) -> f64| rows.iter().map(|r| p.layout_no_wrap(fmt_bytes(f(r)), theme::font(14.5), theme::text()).size().x).fold(0.0, f32::max);
            let up_w = widest(&|r| r.bytes * f64::from(r.up_share)).max(38.0);
            let down_w = widest(&|r| r.bytes - r.bytes * f64::from(r.up_share)).max(38.0);
            let col_up = inner.right() - 14.0;
            let col_down = col_up - up_w - 14.0;
            let down_span = down_w + 14.0;
            p.hline(inner.x_range(), body.top() + 40.0, Stroke::new(1.0, theme::border()));
            let heads = [(0u8, pos2(inner.left() + 14.0 + 40.0, body.top() + 20.0), 80.0), (1, pos2(col_down - 20.0, body.top() + 20.0), 40.0), (2, pos2(col_up - 20.0, body.top() + 20.0), 40.0)];
            for (col, c, w) in heads {
                let hr = Rect::from_center_size(c, vec2(w, 32.0));
                let resp = ui.interact(hr, ui.scope_id().with(("list_head", ci, col)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                let cur = self.traffic.list_sort[ci].filter(|s| s.0 == col);
                if resp.clicked() {
                    let first = col == 0;
                    self.traffic.list_sort[ci] = match cur {
                        None => Some((col, first)),
                        Some((_, asc)) if asc == first => Some((col, !first)),
                        _ => None,
                    };
                }
                let color = if cur.is_some() || resp.hovered() { theme::text() } else { theme::text_dim() };
                match col {
                    0 => {
                        p.text(pos2(inner.left() + 14.0, c.y), Align2::LEFT_CENTER, *title, theme::font(15.0), color);
                    }
                    1 => icons::paint(&p, Icon::ArrowDown, Rect::from_center_size(c, vec2(14.0, 14.0)), color),
                    _ => icons::paint(&p, Icon::ArrowUp, Rect::from_center_size(c, vec2(14.0, 14.0)), color),
                }
                if let Some((_, asc)) = cur {
                    let (x, y) = if col == 0 { (inner.left() + 14.0 + p.layout_no_wrap((*title).to_owned(), theme::font(15.0), color).size().x + 10.0, c.y) } else { (c.x + 14.0, c.y) };
                    let d = if asc { -3.0 } else { 3.0 };
                    p.add(egui::Shape::convex_polygon(vec![pos2(x - 4.0, y + d), pos2(x + 4.0, y + d), pos2(x, y - d)], color, Stroke::NONE));
                }
            }

            if rows.is_empty() {
                let note =
                    if self.caps.live && !self.caps.per_app_traffic { "Not available without administrator rights. Use \"Restart as administrator\"." } else { "No traffic recorded in this period." };
                let g = p.layout(note.to_owned(), theme::font(14.5), theme::text_dim(), inner.width() - 28.0);
                p.galley(pos2(inner.left() + 14.0, body.top() + 56.0), g, theme::text_dim());
            }
            if ci == 3 && self.caps.live && !self.caps.geo_db {
                let g = p.layout("No GeoIP database: countries show as Unknown. See Settings for how to add one.".to_owned(), theme::font(13.0), theme::text_dim(), inner.width() - 28.0);
                p.galley(pos2(inner.left() + 14.0, body.bottom() - 16.0 - g.size().y), g, theme::text_dim());
            }
            let mut sorted: Vec<&UsageRow> = rows.iter().collect();
            if let Some((col, asc)) = self.traffic.list_sort[ci] {
                let up = |r: &UsageRow| r.bytes * f64::from(r.up_share);
                sorted.sort_by(|a, b| {
                    let o = match col {
                        0 => a.label.to_lowercase().cmp(&b.label.to_lowercase()),
                        1 => (a.bytes - up(a)).total_cmp(&(b.bytes - up(b))),
                        _ => up(a).total_cmp(&up(b)),
                    };
                    if asc { o } else { o.reverse() }
                });
            }
            let mut y = body.top() + 41.0;
            for (ri, row) in sorted.into_iter().enumerate() {
                let rr = Rect::from_min_size(pos2(inner.left(), y), vec2(inner.width(), 36.0));
                let resp = ui.interact(rr, ui.scope_id().with(("usage", ci, ri)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                let bg = if resp.hovered() {
                    theme::row_hover()
                } else if ri % 2 == 1 {
                    theme::row_alt()
                } else {
                    theme::surface()
                };
                p.rect_filled(rr, 0, bg);
                if resp.clicked() {
                    clicked = Some((ci, row.key.clone(), rr.left_bottom()));
                }
                let cy = rr.center().y;
                icons::glyph(&p, row.left, Rect::from_center_size(pos2(inner.left() + 25.0, cy), vec2(22.0, 20.0)));
                let up = row.bytes * f64::from(row.up_share);
                let glyph_w = if row.right.is_some() { 30.0 } else { 0.0 };
                if let Some(g) = row.right {
                    icons::glyph(&p, g, Rect::from_center_size(pos2(col_down - down_span - 11.0, cy), vec2(22.0, 20.0)));
                }
                widgets::text_fit(&p, pos2(inner.left() + 46.0, cy), Align2::LEFT_CENTER, &row.label, theme::font(14.5), theme::text(), col_down - down_span - glyph_w - inner.left() - 46.0);
                p.text(pos2(col_down, cy), Align2::RIGHT_CENTER, fmt_bytes(row.bytes - up), theme::font(14.5), theme::text());
                p.text(pos2(col_up, cy), Align2::RIGHT_CENTER, fmt_bytes(up), theme::font(14.5), theme::text());
                y += 36.0;
            }
        }
        if let Some((ci, key, pos)) = clicked {
            let kind = [UsageKind::App, UsageKind::Host, UsageKind::TrafficType, UsageKind::Country][ci];
            self.traffic.detail = self.backend.usage_detail(self.traffic.range, self.traffic.window, kind, &key).map(|d| (pos, d));
            self.traffic.detail_back.clear();
        }
        self.traffic_detail(ui.ctx());
    }

    /// The popup for a clicked usage row: what it is, and who or what it was talking to.
    pub(crate) fn traffic_detail(&mut self, ctx: &egui::Context) {
        let Some((pos, detail)) = self.traffic.detail.clone() else { return };
        let width = 480.0;
        let screen = ctx.content_rect();
        let overhead = 44.0 + 30.0 + 16.0 + if detail.facts.is_empty() { 0.0 } else { 18.0 + 26.0 * detail.facts.len() as f32 };
        let (y, list_h) = popup_fit(screen, pos.y, overhead, (36.0 * detail.rows.len() as f32).max(60.0));
        let pos = pos2(pos.x.min(screen.right() - width - 12.0).max(screen.left() + 8.0), y);
        let mut go_back = false;
        let mut open: Option<(UsageKind, String)> = None;
        let mut whois: Option<String> = None;
        let can_back = !self.traffic.detail_back.is_empty();
        let area = egui::Area::new(egui::Id::unique("usage_detail")).order(egui::Order::Foreground).fixed_pos(pos).show(ctx, |ui| {
            egui::Frame::popup(ui.style()).inner_margin(0).show(ui, |ui| {
                ui.set_width(width);
                ui.spacing_mut().item_spacing = vec2(8.0, 0.0);
                let glyph_slot = |ui: &mut Ui, g: Glyph| {
                    let (r, _) = ui.allocate_exact_size(vec2(22.0, 20.0), Sense::hover());
                    icons::glyph(ui.painter(), g, r);
                };
                ui.horizontal(|ui| {
                    ui.set_height(44.0);
                    ui.add_space(14.0);
                    if can_back {
                        let back = ui.add(egui::Button::new(egui::RichText::new("‹").font(theme::bold(22.0)).color(theme::text_dim())).frame(false));
                        go_back = back.on_hover_cursor(egui::CursorIcon::PointingHand).clicked();
                    }
                    glyph_slot(ui, detail.glyph);
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(&detail.title).font(theme::bold(15.0)).color(theme::text()));
                });
                ui.separator();
                if !detail.facts.is_empty() {
                    ui.add_space(8.0);
                }
                for (k, v) in &detail.facts {
                    ui.horizontal(|ui| {
                        ui.set_height(26.0);
                        ui.add_space(14.0);
                        let (kr, _) = ui.allocate_exact_size(vec2(72.0, 20.0), Sense::hover());
                        ui.painter().text(kr.left_center(), Align2::LEFT_CENTER, k, theme::font(14.0), theme::text_dim());
                        ui.label(egui::RichText::new(v).font(theme::font(14.0)).color(theme::text()));
                        if k == "IP" && widgets::whois_icon(ui, ui.cursor().left_center() + vec2(10.0, 0.0), "detail_ip") {
                            whois = Some(v.clone());
                        }
                    });
                }
                if !detail.facts.is_empty() {
                    ui.add_space(10.0);
                }
                egui::Frame::NONE.fill(theme::panel_bg()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.set_height(30.0);
                        ui.add_space(14.0);
                        ui.label(egui::RichText::new(&detail.heading).font(theme::font(14.0)).color(theme::text_dim()));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_space(14.0);
                            ui.add_sized([70.0, 20.0], egui::Label::new(egui::RichText::new("Upload").font(theme::font(14.0)).color(theme::text_dim())));
                            ui.add_sized([70.0, 20.0], egui::Label::new(egui::RichText::new("Download").font(theme::font(14.0)).color(theme::text_dim())));
                        });
                    });
                });
                egui::ScrollArea::vertical().max_height(list_h).min_scrolled_height(list_h).show(ui, |ui| {
                    for (ri, r) in detail.rows.iter().enumerate() {
                        let hover_bg = ui.painter().add(egui::Shape::Noop);
                        let row = ui.horizontal(|ui| {
                            ui.set_height(36.0);
                            ui.add_space(14.0);
                            glyph_slot(ui, r.left);
                            let label_w = if r.right.is_some() { 200.0 } else { 270.0 };
                            let (lr, _) = ui.allocate_exact_size(vec2(label_w, 20.0), Sense::hover());
                            widgets::text_fit(ui.painter(), lr.left_center(), Align2::LEFT_CENTER, &r.label, theme::font(14.5), theme::text(), label_w);
                            if let Some(g) = r.right {
                                glyph_slot(ui, g);
                                ui.label(egui::RichText::new(&r.extra).font(theme::font(14.0)).color(theme::text_dim()));
                                ui.add_space(8.0);
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.add_space(14.0);
                                ui.add_sized([70.0, 20.0], egui::Label::new(egui::RichText::new(fmt_bytes(r.up)).font(theme::font(14.5)).color(theme::text())));
                                ui.add_sized([70.0, 20.0], egui::Label::new(egui::RichText::new(fmt_bytes(r.down)).font(theme::font(14.5)).color(theme::text())));
                            });
                        });
                        if let Some(t) = &r.target {
                            let resp = ui.interact(row.response.rect, ui.scope_id().with(("detail_row", ri)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                            if resp.hovered() {
                                ui.painter().set(hover_bg, egui::Shape::rect_filled(row.response.rect, 0, theme::row_hover()));
                            }
                            if resp.clicked() {
                                open = Some(t.clone());
                            }
                        }
                    }
                    if detail.rows.is_empty() {
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("  Nothing recorded for this in the selected period.").font(theme::font(14.0)).color(theme::text_dim()));
                        ui.add_space(10.0);
                    }
                });
            });
        });
        if let Some(ip) = whois {
            self.open_whois(ctx, &ip);
        }
        if go_back {
            if let Some(prev) = self.traffic.detail_back.pop() {
                self.traffic.detail = Some((pos, prev));
            }
            return;
        }
        if let Some((kind, key)) = open {
            if let Some(next) = self.backend.usage_detail(self.traffic.range, self.traffic.window, kind, &key) {
                self.traffic.detail_back.push(detail);
                self.traffic.detail = Some((pos, next));
            }
            return;
        }
        // Click outside or Esc closes it.
        let outside = ctx.input(|i| i.pointer.any_pressed() && i.pointer.interact_pos().is_some_and(|p| !area.response.rect.contains(p)));
        if outside || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.traffic.detail = None;
        }
    }

    /// Only the graph view needs the totals and timeline; the others always show the compact bar.
    pub(crate) fn footer_collapsed(&self) -> bool {
        self.traffic.view != 0 || self.settings.traffic_footer_collapsed
    }

    pub(crate) fn traffic_footer(&mut self, ui: &mut Ui) {
        // The stats and the timeline sit on one raised card inside the panel.
        let outer = ui.max_rect().shrink2(vec2(12.0, 8.0));
        let p = ui.painter().clone();
        let t = self.traffic.totals;
        let graph = self.traffic.view == 0;
        let folded = self.footer_collapsed();
        // With room to spare, the busiest apps get a card of their own on the right.
        let apps_room = !folded && outer.width() > 1180.0;
        let (rect, apps_card) = if apps_room {
            (Rect::from_min_max(outer.min, pos2(outer.right() - 312.0, outer.bottom())), Some(Rect::from_min_max(pos2(outer.right() - 300.0, outer.top()), outer.max)))
        } else {
            (outer, None)
        };
        for r in std::iter::once(rect).chain(apps_card) {
            p.rect_filled(r, 8, theme::card());
            p.rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::epaint::StrokeKind::Inside);
        }

        // The fold arrow: down hides the card, up brings it back. Other views have no use for the card, so they show the bar without it.
        if graph {
            let btn = Rect::from_center_size(pos2(rect.right() - 20.0, if folded { rect.center().y } else { rect.top() + 20.0 }), vec2(28.0, 24.0));
            let resp = ui.interact(btn, ui.scope_id().with("footer_fold"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(if folded {
                "Show totals and timeline"
            } else {
                "Hide totals and timeline"
            });
            let ink = if resp.hovered() { theme::text() } else { theme::text_dim() };
            let (c, d) = (btn.center(), if folded { -3.0 } else { 3.0 });
            p.line_segment([c + vec2(-6.0, -d), c + vec2(0.0, d)], Stroke::new(1.8, ink));
            p.line_segment([c + vec2(0.0, d), c + vec2(6.0, -d)], Stroke::new(1.8, ink));
            if resp.clicked() {
                self.settings.traffic_footer_collapsed = !self.settings.traffic_footer_collapsed;
                if let Err(e) = self.settings.save() {
                    self.notify(&format!("Couldn't save settings: {e}"));
                }
            }
        }
        if rect.height() < 100.0 {
            // Compact bar (also while it slides): just the totals.
            let text = format!("Down {}   Up {}   Total {}", fmt_bytes(t.down), fmt_bytes(t.up), fmt_bytes(t.down + t.up));
            widgets::text_fit(&p, pos2(rect.left() + 20.0, rect.center().y), Align2::LEFT_CENTER, &text, theme::font(14.0), theme::text_dim(), (rect.width() - 80.0).max(0.0));
            return;
        }
        let x0 = rect.left() + 44.0;
        let y = rect.top() + 4.0;

        // Download, upload and total as three stat blocks: label, size, rate, and a sparkline of the visible history.
        let total = t.down + t.up;
        for (i, (name, bytes, rate, color)) in [("Download", t.down, t.down_rate, theme::down()), ("Upload", t.up, t.up_rate, theme::up())].into_iter().enumerate() {
            let bx = x0 + 140.0 * i as f32;
            icons::paint(&p, if i == 0 { Icon::ArrowDown } else { Icon::ArrowUp }, Rect::from_center_size(pos2(bx + 7.0, y + 34.0), vec2(14.0, 14.0)), color);
            p.text(pos2(bx + 22.0, y + 34.0), Align2::LEFT_CENTER, name, theme::font(13.5), theme::text_dim());
            p.text(pos2(bx, y + 58.0), Align2::LEFT_CENTER, fmt_bytes(bytes), theme::bold(19.0), theme::text());
            p.text(pos2(bx, y + 80.0), Align2::LEFT_CENTER, fmt_rate(rate), theme::font(14.0), theme::text_dim());
            let series: Vec<f32> = self.traffic.history.samples.iter().map(|s| if i == 0 { s.down } else { s.up }).collect();
            let peak = series.iter().copied().fold(1.0, f32::max);
            let series: Vec<f32> = series.iter().map(|v| v / peak).collect();
            widgets::area_soft_to(&p, Rect::from_min_size(pos2(bx, y + 92.0), vec2(120.0, 18.0)), &series, color, false, None, 1.0);
        }
        let bx = x0 + 280.0;
        p.circle_filled(pos2(bx + 7.0, y + 34.0), 4.0, theme::text_dim());
        p.text(pos2(bx + 22.0, y + 34.0), Align2::LEFT_CENTER, "Total", theme::font(13.5), theme::text_dim());
        p.text(pos2(bx, y + 58.0), Align2::LEFT_CENTER, fmt_bytes(total), theme::bold(19.0), theme::text());
        let down_pct = if total > 0.0 { t.down / total * 100.0 } else { 0.0 };
        p.text(pos2(bx, y + 80.0), Align2::LEFT_CENTER, format!("{down_pct:.0}% down, {:.0}% up", 100.0 - down_pct), theme::font(14.0), theme::text_dim());
        widgets::usage_bar(&p, Rect::from_min_size(pos2(bx, y + 98.0), vec2(120.0, 6.0)), 1.0, if total > 0.0 { (t.up / total) as f32 } else { 0.0 });
        p.vline(x0 + 420.0, (y + 22.0)..=(y + 100.0), Stroke::new(1.0, theme::border()));

        // WAN / LAN: one split bar and a legend.
        let wx = x0 + 446.0;
        let bar_right = if apps_room { (wx + 360.0).min(rect.right() - 50.0) } else { rect.right() - 50.0 };
        let bar = Rect::from_min_max(pos2(wx, y + 48.0), pos2(bar_right.max(wx + 40.0), y + 56.0));
        let wan_share = (t.wan / (t.wan + t.lan).max(1.0)) as f32;
        let (wan_col, lan_col) = (theme::accent(), theme::text_faint());
        p.rect_filled(bar, 4, lan_col);
        p.rect_filled(Rect::from_min_max(bar.min, pos2(bar.left() + bar.width() * wan_share, bar.bottom())), 4, wan_col);
        for (i, (name, bytes, col)) in [("WAN", t.wan, wan_col), ("LAN", t.lan, lan_col)].into_iter().enumerate() {
            let lx = wx + 150.0 * i as f32;
            p.circle_filled(pos2(lx + 5.0, y + 80.0), 4.0, col);
            p.text(pos2(lx + 16.0, y + 80.0), Align2::LEFT_CENTER, name, theme::font(14.0), theme::text_dim());
            p.text(pos2(lx + 56.0, y + 80.0), Align2::LEFT_CENTER, fmt_bytes(bytes), theme::bold(15.0), theme::text());
        }
        if let Some(card) = apps_card {
            p.text(card.left_top() + vec2(20.0, 24.0), Align2::LEFT_CENTER, "TOP APPS", theme::bold(11.5), theme::text_dim());
            let apps = &self.traffic.breakdown.apps;
            let biggest = apps.first().map_or(1.0, |a| a.bytes).max(1.0);
            for (i, row) in apps.iter().take(6).enumerate() {
                let cy = card.top() + 54.0 + 28.0 * i as f32;
                icons::glyph(&p, row.left, Rect::from_center_size(pos2(card.left() + 28.0, cy), vec2(16.0, 16.0)));
                widgets::text_fit(&p, pos2(card.left() + 44.0, cy), Align2::LEFT_CENTER, &row.label, theme::font(13.0), theme::text(), 100.0);
                widgets::usage_bar(&p, Rect::from_min_max(pos2(card.left() + 152.0, cy - 2.0), pos2(card.left() + 212.0, cy + 2.0)), (row.bytes / biggest) as f32, row.up_share);
                p.text(pos2(card.right() - 16.0, cy), Align2::RIGHT_CENTER, fmt_bytes(row.bytes), theme::font(13.0), theme::text_dim());
            }
        }

        // Timeline scrubber.
        // A brush over the whole history: the chosen span stays clear, the rest is dimmed, and square grips sit on its edges.
        let band = Rect::from_min_max(pos2(rect.left() + 24.0, y + 122.0), pos2(rect.right() - 30.0, y + 162.0));
        let (wa, wb) = self.traffic.window;
        let xa = band.left() + wa * band.width();
        let xb = band.left() + wb * band.width();
        p.rect_filled(band, 3, theme::panel_bg());
        let peak = self.traffic.history.samples.iter().map(|s| s.down.max(s.up)).fold(1.0, f32::max);
        for (pick_down, color) in [(true, theme::down()), (false, theme::up_chart())] {
            let mini: Vec<f32> = self.traffic.history.samples.iter().map(|s| (if pick_down { s.down } else { s.up } / peak).sqrt() * 0.9).collect();
            widgets::area_soft_to(&p, band.shrink2(vec2(0.0, 2.0)), &mini, color, false, None, 1.0);
        }
        let (dim_l, dim_r) = (Rect::from_min_max(band.min, pos2(xa, band.bottom())), Rect::from_min_max(pos2(xb, band.top()), band.max));
        p.rect_filled(dim_l, 0, theme::track());
        p.rect_filled(dim_r, 0, theme::track());
        p.rect_stroke(band, 3, Stroke::new(1.0, theme::card_edge()), egui::epaint::StrokeKind::Inside);
        p.rect_stroke(Rect::from_min_max(pos2(xa, band.top()), pos2(xb, band.bottom())), 0, Stroke::new(1.5, theme::accent()), egui::epaint::StrokeKind::Inside);

        let h = &self.traffic.history;
        let span = h.span_minutes();
        let step = tick_step(span, 9.0);
        let mut tm = (h.start_minute / step).ceil() * step;
        while tm <= h.start_minute + span {
            let x = band.left() + (tm - h.start_minute) / span * band.width();
            p.text(pos2(x, band.bottom() + 16.0), Align2::CENTER_CENTER, fmt_clock(tm), theme::font(13.5), theme::text_dim());
            tm += step;
        }

        let mut new_window = self.traffic.window;
        // Dragging the selected region slides the window without resizing it.
        let sel = ui.interact(Rect::from_min_max(pos2(xa, band.top()), pos2(xb, band.bottom())), ui.scope_id().with("slide"), Sense::drag()).on_hover_cursor(egui::CursorIcon::Grab);
        if sel.dragged() {
            let s = (sel.drag_delta().x / band.width()).clamp(-wa, 1.0 - wb);
            new_window = (wa + s, wb + s);
        }
        for (idx, hx) in [xa, xb].into_iter().enumerate() {
            let hr = Rect::from_center_size(pos2(hx, band.center().y), vec2(28.0, band.height()));
            let resp = ui.interact(hr, ui.scope_id().with(("handle", idx)), Sense::drag()).on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
            if let (true, Some(pos)) = (resp.dragged(), resp.interact_pointer_pos()) {
                let f = ((pos.x - band.left()) / band.width()).clamp(0.0, 1.0);
                if idx == 0 {
                    new_window.0 = f.min(new_window.1 - 0.02);
                } else {
                    new_window.1 = f.max(new_window.0 + 0.02);
                }
            }
            let c = pos2(hx, band.center().y);
            p.circle_filled(c + vec2(0.0, 1.0), 11.0, Color32::from_black_alpha(25));
            p.circle_filled(c, 11.0, theme::WHITE);
            p.circle_stroke(c, 11.0, Stroke::new(1.0, theme::border()));
        }
        if new_window != self.traffic.window {
            self.traffic.window = new_window;
            self.reload_window();
        }
    }
}

/// Top y and list height for a popup that wants `content` px of rows: as tall as the content
/// (up to 480), moved up if it would run off the bottom of the screen.
fn popup_fit(screen: Rect, y: f32, overhead: f32, content: f32) -> (f32, f32) {
    let h = content.min(480.0).min(screen.height() - overhead - 24.0);
    (y.min(screen.bottom() - overhead - h - 12.0).max(screen.top() + 8.0), h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::alerts::AlertKind;

    #[test]
    fn every_alert_kind_gets_its_own_pin_icon() {
        for k in AlertKind::ALL {
            let label = AlertKind::label_for_key(k.key());
            assert!(kind_icon(label) != Icon::Bell, "{label} has no pin icon");
        }
    }
}
