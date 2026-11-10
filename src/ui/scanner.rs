use super::row_in;
use crate::app::{Dialog, RustWarden};
use crate::data::*;
use crate::icons::{self, Icon};
use crate::theme;
use crate::widgets;
use egui::{Align2, Color32, Rect, Sense, Stroke, Ui, UiBuilder, pos2, vec2};

/// Column borders: dot, Type, Home Assistant (hidden unless enabled), then the text columns.
pub(crate) const DEFAULT_COLS: [f32; 13] = [0.0, 0.03, 0.08, 0.13, 0.206, 0.376, 0.423, 0.499, 0.603, 0.707, 0.811, 0.868, 1.0];

/// Service name and, for web interfaces, the URL scheme to open it with.
pub(crate) fn service(port: u16) -> (&'static str, Option<&'static str>) {
    match port {
        21 => ("FTP", None),
        22 => ("SSH", None),
        23 => ("Telnet", None),
        25 => ("SMTP", None),
        53 => ("DNS", None),
        139 | 445 => ("File sharing", None),
        515 | 9100 => ("Printer", None),
        554 => ("RTSP stream", None),
        1883 => ("MQTT", None),
        3389 => ("Remote Desktop", None),
        5900 => ("VNC", None),
        443 | 8443 => ("Web (HTTPS)", Some("https")),
        631 => ("Printer web", Some("http")),
        32400 => ("Plex", Some("http")),
        80 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8123 | 8888 | 9000 => ("Web", Some("http")),
        _ => ("Service", None),
    }
}
const ROW_H: f32 = 60.0;
const COL_TITLES: [&str; 12] = ["", "Type", "HA", "Name", "Description", "System", "IP", "MAC Address", "Last Seen", "First Seen", "Times Seen", "Open ports"];

impl RustWarden {
    pub(crate) fn scanner_tab(&mut self, ui: &mut Ui) {
        let full = ui.max_rect();
        // One control card on top, one table card below it, like the Firewall tab.
        let bar = Rect::from_min_size(full.min + vec2(12.0, 12.0), vec2(full.width() - 24.0, 56.0));
        ui.painter().rect_filled(bar, 8, theme::card());
        ui.painter().rect_stroke(bar, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);

        // The scan runs in the backend; while it does, re-read it (state and devices) so the button and label follow along.
        let scanning = self.scanner.scan.scanning;
        if scanning {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
            // Two queries and a clone: at most four times a second, not on every mouse move.
            let id = egui::Id::unique("scanner_devices_at");
            let last = ui.data_mut(|d| d.get_temp::<std::time::Instant>(id));
            if last.is_none_or(|t| t.elapsed() >= std::time::Duration::from_millis(250)) {
                ui.data_mut(|d| d.insert_temp(id, std::time::Instant::now()));
                self.reload_scanner();
            }
        }

        let note_src = crate::plugins::wasm::manager::annotator();
        let ha_on = note_src.is_some();
        row_in(ui, bar.shrink2(vec2(14.0, 0.0)), |ui| {
            let names = self.scanner.networks.clone();
            let ids: Vec<usize> = (0..names.len()).collect();
            if !names.is_empty() && widgets::dropdown(ui, Some(Icon::Wifi), &mut self.scanner.network, &ids, |i| names[i].clone(), 240.0) {
                self.settings.scan_network = names[self.scanner.network].clone();
                self.backend.apply_settings(&self.settings);
                if let Err(e) = self.settings.save() {
                    self.notify(&format!("Couldn't save settings: {e}"));
                }
                self.reload_scanner();
            }
            let label = if !scanning {
                "Scan".to_owned()
            } else if self.caps.live {
                format!("Scanning… {:.0}%", self.scanner.scan.progress * 100.0)
            } else {
                "Scanning…".to_owned()
            };
            if widgets::pill_button(ui, None, &label, false, 130.0).clicked() {
                // The result reload that follows a background job also picks up the new scan state.
                if scanning {
                    self.run_bg(|b| {
                        b.stop_scan();
                        Ok(String::new())
                    });
                } else if let Some(n) = names.get(self.scanner.network).cloned() {
                    self.run_bg(move |b| {
                        b.start_scan(&n);
                        Ok(String::new())
                    });
                } else {
                    self.notify("No network to scan");
                }
            }
            if !scanning && let Some(e) = &self.scanner.scan.error {
                ui.label(egui::RichText::new(e).font(theme::font(15.0)).color(theme::text_dim()));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let resp = widgets::pill_button(ui, None, "Columns", true, 0.0);
                let mut hidden = self.settings.scanner_hidden.clone();
                egui::Popup::menu(&resp).width(200.0).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
                    for t in COL_TITLES.iter().enumerate().filter(|(i, t)| *i > 0 && (*i != 2 || ha_on) && !t.is_empty()).map(|(_, t)| *t) {
                        let on = !hidden.iter().any(|h| h == t);
                        if widgets::check_item(ui, on, t).clicked() {
                            if on { hidden.push(t.to_owned()) } else { hidden.retain(|h| h != t) }
                        }
                    }
                });
                if hidden != self.settings.scanner_hidden {
                    self.settings.scanner_hidden = hidden;
                    if let Err(e) = self.settings.save() {
                        self.notify(&format!("Couldn't save settings: {e}"));
                    }
                }
                if widgets::icon_button(ui, Icon::Info, 34.0, "How scanning works").clicked() {
                    self.dialog = Some(Dialog::Info {
                        title: "How scanning works".into(),
                        body: "RustWarden reads this computer's ARP table, then probes the addresses of your own local subnet (never beyond it) at a limited pace. Names come from reverse DNS, vendors from the MAC address. A device that doesn't answer shows as offline.".into(),
                    });
                }
                let mut auto = self.scanner.auto_scan;
                if widgets::small_toggle(ui, &mut auto).clicked() {
                    let mut s = self.settings.clone();
                    s.auto_scan = auto;
                    self.settings = s;
                    self.scanner.auto_scan = auto;
                    self.backend.apply_settings(&self.settings);
                    if let Err(e) = self.settings.save() {
                        self.notify(&format!("Couldn't save settings: {e}"));
                    }
                }
                ui.label(egui::RichText::new("Auto-scan").font(theme::font(15.0)).color(theme::text()));
                widgets::search_box(ui, &mut self.scanner.search, (full.width() * 0.17).max(160.0));
                if self.caps.live && widgets::pill_button(ui, None, "Forget network", false, 0.0).clicked()
                    && let Some(n) = names.get(self.scanner.network) {
                        let n = n.clone();
                        self.run_bg(move |b| {
                            b.forget_network(&n);
                            Ok("Network forgotten".into())
                        });
                    }
            });
        });

        let table = Rect::from_min_max(pos2(bar.left(), bar.bottom() + 12.0), full.max - vec2(12.0, 12.0));
        let tw = table.width();
        let titles = COL_TITLES;
        let hidden = self.settings.scanner_hidden.clone();
        let shown = |i: usize| (ha_on || i != 2) && !hidden.iter().any(|h| h == titles[i]);
        let p = ui.painter().clone();
        p.rect_filled(table, 8, theme::card());
        p.rect_stroke(table, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
        let head = Rect::from_min_size(table.min, vec2(tw, 38.0));
        p.rect_filled(head, egui::epaint::CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 }, theme::nav_on());
        p.hline(table.x_range(), head.bottom(), Stroke::new(1.0, theme::border()));
        // A hidden HA column has no width, so the others share the space.
        let mut widths: [f32; 12] = std::array::from_fn(|i| self.scanner.cols[i + 1] - self.scanner.cols[i]);
        let total: f32 = (0..12).filter(|&i| shown(i)).map(|i| widths[i]).sum();
        let xs: [f32; 13] = {
            let mut acc = 0.0;
            std::array::from_fn(|i| {
                let x = table.left() + acc / total * tw;
                if i < 12 && shown(i) {
                    acc += widths[i];
                }
                x
            })
        };
        let col = |i: usize| xs[i];
        let mut sort = self.settings.scanner_sort;
        let mut resized = false;
        for (i, t) in titles.iter().enumerate().filter(|(i, _)| shown(*i) && *i != 2) {
            let cell = Rect::from_min_max(pos2(col(i), head.top()), pos2(col(i + 1), head.bottom()));
            let resp = ui.interact(cell, ui.scope_id().with(("scanner_head", i)), Sense::click());
            if resp.clicked() {
                sort = Some((i, !sort.is_some_and(|(c, asc)| c == i && asc)));
            }
            let active = sort.is_some_and(|(c, _)| c == i);
            let color = if active || resp.hovered() { theme::text() } else { theme::text_dim() };
            let cx = (col(i) + col(i + 1)) / 2.0;
            let w = widgets::text_fit(&p, pos2(cx - 7.0, head.center().y), Align2::CENTER_CENTER, &t.to_uppercase(), theme::font(12.5), color, (col(i + 1) - col(i) - 36.0).max(0.0)).width();
            if let Some((_, asc)) = sort.filter(|_| active) {
                let (mx, my) = (cx - 7.0 + w / 2.0 + 7.0, head.center().y);
                let tri = if asc { [pos2(mx - 4.0, my + 2.5), pos2(mx + 4.0, my + 2.5), pos2(mx, my - 3.0)] } else { [pos2(mx - 4.0, my - 2.5), pos2(mx + 4.0, my - 2.5), pos2(mx, my + 3.0)] };
                p.add(egui::Shape::convex_polygon(tri.to_vec(), theme::accent_text(), Stroke::NONE));
            }
        }
        if sort != self.settings.scanner_sort {
            self.settings.scanner_sort = sort;
            if let Err(e) = self.settings.save() {
                self.notify(&format!("Couldn't save settings: {e}"));
            }
        }
        // Drag handles on the borders between visible columns.
        for i in (1..12).filter(|&i| shown(i)) {
            p.vline(col(i), (head.top() + 1.0)..=(head.bottom() - 1.0), Stroke::new(1.0, theme::border()));
            let left = (0..i).rev().find(|&j| shown(j)).unwrap_or(0);
            let handle = Rect::from_center_size(pos2(col(i), head.center().y), vec2(8.0, head.height()));
            let resp = ui.interact(handle, ui.scope_id().with(("scanner_resize", i)), Sense::drag()).on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
            resized |= resp.drag_stopped();
            if resp.dragged() {
                let min = 36.0 / tw * total;
                // min/max, not clamp: two narrow neighbours make lo > hi, which clamp panics on.
                // Limits always include 0, so columns already narrower than the minimum can still be dragged out instead of jumping.
                let d = (resp.drag_delta().x / tw * total).min((widths[i] - min).max(0.0)).max((min - widths[left]).min(0.0));
                widths[left] += d;
                widths[i] -= d;
            }
        }
        for (i, w) in widths.iter().enumerate() {
            self.scanner.cols[i + 1] = self.scanner.cols[i] + w;
        }
        if resized {
            self.settings.scanner_cols = self.scanner.cols.to_vec();
            if let Err(e) = self.settings.save() {
                self.notify(&format!("Couldn't save settings: {e}"));
            }
        }

        let query = self.scanner.search.to_lowercase();
        let body = Rect::from_min_max(pos2(table.left(), head.bottom()), table.max);
        let mut devices = self.scanner.devices.clone();
        if let Some((c, asc)) = sort {
            let ip = |d: &Device| d.ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0);
            devices.sort_by(|a, b| {
                let o = match c {
                    0 => b.online.cmp(&a.online),
                    1 => (a.kind as u8).cmp(&(b.kind as u8)),
                    3 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    4 => a.description.to_lowercase().cmp(&b.description.to_lowercase()),
                    5 => a.system.to_lowercase().cmp(&b.system.to_lowercase()),
                    6 => ip(a).cmp(&ip(b)),
                    7 => a.mac.cmp(&b.mac),
                    8 => a.last_seen.cmp(&b.last_seen), // timestamps, not the formatted text
                    9 => a.first_seen.cmp(&b.first_seen),
                    10 => a.seen_count.cmp(&b.seen_count),
                    11 => a.ports.len().cmp(&b.ports.len()),
                    _ => std::cmp::Ordering::Equal,
                };
                if asc { o } else { o.reverse() }
            });
        }
        let ports_on = shown(11);
        let mut clicked: Option<(String, String)> = None;
        let mut copied: Option<String> = None;
        ui.scope_builder(UiBuilder::new().max_rect(body), |ui| {
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for d in devices.iter().filter(|d| query.is_empty() || [&d.name, &d.description, &d.ip, &d.mac, &d.system].iter().any(|s| s.to_lowercase().contains(&query))) {
                    let (r, resp) = ui.allocate_exact_size(vec2(tw, ROW_H), Sense::click());
                    let p = ui.painter().clone();
                    if resp.hovered() {
                        p.rect_filled(r.shrink2(vec2(6.0, 2.0)), 6, theme::row_hover());
                    }
                    p.hline(r.x_range(), r.bottom(), Stroke::new(1.0, theme::border().gamma_multiply(0.5)));
                    let cy = r.center().y;
                    let dot = pos2((col(0) + col(1)) / 2.0, cy);
                    if d.online {
                        p.circle_filled(dot, 4.0, theme::green());
                    } else {
                        p.circle_stroke(dot, 3.5, Stroke::new(1.0, theme::text_dim()));
                    }
                    let (icon, tint) = match d.kind {
                        DeviceKind::Generic => (Icon::Globe, Color32::from_rgb(90, 150, 240)),
                        DeviceKind::SmartDevice => (Icon::House, Color32::from_rgb(240, 150, 50)),
                        DeviceKind::WiFi => (Icon::Wifi, Color32::from_rgb(40, 190, 210)),
                        DeviceKind::Laptop => (Icon::Laptop, Color32::from_rgb(170, 100, 230)),
                        DeviceKind::Raspberry => (Icon::Raspberry, Color32::from_rgb(220, 70, 90)),
                    };
                    icons::paint(&p, icon, Rect::from_center_size(pos2((col(1) + col(2)) / 2.0, cy), vec2(30.0, 30.0)), tint);
                    let mut over_btn = false;
                    if let Some(src) = &note_src
                        && let Some(mark) = crate::ui::notes::paint_badges(&p, d, src, pos2((col(2) + col(3)) / 2.0, cy))
                        && let Some(url) = crate::ui::notes::device_url(d)
                    {
                        let b = ui.interact(mark, ui.scope_id().with(("ha", &d.mac)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(format!("Open in {}", src.name));
                        over_btn = b.hovered();
                        if b.clicked() {
                            crate::sys::open_url(&url);
                        }
                    }
                    let ha_name = note_src.as_ref().and_then(|src| crate::ui::notes::display_name(d, src));
                    let name = ha_name.as_deref().unwrap_or(if d.name.is_empty() { d.kind.label() } else { d.name.as_str() });
                    let seen_count = d.seen_count.to_string();
                    let (last_seen, first_seen) = (crate::clock::fmt_stamp(d.last_seen), crate::clock::fmt_stamp(d.first_seen));
                    let ports = d.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
                    let cells = [name, &d.description, &d.system, &d.ip, &d.mac, &last_seen, &first_seen, &seen_count];
                    let btn_w = 64.0;
                    for (k, text) in cells.iter().enumerate() {
                        let i = k + 3;
                        // A hidden column has zero width; drawing it would leave a stray "…" on its neighbour.
                        if !shown(i) {
                            continue;
                        }
                        let color = if k == 0 { theme::text() } else { theme::text_dim() };
                        let x = if k == 0 { col(i) + 16.0 } else { col(i) + 14.0 };
                        let font = if k == 0 { theme::bold(15.0) } else { theme::font(15.0) };
                        widgets::text_fit(&p, pos2(x, cy), Align2::LEFT_CENTER, text, font, color, col(i + 1) - x - 8.0);
                    }
                    let (px, has_ports) = (col(11) + 14.0, ports_on && !d.ports.is_empty());
                    let shown_ports = if has_ports {
                        ports.as_str()
                    } else if d.online {
                        "None / not scanned"
                    } else {
                        "–"
                    };
                    let room = col(12) - px - 8.0 - if has_ports { btn_w + 6.0 } else { 0.0 };
                    if ports_on {
                        widgets::text_fit(&p, pos2(px, cy), Align2::LEFT_CENTER, shown_ports, theme::font(15.0), theme::text_dim(), room);
                    }
                    if has_ports {
                        let btn = Rect::from_min_size(pos2(col(12) - btn_w - 8.0, cy - 14.0), vec2(btn_w, 28.0));
                        let b = ui.interact(btn, ui.scope_id().with(("services", &d.mac)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                        over_btn |= b.hovered();
                        p.rect_stroke(btn, 4, Stroke::new(1.0, if b.hovered() { theme::text() } else { theme::border() }), egui::StrokeKind::Inside);
                        p.text(btn.center(), Align2::CENTER_CENTER, "Open", theme::font(14.0), theme::text());
                        egui::Popup::menu(&b).show(|ui| {
                            ui.set_min_width(220.0);
                            if let Some(url) = crate::ui::notes::device_url(d)
                                && ui.button(format!("{} – open entity page", note_src.as_ref().map_or("Home Assistant", |s| s.name.as_str()))).clicked()
                            {
                                crate::sys::open_url(&url);
                                ui.close();
                            }
                            for &port in &d.ports {
                                let (name, scheme) = service(port);
                                let label = if scheme.is_some() { format!("{name} – open :{port}") } else { format!("{name} – copy {}:{port}", d.ip) };
                                if ui.button(label).clicked() {
                                    match scheme {
                                        Some(s) => crate::sys::open_url(&format!("{s}://{}:{port}", d.ip)),
                                        None => copied = Some(format!("{}:{port}", d.ip)),
                                    }
                                    ui.close();
                                }
                            }
                        });
                    }
                    if resp.clicked() && !over_btn {
                        clicked = Some((d.mac.clone(), d.name.clone()));
                    }
                }
            });
        });
        if let Some(addr) = copied {
            ui.ctx().copy_text(addr.clone());
            self.notify(&format!("Copied {addr}"));
        }
        if let Some((mac, text)) = clicked {
            self.dialog = Some(Dialog::Rename { mac, text });
        }
        if self.scanner.devices.is_empty() && !scanning {
            let msg = if self.caps.scanner { "No devices yet. Press Scan to look for devices on this network." } else { "Scanning is unavailable." };
            ui.painter().text(pos2(body.center().x, body.top() + 60.0), Align2::CENTER_CENTER, msg, theme::font(16.0), theme::text_dim());
        }
    }
}
