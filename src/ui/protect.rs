use super::dialogs;
use super::row_in;
use crate::app::{Confirm, ConfirmAction, Dialog, RustWarden};
use crate::data::*;
use crate::icons::{self, Icon};
use crate::settings::PendingBlock;
use crate::theme;
use crate::util::fmt_rate;
use crate::widgets;
use egui::epaint::{CornerRadius, StrokeKind};
use egui::{Align2, Color32, Rect, Sense, Stroke, Ui, UiBuilder, pos2, vec2};

/// Column left edges as fractions of the table width, plus the right edge (1.0).
pub(crate) const DEFAULT_COLS: [f32; 11] = [0.0, 0.19, 0.30, 0.41, 0.505, 0.575, 0.71, 0.78, 0.845, 0.91, 1.0];
const ROW_H: f32 = 45.0;

impl RustWarden {
    pub(crate) fn protect_tab(&mut self, ui: &mut Ui) {
        let full = ui.max_rect();
        let p = ui.painter().clone();

        // The banner (Prompt is on, Windows Firewall off, ...) is the first thing on the page, like the info bar on the other Firewall pages.
        let banner = banner_text(&self.protect.info, self.asks.len());
        let mut banner_action = false;
        let mut controls_top = full.top() + 12.0;
        if let Some((text, action)) = &banner {
            let bar = Rect::from_min_size(pos2(full.left() + 12.0, controls_top), vec2(full.width() - 24.0, 46.0));
            p.rect_filled(bar, 8, theme::accent_soft());
            p.rect_stroke(bar, 8, Stroke::new(1.0, theme::accent().gamma_multiply(0.4)), StrokeKind::Inside);
            icons::paint(&p, Icon::Info, Rect::from_center_size(bar.left_center() + vec2(24.0, 0.0), vec2(18.0, 18.0)), theme::accent_text());
            let button_w = action.map_or(0.0, |label| p.layout_no_wrap(label.to_owned(), theme::font(13.5), theme::text()).size().x + 28.0);
            widgets::text_fit(&p, bar.left_center() + vec2(46.0, 0.0), Align2::LEFT_CENTER, text, theme::font(14.0), theme::text(), (bar.width() - 80.0 - button_w).max(40.0));
            if let Some(label) = action {
                let b = Rect::from_center_size(pos2(bar.right() - 14.0 - button_w / 2.0, bar.center().y), vec2(button_w, 30.0));
                let resp = ui.interact(b, ui.scope_id().with("banner_action"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                widgets::shadowed_pill(&p, b, if resp.hovered() { theme::ctl_hover() } else { theme::ctl() });
                p.text(b.center(), Align2::CENTER_CENTER, label, theme::font(13.5), theme::text());
                banner_action = resp.clicked();
            }
            controls_top = bar.bottom() + 12.0;
        }

        // One control card, one table card below it.
        let controls = Rect::from_min_size(pos2(full.left() + 12.0, controls_top), vec2(full.width() - 24.0, 56.0));
        ui.painter().rect_filled(controls, 8, theme::card());
        ui.painter().rect_stroke(controls, 8, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
        let divider = |x: f32| p.vline(x, (controls.top() + 12.0)..=(controls.bottom() - 12.0), Stroke::new(1.0, theme::border()));
        let row_y = controls.center().y;

        // Mode: the three modes, then Disabled (which is what the old on/off switch did).
        let x = controls.left() + 20.0;
        let label_w = p.text(pos2(x, row_y), Align2::LEFT_CENTER, "Mode", theme::bold(16.0), theme::text()).width();
        let current = self.protect.info.enabled.then_some(self.protect.info.mode);
        let mut picked: Option<Option<FirewallMode>> = None;
        let mut prompt_pick: Option<u32> = None;
        row_in(ui, Rect::from_min_size(pos2(x + label_w + 12.0, row_y - 17.0), vec2(220.0, 34.0)), |ui| {
            // Applying a mode takes seconds (it reads and writes Windows Firewall), so say so while it runs.
            let applying = self.verdicts.lock().unwrap_or_else(|e| e.into_inner()).0 > self.quiet_jobs.load(std::sync::atomic::Ordering::SeqCst);
            let label = if applying { "Applying…" } else { current.map_or("Disabled", |m| m.label()) };
            let resp = widgets::pill_button(ui, Some(Icon::Click), label, true, 210.0);
            if applying {
                ui.put(Rect::from_center_size(pos2(resp.rect.right() - 42.0, resp.rect.center().y), vec2(16.0, 16.0)), egui::Spinner::new());
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
            }
            egui::Popup::menu(&resp).width(resp.rect.width().max(220.0)).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).show(|ui| {
                for m in FirewallMode::ALL {
                    if widgets::check_item(ui, current == Some(m), m.label()).clicked() {
                        picked = Some(Some(m));
                        ui.close();
                    }
                }
                ui.separator();
                if widgets::check_item(ui, current.is_none(), "Disabled").clicked() {
                    picked = Some(None);
                    ui.close();
                }
                ui.separator();
                // A slide-out like the tray menu's: the length stays hidden until the row is clicked.
                let open_id = egui::Id::NULL.with("prompt_for_open");
                let open = ui.data(|d| d.get_temp::<bool>(open_id)).unwrap_or(false);
                if widgets::menu_row(ui, None, "Prompt for", &prompt_for_label(self.settings.prompt_minutes), true, true).clicked() {
                    ui.data_mut(|d| d.insert_temp(open_id, !open));
                }
                for m in PROMPT_FOR.into_iter().filter(|_| open) {
                    if widgets::check_item(ui, self.settings.prompt_minutes == m, &prompt_for_label(m)).clicked() {
                        prompt_pick = Some(m);
                        ui.close();
                    }
                }
            });
        });
        if let Some(m) = prompt_pick {
            self.set_prompt_minutes(m);
        }
        match picked {
            Some(None) if current.is_some() => self.toggle_firewall(false),
            Some(Some(m)) if current != Some(m) => self.change_mode(m),
            _ => {}
        }
        let mode_end = x + label_w + 12.0 + 210.0;
        divider(mode_end + 12.0);

        // Ruleset: the button opens Settings > Firewall, where rulesets are switched, created and deleted.
        let x = mode_end + 24.0;
        let name = if self.protect.profile.is_empty() { "…" } else { self.protect.profile.as_str() };
        let text = crate::util::fit_text(&p, &format!("Firewall Ruleset: {name}"), &theme::font(14.0), 300.0);
        let mut manage = false;
        row_in(ui, Rect::from_min_size(pos2(x, row_y - 17.0), vec2(340.0, 34.0)), |ui| {
            manage = widgets::pill_button(ui, Some(Icon::Sliders), &text, false, 0.0).on_hover_text("Switch, create or delete firewall rulesets in Settings").clicked();
        });
        if manage {
            self.settings_section = Some(6);
            let now = ui.input(|i| i.time);
            ui.data_mut(|d| d.insert_temp(egui::Id::NULL.with("flash_rulesets"), now));
            self.open_settings();
        }

        // Search, on the right of the card.
        let search_w = 240.0_f32.min((controls.right() - (x + 340.0) - 40.0).max(120.0));
        let x = controls.right() - 20.0 - search_w;
        divider(x - 20.0);
        row_in(ui, Rect::from_min_size(pos2(x, row_y - 17.0), vec2(search_w, 34.0)), |ui| {
            widgets::search_box(ui, &mut self.protect.search, search_w);
        });
        let table_top = controls.bottom() + 12.0;

        // Table card.
        let table = Rect::from_min_max(pos2(full.left() + 12.0, table_top), pos2(full.right() - 12.0, full.bottom() - 12.0));
        p.rect_filled(table, 8, theme::card());
        p.rect_stroke(table, 8, Stroke::new(1.0, theme::card_edge()), StrokeKind::Inside);
        let tw = table.width();
        let head = Rect::from_min_size(table.min, vec2(tw, 38.0));
        p.rect_filled(head, CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 }, theme::nav_on());
        p.hline(table.x_range(), head.bottom(), Stroke::new(1.0, theme::border()));
        let titles = ["Apps", "Incoming", "Outgoing", "Local", "Version", "Hosts", "VirusTotal", "", "", "Traffic"];
        let mut cols = self.protect.cols;
        let mut sort = self.protect.sort;
        for (i, title) in titles.iter().enumerate() {
            let (l, r) = (table.left() + cols[i] * tw, table.left() + cols[i + 1] * tw);
            let cx = (l + r) / 2.0;
            let cell = Rect::from_min_max(pos2(l, head.top()), pos2(r, head.bottom()));
            let sortable = i != 6; // VirusTotal results have no useful order
            let resp = ui.interact(cell, ui.scope_id().with(("protect_head", i)), if sortable { Sense::click() } else { Sense::hover() });
            if sortable && resp.clicked() {
                // Ascending, then descending, then back to the default order.
                sort = match sort {
                    Some((c, true)) if c == i => Some((i, false)),
                    Some((c, false)) if c == i => None,
                    _ => Some((i, true)),
                };
            }
            let active = sortable && sort.is_some_and(|s| s.0 == i);
            let color = if active || resp.hovered() { theme::text() } else { theme::text_dim() };
            let mut mark_x = cx;
            match i {
                7 => icons::paint(&p, Icon::ArrowDown, Rect::from_center_size(pos2(cx, head.center().y), vec2(14.0, 14.0)), color),
                8 => icons::paint(&p, Icon::ArrowUp, Rect::from_center_size(pos2(cx, head.center().y), vec2(14.0, 14.0)), color),
                _ => {
                    // Leave room for the sort mark and clip to the cell so narrow columns never spill into their neighbours.
                    let room = (r - l - 36.0).max(0.0);
                    let w = widgets::text_fit(&p, pos2(cx - 7.0, head.center().y), Align2::CENTER_CENTER, &title.to_uppercase(), theme::font(12.5), color, room).width();
                    mark_x = cx - 7.0 + w / 2.0 - 7.0;
                }
            }
            if let Some((_, asc)) = sort.filter(|_| active) {
                let (mx, my) = (mark_x + 14.0, head.center().y);
                let tri = if asc { [pos2(mx - 4.0, my + 2.5), pos2(mx + 4.0, my + 2.5), pos2(mx, my - 3.0)] } else { [pos2(mx - 4.0, my - 2.5), pos2(mx + 4.0, my - 2.5), pos2(mx, my + 3.0)] };
                p.add(egui::Shape::convex_polygon(tri.to_vec(), theme::accent_text(), Stroke::NONE));
            }
        }
        // Drag handles on the inner column borders, added last so they win over the header cells.
        for i in 1..=9 {
            p.vline(table.left() + cols[i] * tw, (head.top() + 1.0)..=(head.bottom() - 1.0), Stroke::new(1.0, theme::border()));
            let handle = Rect::from_center_size(pos2(table.left() + cols[i] * tw, head.center().y), vec2(8.0, head.height()));
            let resp = ui.interact(handle, ui.scope_id().with(("protect_resize", i)), Sense::drag()).on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
            if resp.dragged() {
                // A column can't shrink below its title (plus the room kept for the sort mark).
                let min_frac = |c: usize| (p.layout_no_wrap(titles[c].to_uppercase(), theme::font(12.5), theme::text()).size().x.max(14.0) + 36.0) / tw;
                let lo = cols[i - 1] + min_frac(i - 1);
                let hi = cols[i + 1] - min_frac(i);
                // A column already squeezed past its minimum (narrow window, old saved layout) can still be dragged out: the limits never exclude where it is now.
                cols[i] = (cols[i] + resp.drag_delta().x / tw).min(hi.max(cols[i])).max(lo.min(cols[i]));
            }
        }
        self.protect.cols = cols;
        self.protect.sort = sort;
        let col = |i: usize| table.left() + cols[i] * tw;

        let body = Rect::from_min_max(pos2(table.left(), head.bottom()), table.max);
        let info = self.protect.info.clone();
        let firewall_on = info.enabled;
        let query = self.protect.search.to_lowercase();
        if self.protect.flash.as_ref().is_some_and(|f| f.1.elapsed().as_secs_f32() > 3.0) {
            self.protect.flash = None;
        }
        let mut flash = self.protect.flash.clone();
        if flash.is_some() {
            ui.ctx().request_repaint();
        }
        let apps = std::mem::take(&mut self.protect.apps);
        let mut open_groups = self.protect.open_groups;
        let mut expanded = std::mem::take(&mut self.protect.expanded);
        let mut change: Option<(String, Direction, Verdict)> = None;
        let mut more_clicked: Option<(String, egui::Pos2)> = None;
        let mut remove: Option<String> = None;
        let mut block_after: Option<(String, Vec<Direction>, u64)> = None;
        let mut scan: Option<String> = None;
        // (key, name, path) of a program the user chose to upload; asked about before anything is sent.
        let mut upload: Option<(String, String, String)> = None;
        let mut select: Option<(String, egui::Pos2)> = None;
        let hold = self.protect.hold.clone();
        let mut new_hold: Option<(String, usize, usize, f32)> = None;
        // How far the held row moved in the content since last frame, where it is now, and the scroll offset used.
        let (mut shift, mut held_cy, mut offset_y) = (0.0_f32, None, 0.0_f32);
        let scroll_to = self.protect.scroll_to.take();
        let can_scan = self.caps.live && !crate::live::vt::key().is_empty();

        ui.scope_builder(UiBuilder::new().max_rect(body), |ui| {
            let mut area = egui::ScrollArea::vertical().auto_shrink([false, false]);
            if let Some(y) = scroll_to {
                area = area.vertical_scroll_offset(y);
            }
            let out = area.show(ui, |ui| {
                let top0 = ui.min_rect().top();
                ui.spacing_mut().item_spacing.y = 0.0;
                for (gi, group) in AppGroup::ALL.into_iter().enumerate() {
                    let mut members: Vec<usize> = apps.iter().enumerate().filter(|(_, a)| a.group == group).map(|(i, _)| i).collect();
                    members.sort_by(|&a, &b| {
                        let (a, b) = (&apps[a], &apps[b]);
                        let (col, asc) = sort.unwrap_or((0, true));
                        let by = match col {
                            1 => (a.inbound == Verdict::Blocked).cmp(&(b.inbound == Verdict::Blocked)),
                            2 => (a.outbound == Verdict::Blocked).cmp(&(b.outbound == Verdict::Blocked)),
                            3 => (a.local == Verdict::Blocked).cmp(&(b.local == Verdict::Blocked)),
                            4 => a.version.cmp(&b.version),
                            5 => a.host.to_lowercase().cmp(&b.host.to_lowercase()),
                            7 => a.down_rate.total_cmp(&b.down_rate),
                            8 => a.up_rate.total_cmp(&b.up_rate),
                            9 => (a.down_rate + a.up_rate).total_cmp(&(b.down_rate + b.up_rate)),
                            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                        };
                        (if asc { by } else { by.reverse() }).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                    });
                    // The app under the mouse keeps its place; the others move around it.
                    if let Some((key, _, at, _)) = hold.as_ref().filter(|h| h.1 == gi) {
                        hold_in_place(&mut members, |i| apps[i].key == *key, *at);
                    }
                    if members.is_empty() && group != AppGroup::Active {
                        continue;
                    }
                    // Group header row.
                    let (r, resp) = ui.allocate_exact_size(vec2(tw, 42.0), Sense::click());
                    ui.painter().rect_filled(r, 0, theme::nav_on());
                    ui.painter().hline(r.x_range(), r.bottom(), Stroke::new(1.0, theme::border()));
                    if resp.clicked() {
                        open_groups[gi] = !open_groups[gi];
                    }
                    icons::paint(
                        ui.painter(),
                        if open_groups[gi] { Icon::Chevron } else { Icon::ChevronRight },
                        Rect::from_center_size(pos2(r.left() + 22.0, r.center().y), vec2(14.0, 14.0)),
                        theme::text_dim(),
                    );
                    let label = ui.painter().layout_no_wrap(group.label().to_owned(), theme::bold(15.0), theme::text());
                    let label_w = label.size().x;
                    ui.painter().galley(pos2(r.left() + 44.0, r.center().y - label.size().y / 2.0), label, theme::text());
                    ui.painter().text(pos2(r.left() + 44.0 + label_w + 10.0, r.center().y), Align2::LEFT_CENTER, members.len().to_string(), theme::font(13.0), theme::text_dim());
                    if !open_groups[gi] {
                        continue;
                    }
                    if members.is_empty() {
                        let (r, _) = ui.allocate_exact_size(vec2(tw, ROW_H), Sense::hover());
                        ui.painter().text(r.left_center() + vec2(24.0, 0.0), Align2::LEFT_CENTER, "No apps with network activity yet.", theme::font(15.0), theme::text_dim());
                        continue;
                    }

                    for (mi, &i) in members.iter().enumerate() {
                        let app = &apps[i];
                        if !query.is_empty() && !app.name.to_lowercase().contains(&query) {
                            continue;
                        }
                        let (r, resp) = ui.allocate_exact_size(vec2(tw, ROW_H), Sense::click());
                        let cy = r.top() - top0;
                        if let Some(h) = hold.as_ref().filter(|h| h.1 == gi && h.0 == app.key) {
                            shift = cy - h.3;
                            held_cy = Some(cy);
                        }
                        if ui.rect_contains_pointer(r) {
                            new_hold = Some((app.key.clone(), gi, mi, cy));
                        }
                        let resp = if app.path.is_empty() {
                            resp
                        } else {
                            let signed = match app.signed {
                                Some(true) => "signed",
                                Some(false) => "not signed",
                                None => "signature not checked",
                            };
                            resp.on_hover_text(format!("{}\n{} · {}", app.path, if app.publisher.is_empty() { "unknown publisher" } else { &app.publisher }, signed))
                        };
                        // Only the first column opens the info popup; a click anywhere else dismisses it.
                        if resp.clicked() && resp.interact_pointer_pos().is_some_and(|p| p.x < col(1)) {
                            select = Some((app.key.clone(), pos2(r.left() + 24.0, r.bottom())));
                        }
                        let p = ui.painter().clone();
                        if resp.hovered() || (!app.locked && ui.rect_contains_pointer(r)) {
                            p.rect_filled(r.shrink2(vec2(6.0, 2.0)), 6, theme::nav_on());
                        }
                        p.hline(r.x_range(), r.bottom(), Stroke::new(1.0, theme::border()));
                        if let Some((_, t, scroll)) = flash.as_mut().filter(|f| f.0 == app.name) {
                            if std::mem::take(scroll) {
                                ui.scroll_to_rect(r, Some(egui::Align::Center));
                            }
                            let a = (0.5 + 0.5 * (t.elapsed().as_secs_f32() * 6.0).cos()) * 110.0;
                            p.rect_filled(r, 0, Color32::from_rgba_unmultiplied(255, 170, 0, a as u8));
                        }
                        let cy = r.center().y;
                        let open = expanded.contains(&app.key);
                        let arrow = Rect::from_center_size(pos2(r.left() + 22.0, cy), vec2(13.0, 13.0));
                        if !app.pids.is_empty() {
                            icons::paint(&p, if open { Icon::Chevron } else { Icon::ChevronRight }, arrow, theme::text_dim());
                            let a_resp = ui.interact(arrow.expand(8.0), ui.scope_id().with(("expand", &app.key)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                            if a_resp.clicked() && !expanded.remove(&app.key) {
                                expanded.insert(app.key.clone());
                            }
                        }
                        icons::app_icon_for(&p, app.icon, &app.path, Rect::from_center_size(pos2(r.left() + 52.0, cy), vec2(24.0, 24.0)));
                        // An hourglass while a "block after" is counting down for this app.
                        let countdown = self.block_countdown(&app.key);
                        let name_w = col(1) - r.left() - 84.0 - if countdown.is_some() { 24.0 } else { 0.0 };
                        // While the Remove button shows, a long name fades out before it instead of running under it.
                        let name_end = if !app.locked && ui.rect_contains_pointer(r) {
                            let chip_left = (col(1) + col(2)) / 2.0 - (col(2) - col(1) - 24.0).min(118.0) / 2.0;
                            let room = name_w.min(chip_left - 53.0 - 6.0 - (r.left() + 72.0));
                            widgets::text_faded(&p, pos2(r.left() + 72.0, cy), &app.name, theme::font(15.0), theme::text(), room, 28.0)
                        } else {
                            widgets::text_fit(&p, pos2(r.left() + 72.0, cy), Align2::LEFT_CENTER, &app.name, theme::font(15.0), theme::text(), name_w).width()
                        };
                        if let Some((due, what)) = countdown {
                            let now = crate::clock::now_unix();
                            let spot = Rect::from_center_size(pos2(r.left() + 72.0 + name_end + 16.0, cy), vec2(16.0, 16.0));
                            icons::paint(&p, Icon::Hourglass, spot, theme::orange());
                            ui.interact(spot.expand(4.0), ui.scope_id().with(("timer", &app.key)), Sense::hover()).on_hover_text(format!(
                                "Will block {what} connections at {}, {}",
                                crate::clock::fmt_time_lower(due),
                                crate::clock::in_words(due - now)
                            ));
                        }

                        // Allow | Block segments, one control per direction (the same segmented look as the tab switches).
                        for (k, direction, verdict) in [(1usize, Direction::In, app.inbound), (2usize, Direction::Out, app.outbound), (3usize, Direction::Local, app.local)] {
                            let chip = Rect::from_center_size(pos2((col(k) + col(k + 1)) / 2.0, cy), vec2((col(k + 1) - col(k) - 24.0).min(118.0), 28.0));
                            let locked = app.locked;
                            let resp = ui.interact(chip, ui.scope_id().with(("chip", &app.key, k)), if locked { Sense::hover() } else { Sense::click() });
                            let resp = if locked {
                                resp.on_hover_text("Windows' own program: always allowed, and its rules can't be changed here")
                            } else {
                                resp.on_hover_cursor(egui::CursorIcon::PointingHand)
                            };
                            let dim = |c: Color32, f: f32| if firewall_on { c } else { c.gamma_multiply(f) };
                            widgets::shadowed_pill(&p, chip, dim(theme::ctl(), 0.6));
                            if locked {
                                icons::paint(&p, Icon::Shield, Rect::from_center_size(chip.left_center() + vec2(14.0, 0.0), vec2(12.0, 12.0)), dim(theme::text_dim(), 0.55));
                                widgets::text_fit(&p, pos2(chip.left() + 26.0, cy), Align2::LEFT_CENTER, "Always Allowed", theme::font(13.0), dim(theme::text_dim(), 0.55), chip.width() - 32.0);
                                continue;
                            }
                            let hover_x = resp.hover_pos().map(|h| h.x);
                            for (side, label, seg_verdict) in [(0.0, "Allow", Verdict::Allowed), (1.0, "Block", Verdict::Blocked)] {
                                let seg = Rect::from_min_size(pos2(chip.left() + side * chip.width() / 2.0, chip.top()), vec2(chip.width() / 2.0, chip.height())).shrink(2.5);
                                let on = verdict == seg_verdict;
                                let (fill, ink) = match (on, seg_verdict) {
                                    (true, Verdict::Allowed) => (theme::accent(), theme::on_accent()),
                                    (true, Verdict::Blocked) => (theme::red(), theme::WHITE),
                                    (false, _) => (Color32::TRANSPARENT, theme::text_dim()),
                                };
                                if on {
                                    p.rect_filled(seg, 3, dim(fill, 0.6));
                                } else if hover_x.is_some_and(|x| (x < chip.center().x) == (side == 0.0)) {
                                    p.rect_filled(seg, 3, theme::nav_on());
                                }
                                // Narrow columns: shrink the label so it stays inside its half.
                                let natural = p.layout_no_wrap(label.to_owned(), theme::font(13.5), ink).size().x;
                                p.text(seg.center(), Align2::CENTER_CENTER, label, theme::font(13.5 * ((seg.width() - 6.0) / natural).min(1.0)), dim(ink, 0.55));
                            }
                            if resp.clicked() {
                                let want = if resp.interact_pointer_pos().is_some_and(|pos| pos.x < chip.center().x) { Verdict::Allowed } else { Verdict::Blocked };
                                if want != verdict {
                                    change = Some((app.key.clone(), direction, want));
                                }
                            }
                            if verdict == Verdict::Allowed {
                                resp.context_menu(|ui| {
                                    ui.style_mut().text_styles.insert(egui::TextStyle::Button, theme::font(15.0));
                                    ui.spacing_mut().button_padding = vec2(14.0, 10.0);
                                    ui.menu_button("Block after", |ui| {
                                        ui.set_min_width(180.0);
                                        for m in crate::app::BLOCK_AFTER_MINS {
                                            if widgets::check_item(ui, false, &format!("{m} minutes")).clicked() {
                                                block_after = Some((app.key.clone(), vec![direction], m));
                                                ui.close();
                                            }
                                        }
                                    });
                                });
                            }
                        }

                        widgets::text_fit(&p, pos2(col(4) + 14.0, cy), Align2::LEFT_CENTER, &app.version, theme::font(14.5), theme::text(), col(5) - col(4) - 22.0);
                        let hx = col(5) + 12.0;
                        if app.host.is_empty() {
                            p.text(pos2(hx, cy), Align2::LEFT_CENTER, "No connections recently", theme::font(13.5), theme::text_faint());
                        } else {
                            icons::flag(&p, app.host_country, Rect::from_center_size(pos2(hx + 11.0, cy), vec2(22.0, 16.0)));
                        }
                        let more = if app.more_hosts > 0 { format!("+{} more", app.more_hosts) } else { String::new() };
                        let more_w = if more.is_empty() { 0.0 } else { 72.0 };
                        let avail = col(6) - hx - 30.0 - more_w - 10.0;
                        let host_w = widgets::text_fit(&p, pos2(hx + 30.0, cy), Align2::LEFT_CENTER, &app.host, theme::font(14.5), theme::text(), avail).width();
                        let info = self.backend.net_info(&app.host);
                        if !info.is_empty() && avail - host_w > 60.0 {
                            widgets::text_fit(&p, pos2(hx + 30.0 + host_w + 8.0, cy), Align2::LEFT_CENTER, &info, theme::font(12.5), theme::text_dim(), avail - host_w - 8.0);
                        }
                        if !more.is_empty() {
                            let chip = Rect::from_center_size(pos2(col(6) - 46.0, cy), vec2(66.0, 22.0));
                            let resp = ui.interact(chip, ui.scope_id().with(("more", &app.key)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                            let (stroke, text) = if resp.hovered() { (theme::text_dim(), theme::text()) } else { (theme::text_faint(), theme::text_dim()) };
                            p.rect_stroke(chip, 4, Stroke::new(1.0, stroke), StrokeKind::Inside);
                            p.text(chip.center(), Align2::CENTER_CENTER, more, theme::font(13.0), text);
                            if resp.clicked() {
                                more_clicked = Some((app.usage_key.clone(), chip.left_bottom()));
                            }
                        }
                        // VirusTotal: hash lookup only. The score opens its VirusTotal page; scanning is in the row's right-click menu.
                        let (text, color) = match &app.virustotal {
                            Vt::Result { bad, total } => (format!("{bad}/{total}"), if *bad > 0 { theme::red() } else { theme::green() }),
                            Vt::NotFound => ("Not found".into(), theme::text_dim()),
                            Vt::Pending => ("Scanning…".into(), theme::text_dim()),
                            Vt::Analysing => ("Analysing…".into(), theme::text_dim()),
                            Vt::Skipped => ("Skipped (over 32MB)".into(), theme::text_dim()),
                            Vt::Failed => ("Failed".into(), theme::red()),
                            Vt::OnHold => ("On Hold".into(), theme::text_dim()),
                            Vt::None if can_scan && !app.path.is_empty() => ("Not scanned".into(), theme::text_faint()),
                            Vt::None => (String::new(), theme::text()),
                        };
                        if !text.is_empty() {
                            let cell = Rect::from_min_max(pos2(col(6), r.top()), pos2(col(7), r.bottom()));
                            if matches!(app.virustotal, Vt::Result { .. }) {
                                let w = p.layout_no_wrap(text.clone(), theme::bold(13.0), color).size().x;
                                p.rect_filled(Rect::from_center_size(cell.center(), vec2(w + 20.0, 22.0)), 11, color.gamma_multiply(0.16));
                                p.text(cell.center(), Align2::CENTER_CENTER, text, theme::bold(13.0), color);
                            } else {
                                p.text(cell.center(), Align2::CENTER_CENTER, text, theme::font(14.0), color);
                            }
                            if app.virustotal == Vt::OnHold {
                                ui.interact(cell, ui.scope_id().with(("vt", &app.key)), Sense::hover()).on_hover_text(VT_HOLD_TIP);
                            }
                            if matches!(app.virustotal, Vt::Result { .. }) {
                                let link = ui.interact(cell, ui.scope_id().with(("vt", &app.key)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Open on VirusTotal");
                                if link.clicked() {
                                    crate::sys::open_url(&format!("https://www.virustotal.com/gui/file/{}", app.hash));
                                }
                            }
                        }
                        if can_scan && !app.path.is_empty() && matches!(app.virustotal, Vt::None | Vt::Failed | Vt::NotFound) {
                            resp.context_menu(|ui| {
                                let label = if app.virustotal == Vt::None { "Scan with VirusTotal" } else { "Scan with VirusTotal again" };
                                if app.virustotal != Vt::NotFound && ui.button(label).clicked() {
                                    scan = Some(app.key.clone());
                                    ui.close();
                                }
                                if app.virustotal == Vt::NotFound && ui.button("Upload to VirusTotal…").clicked() {
                                    upload = Some((app.key.clone(), app.name.clone(), app.path.clone()));
                                    ui.close();
                                }
                            });
                        }
                        for (k, rate) in [(7usize, app.down_rate), (8usize, app.up_rate)] {
                            if rate > 0.0 {
                                p.text(pos2(col(k) + 14.0, cy), Align2::LEFT_CENTER, fmt_rate(rate), theme::font(14.5), theme::text());
                            }
                        }
                        let spark = Rect::from_min_max(pos2(col(9) + 14.0, cy - 14.0), pos2(col(10) - 22.0, cy + 14.0));
                        widgets::area(&p, spark, &app.activity, Color32::TRANSPARENT, Some(Stroke::new(1.5, theme::down())));

                        // Remove button: a rounded square left of the In chip, only while the row is hovered.
                        // Windows' own programs can't be removed.
                        if !app.locked && ui.rect_contains_pointer(r) {
                            let chip_left = (col(1) + col(2)) / 2.0 - (col(2) - col(1) - 24.0).min(118.0) / 2.0;
                            let x_rect = Rect::from_center_size(pos2(chip_left - 35.0, cy), vec2(36.0, 36.0));
                            let x_resp = ui.interact(x_rect, ui.scope_id().with(("remove", &app.key)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Remove");
                            p.rect_filled(x_rect, 6, if x_resp.hovered() { theme::track() } else { theme::field() });
                            icons::paint(&p, Icon::Close, Rect::from_center_size(x_rect.center(), vec2(13.0, 13.0)), theme::text_dim());
                            if x_resp.clicked() {
                                remove = Some(app.key.clone());
                            }
                        }

                        if open {
                            for pid in &app.pids {
                                let (r, _) = ui.allocate_exact_size(vec2(tw, ROW_H), Sense::hover());
                                ui.painter().rect_filled(r, 0, theme::nav_on().gamma_multiply(0.6));
                                let exe = if app.path.is_empty() { &app.name } else { app.path.rsplit(['\\', '/']).next().unwrap_or(&app.name) };
                                icons::app_icon_for(ui.painter(), app.icon, &app.path, Rect::from_center_size(pos2(r.left() + 72.0, r.center().y), vec2(24.0, 24.0)));
                                widgets::text_fit(ui.painter(), pos2(r.left() + 98.0, r.center().y), Align2::LEFT_CENTER, exe, theme::font(15.0), theme::text(), col(1) - r.left() - 180.0);
                                ui.painter().text(pos2(col(1) - 14.0, r.center().y), Align2::RIGHT_CENTER, pid.to_string(), theme::font(14.5), theme::text_dim());
                            }
                        }
                    }
                }
            });
            offset_y = out.state.clamped_offset().y;
        });

        // Something above the held row grew or shrank: scroll by the same amount so it stays under the mouse.
        // Until that lands (next frame) the pointer is over a different row, so the hold must not follow it.
        if shift.abs() > 0.5
            && let (Some(h), Some(cy)) = (hold.as_ref(), held_cy)
        {
            self.protect.scroll_to = Some((offset_y + shift).max(0.0));
            new_hold = Some((h.0.clone(), h.1, h.2, cy));
            ui.ctx().request_repaint();
        }
        // Let go once the pointer leaves the row, unless a menu or the info popup opened from it is still up.
        self.protect.hold = new_hold.or_else(|| hold.filter(|_| egui::Popup::is_any_open(ui.ctx()) || self.protect.selected.is_some()));
        self.protect.apps = apps;
        self.protect.open_groups = open_groups;
        self.protect.expanded = expanded;
        self.protect.flash = flash;
        if let Some((key, direction, verdict)) = change {
            self.set_verdict(&key, direction, verdict);
        }
        if let Some((key, directions, mins)) = block_after.take() {
            self.block_after(&key, &directions, mins);
        }
        if let Some(key) = remove {
            self.remove_app(&key);
        }
        if let Some(key) = scan {
            self.backend.scan_virustotal(&key);
        }
        if let Some((key, name, path)) = upload {
            self.dialog = Some(Dialog::Confirm(dialogs::virustotal_upload_confirm(&key, &name, &path)));
        }
        if let Some((key, pos)) = more_clicked {
            self.traffic.detail = self.backend.usage_detail(self.traffic.range, self.traffic.window, UsageKind::App, &key).map(|d| (pos, d));
            self.traffic.detail_back.clear();
        }
        let opened = select.is_some();
        if let Some((key, pos)) = select {
            let name = self.protect.apps.iter().find(|a| a.key == key).map(|a| a.name.clone()).unwrap_or_default();
            self.protect.selected_alerts = self.backend.alerts().into_iter().filter(|a| a.app == name).collect();
            self.protect.selected = Some((key, pos));
            self.protect.show_alerts = false;
        }
        self.traffic_detail(ui.ctx());
        self.app_popup(ui.ctx(), can_scan, opened);
        if banner_action {
            self.banner_action(ui.ctx());
        }
    }

    /// Info popup under a clicked Firewall row: details, VirusTotal scan, quick firewall controls and a More menu.
    pub(crate) fn app_popup(&mut self, ctx: &egui::Context, can_scan: bool, opened: bool) {
        let Some((key, pos)) = self.protect.selected.clone() else { return };
        let Some(app) = self.protect.apps.iter().find(|a| a.key == key).cloned() else {
            self.protect.selected = None;
            return;
        };
        let width = 420.0;
        let screen = ctx.content_rect();
        let pos = pos2(pos.x.min(screen.right() - width - 12.0).max(screen.left() + 8.0), pos.y.min(screen.bottom() - 300.0).max(screen.top() + 8.0));
        let (mut do_scan, mut do_upload, mut hide, mut incognito, mut block_now) = (false, false, false, false, false);
        let mut verdicts: Option<(Verdict, Verdict)> = None;
        let mut popup_delay: Option<u64> = None;
        let mut show_alerts = self.protect.show_alerts;
        let alerts = &self.protect.selected_alerts;
        let quotas = &self.protect.quotas;
        let current = match (app.inbound, app.outbound) {
            (Verdict::Allowed, Verdict::Allowed) => 0,
            (Verdict::Blocked, Verdict::Blocked) => 1,
            (Verdict::Blocked, _) => 2,
            _ => 3,
        };
        const CHOICES: [(&str, Verdict, Verdict); 4] = [
            ("Allow All Connections", Verdict::Allowed, Verdict::Allowed),
            ("Block All Connections", Verdict::Blocked, Verdict::Blocked),
            ("Block Incoming Connections", Verdict::Blocked, Verdict::Allowed),
            ("Block Outgoing Connections", Verdict::Allowed, Verdict::Blocked),
        ];
        let label = ["All allowed", "All blocked", "Incoming blocked", "Outgoing blocked"][current];
        let (vt_text, vt_color) = vt_label(&app.virustotal);
        // "Block after" counting down for this app: shown as a line, and redrawn each second so the countdown moves.
        let countdown = self.block_countdown(&app.key);
        if countdown.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
        egui::Area::new(egui::Id::unique("app_info_popup")).order(egui::Order::Foreground).fixed_pos(pos).show(ctx, |ui| {
            // A solid sheet (never see-through, whatever the Acrylic setting): rows behind the card must not bleed into the text.
            egui::Frame::NONE
                .fill(theme::surface_solid())
                .stroke(Stroke::new(1.0, theme::card_edge()))
                .corner_radius(8)
                .inner_margin(14)
                .shadow(egui::epaint::Shadow { offset: [0, 12], blur: 36, spread: 0, color: Color32::from_black_alpha(80) })
                .show(ui, |ui| {
                    ui.set_width(width - 28.0);
                    ui.spacing_mut().item_spacing = vec2(8.0, 8.0);
                    ui.horizontal(|ui| {
                        let (icon_rect, _) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::hover());
                        icons::app_icon_for(ui.painter(), app.icon, &app.path, icon_rect);
                        ui.allocate_ui_with_layout(vec2(width - 28.0 - 30.0 - 150.0, 24.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.add(egui::Label::new(egui::RichText::new(&app.name).font(theme::bold(15.0)).color(theme::text())).truncate());
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // Segmented Info / Alerts switch.
                            egui::Frame::NONE.fill(theme::ctl()).stroke(Stroke::new(1.0, theme::card_edge())).corner_radius(6).inner_margin(2).show(ui, |ui| {
                                ui.spacing_mut().item_spacing.x = 2.0;
                                ui.spacing_mut().button_padding = vec2(10.0, 3.0);
                                let n = alerts.len();
                                let tab = if n > 0 { format!("Alerts ({n})") } else { "Alerts".into() };
                                for (is_alerts, text) in [(false, "Info".to_owned()), (true, tab)] {
                                    let on = show_alerts == is_alerts;
                                    let (fill, ink) = if on { (theme::accent(), theme::on_accent()) } else { (Color32::TRANSPARENT, theme::text_dim()) };
                                    let font = if on { theme::bold(13.0) } else { theme::font(13.0) };
                                    let b = egui::Button::new(egui::RichText::new(text).font(font).color(ink)).fill(fill).stroke(Stroke::NONE).corner_radius(4);
                                    if ui.add(b).clicked() {
                                        show_alerts = is_alerts;
                                    }
                                }
                            });
                        });
                    });
                    ui.separator();
                    if show_alerts {
                        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                            if alerts.is_empty() {
                                ui.label(egui::RichText::new("No alerts for this app.").color(theme::text_dim()));
                            }
                            for a in alerts {
                                ui.horizontal(|ui| {
                                    ui.set_height(22.0);
                                    ui.label(egui::RichText::new(format!("{} {}", a.text_and_signature().0, a.target)).font(theme::font(13.0)).color(theme::text()));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(egui::RichText::new(format!("{} {}", a.day, a.time)).font(theme::font(12.0)).color(theme::text_dim()));
                                    });
                                });
                            }
                        });
                    } else {
                        let or_unknown = |s: &str| if s.is_empty() { "Unknown".to_owned() } else { s.to_owned() };
                        let exe = if app.path.is_empty() { app.name.clone() } else { app.path.rsplit(['\\', '/']).next().unwrap_or(&app.name).to_owned() };
                        let mut facts = vec![
                            ("Name", exe, theme::text()),
                            ("Path", or_unknown(&app.path), theme::text()),
                            ("Version", or_unknown(&app.version), theme::text()),
                            ("Publisher", or_unknown(&app.publisher), theme::text()),
                        ];
                        if !app.service.is_empty() {
                            facts.push(("Service", app.service.replace('+', ", "), theme::text()));
                        }
                        if !app.parent.is_empty() {
                            facts.push(("Started by", app.parent.clone(), theme::text()));
                        }
                        facts.push(("VirusTotal", vt_text, vt_color));
                        if let Some((due, what)) = &countdown {
                            let text = format!("{what}, at {} ({})", crate::clock::fmt_time_lower(*due), crate::clock::in_words(*due - crate::clock::now_unix()));
                            facts.push(("Blocks", text, theme::orange()));
                        }
                        for (k, v, color) in facts {
                            ui.horizontal(|ui| {
                                ui.set_height(20.0);
                                let (kr, _) = ui.allocate_exact_size(vec2(78.0, 18.0), Sense::hover());
                                ui.painter().text(kr.left_center(), Align2::LEFT_CENTER, k, theme::font(13.0), theme::text_dim());
                                ui.add(egui::Label::new(egui::RichText::new(&v).font(theme::font(13.0)).color(color)).truncate()).on_hover_text(&v);
                            });
                        }
                        for st in quotas.iter().filter(|q| q.quota.app == app.key) {
                            ui.horizontal(|ui| {
                                let (kr, _) = ui.allocate_exact_size(vec2(78.0, 18.0), Sense::hover());
                                ui.painter().text(kr.left_center(), Align2::LEFT_CENTER, "Quota", theme::font(13.0), theme::text_dim());
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 3.0;
                                    widgets::quota_bar(ui, st, 240.0);
                                });
                            });
                        }
                        // Done sooner than planned: block now instead of waiting for the countdown.
                        if countdown.is_some() {
                            ui.horizontal(|ui| {
                                ui.add_space(88.0);
                                let button =
                                    egui::Button::new(egui::RichText::new("Block now").font(theme::font(13.0)).color(theme::WHITE)).fill(theme::red()).corner_radius(6).min_size(vec2(96.0, 26.0));
                                if ui.add(button).on_hover_text("Skip the countdown and block right away").clicked() {
                                    block_now = true;
                                }
                            });
                        }
                    }
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        ui.spacing_mut().button_padding = vec2(10.0, 6.0);
                        let ws = &mut ui.style_mut().visuals.widgets;
                        for w in [&mut ws.inactive, &mut ws.hovered, &mut ws.active] {
                            w.corner_radius = 6.into();
                        }
                        let scan_ok = can_scan && !app.path.is_empty() && matches!(app.virustotal, Vt::None | Vt::Failed | Vt::NotFound);
                        let has_page = matches!(app.virustotal, Vt::Result { .. }) && !app.hash.is_empty();
                        let tip = if has_page { "Open this program on VirusTotal" } else { "No VirusTotal result for this program yet" };
                        let b = ui.add_enabled(has_page, egui::Button::new(egui::RichText::new("VirusTotal").font(theme::font(13.5))).min_size(vec2(98.0, 32.0))).on_hover_text(tip);
                        if b.clicked() {
                            crate::sys::open_url(&format!("https://www.virustotal.com/gui/file/{}", app.hash));
                        }
                        let tip = if can_scan { "Scan this program with VirusTotal" } else { "Add a VirusTotal API key in Settings (Live mode)" };
                        let arrow = ui.add_enabled(scan_ok, egui::Button::new("").min_size(vec2(28.0, 32.0))).on_hover_text(tip);
                        // Painted: the UI font has no ▾ glyph (it showed as a box).
                        icons::paint(ui.painter(), Icon::Chevron, Rect::from_center_size(arrow.rect.center(), vec2(12.0, 12.0)), if scan_ok { theme::text() } else { theme::text_dim() });
                        egui::Popup::menu(&arrow).width(160.0).show(|ui| {
                            if app.virustotal != Vt::NotFound && widgets::check_item(ui, false, if app.virustotal == Vt::None { "Scan" } else { "Rescan" }).clicked() {
                                do_scan = true;
                                ui.close();
                            }
                            if app.virustotal == Vt::NotFound && widgets::check_item(ui, false, "Upload file…").clicked() {
                                do_upload = true;
                                ui.close();
                            }
                        });
                        let quick = ui.add(egui::Button::new(egui::RichText::new(label).font(theme::font(13.5))).min_size(vec2(140.0, 32.0)));
                        egui::Popup::menu(&quick).width(240.0).show(|ui| {
                            for (i, (text, inb, out)) in CHOICES.iter().enumerate() {
                                if widgets::check_item(ui, i == current, text).clicked() {
                                    verdicts = Some((*inb, *out));
                                    ui.close();
                                }
                            }
                            // Same row size and font as the verdict items above.
                            ui.style_mut().text_styles.insert(egui::TextStyle::Button, theme::font(15.0));
                            ui.spacing_mut().button_padding = vec2(14.0, 10.0);
                            ui.menu_button("Block all after", |ui| {
                                ui.set_min_width(180.0);
                                for m in crate::app::BLOCK_AFTER_MINS {
                                    if widgets::check_item(ui, false, &format!("{m} minutes")).clicked() {
                                        popup_delay = Some(m);
                                        ui.close();
                                    }
                                }
                            });
                        });
                        let more = ui.add(egui::Button::new(egui::RichText::new("••• More").font(theme::font(13.5))).min_size(vec2(90.0, 32.0)));
                        egui::Popup::menu(&more).width(200.0).show(|ui| {
                            if widgets::check_item(ui, false, "Hide App").clicked() {
                                hide = true;
                                ui.close();
                            }
                            if widgets::check_item(ui, false, "Add to Incognito…").clicked() {
                                incognito = true;
                                ui.close();
                            }
                        });
                    });
                });
        });
        self.protect.show_alerts = show_alerts;
        if do_scan {
            self.backend.scan_virustotal(&key);
        }
        if do_upload {
            self.dialog = Some(Dialog::Confirm(dialogs::virustotal_upload_confirm(&key, &app.name, &app.path)));
        }
        if let Some((inb, out)) = verdicts {
            if app.inbound != inb {
                self.set_verdict(&key, Direction::In, inb);
            }
            if app.outbound != out {
                self.set_verdict(&key, Direction::Out, out);
            }
        }
        if let Some(m) = popup_delay {
            self.block_after(&key, &[Direction::In, Direction::Out], m);
        }
        if block_now {
            // Each direction waiting for its countdown is blocked at once; `set_verdict` also clears it from the pending list.
            let waiting: Vec<Direction> = self.settings.pending_blocks.iter().filter(|p| p.key == key).flat_map(|p| p.directions.clone()).collect();
            for d in waiting {
                self.set_verdict(&key, d, Verdict::Blocked);
            }
        }
        if hide {
            self.settings.hidden_apps.push(key.clone());
            self.protect.selected = None;
            self.commit_settings(&format!("Hid {} (unhide it in Settings > Hidden Apps)", app.name));
        } else if incognito {
            self.protect.selected = None;
            if app.path.is_empty() || self.settings.incognito_apps.iter().any(|p| p.eq_ignore_ascii_case(&app.path)) {
                self.notify("Nothing to add to Incognito for this app");
            } else {
                self.settings.incognito_apps.push(app.path.clone());
                self.commit_settings(&format!("Added {} to Incognito", app.name));
            }
        } else if !opened && ctx.input(|i| i.pointer.any_click()) && !ctx.input(|i| i.pointer.interact_pos()).and_then(|p| ctx.layer_id_at(p)).is_some_and(|l| l.order == egui::Order::Foreground) {
            // Clicks on the popup or its menus land on a Foreground layer; anything else dismisses it.
            self.protect.selected = None;
        }
    }

    /// Asks where to save the firewall rules and writes them there.
    pub(crate) fn export_rules(&mut self) {
        use crate::rules_file::RulesFile;
        let dest: Vec<_> = self.backend.dest_rules().into_iter().map(|v| v.rule).collect();
        let file = RulesFile::collect(&self.backend.firewall_apps(), &dest, &self.settings);
        let Some(path) = crate::sys::save_dialog("Export rules and settings", &format!("RustWarden-rules-{}.json", crate::clock::file_stamp()), "Rules file", "json") else { return };
        match std::fs::write(&path, file.to_text()) {
            Ok(()) => self.notify(&format!("Exported {} program rule(s), {} destination rule(s) and your settings", file.apps.len(), file.dest.len())),
            Err(e) => self.notify(&format!("Couldn't save the rules: {e}")),
        }
    }

    /// Asks which rules file to read and, when it holds something to apply, returns the confirmation to show.
    pub(crate) fn begin_rules_import(&mut self) -> Option<crate::app::Confirm> {
        use crate::rules_file::{RulesFile, current_of};
        if let Some(reason) = self.read_only_reason() {
            self.notify(&reason);
            return None;
        }
        let path = crate::sys::open_dialog("Import rules and settings", "Rules file", "json")?;
        let file = match std::fs::read_to_string(&path).map_err(|e| format!("Couldn't read the file: {e}")).and_then(|t| RulesFile::parse(&t)) {
            Ok(file) => file,
            Err(e) => {
                self.notify(&e);
                return None;
            }
        };
        let dest: Vec<_> = self.backend.dest_rules().into_iter().map(|v| v.rule).collect();
        let plan = file.plan(&current_of(&self.backend.firewall_apps()), &dest);
        if plan.is_empty() {
            self.notify(&plan.summary());
            return None;
        }
        let mut body = format!("This file would make {}.", plan.summary());
        if plan.unlisted > 0 {
            body += &format!(
                "

{} program(s) in it aren't on the Firewall tab right now; RustWarden tries them anyway and skips any it can't find.",
                plan.unlisted
            );
        }
        body += "

Program rules are applied like clicking their chips on the Firewall tab. Destination rules are added. Settings in the file replace yours, except the Demo/Live mode, window position and password; anything the file lacks keeps its current value. No rules are removed.";
        Some(crate::app::Confirm { title: "Import rules and settings?".into(), body, yes: "Import".into(), action: ConfirmAction::ApplyRules(Box::new(file)) })
    }

    /// Saves the settings after an in-place change and tells the backend.
    fn commit_settings(&mut self, message: &str) {
        match self.settings.save() {
            Ok(()) => self.notify(message),
            Err(e) => self.notify(&format!("Couldn't save settings: {e}")),
        }
        self.backend.apply_settings(&self.settings);
        self.reload_protect();
    }

    /// Why firewall changes are refused right now, if they are.
    fn read_only_reason(&self) -> Option<String> {
        self.protect.info.read_only.clone().or_else(|| (self.caps.live && !self.caps.firewall_write).then(|| "the firewall can't be read right now".to_owned()))
    }

    /// The header toggle. Live mode confirms first because it changes what Windows Firewall enforces.
    pub(crate) fn toggle_firewall(&mut self, on: bool) {
        if let Some(reason) = self.read_only_reason() {
            self.notify(&reason);
        } else if self.caps.live {
            self.dialog = Some(Dialog::Confirm(dialogs::firewall_toggle_confirm(on)));
        } else {
            self.run_bg(move |b| b.set_firewall_enabled(on).map(|()| String::new()));
        }
    }

    /// Dropdown pick: confirm first, since the active rules are switched off.
    pub(crate) fn switch_profile(&mut self, name: &str) {
        if let Some(reason) = self.profile_blocked() {
            self.notify(&reason);
        } else {
            self.dialog = Some(Dialog::Confirm(dialogs::profile_confirm(&self.protect.profile, name, false)));
        }
    }

    pub(crate) fn new_profile(&mut self) {
        if let Some(reason) = self.profile_blocked() {
            self.notify(&reason);
        } else {
            self.dialog = Some(Dialog::NewProfile { text: String::new() });
        }
    }

    fn profile_blocked(&self) -> Option<String> {
        if !self.caps.live { Some("Firewall rulesets need Live mode.".into()) } else { self.read_only_reason() }
    }

    pub(crate) fn change_mode(&mut self, mode: FirewallMode) {
        if !self.caps.mode_enabled(mode) {
            let why = match mode {
                FirewallMode::AskToConnect => "Prompt needs administrator rights and a readable Windows Firewall.",
                _ => "This firewall mode isn't available right now.",
            };
            self.notify(why);
            return;
        }
        if let Some(reason) = self.read_only_reason() {
            self.notify(&reason);
        } else if let (true, Some(confirm)) = (self.caps.live, dialogs::mode_confirm(mode)) {
            self.dialog = Some(Dialog::Confirm(confirm));
        } else {
            self.run_bg(set_mode_and_enable(mode, !self.protect.info.enabled));
        }
    }

    /// Starts, restarts or ends the timer on Prompt: a mode switch to Prompt (by any route) starts it, and when it runs out the previous mode returns.
    /// The allow and block rules made from answered prompts are left alone; only Prompt's default-deny is lifted.
    pub(crate) fn poll_prompt_timer(&mut self) {
        let cur = self.protect.info.enabled.then_some(self.protect.info.mode);
        let (timer, back) = prompt_step(self.prompt_seen, cur, self.prompt_timer, self.settings.prompt_minutes, crate::clock::now_unix());
        self.prompt_seen = Some(cur);
        self.prompt_timer = timer;
        if let Some(back) = back {
            self.notify(&format!("Prompt ended: back to {}", back.map_or("Disabled", FirewallMode::label)));
            match back {
                Some(m) => self.run_bg(set_mode_and_enable(m, false)),
                None => self.run_bg(|b| b.set_firewall_enabled(false).map(|()| String::new())),
            }
        }
    }

    /// Picks how long Prompt lasts from now on (0 is Always); a Prompt already running gets the new length.
    pub(crate) fn set_prompt_minutes(&mut self, mins: u32) {
        self.settings.prompt_minutes = mins;
        let _ = self.settings.save();
        if let Some((_, back)) = self.prompt_timer {
            self.prompt_timer = (mins > 0).then(|| (crate::clock::now_unix() + i64::from(mins) * 60, back));
        } else if mins > 0 && self.protect.info.enabled && self.protect.info.mode == FirewallMode::AskToConnect {
            self.prompt_timer = Some((crate::clock::now_unix() + i64::from(mins) * 60, Some(FirewallMode::ClickToBlock)));
        }
    }

    fn remove_app(&mut self, key: &str) {
        if let Some(reason) = self.read_only_reason() {
            self.notify(&reason);
            return;
        }
        let name = self.protect.apps.iter().find(|a| a.key == key).map(|a| a.name.clone()).unwrap_or_default();
        let key = key.to_owned();
        let quiet = self.quiet_jobs.clone();
        quiet.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.run_bg(move |b| {
            let r = b.remove_app(&key).map(|()| format!("Removed {name}"));
            quiet.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            r
        });
    }

    /// When the block waiting for `key` starts, and for which directions ("incoming and outgoing").
    pub(crate) fn block_countdown(&self, key: &str) -> Option<(i64, String)> {
        countdown_of(&self.settings.pending_blocks, key)
    }

    fn block_after(&mut self, key: &str, directions: &[Direction], mins: u64) {
        let name = self.protect.apps.iter().find(|a| a.key == key).map(|a| a.name.clone()).unwrap_or_default();
        self.schedule_block(key, &name, directions, mins);
    }

    /// Saves a block of `directions` for `key` to start in `mins` minutes. Goes through `set_verdict` when due, so Demo and Live behave the same.
    pub(crate) fn schedule_block(&mut self, key: &str, name: &str, directions: &[Direction], mins: u64) {
        if let Some(reason) = self.read_only_reason() {
            self.notify(&reason);
            return;
        }
        let now = crate::clock::now_unix();
        self.settings.pending_blocks.push(PendingBlock { key: key.to_owned(), name: name.to_owned(), directions: directions.to_vec(), started: now, due: now + mins as i64 * 60 });
        self.save_pending(&format!("Will block {name} in {mins} minutes"));
    }

    fn save_pending(&mut self, message: &str) {
        match self.settings.save() {
            Ok(()) => self.notify(message),
            Err(e) => self.notify(&format!("Couldn't save settings: {e}")),
        }
    }

    /// Applies pending blocks whose time has come (also right after a restart, for ones that came due while closed).
    pub(crate) fn poll_pending_blocks(&mut self) {
        let now = crate::clock::now_unix();
        if !self.settings.pending_blocks.iter().any(|p| p.due <= now) {
            return;
        }
        let (due, wait): (Vec<_>, Vec<_>) = std::mem::take(&mut self.settings.pending_blocks).into_iter().partition(|p| p.due <= now);
        self.settings.pending_blocks = wait;
        let _ = self.settings.save();
        for p in due {
            for d in p.directions {
                self.set_verdict(&p.key, d, Verdict::Blocked);
            }
        }
    }

    fn set_verdict(&mut self, key: &str, direction: Direction, verdict: Verdict) {
        // Changing a direction by hand cancels a block still waiting for it.
        let before = self.settings.pending_blocks.len();
        for p in self.settings.pending_blocks.iter_mut().filter(|p| p.key == key) {
            p.directions.retain(|d| *d != direction);
        }
        self.settings.pending_blocks.retain(|p| !p.directions.is_empty());
        if self.settings.pending_blocks.len() != before || self.settings.pending_blocks.iter().any(|p| p.key == key) {
            let _ = self.settings.save();
        }
        if let Some(reason) = self.read_only_reason() {
            self.notify(&reason);
            return;
        }
        let name = self.protect.apps.iter().find(|a| a.key == key).map(|a| a.name.clone()).unwrap_or_default();
        // The firewall call takes 0.5-2 s, so the row flips now and the call runs on a thread; a failure reloads the real state.
        if let Some(a) = self.protect.apps.iter_mut().find(|a| a.key == key) {
            match direction {
                Direction::In => a.inbound = verdict,
                Direction::Out => a.outbound = verdict,
                Direction::Local => a.local = verdict,
            }
        }
        let dir = match direction {
            Direction::In => "incoming",
            Direction::Out => "outgoing",
            Direction::Local => "local network",
        };
        let what = if verdict == Verdict::Blocked { "Blocked" } else { "Allowed" };
        let off = if self.protect.info.enabled { "" } else { " (the RustWarden firewall is off: turn it on to enforce)" };
        let msg = format!("{what} {dir} connections for {name}{off}");
        let (backend, slot, key) = (self.backend.clone(), self.verdicts.clone(), key.to_owned());
        slot.lock().unwrap_or_else(|e| e.into_inner()).0 += 1;
        std::thread::spawn(move || {
            let r = backend.set_verdict(&key, direction, verdict).map(|()| msg);
            let mut s = slot.lock().unwrap_or_else(|e| e.into_inner());
            s.0 -= 1;
            s.1.push(r);
        });
    }

    fn banner_action(&mut self, ctx: &egui::Context) {
        match &self.protect.info.engine {
            EngineState::WindowsFirewallOff => {
                self.dialog = Some(Dialog::Confirm(Confirm {
                    title: "Turn on Windows Firewall?".into(),
                    body: "RustWarden's rules only work while Windows Firewall is on. This turns Windows Firewall on for all network profiles (domain, private and public). Other rules and default actions are left as they are.".into(),
                    yes: "Turn on Windows Firewall".into(),
                    action: ConfirmAction::WindowsFirewallOn,
                }));
            }
            _ if self.protect.info.block_all_active => {
                self.run_bg(|b| b.set_firewall_mode(FirewallMode::ClickToBlock).map(|()| String::new()));
            }
            // "Review": bring every waiting Prompt prompt to the front.
            EngineState::Ready if self.protect.info.mode == FirewallMode::AskToConnect && !self.asks.is_empty() => {
                for (id, ..) in &self.asks {
                    ctx.send_viewport_cmd_to(egui::ViewportId::from_hash_of(("ask", *id)), egui::ViewportCommand::Focus);
                }
            }
            _ if !self.caps.elevated => {
                self.notify("Use \"Restart as administrator\" in the strip above.");
            }
            _ => {}
        }
    }
}

const VT_HOLD_TIP: &str =
    "VirusTotal lookups failed several times in a row, usually because the free API key's quota ran out. All lookups are paused for 6 hours to avoid exhausting it. Saving a new key resumes them.";

/// Moves the member satisfying `is_held` to position `at` (or the end), leaving the others in order.
fn hold_in_place(members: &mut Vec<usize>, is_held: impl Fn(usize) -> bool, at: usize) {
    if let Some(pos) = members.iter().position(|&i| is_held(i)) {
        let m = members.remove(pos);
        members.insert(at.min(members.len()), m);
    }
}

/// One poll of the Prompt timer: the timer to keep and, when it ran out, the mode to go back to.
/// `seen` is the mode at the previous poll (`None` before the first), `cur` the mode now (`None` inside is Disabled).
#[allow(clippy::type_complexity)]
fn prompt_step(
    seen: Option<Option<FirewallMode>>,
    cur: Option<FirewallMode>,
    timer: Option<(i64, Option<FirewallMode>)>,
    mins: u32,
    now: i64,
) -> (Option<(i64, Option<FirewallMode>)>, Option<Option<FirewallMode>>) {
    if cur != Some(FirewallMode::AskToConnect) {
        return (None, None);
    }
    match timer {
        Some((until, back)) if until <= now => (None, Some(back)),
        Some(t) => (Some(t), None),
        // Only a switch seen happening starts it, not a Prompt left over from the last run.
        None => match seen {
            Some(back) if mins > 0 && back != cur => (Some((now + i64::from(mins) * 60, back)), None),
            _ => (None, None),
        },
    }
}

/// Picking a mode from "Disabled" also switches the firewall back on.
pub(crate) fn set_mode_and_enable(mode: FirewallMode, enable: bool) -> impl FnOnce(&dyn Backend) -> Result<String, String> + Send + 'static {
    move |b| {
        b.set_firewall_mode(mode)?;
        if enable {
            b.set_firewall_enabled(true)?;
        }
        Ok(String::new())
    }
}

/// The VirusTotal row text and colour shown in app info panels.
pub(crate) fn vt_label(vt: &Vt) -> (String, Color32) {
    match vt {
        Vt::Result { bad, total } => (format!("{bad}/{total}"), if *bad > 0 { theme::red() } else { theme::green() }),
        Vt::NotFound => ("Not found".into(), theme::text_dim()),
        Vt::Pending => ("Scanning…".into(), theme::text_dim()),
        Vt::Analysing => ("Analysing…".into(), theme::text_dim()),
        Vt::Skipped => ("Skipped (over 32MB)".into(), theme::text_dim()),
        Vt::Failed => ("Failed".into(), theme::red()),
        Vt::OnHold => ("On Hold".into(), theme::text_dim()),
        Vt::None => ("Unscanned".into(), theme::text_dim()),
    }
}

fn banner_text(info: &FirewallInfo, waiting: usize) -> Option<(String, Option<&'static str>)> {
    if info.block_all_active {
        return Some(("Block All is active: most programs have no internet access.".into(), Some("Undo Block All")));
    }
    if let Some(reason) = &info.read_only {
        return Some((format!("Read-only: {reason}"), None));
    }
    match &info.engine {
        EngineState::WindowsFirewallOff => Some(("Windows Firewall is off, so RustWarden's rules have no effect.".into(), Some("Turn on Windows Firewall"))),
        EngineState::Unavailable(why) => Some((format!("Firewall unavailable: {why}"), None)),
        EngineState::Ready if info.enabled && info.mode == FirewallMode::AskToConnect => {
            let text = match waiting {
                0 => "Prompt is on: new programs are blocked until you answer.".to_owned(),
                1 => "Prompt is on: new programs are blocked until you answer. 1 program is waiting for an answer.".to_owned(),
                n => format!("Prompt is on: new programs are blocked until you answer. {n} programs are waiting for an answer."),
            };
            Some((text, (waiting > 0).then_some("Review")))
        }
        EngineState::Ready => None,
    }
}

/// The earliest start among the blocks waiting for `key`, with the directions of all of them ("incoming and outgoing").
/// `None` when nothing is scheduled for it.
fn countdown_of(blocks: &[PendingBlock], key: &str) -> Option<(i64, String)> {
    let mut waiting: Vec<_> = blocks.iter().filter(|p| p.key == key).collect();
    waiting.sort_by_key(|p| p.due);
    let first = waiting.first()?;
    let mut names: Vec<&str> = Vec::new();
    for d in waiting.iter().flat_map(|p| p.directions.iter()) {
        let n = match d {
            Direction::In => "incoming",
            Direction::Out => "outgoing",
            Direction::Local => "local network",
        };
        if !names.contains(&n) {
            names.push(n);
        }
    }
    let what = match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => names.join(""),
    };
    Some((first.due, what))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_row_keeps_its_place_while_others_move() {
        // The held app (3) was second; the list now puts it last and has a new app (9) first.
        let mut m = vec![9, 1, 2, 3];
        hold_in_place(&mut m, |i| i == 3, 1);
        assert_eq!(m, [9, 3, 1, 2]);
        // A position past the end clamps; a held app that vanished changes nothing.
        hold_in_place(&mut m, |i| i == 9, 50);
        assert_eq!(m, [3, 1, 2, 9]);
        hold_in_place(&mut m, |i| i == 77, 0);
        assert_eq!(m, [3, 1, 2, 9]);
    }

    fn block(key: &str, directions: &[Direction], due: i64) -> PendingBlock {
        PendingBlock { key: key.into(), name: "x".into(), directions: directions.to_vec(), started: 0, due }
    }

    #[test]
    fn countdown_is_the_earliest_block_of_that_app() {
        let blocks = [block("a", &[Direction::In, Direction::Out], 900), block("b", &[Direction::Local], 100), block("a", &[Direction::Local], 500)];
        assert_eq!(countdown_of(&blocks, "a"), Some((500, "local network, incoming and outgoing".into())));
        assert_eq!(countdown_of(&blocks, "b"), Some((100, "local network".into())));
        assert_eq!(countdown_of(&blocks, "c"), None);
    }

    #[test]
    fn prompt_timer_starts_on_a_seen_switch_and_reverts() {
        use FirewallMode::*;
        let step = prompt_step;
        let (t, back) = step(Some(Some(ClickToBlock)), Some(AskToConnect), None, 10, 1000);
        assert_eq!((t, back), (Some((1600, Some(ClickToBlock))), None));
        assert_eq!(step(Some(Some(AskToConnect)), Some(AskToConnect), t, 10, 1599).0, t);
        assert_eq!(step(Some(Some(AskToConnect)), Some(AskToConnect), t, 10, 1600), (None, Some(Some(ClickToBlock))));
        // Always (0), a Prompt left from the last run, and leaving Prompt by hand never time out.
        assert_eq!(step(Some(Some(ClickToBlock)), Some(AskToConnect), None, 0, 1000), (None, None));
        assert_eq!(step(None, Some(AskToConnect), None, 10, 1000), (None, None));
        assert_eq!(step(Some(Some(AskToConnect)), Some(BlockAll), t, 10, 1000), (None, None));
    }
}
