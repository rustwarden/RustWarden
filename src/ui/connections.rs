use super::row_in;
use crate::app::{Confirm, ConfirmAction, Dialog, RustWarden};
use crate::data::{Country, LiveConn};
use crate::icons::flag;
use crate::theme;
use crate::util::fmt_bytes;
use crate::widgets;
use egui::{Align2, Color32, Rect, Stroke, Ui, pos2, vec2};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

const ROW_H: f32 = 30.0;

enum Act {
    Capture(LiveConn),
    Kill(LiveConn),
    Block(std::net::IpAddr),
}

/// How the table is split into collapsible groups.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ConnGroup {
    #[default]
    None,
    Process,
    State,
    Country,
}

impl ConnGroup {
    const ALL: [ConnGroup; 4] = [Self::None, Self::Process, Self::State, Self::Country];

    fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Process => "Process",
            Self::State => "State",
            Self::Country => "Country",
        }
    }

    /// The group a connection falls in.
    fn key_of(self, c: &LiveConn) -> String {
        match self {
            Self::None => String::new(),
            Self::Process => c.app.clone(),
            Self::State => c.state.clone(),
            Self::Country => c.country.map_or("Unknown", |k| k.name()).to_owned(),
        }
    }
}

/// "45s", "12m 3s", "5h 20m", "2d 4h": how long a connection has been open.
pub fn fmt_age(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {}s", s / 60, s % 60),
        3600..=86_399 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d {}h", s / 86_400, s % 86_400 / 3600),
    }
}

const HEADERS: [&str; 7] = ["Process", "State", "Host / IP", "Port", "Duration", "Received", "Sent"];

/// Orders two connections by header column `col`.
fn compare(col: usize, a: &LiveConn, b: &LiveConn) -> std::cmp::Ordering {
    let host = |c: &LiveConn| if c.host.is_empty() { c.remote.ip().to_string() } else { c.host.to_lowercase() };
    match col {
        0 => a.app.to_lowercase().cmp(&b.app.to_lowercase()).then(a.pid.cmp(&b.pid)),
        1 => a.state.cmp(&b.state),
        2 => host(a).cmp(&host(b)),
        3 => a.remote.port().cmp(&b.remote.port()),
        // Ascending is longest-open first; a connection with no known start sorts last.
        4 => a.since.unwrap_or(i64::MAX).cmp(&b.since.unwrap_or(i64::MAX)),
        5 => a.bytes.map(|x| x.0).cmp(&b.bytes.map(|x| x.0)),
        _ => a.bytes.map(|x| x.1).cmp(&b.bytes.map(|x| x.1)),
    }
}

/// One line of the table: a group heading or a connection.
enum Line<'a> {
    Group { name: String, country: Option<Country>, count: usize, bytes: (u64, u64), open: bool },
    Conn(&'a LiveConn),
}

/// Sorts `shown` and, if grouped, lays it out as headings with their connections beneath (folded groups show the heading only).
fn lines<'a>(mut shown: Vec<&'a LiveConn>, sort: Option<(usize, bool)>, group: ConnGroup, collapsed: &HashSet<String>) -> Vec<Line<'a>> {
    if let Some((col, asc)) = sort {
        shown.sort_by(|a, b| if asc { compare(col, a, b) } else { compare(col, b, a) });
    }
    if group == ConnGroup::None {
        return shown.into_iter().map(Line::Conn).collect();
    }
    let mut groups: BTreeMap<String, Vec<&LiveConn>> = BTreeMap::new();
    for c in shown {
        groups.entry(group.key_of(c)).or_default().push(c);
    }
    let mut out = Vec::new();
    for (name, conns) in groups {
        let bytes = conns.iter().filter_map(|c| c.bytes).fold((0, 0), |t, b| (t.0 + b.0, t.1 + b.1));
        let open = !collapsed.contains(&name);
        let country = if group == ConnGroup::Country { conns[0].country } else { None };
        out.push(Line::Group { name, country, count: conns.len(), bytes, open });
        if open {
            out.extend(conns.into_iter().map(Line::Conn));
        }
    }
    out
}

impl RustWarden {
    pub(crate) fn connections_tab(&mut self, ui: &mut Ui) {
        // Reading the TCP table (and its byte counters) takes a moment, so it runs on the worker.
        if self.conns.loaded.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
            let backend = self.backend.clone();
            self.conns_bg.request(move || backend.live_connections());
            self.conns.loaded = Some(Instant::now());
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));

        let full = ui.max_rect();
        let bar = Rect::from_min_size(full.min + vec2(12.0, 12.0), vec2(full.width() - 24.0, 56.0));
        let table = Rect::from_min_max(pos2(bar.left(), bar.bottom() + 12.0), full.max - vec2(12.0, 12.0));
        for r in [bar, table] {
            ui.painter().rect_filled(r, 8, theme::card());
            ui.painter().rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
        }

        let query = self.conns.search.clone();
        let total = self.conns.entries.len();
        let matched: Vec<&LiveConn> = self.conns.entries.iter().filter(|c| c.matches(&query)).collect();
        let n_shown = matched.len();
        let mut group = self.conns.group;
        let driver = crate::driver::in_use(&self.settings);
        let capture = if driver { self.backend.capture_status() } else { None };
        let mut stop_capture = false;
        row_in(ui, bar.shrink2(vec2(14.0, 0.0)), |ui| {
            widgets::search_box(ui, &mut self.conns.search, (full.width() * 0.3).clamp(160.0, 360.0));
            ui.label(egui::RichText::new(format!("{n_shown} of {total} connections")).color(theme::text_dim()));
            if let Some(cap) = &capture {
                ui.add_space(12.0);
                ui.label(egui::RichText::new(format!("Capturing {}: {} packets, {}", cap.what, cap.packets, fmt_bytes(cap.bytes as f64))).color(theme::accent_text())).on_hover_text(&cap.path);
                if widgets::pill_button(ui, None, "Stop", false, 60.0).clicked() {
                    stop_capture = true;
                }
            }
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Group by").color(theme::text_dim()));
            let resp = widgets::pill_button(ui, None, group.label(), true, 110.0);
            egui::Popup::menu(&resp).show(|ui| {
                for g in ConnGroup::ALL {
                    if widgets::check_item(ui, group == g, g.label()).clicked() {
                        group = g;
                        ui.close();
                    }
                }
            });
        });
        self.conns.group = group;
        let rows = lines(matched, self.conns.sort, group, &self.conns.collapsed);

        if n_shown == 0 {
            let why = if total == 0 { "No open connections." } else { "No connections match the search." };
            ui.painter().text(table.center(), Align2::CENTER_CENTER, why, theme::font(16.0), theme::text_dim());
            return;
        }

        // Ending a connection and blocking an address both change the system: administrator only in Live mode.
        let may_act = !self.caps.live || self.caps.elevated;
        let no_admin = "Needs administrator rights. Use \"Restart as administrator\".";
        let mut act = None;
        let mut toggle: Option<String> = None;
        let mut sort = self.conns.sort;
        let now = crate::clock::now_unix();

        let area = table.shrink2(vec2(16.0, 4.0));
        let act_w = 150.0;
        let data_w = (area.width() - act_w).max(300.0);
        if self.conns.cols.len() != 6 {
            self.conns.cols = vec![0.19, 0.29, 0.57, 0.64, 0.74, 0.87];
        }
        let mut edges = std::mem::take(&mut self.conns.cols);
        ui.scope_builder(egui::UiBuilder::new().max_rect(area), |ui| {
            let head = theme::bold(14.0);
            let (r, _) = ui.allocate_exact_size(vec2(area.width(), 34.0), egui::Sense::hover());
            let head_data = Rect::from_min_size(r.min, vec2(data_w, r.height()));
            let cols = [0.0, edges[0] * data_w, edges[1] * data_w, edges[2] * data_w, edges[3] * data_w, edges[4] * data_w, edges[5] * data_w, data_w];
            // Click a header to sort by it; click again to reverse, a third time to reset. Registered before the resize handles, which win at the borders.
            for (i, label) in HEADERS.iter().enumerate() {
                let cell = Rect::from_x_y_ranges(r.left() + cols[i]..=r.left() + cols[i + 1], r.y_range());
                let resp = ui.interact(cell, ui.scope_id().with(("conn_head", i)), egui::Sense::click());
                if resp.clicked() {
                    sort = match sort {
                        Some((c, true)) if c == i => Some((i, false)),
                        Some((c, false)) if c == i => None,
                        _ => Some((i, true)),
                    };
                }
                let active = sort.is_some_and(|(c, _)| c == i);
                let color = if active || resp.hovered() { theme::text() } else { theme::text_dim() };
                let w = ui.painter().with_clip_rect(cell).text(pos2(cell.left() + 4.0, r.center().y), Align2::LEFT_CENTER, *label, head.clone(), color).width();
                if let Some((_, asc)) = sort.filter(|_| active) {
                    let (mx, my) = (cell.left() + 4.0 + w + 10.0, r.center().y);
                    if mx < cell.right() - 4.0 {
                        let tri = if asc { [pos2(mx - 4.0, my + 2.5), pos2(mx + 4.0, my + 2.5), pos2(mx, my - 3.0)] } else { [pos2(mx - 4.0, my - 2.5), pos2(mx + 4.0, my - 2.5), pos2(mx, my + 3.0)] };
                        ui.painter().add(egui::Shape::convex_polygon(tri.to_vec(), theme::accent_text(), Stroke::NONE));
                    }
                }
            }
            widgets::column_handles(ui, "conn_resize", head_data, &mut edges, 0.0, 1.0);
            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, rows.len(), |ui, range| {
                for line in &rows[range] {
                    let (r, resp) = ui.allocate_exact_size(vec2(area.width(), ROW_H), egui::Sense::click());
                    let p = ui.painter();
                    let cell = |x0: f32, x1: f32, text: &str, color: Color32| {
                        let clip = Rect::from_x_y_ranges(r.left() + x0..=r.left() + x1 - 4.0, r.y_range());
                        p.with_clip_rect(clip).text(pos2(r.left() + x0 + 4.0, r.center().y), Align2::LEFT_CENTER, text, theme::font(14.0), color)
                    };
                    let bytes = |n: Option<u64>| n.map_or("-".to_owned(), |n| fmt_bytes(n as f64));
                    let c = match line {
                        Line::Group { name, country, count, bytes: (rx, tx), open } => {
                            p.rect_filled(r, 0, theme::nav_on());
                            let (mx, my) = (r.left() + 12.0, r.center().y);
                            let tri =
                                if *open { [pos2(mx - 4.0, my - 2.5), pos2(mx + 4.0, my - 2.5), pos2(mx, my + 3.0)] } else { [pos2(mx - 2.5, my - 4.0), pos2(mx - 2.5, my + 4.0), pos2(mx + 3.0, my)] };
                            p.add(egui::Shape::convex_polygon(tri.to_vec(), theme::text_dim(), Stroke::NONE));
                            let mut x = 26.0;
                            if let Some(k) = country {
                                flag(p, *k, Rect::from_min_size(pos2(r.left() + x, my - 7.0), vec2(22.0, 15.0)));
                                x += 28.0;
                            }
                            cell(x, cols[5], &format!("{name}  ({count})"), theme::text());
                            cell(cols[5], cols[6], &bytes(Some(*rx)), theme::text_dim());
                            cell(cols[6], cols[7], &bytes(Some(*tx)), theme::text_dim());
                            p.hline(r.x_range(), r.bottom(), Stroke::new(1.0, theme::border().gamma_multiply(0.5)));
                            if resp.clicked() {
                                toggle = Some(name.clone());
                            }
                            continue;
                        }
                        Line::Conn(c) => *c,
                    };
                    let indent = if group == ConnGroup::None { 0.0 } else { 14.0 };
                    let proc = format!("{} ({})", c.app, c.pid);
                    let w = cell(cols[0] + indent, cols[1], &proc, theme::text()).width();
                    // The country flag follows the process name, when the column is wide enough for it.
                    if let Some(k) = c.country {
                        let fx = cols[0] + indent + 4.0 + w + 8.0;
                        if fx + 22.0 < cols[1] - 4.0 {
                            flag(p, k, Rect::from_min_size(pos2(r.left() + fx, r.center().y - 7.0), vec2(22.0, 15.0)));
                        }
                    }
                    let host = if c.host.is_empty() { c.remote.ip().to_string() } else { format!("{}  ({})", c.host, c.remote.ip()) };
                    cell(cols[1], cols[2], &c.state, theme::text_dim());
                    cell(cols[2], cols[3], &host, theme::text());
                    cell(cols[3], cols[4], &c.remote.port().to_string(), theme::text());
                    cell(cols[4], cols[5], &c.since.map_or("-".to_owned(), |t| fmt_age(now - t)), theme::text_dim());
                    cell(cols[5], cols[6], &bytes(c.bytes.map(|b| b.0)), theme::text_dim());
                    cell(cols[6], cols[7], &bytes(c.bytes.map(|b| b.1)), theme::text_dim());
                    p.hline(r.x_range(), r.bottom(), Stroke::new(1.0, theme::border().gamma_multiply(0.5)));

                    if driver && may_act {
                        resp.context_menu(|ui| {
                            if ui.button("Capture this connection to a .pcap file").clicked() {
                                act = Some(Act::Capture(c.clone()));
                                ui.close();
                            }
                        });
                    }
                    let btn = |x: f32| Rect::from_min_size(pos2(r.left() + cols[7] + x + 4.0, r.top() + 3.0), vec2(66.0, ROW_H - 6.0));
                    let kill_tip = if !c.killable {
                        "Windows can only end established IPv4 connections. Block the address instead."
                    } else if !may_act {
                        no_admin
                    } else {
                        "End this connection"
                    };
                    if ui.put(btn(0.0), egui::Button::new("End").small()).on_hover_text(kill_tip).clicked() && c.killable && may_act {
                        act = Some(Act::Kill(c.clone()));
                    }
                    let block_tip = if may_act { "Block this address in both directions" } else { no_admin };
                    if ui.put(btn(70.0), egui::Button::new("Block").small()).on_hover_text(block_tip).clicked() && may_act {
                        act = Some(Act::Block(c.remote.ip()));
                    }
                }
            });
        });

        self.conns.cols = edges;
        self.conns.sort = sort;
        if let Some(name) = toggle
            && !self.conns.collapsed.remove(&name)
        {
            self.conns.collapsed.insert(name);
        }
        if stop_capture {
            self.backend.stop_capture();
        }
        match act {
            Some(Act::Capture(c)) => self.run_bg(move |b| b.start_capture(&c).map(|path| format!("Capturing to {path}"))),
            Some(Act::Kill(c)) => {
                self.dialog = Some(Dialog::Confirm(Confirm {
                    title: "End this connection?".into(),
                    body: format!("{} (PID {}) will lose its connection to {}. The program may simply open a new one.", c.app, c.pid, c.remote),
                    yes: "End connection".into(),
                    action: ConfirmAction::KillConnection(c),
                }));
            }
            Some(Act::Block(ip)) => self.run_bg(move |b| b.block_remote(ip)),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(app: &str, pid: u32, remote: &str) -> LiveConn {
        LiveConn {
            pid,
            app: app.into(),
            state: "Established".into(),
            local: "10.0.0.1:5000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            host: String::new(),
            bytes: None,
            killable: true,
            country: None,
            since: None,
        }
    }

    #[test]
    fn ages_read_naturally() {
        assert_eq!(fmt_age(5), "5s");
        assert_eq!(fmt_age(125), "2m 5s");
        assert_eq!(fmt_age(3 * 3600 + 20 * 60), "3h 20m");
        assert_eq!(fmt_age(2 * 86_400 + 4 * 3600), "2d 4h");
        assert_eq!(fmt_age(-3), "0s");
    }

    #[test]
    fn sorts_by_port_both_ways() {
        let (a, b) = (conn("a", 1, "1.1.1.1:443"), conn("b", 2, "2.2.2.2:80"));
        let asc = lines(vec![&a, &b], Some((3, true)), ConnGroup::None, &HashSet::new());
        assert!(matches!(&asc[0], Line::Conn(c) if c.app == "b"));
        let desc = lines(vec![&a, &b], Some((3, false)), ConnGroup::None, &HashSet::new());
        assert!(matches!(&desc[0], Line::Conn(c) if c.app == "a"));
    }

    #[test]
    fn groups_by_process_and_folds() {
        let (a, b, c) = (conn("x.exe", 1, "1.1.1.1:443"), conn("y.exe", 2, "2.2.2.2:80"), conn("x.exe", 3, "3.3.3.3:80"));
        let open = lines(vec![&a, &b, &c], None, ConnGroup::Process, &HashSet::new());
        assert_eq!(open.len(), 5);
        assert!(matches!(&open[0], Line::Group { name, count: 2, .. } if name == "x.exe"));
        let folded = lines(vec![&a, &b, &c], None, ConnGroup::Process, &HashSet::from(["x.exe".to_owned()]));
        assert_eq!(folded.len(), 3);
    }
}
