use super::row_in;
use crate::app::RustWarden;
use crate::data::DnsEntry;
use crate::theme;
use crate::widgets;
use egui::{Align2, Color32, Rect, Stroke, Ui, pos2, vec2};
use std::time::{Duration, Instant};

const ROW_H: f32 = 30.0;

impl RustWarden {
    pub(crate) fn dns_tab(&mut self, ui: &mut Ui) {
        // The backend read is a database query: once a second is plenty for a log.
        if self.dns.loaded.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
            let backend = self.backend.clone();
            self.dns_bg.request(move || backend.dns_log());
            self.dns.loaded = Some(Instant::now());
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));

        let full = ui.max_rect();
        let bar = Rect::from_min_size(full.min + vec2(12.0, 12.0), vec2(full.width() - 24.0, 56.0));
        let table = Rect::from_min_max(pos2(bar.left(), bar.bottom() + 12.0), full.max - vec2(12.0, 12.0));
        for r in [bar, table] {
            ui.painter().rect_filled(r, 8, theme::card());
            ui.painter().rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
        }

        let query = self.dns.search.clone();
        let shown: Vec<&DnsEntry> = self.dns.entries.iter().filter(|e| e.matches(&query)).collect();
        row_in(ui, bar.shrink2(vec2(14.0, 0.0)), |ui| {
            widgets::search_box(ui, &mut self.dns.search, (full.width() * 0.3).clamp(160.0, 360.0));
            ui.label(egui::RichText::new(format!("{} of {} lookups", shown.len(), self.dns.entries.len())).color(theme::text_dim()));
        });

        let body = table;
        if shown.is_empty() {
            let why = if self.dns.entries.is_empty() {
                if self.caps.live && !self.caps.elevated {
                    "DNS lookups can only be recorded when RustWarden runs as administrator."
                } else if !self.settings.dns_log {
                    "DNS logging is off (Settings > General)."
                } else {
                    "No lookups recorded yet."
                }
            } else {
                "No lookups match the search."
            };
            ui.painter().text(body.center(), Align2::CENTER_CENTER, why, theme::font(16.0), theme::text_dim());
            return;
        }

        // Columns: time, process, name, type, addresses (what is left), status.
        let area = body.shrink2(vec2(16.0, 4.0));
        if self.dns.cols.len() != 5 {
            self.dns.cols = vec![0.07, 0.22, 0.45, 0.51, 0.85];
        }
        let mut edges = std::mem::take(&mut self.dns.cols);
        ui.scope_builder(egui::UiBuilder::new().max_rect(area), |ui| {
            let head = theme::bold(14.0);
            let (r, _) = ui.allocate_exact_size(vec2(area.width(), 34.0), egui::Sense::hover());
            widgets::column_handles(ui, "dns_resize", r, &mut edges, 0.0, 1.0);
            let w = area.width();
            let cols = [0.0, edges[0] * w, edges[1] * w, edges[2] * w, edges[3] * w];
            let ips_end = edges[4] * w;
            for (x, label) in cols.iter().zip(["Time", "Process", "Query name", "Type", "Result"]).chain([(&ips_end, "Status")]) {
                ui.painter().text(pos2(r.left() + x + 4.0, r.center().y), Align2::LEFT_CENTER, label, head.clone(), theme::text_dim());
            }
            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, shown.len(), |ui, range| {
                for e in &shown[range] {
                    let (r, _) = ui.allocate_exact_size(vec2(area.width(), ROW_H), egui::Sense::hover());
                    let p = ui.painter();
                    let cell = |x0: f32, x1: f32, text: &str, color: Color32| {
                        let clip = Rect::from_x_y_ranges(r.left() + x0..=r.left() + x1 - 4.0, r.y_range());
                        p.with_clip_rect(clip).text(pos2(r.left() + x0 + 4.0, r.center().y), Align2::LEFT_CENTER, text, theme::font(14.0), color);
                    };
                    let result = if e.ips.is_empty() { "-".to_owned() } else { e.ips.join(", ") };
                    let status_color = if e.ok() { Color32::from_rgb(0x3f, 0x9e, 0x2f) } else { Color32::from_rgb(0xd0, 0x45, 0x3a) };
                    cell(cols[0], cols[1], &crate::clock::fmt_time_lower(e.ts), theme::text_dim());
                    cell(cols[1], cols[2], &e.app, theme::text());
                    cell(cols[2], cols[3], &e.name, if e.listed { Color32::from_rgb(0xd0, 0x45, 0x3a) } else { theme::text() });
                    cell(cols[3], cols[4], &e.type_label(), theme::text_dim());
                    cell(cols[4], ips_end, &result, theme::text());
                    cell(ips_end, area.width(), &e.status_label(), status_color);
                    p.hline(r.x_range(), r.bottom(), Stroke::new(1.0, theme::border().gamma_multiply(0.5)));
                }
            });
        });
        self.dns.cols = edges;
    }
}
