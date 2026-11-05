use crate::app::RustWarden;
use crate::theme;
use crate::util::{fmt_clock_secs, fmt_size};
use crate::widgets;
use egui::{Align2, Panel, Rect, Stroke, Ui, pos2, vec2};
use std::time::Duration;

const WINDOW_SECS: usize = 300;

/// Selectable chart ranges in minutes; Live mode offers those the history setting covers.
const RANGES: [u32; 6] = [5, 60, 360, 1440, 10_080, 43_200];

fn range_label(mins: u32) -> &'static str {
    match mins {
        5 => "5 Minutes",
        60 => "1 Hour",
        360 => "6 Hours",
        1440 => "24 Hours",
        10_080 => "7 Days",
        _ => "30 Days",
    }
}

/// Title, label of the top of the scale, value of one sample, top of the scale.
type Chart = (&'static str, String, Box<dyn Fn(&crate::data::HardwareSample) -> f32>, f32);

impl RustWarden {
    pub(crate) fn hardware_tab(&mut self, ui: &mut Ui) {
        let hw = self.backend.hardware(WINDOW_SECS);
        let now_secs = hw.now_secs;
        ui.ctx().request_repaint_after(Duration::from_millis(500));

        // The six readings sit on one card, like the Traffic tab's totals.
        Panel::bottom("hardware_stats").exact_size(104.0).frame(egui::Frame::NONE).show(ui, |ui| {
            let r = ui.max_rect().shrink2(vec2(12.0, 8.0));
            let p = ui.painter();
            p.rect_filled(r, 8, theme::card());
            p.rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
            let stats = [
                (format!("{:.0} %", hw.cpu_pct), "CPU Usage"),
                (fmt_size(hw.memory_used), "Memory Usage"),
                (format!("{}/s", fmt_size(hw.disk_read).replace(".0", "")), "Disk Read"),
                (format!("{}/s", fmt_size(hw.disk_write).replace(".0", "")), "Disk Write"),
                (format!("{:.0} %", hw.gpu_pct), "GPU Usage"),
                (fmt_size(hw.gpu_memory), "GPU Memory"),
            ];
            let w = r.width() / stats.len() as f32;
            for (i, (value, label)) in stats.iter().enumerate() {
                let cx = r.left() + w * (i as f32 + 0.5);
                if i > 0 {
                    p.vline(r.left() + w * i as f32, (r.top() + 18.0)..=(r.bottom() - 18.0), Stroke::new(1.0, theme::border()));
                }
                p.text(pos2(cx, r.center().y - 10.0), Align2::CENTER_CENTER, value, theme::bold(18.0), theme::text());
                p.text(pos2(cx, r.center().y + 14.0), Align2::CENTER_CENTER, label, theme::font(15.0), theme::text_dim());
            }
        });

        let full = ui.available_rect_before_wrap();
        let toolbar = Rect::from_min_size(full.min + vec2(12.0, 12.0), vec2(full.width() - 24.0, 48.0));
        let p = ui.painter().clone();
        let chart_card = Rect::from_min_max(pos2(toolbar.left(), toolbar.bottom() + 12.0), full.max - vec2(12.0, 12.0));
        for r in [toolbar, chart_card] {
            p.rect_filled(r, 8, theme::card());
            p.rect_stroke(r, 8, Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
        }
        let toolbar = toolbar.shrink2(vec2(12.0, 0.0));

        // Live mode can look back as far as the hardware history setting allows.
        let max_mins = self.settings.hardware_history_hours * 60;
        let ranges: Vec<u32> = RANGES.iter().copied().filter(|&m| m == 5 || m <= max_mins).collect();
        let mins = ranges.iter().copied().rfind(|&m| m <= self.settings.hardware_range_mins).unwrap_or(5);
        if ranges.len() > 1 {
            let mut pick = mins;
            let r = Rect::from_min_size(pos2(toolbar.right() - 130.0, toolbar.top() + 8.0), vec2(130.0, 32.0));
            ui.scope_builder(egui::UiBuilder::new().max_rect(r), |ui| {
                egui::ComboBox::from_id_salt("hw_range").selected_text(range_label(mins)).width(120.0).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                    for &m in &ranges {
                        ui.selectable_value(&mut pick, m, range_label(m));
                    }
                });
            });
            if pick != mins {
                self.settings.hardware_range_mins = pick;
                if let Err(e) = self.settings.save() {
                    self.notify(&format!("Couldn't save settings: {e}"));
                }
            }
        } else {
            p.text(pos2(toolbar.right() - 8.0, toolbar.center().y), Align2::RIGHT_CENTER, range_label(mins), theme::font(15.0), theme::text_dim());
        }

        // Filter: chart one program's history instead of the whole machine (Demo has sample programs).
        let app_id = egui::Id::unique("hw_app_filter");
        // Stored as the Option itself, so it has to be read back as one (a String read never matches).
        let mut app: Option<String> = ui.data(|d| d.get_temp::<Option<String>>(app_id)).flatten();
        {
            let secs = i64::from(mins.max(5)) * 60;
            let backend = self.backend.clone();
            let apps = self.hw_apps.get(secs, Duration::from_secs(5), move || backend.hardware_apps(secs)).cloned().unwrap_or_default();
            let r = Rect::from_min_size(pos2(toolbar.left(), toolbar.top() + 8.0), vec2(220.0, 32.0));
            ui.scope_builder(egui::UiBuilder::new().max_rect(r), |ui| {
                egui::ComboBox::from_id_salt("hw_filter")
                    .selected_text(app.as_deref().map_or("Filter: All apps".to_owned(), |a| format!("Filter: {a}")))
                    .width(200.0)
                    .truncate()
                    .icon(crate::widgets::combo_icon)
                    .show_ui(ui, |ui| {
                        if crate::widgets::check_item(ui, app.is_none(), "All apps").clicked() {
                            app = None;
                            ui.close();
                        }
                        for a in apps {
                            // The list holds names only; the Firewall list has the icon and path for them.
                            let known = self.protect.apps.iter().find(|k| k.name == a);
                            let on = app.as_deref() == Some(a.as_str());
                            if crate::widgets::check_item_icon(ui, on, &a, known.map(|k| (k.icon, k.path.as_str()))).clicked() {
                                app = Some(a.clone());
                                ui.close();
                            }
                        }
                    });
            });
            ui.data_mut(|d| d.insert_temp(app_id, app.clone()));
        }

        // Four stacked charts plus a time axis.
        let axis_h = 40.0;
        let area = Rect::from_min_max(chart_card.min + vec2(16.0, 8.0), pos2(chart_card.right() - 16.0, chart_card.bottom() - axis_h));
        let total_gb = (hw.memory_total / (1024.0 * 1024.0 * 1024.0)).max(1.0) as f32;
        let mem_pct = move |s: &crate::data::HardwareSample| s.memory / total_gb * 100.0;
        // One slot per sample; `None` is a stretch with no data (the app wasn't running).
        // Clock moved on since the data's right edge, so the plot can slide left between samples.
        let now_f = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
        let (series, window, now_local, age): (Vec<Option<crate::data::HardwareSample>>, i64, i64, f64) = if mins > 5 || app.is_some() {
            let window = i64::from(mins) * 60;
            // History rows are 10 s apart, so a slot narrower than two rows would sometimes catch none
            // and show a false gap (the 1 hour range did at wide window sizes).
            let max_n = (window / (2 * crate::live::hardware::HISTORY_STEP)) as usize;
            let n = if mins > 5 { ((area.width() / 3.0) as usize).max(50).min(max_n) } else { max_n };
            let (backend, filter) = (self.backend.clone(), app.clone());
            // History rows are 10 s apart, so a few seconds of staleness is invisible. Until the first read lands the chart shows gaps.
            let (series, fetched) = self
                .hw_series
                .get((window, n, app.clone()), Duration::from_secs(3), move || (backend.hardware_history(window, n, filter.as_deref()), crate::clock::now_unix()))
                .cloned()
                .unwrap_or_else(|| (vec![None; n], crate::clock::now_unix()));
            (series, window, crate::clock::to_local(crate::clock::now_unix()), now_f - fetched as f64)
        } else {
            (hw.samples.iter().map(|s| Some(*s)).collect(), WINDOW_SECS as i64 - 1, now_secs, crate::clock::to_local(now_f as i64) as f64 + now_f.fract() - now_secs as f64)
        };
        let age = if self.caps.live { age.clamp(0.0, 3.0) } else { 0.0 };
        let shift = (age / window as f64) as f32 * area.width();
        // Ranges up to an hour move visibly each second, so they repaint every frame.
        if self.caps.live && mins <= 60 {
            ui.ctx().request_repaint();
        }
        // Demo keeps the scales of the screenshots; Live scales each chart to its own peak.
        let scales = if self.caps.live {
            let peak = |f: &dyn Fn(&crate::data::HardwareSample) -> f32| series.iter().flatten().map(f).fold(0.0_f32, f32::max);
            let nice = |x: f32| (x / 10.0).ceil().max(1.0) * 10.0;
            [nice(peak(&|s| s.cpu)), nice(peak(&mem_pct)), nice(peak(&|s| s.disk)), nice(peak(&|s| s.gpu))]
        } else {
            [60.0, 20.0, 105.0, 50.0]
        };
        let charts: [Chart; 4] = [
            ("CPU", format!("{:.0}%", scales[0]), Box::new(|s| s.cpu), scales[0]),
            ("Memory", format!("{:.0}%", scales[1]), Box::new(mem_pct), scales[1]),
            ("Disk transfer rate", format!("{:.0} MB/s", scales[2]), Box::new(|s| s.disk), scales[2]),
            ("GPU", if hw.gpu_available && app.is_none() { format!("{:.0}%", scales[3]) } else { "n/a".into() }, Box::new(|s| s.gpu), scales[3]),
        ];
        let slot = area.height() / charts.len() as f32;
        let clip = p.with_clip_rect(Rect::from_x_y_ranges(area.x_range(), full.y_range()));
        let line = Stroke::new(1.5, theme::chart_line());
        for (i, (title, max_label, value, max)) in charts.iter().enumerate() {
            let top = area.top() + slot * i as f32;
            let label_y = top + 14.0;
            let g = p.layout_no_wrap((*title).into(), theme::font(15.0), theme::text_dim());
            let gw = g.size().x;
            p.galley(pos2(area.left(), label_y - g.size().y / 2.0), g, theme::text_dim());
            let gm = p.layout_no_wrap(max_label.clone(), theme::font(14.0), theme::text_dim());
            let mw = gm.size().x;
            p.galley(pos2(area.right() - mw, label_y - gm.size().y / 2.0), gm, theme::text_dim());
            p.hline((area.left() + gw + 12.0)..=(area.right() - mw - 12.0), label_y, Stroke::new(1.0, theme::border()));
            let plot = Rect::from_min_max(pos2(area.left(), label_y + 14.0), pos2(area.right(), top + slot - 14.0));
            // Each run of consecutive samples is drawn on its own, leaving the gaps empty and
            // proportional to the time missing.
            let n = series.len();
            let mut i = 0;
            while i < n {
                if series[i].is_none() {
                    i += 1;
                    continue;
                }
                let start = i;
                while i < n && series[i].is_some() {
                    i += 1;
                }
                let x = |k: usize| plot.left() - shift + k as f32 / (n - 1).max(1) as f32 * plot.width();
                let values: Vec<f32> = series[start..i].iter().flatten().map(|s| value(s) / max).collect();
                widgets::area(&clip, Rect::from_x_y_ranges(x(start)..=x(i - 1), plot.y_range()), &values, theme::chart_fill(), Some(line));
            }
            p.hline(plot.x_range(), plot.bottom(), Stroke::new(1.0, theme::chart_line().gamma_multiply(0.5)));
        }

        let axis_y = chart_card.bottom() - axis_h;
        p.hline(area.x_range(), axis_y, Stroke::new(1.0, theme::border()));
        let start = now_local - window;
        let tage = (crate::clock::to_local(now_f as i64) - now_local) as f32 + now_f.fract() as f32;
        // The smallest tick spacing that keeps the axis to about ten labels.
        let step = [30, 60, 300, 600, 1800, 3600, 7200, 21_600, 43_200, 86_400].into_iter().find(|s| window / s <= 10).unwrap_or(86_400);
        let mut t = (start + step - 1) / step * step;
        while t <= now_local {
            let x = area.left() + ((t - start) as f32 - tage) / window as f32 * area.width();
            if x < area.left() {
                t += step;
                continue;
            }
            let mut label = fmt_clock_secs(t, step < 60);
            if window > 86_400 {
                label = format!("{} {label}", crate::clock::day_label(t - crate::clock::local_offset_at(crate::clock::now_unix()), crate::clock::now_unix()));
            }
            p.text(pos2(x, axis_y + 20.0), Align2::CENTER_CENTER, label, theme::font(14.0), theme::text_dim());
            t += step;
        }
    }
}
