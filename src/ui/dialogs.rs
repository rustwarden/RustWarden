//! Modal boxes: settings, confirmations for anything that touches the firewall, rename, about.

use super::fluent::group;
use crate::app::{Confirm, ConfirmAction, Dialog, Gated, RustWarden, UpdateEvent, UpdateView};
use crate::data::{FirewallMode, ThreatAct};
use crate::icons::{self, Icon};
use crate::live::alerts::AlertKind;
use crate::settings::{AlertLevel, Mode, NetInfoSource, PlanDirection, PlanPeriod, Settings, Theme};
use crate::theme;
use crate::update::Checked;
use egui::{Align2, Context, Ui};

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Times of recent clicks on the About box; 7 within 5 seconds trigger the easter egg.
static ABOUT_CLICKS: Mutex<Vec<Instant>> = Mutex::new(Vec::new());
const ABOUT_PNG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/about_graph.png"));

/// (blocked, whitelisted) malicious addresses, each with "program · signature".
use crate::app::ThreatLists;

/// Records a click; true on the 7th within 5 seconds (and starts over).
fn about_click_hits() -> bool {
    let mut clicks = ABOUT_CLICKS.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    clicks.retain(|t| now.duration_since(*t) <= Duration::from_secs(5));
    clicks.push(now);
    let hit = clicks.len() >= 7;
    if hit {
        clicks.clear();
    }
    hit
}

enum Outcome {
    Keep,
    Close,
    Apply(Box<Settings>),
    Confirmed(ConfirmAction),
    Rename(String, String),
    /// Marks a device known (or not) without closing its details.
    Trust(String, bool),
    /// Whois and blocklist details for an address, shown beside the open dialog.
    IpInfo(String),
    /// Close this dialog and open a confirmation.
    Then(Confirm),
    /// Install the service, making these shortcuts.
    InstallService {
        desktop: bool,
        start_menu: bool,
    },
    /// Download, verify and install this release.
    StartUpdate(crate::update::Release),
    /// Send a sample alert of this kind using the dialog's current (unsaved) settings.
    TestAlert(AlertKind, Box<Settings>),
    TestAsk,
    TestThreat,
    /// Save the firewall rules to a file the user picks.
    ExportRules,
    /// Pick a rules file and ask before applying it.
    ImportRules,
    /// Switch to (confirmed first) or create a firewall ruleset; Settings comes back if nothing opens.
    SwitchRuleset(String),
    NewRuleset,
    /// Forget the saved window position and size and put the window back to its default.
    ResetWindow,
    /// Add or replace a destination rule; the window stays open.
    /// The right password was entered: do what it was guarding.
    Unlocked(Gated),
    /// The wizard was finished: apply its choices.
    WizardDone,
    /// The wizard was skipped or closed.
    WizardSkip,
    /// Dev channel: apply these settings, then run the wizard again.
    RunWizard(Box<Settings>),
}

/// The monitor the app is on, for sizing dialogs (which aren't confined to the app window).
fn screen_size(ctx: &Context) -> egui::Vec2 {
    ctx.input(|i| i.viewport().monitor_size).unwrap_or(ctx.content_rect().size())
}

impl RustWarden {
    /// The address info window opened from the Malicious IPs lists; stays open over Settings.
    pub(crate) fn show_ip_info(&mut self, ctx: &Context) {
        let done = self.ip_info_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        // A late answer for a window that was closed, or for an older lookup, is dropped.
        if let Some(done) = done
            && self.ip_info.as_ref().is_some_and(|(title, _)| *title == done.0)
        {
            self.ip_info = Some(done);
        }
        let Some((title, body)) = &self.ip_info else { return };
        let open = crate::widgets::dialog(title).show(ctx, |ui| {
            ui.set_width(460.0);
            egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| ui.label(body.as_str()));
        });
        if !open {
            self.ip_info = None;
        }
    }

    pub(crate) fn open_ip_info(&mut self, ctx: &Context, ip: &str) {
        self.ip_info = Some((format!("Details for {ip}"), "Looking up whois…".into()));
        let head = self.backend.threat_summary(ip);
        let (slot, ctx, ip) = (self.ip_info_result.clone(), ctx.clone(), ip.to_owned());
        std::thread::spawn(move || {
            let whois = crate::live::asn::whois(&ip);
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((format!("Details for {ip}"), format!("{head}\n\nWhois\n{whois}")));
            ctx.request_repaint();
        });
    }

    /// Looks for a newer release on a thread. A manual check opens the dialog and shows any outcome;
    /// an automatic one does nothing without an update server and otherwise only offers an update it finds.
    pub(crate) fn check_for_updates(&mut self, ctx: &Context, manual: bool) {
        let (server, channel) = (self.settings.update_url.clone(), self.settings.update_channel);
        if manual {
            if !matches!(self.dialog, None | Some(Dialog::Info { .. })) {
                self.notify("Close the open dialog, then check for updates.");
                return;
            }
            self.dialog = Some(Dialog::Update(UpdateView::Checking));
        } else if server.trim().is_empty() && !crate::update::uses_public_repo() {
            return;
        }
        let (slot, ctx) = (self.update_result.clone(), ctx.clone());
        std::thread::spawn(move || {
            let result = crate::update::check(&server, channel);
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(UpdateEvent::Checked { manual, result });
            ctx.request_repaint();
        });
    }

    fn start_update(&mut self, ctx: &Context, rel: crate::update::Release) {
        let (slot, ctx) = (self.update_result.clone(), ctx.clone());
        self.dialog = Some(Dialog::Update(UpdateView::Installing(rel.clone())));
        std::thread::spawn(move || {
            let result = crate::update::install(&rel);
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(UpdateEvent::Installed(result));
            ctx.request_repaint();
        });
    }

    /// Takes in what the update threads found, offers an update that an automatic check found, and starts the next automatic check.
    pub(crate) fn poll_update(&mut self, ctx: &Context) {
        let event = self.update_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        match event {
            Some(UpdateEvent::Checked { manual: true, result }) => {
                if matches!(self.dialog, Some(Dialog::Update(UpdateView::Checking))) {
                    self.dialog = Some(Dialog::Update(match result {
                        Ok(Checked::Latest(history)) => UpdateView::Latest(history),
                        Ok(Checked::Newer(rel)) => UpdateView::Available(rel),
                        Err(e) => UpdateView::CheckFailed(e),
                    }));
                }
            }
            Some(UpdateEvent::Checked { manual: false, result }) => {
                if let Ok(Checked::Newer(rel)) = result
                    && self.update_offered.as_deref() != Some(rel.version.as_str())
                {
                    self.update_offer = Some(rel);
                }
            }
            Some(UpdateEvent::Installed(Ok(exe))) => self.restart_into(ctx, exe),
            Some(UpdateEvent::Installed(Err(e))) => self.dialog = Some(Dialog::Update(UpdateView::InstallFailed(e))),
            None => {}
        }
        if self.dialog.is_none()
            && self.window_visible
            && let Some(rel) = self.update_offer.take()
        {
            self.update_offered = Some(rel.version.clone());
            self.dialog = Some(Dialog::Update(UpdateView::Available(rel)));
        }
        if std::time::Instant::now() >= self.next_update_check {
            self.next_update_check = std::time::Instant::now() + std::time::Duration::from_secs(6 * 3600);
            self.check_for_updates(ctx, false);
        }
    }

    /// Starts the freshly installed exe (already elevated, so it skips the "is it running" check) and closes this one.
    fn restart_into(&mut self, ctx: &Context, exe: std::path::PathBuf) {
        // The service runs the old image (now `.old`); stopping and starting it (we are admin) moves it onto the new exe and opens the new window.
        let started = if crate::sys::is_elevated() {
            crate::sys::autostart::stop_start_service() || std::process::Command::new(&exe).arg("--elevated").spawn().is_ok()
        } else {
            // current_exe() now names the renamed old file, so tell the restart where the new one is.
            *crate::sys::autostart::MOVED_TO.lock().unwrap_or_else(|e| e.into_inner()) = Some(exe);
            crate::sys::restart_elevated().is_ok()
        };
        if started {
            self.backend.shutdown();
            self.quitting = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else {
            self.dialog = Some(Dialog::Update(UpdateView::InstallFailed("RustWarden was updated but could not restart itself. Start it again to use the new version.".into())));
        }
    }

    /// The graph picture `build.rs` drew from assets/about_graph.json.
    pub(crate) fn about_image() -> egui::ColorImage {
        let mut dec = png::Decoder::new(std::io::Cursor::new(ABOUT_PNG)).read_info().expect("about png");
        let mut buf = vec![0; dec.output_buffer_size().unwrap_or(0)];
        let info = dec.next_frame(&mut buf).expect("about png frame");
        egui::ColorImage::from_rgb([info.width as usize, info.height as usize], &buf[..info.buffer_size()])
    }

    /// Easter egg: saves the About picture beside the exe (rewritten each time, so an update brings the new graph) and makes it the wallpaper.
    fn set_about_wallpaper() -> Result<(), String> {
        let img = Self::about_image();
        let beside = std::env::current_exe().map_err(|e| e.to_string())?.with_file_name("wallpaper.png");
        let path = if std::fs::write(&beside, ABOUT_PNG).is_ok() {
            beside
        } else {
            let dir = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").map_err(|e| e.to_string())?).join("RustWarden");
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::write(dir.join("wallpaper.png"), ABOUT_PNG).map_err(|e| e.to_string())?;
            dir.join("wallpaper.png")
        };
        let bg = img.pixels[0];
        crate::sys::wallpaper::set_wallpaper(&path, [bg.r(), bg.g(), bg.b()])
    }

    /// The Firewall tab's "Destination rules" page: the rule list and the form for a new one.
    pub(crate) fn dest_rules_tab(&mut self, ui: &mut Ui) {
        let mut d = std::mem::take(&mut self.dest_draft);
        let mut dest_cols = std::mem::take(&mut self.dest_cols);
        let (mut save, mut remove, mut download) = (None, None, false);
        let driver = self.settings.app_mode == crate::settings::AppMode::Driver;
        let dom = if driver { self.backend.domain_blocks() } else { Default::default() };
        let mut dd = std::mem::take(&mut self.domain_draft);
        let (mut dom_save, mut dom_remove, mut dom_import, mut dom_clear) = (None, None, None, false);
        let rules = self.backend.dest_rules();
        let asn_ready = self.backend.asn_db_ready();
        let apps: Vec<(String, String, crate::data::AppIcon)> = self.protect.apps.iter().filter(|a| !a.path.is_empty() && !a.locked).map(|a| (a.name.clone(), a.path.clone(), a.icon)).collect();
        let program_name = |path: &str| if path.is_empty() { "Any program".to_owned() } else { crate::live::apps::file_name(path).to_owned() };
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            egui::Frame::NONE.inner_margin(egui::Margin::same(12)).show(ui, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 12.0);
                let edge = egui::Stroke::new(1.0, theme::card_edge());

                // What this page does, as the soft info bar the Firewall page uses.
                egui::Frame::NONE.fill(theme::accent_soft()).stroke(egui::Stroke::new(1.0, theme::accent().gamma_multiply(0.4))).corner_radius(8).inner_margin(egui::Margin::symmetric(14, 12)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_top(|ui| {
                        let (icon, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                        crate::icons::paint(ui.painter(), crate::icons::Icon::Info, icon, theme::accent_text());
                        ui.add(egui::Label::new(egui::RichText::new("Allow or block a program by where it connects: a domain, an AS number or a country. Windows Firewall only knows addresses, so RustWarden turns each rule into the addresses it can find and keeps them up to date. A domain covers what this PC has looked up for it, so a program's first connection to a brand-new server can fail once. Programs using their own encrypted DNS are not seen.").font(theme::font(14.0)).color(theme::text())).wrap());
                    });
                });

                // New rule.
                egui::Frame::NONE.fill(theme::card()).stroke(edge).corner_radius(8).inner_margin(egui::Margin::same(14)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(egui::RichText::new("New rule").font(theme::bold(15.0)).color(theme::text()));
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        labelled(ui, "Program", |ui| {
                            let shown = crate::util::fit_text(ui.painter(), &program_name(&d.program), &theme::font(14.0), 150.0);
                            let resp = crate::widgets::pill_button(ui, None, &shown, true, 200.0);
                            egui::Popup::menu(&resp).width(280.0).show(|ui| {
                                ui.set_max_height(340.0);
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    if crate::widgets::check_item(ui, d.program.is_empty(), "Any program").clicked() {
                                        d.program.clear();
                                        ui.close();
                                    }
                                    for (name, path, icon) in &apps {
                                        if crate::widgets::check_item_icon(ui, d.program == *path, name, Some((*icon, path))).clicked() {
                                            d.program = path.clone();
                                            ui.close();
                                        }
                                    }
                                });
                            });
                        });
                        labelled(ui, "Action", |ui| {
                            crate::widgets::dropdown(ui, None, &mut d.mode, &[crate::destrules::Mode::Block, crate::destrules::Mode::OnlyAllow], |m| m.label().into(), 130.0);
                        });
                        labelled(ui, "Match by", |ui| {
                            crate::widgets::dropdown(ui, None, &mut d.kind, &["Domain", "ASN", "Country"], |k| k.into(), 120.0);
                        });
                        labelled(ui, "Destination", |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                let hint = match d.kind {
                                    "Domain" => "example.com",
                                    "ASN" => "AS15169",
                                    _ => "DE",
                                };
                                let edit = ui.add(egui::TextEdit::singleline(&mut d.value).hint_text(hint).font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(220.0));
                    let open_id = egui::Id::NULL.with("dest_country_open");
                    let mut open = d.kind == "Country" && ui.data(|m| m.get_temp::<bool>(open_id)).unwrap_or(false);
                    if d.kind == "Country" {
                        let (arrow_rect, arrow) = ui.allocate_exact_size(egui::vec2(26.0, edit.rect.height()), egui::Sense::click());
                        let c = arrow_rect.center();
                        let col = if arrow.hovered() { theme::text() } else { theme::text_dim() };
                        ui.painter().add(egui::Shape::convex_polygon(vec![c + egui::vec2(-5.0, -2.5), c + egui::vec2(5.0, -2.5), c + egui::vec2(0.0, 3.5)], col, egui::Stroke::NONE));
                        if arrow.clicked() {
                            open = !open;
                            edit.request_focus();
                        }
                        if edit.changed() || (edit.has_focus() && ui.input(|i| i.key_pressed(egui::Key::ArrowDown))) {
                            open = true;
                        }
                        let hits = crate::countries::search(&d.value);
                        let mut picked = None;
                        egui::Popup::from_response(&edit).kind(egui::PopupKind::Popup).align(egui::RectAlign::BOTTOM_START).close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside).width(340.0).open_bool(&mut open).show(|ui| {
                            egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                                if hits.is_empty() {
                                    ui.label(egui::RichText::new("No matching country").color(theme::text_dim()));
                                }
                                for e in hits {
                                    let (rect, r) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 24.0), egui::Sense::click());
                                    if r.hovered() {
                                        ui.painter().rect_filled(rect, 4.0, theme::text_dim().gamma_multiply(0.25));
                                    }
                                    let flag = egui::Rect::from_min_size(rect.min + egui::vec2(6.0, 4.0), egui::vec2(24.0, 16.0));
                                    crate::icons::flag(ui.painter(), crate::data::Country::from_a2(crate::countries::parse_a2(e.a2).unwrap_or(*b"ZZ")), flag);
                                    ui.painter_at(rect).text(egui::pos2(rect.left() + 38.0, rect.center().y), egui::Align2::LEFT_CENTER, format!("{}  ({})", e.name, e.a2), egui::FontId::proportional(14.0), ui.visuals().text_color());
                                    if r.clicked() {
                                        picked = Some(e.a2);
                                    }
                                }
                            });
                        });
                        if let Some(a2) = picked {
                            d.value = a2.to_owned();
                            open = false;
                        }
                    }
                                ui.data_mut(|m| m.insert_temp(open_id, open));
                            });
                        });
                        labelled(ui, " ", |ui| {
                            if crate::widgets::pill_button(ui, None, "Add rule", false, 90.0).clicked() {
                                let draft = crate::destrules::Target::parse(d.kind, &d.value).map(|target| crate::destrules::DestRule { id: 0, enabled: true, mode: d.mode, target, program: d.program.clone() });
                                match draft {
                                    Ok(rule) => match rule.problem() {
                                        Some(problem) => d.error = problem.into(),
                                        None => {
                                            d.error.clear();
                                            d.value.clear();
                                            save = Some(rule);
                                        }
                                    },
                                    Err(e) => d.error = e,
                                }
                            }
                        });
                    });
                    if !d.error.is_empty() {
                        ui.colored_label(theme::red(), &d.error);
                    }
                    if d.kind == "ASN" && !asn_ready {
                        ui.label(egui::RichText::new("Rules on an AS number need the free DB-IP ASN database. Downloading it is the only network use of this window.").font(theme::font(14.0)).color(theme::text_dim()));
                        if crate::widgets::pill_button(ui, None, "Download ASN database", false, 0.0).clicked() {
                            download = true;
                        }
                    }
                });

                // The rules, as a table like the Firewall page's.
                egui::Frame::NONE.fill(theme::card()).stroke(edge).corner_radius(8).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let w = ui.available_width();
                    if dest_cols.len() != 3 {
                        dest_cols = vec![0.25, 0.4, 0.62];
                    }
                    let (head, _) = ui.allocate_exact_size(egui::vec2(w, 38.0), egui::Sense::hover());
                    let p = ui.painter();
                    p.rect_filled(head, egui::CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 }, theme::nav_on());
                    p.hline(head.x_range(), head.bottom(), egui::Stroke::new(1.0, theme::border()));
                    crate::widgets::column_handles(ui, "dest_resize", head, &mut dest_cols, 64.0 / w, 1.0 - 120.0 / w);
                    let p = ui.painter();
                    let cols = [64.0, dest_cols[0] * w, dest_cols[1] * w, dest_cols[2] * w];
                    for (x, title) in [(16.0, "ON"), (cols[0], "PROGRAM"), (cols[1], "ACTION"), (cols[2], "DESTINATION"), (cols[3], "STATUS")] {
                        p.text(egui::pos2(head.left() + x, head.center().y), egui::Align2::LEFT_CENTER, title, theme::font(12.5), theme::text_dim());
                    }
                    if rules.is_empty() {
                        let (r, _) = ui.allocate_exact_size(egui::vec2(w, 64.0), egui::Sense::hover());
                        ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "No destination rules yet.", theme::font(14.5), theme::text_dim());
                    }
                    for (i, v) in rules.iter().enumerate() {
                        let (r, resp) = ui.allocate_exact_size(egui::vec2(w, 48.0), egui::Sense::hover());
                        let p = ui.painter();
                        if resp.hovered() {
                            p.rect_filled(r, 0, theme::row_hover());
                        }
                        if i > 0 {
                            p.hline(r.x_range(), r.top(), egui::Stroke::new(1.0, theme::border().gamma_multiply(0.5)));
                        }
                        let cy = r.center().y;
                        let cell = |x: f32, to: f32, text: &str, color: egui::Color32| {
                            crate::widgets::text_fit(p, egui::pos2(r.left() + x, cy), egui::Align2::LEFT_CENTER, text, theme::font(14.0), color, (to - x - 12.0).max(20.0));
                        };
                        cell(cols[0], cols[1], &program_name(&v.rule.program), theme::text());
                        cell(cols[1], cols[2], v.rule.mode.label(), theme::text());
                        cell(cols[2], cols[3], &format!("{}: {}", v.rule.target.kind(), v.rule.target.text()), theme::text());
                        cell(cols[3], w - 120.0, &v.status, if v.problem { theme::red() } else { theme::text_dim() });
                        let mut on = v.rule.enabled;
                        if super::row_in(ui, egui::Rect::from_min_size(egui::pos2(r.left() + 16.0, cy - 12.0), egui::vec2(44.0, 24.0)), |ui| crate::widgets::small_toggle(ui, &mut on)).clicked() {
                            save = Some(crate::destrules::DestRule { enabled: on, ..v.rule.clone() });
                        }
                        let btn = egui::Rect::from_min_max(egui::pos2(r.right() - 108.0, r.top()), egui::pos2(r.right() - 14.0, r.bottom()));
                        ui.scope_builder(egui::UiBuilder::new().max_rect(btn).layout(egui::Layout::right_to_left(egui::Align::Center)), |ui| {
                            if crate::widgets::pill_button(ui, None, "Remove", false, 0.0).clicked() {
                                remove = Some(v.rule.id);
                            }
                        });
                    }
                });

                if driver {
                    egui::Frame::NONE.fill(theme::card()).stroke(edge).corner_radius(8).inner_margin(egui::Margin::same(14)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(egui::RichText::new("Block by domain (Driver mode)").font(theme::bold(15.0)).color(theme::text()));
                        ui.label(egui::RichText::new("Stops every program on this PC from connecting to a domain and everything below it (example.com covers www.example.com). The driver drops the DNS lookup and the start of the HTTPS connection. Programs using encrypted DNS and Encrypted Client Hello can slip past, and QUIC isn't read.").font(theme::font(13.5)).color(theme::text_dim()));
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut dd.pattern).hint_text("ads.example.com").font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(260.0));
                            if crate::widgets::pill_button(ui, None, "Block", false, 80.0).clicked() {
                                match crate::domainblock::normalize(&dd.pattern) {
                                    Ok(pattern) => {
                                        dd.error.clear();
                                        dd.pattern.clear();
                                        dom_save = Some(crate::domainblock::DomainRule { id: 0, enabled: true, pattern });
                                    }
                                    Err(e) => dd.error = e.into(),
                                }
                            }
                        });
                        for r in &dom.rules {
                            ui.horizontal(|ui| {
                                let mut on = r.enabled;
                                if crate::widgets::small_toggle(ui, &mut on).clicked() {
                                    dom_save = Some(crate::domainblock::DomainRule { enabled: on, ..r.clone() });
                                }
                                ui.label(egui::RichText::new(&r.pattern).font(theme::font(14.0)).color(theme::text()));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if crate::widgets::pill_button(ui, None, "Remove", false, 0.0).clicked() {
                                        dom_remove = Some(r.id);
                                    }
                                });
                            });
                        }
                        ui.separator();
                        ui.label(egui::RichText::new("Block list").font(theme::bold(14.0)).color(theme::text()));
                        ui.label(egui::RichText::new("Optional: download a hosts-style or one-domain-per-line list from an https address you trust. Nothing is downloaded until you press Import.").font(theme::font(13.5)).color(theme::text_dim()));
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut dd.url).hint_text("https://example.com/hosts.txt").font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(320.0));
                            if crate::widgets::pill_button(ui, None, "Import list", false, 100.0).clicked() {
                                dom_import = Some(dd.url.trim().to_owned());
                            }
                            if dom.list_count > 0 && crate::widgets::pill_button(ui, None, "Remove list", false, 110.0).clicked() {
                                dom_clear = true;
                            }
                        });
                        if dom.list_count > 0 {
                            ui.label(egui::RichText::new(format!("List in use: {} domains from {}", dom.list_count, dom.list_url)).font(theme::font(13.5)).color(theme::text_dim()));
                        }
                        if !dd.error.is_empty() {
                            ui.colored_label(theme::red(), &dd.error);
                        }
                        ui.label(egui::RichText::new(&dom.status).font(theme::font(13.5)).color(if dom.problem { theme::red() } else { theme::text_dim() }));
                    });
                }
            });
        });
        self.domain_draft = dd;
        if let Some(rule) = dom_save {
            self.run_bg(move |b| b.save_domain_block(rule).map(|()| "Domain rule saved".into()));
        }
        if let Some(id) = dom_remove {
            self.run_bg(move |b| b.remove_domain_block(id).map(|()| "Domain rule removed".into()));
        }
        if let Some(url) = dom_import {
            self.run_bg(move |b| b.import_domain_list(&url).map(|n| format!("Imported {n} domains")));
        }
        if dom_clear {
            self.run_bg(|b| b.clear_domain_list().map(|()| "Block list removed".into()));
        }
        self.dest_draft = d;
        self.dest_cols = dest_cols;
        if let Some(rule) = save {
            self.run_bg(move |b| b.save_dest_rule(rule).map(|()| "Destination rule saved".into()));
        }
        if let Some(id) = remove {
            self.run_bg(move |b| b.remove_dest_rule(id).map(|()| "Destination rule removed".into()));
        }
        if download {
            self.run_bg(|b| b.download_asn_db().map(|()| "ASN database downloaded".into()));
        }
    }

    pub(crate) fn bandwidth_tab(&mut self, ui: &mut Ui) {
        let mut d = std::mem::take(&mut self.qos_draft);
        let mut cols = std::mem::take(&mut self.qos_cols);
        let (mut save, mut remove) = (None, None);
        let limits = self.backend.qos_limits();
        let driver = self.settings.app_mode == crate::settings::AppMode::Driver;
        let apps: Vec<(String, String, crate::data::AppIcon)> = self.protect.apps.iter().filter(|a| !a.path.is_empty() && !a.locked).map(|a| (a.name.clone(), a.path.clone(), a.icon)).collect();
        let program_name = |path: &str| if path.is_empty() { "Pick a program".to_owned() } else { crate::live::apps::file_name(path).to_owned() };
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            egui::Frame::NONE.inner_margin(egui::Margin::same(12)).show(ui, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 12.0);
                let edge = egui::Stroke::new(1.0, theme::card_edge());

                egui::Frame::NONE.fill(theme::accent_soft()).stroke(egui::Stroke::new(1.0, theme::accent().gamma_multiply(0.4))).corner_radius(8).inner_margin(egui::Margin::symmetric(14, 12)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_top(|ui| {
                        let (icon, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                        crate::icons::paint(ui.painter(), crate::icons::Icon::Info, icon, theme::accent_text());
                        let intro = if driver { "Cap how fast a program can upload, download or both, each with its own rate. In Driver mode the WinDivert driver enforces the cap, which also works over a VPN. You can also simulate a bad connection for a program: add delay and packet loss (with or without a cap), which switches itself off after 30 minutes. If the driver isn't ready, uploads fall back to a Windows QoS policy and downloads show why they aren't limited. Limits need administrator rights and \"Restore firewall defaults\" removes them all." } else { "Cap how fast a program can upload. Windows enforces the cap itself with a QoS policy, so nothing extra runs and no driver is installed. Only uploads can be limited: Windows has no way to cap downloads. Limits need administrator rights, are named \"RustWarden QoS\", and \"Restore firewall defaults\" removes them all." };
                        ui.add(egui::Label::new(egui::RichText::new(intro).font(theme::font(14.0)).color(theme::text())).wrap());
                    });
                });

                egui::Frame::NONE.fill(theme::card()).stroke(edge).corner_radius(8).inner_margin(egui::Margin::same(14)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(egui::RichText::new("New limit").font(theme::bold(15.0)).color(theme::text()));
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;
                        labelled(ui, "Program", |ui| {
                            let shown = crate::util::fit_text(ui.painter(), &program_name(&d.program), &theme::font(14.0), 150.0);
                            let resp = crate::widgets::pill_button(ui, None, &shown, true, 200.0);
                            egui::Popup::menu(&resp).width(280.0).show(|ui| {
                                ui.set_max_height(340.0);
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    for (name, path, icon) in &apps {
                                        if crate::widgets::check_item_icon(ui, d.program == *path, name, Some((*icon, path))).clicked() {
                                            d.program = path.clone();
                                            ui.close();
                                        }
                                    }
                                });
                            });
                        });
                        if driver {
                            labelled(ui, "Direction", |ui| {
                                crate::widgets::dropdown(ui, None, &mut d.dir, &crate::qos::LimitDir::ALL, |m| m.label().into(), 150.0);
                            });
                        }
                        if !driver || d.dir.up() {
                            labelled(ui, "Upload limit", |ui| {
                                ui.add(egui::TextEdit::singleline(&mut d.value).hint_text("5").font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(90.0));
                            });
                            labelled(ui, "Unit", |ui| {
                                crate::widgets::dropdown(ui, None, &mut d.unit, &["Kbps", "Mbps"], |u| (*u).into(), 100.0);
                            });
                        }
                        if driver && d.dir.down() {
                            labelled(ui, "Download limit", |ui| {
                                ui.add(egui::TextEdit::singleline(&mut d.down_value).hint_text("20").font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(90.0));
                            });
                            labelled(ui, "Unit", |ui| {
                                crate::widgets::dropdown(ui, None, &mut d.down_unit, &["Kbps", "Mbps"], |u| (*u).into(), 100.0);
                            });
                        }
                        labelled(ui, "Priority", |ui| {
                            crate::widgets::dropdown(ui, None, &mut d.priority, &crate::qos::Priority::ALL, |p| p.label().into(), 100.0);
                        });
                        if driver {
                            labelled(ui, "Add delay (ms)", |ui| {
                                ui.add(egui::TextEdit::singleline(&mut d.delay).hint_text("0").font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(70.0));
                            });
                            labelled(ui, "Packet loss (%)", |ui| {
                                ui.add(egui::TextEdit::singleline(&mut d.loss).hint_text("0").font(theme::font(14.0)).margin(egui::Margin::symmetric(10, 8)).desired_width(70.0));
                            });
                        }
                        labelled(ui, " ", |ui| {
                            if crate::widgets::pill_button(ui, None, "Set limit", false, 90.0).clicked() {
                                let rate = |text: &str, unit: &str| text.trim().replace(',', ".").parse::<f64>().ok().filter(|v| v.is_finite() && *v >= 0.0).map(|v| (v * if unit == "Mbps" { 1000.0 } else { 1.0 }).round().min(f64::from(u32::MAX)) as u32);
                                let dir = if driver { d.dir } else { crate::qos::LimitDir::Up };
                                let (up, down) = (rate(&d.value, d.unit), rate(&d.down_value, d.down_unit));
                                let whole = |t: &str| if t.trim().is_empty() { Some(0) } else { t.trim().parse::<u32>().ok() };
                                let (delay, loss) = if driver { (whole(&d.delay), whole(&d.loss)) } else { (Some(0), Some(0)) };
                                let sim = delay.unwrap_or(0) > 0 || loss.unwrap_or(0) > 0;
                                // With a simulation or a priority, an empty rate means "no cap".
                                let skipped = |t: &str| (sim || d.priority != crate::qos::Priority::Normal) && t.trim().is_empty();
                                if delay.is_none() || loss.is_none() {
                                    d.error = "Delay and loss must be whole numbers.".into();
                                } else if (dir.up() && up.is_none() && !skipped(&d.value)) || (dir.down() && down.is_none() && !skipped(&d.down_value)) {
                                    d.error = "Enter a number, such as 5.".into();
                                } else {
                                    // A program that already has a limit gets that limit changed, so this button is also "edit".
                                    let id = limits.iter().find(|v| v.limit.program.eq_ignore_ascii_case(d.program.trim())).map_or(0, |v| v.limit.id);
                                    let limit = crate::qos::QosLimit { dir, down_kbps: if dir.down() { down.unwrap_or(0) } else { 0 }, kbps: if dir.up() { up.unwrap_or(0) } else { 0 }, delay_ms: delay.unwrap_or(0), loss_pct: loss.unwrap_or(0).min(255) as u8, sim_until: if sim { crate::clock::now_unix() + crate::qos::SIM_SECS } else { 0 }, priority: d.priority, ..crate::qos::QosLimit::upload(id, true, d.program.clone(), 0) };
                                    match limit.problem() {
                                        Some(problem) => d.error = problem.into(),
                                        None => {
                                            d.error.clear();
                                            d.value.clear();
                                            d.down_value.clear();
                                            d.delay.clear();
                                            d.loss.clear();
                                            save = Some(limit);
                                        }
                                    }
                                }
                            }
                        });
                    });
                    if !d.error.is_empty() {
                        ui.colored_label(theme::red(), &d.error);
                    }
                });

                egui::Frame::NONE.fill(theme::card()).stroke(edge).corner_radius(8).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let w = ui.available_width();
                    if cols.len() != 2 {
                        cols = vec![0.4, 0.55];
                    }
                    let (head, _) = ui.allocate_exact_size(egui::vec2(w, 38.0), egui::Sense::hover());
                    ui.painter().rect_filled(head, egui::CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 }, theme::nav_on());
                    ui.painter().hline(head.x_range(), head.bottom(), egui::Stroke::new(1.0, theme::border()));
                    crate::widgets::column_handles(ui, "qos_resize", head, &mut cols, 64.0 / w, 1.0 - 120.0 / w);
                    let p = ui.painter();
                    let xs = [64.0, cols[0] * w, cols[1] * w];
                    for (x, title) in [(16.0, "ON"), (xs[0], "PROGRAM"), (xs[1], if driver { "LIMIT" } else { "UPLOAD LIMIT" }), (xs[2], "STATUS")] {
                        p.text(egui::pos2(head.left() + x, head.center().y), egui::Align2::LEFT_CENTER, title, theme::font(12.5), theme::text_dim());
                    }
                    if limits.is_empty() {
                        let (r, _) = ui.allocate_exact_size(egui::vec2(w, 64.0), egui::Sense::hover());
                        ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "No bandwidth limits yet.", theme::font(14.5), theme::text_dim());
                    }
                    for (i, v) in limits.iter().enumerate() {
                        let (r, resp) = ui.allocate_exact_size(egui::vec2(w, 48.0), egui::Sense::hover());
                        let p = ui.painter();
                        if resp.hovered() {
                            p.rect_filled(r, 0, theme::row_hover());
                        }
                        if i > 0 {
                            p.hline(r.x_range(), r.top(), egui::Stroke::new(1.0, theme::border().gamma_multiply(0.5)));
                        }
                        let cy = r.center().y;
                        let cell = |x: f32, to: f32, text: &str, color: egui::Color32| {
                            crate::widgets::text_fit(p, egui::pos2(r.left() + x, cy), egui::Align2::LEFT_CENTER, text, theme::font(14.0), color, (to - x - 12.0).max(20.0));
                        };
                        cell(xs[0], xs[1], v.limit.exe_name(), theme::text());
                        cell(xs[1], xs[2], &v.limit.rate_text(driver), theme::text());
                        cell(xs[2], w - 120.0, &v.status, if v.problem { theme::red() } else { theme::text_dim() });
                        let mut on = v.limit.enabled;
                        if super::row_in(ui, egui::Rect::from_min_size(egui::pos2(r.left() + 16.0, cy - 12.0), egui::vec2(44.0, 24.0)), |ui| crate::widgets::small_toggle(ui, &mut on)).clicked() {
                            save = Some(crate::qos::QosLimit { enabled: on, ..v.limit.clone() });
                        }
                        let btn = egui::Rect::from_min_max(egui::pos2(r.right() - 108.0, r.top()), egui::pos2(r.right() - 14.0, r.bottom()));
                        ui.scope_builder(egui::UiBuilder::new().max_rect(btn).layout(egui::Layout::right_to_left(egui::Align::Center)), |ui| {
                            if crate::widgets::pill_button(ui, None, "Remove", false, 0.0).clicked() {
                                remove = Some(v.limit.id);
                            }
                        });
                    }
                });
            });
        });
        self.qos_draft = d;
        self.qos_cols = cols;
        if let Some(limit) = save {
            self.run_bg(move |b| b.save_qos_limit(limit).map(|()| "Bandwidth limit saved".into()));
        }
        if let Some(id) = remove {
            self.run_bg(move |b| b.remove_qos_limit(id).map(|()| "Bandwidth limit removed".into()));
        }
    }

    pub(crate) fn show_dialog(&mut self, ctx: &Context) {
        let Some(mut dialog) = self.dialog.take() else { return };
        let live = self.settings.mode == Mode::Live;
        let mut notice = None;
        let outcome = match &mut dialog {
            Dialog::Info { title, body } => {
                let mut out = Outcome::Keep;
                if !crate::widgets::dialog(title).show(ctx, |ui| {
                    ui.label(body.as_str());
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        out = Outcome::Close;
                    }
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::Report(r) => {
                let mut out = Outcome::Keep;
                if !crate::widgets::dialog("Weekly report").show(ctx, |ui| {
                    egui::ScrollArea::vertical().max_height(screen_size(ctx).y * 0.7).show(ui, |ui| report_charts(ui, r));
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        out = Outcome::Close;
                    }
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::About(tex) => {
                let mut out = Outcome::Keep;
                let avail = screen_size(ctx) * 0.8;
                let size = tex.size_vec2();
                let fit = (avail.x / size.x).min((avail.y - 90.0) / size.y).min(1.0);
                if !crate::widgets::dialog(&format!("About RustWarden {}", env!("CARGO_PKG_VERSION"))).flush().show(ctx, |ui| {
                    ui.add(egui::Image::new((tex.id(), size * fit)));
                    if ctx.input(|i| i.pointer.primary_clicked()) && about_click_hits() {
                        notice = Some(Self::set_about_wallpaper().map_or_else(|e| format!("Could not set the wallpaper: {e}"), |_| "bazinga".into()));
                    }
                    egui::Frame::NONE.inner_margin(egui::Margin::same(14)).show(ui, |ui| {
                        ui.label("RustWarden is a Windows network monitor that shows live traffic per app and lets you block it with firewall rules.");
                        ui.label(format!("Created by Connor & Norman - Version: {} ({})", env!("CARGO_PKG_VERSION"), crate::util::build_label()));
                        ui.add_space(6.0);
                        if ui.button("Close").clicked() {
                            out = Outcome::Close;
                        }
                    });
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::InstallService { desktop, start_menu } => {
                let mut out = Outcome::Keep;
                if !crate::widgets::dialog("Install the RustWarden service?").show(ctx, |ui| {
                    ui.set_max_width(420.0);
                    ui.label("Do you want to install RustWarden? It copies RustWarden to Program Files and adds a Windows service, so RustWarden can open as administrator without asking each time. Windows asks for administrator approval once, and RustWarden restarts afterwards.");
                    ui.add_space(6.0);
                    crate::widgets::switch(ui, desktop, "Create a desktop shortcut");
                    crate::widgets::switch(ui, start_menu, "Create a Start menu shortcut");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Install").clicked() {
                            out = Outcome::InstallService { desktop: *desktop, start_menu: *start_menu };
                        }
                        if ui.button("Cancel").clicked() {
                            out = Outcome::Close;
                        }
                    });
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::Update(view) => {
                let mut out = Outcome::Keep;
                let installing = matches!(view, UpdateView::Installing(_));
                let open = crate::widgets::dialog("Software update").show(ctx, |ui| {
                    ui.set_width(460.0);
                    let close = |ui: &mut Ui, out: &mut Outcome| {
                        if ui.button("Close").clicked() {
                            *out = Outcome::Close;
                        }
                    };
                    match &*view {
                        UpdateView::Checking => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("Checking for updates…");
                            });
                            ui.add_space(8.0);
                            close(ui, &mut out);
                        }
                        UpdateView::Latest(history) => {
                            ui.label(egui::RichText::new("No update available").strong());
                            ui.label(format!("RustWarden {} is the latest version.", env!("CARGO_PKG_VERSION")));
                            ui.add_space(6.0);
                            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                for note in history {
                                    release_notes(ui, note);
                                }
                            });
                            ui.add_space(8.0);
                            close(ui, &mut out);
                        }
                        UpdateView::Available(rel) => {
                            ui.label(egui::RichText::new(format!("Update available: RustWarden {}", rel.version)).strong());
                            ui.label(format!("You have {}.", env!("CARGO_PKG_VERSION")));
                            ui.add_space(6.0);
                            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                for note in &rel.history {
                                    release_notes(ui, note);
                                }
                            });
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                if ui.button("Update").clicked() {
                                    out = Outcome::StartUpdate(rel.clone());
                                }
                                if ui.button("Not now").clicked() {
                                    out = Outcome::Close;
                                }
                            });
                        }
                        UpdateView::Installing(rel) => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(format!("Downloading and verifying RustWarden {}…", rel.version));
                            });
                            let pct = crate::update::PROGRESS.load(std::sync::atomic::Ordering::Relaxed);
                            ui.add(egui::ProgressBar::new(pct as f32 / 100.0).show_percentage());
                            ui.label("RustWarden restarts when it is done.");
                            ctx.request_repaint_after(std::time::Duration::from_millis(100));
                        }
                        UpdateView::CheckFailed(e) | UpdateView::InstallFailed(e) => {
                            let what = if matches!(view, UpdateView::CheckFailed(_)) { "Failed to check for updates" } else { "The update failed" };
                            ui.label(egui::RichText::new(what).strong());
                            ui.colored_label(theme::red(), e.as_str());
                            ui.add_space(8.0);
                            close(ui, &mut out);
                        }
                    }
                });
                // The window's own close is ignored while installing: the swap can't be interrupted.
                if !open && !installing {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::Confirm(c) => {
                let mut out = Outcome::Keep;
                if !crate::widgets::dialog(&c.title).show(ctx, |ui| {
                    ui.set_max_width(420.0);
                    egui::ScrollArea::vertical().max_height(screen_size(ctx).y * 0.6).show(ui, |ui| ui.label(&c.body));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button(&c.yes).clicked() {
                            out = Outcome::Confirmed(c.action.clone());
                        }
                        // Switching to Demo can also keep the rules in place.
                        if matches!(c.action, ConfirmAction::SwitchToDemo { .. }) && ui.button("Keep rules and switch").clicked() {
                            out = Outcome::Confirmed(ConfirmAction::SwitchToDemo { remove_rules: false });
                        }
                        if ui.button("Cancel").clicked() {
                            out = Outcome::Close;
                        }
                    });
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::Password { then, text, error } => {
                let mut out = Outcome::Keep;
                let title = match then {
                    Gated::Settings => "Settings are locked",
                    Gated::Exit => "Exit RustWarden",
                    Gated::Restart => "Restart RustWarden",
                    Gated::ServiceStop => "Stop the RustWarden service",
                };
                if !crate::widgets::dialog(title).show(ctx, |ui| {
                    ui.set_max_width(360.0);
                    ui.label("Enter the RustWarden password.");
                    let edit = ui.add(egui::TextEdit::singleline(text).password(true).desired_width(f32::INFINITY));
                    // Only when nothing has it: asking every frame fights the on-screen keyboard for focus.
                    if ctx.input(|i| i.focused) && ctx.memory(|m| m.focused().is_none()) {
                        edit.request_focus();
                    }
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if *error {
                        ui.colored_label(theme::red(), "Wrong password.");
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Unlock").clicked() || enter {
                            if crate::tamper::verify(&self.settings.tamper_hash, text) {
                                out = Outcome::Unlocked(*then);
                            } else {
                                *error = true;
                                text.clear();
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            out = Outcome::Close;
                        }
                    });
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::NewProfile { text } => {
                let mut out = Outcome::Keep;
                let name = text.trim().to_owned();
                let check = crate::live::firewall::valid_profile_name(&name, &self.protect.profiles);
                let current = self.protect.profile.clone();
                if !crate::widgets::dialog("Create New Ruleset").show(ctx, |ui| {
                    ui.set_max_width(420.0);
                    ui.label(
                        "A firewall ruleset is a separate set of RustWarden rules. Name the new one; your current rules are kept safe under the current ruleset and you can switch back at any time.",
                    );
                    let edit = ui.text_edit_singleline(text);
                    let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    match &check {
                        Err(e) if !name.is_empty() => {
                            ui.colored_label(theme::red(), e);
                        }
                        _ => {}
                    }
                    ui.horizontal(|ui| {
                        if (ui.add_enabled(check.is_ok(), egui::Button::new("Continue")).clicked() || enter) && check.is_ok() {
                            out = Outcome::Then(profile_confirm(&current, &name, true));
                        }
                        if ui.button("Cancel").clicked() {
                            out = Outcome::Close;
                        }
                    });
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::Rename { mac, text } => {
                let mut out = Outcome::Keep;
                let dev = self.scanner.devices.iter().find(|d| d.mac == *mac);
                let note_src = crate::plugins::wasm::manager::annotator();
                let src_name = note_src.as_ref().map_or("Home Assistant", |s| s.name.as_str()).to_owned();
                let ha_url = dev.and_then(crate::ui::notes::device_url);
                if !crate::widgets::dialog("Device details").show(ctx, |ui| {
                    ui.set_min_width(380.0);
                    if let Some(d) = dev {
                        egui::Grid::new("device_details").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                            let mut row = |k: &str, v: &str| {
                                if !v.is_empty() {
                                    ui.label(k);
                                    ui.label(v);
                                    ui.end_row();
                                }
                            };
                            row("Status", if d.online { "Online" } else { "Offline" });
                            row("Type", d.kind.label());
                            row("IP", &d.ip);
                            row("MAC", &d.mac);
                            row("Description", &d.description);
                            row("System", &d.system);
                            row("First seen", &crate::clock::fmt_stamp(d.first_seen));
                            row("Last seen", &crate::clock::fmt_stamp(d.last_seen));
                            row("Times seen", &d.seen_count.to_string());
                            if let Some(n) = &d.note {
                                row(&format!("{src_name} name"), &n.name);
                                row(&format!("{src_name} area"), &n.area);
                                row(&format!("{src_name} model"), &n.model);
                            }
                        });
                        if let Some(url) = &ha_url
                            && ui.link(format!("Open in {src_name}")).clicked()
                        {
                            crate::sys::open_url(url);
                        }
                        if !d.ports.is_empty() {
                            ui.add_space(4.0);
                            ui.label("Open ports");
                            ui.horizontal_wrapped(|ui| {
                                for &port in &d.ports {
                                    let (name, scheme) = crate::ui::scanner::service(port);
                                    match scheme {
                                        Some(s) => {
                                            if ui.link(format!("{name} :{port}")).clicked() {
                                                crate::sys::open_url(&format!("{s}://{}:{port}", d.ip));
                                            }
                                        }
                                        None => {
                                            ui.label(format!("{name} :{port}"));
                                        }
                                    }
                                }
                            });
                        }
                        let mut trusted = d.trusted;
                        if ui.checkbox(&mut trusted, "Trusted (a known device)").changed() {
                            out = Outcome::Trust(mac.clone(), trusted);
                        }
                        ui.separator();
                    }
                    ui.label("Name");
                    let edit = ui.text_edit_singleline(text);
                    let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() || enter {
                            out = Outcome::Rename(mac.clone(), text.trim().to_owned());
                        }
                        if ui.button("Cancel").clicked() {
                            out = Outcome::Close;
                        }
                    });
                }) {
                    out = Outcome::Close;
                }
                out
            }
            Dialog::Wizard(w) => match super::wizard::show(ctx, w) {
                super::wizard::Step::Keep => Outcome::Keep,
                super::wizard::Step::Skip => Outcome::WizardSkip,
                super::wizard::Step::Finish => Outcome::WizardDone,
            },
            Dialog::Settings(draft) => {
                let mut out = Outcome::Keep;
                let jump = self.settings_section.take();
                let profiles = (self.protect.profiles.clone(), self.protect.profile.clone());
                ctx.data_mut(|d| d.insert_temp(egui::Id::NULL.with("service_installed"), self.service));
                if !crate::driver::progress().is_empty() {
                    ctx.request_repaint_after(std::time::Duration::from_millis(300));
                }
                let backend_for_driver = self.backend.clone();
                let driver = self.driver_state.get((), std::time::Duration::from_secs(1), || backend_for_driver.driver_state()).clone();
                ctx.data_mut(|d| {
                    d.insert_temp(egui::Id::NULL.with("driver_state"), driver);
                    d.insert_temp(egui::Id::NULL.with("driver_progress"), crate::driver::progress());
                    d.insert_temp(egui::Id::NULL.with("driver_elevated"), self.caps.elevated);
                });
                let backend = &self.backend;
                let lists: ThreatLists = self.threat_lists.get((), std::time::Duration::from_secs(1), || (backend.blocked_ips(), backend.threat_whitelist())).clone();
                let p2p = backend.p2p_apps();
                let extras: Vec<(bool, bool)> = self.extras_state.get((), std::time::Duration::from_secs(1), || backend.windows_extras_state()).clone();
                // Leave room for the title bar and footer so OK/Cancel stay on screen on a small monitor.
                let mut apps: Vec<QuotaApp> = self.protect.apps.iter().filter(|a| !a.locked).map(|a| (a.key.clone(), a.name.clone(), a.icon, a.path.clone())).collect();
                apps.sort_by_key(|a| a.1.to_lowercase());
                let quotas = QuotaUi { status: self.protect.quotas.clone(), apps };
                let body_h = (screen_size(ctx).y - 220.0).clamp(280.0, 520.0);
                if !crate::widgets::dialog("Settings").backdrop().flush().show(ctx, |ui| {
                    super::fluent::style(ui);
                    let sel_id = ui.scope_id().with("settings_section");
                    let mut sel: usize = ui.data_mut(|d| d.get_temp(sel_id).unwrap_or(0));
                    if let Some(n) = jump {
                        sel = n;
                    }
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(0.0, 2.0);
                        ui.allocate_ui_with_layout(egui::vec2(232.0, body_h), egui::Layout::top_down(egui::Align::Min), |ui| {
                            ui.add_space(14.0);
                            ui.horizontal(|ui| {
                                ui.add_space(20.0);
                                ui.label(egui::RichText::new("Settings").font(theme::bold(24.0)));
                            });
                            ui.add_space(14.0);
                            for (i, (name, icon, _)) in sections().iter().enumerate() {
                                let (rect, resp) = ui.allocate_exact_size(egui::vec2(232.0, 40.0), egui::Sense::click());
                                let rect = rect.shrink2(egui::vec2(8.0, 1.0));
                                let on = sel == i;
                                if on || resp.hovered() {
                                    ui.painter().rect_filled(rect, 4, if on { theme::nav_on() } else { theme::nav_on().gamma_multiply(0.6) });
                                }
                                if on {
                                    ui.painter().rect_filled(egui::Rect::from_center_size(rect.left_center() + egui::vec2(1.5, 0.0), egui::vec2(3.0, 16.0)), 2, theme::accent());
                                }
                                icons::paint(ui.painter(), *icon, egui::Rect::from_center_size(rect.left_center() + egui::vec2(26.0, 0.0), egui::vec2(18.0, 18.0)), theme::text());
                                ui.painter().text(rect.left_center() + egui::vec2(48.0, 0.0), Align2::LEFT_CENTER, name, theme::font(14.0), theme::text());
                                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                    if sel != i {
                                        ui.data_mut(|d| d.remove_temp::<usize>(privacy_tab_id()));
                                    }
                                    sel = i;
                                }
                            }
                        });
                        ui.vertical(|ui| {
                            ui.set_width(680.0);
                            egui::Frame::NONE.inner_margin(egui::Margin { left: 8, right: 24, top: 14, bottom: 0 }).show(ui, |ui| {
                                egui::ScrollArea::vertical().max_height(body_h - 14.0).show(ui, |ui| settings_form(ui, draft, live, sel, &profiles, &lists, &extras, &quotas, &p2p, &mut out));
                            });
                        });
                    });
                    ui.data_mut(|d| d.insert_temp(sel_id, sel));
                    let (foot, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 64.0), egui::Sense::hover());
                    ui.painter().rect_filled(foot, 0, theme::footer());
                    ui.painter().hline(foot.x_range(), foot.top(), egui::Stroke::new(1.0, theme::card_edge()));
                    ui.scope_builder(egui::UiBuilder::new().max_rect(foot.shrink2(egui::vec2(24.0, 14.0))).layout(egui::Layout::right_to_left(egui::Align::Center)), |ui| {
                        for (label, ok) in [("Save", true), ("Cancel", false)] {
                            let (rect, resp) = ui.allocate_exact_size(egui::vec2(120.0, 34.0), egui::Sense::click());
                            let (fill, ink) = if ok { (theme::accent(), theme::pick(theme::WHITE, egui::Color32::from_rgb(0x10, 0x15, 0x1f))) } else { (theme::ctl(), theme::text()) };
                            ui.painter().rect_filled(rect, 4, if resp.hovered() { fill.gamma_multiply(0.9) } else { fill });
                            if !ok {
                                ui.painter().rect_stroke(rect, 4, egui::Stroke::new(1.0, theme::card_edge()), egui::StrokeKind::Inside);
                            }
                            ui.painter().text(rect.center(), Align2::CENTER_CENTER, label, theme::font(14.0), ink);
                            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                out = if ok { Outcome::Apply(draft.clone()) } else { Outcome::Close };
                            }
                        }
                    });
                }) {
                    out = Outcome::Close;
                }
                out
            }
        };
        if let Some(body) = notice {
            dialog = Dialog::Info { title: "Wallpaper".into(), body };
        }
        match outcome {
            Outcome::Keep => self.dialog = Some(dialog),
            // Switches flipped on the Plugins page start plugins at once; closing without Save puts them back.
            Outcome::Close => crate::plugins::wasm::manager::apply(&self.settings, ctx),
            Outcome::Apply(s) => self.apply_settings(ctx, *s),
            Outcome::Confirmed(action) => self.run_confirmed(ctx, action),
            Outcome::Rename(mac, name) => {
                if let Some(net) = self.scanner.networks.get(self.scanner.network).cloned() {
                    self.run_bg(move |b| {
                        b.rename_device(&net, &mac, &name);
                        Ok(String::new())
                    });
                }
            }
            Outcome::Trust(mac, trusted) => {
                if let Some(net) = self.scanner.networks.get(self.scanner.network).cloned() {
                    self.run_bg(move |b| {
                        b.set_device_trusted(&net, &mac, trusted);
                        Ok(String::new())
                    });
                }
                self.dialog = Some(dialog);
            }
            Outcome::IpInfo(ip) => {
                self.dialog = Some(dialog);
                self.open_ip_info(ctx, &ip);
            }
            Outcome::SwitchRuleset(_) | Outcome::NewRuleset => {
                if let Dialog::Settings(draft) = dialog {
                    self.settings_back = Some(draft);
                }
                match outcome {
                    Outcome::SwitchRuleset(name) => self.switch_profile(&name),
                    _ => self.new_profile(),
                }
                if self.dialog.is_none() {
                    self.dialog = self.settings_back.take().map(Dialog::Settings);
                }
            }
            Outcome::Then(c) => {
                if let Dialog::Settings(draft) = dialog {
                    self.settings_back = Some(draft);
                }
                self.dialog = Some(Dialog::Confirm(c));
            }
            Outcome::WizardSkip => {
                self.settings.wizard_seen = crate::settings::WIZARD_VERSION;
                let _ = self.settings.save();
            }
            Outcome::WizardDone => {
                let Dialog::Wizard(w) = dialog else { return };
                let w = *w;
                let mut s = w.draft;
                s.wizard_seen = crate::settings::WIZARD_VERSION;
                self.apply_settings(ctx, s);
                self.dialog = super::dialogs::mode_confirm(w.firewall).map(Dialog::Confirm);
            }
            Outcome::RunWizard(draft) => {
                self.apply_settings(ctx, *draft);
                self.dialog = Some(Dialog::Wizard(Box::new(crate::ui::wizard::Wizard::new(self.settings.clone()))));
            }
            Outcome::StartUpdate(rel) => self.start_update(ctx, rel),
            Outcome::TestAlert(kind, s) => {
                self.backend.test_alert(kind.key(), &s);
                self.dialog = Some(dialog);
                self.notify("Test notification sent");
            }
            Outcome::ResetWindow => {
                self.reset_window();
                self.dialog = Some(dialog);
                self.notify("Window size and position reset");
            }
            Outcome::TestAsk => {
                self.popup_seq += 1;
                self.asks.push((self.popup_seq, crate::data::ConnectAsk::demo()));
                self.dialog = Some(dialog);
                self.notify("Test Prompt prompt shown");
            }
            Outcome::ExportRules => {
                self.export_rules();
                self.dialog = Some(dialog);
            }
            Outcome::ImportRules => match self.begin_rules_import() {
                Some(confirm) => {
                    if let Dialog::Settings(draft) = dialog {
                        self.settings_back = Some(draft);
                    }
                    self.dialog = Some(Dialog::Confirm(confirm));
                }
                None => self.dialog = Some(dialog),
            },
            Outcome::TestThreat => {
                self.popup_seq += 1;
                self.threats.push((self.popup_seq, crate::data::Threat::test(), None));
                self.dialog = Some(dialog);
                self.notify("Test Malicious IP popup shown");
            }
            Outcome::InstallService { desktop, start_menu } => self.change_service(ctx, true, desktop, start_menu),
            Outcome::Unlocked(Gated::Settings) => self.show_settings(),
            Outcome::Unlocked(Gated::Exit) => {
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Outcome::Unlocked(Gated::Restart) => self.restart_now(ctx),
            Outcome::Unlocked(Gated::ServiceStop) => {
                self.stop_asked = None;
                crate::sys::autostart::answer_stop(true);
            }
        }
        if !matches!(self.dialog, Some(Dialog::Settings(_))) {
            // Settings is closed: forget the startup switches' cached state (Task Manager can change it), and keep a finished download.
            ctx.data_mut(|d| {
                d.remove_temp::<Autostart>(egui::Id::unique("autostart"));
                d.remove_temp::<bool>(egui::Id::unique("autostart").with("asked"));
            });
            if let Some(path) = ctx.data_mut(|d| d.remove_temp::<String>(egui::Id::unique("geo_downloaded"))) {
                let mut s = self.settings.clone();
                s.geo_db_path = Some(path);
                self.apply_settings(ctx, s);
            }
        }
        // The confirmation is over: back to the Settings edits it interrupted.
        if self.dialog.is_none()
            && let Some(draft) = self.settings_back.take()
        {
            self.dialog = Some(Dialog::Settings(draft));
        }
    }
}

/// One release's notes; versions the user hasn't installed yet are highlighted, older ones dimmed.
fn release_notes(ui: &mut Ui, note: &crate::update::Note) {
    let frame = if note.missed { egui::Frame::NONE.fill(theme::accent_soft()) } else { egui::Frame::NONE };
    frame.inner_margin(6.0).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("Version {}", note.version)).font(theme::bold(15.0)));
            if note.missed {
                ui.label(egui::RichText::new("NEW").font(theme::bold(11.0)).color(theme::green()));
            } else {
                ui.weak("already installed");
            }
        });
        ui.add_enabled_ui(note.missed, |ui| changelog(ui, &note.notes));
    });
    ui.add_space(4.0);
}

/// Release notes are markdown; show headings in bold and list items as bullets, and leave out links.
fn changelog(ui: &mut Ui, notes: &str) {
    for line in notes.lines().map(str::trim).filter(|l| !l.is_empty() && !l.contains("](")) {
        if let Some(h) = line.strip_prefix('#') {
            ui.label(egui::RichText::new(h.trim_start_matches('#').trim()).strong());
        } else if let Some(item) = line.strip_prefix("- ") {
            ui.label(format!("•  {item}"));
        } else {
            ui.label(line);
        }
    }
}

/// Master/detail editor: pick an alert at the left, set its switch, desktop popup and level at the right.
fn alert_settings(ui: &mut Ui, s: &mut Settings) {
    group(ui, "", |c| {
        c.row("Send alerts to the Windows event log", "Application log, source \"RustWarden\".", |ui| {
            crate::widgets::small_toggle(ui, &mut s.event_log);
        });
        c.enable(crate::sys::is_elevated());
        c.row("Behaviour baseline", "Learns each program's usual countries, networks, hours and daily volume, and alerts when it steps outside them. Needs administrator.", |ui| {
            crate::widgets::small_toggle(ui, &mut s.baseline);
        });
        c.enable(true);
        if s.baseline {
            c.row("Baseline window", "Built from the last N days, with no alerts for the first M days.", |ui| {
                let days = s.baseline_days;
                ui.add(egui::DragValue::new(&mut s.baseline_learn_days).range(1..=days).suffix(" days"));
                ui.label("no alerts for");
                ui.add(egui::DragValue::new(&mut s.baseline_days).range(3..=365).suffix(" days"));
            });
            c.row("Repeat the same alert at most every", "", |ui| {
                ui.add(egui::DragValue::new(&mut s.baseline_throttle_hours).range(1..=720).suffix(" h"));
            });
            // Turning this on is the consent to send addresses out: with the net-info lookup off, it picks Team Cymru.
            let was = s.baseline_networks;
            c.row("Learn networks too", "Sends each internet address to the net-info service, Team Cymru if none is set.", |ui| {
                crate::widgets::small_toggle(ui, &mut s.baseline_networks);
            });
            if s.baseline_networks && !was && s.net_info == NetInfoSource::Off {
                s.net_info = NetInfoSource::TeamCymru;
            }
        }
    });
    let sel_id = ui.scope_id().with("alert_sel");
    let mut sel: usize = ui.data_mut(|d| d.get_temp(sel_id).unwrap_or(0));
    if let Some(i) = ui.ctx().data_mut(|d| d.remove_temp::<usize>(egui::Id::unique(ALERT_JUMP))) {
        sel = i;
    }
    group(ui, "Alert types", |c| {
        c.block(|ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 24.0;
                ui.vertical(|ui| {
                    ui.set_width(290.0);
                    egui::ScrollArea::vertical().min_scrolled_height(410.0).max_height(410.0).show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for (i, kind) in AlertKind::ALL.iter().enumerate() {
                            // Needs the driver, so it only appears in Driver mode with the driver installed.
                            if matches!(*kind, AlertKind::InboundScan | AlertKind::RogueDhcp | AlertKind::TlsMismatch) && (s.app_mode != crate::settings::AppMode::Driver || !crate::driver::ready()) {
                                continue;
                            }
                            let (name, on) = (kind.title(), kind.enabled(&s.alerts));
                            let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), egui::Sense::click());
                            if sel == i {
                                ui.painter().rect_filled(rect, 4, theme::nav_on());
                                ui.painter().rect_filled(egui::Rect::from_center_size(rect.left_center() + egui::vec2(1.5, 0.0), egui::vec2(3.0, 16.0)), 2, theme::accent());
                            } else if resp.hovered() {
                                ui.painter().rect_filled(rect, 4, theme::nav_on().gamma_multiply(0.6));
                            }
                            let badge = egui::Rect::from_center_size(rect.left_center() + egui::vec2(30.0, 0.0), egui::vec2(34.0, 20.0));
                            if on {
                                ui.painter().rect_filled(badge, 4, theme::green());
                                ui.painter().text(badge.center(), Align2::CENTER_CENTER, "ON", theme::bold(11.0), theme::WHITE);
                            }
                            ui.painter().text(rect.left_center() + egui::vec2(56.0, 0.0), Align2::LEFT_CENTER, name, theme::font(14.0), theme::text());
                            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                sel = i;
                            }
                        }
                    });
                });
                ui.vertical(|ui| {
                    ui.set_width(300.0);
                    ui.spacing_mut().item_spacing.y = 18.0;
                    let kind = AlertKind::ALL[sel.min(AlertKind::ALL.len() - 1)];
                    ui.label(egui::RichText::new(kind.title()).font(theme::bold(18.0)));
                    crate::widgets::switch(ui, kind.switch_mut(&mut s.alerts), kind.description());
                    let mut opts = kind.opts(s);
                    let on = kind.enabled(&s.alerts);
                    ui.add_enabled_ui(on, |ui| {
                        ui.spacing_mut().item_spacing.y = 18.0;
                        crate::widgets::switch(ui, &mut opts.desktop, "Show desktop notification.");
                        let log_label = if s.event_log { "Send to the Windows event log." } else { "Send to the Windows event log (switched off at the top of this page)." };
                        crate::widgets::switch(ui, &mut opts.event_log, log_label);
                        let has_plugin = crate::plugins::wasm::manager::any_notification_plugin();
                        ui.add_enabled_ui(has_plugin, |ui| {
                            crate::widgets::switch(ui, &mut opts.api, "Send to Notification Plugins.");
                        })
                        .response
                        .on_disabled_hover_text("Switch on a notification plugin in Settings > Plugins first.");
                        ui.label(egui::RichText::new("Alerts level:").color(theme::text_dim()));
                        egui::ComboBox::from_id_salt("alert_level").width(300.0).selected_text(opts.level.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                            for l in AlertLevel::ALL {
                                ui.selectable_value(&mut opts.level, l, l.label());
                            }
                        });
                        ui.label(egui::RichText::new(opts.level.hint()).color(theme::text_dim()));
                        if kind == AlertKind::ThinkBroadband {
                            ui.label(egui::RichText::new("The packet-loss level is set in Settings > Plugins > thinkbroadband > Settings.").color(theme::text_dim()));
                        }
                        if kind == AlertKind::DeviceReturned {
                            ui.horizontal(|ui| {
                                ui.label("Device returned after");
                                crate::widgets::num_field(ui, &mut s.device_return_days, 1..=365, " days away");
                            });
                        }
                        if kind == AlertKind::DnsLeak {
                            ui.label(
                                egui::RichText::new("Ignore adapters whose name contains (comma separated). Bridged virtual machines never use the VPN, so their adapters are skipped:")
                                    .color(theme::text_dim()),
                            );
                            ui.add(egui::TextEdit::singleline(&mut s.dns_leak_ignore).desired_width(300.0));
                        }
                        if kind == AlertKind::Away {
                            ui.horizontal(|ui| {
                                ui.label("Away after");
                                crate::widgets::num_field(ui, &mut s.away_after_minutes, 1..=1440, " min idle");
                            });
                        }
                    });
                    if opts != kind.default_opts() || s.alert_opts.contains_key(kind.key()) {
                        s.alert_opts.insert(kind.key().to_owned(), opts);
                    }
                });
            });
        });
    });
    ui.data_mut(|d| d.insert_temp(sel_id, sel));
}

fn other_section(ui: &mut Ui, s: &mut Settings, out: &mut Outcome) {
    group(ui, "", |c| {
        let mut demo = s.mode == Mode::Demo;
        c.row("Use demo data", "Shows placeholder data and a DEMO tag in the header. Turn off to measure this machine.", |ui| {
            if crate::widgets::small_toggle(ui, &mut demo).changed() {
                s.mode = if demo { Mode::Demo } else { Mode::Live };
            }
        });
    });

    group(ui, "Notifications", |c| {
        let sel_id = c.ui_id().with("test_alert_kind");
        c.row(
            "Send a test notification",
            "Shows a made-up Prompt prompt, Malicious IP popup or alert of the chosen type, without recording it or changing any firewall rule. Alerts are delivered the way a real one is (per its Alerts settings).",
            |ui| {
                // 0 = Prompt, 1 = Malicious IP, then the alert kinds.
                const EXTRA: [&str; 2] = ["Prompt", "Malicious IP"];
                let name = |i: usize| if i < EXTRA.len() { EXTRA[i] } else { AlertKind::ALL[i - EXTRA.len()].title() };
                let mut sel: usize = ui.data_mut(|d| d.get_temp(sel_id).unwrap_or(0)).min(EXTRA.len() + AlertKind::ALL.len() - 1);
                if ui.button("Test").clicked() {
                    *out = match sel {
                        0 => Outcome::TestAsk,
                        1 => Outcome::TestThreat,
                        i => Outcome::TestAlert(AlertKind::ALL[i - EXTRA.len()], Box::new(s.clone())),
                    };
                }
                egui::ComboBox::from_id_salt("test_alert_kind").selected_text(name(sel)).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                    for i in 0..EXTRA.len() + AlertKind::ALL.len() {
                        ui.selectable_value(&mut sel, i, name(i));
                    }
                });
                ui.data_mut(|d| d.insert_temp(sel_id, sel));
            },
        );
    });

    group(ui, "Back up rules and settings", |c| {
        c.row("Export rules and settings", "Saves the programs you have blocked, your destination rules and all your settings (the password is left out; tokens and webhook addresses stay encrypted for this Windows user) to a file, to bring back after a reinstall or when the app changes name.", |ui| {
            if ui.button("Export…").clicked() {
                *out = Outcome::ExportRules;
            }
        });
        c.row("Import rules and settings", "Reads a file from Export and applies what differs from now, after showing you a summary. Files from older or newer versions work: settings they lack keep their current value. Nothing is removed.", |ui| {
            if ui.button("Import…").clicked() {
                *out = Outcome::ImportRules;
            }
        });
    });

    group(ui, "Window", |c| {
        c.row("Window size and position", "RustWarden reopens where you left it. If that goes wrong, this puts it back to the default size in the middle of the screen.", |ui| {
            if ui.button("Reset window").clicked() {
                *out = Outcome::ResetWindow;
            }
        });
    });

    group(ui, "Clean up", |c| {
        c.row("Downloaded components", "RustWarden has no installer, so what it downloads stays on this PC until you remove it here: speedtest-cli, the GeoIP and ASN databases, the malicious IP and domain lists and the thinkbroadband sign-in.", |ui| {
            if ui.button("Remove…").clicked() {
                *out = Outcome::Then(Confirm {
                    title: "Remove downloaded components?".into(),
                    body: crate::cleanup::warning(),
                    yes: "Remove and switch off".into(),
                    action: ConfirmAction::CleanUp,
                });
            }
        });
    });

    group(ui, "Windows service", |c| {
        c.row("Service", "Lets RustWarden open as administrator without a prompt. Installing or removing it asks for administrator approval once and restarts RustWarden.", |ui| {
            let installed = ui.data(|d| d.get_temp::<bool>(egui::Id::NULL.with("service_installed"))).unwrap_or(false);
            for (label, install) in [("Uninstall service…", false), ("Install service…", true)] {
                if ui.add_enabled(install != installed, egui::Button::new(label)).clicked() {
                    *out = Outcome::Then(Confirm {
                        title: format!("{} the service?", if install { "Install" } else { "Uninstall" }),
                        body: "RustWarden will restart afterwards.".into(),
                        yes: format!("{} and restart", if install { "Install" } else { "Uninstall" }),
                        action: ConfirmAction::Service { install },
                    });
                }
            }
        });
    });

    group(ui, "Updates", |c| {
        // From 1.0.0 releases come straight from the public GitHub repo, so there is no server to enter.
        if !crate::update::uses_public_repo() {
            c.row(
            "Update server",
            "RustWarden checks for a new version when it starts and every few hours, and quietly does nothing if that fails. Downloads are only installed if their SHA-256 matches the published one.",
            |ui| {
                let r = ui.add(egui::TextEdit::singleline(&mut s.update_url).hint_text("https://example.com/updates/").desired_width(260.0));
                crate::widgets::edit_menu(ui, &r, &mut s.update_url, true);
                s.update_url = s.update_url.trim().to_owned();
            },
        );
        }
        c.row("Update channel", "", |ui| {
            crate::widgets::radio(ui, &mut s.update_channel, crate::settings::UpdateChannel::Dev, "Dev");
            crate::widgets::radio(ui, &mut s.update_channel, crate::settings::UpdateChannel::Release, "Release");
        });
        if s.update_channel == crate::settings::UpdateChannel::Dev {
            c.block(|ui| {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    "Dev builds are alpha-level software and may break. Switch back to Release at any time; the next update check installs the latest release.",
                );
            });
        }
        if s.update_channel == crate::settings::UpdateChannel::Dev {
            c.row("First-run wizard", "Dev channel only: runs the setup wizard again. Pending changes here are saved first.", |ui| {
                if ui.button("Run wizard").clicked() {
                    *out = Outcome::RunWizard(Box::new(s.clone()));
                }
            });
        }
        c.row("App mode", "Driver mode adds features that need a small signed network driver (WinDivert), such as download limits. Normal mode needs no driver and hides those features.", |ui| {
            crate::widgets::dropdown(ui, None, &mut s.app_mode, &[crate::settings::AppMode::Normal, crate::settings::AppMode::Driver], |m| m.label().into(), 130.0);
        });
        if s.app_mode == crate::settings::AppMode::Driver {
            driver_rows(c, out);
            c.row("Force DNS through my resolver", "Sends every program's DNS lookups (port 53) to the resolver below, whatever server they were aimed at, and makes the answers look as if the original server gave them. This closes DNS leaks. IPv4 and plain DNS only: encrypted DNS is not touched. The resolver must be reachable on your normal connection.", |ui| {
                crate::widgets::small_toggle(ui, &mut s.dns_enforce);
                ui.add_enabled(s.dns_enforce, egui::TextEdit::singleline(&mut s.dns_resolver).hint_text("1.1.1.1").desired_width(130.0));
                if s.dns_enforce && crate::live::dnsguard::parse_resolver(&s.dns_resolver).is_err() {
                    ui.colored_label(ui.visuals().warn_fg_color, "Enter an IPv4 address");
                }
            });
            c.row("Line speed (up / down, Mbps)", "Your connection's speed, for the priorities in Limits / QoS. Programs with a priority share it: High is never held back and is served first, Normal gets the rest, Low what is left after that. Only programs listed in Limits / QoS are shared this way. 0 = not set (no sharing).", |ui| {
                ui.add(egui::DragValue::new(&mut s.line_up_mbps).range(0..=100_000).suffix(" up"));
                ui.add(egui::DragValue::new(&mut s.line_down_mbps).range(0..=100_000).suffix(" down"));
            });
            c.row("Learn host names from the driver", "Reads the server name of new HTTPS connections and DNS answers on this PC (nothing leaves it), so the Connections tab shows names such as youtube.com, and the DNS Log also lists lookups made by programs with their own resolver, such as some browsers.", |ui| crate::widgets::small_toggle(ui, &mut s.driver_names));
            if crate::driver::ready() {
                c.row(
                    "QUIC fallback (programs)",
                    "Blocks QUIC (HTTP/3, UDP port 443) for these programs, separated by commas (for example chrome.exe, msedge.exe), so they use HTTPS over TCP. There the server name is in the open, which is what Block by domain and the host names read. Needs administrator rights.",
                    |ui| {
                        ui.add(egui::TextEdit::singleline(&mut s.quic_fallback).hint_text("chrome.exe, msedge.exe").desired_width(230.0));
                    },
                );
            }
        }
        c.row(
            "Let RustWarden's own downloads through the firewall",
            "While RustWarden runs its own curl, PowerShell or speed test helper (updates, lookups, downloads), that helper is allowed online for a few minutes even if a rule blocks it. Any rule switched off is switched back on afterwards, when RustWarden closes, or by Restore firewall defaults. Needs administrator rights.",
            |ui| crate::widgets::small_toggle(ui, &mut s.allow_helper_tools),
        );
        c.row(
            "VPN kill switch",
            "While a VPN is connected, blocks everything except your local network and the VPN's own server on your real network cards, so nothing can leave outside the tunnel. If the VPN drops, the block stays and the internet is cut until it reconnects. It switches itself on the first time it sees a VPN connected (a VPN such as PIA only creates its adapter when you press Connect), and turning it off lifts it. Use \"Let the VPN connect\" for two minutes to reach a new server. Needs administrator rights.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.vpn_kill_switch);
                if ui.add_enabled(s.vpn_kill_switch, egui::Button::new("Let the VPN connect")).on_hover_text("Opens the network for two minutes").clicked() {
                    crate::live::guard::release();
                }
            },
        );
        c.row(
            "Block DNS-over-HTTPS resolvers",
            "Blocks encrypted DNS (HTTPS and DNS-over-TLS, ports 443 and 853) to well-known public resolvers such as Google, Cloudflare, Quad9, OpenDNS, AdGuard and NextDNS, so browsers that bypass the system's DNS fall back to it, where domain blocks and the DNS log can see the lookups. Plain DNS is not touched. Needs administrator rights.",
            |ui| crate::widgets::small_toggle(ui, &mut s.block_doh),
        );
    });
}

/// The driver's status and its Install / Remove buttons (Settings > Other, Driver mode).
fn driver_rows(c: &mut crate::ui::fluent::Card, out: &mut Outcome) {
    c.row("Driver", "WinDivert, an open-source signed driver, is downloaded from github.com on request and checked against a pinned SHA-256. Needs administrator rights.", |ui| {
        let (state, busy, elevated) = ui.data(|d| {
            (
                d.get_temp::<crate::driver::DriverState>(egui::Id::NULL.with("driver_state")).unwrap_or(crate::driver::DriverState::Missing),
                d.get_temp::<String>(egui::Id::NULL.with("driver_progress")).unwrap_or_default(),
                d.get_temp::<bool>(egui::Id::NULL.with("driver_elevated")).unwrap_or(false),
            )
        });
        use crate::driver::DriverState::*;
        if !busy.is_empty() {
            ui.label(busy);
            return;
        }
        let ready = state == Ready;
        if ui.add_enabled(elevated && ready, egui::Button::new("Remove driver…")).clicked() {
            *out = Outcome::Then(Confirm { title: "Remove the driver?".into(), body: "Driver features switch off and the downloaded files are deleted.".into(), yes: "Remove".into(), action: ConfirmAction::RemoveDriver });
        }
        if ui.add_enabled(elevated && !ready, egui::Button::new("Download and install…")).clicked() {
            *out = Outcome::Then(Confirm {
                title: "Download the driver?".into(),
                body: "RustWarden will download WinDivert from github.com and keep it in Program Files\\RustWarden\\driver. Microsoft Defender sometimes flags WinDivert, because some cheat tools use it, so RustWarden first adds a Defender exclusion for that folder only (removed again when you remove the driver).".into(),
                yes: "Allow and install".into(),
                action: ConfirmAction::InstallDriver,
            });
        }
        match &state {
            Ready => ui.label("Installed"),
            Missing => ui.label(if elevated { "Not installed" } else { "Not installed (needs administrator)" }),
            Blocked(why) => ui.colored_label(ui.visuals().warn_fg_color, why),
        };
    });
}

/// Related controls (a label, its slider, its description) read as one group.
fn tight<R>(ui: &mut Ui, f: impl FnOnce(&mut Ui) -> R) -> R {
    let gap = std::mem::replace(&mut ui.spacing_mut().item_spacing.y, 4.0);
    let r = f(ui);
    ui.spacing_mut().item_spacing.y = gap;
    r
}

/// Temp-data key a popup sets (to an `AlertKind::ALL` index) so Settings > Alerts opens on that kind.
pub(super) const ALERT_JUMP: &str = "alert_jump";

fn sections() -> [(&'static str, Icon, egui::Color32); 12] {
    [
        ("General", Icon::Sliders, theme::accent()),
        ("Personalise", Icon::Palette, theme::orange()),
        ("Data Plan", Icon::Bell, theme::orange()),
        ("Quotas", Icon::Filter, theme::orange()),
        ("Alerts", Icon::Alerts, theme::red()),
        ("Network Scanner", Icon::Scanner, theme::green()),
        ("Firewall", Icon::Shield, theme::green()),
        ("Malicious IPs", Icon::ShieldAlert, theme::red()),
        ("Privacy", Icon::Privacy, theme::text()),
        ("Countries & Network", Icon::Globe, theme::accent()),
        ("Plugins", Icon::House, theme::accent()),
        ("Other", Icon::More, theme::text()),
    ]
}

#[allow(clippy::too_many_arguments)]
fn settings_form(
    ui: &mut Ui,
    s: &mut Settings,
    live: bool,
    sel: usize,
    profiles: &(Vec<String>, String),
    lists: &ThreatLists,
    extras: &[(bool, bool)],
    quotas: &QuotaUi,
    p2p: &[crate::data::P2pApp],
    out: &mut Outcome,
) {
    // Roomy controls on every page; long pages scroll.
    let sp = ui.spacing_mut();
    sp.item_spacing = egui::vec2(10.0, 16.0);
    sp.interact_size.y = 34.0;
    sp.button_padding = egui::vec2(12.0, 6.0);
    tight(ui, |ui| ui.label(egui::RichText::new(sections()[sel].0).font(theme::bold(26.0))));
    match sel {
        0 => general_section(ui, s, out),
        1 => personalise_section(ui, s),
        2 => plan_section(ui, s),
        3 => quotas_section(ui, s, quotas),
        4 => alert_settings(ui, s),
        5 => scanner_section(ui, s),
        6 => firewall_section(ui, s, live, profiles, extras, out),
        7 => threat_section(ui, s, lists, out),
        8 => privacy_section(ui, s, p2p),
        9 => countries_section(ui, s),
        10 => group(ui, "", |c| c.block(|ui| crate::ui::plugins::section(ui, s))),
        _ => other_section(ui, s, out),
    }
}

fn personalise_section(ui: &mut Ui, s: &mut Settings) {
    group(ui, "", |c| {
        c.row("Follow the Windows theme", "Switches between light and dark by itself when Windows does (Windows Settings > Personalisation > Colours). Turn it off to choose a theme here.", |ui| {
            crate::widgets::small_toggle(ui, &mut s.follow_windows_theme);
        });
        c.enable(!s.follow_windows_theme);
        c.row("Theme", "Light or dark", |ui| {
            egui::ComboBox::from_id_salt("theme").selected_text(s.theme.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                for t in [Theme::Light, Theme::Dark] {
                    ui.selectable_value(&mut s.theme, t, t.label());
                }
            });
        });
        c.enable(true);
        c.row("Acrylic intensity", "How much of the colours behind the window shine through (Windows 11).", |ui| {
            crate::widgets::slider(ui, &mut s.acrylic, 0.0..=1.0, 0.01, |v| format!("{:.0}%", v * 100.0));
        });
        c.row("Popup opacity", "The least opaque the Traffic detail popups get, however strong the Acrylic is. Notifications are always solid.", |ui| {
            crate::widgets::slider(ui, &mut s.popup_opacity, 0.5..=1.0, 0.01, |v| format!("{:.0}%", v * 100.0));
        });
        c.row("Popup corner", "Where alert and Prompt popups appear.", |ui| {
            egui::ComboBox::from_id_salt("popup_corner").selected_text(s.popup_corner.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                for corner in crate::ui::toast::Corner::ALL {
                    ui.selectable_value(&mut s.popup_corner, corner, corner.label());
                }
            });
        });
        c.row("Popup duration", "How long an alert popup stays up. Prompt prompts stay until you answer.", |ui| {
            let mut secs = s.popup_secs as f32;
            crate::widgets::slider(ui, &mut secs, 3.0..=60.0, 1.0, |v| format!("{v:.0} s"));
            s.popup_secs = secs.round() as u32;
        });
        c.row("Popups shown at once", "The most alert popups on screen together; older ones make way for new ones.", |ui| {
            let mut most = s.popup_max as f32;
            crate::widgets::slider(ui, &mut most, 1.0..=8.0, 1.0, |v| format!("{v:.0}"));
            s.popup_max = most.round() as u32;
        });
        c.row("Use Windows accent colour", "Follows the accent colour set in Windows, and changes with it.", |ui| {
            crate::widgets::small_toggle(ui, &mut s.accent_windows);
        });
        c.enable(!s.accent_windows);
        c.block(|ui| accent_picker(ui, &mut s.accent));
        c.enable(true);
        c.row("Tint with wallpaper colour", "Uses the Mica backdrop, coloured by your wallpaper like File Explorer, instead of grey acrylic.", |ui| {
            crate::widgets::small_toggle(ui, &mut s.tint);
        });
        c.row("UI scale", "Scales every window, popup and banner. Applies when you save.", |ui| {
            crate::widgets::slider(ui, &mut s.text_scale, 1.0..=1.5, 0.1, |v| format!("{v:.1}x")).on_hover_text("1.0x – 1.5x");
        });
    });
}

/// The Windows 11 accent colours, 8 to a row.
const ACCENTS: [u32; 48] = [
    0xFFB900, 0xFF8C00, 0xF7630C, 0xCA5010, 0xDA3B01, 0xEF6950, 0xD13438, 0xFF4343, 0xE74856, 0xE81123, 0xEA005E, 0xC30052, 0xE3008C, 0xBF0077, 0xC239B3, 0x9A0089, 0x0078D7, 0x0063B1, 0x8E8CD8,
    0x6B69D6, 0x8764B8, 0x744DA9, 0xB146C2, 0x881798, 0x0099BC, 0x2D7D9A, 0x00B7C3, 0x038387, 0x00B294, 0x018574, 0x00CC6A, 0x10893E, 0x7A7574, 0x5D5A58, 0x68768A, 0x515C6B, 0x567C73, 0x486860,
    0x498205, 0x107C10, 0x767676, 0x4C4A48, 0x69797E, 0x4A5459, 0x647C64, 0x525E54, 0x847545, 0x7E735F,
];

/// A grid of Windows' accent colours with a custom colour button; `hex` is "" for the built-in look.
fn accent_picker(ui: &mut Ui, hex: &mut String) {
    let current = crate::settings::parse_hex(hex);
    ui.horizontal(|ui| {
        ui.label("Accent colour");
        if ui.button("Default").clicked() {
            hex.clear();
        }
        let mut rgb = current.unwrap_or_else(theme::accent_default);
        if ui.color_edit_button_srgb(&mut rgb).changed() {
            *hex = format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2]);
        }
    });
    ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
    for row in ACCENTS.chunks(8) {
        ui.horizontal(|ui| {
            for &c in row {
                let rgb = [(c >> 16) as u8, (c >> 8) as u8, c as u8];
                let (rect, r) = ui.allocate_exact_size(egui::vec2(34.0, 34.0), egui::Sense::click());
                let col = egui::Color32::from_rgb(rgb[0], rgb[1], rgb[2]);
                ui.painter().rect_filled(rect, 4, col);
                if current == Some(rgb) {
                    ui.painter().rect_stroke(rect.expand(1.0), 4, egui::Stroke::new(2.0, theme::text()), egui::StrokeKind::Outside);
                    let ink = if (0.299 * rgb[0] as f32 + 0.587 * rgb[1] as f32 + 0.114 * rgb[2] as f32) > 150.0 { egui::Color32::BLACK } else { egui::Color32::WHITE };
                    icons::paint(ui.painter(), Icon::Check, rect.shrink(8.0), ink);
                } else if r.hovered() {
                    ui.painter().rect_stroke(rect, 4, egui::Stroke::new(1.5, theme::text_dim()), egui::StrokeKind::Inside);
                }
                if r.clicked() {
                    *hex = format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2]);
                }
            }
        });
    }
}

fn general_section(ui: &mut Ui, s: &mut Settings, out: &mut Outcome) {
    group(ui, "", |c| {
        c.block(startup_controls);
        c.row("Show rates in bits", "Instead of bytes.", |ui| {
            crate::widgets::small_toggle(ui, &mut s.bits);
        });
    });

    group(ui, "Tamper protection", |c| {
        let sub = if s.tamper_on() {
            "A password is set: opening Settings, Exit and Restart ask for it."
        } else {
            "Set a password to lock Settings, Exit and Restart (shared or family PCs). It does not stop an administrator ending the process or the service."
        };
        let sub = if s.tamper_new.trim().is_empty() { sub.to_owned() } else { format!("{sub} Saved when you press Save.") };
        c.row("Password", &sub, |ui| {
            if s.tamper_on() && ui.button("Remove").clicked() {
                s.tamper_hash.clear();
                s.tamper_new.clear();
            }
            let hint = if s.tamper_on() { "New password" } else { "Password" };
            ui.add(egui::TextEdit::singleline(&mut s.tamper_new).password(true).hint_text(hint).desired_width(200.0));
        });
    });

    group(ui, "Firewall list", |c| {
        c.row(
            "Split \"NT Kernel & System\" by service",
            "Windows reports all kernel networking (file sharing, NetBIOS, discovery, HTTP.sys) as one program. This shows a row per service, told apart by port. Applies to new traffic.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.split_kernel);
            },
        );
    });

    group(ui, "History", |c| {
        c.row("Traffic history", "How long Live mode keeps traffic history.", |ui| {
            crate::widgets::num_field(ui, &mut s.retention_days, 1..=3650, " days");
        });
        c.row("Hardware history", "How long Live mode keeps hardware history (CPU, memory, disk, GPU).", |ui| {
            crate::widgets::num_field(ui, &mut s.hardware_history_hours, 1..=24 * 30, " hours");
        });
        c.enable(crate::sys::is_elevated());
        c.row("DNS log", "Logs each program's DNS lookups (Network > DNS Log).", |ui| {
            crate::widgets::small_toggle(ui, &mut s.dns_log);
        });
        c.enable(crate::sys::is_elevated() && s.dns_log);
        c.row("DNS log history", "How long the DNS log is kept. It stays on this PC; programs hidden in Settings > Privacy are left out.", |ui| {
            crate::widgets::num_field(ui, &mut s.dns_retention_days, 1..=365, " days");
        });
        c.enable(true);
        // Demo mode keeps no history, so there is nothing to clear.
        c.row("Clear traffic history", "Deletes the stored traffic history of Live mode. Alerts, apps and devices are kept.", |ui| {
            if ui.add_enabled(s.mode == Mode::Live, egui::Button::new("Clear…")).on_disabled_hover_text("Demo mode keeps no history").clicked() {
                *out = Outcome::Then(Confirm {
                    title: "Clear traffic history?".into(),
                    body: "Deletes the stored traffic history of Live mode. Alerts, apps and devices are kept.".into(),
                    yes: "Clear history".into(),
                    action: ConfirmAction::ClearHistory,
                });
            }
        });
    });
}

#[derive(Clone, Default)]
struct Autostart {
    startup: bool,
    hidden: bool,
    error: String,
}

/// Acts immediately, not on Apply.
fn startup_controls(ui: &mut Ui) {
    use crate::sys::autostart as a;
    let id = egui::Id::unique("autostart");
    // Both the reads and the writes start reg.exe, so they run on a thread and put the answer back here.
    let apply = |ctx: egui::Context, change: Option<(bool, bool)>| {
        std::thread::spawn(move || {
            let error = change.and_then(|(on, hidden)| a::set_startup(on, hidden).err()).unwrap_or_default();
            ctx.data_mut(|d| d.insert_temp(id, Autostart { startup: a::startup_enabled(), hidden: a::startup_hidden(), error }));
            ctx.request_repaint();
        });
    };
    let Some(mut st) = ui.data_mut(|d| d.get_temp::<Autostart>(id)) else {
        let asked_id = id.with("asked");
        if !ui.data_mut(|d| d.get_temp::<bool>(asked_id)).unwrap_or(false) {
            ui.data_mut(|d| d.insert_temp(asked_id, true));
            apply(ui.ctx().clone(), None);
        }
        ui.label(egui::RichText::new("Checking the startup setting…").color(theme::text_dim()));
        return;
    };
    ui.add_space(4.0);
    let mut change = None;
    if crate::widgets::switch(ui, &mut st.startup, "Start RustWarden when Windows starts").changed() {
        // Hidden is on by default when first enabled.
        change = Some((st.startup, st.hidden || st.startup));
    }
    if st.startup && crate::widgets::switch(ui, &mut st.hidden, "Start hidden in the tray (don't show the window)").changed() {
        change = Some((true, st.hidden));
    }
    if !st.error.is_empty() {
        ui.colored_label(theme::red(), &st.error);
    }
    // Written back only for a change, and before the thread starts, so the thread's answer is never overwritten.
    if let Some(c) = change {
        ui.data_mut(|d| d.insert_temp(id, st));
        apply(ui.ctx().clone(), Some(c));
    }
}

fn plan_section(ui: &mut Ui, s: &mut Settings) {
    group(ui, "", |c| {
        // The warning is the "Data plan" alert, so turning the plan on turns that alert on too.
        c.row("Warn at 75% and when over the limit", "", |ui| {
            if crate::widgets::small_toggle(ui, &mut s.data_plan.enabled).changed() && s.data_plan.enabled {
                s.alerts.data_plan = true;
            }
        });
        c.row("Allowance", "How much data your plan includes, and how it is counted.", |ui| {
            egui::ComboBox::from_id_salt("plan_dir").selected_text(s.data_plan.direction.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                for d in PlanDirection::ALL {
                    ui.selectable_value(&mut s.data_plan.direction, d, d.label());
                }
            });
            egui::ComboBox::from_id_salt("plan_period").selected_text(s.data_plan.period.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                for p in PlanPeriod::ALL {
                    ui.selectable_value(&mut s.data_plan.period, p, p.label());
                }
            });
            crate::widgets::num_field(ui, &mut s.data_plan.limit_gb, 0.1..=100_000.0, " GB");
        });
        c.row("Don't count local network traffic", "", |ui| {
            crate::widgets::small_toggle(ui, &mut s.data_plan.exclude_local);
        });
    });
}

/// What the Quotas page needs besides the settings: live usage, and the apps a quota can aim at (key, name, icon, path).
struct QuotaUi {
    status: Vec<crate::data::QuotaStatus>,
    apps: Vec<QuotaApp>,
}

type QuotaApp = (String, String, crate::data::AppIcon, String);

fn quotas_section(ui: &mut Ui, s: &mut Settings, ctx: &QuotaUi) {
    use crate::settings::{Quota, QuotaAction};
    ui.label(
        egui::RichText::new(
            "Limit how much data an app, or all internet traffic, may use in a day, week or month. Local network traffic isn't counted. You get an alert at the warning percentage and at 100%.",
        )
        .color(theme::text_dim()),
    );
    if s.quotas.is_empty() && !ctx.status.is_empty() {
        group(ui, "Sample quotas (Demo mode). Add one to try it.", |c| {
            for st in &ctx.status {
                c.row(&st.name, &format!("{} · {}", st.quota.period.label(), st.quota.action.label()), |ui| {
                    crate::widgets::quota_bar(ui, st, 150.0);
                });
            }
        });
    }
    let mut remove = None;
    for (i, q) in s.quotas.iter_mut().enumerate() {
        ui.push_id(("quota", q.id), |ui| {
            let shown = if q.app.is_empty() {
                "All traffic".to_owned()
            } else if q.app_name.is_empty() {
                q.app.clone()
            } else {
                q.app_name.clone()
            };
            group(ui, "", |c| {
                c.row(&shown, "Turn the quota on or off, or remove it.", |ui| {
                    if ui.button("Remove").clicked() {
                        remove = Some(i);
                    }
                    crate::widgets::small_toggle(ui, &mut q.enabled);
                });
                c.row("Applies to", "", |ui| {
                    // Room on the left of the closed box for the chosen app's icon, drawn over it after the box is laid out.
                    let chosen = ctx.apps.iter().find(|a| !q.app.is_empty() && a.0 == q.app);
                    let mut text = egui::text::LayoutJob::simple_singleline(shown.clone(), egui::TextStyle::Button.resolve(ui.style()), ui.visuals().text_color());
                    if chosen.is_some() {
                        text.sections[0].leading_space = 22.0;
                    }
                    // A long app name is cut short inside the box instead of running over its edge.
                    text.wrap = egui::text::TextWrapping::truncate_at_width(160.0);
                    let combo = egui::ComboBox::from_id_salt("quota_app").width(220.0).selected_text(text).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                        if ui.selectable_label(q.app.is_empty(), "All traffic").clicked() {
                            (q.app, q.app_name) = (String::new(), String::new());
                            if q.action.needs_app() {
                                q.action = QuotaAction::AlertOnly;
                            }
                        }
                        for (key, name, icon, path) in &ctx.apps {
                            let (rect, r) = ui.allocate_exact_size(egui::vec2(ui.available_width().max(200.0), 26.0), egui::Sense::click());
                            if r.hovered() || &q.app == key {
                                ui.painter().rect_filled(rect, 4, theme::text_dim().gamma_multiply(if r.hovered() { 0.25 } else { 0.12 }));
                            }
                            icons::app_icon_for(ui.painter(), *icon, path, egui::Rect::from_center_size(egui::pos2(rect.left() + 14.0, rect.center().y), egui::vec2(20.0, 20.0)));
                            crate::widgets::text_fit(
                                ui.painter(),
                                egui::pos2(rect.left() + 32.0, rect.center().y),
                                egui::Align2::LEFT_CENTER,
                                name,
                                theme::font(14.0),
                                ui.visuals().text_color(),
                                (rect.width() - 40.0).max(60.0),
                            );
                            let clicked = r.clicked();
                            if clicked {
                                (q.app, q.app_name) = (key.clone(), name.clone());
                            }
                        }
                    });
                    if let Some((_, _, icon, path)) = chosen {
                        let r = combo.response.rect;
                        icons::app_icon_for(ui.painter(), *icon, path, egui::Rect::from_center_size(egui::pos2(r.left() + 16.0, r.center().y), egui::vec2(18.0, 18.0)));
                    }
                });
                c.row("Limit", "How much data, per day, week or month.", |ui| {
                    egui::ComboBox::from_id_salt("quota_period").width(90.0).selected_text(q.period.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                        for p in PlanPeriod::ALL {
                            ui.selectable_value(&mut q.period, p, p.label());
                        }
                    });
                    egui::ComboBox::from_id_salt("quota_unit").width(70.0).selected_text(if q.gb { "GB" } else { "MB" }).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                        ui.selectable_value(&mut q.gb, false, "MB");
                        ui.selectable_value(&mut q.gb, true, "GB");
                    });
                    crate::widgets::num_field(ui, &mut q.limit, 0.001..=1_000_000.0, "");
                });
                let action_sub = match q.action {
                    QuotaAction::Block => "The app is unblocked automatically when the period resets.",
                    QuotaAction::Throttle | QuotaAction::ThrottleBlock => "The upload cap (a bandwidth limit, needs administrator rights) is lifted when the period resets.",
                    _ => "What happens when the limit is reached.",
                };
                c.row("Warn and act", action_sub, |ui| {
                    egui::ComboBox::from_id_salt("quota_action").width(170.0).selected_text(q.action.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                        for a in QuotaAction::ALL {
                            // A quota on all traffic has no single app to block or slow.
                            if !a.needs_app() || !q.app.is_empty() {
                                ui.selectable_value(&mut q.action, a, a.label());
                            }
                        }
                    });
                    crate::widgets::num_field(ui, &mut q.warn_pct, 1..=99, " % warns");
                });
                if q.action.throttles() {
                    c.row("Upload cap", "Applied as a bandwidth limit on the program (Firewall > Limits / QoS). Only uploads can be capped.", |ui| {
                        crate::widgets::num_field(ui, &mut q.throttle_kbps, crate::qos::MIN_KBPS..=crate::qos::MAX_KBPS, " Kbps");
                    });
                }
                if let Some(st) = ctx.status.iter().find(|st| st.quota.id == q.id) {
                    c.block(|ui| crate::widgets::quota_bar(ui, st, 360.0));
                }
            });
        });
    }
    if let Some(i) = remove {
        s.quotas.remove(i);
    }
    if ui.button("Add quota").clicked() {
        let id = s.next_quota_id();
        s.quotas.push(Quota { id, ..Quota::default() });
    }
}

fn scanner_section(ui: &mut Ui, s: &mut Settings) {
    group(ui, "Scanning", |c| {
        c.row("Scan automatically", "", |ui| {
            crate::widgets::small_toggle(ui, &mut s.auto_scan);
        });
        c.row("Time between scans", "", |ui| {
            crate::widgets::num_field(ui, &mut s.auto_scan_minutes, 1..=1440, " min");
        });
        c.row("Time between probes", "", |ui| {
            crate::widgets::num_field(ui, &mut s.scan_delay_ms, 1..=1000, " ms");
        });
        c.row("Scan other VLANs and subnets", "Finds devices on routed networks behind the router, but scans take longer.", |ui| {
            crate::widgets::small_toggle(ui, &mut s.scan_other_vlans);
        });
    });
}

fn threat_section(ui: &mut Ui, s: &mut Settings, lists: &ThreatLists, out: &mut Outcome) {
    group(ui, "Malicious IPs", |c| {
        c.row(
            "Warn about malicious IPs",
            "Warns when a program connects to a known malicious or botnet IP (downloads the lists below). Alert delivery is set under Alerts > Malicious IP protection.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.threat_protect);
            },
        );
        c.enable(s.threat_protect);
        c.row("Block those addresses automatically", "", |ui| {
            crate::widgets::small_toggle(ui, &mut s.threat_block);
        });
        c.row("Update the lists", "Hours between list updates.", |ui| {
            crate::widgets::num_field(ui, &mut s.threat_update_hours, 1..=720, " hours");
        });
        c.block(|ui| {
            ui.label("Blocklist URLs, one per line");
            ui.add(egui::TextEdit::multiline(&mut s.threat_feeds).desired_rows(3).desired_width(f32::INFINITY));
        });
    });
    group(ui, "Malicious domains", |c| {
        c.row(
            "Warn about malicious domains",
            "Warns when a program looks up a known malicious domain (downloads the lists below; needs the DNS log). This only warns: RustWarden doesn't block names or change your DNS settings. Alert delivery is set under Alerts > Malicious domain alerts.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.dns_block_alerts);
            },
        );
        c.enable(s.dns_block_alerts);
        c.row("Update the lists", "Hours between list updates.", |ui| {
            crate::widgets::num_field(ui, &mut s.dns_block_update_hours, 1..=720, " hours");
        });
        c.block(|ui| {
            ui.label("Domain list URLs, one per line (hosts files or plain names)");
            ui.add(egui::TextEdit::multiline(&mut s.dns_block_feeds).desired_rows(3).desired_width(f32::INFINITY));
        });
    });
    for (title, empty, list, buttons) in [
        (
            "Blocked addresses",
            "None. A blocked address is listed here with Unblock and Whitelist buttons (the warning banner has them too). Unblocking makes the next connection raise a new warning that doesn't auto-block.",
            &lists.0,
            vec![("Unblock", ThreatAct::Unblock), ("Whitelist", ThreatAct::Whitelist)],
        ),
        ("Whitelisted addresses", "None. Whitelisted addresses are never warned about or blocked.", &lists.1, vec![("Remove", ThreatAct::Unwhitelist)]),
    ] {
        group(ui, title, |c| {
            if list.is_empty() {
                c.block(|ui| {
                    ui.weak(empty);
                });
            }
            for (ip, who) in list {
                c.row(ip, who, |ui| {
                    for (label, act) in buttons.iter().rev() {
                        if ui.button(*label).clicked() {
                            *out = Outcome::Then(Confirm {
                                title: format!("{label} {ip}?"),
                                body: match act {
                                    ThreatAct::Unwhitelist => format!("{ip} will be warned about (and blocked, if auto-block is on) the next time a program connects to it."),
                                    _ => format!(
                                        "{ip} is on a malicious-IP list. {label} lets programs reach it again{}.",
                                        if *act == ThreatAct::Whitelist { " and RustWarden will never warn about it again" } else { "" }
                                    ),
                                },
                                yes: (*label).into(),
                                action: ConfirmAction::Threat { ip: ip.clone(), act: *act },
                            });
                        }
                    }
                    if ui.button("Details").on_hover_text("Whois and blocklist details").clicked() {
                        *out = Outcome::IpInfo(ip.clone());
                    }
                });
            }
        });
    }
}

fn firewall_section(ui: &mut Ui, s: &mut Settings, live: bool, profiles: &(Vec<String>, String), extras: &[(bool, bool)], out: &mut Outcome) {
    group(ui, "Blocking", |c| {
        c.row(
            "Keep Prompt blocking when RustWarden is closed",
            "New programs have no internet until you reopen RustWarden and answer; it asks about the programs it stopped on the next start. It switches on the Windows \"Filtering Platform Connection\" failure audit so blocked attempts are logged, and switches it off again when this is turned off.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.keep_blocking_closed);
            },
        );
        // Idle apps aren't cleaned: a blocked app sends nothing, so idle can't tell it from an unused one.
        c.row("Remove block rules of uninstalled apps", "", |ui| {
            crate::widgets::small_toggle(ui, &mut s.firewall_cleanup);
        });
        c.row("Wait before removing them", "Days after the app was uninstalled.", |ui| {
            crate::widgets::num_field(ui, &mut s.cleanup_uninstalled_days, 1..=3650, " days");
        });
    });
    if live {
        group(ui, "Existing firewall rules", |c| {
            for (label, rename, sub, body) in [
                (
                    "Import existing firewall rules…",
                    false,
                    "Lets RustWarden use the per-program rules another firewall app left in Windows Firewall; they show on the Firewall tab.",
                    "Lets RustWarden use the per-program Windows Firewall rules another firewall app created: they show on the Firewall tab and can be changed here. Names are kept, so the app that made them still recognises them if it comes back.",
                ),
                (
                    "Import and rename existing rules…",
                    true,
                    "Like importing, and the rules are renamed to RustWarden's naming. The app that made them will no longer recognise them.",
                    "Like importing, but the rules are also renamed to RustWarden's naming. The app that made them will no longer recognise them.",
                ),
            ] {
                c.row(label.trim_end_matches('…'), sub, |ui| {
                    if ui.button("Choose…").clicked() {
                        *out = Outcome::Then(Confirm { title: label.trim_end_matches('…').into(), body: body.into(), yes: "Import rules".into(), action: ConfirmAction::ImportRules { rename } });
                    }
                });
            }
        });
        group(ui, "Windows components", |c| {
            use crate::live::firewall::ExtrasAct;
            c.row("Block Windows components that don't need internet", "Makes block rules for background components Windows doesn't need online.", |ui| {
                if ui.button("Block…").clicked() {
                    *out = Outcome::Then(Confirm {
                        title: "Block Windows components?".into(),
                        body: crate::live::windows_extras::description(),
                        yes: "Block them".into(),
                        action: ConfirmAction::BlockWindowsExtras,
                    });
                }
            });
            for (i, g) in crate::live::windows_extras::GROUPS.iter().enumerate() {
                let (has, paused) = extras.get(i).copied().unwrap_or_default();
                let sub = if !has {
                    "Not blocked yet."
                } else if paused {
                    "Paused."
                } else {
                    "Blocked."
                };
                c.row(g.title, sub, |ui| {
                    // Pause turns into Resume; Unblock removes the rules, so both buttons then disappear.
                    for (label, act, body, shown) in [
                        ("Unblock", ExtrasAct::Unblock, "Deletes the rules this feature made for this group. Blocks you set yourself on the Firewall tab are not touched.", has),
                        ("Resume", ExtrasAct::Resume, "Switches the paused rules back on.", has && paused),
                        ("Pause", ExtrasAct::Pause, "Switches these rules off so the programs can use the internet again. The rules are kept; Resume switches them back on.", has && !paused),
                    ] {
                        if shown && ui.button(label).clicked() {
                            *out = Outcome::Then(Confirm { title: format!("{label}: {}", g.title), body: body.into(), yes: label.into(), action: ConfirmAction::WindowsExtras { group: i, act } });
                        }
                    }
                });
            }
            c.row("Repeat that automatically", "Covers programs Windows Update reinstalled. Starts after you have used the button once.", |ui| {
                crate::widgets::small_toggle(ui, &mut s.block_windows_auto);
            });
            c.enable(s.block_windows_auto);
            c.row("Hours between repeats", "24 suits most; 48 if you update rarely.", |ui| {
                crate::widgets::num_field(ui, &mut s.block_windows_hours, 1..=720, " hours");
            });
        });
        group(ui, "", |c| {
            c.row("Restore firewall defaults", "Deletes every Windows Firewall rule that RustWarden created (the \"RustWarden\" group) and nothing else.", |ui| {
                if ui.button("Restore…").clicked() {
                    *out = Outcome::Then(Confirm {
                        title: "Restore firewall defaults?".into(),
                        body: "This deletes every Windows Firewall rule that RustWarden created (the \"RustWarden\" group) and nothing else.".into(),
                        yes: "Remove RustWarden rules".into(),
                        action: ConfirmAction::RestoreDefaults,
                    });
                }
            });
        });
    }
    profiles_section(ui, profiles, out);
}

/// Firewall rulesets: switch to one, create one, or delete one. The active and the only ruleset can't be deleted.
fn profiles_section(ui: &mut Ui, (names, active): &(Vec<String>, String), out: &mut Outcome) {
    let id = ui.scope_id().with("ruleset_pick");
    let mut pick: String = ui.data_mut(|d| d.get_temp(id)).unwrap_or_else(|| active.clone());
    if !names.contains(&pick) {
        pick = active.clone();
    }
    let why = if names.len() < 2 {
        Some("The only ruleset can't be deleted.")
    } else if pick == *active {
        Some("This is the active ruleset. Switch to another one first.")
    } else {
        None
    };
    // Arriving from the Firewall tab's ruleset button: scroll here once, and flash the card so it's easy to spot.
    let flash_id = egui::Id::NULL.with("flash_rulesets");
    let flash: Option<f64> = ui.data(|d| d.get_temp(flash_id));
    let section = ui.scope(|ui| {
        profiles_card(ui, names, active, &pick, id, why, out);
    });
    if let Some(t) = flash {
        let age = (ui.input(|i| i.time) - t) as f32;
        if ui.data_mut(|d| d.get_temp::<bool>(flash_id.with("done")).is_none_or(|v| !v)) {
            ui.data_mut(|d| d.insert_temp(flash_id.with("done"), true));
            ui.scroll_to_rect(section.response.rect.expand(8.0), Some(egui::Align::Center));
        }
        if age < 1.8 {
            let a = (1.0 - age / 1.8).clamp(0.0, 1.0);
            ui.painter().rect_filled(section.response.rect.expand(4.0), 8, theme::accent().gamma_multiply(0.3 * a));
            ui.ctx().request_repaint();
        } else {
            ui.data_mut(|d| d.remove_temp::<f64>(flash_id));
            ui.data_mut(|d| d.remove_temp::<bool>(flash_id.with("done")));
        }
    }
}

fn profiles_card(ui: &mut Ui, names: &[String], active: &str, pick: &str, id: egui::Id, why: Option<&str>, out: &mut Outcome) {
    let mut pick = pick.to_owned();
    group(ui, "Firewall Rulesets", |c| {
        c.row("Ruleset", &format!("Active: {active}. A ruleset is a separate set of RustWarden firewall rules; switching parks the current rules and brings back the other's."), |ui| {
            egui::ComboBox::from_id_salt("ruleset_combo").selected_text(&pick).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                for n in names {
                    ui.selectable_value(&mut pick, n.clone(), n);
                }
            });
        });
        c.row("Switch to this ruleset", "", |ui| {
            if ui.add_enabled(pick != *active, egui::Button::new("Switch…")).clicked() {
                *out = Outcome::SwitchRuleset(pick.clone());
            }
        });
        c.row("Create a new ruleset", "Starts empty; your current rules are kept safe under the current ruleset.", |ui| {
            if ui.button("Create…").clicked() {
                *out = Outcome::NewRuleset;
            }
        });
        c.row("Delete this ruleset", why.unwrap_or("Delete a ruleset you no longer use."), |ui| {
            if ui.add_enabled(why.is_none(), egui::Button::new("Delete ruleset…")).clicked() {
                *out = Outcome::Then(Confirm {
                    title: format!("Delete ruleset \"{pick}\"?"),
                    body: format!(
                        "This permanently deletes the ruleset \"{pick}\" and its saved rules from Windows Firewall. It can't be undone. The active ruleset \"{active}\" and other rulesets are not touched."
                    ),
                    yes: "Delete ruleset".into(),
                    action: ConfirmAction::DeleteProfile { name: pick.clone() },
                });
            }
        });
    });
    ui.data_mut(|d| d.insert_temp(id, pick));
}

fn privacy_tab_id() -> egui::Id {
    egui::Id::NULL.with("privacy_tab")
}

/// Incognito / Hidden Apps tabs; the sidebar resets the tab to Incognito whenever Privacy is opened.
fn privacy_section(ui: &mut Ui, s: &mut Settings, p2p: &[crate::data::P2pApp]) {
    let mut tab: usize = ui.data_mut(|d| d.get_temp(privacy_tab_id()).unwrap_or(0));
    ui.horizontal(|ui| {
        crate::widgets::segmented_text(ui, &mut tab, &["Incognito", "Hidden Apps", "VPN", "P2P"]);
    });
    ui.data_mut(|d| d.insert_temp(privacy_tab_id(), tab));
    match tab {
        0 => incognito_section(ui, s),
        1 => hidden_section(ui, s),
        2 => vpn_section(ui, s),
        _ => p2p_section(ui, s, p2p),
    }
}

/// Peer-to-peer detection, and the programs to keep off the network while no VPN is connected.
fn p2p_section(ui: &mut Ui, s: &mut Settings, found: &[crate::data::P2pApp]) {
    group(ui, "", |c| {
        c.row(
            "Detect peer-to-peer traffic",
            "Off by default. Watches, on this PC only, for well-known torrent programs, and for any other program that exchanges data with many internet addresses no website lookup ever named. Browsers are never flagged. It is a guess from traffic patterns, not a look inside it, so use 'Not P2P' on a false alarm. Needs Live mode with administrator rights.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.p2p_detect);
            },
        );
    });
    if !s.p2p_detect {
        return;
    }
    // Programs picked earlier stay listed (and can be unpicked) even when they haven't been flagged this run.
    let mut rows: Vec<(String, String, Option<i64>)> = found.iter().filter(|a| !s.p2p_ignore.contains(&a.key)).map(|a| (a.key.clone(), a.name.clone(), Some(a.last_seen))).collect();
    for k in &s.p2p_block {
        if !rows.iter().any(|r| r.0.eq_ignore_ascii_case(k)) {
            rows.push((k.clone(), crate::live::apps::file_name(k).to_owned(), None));
        }
    }
    let now = crate::clock::now_unix();
    let mut ignore = None;
    group(ui, "Block without a VPN", |c| {
        c.block(|ui| {
            ui.weak("A picked program is blocked completely, in both directions (a firewall can't single out its peer-to-peer part), whenever no VPN adapter is connected, and let through again when one is. Needs administrator rights.");
        });
        if rows.is_empty() {
            c.block(|ui| {
                ui.weak("No peer-to-peer programs seen yet.");
            });
        }
        for (key, name, seen) in &rows {
            let seen = seen.map_or_else(|| "not seen this run".to_owned(), |t| format!("seen {} min ago", ((now - t).max(0) + 59) / 60));
            c.row(name, &format!("{key} ({seen})"), |ui| {
                if ui.button("Not P2P").on_hover_text("A false alarm: stop flagging this program").clicked() {
                    ignore = Some(key.clone());
                }
                let mut on = s.p2p_block.iter().any(|k| k.eq_ignore_ascii_case(key));
                if crate::widgets::small_toggle(ui, &mut on).changed() {
                    s.p2p_block.retain(|k| !k.eq_ignore_ascii_case(key));
                    if on {
                        s.p2p_block.push(key.clone());
                    }
                }
            });
        }
    });
    if let Some(key) = ignore {
        s.p2p_block.retain(|k| !k.eq_ignore_ascii_case(&key));
        s.p2p_ignore.push(key);
    }
    let ignored = s.p2p_ignore.clone();
    if !ignored.is_empty()
        && let Some(i) = name_list(ui, "Not flagged (false alarms)", "", &ignored, "Flag again", "", None)
    {
        s.p2p_ignore.remove(i);
    }
}

/// A card listing `items` with a button each, and a box below it to add one. The index of a clicked button is returned.
fn name_list(ui: &mut Ui, title: &str, hint: &str, items: &[String], button: &str, new_id: &str, add: Option<&mut Vec<String>>) -> Option<usize> {
    let mut clicked = None;
    group(ui, title, |c| {
        if items.is_empty() {
            c.block(|ui| {
                ui.weak(hint);
            });
        }
        for (i, name) in items.iter().enumerate() {
            c.row(name, "", |ui| {
                if ui.button(button).clicked() {
                    clicked = Some(i);
                }
            });
        }
        if let Some(list) = add {
            c.block(|ui| {
                let id = ui.scope_id().with(new_id);
                let mut text: String = ui.data_mut(|d| d.get_temp(id).unwrap_or_default());
                ui.horizontal(|ui| {
                    if ui.button("Add").clicked() && !text.trim().is_empty() {
                        list.push(text.trim().to_owned());
                        text.clear();
                    }
                    ui.add(egui::TextEdit::singleline(&mut text).desired_width(f32::INFINITY));
                });
                ui.data_mut(|d| d.insert_temp(id, text));
            });
        }
    });
    clicked
}

fn vpn_section(ui: &mut Ui, s: &mut Settings) {
    group(ui, "", |c| {
        c.row(
            "Don't count VPN tunnel traffic while a VPN is connected",
            "A VPN client's encrypted traffic duplicates what your apps send through it, so it would top the list. Your apps' own traffic is still counted. Built-in clients (OpenVPN, WireGuard, NordVPN, ExpressVPN, Proton, Mullvad, Tailscale...) are covered; add others by executable name.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.hide_vpn_traffic);
            },
        );
    });
    let names = s.vpn_apps.clone();
    if let Some(i) = name_list(ui, "Other VPN programs", "None added.", &names, "Remove", "vpn_new", Some(&mut s.vpn_apps)) {
        s.vpn_apps.remove(i);
    }
}

fn hidden_section(ui: &mut Ui, s: &mut Settings) {
    ui.label("Apps hidden from the Firewall tab. Their traffic is still recorded.");
    let names = s.hidden_apps.clone();
    if let Some(i) = name_list(ui, "Hidden apps", "No hidden apps.", &names, "Unhide", "hidden_new", None) {
        s.hidden_apps.remove(i);
    }
}

fn incognito_section(ui: &mut Ui, s: &mut Settings) {
    ui.label("Traffic of these programs is not shown or recorded (full executable path).");
    let names = s.incognito_apps.clone();
    if let Some(i) = name_list(ui, "Incognito programs", "None added.", &names, "Remove", "incognito_new", Some(&mut s.incognito_apps)) {
        s.incognito_apps.remove(i);
    }
}

/// egui's own hyperlinks need a browser feature this build leaves out, so open the URL ourselves.
pub(crate) fn link(ui: &mut Ui, text: &str, url: &str) {
    if ui.link(text).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(url).clicked() {
        crate::sys::open_url(url);
    }
}

/// A database download running on a thread; the UI polls it each frame.
#[derive(Default)]
struct DlJob {
    result: std::sync::Mutex<Option<Result<(), String>>>,
    pct: std::sync::atomic::AtomicU32,
}

/// Starts a download when `start` is given, and polls the one stored under `id`:
/// (progress 0..1 while it runs, its result the frame it finishes).
fn download_job(ui: &Ui, id: egui::Id, start: Option<(std::path::PathBuf, &'static str)>) -> (Option<f32>, Option<Result<(), String>>) {
    use std::sync::{Arc, atomic::Ordering};
    if let Some((dest, edition)) = start {
        let job = Arc::new(DlJob::default());
        ui.data_mut(|d| d.insert_temp(id, Some(job.clone())));
        let ctx = ui.ctx().clone();
        std::thread::spawn(move || {
            let r = crate::live::geo::download_dbip(&dest, edition, &job.pct);
            *job.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
            ctx.request_repaint();
        });
    }
    let Some(job) = ui.data_mut(|d| d.get_temp::<Option<Arc<DlJob>>>(id)).flatten() else { return (None, None) };
    if let Some(r) = job.result.lock().unwrap_or_else(|e| e.into_inner()).take() {
        ui.data_mut(|d| d.insert_temp(id, None::<Arc<DlJob>>));
        return (None, Some(r));
    }
    ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
    (Some(job.pct.load(Ordering::Relaxed) as f32 / 100.0), None)
}

/// One downloadable database: its name, where it is installed, when it was downloaded (the file's
/// modified time), and a button with a progress bar. True the frame a download finishes successfully.
fn db_row(ui: &mut Ui, name: &str, path: &std::path::Path, edition: &'static str, id: egui::Id, ok_msg: &str) -> bool {
    let (mut prog, done) = download_job(ui, id, None);
    let mut ok = false;
    if let Some(r) = done {
        ok = r.is_ok();
        ui.data_mut(|d| d.insert_temp(id.with("msg"), r.err().unwrap_or_else(|| ok_msg.to_owned())));
    }
    let stamp = std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| crate::clock::fmt_stamp(d.as_secs() as i64));
    tight(ui, |ui| {
        ui.label(egui::RichText::new(name).strong());
        ui.label(format!("Installed at: {}", path.display()));
        ui.label(format!("Downloaded: {}", stamp.as_deref().unwrap_or("Not downloaded")));
    });
    ui.horizontal(|ui| {
        let label = if prog.is_some() {
            "Downloading…"
        } else if stamp.is_some() {
            "Update"
        } else {
            "Download"
        };
        if ui.add_enabled(prog.is_none(), egui::Button::new(label)).clicked() {
            ui.data_mut(|d| d.remove_temp::<String>(id.with("msg")));
            prog = download_job(ui, id, Some((path.to_path_buf(), edition))).0;
        }
        if let Some(p) = prog {
            ui.add(egui::ProgressBar::new(p).desired_width(160.0).show_percentage());
        } else if let Some(msg) = ui.data(|d| d.get_temp::<String>(id.with("msg"))) {
            ui.label(msg);
        }
    });
    ok
}

fn dl_id(edition: &str) -> egui::Id {
    egui::Id::unique(("db_download", edition))
}

/// Downloads every database in `editions` after showing where each comes from and how it is checked,
/// then lists them with their progress. Shared by Settings > Countries & Network and the first-run wizard.
/// Downloading the country database also points the draft at it, as its own Download button does.
pub(super) fn databases_panel(ui: &mut Ui, s: &mut Settings, editions: &[&'static str]) {
    use crate::live::geo;
    let want: Vec<&geo::DbInfo> = geo::DATABASES.iter().filter(|d| editions.contains(&d.edition)).collect();
    let running = |ui: &Ui, id| ui.data(|d| d.get_temp::<Option<std::sync::Arc<DlJob>>>(id)).flatten().is_some();
    let busy = want.iter().any(|d| running(ui, dl_id(d.edition)));
    let confirm_id = ui.scope_id().with("dl_all_confirm");
    let confirming = ui.data(|d| d.get_temp::<bool>(confirm_id)).unwrap_or(false);
    if !confirming {
        if ui.add_enabled(!busy && !want.is_empty(), egui::Button::new("Download all…")).clicked() {
            ui.data_mut(|d| d.insert_temp(confirm_id, true));
        }
    } else {
        egui::Frame::NONE.fill(theme::card()).stroke(egui::Stroke::new(1.0, theme::card_edge())).corner_radius(8).inner_margin(12.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new("RustWarden will download:").strong());
            for d in &want {
                tight(ui, |ui| {
                    ui.label(format!("• {} ({}), for {}", d.name, d.size, d.used_for));
                    ui.weak(format!("From {}", geo::download_url(d.edition)));
                    ui.weak(format!("Saved to {}", geo::db_path(d.edition).display()));
                });
            }
            if s.threat_protect || s.dns_block_alerts {
                ui.label("The malicious IP and domain lists you switched on are fetched by RustWarden itself from the addresses under Malicious IPs, then kept up to date; nothing more is needed here.");
            }
            ui.label(
                "How they are checked: they come over HTTPS from DB-IP's own download server (db-ip.com, free \"Lite\" editions, CC BY 4.0), which publishes no checksums. \
                 Each file is unpacked beside the old one and only used if it opens as a database of the right kind (country, city or ASN) and holds data; otherwise it is deleted and the old one stays. \
                 Nothing about you is sent: a plain request, no account, no identifier.",
            );
            ui.horizontal(|ui| {
                if ui.button("Download").clicked() {
                    for d in &want {
                        let id = dl_id(d.edition);
                        if !running(ui, id) {
                            ui.data_mut(|data| data.remove_temp::<String>(id.with("msg")));
                            download_job(ui, id, Some((geo::db_path(d.edition), d.edition)));
                        }
                    }
                    ui.data_mut(|d| d.insert_temp(confirm_id, false));
                }
                if ui.button("Cancel").clicked() {
                    ui.data_mut(|d| d.insert_temp(confirm_id, false));
                }
            });
        });
    }
    for d in want {
        let msg = if d.edition == "country" { "Downloaded. Flags appear within a few seconds." } else { "Downloaded. If it was already in use, restart RustWarden to load the update." };
        if db_row(ui, d.name, &geo::db_path(d.edition), d.edition, dl_id(d.edition), msg) && d.edition == "country" {
            let path = geo::db_path("country").to_string_lossy().into_owned();
            s.geo_db_path = Some(path.clone());
            // Also remembered outside the draft, so Cancel doesn't leave the file downloaded but unused.
            ui.data_mut(|d| d.insert_temp(egui::Id::unique("geo_downloaded"), path));
        }
    }
}

fn countries_section(ui: &mut Ui, s: &mut Settings) {
    const TABS: [&str; 3] = ["Downloads", "Geolocation", "Lookups"];
    let tab_id = ui.scope_id().with("countries_tab");
    let mut tab: usize = ui.data(|d| d.get_temp(tab_id)).unwrap_or(0);
    ui.horizontal(|ui| {
        for (i, name) in TABS.iter().enumerate() {
            ui.selectable_value(&mut tab, i, *name);
        }
    });
    ui.data_mut(|d| d.insert_temp(tab_id, tab));
    match tab {
        0 => {
            ui.label("The databases that show flags, map locations and AS numbers. Any MaxMind GeoLite2/GeoIP2 or DB-IP country or city file also works (see Geolocation).");
            group(ui, "Databases", |c| {
                c.block(|ui| databases_panel(ui, s, &["country", "city", "asn"]));
            });
            group(ui, "", |c| {
                c.row("Keep downloaded databases up to date", "Checked every few hours; replaced when over a month old.", |ui| {
                    crate::widgets::small_toggle(ui, &mut s.geo_auto_update);
                });
            });
            ui.add_space(4.0);
            link(ui, "IP geolocation by DB-IP (CC BY 4.0)", "https://db-ip.com");
        }
        1 => {
            group(ui, "Country database", |c| {
                c.row("Custom country database (.mmdb)", "Leave empty to use the downloaded one.", |ui| {
                    let mut path = s.geo_db_path.clone().unwrap_or_default();
                    if ui.add(egui::TextEdit::singleline(&mut path).desired_width(240.0)).changed() {
                        s.geo_db_path = (!path.trim().is_empty()).then(|| path.trim().to_owned());
                    }
                });
            });
            group(ui, "City database", |c| {
                c.row(
                    "Use the city database on the map",
                    "Places connections at their city instead of the middle of the country; nearby ones still merge when zoomed out (about 130 MB in memory).",
                    |ui| {
                        crate::widgets::small_toggle(ui, &mut s.geoip_city);
                    },
                );
            });
        }
        _ => lookups_section(ui, s),
    }
}

fn lookups_section(ui: &mut Ui, s: &mut Settings) {
    group(ui, "AS number and company", |c| {
        c.row("Lookup service", "Shows e.g. \"AS15169 · Google LLC\" for remote addresses. The address is sent to the service you pick; Off sends nothing.", |ui| {
            egui::ComboBox::from_id_salt("net_info_source").selected_text(s.net_info.label()).icon(crate::widgets::combo_icon).show_ui(ui, |ui| {
                for v in NetInfoSource::ALL {
                    ui.selectable_value(&mut s.net_info, v, v.label());
                }
            });
        });
        if s.net_info == NetInfoSource::Http {
            c.block(|ui| {
                ui.label("Web API address; {ip} is replaced by the remote address. The answer must contain an \"asn\" and/or \"org\" (or \"as\") field, like ipinfo.io, ip-api.com or ipwho.is.");
                ui.add(egui::TextEdit::singleline(&mut s.net_info_url).desired_width(f32::INFINITY));
            });
        }
    });

    group(ui, "Public IP address", |c| {
        c.row(
            "Watch my public IP address",
            "Asks the web service below for this PC's address every ten minutes and raises a \"Public IP address\" alert when it or the ISP changes. Off by default: it goes online.",
            |ui| {
                crate::widgets::small_toggle(ui, &mut s.public_ip_check);
            },
        );
        if s.public_ip_check {
            c.block(|ui| {
                ui.label("Address of a service that answers with just your IP address (https only), like api.ipify.org or icanhazip.com.");
                ui.add(egui::TextEdit::singleline(&mut s.public_ip_url).desired_width(f32::INFINITY));
            });
        }
    });

    group(ui, "Whois", |c| {
        c.block(|ui| {
            ui.label("The (i) icon next to an IP address shows who it belongs to.");
            crate::widgets::radio(ui, &mut s.whois_internal, false, "Open Shodan in the browser");
            crate::widgets::radio(ui, &mut s.whois_internal, true, "Show the answer in RustWarden (free rdap.org lookup; the address is sent to it)");
        });
    });
}

/// Confirmation for moving from ruleset `from` to `to`, which is new when `create`.
pub fn profile_confirm(from: &str, to: &str, create: bool) -> Confirm {
    let what = if create { format!("A new, empty ruleset \"{to}\" is created and becomes active.") } else { format!("The saved rules of \"{to}\" are switched back on.") };
    Confirm {
        title: if create { format!("Create ruleset \"{to}\"?") } else { format!("Switch to ruleset \"{to}\"?") },
        body: format!(
            "The rules of \"{from}\" are switched off and kept in Windows Firewall (group \"RustWarden saved profiles\"); nothing is deleted, and switching back restores them. {what}

Block All and Prompt are turned off by this."
        ),
        yes: if create { "Create ruleset" } else { "Switch ruleset" }.into(),
        action: ConfirmAction::SwitchProfile { name: to.into(), create },
    }
}

/// Confirmation texts for the firewall toggles, shared by the Firewall tab.
pub fn firewall_toggle_confirm(on: bool) -> Confirm {
    Confirm {
        title: if on { "Turn RustWarden firewall on?" } else { "Turn RustWarden firewall off?" }.into(),
        body: if on {
            "RustWarden's block rules in Windows Firewall will be switched on. Apps you blocked lose network access in the blocked direction.".into()
        } else {
            "RustWarden's block rules stay saved but are switched off, so every app can use the network again. Windows Firewall itself stays as it is.".into()
        },
        yes: if on { "Turn on" } else { "Turn off" }.into(),
        action: ConfirmAction::FirewallEnabled(on),
    }
}

/// Asks before a file leaves this PC: VirusTotal lookups send only a hash, an upload sends the file itself.
pub fn virustotal_upload_confirm(key: &str, name: &str, path: &str) -> Confirm {
    Confirm {
        title: format!("Upload {name} to VirusTotal?"),
        body: format!(
            "{path}\n\nVirusTotal has never seen this file. Uploading sends the file itself, not just its hash, to VirusTotal. It is shared with security vendors and may be kept and visible to others who search for it. Do not upload private, confidential or licensed software.\n\nOnly this file is uploaded (up to 32 MB). RustWarden never uploads files on its own."
        ),
        yes: "Upload this file".into(),
        action: ConfirmAction::VirusTotalUpload { key: key.to_owned() },
    }
}

pub fn mode_confirm(mode: FirewallMode) -> Option<Confirm> {
    match mode {
        FirewallMode::ClickToBlock => None,
        FirewallMode::BlockAll => Some(Confirm {
            title: "Turn on Block All?".into(),
            body: "Block All changes the Windows Firewall default for outbound connections to Block, with exceptions for RustWarden and the network basics it needs to stay usable. Almost every other program loses internet access until you switch the mode back.\n\nRustWarden restores the previous setting when you switch the mode back, when you exit, and on next start if it crashed.".into(),
            yes: "Block All".into(),
            action: ConfirmAction::FirewallMode(mode),
        }),
        FirewallMode::AskToConnect => Some(Confirm {
            title: "Turn on Prompt?".into(),
            body: "Prompt changes the Windows Firewall default for outbound connections to Block. Programs RustWarden has already seen keep their access; a new program is stopped and RustWarden asks whether to allow or block it. Windows can't pause a connection while you decide, so the program's first attempt fails and it works once you allow it and it retries.\n\nRustWarden restores the previous setting when you switch the mode back, when you exit, and on next start if it crashed.".into(),
            yes: "Prompt".into(),
            action: ConfirmAction::FirewallMode(mode),
        }),
    }
}

/// One labelled bar per row, scaled to the biggest value.
type BarRow = (String, f64, String);

fn bars(ui: &mut egui::Ui, id: &str, rows: &[BarRow]) {
    let max = rows.iter().map(|r| r.1).fold(0.0, f64::max).max(1.0);
    egui::Grid::new(id).num_columns(2).show(ui, |ui| {
        for (name, v, text) in rows {
            ui.label(name);
            ui.add(egui::ProgressBar::new((v / max) as f32).desired_width(240.0).text(text));
            ui.end_row();
        }
    });
}

/// The weekly report as bar charts, with the counts that don't chart as text beneath.
fn report_charts(ui: &mut egui::Ui, r: &crate::report::Report) {
    use crate::util::fmt_bytes;
    ui.label(format!("7 days to {}", crate::clock::fmt_date(r.until)));
    let sections: [(&str, Vec<BarRow>); 5] = [
        ("Traffic per day", r.daily.iter().map(|(t, b)| (crate::clock::fmt_date(*t), *b, fmt_bytes(*b))).collect()),
        ("Top apps", r.top_apps.iter().take(8).map(|(n, b)| (n.clone(), *b, fmt_bytes(*b))).collect()),
        ("Alerts", r.alerts.iter().take(8).map(|(k, n)| (k.clone(), *n as f64, n.to_string())).collect()),
        ("Ping", r.ping.iter().map(|(n, ms, loss)| (n.clone(), f64::from(*ms), format!("{ms:.0} ms, loss {loss:.1}%"))).collect()),
        ("Broadband", r.broadband.iter().map(|(n, ms, loss)| (n.clone(), f64::from(*ms), format!("{ms:.0} ms, loss {loss:.1}%"))).collect()),
    ];
    for (title, rows) in sections.iter().filter(|(_, rows)| !rows.is_empty()) {
        ui.add_space(6.0);
        ui.strong(*title);
        bars(ui, title, rows);
    }
    ui.add_space(6.0);
    ui.label(format!(
        "{}{}Blocked connections: {}, quota events: {}",
        crate::report::new_line("New hosts", &r.new_hosts),
        crate::report::new_line("New countries", &r.new_countries),
        r.blocked,
        r.quota_events
    ));
}

/// A small dim caption over a control, as on the Firewall page's control card.
fn labelled(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 4.0;
        ui.label(egui::RichText::new(label).font(theme::font(12.5)).color(theme::text_dim()));
        add(ui);
    });
}
