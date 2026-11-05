use crate::cleanup;
use crate::data::*;
use crate::icons::{self, Icon};
use crate::settings::{Mode, Settings};
use crate::theme;
use crate::widgets;
use egui::{Align2, Color32, Frame, Id, Panel, PointerButton, Rect, Sense, Stroke, Ui, ViewportCommand, pos2, vec2};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Traffic,
    Protect,
    Log,
    Scanner,
    Hardware,
    Broadband,
    Ping,
    Speedtest,
    Dns,
    Connections,
    DestRules,
    Bandwidth,
    AlertRules,
}

impl Tab {
    /// Stable name saved in the settings so the app reopens where it was; never rename these.
    pub fn key(self) -> &'static str {
        match self {
            Tab::Traffic => "traffic",
            Tab::Protect => "protect",
            Tab::Log => "log",
            Tab::Scanner => "scanner",
            Tab::Hardware => "hardware",
            Tab::Broadband => "broadband",
            Tab::Ping => "ping",
            Tab::Speedtest => "speedtest",
            Tab::Dns => "dns",
            Tab::Connections => "connections",
            Tab::DestRules => "dest_rules",
            Tab::Bandwidth => "bandwidth",
            Tab::AlertRules => "alert_rules",
        }
    }

    /// Every tab, including the sub-tabs.
    const EVERY: [Tab; 13] =
        [Tab::Traffic, Tab::Protect, Tab::Log, Tab::Scanner, Tab::Hardware, Tab::Broadband, Tab::Ping, Tab::Speedtest, Tab::Dns, Tab::Connections, Tab::DestRules, Tab::Bandwidth, Tab::AlertRules];

    pub fn from_key(key: &str) -> Option<Tab> {
        Self::EVERY.into_iter().find(|t| t.key() == key)
    }

    /// The header's tabs; Broadband Quality lives under Network (see `network_tabs`).
    const ALL: [Tab; 5] = [Tab::Traffic, Tab::Protect, Tab::Log, Tab::Scanner, Tab::Hardware];

    fn lines(self) -> (&'static str, &'static str) {
        match self {
            Tab::Traffic => ("Traffic", ""),
            Tab::Protect => ("Firewall", ""),
            Tab::Log => ("Alerts", ""),
            Tab::Scanner => ("Network", ""),
            Tab::Hardware => ("Hardware", ""),
            Tab::Broadband => ("Broadband", "Quality"),
            Tab::Ping => ("Ping", "Monitor"),
            Tab::Speedtest => ("Speedtest", ""),
            Tab::Dns => ("DNS", "Log"),
            Tab::Connections => ("Live", "Connections"),
            Tab::DestRules => ("Destination", "Rules"),
            Tab::Bandwidth => ("Bandwidth", "Limits"),
            Tab::AlertRules => ("Alert", "Rules"),
        }
    }

    fn icon(self) -> Icon {
        match self {
            Tab::Traffic => Icon::Traffic,
            Tab::Protect | Tab::Connections | Tab::DestRules | Tab::Bandwidth => Icon::Shield,
            Tab::Log | Tab::AlertRules => Icon::Alerts,
            Tab::Scanner => Icon::Scanner,
            Tab::Hardware => Icon::Chip,
            Tab::Broadband | Tab::Ping | Tab::Speedtest | Tab::Dns => Icon::Wave,
        }
    }
}

pub struct TrafficState {
    pub view: usize,
    pub range: TimeRange,
    /// Selected window as fractions of the range (start, end).
    pub window: (f32, f32),
    pub history: TrafficHistory,
    /// Unix time (seconds) `history` was loaded at; the live graph scrolls from the last bucket it contains.
    pub loaded_at: f64,
    pub totals: Totals,
    pub breakdown: UsageBreakdown,
    pub map: MapData,
    pub live: bool,
    /// Map centre (lon, Mercator y) and zoom factor.
    pub map_center: (f32, f32),
    pub map_zoom: f32,
    /// Zoom the +/- buttons are easing toward.
    pub map_zoom_to: f32,
    /// Centre the Home key is easing toward; cleared when it arrives or the user drags.
    pub map_center_to: Option<(f32, f32)>,
    /// True once the user has panned or zoomed; until then the map stays centred on Home.
    pub map_touched: bool,
    /// Open detail popup: where it hangs and what it shows.
    pub detail: Option<(egui::Pos2, UsageDetail)>,
    /// Popups left behind by drilling into a row; the back arrow pops one.
    pub detail_back: Vec<UsageDetail>,
    /// Highlighted span of the graph as (start, end) minutes of day, its breakdown, and the open list popup (0 apps, 1 hosts).
    pub sel: Option<(f32, f32)>,
    pub sel_data: UsageBreakdown,
    pub sel_popup: Option<(usize, egui::Pos2)>,
    /// Alert whose graph pin was clicked (id, anchor).
    pub alert_popup: Option<(u64, egui::Pos2)>,
    pub filter: TrafficFilter,
    pub filter_open: bool,
    /// Filter-panel table order: (column 0 name / 1 down / 2 up, ascending). None = as loaded.
    pub app_sort: Option<(u8, bool)>,
    /// Hosts-view table order per list (Apps, Hosts, Traffic Type, Countries): (column 0 name / 1 down / 2 up, ascending).
    pub list_sort: [Option<(u8, bool)>; 4],
    /// Apps of the last unfiltered-by-app load; the filter panel keeps listing them while one app is picked.
    pub app_list: Vec<UsageRow>,
}

pub struct ProtectState {
    pub info: FirewallInfo,
    pub search: String,
    pub apps: Vec<FirewallApp>,
    pub open_groups: [bool; 4],
    /// Column left edges as fractions of the table width (last is 1.0); dragged from the header.
    pub cols: [f32; 11],
    /// Sorted column index and whether it ascends.
    pub sort: Option<(usize, bool)>,
    /// Keys of apps whose process list is expanded.
    pub expanded: HashSet<String>,
    /// Firewall profile names and the active one.
    pub profiles: Vec<String>,
    pub profile: String,
    /// App whose info popup is open (key, anchor) and its alerts, plus whether the Alerts tab is showing.
    pub selected: Option<(String, egui::Pos2)>,
    pub selected_alerts: Vec<Alert>,
    pub show_alerts: bool,
    /// Usage of the data quotas, for the app popup and the Quotas settings.
    pub quotas: Vec<QuotaStatus>,
    /// App an alert asked to show: its name, when it started flashing, and whether it still has to be scrolled to.
    pub flash: Option<(String, std::time::Instant, bool)>,
    /// The row under the mouse: (app key, group, position in its group). It stays at that position while the pointer is on it, so a list that is changing underneath can't put another app beneath a click.
    /// Its fourth part is where the row sits in the scrolled content, to notice layout changes above it.
    pub hold: Option<(String, usize, usize, f32)>,
    /// Scroll offset to apply next frame, to keep the held row where the mouse is.
    pub scroll_to: Option<f32>,
}

#[derive(Default)]
pub struct DnsState {
    /// Column borders as fractions of the table width; empty until the table is first drawn.
    pub cols: Vec<f32>,
    pub search: String,
    pub entries: Vec<DnsEntry>,
    pub loaded: Option<Instant>,
}

#[derive(Default)]
pub struct ConnsState {
    pub cols: Vec<f32>,
    /// Sorted column (index into the headers) and whether ascending; `None` keeps the backend's order.
    pub sort: Option<(usize, bool)>,
    pub group: crate::ui::connections::ConnGroup,
    /// Groups folded shut, by group name.
    pub collapsed: std::collections::HashSet<String>,
    pub search: String,
    pub entries: Vec<LiveConn>,
    pub loaded: Option<Instant>,
}

pub struct LogState {
    pub filter: AlertFilter,
    pub period: AlertPeriod,
    pub search: String,
    pub alerts: Vec<Alert>,
    pub extra: LogFilter,
    pub filter_open: bool,
}

pub struct ScannerState {
    pub networks: Vec<String>,
    pub network: usize,
    pub auto_scan: bool,
    pub search: String,
    pub devices: Vec<Device>,
    pub scan: ScanState,
    /// Column borders as fractions of the table width (see ui::scanner::DEFAULT_COLS).
    pub cols: [f32; 13],
}

/// A modal box over the main window.
pub enum Dialog {
    Settings(Box<Settings>),
    Confirm(Confirm),
    Rename {
        mac: String,
        text: String,
    },
    Info {
        title: String,
        body: String,
    },
    /// The knowledge-graph picture drawn at build time from assets/about_graph.json.
    About(egui::TextureHandle),
    /// The weekly report with charts.
    Report(Box<crate::report::Report>),
    /// Offer to install the service, with the shortcuts to make.
    InstallService {
        desktop: bool,
        start_menu: bool,
    },
    /// Name entry for a new firewall profile.
    NewProfile {
        text: String,
    },
    /// Software update: the result of a check, or an install in progress.
    Update(UpdateView),
    /// Tamper protection: the password to enter before `then` happens.
    Password {
        then: Gated,
        text: String,
        error: bool,
    },
}

/// What the password dialog unlocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gated {
    Settings,
    Exit,
    Restart,
    /// A stop of the service from outside (services.msc, `sc stop`).
    ServiceStop,
}

/// The new-rule form of the Destination rules tab.
pub struct DestDraft {
    /// Program path; empty for any program.
    pub program: String,
    /// One of the kinds `Target::parse` knows: "Domain", "ASN" or "Country".
    pub kind: &'static str,
    pub value: String,
    pub mode: crate::destrules::Mode,
    pub error: String,
}

/// The "Block by domain" card on the Destination Rules tab (Driver mode).
#[derive(Default)]
pub struct DomainDraft {
    pub pattern: String,
    pub url: String,
    pub error: String,
}

/// The new-limit form of the Bandwidth limits tab.
pub struct QosDraft {
    /// Program path.
    pub program: String,
    /// What the user typed; read as a number of `unit`.
    pub value: String,
    /// "Kbps" or "Mbps".
    pub unit: &'static str,
    /// Driver mode: which way the limit applies, and the download rate (read as a number of `down_unit`).
    pub dir: crate::qos::LimitDir,
    pub down_value: String,
    pub down_unit: &'static str,
    /// Driver mode: simulated conditions (whole numbers; empty = none).
    pub delay: String,
    pub loss: String,
    /// Priority class; High and Low may leave the rates empty.
    pub priority: crate::qos::Priority,
    pub error: String,
}

impl Default for QosDraft {
    fn default() -> Self {
        Self {
            program: String::new(),
            value: String::new(),
            unit: "Mbps",
            dir: Default::default(),
            down_value: String::new(),
            down_unit: "Mbps",
            delay: String::new(),
            loss: String::new(),
            priority: Default::default(),
            error: String::new(),
        }
    }
}

impl Default for DestDraft {
    fn default() -> Self {
        Self { program: String::new(), kind: "Domain", value: String::new(), mode: crate::destrules::Mode::Block, error: String::new() }
    }
}

pub enum UpdateView {
    Checking,
    Latest(Vec<crate::update::Note>),
    Available(crate::update::Release),
    Installing(crate::update::Release),
    CheckFailed(String),
    InstallFailed(String),
}

/// What a background update thread reports back.
pub enum UpdateEvent {
    /// `manual` checks show their result; automatic ones only offer an update and otherwise stay silent.
    Checked { manual: bool, result: Result<crate::update::Checked, String> },
    /// The new exe is in place (its path) or the install failed.
    Installed(Result<std::path::PathBuf, String>),
}

pub struct Confirm {
    pub title: String,
    pub body: String,
    /// Label of the button that does it.
    pub yes: String,
    pub action: ConfirmAction,
}

#[derive(Clone, Debug)]
pub enum ConfirmAction {
    FirewallEnabled(bool),
    FirewallMode(FirewallMode),
    WindowsFirewallOn,
    RestoreDefaults,
    /// Import another firewall's rules; `rename` also gives them RustWarden's names.
    ImportRules {
        rename: bool,
    },
    BlockWindowsExtras,
    /// Apply a rules file chosen in Settings > Other (see `rules_file`).
    ApplyRules(Box<crate::rules_file::RulesFile>),
    /// End one open connection (Live connections tab).
    KillConnection(LiveConn),
    /// Unblock, pause or resume one group of the Windows components rules.
    WindowsExtras {
        group: usize,
        act: crate::live::firewall::ExtrasAct,
    },
    ClearHistory,
    /// Delete everything RustWarden downloaded and switch off the features that used it.
    CleanUp,
    /// Send this one program's file (by app key) to VirusTotal.
    VirusTotalUpload {
        key: String,
    },
    /// Download and install the optional network driver (Driver mode), or remove it.
    InstallDriver,
    RemoveDriver,
    /// Install or remove the Windows service, then restart the app.
    Service {
        install: bool,
    },
    /// Switch to Demo; `remove_rules` first removes the RustWarden firewall rules.
    SwitchToDemo {
        remove_rules: bool,
    },
    /// Park the active profile's rules and switch to (or create) `name`.
    SwitchProfile {
        name: String,
        create: bool,
    },
    DeleteProfile {
        name: String,
    },
    Threat {
        ip: String,
        act: crate::data::ThreatAct,
    },
}

/// Pending Allow/Block count and their toast messages (Err = failed).
type Verdicts = Arc<Mutex<(usize, Vec<Result<String, String>>)>>;
/// Hardware chart samples keyed by (window, bucket count, app filter), with when they were fetched.
type HwSeries = crate::util::AsyncMemo<(i64, usize, Option<String>), (Vec<Option<HardwareSample>>, i64)>;

/// What `reload_protect` reads.
struct ProtectLoad {
    info: FirewallInfo,
    apps: Vec<FirewallApp>,
    quotas: Vec<QuotaStatus>,
    profiles: (Vec<String>, String),
}

/// What `reload_scanner` reads.
struct ScannerLoad {
    networks: Vec<String>,
    network: usize,
    devices: Vec<Device>,
    scan: ScanState,
}

pub struct RustWarden {
    pub backend: Arc<dyn Backend>,
    pub settings: Settings,
    pub caps: Capabilities,
    pub notes: Vec<StatusNote>,
    pub tab: Tab,
    pub traffic: TrafficState,
    pub protect: ProtectState,
    pub dest_draft: DestDraft,
    pub domain_draft: DomainDraft,
    pub dest_cols: Vec<f32>,
    pub qos_draft: QosDraft,
    pub rule_draft: crate::ui::alert_rules::RuleDraft,
    pub qos_cols: Vec<f32>,
    pub log: LogState,
    pub dns: DnsState,
    pub conns: ConnsState,
    pub scanner: ScannerState,
    pub tbb: crate::plugins::core::latency::State,
    pub ping_view: crate::plugins::core::latency::State,
    pub ping_dlg: crate::plugins::ping::ui::Dlg,
    pub speedtest: crate::plugins::speedtest::ui::SpeedState,
    pub toast: Option<(String, f64)>,
    /// Desktop popups on screen: (viewport number, alert, expiry in `started` seconds).
    pub popups: Vec<(u64, Alert, f64)>,
    pub popup_seq: u64,
    /// What the banner windows report back; they are deferred viewports, which can't borrow `self`.
    pub(crate) banners: crate::ui::Banners,
    /// Window size (points) to apply on the next frame, once a new zoom is in effect; zero = only the minimum.
    fit: Option<egui::Vec2>,
    /// The window rectangle (pixels) last seen and when it last changed, so the new one is saved once it stops moving.
    win_seen: Option<[i32; 4]>,
    win_dirty: Option<Instant>,
    /// Frames to wait after a window reset before centring it on the screen.
    recenter: u8,
    /// Alert popup whose Info panel is open (viewport number) and the app it describes.
    pub popup_info: Option<(u64, crate::data::FirewallApp)>,
    /// Prompt prompts on screen: (viewport number, request).
    pub asks: Vec<(u64, ConnectAsk)>,
    /// The prompt (viewport number) and button whose menu is open.
    pub ask_flyout: Option<(u64, crate::ui::popup::AskMenu)>,
    /// Id of the Prompt prompt whose app-info panel is open.
    pub ask_info: Option<u64>,
    /// Malicious-IP banners on screen: (viewport number, warning, action awaiting confirmation).
    pub threats: Vec<(u64, crate::data::Threat, Option<crate::data::ThreatAct>)>,
    pub dialog: Option<Dialog>,
    /// Unsaved Settings edits while a confirmation opened from Settings is up; reopened when it closes.
    pub settings_back: Option<Box<Settings>>,
    /// Settings section to show when the Settings dialog opens next (set by buttons elsewhere).
    pub settings_section: Option<usize>,
    pub started: Instant,
    /// Native window handle, kept to re-tint the acrylic backdrop when the theme changes.
    hwnd: isize,
    pub(crate) last_refresh: Instant,
    /// When the Windows accent colour was last looked at (it can change while the app runs).
    accent_polled: Instant,
    theme_polled: Instant,
    /// Reads the Traffic tab's data off the UI thread; `poll_traffic` applies what it found.
    traffic_loader: crate::traffic_load::Loader,
    /// The Protect, Log and Scanner tabs' data, read the same way.
    protect_bg: crate::util::Bg<ProtectLoad>,
    log_bg: crate::util::Bg<Vec<Alert>>,
    scanner_bg: crate::util::Bg<ScannerLoad>,
    pub(crate) dns_bg: crate::util::Bg<Vec<DnsEntry>>,
    pub(crate) conns_bg: crate::util::Bg<Vec<LiveConn>>,
    pub(crate) vt_cache: crate::ui::popup::VtCache,
    /// Filled by the screenshot callback with the saved path or the error.
    snapshot_result: Slot<Result<std::path::PathBuf, String>>,
    /// Whois answer from the background lookup: (ip, text).
    whois_result: Slot<(String, String)>,
    /// Outcome of a service install (true) or removal (false) running behind its UAC prompt.
    service_result: Slot<(bool, Result<(), String>)>,
    /// Outcome of removing RustWarden's rules on a thread before switching to Demo; the switch waits for it.
    demo_switch: Slot<Result<(), String>>,
    pub(crate) update_result: Slot<UpdateEvent>,
    /// Result of the alert log's hash-chain check, run on a thread from the Alerts tab.
    pub(crate) alert_check_result: Slot<Result<AlertCheck, String>>,
    /// Where a history export was written, or why it failed.
    pub(crate) history_result: Slot<Result<std::path::PathBuf, String>>,
    /// The weekly report's text, built on a thread from the Alerts tab.
    pub(crate) report_result: Slot<Result<crate::report::Report, String>>,
    /// The Prometheus endpoint, while Settings > Integrations has it on.
    pub(crate) metrics: Option<crate::metrics::Endpoint>,
    /// Allow/Block changes running on threads: how many are pending, and their toast messages (Err = failed).
    pub(crate) verdicts: Verdicts,
    /// How many of those are not mode changes (removing an app), so the Mode box doesn't flash "Applying…" for them.
    pub(crate) quiet_jobs: Arc<std::sync::atomic::AtomicUsize>,
    /// An update found by an automatic check, waiting for a free moment to be offered.
    pub(crate) update_offer: Option<crate::update::Release>,
    /// Version already offered this session, so the same one isn't offered again.
    pub(crate) update_offered: Option<String>,
    pub(crate) next_update_check: Instant,
    pub ip_info: Option<(String, String)>,
    /// Backend answers the Hardware tab and Settings would otherwise fetch every frame.
    pub(crate) hw_apps: crate::util::AsyncMemo<i64, Vec<String>>,
    pub(crate) hw_series: HwSeries,
    pub(crate) threat_lists: crate::util::Memo<(), ThreatLists>,
    /// Which Windows-component groups have rules / are paused, for the Settings buttons.
    pub(crate) extras_state: crate::util::Memo<(), Vec<(bool, bool)>>,
    pub(crate) driver_state: crate::util::Memo<(), crate::driver::DriverState>,
    pub ip_info_result: Slot<(String, String)>,
    /// `None` if the tray icon couldn't be created; the app then just works without it.
    tray: Option<crate::tray::Tray>,
    pub(crate) window_visible: bool,
    /// The open tray menu, if any.
    pub(crate) tray_menu: Option<crate::ui::TrayMenu>,
    pub(crate) tray_act: Option<crate::ui::TrayAct>,
    /// A timed Prompt: when it ends (unix time) and the mode to go back to (`None` was Disabled).
    pub(crate) prompt_timer: Option<(i64, Option<FirewallMode>)>,
    /// The mode seen at the last poll (`None` before the first), to notice Prompt being switched on.
    pub(crate) prompt_seen: Option<Option<FirewallMode>>,
    /// Set by Exit / restart so the next close request really quits instead of hiding to the tray.
    pub(crate) quitting: bool,
    /// When the service last asked for the password to allow a stop; None when no request is open.
    pub(crate) stop_asked: Option<std::time::Instant>,
    /// Whether the Windows service is installed (cached; asking costs a process spawn).
    pub(crate) service: bool,
    /// Set by `RUSTYWIRE_SHOTS`: walks the README screens and then quits (see shots.rs).
    shots: Option<crate::shots::Shots>,
}

/// How often the UI re-reads the backend.
/// A result a background thread hands to the UI.
type Slot<T> = Arc<Mutex<Option<T>>>;
/// Blocked malicious addresses and the whitelist, as (address, detail) pairs.
pub type ThreatLists = (Vec<(String, String)>, Vec<(String, String)>);

/// Minutes offered by the "Block after" menus.
pub const BLOCK_AFTER_MINS: [u64; 5] = [5, 10, 20, 30, 60];

const REFRESH_EVERY: Duration = Duration::from_millis(1000);

/// Demo's fixed data has its spike at the start of the range; Live data is newest at the right, so it shows everything.
fn default_window(mode: Mode) -> (f32, f32) {
    if mode == Mode::Live { (0.0, 1.0) } else { (0.0, 0.15) }
}

pub fn make_backend(settings: &Settings) -> Arc<dyn Backend> {
    match settings.mode {
        Mode::Demo => Arc::new(crate::demo::MockBackend::new()),
        Mode::Live => Arc::new(crate::live::LiveBackend::new(settings)),
    }
}

/// Viewport commands are in points of the current zoom, so `fit_window` runs on the first frame after the
/// zoom changed. The layout needs 980x640 points; `size` (points, zero = leave alone) keeps the window's layout size.
fn fit_window(ctx: &egui::Context, size: egui::Vec2) {
    let screen = ctx.input(|i| i.viewport().monitor_size).unwrap_or(vec2(f32::MAX, f32::MAX));
    ctx.send_viewport_cmd(ViewportCommand::MinInnerSize(vec2(1160.0, 640.0).min(screen)));
    if size != egui::Vec2::ZERO {
        ctx.send_viewport_cmd(ViewportCommand::InnerSize(size.min(screen)));
    }
}

/// `points` rounded to whole physical pixels. Stacked translucent panels whose edge falls between two pixels
/// each cover only part of that row, so a bright line of the window backdrop shows through between them.
fn snap(ctx: &egui::Context, points: f32) -> f32 {
    let ppp = ctx.pixels_per_point();
    (points * ppp).round() / ppp
}

impl RustWarden {
    /// Keeps the settings' record of the open tab and the Traffic view current, so the next start reopens there.
    fn remember_view(&mut self) {
        if self.settings.last_tab != self.tab.key() || self.settings.traffic_view != self.traffic.view {
            self.settings.last_tab = self.tab.key().to_owned();
            self.settings.traffic_view = self.traffic.view;
            let _ = self.settings.save();
        }
    }

    /// Saves the window's position and size a second after it stops changing, so the next start opens it there.
    fn remember_window(&mut self, ctx: &egui::Context) {
        let (inner, outer, away) = ctx.input(|i| {
            let v = i.viewport();
            (v.inner_rect, v.outer_rect, v.maximized.unwrap_or(false) || v.minimized.unwrap_or(false) || v.fullscreen.unwrap_or(false))
        });
        let (Some(inner), Some(outer)) = (inner, outer) else { return };
        if away || self.fit.is_some() {
            return;
        }
        let ppp = ctx.pixels_per_point();
        let now = [outer.min.x * ppp, outer.min.y * ppp, inner.width() * ppp, inner.height() * ppp].map(|v| v.round() as i32);
        // A hidden or minimised window reports odd rectangles.
        if now[0] < -10_000 || now[1] < -10_000 || now[2] < 300 || now[3] < 300 {
            return;
        }
        match self.win_seen {
            None => self.win_seen = Some(now),
            Some(seen) if seen != now => (self.win_seen, self.win_dirty) = (Some(now), Some(Instant::now())),
            _ => {}
        }
        if let Some(at) = self.win_dirty {
            if at.elapsed() >= Duration::from_secs(1) {
                self.win_dirty = None;
                if self.settings.window != self.win_seen {
                    self.settings.window = self.win_seen;
                    let _ = self.settings.save();
                }
            } else {
                ctx.request_repaint_after(Duration::from_millis(1100));
            }
        }
    }

    /// Forgets the saved window rectangle and puts the window back to its default size in the middle of the screen.
    pub(crate) fn reset_window(&mut self) {
        self.settings.window = None;
        let _ = self.settings.save();
        (self.win_seen, self.win_dirty) = (None, None);
        self.fit = Some(vec2(1190.0, 780.0));
        self.recenter = 3;
    }

    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let shots = crate::shots::folder().map(crate::shots::Shots::new);
        let mut settings = Settings::load();
        if shots.is_some() {
            settings = crate::shots::settings();
        }
        theme::set(settings.dark(), settings.acrylic);
        theme::set_accent(settings.accent_rgb());
        theme::apply(&cc.egui_ctx);
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        let hwnd = match cc.window_handle().map(|h| h.as_raw()) {
            Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
            _ => 0,
        };
        theme::set_popup_opacity(settings.popup_opacity);
        theme::acrylic(hwnd, theme::is_dark(), settings.tint);
        crate::sys::modal::set_main(hwnd);
        theme::install_resize_border(hwnd);
        crate::sys::modal::use_exe_icons(hwnd);
        crate::util::set_bits(settings.bits);
        cc.egui_ctx.set_zoom_factor(settings.text_scale);
        // main.rs already opened the window at the saved size; converting it to points here would miss the zoom factor, which only
        // reaches pixels_per_point on the first frame, and make the window that much bigger on every start.
        let saved_size = settings.window.is_some() && shots.is_none();
        crate::sys::autostart::watch_show(cc.egui_ctx.clone());
        let backend = make_backend(&settings);
        backend.set_repaint(cc.egui_ctx.clone());
        let range = settings.traffic_range;
        let start_tab = Tab::from_key(&settings.last_tab);
        let window = default_window(settings.mode);
        let mut app = Self {
            traffic: TrafficState {
                view: std::env::var("RUSTYWIRE_VIEW").ok().and_then(|v| v.parse().ok()).unwrap_or(settings.traffic_view.min(2)),
                range,
                window,
                loaded_at: 0.0,
                history: TrafficHistory { start_minute: 0.0, step_minutes: 1.0, samples: Vec::new() },
                totals: Totals::default(),
                breakdown: UsageBreakdown::default(),
                map: MapData::default(),
                live: true,
                map_center: (-22.0, crate::geo::mercator_y(48.0)),
                map_zoom: 1.0,
                map_zoom_to: 1.0,
                map_center_to: None,
                map_touched: false,
                detail: None,
                detail_back: Vec::new(),
                sel: None,
                sel_data: UsageBreakdown::default(),
                sel_popup: None,
                alert_popup: None,
                filter: TrafficFilter::default(),
                filter_open: false,
                app_sort: None,
                list_sort: [None; 4],
                app_list: Vec::new(),
            },
            dest_draft: DestDraft::default(),
            domain_draft: DomainDraft::default(),
            dest_cols: Vec::new(),
            qos_draft: QosDraft::default(),
            rule_draft: Default::default(),
            qos_cols: Vec::new(),
            protect: ProtectState {
                info: backend.firewall_info(),
                search: String::new(),
                apps: Vec::new(),
                open_groups: [true; 4],
                cols: crate::ui::protect::DEFAULT_COLS,
                sort: None,
                expanded: HashSet::new(),
                profiles: Vec::new(),
                profile: String::new(),
                selected: None,
                selected_alerts: Vec::new(),
                show_alerts: false,
                quotas: Vec::new(),
                flash: None,
                hold: None,
                scroll_to: None,
            },
            log: LogState { filter: AlertFilter::Important, period: AlertPeriod::AllTime, search: String::new(), alerts: Vec::new(), extra: LogFilter::default(), filter_open: false },
            scanner: ScannerState {
                networks: Vec::new(),
                network: 0,
                auto_scan: settings.auto_scan,
                search: String::new(),
                devices: Vec::new(),
                scan: ScanState::default(),
                cols: <[f32; 13]>::try_from(settings.scanner_cols.as_slice()).unwrap_or(crate::ui::scanner::DEFAULT_COLS),
            },
            caps: backend.capabilities(),
            notes: Vec::new(),
            backend,
            settings,
            // Dev aid: RUSTYWIRE_TAB=0..4 picks the starting tab, RUSTYWIRE_VIEW=0..2 the traffic view.
            tab: std::env::var("RUSTYWIRE_TAB").ok().and_then(|v| v.parse::<usize>().ok()).and_then(|i| Tab::ALL.get(i).copied()).or(start_tab).unwrap_or(Tab::Traffic),
            tbb: Default::default(),
            ping_view: Default::default(),
            speedtest: Default::default(),
            ping_dlg: Default::default(),
            toast: None,
            popups: Vec::new(),
            popup_seq: 0,
            banners: Default::default(),
            fit: Some(if saved_size { egui::Vec2::ZERO } else { vec2(1190.0, 780.0) }),
            win_seen: None,
            win_dirty: None,
            recenter: 0,
            popup_info: None,
            asks: Vec::new(),
            ask_flyout: None,
            ask_info: None,
            dns: DnsState::default(),
            conns: ConnsState::default(),
            threats: Vec::new(),
            dialog: None,
            settings_back: None,
            settings_section: None,
            started: Instant::now(),
            hwnd,
            last_refresh: Instant::now(),
            accent_polled: Instant::now(),
            theme_polled: Instant::now(),
            traffic_loader: crate::traffic_load::Loader::new(cc.egui_ctx.clone()),
            protect_bg: crate::util::Bg::new(cc.egui_ctx.clone()),
            log_bg: crate::util::Bg::new(cc.egui_ctx.clone()),
            scanner_bg: crate::util::Bg::new(cc.egui_ctx.clone()),
            snapshot_result: Arc::new(Mutex::new(None)),
            whois_result: Arc::new(Mutex::new(None)),
            service_result: Arc::new(Mutex::new(None)),
            demo_switch: Arc::new(Mutex::new(None)),
            verdicts: Arc::default(),
            quiet_jobs: Arc::default(),
            update_result: Arc::new(Mutex::new(None)),
            alert_check_result: Arc::new(Mutex::new(None)),
            history_result: Arc::new(Mutex::new(None)),
            report_result: Arc::new(Mutex::new(None)),
            metrics: None,
            update_offer: None,
            update_offered: None,
            next_update_check: Instant::now() + std::time::Duration::from_secs(10),
            ip_info: None,
            hw_apps: crate::util::AsyncMemo::new(cc.egui_ctx.clone()),
            hw_series: crate::util::AsyncMemo::new(cc.egui_ctx.clone()),
            dns_bg: crate::util::Bg::new(cc.egui_ctx.clone()),
            conns_bg: crate::util::Bg::new(cc.egui_ctx.clone()),
            vt_cache: Default::default(),
            threat_lists: Default::default(),
            extras_state: Default::default(),
            driver_state: Default::default(),
            ip_info_result: Arc::new(Mutex::new(None)),
            tray: None,
            window_visible: true,
            tray_menu: None,
            tray_act: None,
            prompt_timer: None,
            prompt_seen: None,
            quitting: false,
            stop_asked: None,
            service: crate::sys::autostart::service_installed(),
            shots,
        };
        app.tray = crate::tray::Tray::new(&cc.egui_ctx).ok();
        crate::live::geo::spawn_auto_update();
        // Only with a tray icon to bring it back from.
        if crate::sys::hidden_start() && app.tray.is_some() {
            app.show_window(&cc.egui_ctx, false);
        }
        crate::update::cleanup();
        app.apply_metrics();
        if !cfg!(debug_assertions) && app.shots.is_none() {
            std::thread::spawn(crate::sys::autostart::ensure_service_running);
            crate::sys::autostart::watch_stop_ask(cc.egui_ctx.clone());
        }
        // A Block All left active by a crash is undone on start. The live backend does that itself and then
        // resumes the remembered mode, so this is only for Demo (undoing it here would race the resume).
        if app.settings.mode == Mode::Demo && crate::live::firewall::block_all_marker_exists() {
            match crate::live::firewall::recover_block_all() {
                Ok(_) => app.notify("Block All from an earlier session was undone"),
                Err(e) => {
                    app.dialog = Some(Dialog::Info {
                        title: "Block All is still active".into(),
                        body: format!(
                            "{e}

Start RustWarden as administrator once: it undoes Block All automatically."
                        ),
                    })
                }
            }
        }
        app.reload_all();
        if let Some(e) = app.settings.load_error.take() {
            app.notify(&e);
        }
        app
    }

    /// Shows a short message at the bottom of the window.
    pub fn notify(&mut self, message: &str) {
        let now = self.started.elapsed().as_secs_f64();
        self.toast = Some((message.to_owned(), now + 2.6));
    }

    /// Runs a backend write; shows the error as a toast and returns whether it worked.
    pub fn attempt(&mut self, result: Result<(), String>) -> bool {
        match result {
            Ok(()) => true,
            Err(e) => {
                self.notify(&e);
                false
            }
        }
    }

    pub fn reload_traffic(&mut self) {
        self.request_traffic(true, true, false);
    }

    /// Asks the worker for fresh Traffic data: the history and map, the figures for the window, or just the selection.
    pub fn request_traffic(&mut self, history: bool, figures: bool, app_list: bool) {
        let t = &self.traffic;
        let q = crate::traffic_load::Query {
            range: t.range,
            window: t.window,
            filter: t.filter.clone(),
            apply_filter: false,
            sel: t.sel,
            basis: (t.history.start_minute, t.history.span_minutes()),
            history,
            figures,
            app_list,
        };
        self.traffic_loader.request(&self.backend, q);
        // A selection-only read runs every frame while dragging; stamping it would starve the one-second refresh, so the live graph
        // (which scrolls from the last reload) froze for as long as the drag lasted and then jumped.
        if history || figures || app_list {
            self.last_refresh = Instant::now();
        }
    }

    /// Takes in what the worker read. A load for a range the user has since left is dropped.
    fn poll_traffic(&mut self) {
        match self.traffic_loader.poll(&self.backend) {
            Some(Ok(l)) => {
                self.traffic_loader.failing = false;
                let t = &mut self.traffic;
                if l.range != Some(t.range) {
                    return;
                }
                if let Some(h) = l.history {
                    (t.history, t.loaded_at) = (h, l.loaded_at);
                }
                if let Some(map) = l.map {
                    t.map = map;
                }
                if let (Some(totals), Some(breakdown)) = (l.totals, l.breakdown) {
                    (t.totals, t.breakdown) = (totals, breakdown);
                }
                if let Some(list) = l.app_list {
                    t.app_list = list;
                }
                if let Some(sel) = l.sel_data {
                    t.sel_data = sel;
                }
            }
            Some(Err(e)) if !self.traffic_loader.failing => {
                self.traffic_loader.failing = true;
                self.notify(&format!("Couldn't refresh traffic data: {e}"));
            }
            _ => {}
        }
    }

    /// After the visible window moved (drag, zoom): only the figures for the new span change, not the history or map.
    /// Skipped when the last reload was a moment ago; the next one-second refresh catches up.
    pub fn reload_window(&mut self) {
        if self.last_refresh.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.request_traffic(false, true, false);
    }

    /// The highlighted span as fractions of the loaded history.
    pub fn sel_window(&self) -> Option<(f32, f32)> {
        let t = &self.traffic;
        let (a, b) = t.sel?;
        crate::traffic_load::sel_fractions((a, b), t.history.start_minute, t.history.span_minutes())
    }

    pub fn reload_sel(&mut self) {
        if self.traffic.sel.is_some() {
            self.request_traffic(false, false, false);
        }
    }

    pub fn reload_protect(&mut self) {
        // A change still being applied would be flipped back by the stale list; poll_verdicts reloads when it lands.
        if self.verdicts.lock().unwrap_or_else(|e| e.into_inner()).0 > 0 {
            return;
        }
        let (b, settings) = (self.backend.clone(), self.settings.clone());
        self.protect_bg.request(move || ProtectLoad { info: b.firewall_info(), apps: b.firewall_apps(), quotas: b.quotas(&settings), profiles: b.firewall_profiles() });
    }

    pub fn reload_log(&mut self) {
        let b = self.backend.clone();
        self.log_bg.request(move || b.alerts());
    }

    pub fn reload_scanner(&mut self) {
        let (b, saved) = (self.backend.clone(), self.settings.scan_network.clone());
        self.scanner_bg.request(move || {
            let networks = b.networks();
            // Keep following the saved adapter by name; indexes shift when adapters come and go.
            // If it is gone, an old index could now point at a different one, so start from the first.
            let network = networks.iter().position(|n| *n == saved).unwrap_or(0);
            let devices = networks.get(network).map(|n| b.devices(n)).unwrap_or_default();
            ScannerLoad { networks, network, devices, scan: b.scan_state() }
        });
    }

    /// Takes in what the Protect, Log and Scanner workers read; a failure shows once as a toast.
    fn poll_tabs(&mut self) {
        match self.protect_bg.poll() {
            // A change still being applied would be flipped back by this list; poll_verdicts reloads when it lands.
            Some(Ok(l)) if self.verdicts.lock().unwrap_or_else(|e| e.into_inner()).0 == 0 => {
                (self.protect.info, self.protect.apps, self.protect.quotas) = (l.info, l.apps, l.quotas);
                (self.protect.profiles, self.protect.profile) = l.profiles;
                self.protect.apps.retain(|a| !self.settings.hidden_apps.contains(&a.key));
                let keys: HashSet<&str> = self.protect.apps.iter().map(|a| a.key.as_str()).collect();
                self.protect.expanded.retain(|k| keys.contains(k.as_str()));
            }
            Some(Err(e)) => self.notify(&format!("Couldn't refresh the app list: {e}")),
            _ => {}
        }
        match self.log_bg.poll() {
            Some(Ok(alerts)) => self.log.alerts = alerts,
            Some(Err(e)) => self.notify(&format!("Couldn't refresh the alert log: {e}")),
            None => {}
        }
        if let Some(entries) = self.conns_bg.poll() {
            match entries {
                Ok(entries) => self.conns.entries = entries,
                Err(e) => self.notify(&format!("Couldn't refresh the connections: {e}")),
            }
        }
        match self.dns_bg.poll() {
            Some(Ok(entries)) => self.dns.entries = entries,
            Some(Err(e)) => self.notify(&format!("Couldn't refresh the DNS log: {e}")),
            None => {}
        }
        // The Hardware tab's reads fail quietly in `AsyncMemo`; say so here.
        if let Some(e) = self.hw_series.error.take().or_else(|| self.hw_apps.error.take()) {
            self.notify(&format!("Couldn't read the hardware history: {e}"));
        }
        match self.scanner_bg.poll() {
            Some(Ok(l)) => {
                (self.scanner.networks, self.scanner.network, self.scanner.devices, self.scanner.scan) = (l.networks, l.network, l.devices, l.scan);
            }
            Some(Err(e)) => self.notify(&format!("Couldn't refresh the scanner: {e}")),
            None => {}
        }
    }

    /// Re-reads everything from the backend (after a mode switch, or on the refresh timer).
    pub fn reload_all(&mut self) {
        self.caps = self.backend.capabilities();
        self.notes = self.backend.status();
        self.reload_traffic();
        // The app list is the costly part (every process, several queries per app): only refreshed while shown.
        if self.tab == Tab::Protect || self.traffic.filter_open || self.protect.apps.is_empty() {
            self.reload_protect();
        } else {
            self.protect.info = self.backend.firewall_info();
        }
        self.reload_log();
        // Devices are only read for the Scanner tab (and once at the start, for its network list).
        if self.tab == Tab::Scanner || self.scanner.networks.is_empty() {
            self.reload_scanner();
        }
        self.last_refresh = Instant::now();
    }

    /// Replaces the backend with one for `mode` and rebuilds all state from it.
    pub fn switch_mode(&mut self, ctx: &egui::Context, mode: Mode) {
        if self.settings.mode == mode {
            return;
        }
        self.backend.shutdown();
        self.settings.set_mode(mode);
        if let Err(e) = self.settings.save() {
            self.notify(&format!("Couldn't save settings: {e}"));
        }
        self.backend = make_backend(&self.settings);
        self.backend.set_repaint(ctx.clone());
        self.backend.set_traffic_filter(&self.traffic.filter);
        self.traffic.window = default_window(mode);
        self.protect.expanded.clear();
        // Prompts and selections belong to the old backend; answering them now would go to the wrong one.
        self.protect.selected = None;
        self.asks.clear();
        self.threats.clear();
        self.popups.clear();
        self.popup_info = None;
        let t = &mut self.traffic;
        (t.detail, t.sel, t.sel_popup, t.alert_popup) = (None, None, None, None);
        t.detail_back.clear();
        self.reload_protect();
        self.reload_all();
        self.notify(&format!("{} mode", mode.label()));
    }

    /// Switching away from Live offers to remove RustWarden's firewall rules first.
    pub fn request_mode(&mut self, ctx: &egui::Context, mode: Mode) {
        if mode == self.settings.mode {
            return;
        }
        if mode == Mode::Demo && self.protect.info.rule_count > 0 {
            self.dialog = Some(Dialog::Confirm(Confirm {
                title: "Switch to Demo mode?".into(),
                body: format!(
                    "RustWarden has {} firewall rule(s) in Windows Firewall. They keep blocking until you remove them.\n\nRemove them now, or leave them in place?",
                    self.protect.info.rule_count
                ),
                yes: "Remove rules and switch".into(),
                action: ConfirmAction::SwitchToDemo { remove_rules: true },
            }));
        } else {
            self.switch_mode(ctx, mode);
        }
    }

    pub fn unread_count(&self) -> usize {
        self.log.alerts.iter().filter(|a| a.unread).count()
    }

    pub fn apply_settings(&mut self, ctx: &egui::Context, settings: Settings) {
        let wanted_mode = settings.mode;
        let mut settings = settings;
        if !settings.tamper_new.trim().is_empty() {
            settings.tamper_hash = crate::tamper::hash(&settings.tamper_new);
        }
        settings.tamper_new.clear();
        settings.mode = self.settings.mode;
        settings.sanitize();
        crate::util::set_bits(settings.bits);
        let (maximized, points) = ctx.input(|i| (i.viewport().maximized.unwrap_or(false), i.viewport().inner_rect.map(|r| r.size())));
        ctx.set_zoom_factor(settings.text_scale);
        self.fit = Some(points.filter(|_| !maximized).unwrap_or(egui::Vec2::ZERO));
        theme::set(settings.dark(), settings.acrylic);
        theme::set_accent(settings.accent_rgb());
        theme::restyle(ctx);
        theme::set_popup_opacity(settings.popup_opacity);
        theme::acrylic(self.hwnd, theme::is_dark(), settings.tint);
        settings.window = self.settings.window;
        if settings.update_channel != self.settings.update_channel {
            self.next_update_check = Instant::now();
            self.update_offered = None;
        }
        self.settings = settings;
        if let Err(e) = self.settings.save() {
            self.notify(&format!("Couldn't save settings: {e}"));
        }
        self.backend.apply_settings(&self.settings);
        self.apply_metrics();
        self.scanner.auto_scan = self.settings.auto_scan;
        self.request_mode(ctx, wanted_mode);
        self.reload_all();
    }

    pub fn restart_as_admin(&mut self, ctx: &egui::Context) {
        match crate::sys::restart_elevated() {
            Ok(()) => {
                self.backend.shutdown();
                self.quitting = true;
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            Err(e) => self.notify(&e),
        }
    }

    /// Asks for the tamper-protection password before `then`.
    pub(crate) fn ask_password(&mut self, then: Gated) {
        self.dialog = Some(Dialog::Password { then, text: String::new(), error: false });
    }

    /// Brings the window up when a tray action asked for the password.
    pub(crate) fn show_password(&mut self, ctx: &egui::Context) {
        if matches!(self.dialog, Some(Dialog::Password { .. })) {
            self.show_window(ctx, true);
        }
    }

    /// Exits for real (the close button only hides to the tray), after the password if one is set.
    pub(crate) fn request_exit(&mut self, ctx: &egui::Context) {
        if self.settings.tamper_on() {
            self.ask_password(Gated::Exit);
        } else {
            self.quitting = true;
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }
    }

    /// Relaunches the whole app (and its service, if installed) and closes this window.
    pub fn restart_app(&mut self, ctx: &egui::Context) {
        if self.settings.tamper_on() {
            return self.ask_password(Gated::Restart);
        }
        self.restart_now(ctx);
    }

    pub(crate) fn restart_now(&mut self, ctx: &egui::Context) {
        match crate::sys::restart_app() {
            Ok(()) => {
                self.backend.shutdown();
                self.quitting = true;
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            Err(e) => self.notify(&e),
        }
    }

    /// The thin strip under the header that says what Live mode can't do right now.
    /// The Network tab's sub-tabs, centred; only drawn while the Broadband tab is in use.
    fn network_tabs(&mut self, ui: &mut Ui) {
        let mut subs = vec![(Tab::Scanner, "Network Scanner")];
        if crate::plugins::thinkbroadband::tab_visible(&self.settings) {
            subs.push((Tab::Broadband, "Broadband Quality"));
        }
        if crate::plugins::ping::tab_visible(&self.settings) {
            subs.push((Tab::Ping, "Ping Monitor"));
        }
        if crate::plugins::speedtest::tab_visible(&self.settings) {
            subs.push((Tab::Speedtest, "Speedtest"));
        }
        subs.push((Tab::Dns, "DNS Log"));
        self.sub_tab_strip(ui, subs);
    }

    /// The Alerts tab's sub-tabs: the log and the rules that shape what reaches you.
    fn alert_tabs(&mut self, ui: &mut Ui) {
        self.sub_tab_strip(ui, vec![(Tab::Log, "Alerts"), (Tab::AlertRules, "Rules")]);
    }

    /// The Firewall tab's sub-tabs: the firewall rules and the live connections table.
    fn protect_tabs(&mut self, ui: &mut Ui) {
        self.sub_tab_strip(ui, vec![(Tab::Protect, "Firewall"), (Tab::Connections, "Live Connections"), (Tab::DestRules, "Destination Rules"), (Tab::Bandwidth, "Limits / QoS")]);
    }

    fn sub_tab_strip(&mut self, ui: &mut Ui, subs: Vec<(Tab, &'static str)>) {
        let rect = ui.max_rect();
        let p = ui.painter().clone();
        let widths: Vec<f32> = subs.iter().map(|(_, t)| p.layout_no_wrap((*t).into(), theme::font(14.5), theme::text()).size().x + 52.0).collect();
        let mut x = rect.left() + 14.0;
        let mut underline = None;
        for ((tab, label), w) in subs.into_iter().zip(widths) {
            let r = Rect::from_min_size(pos2(x, rect.top()), vec2(w, rect.height()));
            x += w;
            let resp = ui.interact(r, Id::unique(("subtab", tab as u8)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            if resp.clicked() {
                self.tab = tab;
            }
            let active = self.tab == tab;
            let color = if active {
                theme::accent_text()
            } else if resp.hovered() {
                theme::text()
            } else {
                theme::text_dim()
            };
            let icon = match tab {
                Tab::Protect => Icon::Shield,
                Tab::Connections => Icon::Plug,
                Tab::DestRules => Icon::Globe,
                Tab::Bandwidth => Icon::Traffic,
                Tab::Log => Icon::Alerts,
                Tab::AlertRules => Icon::Sliders,
                Tab::Scanner => Icon::Scanner,
                Tab::Broadband => Icon::Wifi,
                Tab::Ping => Icon::Wave,
                Tab::Speedtest => Icon::Traffic,
                _ => Icon::Search,
            };
            icons::outline(&p, icon, Rect::from_center_size(pos2(r.left() + 24.0, r.center().y), vec2(16.0, 16.0)), color);
            p.text(pos2(r.left() + 40.0, r.center().y), Align2::LEFT_CENTER, label, theme::font(14.5), color);
            if active {
                underline = Some((r.left() + 10.0, r.right() - 10.0));
            }
        }
        // The underline slides from the old tab to the new one.
        if let Some((l, rt)) = underline {
            let ctx = ui.ctx();
            let (l, rt) = (ctx.animate_value_with_time(Id::NULL.with("sub_ul_l"), l, 0.15), ctx.animate_value_with_time(Id::NULL.with("sub_ul_r"), rt, 0.15));
            p.rect_filled(Rect::from_min_max(pos2(l, rect.bottom() - 3.0), pos2(rt, rect.bottom())), 2, theme::accent());
        }
    }

    fn status_strip(&mut self, ui: &mut Ui) {
        let warns: Vec<&StatusNote> = self.notes.iter().filter(|n| n.level == NoteLevel::Warn).collect();
        let Some(first) = warns.first() else { return };
        let text = if warns.len() > 1 { format!("{}  (+{} more)", first.text, warns.len() - 1) } else { first.text.clone() };
        let all = self.notes.iter().map(|n| n.text.as_str()).collect::<Vec<_>>().join("\n");
        let elevate = !self.caps.elevated;
        let mut restart = false;
        let mut install = false;
        let offer_install = elevate && !self.service && !cfg!(debug_assertions);
        Panel::top("status").exact_size(30.0).frame(Frame::NONE.fill(theme::banner_bg()).stroke(Stroke::new(1.0, theme::border()))).show(ui, |ui| {
            crate::ui::row_in(ui, ui.max_rect().shrink2(vec2(16.0, 0.0)), |ui| {
                ui.label(egui::RichText::new(text).font(theme::font(14.0)).color(theme::text())).on_hover_text(all);
                if elevate {
                    ui.add_space(10.0);
                    restart = ui.link(egui::RichText::new("Restart as administrator").font(theme::font(14.0))).clicked();
                }
                if offer_install {
                    ui.add_space(10.0);
                    install = ui.link(egui::RichText::new("Install service").font(theme::font(14.0))).on_hover_text("Lets RustWarden open as administrator without asking each time").clicked();
                }
            });
        });
        if install {
            self.dialog = Some(Dialog::InstallService { desktop: true, start_menu: true });
        }
        if restart {
            self.restart_as_admin(ui.ctx());
        }
    }

    /// "Follow Windows theme": picks up a switch between light and dark made in Windows Settings within a second.
    fn follow_windows_theme(&mut self, ctx: &egui::Context) {
        if !self.settings.follow_windows_theme || self.theme_polled.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.theme_polled = Instant::now();
        let dark = self.settings.dark();
        if dark != theme::is_dark() {
            theme::set(dark, self.settings.acrylic);
            theme::restyle(ctx);
            theme::acrylic(self.hwnd, dark, self.settings.tint);
            ctx.request_repaint();
        }
    }

    /// "Use Windows accent colour": picks up a change made in Windows Settings within a second.
    fn follow_windows_accent(&mut self, ctx: &egui::Context) {
        if !self.settings.accent_windows || self.accent_polled.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.accent_polled = Instant::now();
        let now = self.settings.accent_rgb();
        if now != theme::accent_rgb() {
            theme::set_accent(now);
            theme::restyle(ctx);
            ctx.request_repaint();
        }
    }

    fn header(&mut self, ui: &mut Ui) {
        let rect = ui.max_rect();
        let ctx = ui.ctx().clone();
        let drag = ui.interact(rect, Id::unique("titlebar"), Sense::click_and_drag());
        if drag.drag_started_by(PointerButton::Primary) {
            ctx.send_viewport_cmd(ViewportCommand::StartDrag);
        }
        if drag.double_clicked() {
            let max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
            ctx.send_viewport_cmd(ViewportCommand::Maximized(!max));
        }

        // Brand menu.
        let cy = rect.top() + 32.0;
        let brand = Rect::from_min_size(pos2(rect.left() + 14.0, cy - 18.0), vec2(160.0, 36.0));
        let resp = ui.interact(brand, Id::unique("brand"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
        let p = ui.painter().clone();
        let mut job = egui::text::LayoutJob::default();
        for (word, color) in [("Rust", theme::brand_orange()), ("Warden", theme::brand_cream())] {
            job.append(word, 0.0, egui::TextFormat { font_id: theme::bold(17.0), color, ..Default::default() });
        }
        let g = p.layout_job(job);
        // The app icon, loaded once as a small texture.
        let logo_id = Id::NULL.with("brand_logo");
        let logo = ctx.data_mut(|d| d.get_temp::<egui::TextureHandle>(logo_id)).unwrap_or_else(|| {
            let (rgba, w, h) = crate::util::small_icon_rgba();
            let tex = ctx.load_texture("brand-logo", egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba), egui::TextureOptions::LINEAR);
            ctx.data_mut(|d| d.insert_temp(logo_id, tex.clone()));
            tex
        });
        p.image(logo.id(), Rect::from_center_size(pos2(brand.left() + 13.0, cy), vec2(22.0, 22.0)), Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
        p.galley(pos2(brand.left() + 32.0, cy - g.size().y / 2.0), g.clone(), theme::brand_cream());
        icons::paint(&p, Icon::Chevron, Rect::from_center_size(pos2(brand.left() + g.size().x + 44.0, cy), vec2(11.0, 11.0)), theme::brand_yellow());
        egui::Popup::menu(&resp).width(264.0).show(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let row = |ui: &mut Ui, icon, label: &str| widgets::brand_menu_row(ui, icon, label).clicked();
            if self.settings.mode == Mode::Live {
                if !self.caps.elevated && row(ui, Icon::Shield, "Restart as administrator") {
                    self.restart_as_admin(&ctx);
                    ui.close();
                }
                if row(ui, Icon::Reset, "Restore firewall defaults") {
                    self.confirm_restore_defaults();
                    ui.close();
                }
                widgets::menu_sep(ui);
            }
            if row(ui, Icon::Shield, "Destination rules...") {
                self.tab = Tab::DestRules;
                ui.close();
            }
            if row(ui, Icon::Traffic, "Limits / QoS...") {
                self.tab = Tab::Bandwidth;
                ui.close();
            }
            if row(ui, Icon::Sliders, "Settings...") {
                self.open_settings();
                ui.close();
            }
            if row(ui, Icon::Export, "Save snapshot") {
                self.request_snapshot(&ctx);
                ui.close();
            }
            widgets::menu_sep(ui);
            if row(ui, Icon::Reset, "Check for updates") {
                self.check_for_updates(&ctx, true);
                ui.close();
            }
            if row(ui, Icon::Restart, "Restart service") {
                self.restart_app(&ctx);
                ui.close();
            }
            if row(ui, Icon::Info, "About RustWarden") {
                self.dialog = Some(Dialog::About(ctx.load_texture("about-graph", Self::about_image(), egui::TextureOptions::LINEAR)));
                ui.close();
            }
        });

        // Demo chip: only shown while demo data is in use; switched off in Settings > Other.
        if self.settings.mode == Mode::Demo {
            let chip = Rect::from_min_size(pos2(brand.left() + 32.0 + g.size().x + 34.0, cy - 11.0), vec2(58.0, 22.0));
            let chip_resp = ui.interact(chip, Id::unique("mode_chip"), Sense::hover());
            let (fill, ink) = (theme::accent_soft(), theme::accent_text());
            p.rect_filled(chip, 11, fill);
            p.rect_stroke(chip, 11, Stroke::new(1.0, ink.gamma_multiply(0.5)), egui::epaint::StrokeKind::Inside);
            p.text(chip.center(), Align2::CENTER_CENTER, self.settings.mode.label(), theme::bold(12.0), ink);
            chip_resp.on_hover_text("Placeholder data. Turn off \"Use demo data\" in Settings > Other to measure this machine.");
        }

        // VPN chip: same spot as the Demo chip (Demo wins if both apply); the old banner text is the tooltip.
        if self.settings.mode != Mode::Demo
            && let Some(note) = self.notes.iter().find(|n| n.level == NoteLevel::Vpn)
        {
            let chip = Rect::from_min_size(pos2(brand.left() + 32.0 + g.size().x + 34.0, cy - 11.0), vec2(74.0, 22.0));
            let chip_resp = ui.interact(chip, Id::unique("vpn_chip"), Sense::hover());
            let (fill, ink) = (theme::accent_soft(), theme::accent_text());
            p.rect_filled(chip, 11, fill);
            p.rect_stroke(chip, 11, Stroke::new(1.0, ink.gamma_multiply(0.5)), egui::epaint::StrokeKind::Inside);
            p.text(chip.center(), Align2::CENTER_CENTER, "VPN in use", theme::bold(12.0), ink);
            chip_resp.on_hover_text(note.text.clone());
        }

        // Tabs: left-aligned after the brand, one line each, the open one underlined in the accent colour.
        let tabs: Vec<Tab> = Tab::ALL.into();
        let chip_w: f32 = if self.settings.mode == Mode::Demo {
            58.0
        } else if self.notes.iter().any(|n| n.level == NoteLevel::Vpn) {
            74.0
        } else {
            0.0
        };
        // Never under the chip on the left or the buttons on the right: tighter padding when short of room.
        let left_limit = brand.left() + 32.0 + g.size().x + 34.0 + chip_w.max(26.0) + 16.0;
        let room = (rect.right() - 230.0 - left_limit).max(0.0);
        // Full names while they fit, then tighter padding, then one-word names.
        let label_of = |t: &Tab, short: bool| match (t, short) {
            (_, true) => t.lines().0.to_owned(),
            (_, false) => {
                let (a, b) = t.lines();
                if b.is_empty() { a.to_owned() } else { format!("{a} {b}") }
            }
        };
        let widths_for =
            |pad: f32, short: bool| -> Vec<f32> { tabs.iter().map(|t| pad + 22.0 + 8.0 + p.layout_no_wrap(label_of(t, short), theme::font(15.0), theme::text()).size().x + pad).collect() };
        let (mut pad, mut short) = (16.0, false);
        let mut widths = widths_for(pad, short);
        if widths.iter().sum::<f32>() > room {
            pad = 9.0;
            widths = widths_for(pad, short);
        }
        if widths.iter().sum::<f32>() > room {
            (pad, short) = (12.0, true);
            widths = widths_for(pad, short);
        }
        let mut x = left_limit;
        let unread = self.unread_count();
        let mut underline = None;
        for (tab, w) in tabs.into_iter().zip(widths) {
            let r = Rect::from_min_size(pos2(x, rect.top() + 6.0), vec2(w, rect.height() - 6.0));
            x += w;
            let resp = ui.interact(r, Id::unique(("tab", tab as u8)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            let active = self.tab == tab
                || (tab == Tab::Scanner && matches!(self.tab, Tab::Broadband | Tab::Ping | Tab::Speedtest | Tab::Dns))
                || (tab == Tab::Protect && matches!(self.tab, Tab::Connections | Tab::DestRules | Tab::Bandwidth))
                || (tab == Tab::Log && self.tab == Tab::AlertRules);
            if resp.clicked() && !active {
                self.tab = tab;
            }
            if resp.hovered() && !active {
                p.rect_filled(Rect::from_center_size(pos2(r.center().x, cy - 1.0), vec2(w, 42.0)), 6, theme::nav_on());
            }
            if active {
                underline = Some((r.left() + pad - 2.0, r.right() - pad + 2.0));
            }
            let icon_rect = Rect::from_center_size(pos2(r.left() + pad + 11.0, cy), vec2(22.0, 22.0));
            icons::outline(&p, tab.icon(), icon_rect, if active { theme::accent_text() } else { theme::text_dim() });
            if tab == Tab::Log && unread > 0 {
                widgets::count_badge(&p, icon_rect.right_top() + vec2(0.0, 2.0), unread);
            }
            p.text(pos2(r.left() + pad + 30.0, cy), Align2::LEFT_CENTER, label_of(&tab, short), theme::font(15.0), theme::text());
        }
        // The underline slides from the old tab to the new one.
        if let Some((l, rt)) = underline {
            let (l, rt) = (ctx.animate_value_with_time(Id::NULL.with("tab_ul_l"), l, 0.15), ctx.animate_value_with_time(Id::NULL.with("tab_ul_r"), rt, 0.15));
            p.rect_filled(Rect::from_min_max(pos2(l, rect.bottom() - 4.0), pos2(rt, rect.bottom() - 1.0)), 2, theme::accent());
        }

        // Window controls (Windows 11 sizes: 46x32, the close button turns red) and account.
        let mut right = rect.right();
        for (icon, cmd_id) in [(Icon::Close, 2), (Icon::Maximize, 1), (Icon::Minimize, 0)] {
            let r = Rect::from_min_max(pos2(right - 46.0, rect.top()), pos2(right, rect.top() + 32.0));
            right -= 46.0;
            let resp = ui.interact(r, Id::unique(("winctl", cmd_id)), Sense::click());
            let hot = resp.hovered();
            if hot {
                p.rect_filled(r, 0, if cmd_id == 2 { theme::red() } else { theme::nav_on() });
            }
            let color = if hot && cmd_id == 2 { Color32::WHITE } else { theme::text() };
            icons::paint(&p, icon, Rect::from_center_size(r.center(), vec2(16.0, 16.0)), color);
            if resp.clicked() {
                match cmd_id {
                    0 => ctx.send_viewport_cmd(ViewportCommand::Minimized(true)),
                    1 => {
                        let max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                        ctx.send_viewport_cmd(ViewportCommand::Maximized(!max));
                    }
                    _ => ctx.send_viewport_cmd(ViewportCommand::Close),
                }
            }
        }
        let sun = Rect::from_min_max(pos2(right - 46.0, rect.top()), pos2(right, rect.top() + 32.0));
        let sun_resp = ui.interact(sun, Id::unique("theme_btn"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(if theme::is_dark() {
            "Switch to the light theme"
        } else {
            "Switch to the dark theme"
        });
        if sun_resp.hovered() {
            p.rect_filled(sun, 0, theme::nav_on());
        }
        icons::theme_toggle(&p, theme::is_dark(), Rect::from_center_size(sun.center(), vec2(18.0, 18.0)), theme::text());
        if sun_resp.clicked() {
            let mut s = self.settings.clone();
            s.theme = if theme::is_dark() { crate::settings::Theme::Light } else { crate::settings::Theme::Dark };
            self.apply_settings(&ctx, s);
        }
    }

    /// Opens the confirmation for removing every RustWarden firewall rule.
    pub fn confirm_restore_defaults(&mut self) {
        self.dialog = Some(Dialog::Confirm(Confirm {
            title: "Restore firewall defaults?".into(),
            body: "This deletes every Windows Firewall rule that RustWarden created (the \"RustyWire\" group) and nothing else. Rules from Windows or other programs are not touched.".into(),
            yes: "Remove RustWarden rules".into(),
            action: ConfirmAction::RestoreDefaults,
        }));
    }

    /// Runs the action behind a confirmed dialog.
    pub fn run_confirmed(&mut self, ctx: &egui::Context, action: ConfirmAction) {
        match action {
            // The firewall calls below take seconds; they run on a thread and report through poll_verdicts.
            ConfirmAction::FirewallEnabled(on) => self.run_bg(move |b| b.set_firewall_enabled(on).map(|()| String::new())),
            ConfirmAction::KillConnection(c) => self.run_bg(move |b| b.kill_connection(&c)),
            ConfirmAction::FirewallMode(mode) => self.run_bg(crate::ui::protect::set_mode_and_enable(mode, !self.protect.info.enabled)),
            ConfirmAction::WindowsFirewallOn => self.run_bg(|b| b.enable_windows_firewall().map(|()| String::new())),
            ConfirmAction::Threat { ip, act } => self.run_bg(move |b| b.threat_act(&ip, act).map(|()| String::new())),
            ConfirmAction::RestoreDefaults => self.run_bg(|b| b.restore_defaults().map(|()| "RustWarden firewall rules removed".into())),
            ConfirmAction::SwitchProfile { name, create } => self.run_bg(move |b| b.switch_firewall_profile(&name, create).map(|()| format!("Firewall ruleset: {name}"))),
            ConfirmAction::DeleteProfile { name } => self.run_bg(move |b| b.delete_firewall_profile(&name).map(|()| format!("Deleted firewall ruleset {name}"))),
            ConfirmAction::ImportRules { rename } => self.run_bg(move |b| b.import_firewall_rules(rename).map(|n| format!("Imported {n} existing firewall rule(s)"))),
            ConfirmAction::ApplyRules(file) => {
                if let Some(text) = &file.settings {
                    match self.settings.merged_from(text) {
                        Ok((merged, skipped)) => {
                            self.apply_settings(ctx, merged);
                            if skipped > 0 {
                                self.notify(&format!("{skipped} setting(s) in the file weren't understood and were skipped"));
                            }
                        }
                        Err(e) => self.notify(&e),
                    }
                }
                self.run_bg(move |b| {
                    let dest: Vec<_> = b.dest_rules().into_iter().map(|v| v.rule).collect();
                    let plan = file.plan(&crate::rules_file::current_of(&b.firewall_apps()), &dest);
                    let (mut done, mut failed) = (0, 0);
                    for (key, direction, verdict) in plan.verdicts {
                        if b.set_verdict(&key, direction, verdict).is_ok() { done += 1 } else { failed += 1 }
                    }
                    for rule in plan.dest {
                        if b.save_dest_rule(rule).is_ok() { done += 1 } else { failed += 1 }
                    }
                    Ok(if failed == 0 { format!("Imported rules: {done} applied") } else { format!("Imported rules: {done} applied, {failed} couldn't be (program not found or protected)") })
                })
            }
            ConfirmAction::BlockWindowsExtras => self.run_bg(|b| b.block_windows_extras().map(|n| format!("Blocked internet access for {n} Windows program(s)"))),
            ConfirmAction::WindowsExtras { group, act } => self.run_bg(move |b| {
                b.windows_extras_act(group, act).map(|n| match (n, act) {
                    (0, _) => "Nothing to change: this group has no rules made by RustWarden.".to_owned(),
                    (n, crate::live::firewall::ExtrasAct::Unblock) => format!("Unblocked {n} Windows component rule(s)"),
                    (n, crate::live::firewall::ExtrasAct::Pause) => format!("Paused {n} Windows component rule(s)"),
                    (n, crate::live::firewall::ExtrasAct::Resume) => format!("Resumed {n} Windows component rule(s)"),
                })
            }),
            ConfirmAction::VirusTotalUpload { key } => self.backend.upload_virustotal(&key),
            ConfirmAction::CleanUp => {
                if self.backend.speedtest_status().running {
                    self.notify("A speed test is running; try again when it has finished.");
                    return;
                }
                cleanup::disable(&mut self.settings);
                if let Err(e) = self.settings.save() {
                    self.notify(&format!("Couldn't save settings: {e}"));
                }
                let new = self.settings.clone();
                // Deleting runs on a worker; the backend then re-reads the settings (and drops the GeoIP database).
                self.run_bg(move |b| {
                    let done = cleanup::run();
                    b.apply_settings(&new);
                    done
                });
            }
            ConfirmAction::ClearHistory => self.run_bg(|b| b.clear_history().map(|()| "Traffic history cleared".into())),
            ConfirmAction::InstallDriver => self.run_bg(|b| b.install_driver().map(|()| "Driver installed".into())),
            ConfirmAction::RemoveDriver => self.run_bg(|b| b.remove_driver().map(|()| "Driver removed".into())),
            ConfirmAction::Service { install } => {
                self.change_service(ctx, install, true, false);
                return;
            }
            ConfirmAction::SwitchToDemo { remove_rules } => {
                if remove_rules {
                    let (backend, slot, ctx) = (self.backend.clone(), self.demo_switch.clone(), ctx.clone());
                    std::thread::spawn(move || {
                        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(backend.restore_defaults());
                        ctx.request_repaint();
                    });
                    return;
                }
                self.switch_mode(ctx, Mode::Demo);
            }
        }
        self.reload_all();
    }

    pub(crate) fn show_window(&mut self, ctx: &egui::Context, visible: bool) {
        self.window_visible = visible;
        ctx.send_viewport_cmd(ViewportCommand::Visible(visible));
        if visible {
            ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(ViewportCommand::Focus);
        }
    }

    /// Handles clicks from the tray icon and its menu.
    fn poll_tray(&mut self, ctx: &egui::Context) {
        use crate::tray::TrayCmd;
        if crate::sys::autostart::SHOW.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.show_window(ctx, true);
        }
        if crate::sys::autostart::STOP_ASK.swap(false, std::sync::atomic::Ordering::SeqCst) {
            if self.settings.tamper_on() {
                self.stop_asked = Some(std::time::Instant::now());
                self.ask_password(Gated::ServiceStop);
                self.show_window(ctx, true);
            } else {
                crate::sys::autostart::answer_stop(true);
            }
        }
        // The service gives up after 5 min; a dialog closed any other way than unlocking is a "no".
        if let Some(at) = self.stop_asked {
            let open = matches!(self.dialog, Some(Dialog::Password { then: Gated::ServiceStop, .. }));
            if open && at.elapsed().as_millis() >= u128::from(crate::sys::autostart::STOP_ASK_MS) {
                self.dialog = None;
            } else if !open {
                crate::sys::autostart::answer_stop(false);
                self.stop_asked = None;
            }
        }
        let cmds: Vec<TrayCmd> = self.tray.as_ref().map(|t| t.rx.try_iter().collect()).unwrap_or_default();
        for cmd in cmds {
            match cmd {
                TrayCmd::Toggle => {
                    // A minimised window is still "visible"; clicking the icon should bring it back.
                    let minimized = ctx.input(|i| i.viewport().minimized.unwrap_or(false));
                    self.show_window(ctx, !self.window_visible || minimized);
                }
                TrayCmd::Menu(x, y) => self.tray_menu = Some(crate::ui::TrayMenu::new(x, y)),
            }
        }
    }

    /// Shows the outcome of a finished snapshot.
    /// Starts, restarts or stops the metrics endpoint to match Settings > Integrations. Dropping the old one stops it.
    pub(crate) fn apply_metrics(&mut self) {
        let want = self.settings.metrics.then_some(self.settings.metrics_port);
        if self.metrics.as_ref().map(|m| m.port()) == want {
            return;
        }
        self.metrics = None;
        if let Some(port) = want {
            let backend = self.backend.clone();
            self.metrics = Some(crate::metrics::Endpoint::start(port, Arc::new(move || backend.metrics_snapshot())));
        }
    }

    fn poll_history_export(&mut self) {
        let done = self.history_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        match done {
            Some(Ok(path)) => self.notify(&format!("Exported to {}", path.display())),
            Some(Err(e)) => self.notify(&format!("Couldn't export: {e}")),
            None => {}
        }
    }

    fn poll_snapshot(&mut self) {
        let done = self.snapshot_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        match done {
            Some(Ok(path)) => self.notify(&format!("Snapshot saved: {}", path.display())),
            Some(Err(e)) => self.notify(&format!("Snapshot failed: {e}")),
            None => {}
        }
    }

    /// The whois icon: Shodan in the browser, or RDAP shown in a dialog, per Settings.
    pub fn open_whois(&mut self, ctx: &egui::Context, ip: &str) {
        if !self.settings.whois_internal {
            crate::sys::open_url(&format!("https://www.shodan.io/host/{ip}"));
            return;
        }
        self.notify("Looking up whois…");
        let (slot, ctx, ip) = (self.whois_result.clone(), ctx.clone(), ip.to_owned());
        std::thread::spawn(move || {
            let text = crate::live::asn::whois(&ip);
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((ip, text));
            ctx.request_repaint();
        });
    }

    /// Installs or removes the service on a thread: it waits on a UAC prompt, which would freeze the window.
    pub(crate) fn change_service(&mut self, ctx: &egui::Context, install: bool, desktop: bool, start_menu: bool) {
        // Installing over a running service (or removing a missing one) is what used to take the app and service down.
        if install == self.service {
            self.notify(if install { "The service is already installed." } else { "The service isn't installed." });
            return;
        }
        let (slot, ctx) = (self.service_result.clone(), ctx.clone());
        std::thread::spawn(move || {
            let r = if install { crate::sys::autostart::install_service(desktop, start_menu) } else { crate::sys::autostart::uninstall_service() };
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((install, r));
            ctx.request_repaint();
        });
    }

    /// Runs a slow firewall call on a thread. Its Ok text is shown as the toast (none when empty), its error too;
    /// `poll_verdicts` then reloads the views.
    pub(crate) fn run_bg(&self, f: impl FnOnce(&dyn Backend) -> Result<String, String> + Send + 'static) {
        let (backend, slot) = (self.backend.clone(), self.verdicts.clone());
        slot.lock().unwrap_or_else(|e| e.into_inner()).0 += 1;
        std::thread::spawn(move || {
            let r = f(&*backend);
            let mut s = slot.lock().unwrap_or_else(|e| e.into_inner());
            s.0 -= 1;
            s.1.push(r);
        });
    }

    fn poll_verdicts(&mut self) {
        let done = std::mem::take(&mut self.verdicts.lock().unwrap_or_else(|e| e.into_inner()).1);
        if done.is_empty() {
            return;
        }
        for r in done {
            let msg = r.unwrap_or_else(|e| e);
            if !msg.is_empty() {
                self.notify(&msg);
            }
        }
        // A clear-history or rules change can touch every view, not only Protect.
        self.reload_protect();
        self.reload_all();
    }

    fn poll_service(&mut self, ctx: &egui::Context) {
        let done = self.service_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some((install, r)) = done
            && self.attempt(r)
        {
            self.service = install;
            self.restart_as_admin(ctx);
        }
        let removed = self.demo_switch.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(r) = removed
            && self.attempt(r)
        {
            self.switch_mode(ctx, Mode::Demo);
        }
    }

    /// Opens Settings, unless the user is already in a dialog (unsaved edits, a confirmation).
    pub(crate) fn open_settings(&mut self) {
        if matches!(self.dialog, None | Some(Dialog::Info { .. })) {
            if self.settings.tamper_on() {
                return self.ask_password(Gated::Settings);
            }
            self.show_settings();
        }
    }

    pub(crate) fn show_settings(&mut self) {
        self.settings_back = None;
        self.dialog = Some(Dialog::Settings(Box::new(self.settings.clone())));
    }

    fn poll_whois(&mut self) {
        let done = self.whois_result.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some((ip, body)) = done {
            let title = format!("Whois {ip}");
            match self.dialog {
                // Never replace a dialog the user is working in (Settings, a confirmation); show the result beside it.
                None | Some(Dialog::Info { .. }) => self.dialog = Some(Dialog::Info { title, body }),
                _ => self.ip_info = Some((title, body)),
            }
        }
    }

    pub fn request_snapshot(&mut self, ctx: &egui::Context) {
        let Some(path) = crate::sys::save_dialog("Save snapshot", &format!("RustWarden-{}.png", crate::clock::file_stamp()), "PNG image", "png") else { return };
        let slot = self.snapshot_result.clone();
        let repaint = ctx.clone();
        let callback = egui::ScreenshotCallback::new(move |image| {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(crate::snapshot::save(&image, path));
            repaint.request_repaint();
        });
        ctx.send_viewport_cmd(ViewportCommand::Screenshot(callback));
    }
}

impl eframe::App for RustWarden {
    /// Runs even while the window is hidden or minimised, when `ui` doesn't. Popups queued then are
    /// created by forcing a frame (see `RequestPaintWhileHidden` below).
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Background work lives here, not in `ui`, so the tray badge, update checks and tray clicks keep working while hidden.
        if self.last_refresh.elapsed() >= REFRESH_EVERY {
            self.reload_all();
        }
        // Keep the clock ticking even when nothing else asks for a repaint.
        ctx.request_repaint_after(REFRESH_EVERY);
        self.follow_windows_accent(ctx);
        self.follow_windows_theme(ctx);
        self.poll_service(ctx);
        self.poll_traffic();
        self.poll_tabs();
        self.poll_pending_blocks();
        self.poll_prompt_timer();
        self.poll_verdicts();
        self.poll_update(ctx);
        self.poll_tray(ctx);
        let unread = self.unread_count() > 0;
        if let Some(tray) = &mut self.tray {
            tray.set_badge(unread);
        }
        // Here rather than in `ui`, which doesn't run while the window is hidden in the tray.
        self.show_asks(ctx);
        self.show_threats(ctx);
        self.show_popups(ctx);
        // eframe skips the frame (and so creating the popup windows) while the main window is covered, minimised or hidden.
        if !(self.asks.is_empty() && self.threats.is_empty() && self.popups.is_empty()) && ctx.input(|i| i.viewport().visible()) == Some(false) {
            ctx.send_viewport_cmd(ViewportCommand::RequestPaintWhileHidden);
        }
        // The cards slide and fade in; the Info panels and menus that open from them just appear.
        for title in ["RustWarden alert", "RustWarden malicious IP warning", "RustWarden connection request"] {
            theme::toast_window(title, true);
        }
        for title in ["RustWarden app info", "RustWarden connection info", crate::ui::toast::FLYOUT_TITLE] {
            theme::toast_window(title, false);
        }
        if let Some(mut shots) = self.shots.take() {
            shots.step(self, ctx);
            self.shots = Some(shots);
        }
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(size) = self.fit.take() {
            fit_window(&ctx, size);
        }
        if self.recenter > 0 {
            self.recenter -= 1;
            if self.recenter == 0
                && let Some(cmd) = ViewportCommand::center_on_screen(&ctx)
            {
                ctx.send_viewport_cmd(cmd);
            }
            ctx.request_repaint();
        }
        theme::hide_caption_buttons(self.hwnd);
        self.remember_window(&ctx);
        self.remember_view();

        self.poll_snapshot();
        self.poll_whois();
        self.poll_alert_check();
        self.poll_history_export();
        self.poll_weekly_report();
        // Close button / taskbar close hide to the tray; only tray Exit really quits.
        // Without a tray icon there would be no way back, so the window just closes (after the password, if set).
        if !self.quitting && ctx.input(|i| i.viewport().close_requested()) {
            if self.tray.is_some() {
                ctx.send_viewport_cmd(ViewportCommand::CancelClose);
                self.show_window(&ctx, false);
            } else if self.settings.tamper_on() {
                ctx.send_viewport_cmd(ViewportCommand::CancelClose);
                self.ask_password(Gated::Exit);
            }
        }

        Panel::top("header").exact_size(snap(&ctx, 64.0)).frame(Frame::NONE.fill(theme::surface())).show(ui, |ui| self.header(ui));

        let broadband = crate::plugins::thinkbroadband::tab_visible(&self.settings);
        let ping = crate::plugins::ping::tab_visible(&self.settings);
        if (self.tab == Tab::Broadband && !broadband) || (self.tab == Tab::Ping && !ping) || (self.tab == Tab::Speedtest && !crate::plugins::speedtest::tab_visible(&self.settings)) {
            self.tab = Tab::Scanner;
        }
        if self.settings.mode == Mode::Live {
            self.status_strip(ui);
        }

        if self.settings.mode == Mode::Live && !self.service && !cfg!(debug_assertions) {
            Panel::bottom("install_service").exact_size(36.0).frame(Frame::NONE.fill(theme::banner_bg()).stroke(Stroke::new(1.0, theme::border()))).show(ui, |ui| {
                crate::ui::row_in(ui, ui.max_rect().shrink2(vec2(16.0, 0.0)), |ui| {
                    ui.label("The RustWarden service isn't installed, so it can't open as administrator without a prompt.");
                    if ui.button("Install service").clicked() && matches!(self.dialog, None | Some(Dialog::Info { .. })) {
                        self.dialog = Some(Dialog::InstallService { desktop: true, start_menu: true });
                    }
                });
            });
        }

        if self.tab == Tab::Traffic {
            let h = ctx.animate_value_with_time(Id::NULL.with("traffic_footer_h"), if self.footer_collapsed() { 44.0 } else { 226.0 }, 0.2);
            Panel::bottom("traffic_footer").exact_size(snap(&ctx, h)).frame(Frame::NONE.fill(theme::surface())).show(ui, |ui| self.traffic_footer(ui));
        }

        if matches!(self.tab, Tab::Scanner | Tab::Broadband | Tab::Ping | Tab::Speedtest | Tab::Dns) {
            Panel::top("network_tabs").exact_size(snap(&ctx, 42.0)).frame(Frame::NONE.fill(theme::surface())).show(ui, |ui| self.network_tabs(ui));
        }
        if matches!(self.tab, Tab::Log | Tab::AlertRules) {
            Panel::top("alert_tabs").exact_size(snap(&ctx, 42.0)).frame(Frame::NONE.fill(theme::surface())).show(ui, |ui| self.alert_tabs(ui));
        }
        if matches!(self.tab, Tab::Protect | Tab::Connections | Tab::DestRules | Tab::Bandwidth) {
            Panel::top("protect_tabs").exact_size(snap(&ctx, 42.0)).frame(Frame::NONE.fill(theme::surface())).show(ui, |ui| self.protect_tabs(ui));
        }

        let bg = match self.tab {
            Tab::Traffic if self.traffic.view == 0 => theme::teal_bg(),
            Tab::Log | Tab::AlertRules | Tab::Protect | Tab::Scanner | Tab::Dns | Tab::Connections | Tab::DestRules | Tab::Bandwidth | Tab::Hardware | Tab::Broadband | Tab::Ping | Tab::Speedtest => {
                theme::panel_bg()
            }
            // Connections falls through to the surface colour, like the DNS log.
            _ => theme::surface(),
        };
        egui::CentralPanel::default().frame(Frame::NONE.fill(bg)).show(ui, |ui| match self.tab {
            Tab::Traffic => self.traffic_tab(ui),
            Tab::Protect => self.protect_tab(ui),
            Tab::Log => self.log_tab(ui),
            Tab::Scanner => self.scanner_tab(ui),
            Tab::Hardware => self.hardware_tab(ui),
            Tab::Broadband => self.broadband_tab(ui),
            Tab::Ping => self.ping_tab(ui),
            Tab::Speedtest => self.speedtest_tab(ui),
            Tab::Dns => self.dns_tab(ui),
            Tab::Connections => self.connections_tab(ui),
            Tab::DestRules => self.dest_rules_tab(ui),
            Tab::Bandwidth => self.bandwidth_tab(ui),
            Tab::AlertRules => self.alert_rules_tab(ui),
        });

        self.show_dialog(&ctx);
        self.show_tbb_login(&ctx);
        self.show_ping_dialogs(&ctx);
        self.show_ip_info(&ctx);
        self.show_tray_menu(&ctx);
        crate::sys::modal::release_unheld();

        let now = self.started.elapsed().as_secs_f64();
        if let Some((msg, until)) = &self.toast {
            if now < *until {
                widgets::toast(&ctx, msg);
                ctx.request_repaint_after(Duration::from_millis(200));
            } else {
                self.toast = None;
            }
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [0.0; 4] // let the acrylic backdrop show through
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        crate::live::geo::QUIT.store(true, std::sync::atomic::Ordering::Relaxed);
        self.backend.exit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tab_has_its_own_key_that_reads_back() {
        let keys: std::collections::HashSet<&str> = Tab::EVERY.iter().map(|t| t.key()).collect();
        assert_eq!(keys.len(), Tab::EVERY.len());
        assert!(Tab::EVERY.iter().all(|t| Tab::from_key(t.key()) == Some(*t)));
        assert!(Tab::from_key("no such tab").is_none());
    }
}
