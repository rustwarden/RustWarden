//! User settings and the on-disk config (`%APPDATA%\RustWarden\config.toml`).
//!
//! The mode is stored here too, so the app reopens in whatever the user last chose.
//! `RUSTWARDEN_MODE=demo|live` overrides it for one run without touching the file.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Whether the optional network driver features (per-app download limits and more) are available.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    /// Everything works without a driver.
    #[default]
    Normal,
    /// Also uses the downloaded WinDivert driver.
    Driver,
}

impl AppMode {
    pub fn label(self) -> &'static str {
        match self {
            AppMode::Normal => "Normal",
            AppMode::Driver => "Driver",
        }
    }
}

/// Bump to show the first-run wizard again to everyone on the next start (after it gains steps).
pub const WIZARD_VERSION: u32 = 1;

/// Which builds the updater follows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    /// Full releases.
    #[default]
    Release,
    /// Alpha builds (pre-releases from the dev branch). Called "playground" before the wizard release.
    #[serde(alias = "playground")]
    Dev,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Fixed placeholder data; always starts, needs no privileges.
    #[default]
    Demo,
    /// Real measurements from this machine.
    Live,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Demo => "DEMO",
            Mode::Live => "LIVE",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "demo" => Some(Mode::Demo),
            "live" => Some(Mode::Live),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Light,
    Dark,
}

impl Theme {
    pub fn label(self) -> &'static str {
        match self {
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }
}

/// Where "AS15169 · Google LLC" comes from; anything but `Off` sends remote addresses to that service.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetInfoSource {
    #[default]
    Off,
    TeamCymru,
    Http,
}

impl NetInfoSource {
    pub const ALL: [NetInfoSource; 3] = [Self::Off, Self::TeamCymru, Self::Http];

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::TeamCymru => "Team Cymru (DNS)",
            Self::Http => "Custom web API",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanPeriod {
    Day,
    Week,
    #[default]
    Month,
}

impl PlanPeriod {
    pub const ALL: [PlanPeriod; 3] = [Self::Day, Self::Week, Self::Month];

    pub fn label(self) -> &'static str {
        match self {
            Self::Day => "Day",
            Self::Week => "Week",
            Self::Month => "Month",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanDirection {
    #[default]
    Total,
    In,
    Out,
}

impl PlanDirection {
    pub const ALL: [PlanDirection; 3] = [Self::Total, Self::In, Self::Out];

    pub fn label(self) -> &'static str {
        match self {
            Self::Total => "Total",
            Self::In => "Download",
            Self::Out => "Upload",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DataPlan {
    pub enabled: bool,
    pub limit_gb: f64,
    pub period: PlanPeriod,
    pub direction: PlanDirection,
    pub exclude_local: bool,
}

impl Default for DataPlan {
    fn default() -> Self {
        Self { enabled: false, limit_gb: 100.0, period: PlanPeriod::Month, direction: PlanDirection::Total, exclude_local: true }
    }
}

/// What a quota does when it is used up. The warning alert fires whatever this is.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaAction {
    /// Only the warning alert and the progress bar.
    None,
    /// Also alert when the whole quota is used.
    #[default]
    AlertOnly,
    /// Alert and block the app until the period resets (per-app quotas only).
    Block,
    /// Alert and cap the app's upload rate (a bandwidth limit) until the period resets (per-app only).
    Throttle,
    /// Cap the upload rate when the warning level is reached, then block at 100% (per-app only).
    ThrottleBlock,
}

impl QuotaAction {
    pub const ALL: [QuotaAction; 5] = [Self::None, Self::AlertOnly, Self::Throttle, Self::ThrottleBlock, Self::Block];

    /// Acts on one program, so a quota on all traffic can't use it.
    pub fn needs_app(self) -> bool {
        matches!(self, Self::Block | Self::Throttle | Self::ThrottleBlock)
    }

    pub fn blocks(self) -> bool {
        matches!(self, Self::Block | Self::ThrottleBlock)
    }

    pub fn throttles(self) -> bool {
        matches!(self, Self::Throttle | Self::ThrottleBlock)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "Nothing at 100%",
            Self::AlertOnly => "Alert at 100%",
            Self::Block => "Block at 100%",
            Self::Throttle => "Limit upload at 100%",
            Self::ThrottleBlock => "Limit upload at warning, block at 100%",
        }
    }
}

/// A data-usage limit for one app, or for all internet traffic, over a calendar period.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Quota {
    /// Stable identity; the saved counters and block state are keyed by it.
    pub id: u32,
    pub enabled: bool,
    /// Key of the app (lower-cased executable path); empty counts all traffic.
    pub app: String,
    /// Display name of the app, kept so the list still reads when the app is gone.
    pub app_name: String,
    pub limit: f64,
    /// `limit` is in GB instead of MB.
    pub gb: bool,
    pub period: PlanPeriod,
    /// Percentage of the limit that raises the warning.
    pub warn_pct: u32,
    pub action: QuotaAction,
    /// Upload cap in Kbps for the throttling actions.
    pub throttle_kbps: u32,
}

impl Default for Quota {
    fn default() -> Self {
        Self { id: 0, enabled: true, app: String::new(), app_name: String::new(), limit: 10.0, gb: true, period: PlanPeriod::Month, warn_pct: 80, action: QuotaAction::AlertOnly, throttle_kbps: 1000 }
    }
}

impl Quota {
    pub fn limit_bytes(&self) -> f64 {
        self.limit * if self.gb { 1024.0 * 1024.0 * 1024.0 } else { 1024.0 * 1024.0 }
    }
}

/// One switch per alert monitor, named like the monitors in `live::monitors`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertSwitches {
    pub first_activity: bool,
    pub app_changed: bool,
    pub internet: bool,
    pub arp: bool,
    pub dns_servers: bool,
    pub proxy: bool,
    pub hosts_file: bool,
    pub new_device: bool,
    pub device_spoof: bool,
    pub device_returned: bool,
    pub remote_session: bool,
    pub data_plan: bool,
    pub away: bool,
    pub firewall_rules: bool,
    pub unlock: bool,
    pub threat: bool,
    pub dns_threat: bool,
    pub thinkbroadband: bool,
    pub user_accounts: bool,
    pub scheduled_tasks: bool,
    pub root_certs: bool,
    pub startup_entries: bool,
    pub new_services: bool,
    pub mic_camera: bool,
    pub quota: bool,
    pub new_listener: bool,
    pub dns_leak: bool,
    pub public_ip: bool,
    pub anomaly_contact: bool,
    pub anomaly_volume: bool,
    pub anomaly_hour: bool,
    pub inbound_scan: bool,
    pub beaconing: bool,
    pub dns_tunnel: bool,
    pub rogue_dhcp: bool,
    pub tls_mismatch: bool,
}

impl Default for AlertSwitches {
    fn default() -> Self {
        Self {
            first_activity: true,
            app_changed: true,
            internet: false,
            arp: true,
            dns_servers: true,
            proxy: true,
            hosts_file: true,
            new_device: true,
            device_spoof: true,
            device_returned: true,
            remote_session: true,
            data_plan: false,
            away: false,
            firewall_rules: true,
            unlock: false,
            threat: true,
            dns_threat: true,
            thinkbroadband: true,
            user_accounts: true,
            scheduled_tasks: true,
            root_certs: true,
            startup_entries: true,
            new_services: true,
            mic_camera: true,
            quota: true,
            new_listener: true,
            dns_leak: true,
            public_ip: true,
            anomaly_contact: true,
            anomaly_volume: true,
            anomaly_hour: true,
            inbound_scan: true,
            beaconing: true,
            dns_tunnel: true,
            rogue_dhcp: true,
            tls_mismatch: true,
        }
    }
}

/// Logs alerts arrive read; Important ones arrive unread and get their own filter.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    #[default]
    Logs,
    Important,
}

impl AlertLevel {
    pub const ALL: [AlertLevel; 2] = [Self::Logs, Self::Important];

    pub fn label(self) -> &'static str {
        match self {
            Self::Logs => "Logs",
            Self::Important => "Important",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Self::Logs => "Logs alerts are read by default.",
            Self::Important => "Important alerts are unread by default and have their own dedicated \"Important\" section.",
        }
    }
}

/// Per-monitor delivery options; the on/off switch stays in `AlertSwitches`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AlertOpts {
    #[serde(default)]
    pub desktop: bool,
    #[serde(default)]
    pub level: AlertLevel,
    /// Also write to the Windows event log (when the master switch `Settings::event_log` is on).
    #[serde(default = "yes")]
    pub event_log: bool,
    /// Also post to the services configured under Integrations > External Notifications.
    #[serde(default = "yes", alias = "discord")]
    pub api: bool,
}

fn yes() -> bool {
    true
}

/// A block set to start later ("Block after N minutes"). Kept in the config so it survives a restart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingBlock {
    pub key: String,
    pub name: String,
    pub directions: Vec<crate::data::Direction>,
    /// Unix seconds when it was set, and when the block takes effect.
    pub started: i64,
    pub due: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub mode: Mode,
    /// `(env override, mode in the file)` while `RUSTWARDEN_MODE` is in force, so `save` keeps the file's own mode.
    #[serde(skip)]
    env_mode: Option<(Mode, Mode)>,
    /// Why the config file was ignored at startup, shown once as a toast.
    #[serde(skip)]
    pub load_error: Option<String>,
    /// The ignored file couldn't be backed up either, so `save` must not replace it.
    #[serde(skip)]
    keep_file: bool,
    /// Show rates and totals in bits instead of bytes.
    pub bits: bool,
    /// Time range of the traffic graph, remembered between runs.
    pub traffic_range: crate::data::TimeRange,
    /// Map labels for countries with connections: the name, the flag, or both.
    pub map_names: bool,
    pub map_flags: bool,
    /// Dots drifting along the map arcs.
    pub map_animate: bool,
    /// Which traffic the map draws: connections that went through, and attempts the firewall blocked.
    pub map_allowed: bool,
    pub map_blocked: bool,
    /// Use the downloaded city database for the map (specific places instead of country centres).
    pub geoip_city: bool,
    /// Re-download the downloaded GeoIP databases every `geo_update_hours`.
    pub geo_auto_update: bool,
    pub geo_update_hours: u32,
    /// Alert types (as shown on the graph pins) hidden from the traffic graph.
    pub graph_hidden: Vec<String>,
    /// Scanner table columns (by title) the user hid.
    pub scanner_hidden: Vec<String>,
    /// Scanner table sort: (column index, ascending); none keeps the scan order.
    pub scanner_sort: Option<(usize, bool)>,
    /// Scanner table column borders (fractions of the table width); empty means the defaults.
    pub scanner_cols: Vec<f32>,
    /// UI scale of the whole app, 1.0 to 1.5 in steps of 0.1.
    pub text_scale: f32,
    pub theme: Theme,
    /// Follow Windows' light/dark app mode live instead of `theme`.
    pub follow_windows_theme: bool,
    /// How much of the Windows 11 acrylic backdrop shines through the surfaces, 0 (opaque) to 1.
    pub acrylic: f32,
    /// The least opaque an alert or Prompt popup may be, 0.5 to 1, so a small popup stays readable at any Acrylic setting.
    pub popup_opacity: f32,
    /// Where alert and Prompt popups appear on the screen.
    pub popup_corner: crate::ui::toast::Corner,
    /// How long an alert popup stays up, in seconds (3 to 60). Prompt prompts stay until answered.
    pub popup_secs: u32,
    /// The most alert popups shown at once (1 to 8); older ones make way for new ones.
    pub popup_max: u32,
    /// Use the Mica backdrop (tinted by the desktop wallpaper colour, like Explorer) instead of grey acrylic.
    pub tint: bool,
    /// Accent colour as `#rrggbb`; empty keeps the built-in look.
    pub accent: String,
    /// Follow the Windows accent colour (and its changes) instead of `accent`.
    pub accent_windows: bool,
    pub retention_days: u32,
    /// Record each program's DNS lookups (ETW, Live mode, administrator); stored locally only.
    pub dns_log: bool,
    /// Tamper protection: hash of the password that guards Settings, Exit and Restart; empty = off.
    #[serde(with = "secret")]
    pub tamper_hash: String,
    /// Edit buffer for a new password in Settings; hashed into `tamper_hash` on OK, never saved.
    #[serde(skip)]
    pub tamper_new: String,
    /// How long the DNS log is kept, in days.
    pub dns_retention_days: u32,
    /// How long Live mode keeps hardware (CPU, memory, disk, GPU) history, in hours.
    pub hardware_history_hours: u32,
    /// Time range of the hardware charts in minutes, remembered between runs.
    pub hardware_range_mins: u32,
    pub data_plan: DataPlan,
    /// Per-app and global data quotas; empty means the feature is idle.
    pub quotas: Vec<Quota>,
    /// What happens to alerts after they are raised (Alerts > Rules); the first matching rule applies.
    pub alert_rules: Vec<crate::alertrules::AlertRule>,
    /// Learn each app's usual countries, networks, hours and daily volume, and alert on departures (needs per-app measurement).
    pub baseline: bool,
    /// Days of history an app's baseline is built from.
    pub baseline_days: u32,
    /// Days after an app first appears during which it only learns and never alerts.
    pub baseline_learn_days: u32,
    /// Hours before the same baseline alert is raised again for the same app and value.
    pub baseline_throttle_hours: u32,
    /// Also learn which networks (AS numbers) a program talks to. Each internet address is sent to the net-info service, so it is off until the user turns it on.
    pub baseline_networks: bool,
    /// Serves Prometheus metrics at 127.0.0.1 only (see metrics.rs). Off until the user turns it on.
    pub metrics: bool,
    pub metrics_port: u16,
    /// Sends the weekly summary through External Notifications (see report.rs). Off until the user turns it on.
    pub report: bool,
    /// 0 = Monday.
    pub report_weekday: u8,
    pub report_hour: u8,
    pub alerts: AlertSwitches,
    /// Overrides of the per-kind defaults, keyed by `AlertKind::key`.
    pub alert_opts: BTreeMap<String, AlertOpts>,
    /// Set only on a new install: alerts the user hasn't configured default to no desktop popup. Older configs
    /// lack it (false) and keep the per-kind popup defaults they had.
    pub quiet_alert_defaults: bool,
    /// Master switch for sending alerts to the Windows event log.
    pub event_log: bool,
    /// Idle time before "while you were away" starts counting, in minutes.
    pub away_after_minutes: u32,
    /// A known device back after this many days away raises the "device returned" alert.
    pub device_return_days: u32,
    pub auto_scan: bool,
    pub auto_scan_minutes: u32,
    /// Adapter (network label) picked on the Network scan tab; also the one auto-scan sweeps.
    pub scan_network: String,
    /// Pause between probes of the sweep, in milliseconds (rate limit).
    pub scan_delay_ms: u32,
    /// Also look for devices on other VLANs/subnets behind the router (ping sweep; slower than ARP).
    pub scan_other_vlans: bool,
    pub firewall_cleanup: bool,
    /// Repeat "Block Windows components" every `block_windows_hours`, to cover programs Windows Update reinstalled.
    pub block_windows_auto: bool,
    pub block_windows_hours: u32,
    pub cleanup_uninstalled_days: u32,
    /// Executable paths hidden from the UI and not recorded (Incognito).
    pub incognito_apps: Vec<String>,
    /// While a VPN adapter is up, don't count the VPN client's own encrypted tunnel traffic (the apps' traffic is already counted).
    pub hide_vpn_traffic: bool,
    /// Show "NT Kernel & System" traffic as one row per service (SMB, NetBIOS, discovery, HTTP.sys...) instead of a single row.
    pub split_kernel: bool,
    /// Extra VPN client executable names (e.g. `myvpn.exe`) besides the built-in list.
    pub vpn_apps: Vec<String>,
    /// Watch for apps talking to many peers they have no name for (peer-to-peer), and list them. Off by default.
    pub p2p_detect: bool,
    /// App keys (executable paths) kept off the network, both ways, whenever no VPN is connected. Only enforced while `p2p_detect` is on.
    pub p2p_block: Vec<String>,
    /// App keys never flagged as peer-to-peer (false positives).
    pub p2p_ignore: Vec<String>,
    /// App keys hidden from the Firewall tab (still recorded, unlike Incognito).
    pub hidden_apps: Vec<String>,
    /// Blocks waiting for their time; a restart keeps them, and one already due fires at startup.
    pub pending_blocks: Vec<PendingBlock>,
    /// Optional MaxMind GeoLite2/GeoIP2 country or city database the user supplies.
    pub geo_db_path: Option<String>,
    pub net_info: NetInfoSource,
    /// Web API for `NetInfoSource::Http`; `{ip}` is replaced by the address.
    #[serde(with = "secret")]
    pub net_info_url: String,
    /// Ask a web service for this PC's public address every few minutes (off by default: it goes online).
    pub public_ip_check: bool,
    /// Adapters the VPN DNS leak check skips: names or parts of names, separated by commas (bridged VM adapters never use the VPN).
    pub dns_leak_ignore: String,
    /// Blocks the internet on the real network cards while a VPN is up or has dropped (see `live::guard`). Off by default.
    pub vpn_kill_switch: bool,
    /// Blocks HTTPS and DNS-over-TLS to well-known public DNS resolvers. Off by default.
    pub block_doh: bool,
    /// Programs (file names, e.g. `chrome.exe`) whose QUIC / HTTP/3 traffic (UDP 443) is blocked, so they use HTTPS over TCP.
    pub quic_fallback: String,
    /// Programs the beaconing alert skips: names or parts of a path, comma separated (see `live::beacon::ignored`).
    pub beacon_ignore: String,
    /// Beaconing: seconds the contacts must span, the largest jitter (fraction of the interval) and the score needed to report.
    pub beacon_min_window: u32,
    pub beacon_max_jitter: f64,
    pub beacon_threshold: i32,
    /// Beaconing: domain suffixes of media / CDN / telemetry hosts that lower the score.
    pub beacon_cdn_suffixes: String,
    /// DHCP servers the second-server alert trusts: addresses, or `interface name=address`, comma separated.
    pub dhcp_trusted: String,
    /// Also alert about a second DHCP server on a virtual adapter (VMware, Hyper-V, VirtualBox, tunnels). Off: those only get a note.
    pub dhcp_virtual_alert: bool,
    /// Service that answers with just the caller's address; must be https.
    pub public_ip_url: String,
    /// Whois icon: show the answer in RustWarden (rdap.org) instead of opening Shodan in the browser.
    pub whois_internal: bool,
    /// Address of the update server script; no automatic checks without it.
    pub update_url: String,
    /// Release (stable) or Dev (alpha) builds.
    pub update_channel: UpdateChannel,
    /// Normal, or Driver (needs the WinDivert driver downloaded in Settings).
    pub app_mode: AppMode,
    /// Driver mode: the line's speed in Mbps (0 = not set). Programs with a priority in Limits / QoS share it: High first, Low last.
    pub line_up_mbps: u32,
    pub line_down_mbps: u32,
    /// Driver mode: read the server name of outgoing TLS connections and DNS answers to name connections and fill the DNS log.
    pub driver_names: bool,
    /// Driver mode: send every program's DNS queries (port 53) to `dns_resolver` instead of wherever they were going.
    pub dns_enforce: bool,
    /// IPv4 address of the resolver `dns_enforce` uses.
    pub dns_resolver: String,
    /// While RustWarden runs one of its own helpers (curl, PowerShell, speedtest), temporarily let that helper online even if a rule blocks it.
    pub allow_helper_tools: bool,
    /// The tab (and sub-tab) the app was on, as `Tab::key`, reopened at the next start.
    pub last_tab: String,
    /// The first-run wizard version the user has seen (0 = never); the wizard opens when this is below `WIZARD_VERSION`.
    pub wizard_seen: u32,
    /// The Traffic tab's view (0 graph, 1 usage, 2 map) when it was last used.
    pub traffic_view: usize,
    /// The main window's last position and size (x, y, width, height in pixels), restored at the next start.
    pub window: Option<[i32; 4]>,
    /// The Traffic tab's totals and timeline card is folded into a compact bar (graph view; other views always fold it).
    pub traffic_footer_collapsed: bool,
    /// Download malicious-IP lists and warn when a program reaches one.
    pub threat_protect: bool,
    /// Block such addresses in the firewall straight away (otherwise only warn).
    pub threat_block: bool,
    /// Leave Prompt's default-deny in force when RustWarden exits, and ask about the programs it stopped meanwhile on the next start.
    pub keep_blocking_closed: bool,
    /// Minutes Prompt stays on before the previous mode returns; 0 is Always.
    pub prompt_minutes: u32,
    pub threat_update_hours: u32,
    /// Blocklist URLs, one per line; each is a text file of addresses.
    #[serde(with = "secret")]
    pub threat_feeds: String,
    /// Download malicious-domain lists and alert when a program looks one up. Off by default: it downloads.
    pub dns_block_alerts: bool,
    pub dns_block_update_hours: u32,
    /// Domain list URLs, one per line; each is a hosts file or a list of names.
    #[serde(with = "secret")]
    pub dns_block_feeds: String,
    /// Alerts are posted to the API services even while snoozed.
    pub api_in_snooze: bool,
    /// What the user decided about each `.wasm` plugin, by plugin id (Settings > Plugins).
    pub plugins: std::collections::BTreeMap<String, PluginState>,
    /// Hidden (beta) built-in plugins are listed: toggled by typing "beta" + Enter in a plugin search box.
    pub beta_plugins: bool,
}

/// The user's decision on one `.wasm` plugin. Its own config and secrets live in a file of their own
/// (`plugins::wasm::manager`), because a plugin's worker saves them and a worker can't write `Settings`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginState {
    pub enabled: bool,
    /// SHA-256 of the file the user approved; a different file must be approved again.
    pub approved_hash: String,
    /// The opt-in permissions the user allowed.
    pub granted: Vec<String>,
    /// A built-in plugin the user uninstalled: hidden from the list and not run until restored.
    pub removed: bool,
}

impl Settings {
    /// Whether to draw dark: Windows' own mode while following it (the chosen theme if Windows doesn't say), else the chosen theme.
    pub fn dark(&self) -> bool {
        if self.follow_windows_theme
            && let Some(dark) = crate::sys::accent::windows_dark()
        {
            return dark;
        }
        self.theme == Theme::Dark
    }

    /// The theme setting as one three-way choice: `None` follows Windows.
    pub fn theme_choice(&self) -> Option<Theme> {
        (!self.follow_windows_theme).then_some(self.theme)
    }

    /// The header theme button's order: follow Windows, then light, then dark.
    pub fn next_theme_choice(&self) -> Option<Theme> {
        match self.theme_choice() {
            None => Some(Theme::Light),
            Some(Theme::Light) => Some(Theme::Dark),
            Some(Theme::Dark) => None,
        }
    }

    pub fn set_theme_choice(&mut self, choice: Option<Theme>) {
        self.follow_windows_theme = choice.is_none();
        if let Some(t) = choice {
            self.theme = t;
        }
    }

    /// The accent colour to draw with: Windows' own, or the chosen one.
    pub fn accent_rgb(&self) -> Option<[u8; 3]> {
        if self.accent_windows {
            return crate::sys::accent::windows_accent();
        }
        parse_hex(&self.accent)
    }
}

/// `#rrggbb` (the `#` optional) as its three bytes.
pub fn parse_hex(s: &str) -> Option<[u8; 3]> {
    let h = s.trim().trim_start_matches('#');
    let v = (h.len() == 6).then(|| u32::from_str_radix(h, 16).ok()).flatten()?;
    Some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Demo,
            env_mode: None,
            load_error: None,
            keep_file: false,
            bits: false,
            traffic_range: crate::data::TimeRange::FiveMinutes,
            map_names: true,
            map_flags: false,
            map_animate: true,
            map_allowed: true,
            map_blocked: true,
            geoip_city: false,
            geo_auto_update: false,
            // DB-IP publishes monthly.
            geo_update_hours: 720,
            graph_hidden: Vec::new(),
            scanner_hidden: Vec::new(),
            scanner_sort: None,
            scanner_cols: Vec::new(),
            text_scale: 1.0,
            theme: Theme::Light,
            last_tab: "traffic".into(),
            wizard_seen: 0,
            traffic_view: 0,
            follow_windows_theme: true,
            acrylic: 0.4,
            popup_opacity: 0.9,
            popup_corner: crate::ui::toast::Corner::default(),
            popup_secs: 8,
            popup_max: 4,
            tint: false,
            accent: String::new(),
            accent_windows: true,
            retention_days: 30,
            dns_log: true,
            tamper_hash: String::new(),
            tamper_new: String::new(),
            dns_retention_days: 7,
            hardware_history_hours: 24,
            hardware_range_mins: 5,
            data_plan: DataPlan::default(),
            quotas: Vec::new(),
            alert_rules: Vec::new(),
            baseline: false,
            baseline_days: 14,
            baseline_learn_days: 7,
            baseline_throttle_hours: 24,
            baseline_networks: false,
            metrics: false,
            metrics_port: 9877,
            report: false,
            report_weekday: 0,
            report_hour: 8,
            alerts: AlertSwitches::default(),
            alert_opts: BTreeMap::new(),
            quiet_alert_defaults: false,
            event_log: false,
            away_after_minutes: 10,
            device_return_days: 14,
            auto_scan: false,
            auto_scan_minutes: 30,
            scan_network: String::new(),
            scan_delay_ms: 20,
            scan_other_vlans: true,
            firewall_cleanup: false,
            block_windows_auto: false,
            block_windows_hours: 24,
            cleanup_uninstalled_days: 7,
            incognito_apps: Vec::new(),
            hide_vpn_traffic: true,
            split_kernel: true,
            vpn_apps: Vec::new(),
            p2p_detect: false,
            p2p_block: Vec::new(),
            p2p_ignore: Vec::new(),
            hidden_apps: Vec::new(),
            pending_blocks: Vec::new(),
            geo_db_path: None,
            net_info: NetInfoSource::Off,
            net_info_url: "https://ipinfo.io/{ip}/json".into(),
            public_ip_check: false,
            dns_leak_ignore: "VMware, VirtualBox, vEthernet".into(),
            vpn_kill_switch: false,
            block_doh: false,
            quic_fallback: String::new(),
            beacon_ignore: String::new(),
            beacon_min_window: 300,
            beacon_max_jitter: 0.08,
            beacon_threshold: 60,
            beacon_cdn_suffixes: crate::live::beacon::DEFAULT_CDN.into(),
            dhcp_trusted: String::new(),
            dhcp_virtual_alert: false,
            public_ip_url: "https://api.ipify.org".into(),
            whois_internal: false,
            update_url: String::new(),
            update_channel: UpdateChannel::Release,
            app_mode: AppMode::Normal,
            line_up_mbps: 0,
            line_down_mbps: 0,
            driver_names: true,
            dns_enforce: false,
            dns_resolver: String::new(),
            allow_helper_tools: true,
            window: None,
            traffic_footer_collapsed: false,
            threat_protect: false,
            threat_block: true,
            keep_blocking_closed: false,
            prompt_minutes: 0,
            api_in_snooze: true,
            plugins: Default::default(),
            beta_plugins: false,
            threat_update_hours: 24,
            threat_feeds: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt
https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
                .into(),
            dns_block_alerts: false,
            dns_block_update_hours: 24,
            dns_block_feeds: DNS_FEED_DEFAULT.into(),
        }
    }
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(|p| PathBuf::from(p).join("RustWarden"))
}

/// `%APPDATA%\RustWarden`, falling back to the working directory.
pub fn config_dir() -> PathBuf {
    env_dir("APPDATA").unwrap_or_else(|| PathBuf::from("."))
}

/// `%LOCALAPPDATA%\RustWarden`: database, icon cache, GeoIP database.
pub fn data_dir() -> PathBuf {
    env_dir("LOCALAPPDATA").unwrap_or_else(|| PathBuf::from("."))
}

/// Where versions before the rename to RustWarden kept what [`admin_dir`] holds now.
pub fn legacy_admin_dir() -> PathBuf {
    admin_dir().with_file_name("RustyWire")
}

/// `Program Files\RustWarden`: only administrators can write here, so elevated code may load or run what it holds.
/// Windows is asked, not `%ProgramFiles%`, because a user can override environment variables.
pub fn admin_dir() -> PathBuf {
    use windows::Win32::UI::Shell::FOLDERID_ProgramFiles;
    PathBuf::from(known_folder(&FOLDERID_ProgramFiles).unwrap_or_else(|| r"C:\Program Files".to_owned())).join("RustWarden")
}

/// A folder Windows names (not an environment variable, which any program running as the user can override).
pub fn known_folder(id: &windows::core::GUID) -> Option<String> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    unsafe {
        SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok().and_then(|p| {
            let path = p.to_string().ok();
            CoTaskMemFree(Some(p.0 as *const _));
            path
        })
    }
}

/// The Windows folder, asked of Windows (`%SystemRoot%` can be overridden by the user's own programs).
pub fn windows_dir() -> String {
    let mut buf = [0u16; 260];
    let n = unsafe { windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(Some(&mut buf)) } as usize;
    if n > 0 && n < buf.len() { String::from_utf16_lossy(&buf[..n]) } else { r"C:\Windows".to_owned() }
}

/// Tokens and webhook addresses are written to the config encrypted for the current Windows user
/// (DPAPI), as `dpapi:<hex>`. A plain value from an older file is read as is and encrypted on the next save.
pub mod secret {
    use serde::{Deserialize, Deserializer, Serializer};

    const PREFIX: &str = "dpapi:";

    pub fn serialize<S: Serializer>(value: &str, s: S) -> Result<S::Ok, S::Error> {
        // Kept as read when it couldn't be decrypted (another user's file), so saving doesn't lose it.
        if value.is_empty() || value.starts_with(PREFIX) {
            return s.serialize_str(value);
        }
        match seal(value) {
            Some(sealed) => s.serialize_str(&sealed),
            // Never written as plain text: the save fails (and says so) until Windows can encrypt it.
            None => Err(serde::ser::Error::custom("Windows couldn't encrypt a saved token or webhook address, so nothing was written")),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        Ok(open(&String::deserialize(d)?))
    }

    /// `dpapi:<hex>` for `value`, encrypted for the current Windows user.
    pub fn seal(value: &str) -> Option<String> {
        crate::sys::dpapi::protect(value.as_bytes()).map(|sealed| format!("{PREFIX}{}", sealed.iter().map(|b| format!("{b:02x}")).collect::<String>()))
    }

    /// The text behind a stored value: decrypted when it is `dpapi:<hex>`, else as it is.
    pub fn open(raw: &str) -> String {
        let Some(hex) = raw.strip_prefix(PREFIX) else { return raw.to_owned() };
        let bytes: Option<Vec<u8>> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect();
        bytes.and_then(|b| crate::sys::dpapi::unprotect(&b)).and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| raw.to_owned())
    }
}

/// Which plugins are on, what file the user approved and which permissions they granted, as an elevated run keeps it in
/// `Program Files\RustWarden`. config.toml is writable by any program running as the user; without this copy such a
/// program could switch on a built-in plugin (which then runs with every permission it asks for) in the elevated window.
#[derive(Serialize, Deserialize, Default)]
struct PluginsCopy {
    plugins: BTreeMap<String, PluginState>,
}

fn plugins_copy_path() -> PathBuf {
    admin_dir().join("plugins.toml")
}

fn read_plugins_copy(path: &std::path::Path) -> Option<BTreeMap<String, PluginState>> {
    toml::from_str::<PluginsCopy>(&std::fs::read_to_string(path).ok()?).ok().map(|c| c.plugins)
}

fn write_plugins_copy(path: &std::path::Path, plugins: &BTreeMap<String, PluginState>) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text = toml::to_string_pretty(&PluginsCopy { plugins: plugins.clone() }).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// Keyless mirror of the abuse.ch URLhaus hostfile, which now needs an Auth-Key.
const DNS_FEED_DEFAULT: &str = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt";
const DNS_FEED_RETIRED: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

impl Settings {
    pub fn tamper_on(&self) -> bool {
        !self.tamper_hash.is_empty()
    }

    /// The database the map's backend opens: the city file when enabled and downloaded, else the country one.
    pub fn geo_path(&self) -> Option<String> {
        let city = crate::live::geo::city_db_path();
        (self.geoip_city && city.exists()).then(|| city.to_string_lossy().into_owned()).or_else(|| self.geo_db_path.clone())
    }

    /// Reads the config (defaults when missing or broken), then applies `RUSTWARDEN_MODE`.
    pub fn load() -> Self {
        let mut s = Self::load_from(&config_path());
        // The old integration fields are no longer in `Settings`; carry their values into plugins before a save drops them.
        if let Some(raw) = std::fs::read_to_string(config_path()).ok().and_then(|t| toml::from_str::<toml::Table>(&t).ok()) {
            crate::plugins::legacy::run(&mut s, &raw);
        }
        if let Some(mode) = std::env::var("RUSTWARDEN_MODE").ok().filter(|_| !crate::sys::from_service()).and_then(|v| Mode::parse(&v)) {
            s.env_mode = Some((mode, s.mode));
            s.mode = mode;
        }
        // config.toml is writable by any program running as the user, so the copy an elevated run keeps where only
        // administrators can write wins: deleting the password line, or replacing it with a hash of a password the
        // other program knows, must not unlock Settings or Exit.
        let kept = crate::tamper::recall();
        if !kept.is_empty() {
            s.tamper_hash = kept;
        }
        // The same for what plugins may run and with which permissions: enabling one is a decision config.toml can't make for an elevated run.
        // The first elevated run takes the file's decisions as they are; after that the admin-only copy rules.
        if !cfg!(test) && crate::sys::is_elevated() {
            match read_plugins_copy(&plugins_copy_path()) {
                Some(kept) => s.plugins = kept,
                None => {
                    let _ = write_plugins_copy(&plugins_copy_path(), &s.plugins);
                }
            }
        }
        s.sanitize();
        s
    }

    /// Defaults when `path` is missing. A file that exists but can't be read or parsed is copied
    /// to `.toml.bak` first, so the next save can't destroy the only record of the user's settings.
    fn load_from(path: &std::path::Path) -> Self {
        let read = std::fs::read_to_string(path);
        match read.as_ref().map(|t| Self::from_toml(t)) {
            Ok(Some(s)) => s,
            // A new install starts with every alert off, so a new user isn't flooded; the wizard offers them.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut s = Self { quiet_alert_defaults: true, ..Self::default() };
                for kind in crate::live::alerts::AlertKind::ALL {
                    *kind.switch_mut(&mut s.alerts) = false;
                }
                s
            }
            bad => {
                let why = match bad {
                    Err(e) => e.to_string(),
                    _ => "it has a value this version doesn't understand".into(),
                };
                let backed_up = std::fs::copy(path, path.with_extension("toml.bak")).is_ok();
                let what = if backed_up { "a copy was saved as config.toml.bak" } else { "the file will be left untouched" };
                Self { load_error: Some(format!("Settings couldn't be loaded ({why}), using defaults; {what}.")), keep_file: !backed_up, ..Self::default() }
            }
        }
    }

    /// These settings as exported text: everything except the password hash (it must not travel in a file).
    pub fn to_export(&self) -> String {
        toml::to_string_pretty(&Self { tamper_hash: String::new(), window: None, ..self.clone() }).unwrap_or_default()
    }

    /// `self` with the values from exported `text` laid over it, one key at a time, so a key this version
    /// can't read (older or newer file) is skipped instead of failing the whole import, and a key the file
    /// lacks keeps its current value. Returns the result and how many keys were skipped.
    /// The mode, window position and password stay as they are here.
    pub fn merged_from(&self, text: &str) -> Result<(Self, usize), String> {
        let theirs: toml::Table = toml::from_str(text).map_err(|e| format!("The settings in this file can't be read: {e}"))?;
        let mut table = toml::Table::try_from(self).map_err(|e| e.to_string())?;
        let mut skipped = 0;
        for (key, value) in theirs {
            if matches!(key.as_str(), "mode" | "window" | "tamper_hash") {
                continue;
            }
            // A secret sealed for another Windows user or PC can't be opened here; importing it would replace a working value with noise.
            if let toml::Value::String(s) = &value
                && s.starts_with("dpapi:")
                && secret::open(s).starts_with("dpapi:")
            {
                skipped += 1;
                continue;
            }
            let old = table.insert(key.clone(), value);
            if toml::Value::Table(table.clone()).try_into::<Self>().is_err() {
                skipped += 1;
                match old {
                    Some(old) => table.insert(key, old),
                    None => table.remove(&key),
                };
            }
        }
        let mut merged: Self = toml::Value::Table(table).try_into().map_err(|e| format!("The settings in this file can't be read: {e}"))?;
        merged.sanitize();
        Ok((merged, skipped))
    }

    pub fn from_toml(text: &str) -> Option<Self> {
        toml::from_str(text).ok()
    }

    /// Ranges for every quota, unique non-zero ids, and no Block on the global quota (it has no app to block).
    fn sanitize_alert_rules(&mut self) {
        use crate::alertrules::{ALL_DAYS, MAX_RULES};
        self.alert_rules.truncate(MAX_RULES);
        let mut seen = std::collections::HashSet::new();
        let mut next = self.alert_rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        for r in &mut self.alert_rules {
            r.from = r.from.min(1439);
            r.to = r.to.min(1439);
            r.days &= ALL_DAYS;
            r.limit_min = r.limit_min.clamp(1, 10_080);
            if r.id == 0 || !seen.insert(r.id) {
                r.id = next;
                seen.insert(next);
                next += 1;
            }
        }
    }

    fn sanitize_quotas(&mut self) {
        let mut seen = std::collections::HashSet::new();
        let mut next = self.quotas.iter().map(|q| q.id).max().unwrap_or(0) + 1;
        for q in &mut self.quotas {
            if !q.limit.is_finite() {
                q.limit = 1.0;
            }
            q.limit = q.limit.clamp(0.001, 1_000_000_000.0);
            q.warn_pct = q.warn_pct.clamp(1, 99);
            if q.app.is_empty() && q.action.needs_app() {
                q.action = QuotaAction::AlertOnly;
            }
            q.throttle_kbps = q.throttle_kbps.clamp(crate::qos::MIN_KBPS, crate::qos::MAX_KBPS);
            if q.id == 0 || !seen.insert(q.id) {
                q.id = next;
                next += 1;
                seen.insert(q.id);
            }
        }
    }

    /// An id no quota uses yet.
    pub fn next_quota_id(&self) -> u32 {
        self.quotas.iter().map(|q| q.id).max().unwrap_or(0) + 1
    }

    /// Keeps hand-edited values in a range the rest of the code can rely on.
    /// abuse.ch retired the keyless URLhaus hostfile (410 Gone); swap it for the mirror, keeping any other feeds.
    fn migrate_dns_feeds(&mut self) {
        if !self.dns_block_feeds.contains(DNS_FEED_RETIRED) {
            return;
        }
        let mut out: Vec<&str> = Vec::new();
        for line in self.dns_block_feeds.lines() {
            let line = if line.trim().trim_end_matches('/') == DNS_FEED_RETIRED.trim_end_matches('/') { DNS_FEED_DEFAULT } else { line };
            if !out.contains(&line) {
                out.push(line);
            }
        }
        self.dns_block_feeds = out.join(
            "
",
        );
    }

    pub fn sanitize(&mut self) {
        // Whole 0.1 steps from 1.0 to 1.5, matching the Settings slider.
        if !self.text_scale.is_finite() {
            self.text_scale = 1.0;
        }
        if !self.acrylic.is_finite() {
            self.acrylic = 0.4;
        }
        self.popup_opacity = if self.popup_opacity.is_finite() { self.popup_opacity.clamp(0.5, 1.0) } else { 0.9 };
        self.popup_secs = self.popup_secs.clamp(3, 60);
        self.popup_max = self.popup_max.clamp(1, 8);
        self.text_scale = ((self.text_scale.clamp(1.0, 1.5) * 10.0).round() / 10.0).clamp(1.0, 1.5);
        self.acrylic = self.acrylic.clamp(0.0, 1.0);
        self.retention_days = self.retention_days.clamp(1, 3650);
        self.dns_retention_days = self.dns_retention_days.clamp(1, 365);
        self.hardware_history_hours = self.hardware_history_hours.clamp(1, 24 * 30);
        self.hardware_range_mins = self.hardware_range_mins.clamp(5, 24 * 60 * 30);
        self.auto_scan_minutes = self.auto_scan_minutes.clamp(1, 24 * 60);
        self.scan_delay_ms = self.scan_delay_ms.clamp(1, 1000);
        self.away_after_minutes = self.away_after_minutes.clamp(1, 24 * 60);
        self.device_return_days = self.device_return_days.clamp(1, 365);
        self.threat_update_hours = self.threat_update_hours.clamp(1, 24 * 30);
        self.dns_block_update_hours = self.dns_block_update_hours.clamp(1, 24 * 30);
        self.geo_update_hours = self.geo_update_hours.clamp(1, 24 * 30);
        self.data_plan.limit_gb = self.data_plan.limit_gb.max(0.1);
        self.sanitize_quotas();
        self.sanitize_alert_rules();
        self.baseline_days = self.baseline_days.clamp(3, 365);
        self.baseline_learn_days = self.baseline_learn_days.clamp(1, self.baseline_days);
        self.baseline_throttle_hours = self.baseline_throttle_hours.clamp(1, 24 * 30);
        self.block_windows_hours = self.block_windows_hours.clamp(1, 24 * 30);
        self.cleanup_uninstalled_days = self.cleanup_uninstalled_days.clamp(1, 3650);
        // Column edges from 0 to 1, strictly increasing; anything else would give zero-width columns.
        let edges_ok = self.scanner_cols.len() == 13 && self.scanner_cols[0] == 0.0 && self.scanner_cols[12] == 1.0 && self.scanner_cols.windows(2).all(|w| w[0] < w[1]);
        if !self.scanner_cols.is_empty() && !edges_ok {
            self.scanner_cols.clear();
        }
        // Ports below 1024 need administrator rights to bind.
        self.metrics_port = self.metrics_port.max(1024);
        self.report_weekday = self.report_weekday.min(6);
        self.report_hour = self.report_hour.min(23);
        self.migrate_dns_feeds();
    }

    /// A mode picked in the UI; it ends the `RUSTWARDEN_MODE` override, so it is saved even when it matches it.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.env_mode = None;
    }

    pub fn save(&self) -> std::io::Result<()> {
        if self.keep_file {
            return Err(std::io::Error::other("config.toml couldn't be read or backed up, so it isn't overwritten"));
        }
        let path = config_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut out = self.clone();
        if let Some((env, file)) = self.env_mode {
            // `RUSTWARDEN_MODE` is for one run; only a mode picked in the UI is written.
            if self.mode == env {
                out.mode = file;
            }
        }
        let text = toml::to_string_pretty(&out).map_err(std::io::Error::other)?;
        crate::tamper::remember(&self.tamper_hash);
        if !cfg!(test) && crate::sys::is_elevated() {
            let _ = write_plugins_copy(&plugins_copy_path(), &self.plugins);
        }
        // Write beside the file and rename, so a crash mid-write can't leave a truncated config.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn new_install_has_alerts_off_and_playground_reads_as_dev() {
        let dir = std::env::temp_dir().join("rustwarden-test-missing-config");
        let s = super::Settings::load_from(&dir.join("config.toml"));
        assert!(crate::live::alerts::AlertKind::ALL.iter().all(|k| !k.enabled(&s.alerts)));
        assert_eq!(s.wizard_seen, 0);
        let old = super::Settings::from_toml("update_channel = \"playground\"").unwrap();
        assert_eq!(old.update_channel, super::UpdateChannel::Dev);
    }

    use super::*;

    #[test]
    fn import_keeps_what_the_file_lacks_and_skips_what_it_cannot_read() {
        let mine = Settings { retention_days: 10, text_scale: 1.2, ..Settings::default() };
        let (m, skipped) = mine.merged_from("retention_days = 99\nfuture_option = true\ntext_scale = \"big\"\nmode = \"live\"\ntamper_hash = \"x\"").unwrap();
        assert_eq!(m.retention_days, 99);
        assert_eq!(m.text_scale, 1.2);
        assert_eq!(m.mode, mine.mode);
        assert!(m.tamper_hash.is_empty());
        // `future_option` is ignored by the struct itself; only the unreadable scale counts as skipped.
        assert_eq!(skipped, 1);
        assert!(mine.merged_from("not = [valid").is_err());
    }

    #[test]
    fn export_round_trips_and_leaves_out_the_password() {
        let s = Settings { retention_days: 77, tamper_hash: "secret".into(), ..Settings::default() };
        let (back, skipped) = Settings::default().merged_from(&s.to_export()).unwrap();
        assert_eq!((back.retention_days, skipped), (77, 0));
        assert!(!s.to_export().contains("secret"));
    }

    #[test]
    fn plugin_decisions_survive_the_admin_copy_and_junk_reads_as_none() {
        let dir = std::env::temp_dir().join(format!("rustwarden-plugins-copy-{}", std::process::id()));
        let path = dir.join("plugins.toml");
        let mut plugins = BTreeMap::new();
        plugins.insert("ping".to_owned(), PluginState { enabled: true, approved_hash: "ab".into(), granted: vec!["ping".into()], removed: false });
        plugins.insert("old".to_owned(), PluginState { removed: true, ..Default::default() });
        assert!(read_plugins_copy(&path).is_none(), "no file yet");
        write_plugins_copy(&path, &plugins).unwrap();
        assert_eq!(read_plugins_copy(&path), Some(plugins));
        std::fs::write(&path, "plugins = 5").unwrap();
        assert!(read_plugins_copy(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_secret_sealed_for_someone_else_is_not_imported() {
        let mine = Settings::default();
        let (m, skipped) = mine.merged_from("threat_feeds = \"dpapi:00\"\nretention_days = 5\n").unwrap();
        assert_eq!((m.threat_feeds.as_str(), m.retention_days, skipped), (mine.threat_feeds.as_str(), 5, 1));
    }

    #[test]
    fn pending_blocks_survive_a_save_and_load() {
        let mut s = Settings::default();
        s.pending_blocks.push(PendingBlock { key: r"c:.exe".into(), name: "a".into(), directions: vec![crate::data::Direction::In, crate::data::Direction::Out], started: 100, due: 1900 });
        let back: Settings = toml::from_str(&toml::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.pending_blocks, s.pending_blocks);
    }

    #[test]
    fn default_mode_is_demo() {
        assert_eq!(Settings::default().mode, Mode::Demo);
    }

    #[test]
    fn alert_rules_are_sanitized_and_survive_a_save() {
        use crate::alertrules::AlertRule;
        let mut s = Settings {
            alert_rules: vec![
                AlertRule { id: 0, from: 5000, days: 0xff, limit_min: 0, ..AlertRule::default() },
                AlertRule { id: 3, ..AlertRule::default() },
                AlertRule { id: 3, ..AlertRule::default() },
            ],
            ..Settings::default()
        };
        s.sanitize();
        let ids: std::collections::HashSet<u32> = s.alert_rules.iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), 3);
        assert!(!ids.contains(&0));
        assert_eq!((s.alert_rules[0].from, s.alert_rules[0].days, s.alert_rules[0].limit_min), (1439, 0x7f, 1));
        let text = toml::to_string(&s).unwrap();
        let back: Settings = toml::from_str(&text).unwrap();
        assert_eq!(back.alert_rules, s.alert_rules);
    }

    #[test]
    fn theme_button_cycles_system_light_dark() {
        let mut s = Settings::default();
        let mut seen = vec![s.theme_choice()];
        for _ in 0..3 {
            s.set_theme_choice(s.next_theme_choice());
            seen.push(s.theme_choice());
        }
        assert_eq!(seen, [None, Some(Theme::Light), Some(Theme::Dark), None]);
    }

    #[test]
    fn theme_choice_is_system_light_or_dark() {
        let mut s = Settings::default();
        assert_eq!(s.theme_choice(), None);
        s.set_theme_choice(Some(Theme::Dark));
        assert_eq!(s.theme_choice(), Some(Theme::Dark));
        assert!(s.dark());
        s.set_theme_choice(None);
        assert_eq!(s.theme_choice(), None);
        // Going back to System remembers the last fixed theme.
        assert_eq!(s.theme, Theme::Dark);
    }

    #[test]
    fn theme_follows_windows_by_default_and_the_choice_otherwise() {
        let mut s = Settings::default();
        assert!(s.follow_windows_theme && s.accent_windows);
        s.follow_windows_theme = false;
        s.theme = Theme::Dark;
        assert!(s.dark());
        s.theme = Theme::Light;
        assert!(!s.dark());
        // An old config without the key follows Windows.
        let old: Settings = toml::from_str("theme = \"dark\"").unwrap();
        assert!(old.follow_windows_theme);
    }

    #[test]
    fn app_mode_defaults_to_normal_and_round_trips() {
        assert_eq!(toml::from_str::<Settings>("theme = \"dark\"").unwrap().app_mode, AppMode::Normal);
        let s = Settings { app_mode: AppMode::Driver, ..Settings::default() };
        assert_eq!(toml::from_str::<Settings>(&toml::to_string(&s).unwrap()).unwrap().app_mode, AppMode::Driver);
    }

    #[test]
    fn quotas_are_sanitized() {
        let q = |id, app: &str, action| Quota { id, app: app.into(), action, limit: f64::NAN, warn_pct: 0, ..Quota::default() };
        let mut s = Settings { quotas: vec![q(0, "", QuotaAction::Block), q(2, "a", QuotaAction::Block), q(2, "b", QuotaAction::None)], ..Settings::default() };
        s.sanitize();
        assert_eq!(s.quotas[0].action, QuotaAction::AlertOnly); // global can't block
        assert_eq!(s.quotas[1].action, QuotaAction::Block);
        let mut t = Settings {
            quotas: vec![
                Quota { id: 1, app: String::new(), action: QuotaAction::ThrottleBlock, throttle_kbps: 1, ..Quota::default() },
                Quota { id: 2, app: "a".into(), action: QuotaAction::Throttle, throttle_kbps: u32::MAX, ..Quota::default() },
            ],
            ..Settings::default()
        };
        t.sanitize();
        assert_eq!(t.quotas[0].action, QuotaAction::AlertOnly);
        assert_eq!((t.quotas[0].throttle_kbps, t.quotas[1].throttle_kbps, t.quotas[1].action), (crate::qos::MIN_KBPS, crate::qos::MAX_KBPS, QuotaAction::Throttle));
        assert!(s.quotas.iter().all(|q| q.limit == 1.0 && q.warn_pct == 1));
        let mut ids: Vec<u32> = s.quotas.iter().map(|q| q.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3);
        assert!(!ids.contains(&0));
        assert_eq!(Quota { limit: 2.0, gb: false, ..Quota::default() }.limit_bytes(), 2.0 * 1024.0 * 1024.0);
    }

    #[test]
    fn baseline_settings_are_clamped() {
        let mut s = Settings { baseline_days: 1, baseline_learn_days: 99, baseline_throttle_hours: 0, ..Settings::default() };
        s.sanitize();
        assert_eq!((s.baseline_days, s.baseline_learn_days, s.baseline_throttle_hours), (3, 3, 1));
        assert!(!Settings::default().baseline);
        assert!(!Settings::default().baseline_networks);
        assert!(!Settings::default().metrics);
        let mut low = Settings { metrics_port: 80, ..Settings::default() };
        low.sanitize();
        assert_eq!(low.metrics_port, 1024);
        assert!(!Settings::default().report);
        // Anything that downloads is opt-in.
        assert!(!Settings::default().threat_protect);
        assert!(!Settings::default().geo_auto_update);
        let mut late = Settings { report_weekday: 9, report_hour: 40, ..Settings::default() };
        late.sanitize();
        assert_eq!((late.report_weekday, late.report_hour), (6, 23));
    }

    #[test]
    fn sanitize_fixes_hand_edited_values() {
        let mut s = Settings { cleanup_uninstalled_days: 0, scanner_cols: vec![2.0; 13], ..Default::default() };
        s.sanitize();
        assert_eq!(s.cleanup_uninstalled_days, 1);
        assert!(s.scanner_cols.is_empty());
        s.scanner_cols = crate::ui::scanner::DEFAULT_COLS.to_vec();
        s.sanitize();
        assert_eq!(s.scanner_cols.len(), 13);
    }

    #[test]
    fn mode_round_trips_through_toml() {
        let mut s = Settings { mode: Mode::Live, ..Settings::default() };
        s.retention_days = 7;
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(text.contains("mode = \"live\""));
        let back = Settings::from_toml(&text).unwrap();
        assert_eq!(back.mode, Mode::Live);
        assert_eq!(back.retention_days, 7);
    }

    #[test]
    fn partial_and_broken_files_fall_back() {
        assert_eq!(Settings::from_toml("mode = \"live\"").unwrap().retention_days, 30);
        assert!(Settings::from_toml("mode = [").is_none());
        // An alert entry missing a field no longer sinks the whole file.
        assert!(
            Settings::from_toml(
                "[alert_opts.proxy]
desktop = true"
            )
            .is_some()
        );
    }

    #[test]
    fn unreadable_file_is_backed_up_not_lost() {
        let dir = std::env::temp_dir().join(format!("rustwarden-settings-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        assert!(Settings::load_from(&path).load_error.is_none(), "a missing file is not an error");
        std::fs::write(&path, b"mode = \"live\"\n# Jos\xe9\n").unwrap(); // ANSI, not UTF-8
        let s = Settings::load_from(&path);
        assert!(s.load_error.is_some());
        assert!(path.with_extension("toml.bak").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn secrets_are_encrypted_in_the_file() {
        let s = Settings {
            // Feed and lookup URLs often carry a key in the query.
            threat_feeds: "https://feeds.example/ips.txt?key=feedkey".into(),
            dns_block_feeds: "https://feeds.example/hosts.txt?key=dnskey".into(),
            net_info_url: "https://info.example/{ip}?token=infotoken".into(),
            ..Settings::default()
        };
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(text.contains("dpapi:"));
        assert!(!text.contains("feedkey") && !text.contains("dnskey") && !text.contains("infotoken"));
        let back = Settings::from_toml(&text).unwrap();
        assert_eq!((back.threat_feeds, back.dns_block_feeds, back.net_info_url), (s.threat_feeds, s.dns_block_feeds, s.net_info_url));
        // Older plain files still load; a value that can't be decrypted is kept as it was.
        assert_eq!(Settings::from_toml("threat_feeds = \"plain\"").unwrap().threat_feeds, "plain");
        assert_eq!(Settings::from_toml("threat_feeds = \"dpapi:00ff\"").unwrap().threat_feeds, "dpapi:00ff");
    }

    #[test]
    fn popup_settings_default_clamp_and_load_from_old_files() {
        let s = Settings::default();
        assert_eq!((s.popup_corner, s.popup_secs, s.popup_max), (crate::ui::toast::Corner::BottomRight, 8, 4));
        let mut s = Settings { popup_secs: 0, popup_max: 99, ..Settings::default() };
        s.sanitize();
        assert_eq!((s.popup_secs, s.popup_max), (3, 8));
        // A settings file from before these existed still loads, with the defaults.
        let old: Settings = toml::from_str("text_scale = 1.0").unwrap();
        assert_eq!((old.popup_secs, old.popup_max), (8, 4));
        // The corner survives a save and load.
        let s = Settings { popup_corner: crate::ui::toast::Corner::TopLeft, ..Settings::default() };
        let back: Settings = toml::from_str(&toml::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.popup_corner, crate::ui::toast::Corner::TopLeft);
    }

    #[test]
    fn nan_scale_is_reset() {
        let mut s = Settings { text_scale: f32::NAN, acrylic: f32::NAN, popup_opacity: f32::NAN, ..Settings::default() };
        s.sanitize();
        assert_eq!((s.text_scale, s.acrylic, s.popup_opacity), (1.0, 0.4, 0.9));
        s.popup_opacity = 0.1;
        s.sanitize();
        assert_eq!(s.popup_opacity, 0.5);
    }

    #[test]
    fn mode_parse_is_forgiving() {
        assert_eq!(Mode::parse(" LIVE "), Some(Mode::Live));
        assert_eq!(Mode::parse("demo"), Some(Mode::Demo));
        assert_eq!(Mode::parse("x"), None);
    }

    #[test]
    fn sanitize_clamps() {
        let mut s = Settings { text_scale: 9.0, retention_days: 0, ..Settings::default() };
        s.sanitize();
        assert_eq!(s.text_scale, 1.5);
        s.text_scale = 1.33;
        s.sanitize();
        assert_eq!(s.text_scale, 1.3);
        assert_eq!(s.retention_days, 1);
    }

    #[test]
    fn accent_hex_parses() {
        assert_eq!(parse_hex("#0078d7"), Some([0, 0x78, 0xd7]));
        assert_eq!(parse_hex("ff8c00"), Some([0xff, 0x8c, 0]));
        assert_eq!(parse_hex(""), None);
        assert_eq!(parse_hex("#12345"), None);
        assert_eq!(parse_hex("#zzzzzz"), None);
    }

    #[test]
    fn retired_dns_feed_is_migrated() {
        let mut s = Settings {
            dns_block_feeds: format!(
                "https://example.com/a.txt
{DNS_FEED_RETIRED}
{DNS_FEED_DEFAULT}"
            ),
            ..Settings::default()
        };
        s.sanitize();
        assert_eq!(
            s.dns_block_feeds,
            format!(
                "https://example.com/a.txt
{DNS_FEED_DEFAULT}"
            )
        );
    }

    #[test]
    fn split_kernel_is_on_by_default() {
        assert!(Settings::from_toml("mode = \"live\"").unwrap().split_kernel);
        assert!(!Settings::from_toml("split_kernel = false").unwrap().split_kernel);
    }

    #[test]
    fn dns_log_defaults_and_clamp() {
        let mut s = Settings::from_toml("mode = \"live\"").unwrap();
        assert!(s.dns_log);
        assert_eq!(s.dns_retention_days, 7);
        s.dns_retention_days = 0;
        s.sanitize();
        assert_eq!(s.dns_retention_days, 1);
        s.dns_retention_days = 9999;
        s.sanitize();
        assert_eq!(s.dns_retention_days, 365);
    }

    #[test]
    fn domain_alerts_are_off_until_enabled() {
        let mut s = Settings::from_toml("mode = \"live\"").unwrap();
        assert!(!s.dns_block_alerts, "it downloads lists, so it starts off");
        assert!(s.alerts.dns_threat);
        assert!(s.dns_block_feeds.starts_with("https://"));
        s.dns_block_update_hours = 0;
        s.sanitize();
        assert_eq!(s.dns_block_update_hours, 1);
    }
}
