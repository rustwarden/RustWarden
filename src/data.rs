//! Data model and the backend seam.
//!
//! The UI only talks to [`Backend`]. [`crate::demo::MockBackend`] returns fixed
//! placeholder data shaped like real captures; [`crate::live::LiveBackend`]
//! measures this machine.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Country {
    Local,
    UnitedKingdom,
    Ireland,
    Germany,
    Sweden,
    UnitedStates,
    France,
    Netherlands,
    /// Any other country, by ISO 3166 alpha-2 code (Live mode, from the GeoIP database).
    Iso([u8; 2]),
    Other,
}

impl Country {
    pub fn name(self) -> &'static str {
        match self {
            Country::Local => "Local Network",
            Country::UnitedKingdom => "United Kingdom",
            Country::Ireland => "Ireland",
            Country::Germany => "Germany",
            Country::Sweden => "Sweden",
            Country::UnitedStates => "United States",
            Country::France => "France",
            Country::Netherlands => "Netherlands",
            Country::Iso(code) => crate::countries::by_a2(code).map_or("Other", |e| e.name),
            Country::Other => "Other",
        }
    }

    /// Country for a GeoIP alpha-2 code; the few with hand-drawn flags map to their own variant.
    pub fn from_a2(code: [u8; 2]) -> Self {
        match &code {
            b"GB" => Country::UnitedKingdom,
            b"IE" => Country::Ireland,
            b"DE" => Country::Germany,
            b"SE" => Country::Sweden,
            b"US" => Country::UnitedStates,
            b"FR" => Country::France,
            b"NL" => Country::Netherlands,
            _ => Country::Iso(code),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeRange {
    OneMinute,
    FiveMinutes,
    TenMinutes,
    FifteenMinutes,
    ThirtyMinutes,
    OneHour,
    ThreeHours,
    Day,
}

impl TimeRange {
    pub fn label(self) -> &'static str {
        match self {
            Self::OneMinute => "1 Minute",
            Self::FiveMinutes => "5 Minutes",
            Self::TenMinutes => "10 Minutes",
            Self::FifteenMinutes => "15 Minutes",
            Self::ThirtyMinutes => "30 Minutes",
            Self::OneHour => "1 Hour",
            Self::ThreeHours => "3 Hours",
            Self::Day => "24 Hours",
        }
    }

    pub fn minutes(self) -> f32 {
        match self {
            Self::OneMinute => 1.0,
            Self::FiveMinutes => 5.0,
            Self::TenMinutes => 10.0,
            Self::FifteenMinutes => 15.0,
            Self::ThirtyMinutes => 30.0,
            Self::OneHour => 60.0,
            Self::ThreeHours => 180.0,
            Self::Day => 1440.0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Scope {
    #[default]
    Both,
    Wan,
    Lan,
}

impl Scope {
    pub const ALL: [Scope; 3] = [Self::Both, Self::Wan, Self::Lan];

    pub fn label(self) -> &'static str {
        match self {
            Self::Both => "WAN & LAN",
            Self::Wan => "WAN Only",
            Self::Lan => "LAN Only",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TrafficDir {
    #[default]
    Both,
    In,
    Out,
}

impl TrafficDir {
    pub const ALL: [TrafficDir; 3] = [Self::Both, Self::In, Self::Out];
}

impl TrafficDir {
    /// Pill text; the menu shows the full label.
    pub fn short(self) -> &'static str {
        match self {
            Self::Both => "In & Out",
            Self::In => "In Only",
            Self::Out => "Out Only",
        }
    }
}

/// What the Traffic tab is narrowed to.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TrafficFilter {
    /// `(usage key, name)` of the one app shown; `None` is all apps.
    pub app: Option<(String, String)>,
    pub scope: Scope,
    pub dir: TrafficDir,
    /// Company or AS number (e.g. "google", "15169") the remote hosts must belong to; empty is all.
    pub network: String,
}

/// Which app icon to draw. Real code would extract the executable's icon.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppIcon {
    Generic,
    Gear,
    Chrome,
    VsCode,
    Drive,
    Claude,
    ClaudeCode,
    Bitwarden,
    RemoteDesktop,
    Monitor,
    Installer,
}

/// A small picture at the start or end of a usage row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Glyph {
    App(AppIcon),
    Flag(Country),
    More,
    Window,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TrafficSample {
    pub down: f32,
    pub up: f32,
}

/// Bucketed traffic for a time range, oldest first.
#[derive(Clone, Debug)]
pub struct TrafficHistory {
    /// Minute of day of the first bucket.
    pub start_minute: f32,
    pub step_minutes: f32,
    pub samples: Vec<TrafficSample>,
}

impl TrafficHistory {
    pub fn span_minutes(&self) -> f32 {
        self.step_minutes * self.samples.len().saturating_sub(1) as f32
    }
}

#[derive(Clone, Debug)]
pub struct UsageRow {
    pub label: String,
    /// Identity for click-through: IP for hosts, app id for apps, traffic type name, country code. Empty when not clickable.
    pub key: String,
    pub bytes: f64,
    /// Share of `bytes` that was upload (drawn pink at the end of the bar).
    pub up_share: f32,
    pub left: Glyph,
    pub right: Option<Glyph>,
}

#[derive(Clone, Debug, Default)]
pub struct UsageBreakdown {
    pub apps: Vec<UsageRow>,
    pub hosts: Vec<UsageRow>,
    pub traffic_types: Vec<UsageRow>,
    pub countries: Vec<UsageRow>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Totals {
    pub down: f64,
    pub up: f64,
    pub down_rate: f64,
    pub up_rate: f64,
    pub wan: f64,
    pub lan: f64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Allowed,
    Blocked,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppGroup {
    Active,
    Inactive,
    /// Windows itself (locked system rows), kept apart from the apps the user installed.
    Windows,
    Uninstalled,
}

impl AppGroup {
    pub const ALL: [AppGroup; 4] = [Self::Active, Self::Inactive, Self::Windows, Self::Uninstalled];

    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "Currently Connected",
            Self::Inactive => "Not Currently Connected",
            Self::Windows => "Windows",
            Self::Uninstalled => "Uninstalled Apps",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Direction {
    In,
    Out,
    /// Connections to the local network (private ranges), a rule of its own beside In and Out.
    Local,
}

#[derive(Clone, Debug)]
pub struct FirewallApp {
    /// Stable identity (lower-cased executable path in Live mode); verdict changes are addressed by it.
    pub key: String,
    /// Key of this app in `usage_detail` (the stored app id in Live mode).
    pub usage_key: String,
    pub name: String,
    pub path: String,
    pub publisher: String,
    /// `None` when not checked or not applicable.
    pub signed: Option<bool>,
    pub group: AppGroup,
    pub icon: AppIcon,
    pub inbound: Verdict,
    pub outbound: Verdict,
    /// Reaching the local network (LAN); allowed unless a RustWarden rule says otherwise.
    pub local: Verdict,
    /// System apps cannot be changed (shown with a shield).
    pub locked: bool,
    pub version: String,
    pub host: String,
    pub host_country: Country,
    pub more_hosts: u32,
    pub down_rate: f64,
    pub up_rate: f64,
    pub activity: Vec<f32>,
    pub virustotal: Vt,
    /// SHA-256 of the executable; empty when unknown. Identifies the VirusTotal page.
    pub hash: String,
    /// Running processes of this app, shown when the row is expanded.
    pub pids: Vec<u32>,
    /// Windows service this row is, for svchost.exe split by service; empty for a whole program.
    pub service: String,
    /// File name of the process that started this program; empty when unknown.
    pub parent: String,
}

impl FirewallApp {
    /// What an alert knows about its app, for the Info panel of a program the firewall list doesn't hold
    /// (a sample alert, or an app that has since been removed or renamed).
    pub fn from_alert(a: &Alert) -> Self {
        FirewallApp {
            key: a.app.to_lowercase(),
            usage_key: String::new(),
            name: a.app.clone(),
            path: String::new(),
            publisher: String::new(),
            signed: None,
            group: AppGroup::Inactive,
            icon: a.icon,
            inbound: Verdict::Allowed,
            outbound: Verdict::Allowed,
            local: Verdict::Allowed,
            locked: false,
            version: String::new(),
            host: String::new(),
            host_country: Country::Local,
            more_hosts: 0,
            down_rate: 0.0,
            up_rate: 0.0,
            activity: Vec::new(),
            virustotal: Vt::None,
            hash: String::new(),
            pids: Vec::new(),
            service: String::new(),
            parent: String::new(),
        }
    }
}

/// VirusTotal verdict for one program, looked up by file hash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Vt {
    #[default]
    None,
    Pending,
    /// Uploaded, waiting for VirusTotal to finish its report.
    Analysing,
    /// Unknown to VirusTotal and over the 32 MB upload limit.
    Skipped,
    /// VirusTotal has never seen this file.
    NotFound,
    /// `bad` of `total` engines flag it.
    Result {
        bad: u32,
        total: u32,
    },
    Failed,
    /// Lookups are paused for a while after repeated failures, to spare the API key's quota.
    OnHold,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FirewallMode {
    ClickToBlock,
    AskToConnect,
    BlockAll,
}

impl FirewallMode {
    pub const ALL: [FirewallMode; 3] = [Self::ClickToBlock, Self::AskToConnect, Self::BlockAll];

    pub fn label(self) -> &'static str {
        match self {
            Self::ClickToBlock => "Manual Blocking",
            Self::AskToConnect => "Prompt",
            Self::BlockAll => "Block All",
        }
    }
}

/// How long Prompt stays on before the previous mode returns, in minutes; 0 is Always.
pub const PROMPT_FOR: [u32; 5] = [0, 10, 30, 60, 120];

pub fn prompt_for_label(mins: u32) -> String {
    match mins {
        0 => "Always".into(),
        m if m % 60 == 0 => format!("{} hour{}", m / 60, if m == 60 { "" } else { "s" }),
        m => format!("{m} minutes"),
    }
}

/// One open TCP connection as the Live connections tab shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveConn {
    pub pid: u32,
    /// Owning process: its file name, or "PID n" when it can't be read.
    pub app: String,
    pub state: String,
    pub local: std::net::SocketAddr,
    pub remote: std::net::SocketAddr,
    /// Name learned from DNS, or empty.
    pub host: String,
    /// (received, sent) since RustWarden started watching this connection; `None` when unknown.
    pub bytes: Option<(u64, u64)>,
    /// Windows can only end established IPv4 connections.
    pub killable: bool,
    /// Where the remote address is; `None` when the database doesn't know it.
    pub country: Option<Country>,
    /// Unix time the connection was created, when Windows says.
    pub since: Option<i64>,
}

impl LiveConn {
    /// Case-insensitive match of `q` against the process, PID, state, host and remote address; an empty `q` matches all.
    pub fn matches(&self, q: &str) -> bool {
        let q = q.trim().to_lowercase();
        q.is_empty() || [self.app.to_lowercase(), self.pid.to_string(), self.state.to_lowercase(), self.host.to_lowercase(), self.remote.to_string()].iter().any(|f| f.contains(&q))
    }
}

/// One DNS lookup as the DNS Log tab shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsEntry {
    pub ts: i64,
    /// Process that asked: its file name, or "Unknown".
    pub app: String,
    pub name: String,
    /// DNS record type number (1 = A, 28 = AAAA, ...).
    pub qtype: u16,
    pub ips: Vec<String>,
    /// Windows DNS status: 0 is success.
    pub status: u32,
    /// The name is on a malicious-domain list. Worked out when the log is read, never stored.
    pub listed: bool,
}

impl DnsEntry {
    pub fn type_label(&self) -> String {
        match self.qtype {
            1 => "A".into(),
            2 => "NS".into(),
            5 => "CNAME".into(),
            12 => "PTR".into(),
            15 => "MX".into(),
            16 => "TXT".into(),
            28 => "AAAA".into(),
            33 => "SRV".into(),
            65 => "HTTPS".into(),
            n => n.to_string(),
        }
    }

    /// "OK" for a lookup that returned addresses, else what went wrong.
    pub fn status_label(&self) -> String {
        match self.status {
            _ if self.listed => "Malicious domain".into(),
            0 if self.ips.is_empty() => "No addresses".into(),
            0 => "OK".into(),
            9003 => "Name not found".into(),
            9501 => "No records".into(),
            1460 | 9002 => "Timed out".into(),
            n => format!("Error {n}"),
        }
    }

    pub fn ok(&self) -> bool {
        self.status == 0 && !self.ips.is_empty() && !self.listed
    }

    /// Case-insensitive match of `q` against the process, name, type and addresses; an empty `q` matches all.
    pub fn matches(&self, q: &str) -> bool {
        let q = q.trim().to_lowercase();
        q.is_empty() || [&self.app, &self.name, &self.type_label(), &self.status_label()].iter().any(|s| s.to_lowercase().contains(&q)) || self.ips.iter().any(|i| i.contains(&q))
    }
}

/// A program Prompt stopped on its first outbound connection, waiting for an answer.
#[derive(Clone, Debug)]
pub struct ConnectAsk {
    pub path: String,
    /// Display name: the file description from the exe's version resource, else the file name.
    pub app: String,
    pub publisher: String,
    pub version: String,
    pub icon: AppIcon,
    /// Host or address it tried to reach.
    pub target: String,
    pub country: Option<Country>,
    /// "AS15169 · Google LLC", empty when unknown or lookups are off.
    pub info: String,
    /// SHA-256 of the program, for the VirusTotal bubble; empty when VirusTotal is off.
    pub hash: String,
    /// The prompt's "Allow local network access" box; unticked, as Prompt denies by default.
    pub local: bool,
    /// Late details (host, network, hash) for a prompt already shown: patches it, and is dropped if it was answered.
    pub update: bool,
}

impl ConnectAsk {
    /// A made-up prompt for Settings > Test Prompt and the README screenshots. Empty path marks it as a demo: answering it records nothing (see show_asks).
    pub fn demo() -> Self {
        Self {
            path: String::new(),
            app: "demo.exe".into(),
            publisher: String::new(),
            version: String::new(),
            icon: AppIcon::Generic,
            target: "us.demo.example.com".into(),
            country: Some(Country::UnitedStates),
            info: "AS15169 · Example Networks".into(),
            hash: String::new(),
            local: false,
            update: false,
        }
    }
}

/// The user's answer to a [`ConnectAsk`]; `Block(None)` blocks both directions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    Allow { local: bool },
    Block(Option<Direction>),
}

/// A program that reached an address on a malicious-IP list; shown until dealt with.
#[derive(Clone, Debug)]
pub struct Threat {
    pub ip: String,
    pub app: String,
    pub signed: Option<bool>,
    pub blocked: bool,
    /// Why blocking failed, when it was wanted.
    pub error: Option<String>,
}

impl Threat {
    /// The address of a test popup: from the range reserved for documentation, so it is never a real host.
    const TEST_IP: &'static str = "203.0.113.45";

    /// A made-up warning for Settings > Send a test notification and the README screenshots.
    pub fn test() -> Self {
        Threat { ip: Self::TEST_IP.into(), app: "updater.exe".into(), signed: Some(false), blocked: false, error: None }
    }

    /// Whether this is a test popup, whose buttons must not touch the firewall or the whitelist.
    pub fn is_test(&self) -> bool {
        self.ip == Self::TEST_IP
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreatAct {
    Block,
    Unblock,
    /// Unblock and never warn about this address again.
    Whitelist,
    /// Take an address off the whitelist.
    Unwhitelist,
}

/// Result of walking the alert log's hash chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AlertCheck {
    pub checked: usize,
    /// Entries stored before the chain existed; they carry no hash, so they cannot be checked.
    pub unchained: usize,
    /// Oldest entry whose contents or link to the entry before it no longer match.
    pub first_bad: Option<i64>,
    /// Hash of the newest entry. Copy it somewhere safe: it shows whether the newest entries were removed later.
    pub head: String,
}

impl AlertCheck {
    pub fn summary(&self) -> String {
        match self.first_bad {
            None => format!("Alert log intact: {} entries checked, {} from before the chain existed.\nHead: {}", self.checked, self.unchained, self.head),
            Some(id) => format!("Alert log changed: entry #{id} was edited or removed. {} entries before it still check out.", self.checked),
        }
    }
}

/// What a history export holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryData {
    Traffic,
    Alerts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryFormat {
    Csv,
    Json,
}

#[derive(Clone, Debug)]
pub struct Alert {
    pub id: u64,
    pub app: String,
    pub icon: AppIcon,
    /// What happened, between the app name and the target ("initiated its first network connection to").
    pub text: String,
    pub target: String,
    /// Flag drawn before the target; `None` for alerts that are not about a remote host.
    pub country: Option<Country>,
    /// Label of the monitor that raised it, shown at the right.
    pub kind: String,
    pub time: String,
    /// "Today", "Yesterday" or a date; consecutive alerts with the same day are grouped.
    pub day: String,
    /// Unix seconds; 0 in Demo mode.
    pub ts: i64,
    pub unread: bool,
    pub important: bool,
    /// Raised by the behaviour baseline: it can be marked as normal, which teaches the baseline.
    pub anomaly: bool,
}

impl Alert {
    /// The text without a trailing " [Signed]" / " [Unsigned]" marker, and what it said.
    pub fn text_and_signature(&self) -> (&str, Option<bool>) {
        if let Some(t) = self.text.strip_suffix(" [Signed]") {
            (t, Some(true))
        } else if let Some(t) = self.text.strip_suffix(" [Unsigned]") {
            (t, Some(false))
        } else {
            (&self.text, None)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertFilter {
    Important,
    All,
    Unread,
}

impl AlertFilter {
    pub const ALL: [AlertFilter; 3] = [Self::Important, Self::All, Self::Unread];

    pub fn label(self) -> &'static str {
        match self {
            Self::Important => "Important",
            Self::All => "All",
            Self::Unread => "Unread",
        }
    }
}

/// What kind of application raised an alert, for the Alerts tab's category filter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AppCategory {
    Browsers,
    DevTools,
    AiAssistants,
    CloudSync,
    Security,
    RemoteAccess,
    System,
    Other,
}

impl AppCategory {
    pub const ALL: [AppCategory; 8] = [Self::Browsers, Self::DevTools, Self::AiAssistants, Self::CloudSync, Self::Security, Self::RemoteAccess, Self::System, Self::Other];

    pub fn label(self) -> &'static str {
        match self {
            Self::Browsers => "Web browsers",
            Self::DevTools => "Developer tools",
            Self::AiAssistants => "AI assistants",
            Self::CloudSync => "Cloud & sync",
            Self::Security => "Security & privacy",
            Self::RemoteAccess => "Remote access",
            Self::System => "System & updates",
            Self::Other => "Other apps",
        }
    }

    /// Live alerts carry no icon, so the app name decides too.
    pub fn of(app: &str, icon: AppIcon) -> Self {
        let n = app.to_lowercase();
        let has = |words: &[&str]| words.iter().any(|w| n.contains(w));
        match icon {
            AppIcon::Chrome => Self::Browsers,
            AppIcon::VsCode => Self::DevTools,
            AppIcon::Claude | AppIcon::ClaudeCode => Self::AiAssistants,
            AppIcon::Drive => Self::CloudSync,
            AppIcon::Bitwarden => Self::Security,
            AppIcon::RemoteDesktop => Self::RemoteAccess,
            AppIcon::Installer | AppIcon::Gear => Self::System,
            _ if has(&["chrome", "firefox", "edge", "brave", "opera", "vivaldi"]) => Self::Browsers,
            _ if has(&["code", "git", "cargo", "rust", "node", "python", "docker", "studio"]) => Self::DevTools,
            _ if has(&["claude", "chatgpt", "copilot", "gemini"]) => Self::AiAssistants,
            _ if has(&["drive", "dropbox", "onedrive", "sync", "backup"]) => Self::CloudSync,
            _ if has(&["defender", "antivirus", "vpn", "bitwarden", "keepass", "password"]) => Self::Security,
            _ if has(&["remote", "rdp", "teamviewer", "anydesk", "rustdesk", "ssh"]) => Self::RemoteAccess,
            _ if has(&["windows", "update", "installer", "svchost", "service", "svc", "system"]) => Self::System,
            _ => Self::Other,
        }
    }
}

/// Extra Log filters from the Filter panel; the default lets everything through.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct LogFilter {
    /// Empty means every category.
    pub categories: std::collections::HashSet<AppCategory>,
    /// Empty means every monitor (the alert's `kind` label).
    pub kinds: std::collections::HashSet<String>,
    pub dest: AlertDest,
    pub signed: AlertSigned,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum AlertDest {
    #[default]
    Any,
    Remote,
    Local,
}

impl AlertDest {
    pub const ALL: [AlertDest; 3] = [Self::Any, Self::Remote, Self::Local];

    pub fn label(self) -> &'static str {
        match self {
            Self::Any => "Any destination",
            Self::Remote => "Internet only",
            Self::Local => "Local network",
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum AlertSigned {
    #[default]
    Any,
    Signed,
    Unsigned,
}

impl AlertSigned {
    pub const ALL: [AlertSigned; 3] = [Self::Any, Self::Signed, Self::Unsigned];

    pub fn label(self) -> &'static str {
        match self {
            Self::Any => "Any signature",
            Self::Signed => "Signed",
            Self::Unsigned => "Unsigned",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertPeriod {
    AllTime,
    Today,
    Week,
}

impl AlertPeriod {
    pub const ALL: [AlertPeriod; 3] = [Self::AllTime, Self::Today, Self::Week];

    pub fn label(self) -> &'static str {
        match self {
            Self::AllTime => "All Time",
            Self::Today => "Today",
            Self::Week => "This Week",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceKind {
    Generic,
    SmartDevice,
    WiFi,
    Laptop,
    Raspberry,
}

impl DeviceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Generic => "Generic",
            Self::SmartDevice => "Smart Device",
            Self::WiFi => "Wi-Fi",
            Self::Laptop => "Laptop",
            Self::Raspberry => "Raspberry",
        }
    }
}

/// What a plugin knows about a scanned device: its name and area for it, the model, a kind such as "light" or
/// "switch" (drives the icon) and a link to its page.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeviceNote {
    pub name: String,
    pub area: String,
    pub model: String,
    pub kind: String,
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct Device {
    /// User-given name; empty falls back to the type label.
    pub name: String,
    pub online: bool,
    pub kind: DeviceKind,
    pub description: String,
    pub system: String,
    pub ip: String,
    pub mac: String,
    /// Unix seconds.
    pub last_seen: i64,
    pub first_seen: i64,
    /// Number of scans that found this device.
    pub seen_count: i64,
    /// Open TCP ports found by the last port scan, ascending; empty when none or not scanned yet.
    pub ports: Vec<u16>,
    /// What a device-annotating plugin (Home Assistant) calls this device, when it matched the MAC.
    pub note: Option<DeviceNote>,
    /// Marked as a known device by the user.
    pub trusted: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HardwareSample {
    pub cpu: f32,
    pub memory: f32,
    pub disk: f32,
    pub gpu: f32,
}

#[derive(Clone, Debug, Default)]
pub struct HardwareSnapshot {
    /// One sample per second, oldest first; the last one is "now".
    pub samples: Vec<HardwareSample>,
    /// Second of day of the last sample.
    pub now_secs: i64,
    pub cpu_pct: f32,
    pub memory_used: f64,
    /// Installed memory in bytes; the memory chart is drawn as a share of it.
    pub memory_total: f64,
    /// Whether a GPU counter is available (Live mode); Demo always has one.
    pub gpu_available: bool,
    pub disk_read: f64,
    pub disk_write: f64,
    pub gpu_pct: f32,
    pub gpu_memory: f64,
}

#[derive(Clone, Debug)]
pub struct MapConnection {
    pub lon: f32,
    pub lat: f32,
    pub count: u32,
    /// Bytes received from / sent to this country in the range.
    pub down: f64,
    pub up: f64,
    /// Connection attempts the firewall blocked; `count` is only the allowed hosts.
    pub blocked: u32,
    /// City name when a city database supplied the position.
    pub label: String,
    /// Country key for `usage_detail`.
    pub key: String,
}

/// Which countries to shade darker, as 3-letter codes.
pub type ActiveCountries = Vec<String>;

#[derive(Clone, Debug, Default)]
pub struct MapData {
    /// Where the local machine is (lon, lat).
    pub home: (f32, f32),
    pub connections: Vec<MapConnection>,
    pub active: ActiveCountries,
}

/// What the active backend can do right now. The UI greys out or annotates the rest.
#[derive(Clone, Debug)]
pub struct Capabilities {
    pub live: bool,
    pub elevated: bool,
    /// Per-app bytes, hosts and protocols (needs the ETW session, so administrator).
    pub per_app_traffic: bool,
    /// Can create and delete RustWarden firewall rules.
    pub firewall_write: bool,
    /// Which of [`FirewallMode::ALL`] can be selected.
    pub firewall_modes: [bool; 3],
    pub scanner: bool,
    pub geo_db: bool,
}

impl Capabilities {
    pub fn mode_enabled(&self, mode: FirewallMode) -> bool {
        FirewallMode::ALL.iter().position(|m| *m == mode).is_some_and(|i| self.firewall_modes[i])
    }
}

/// A program seen talking to many peers it has no name for, which is what peer-to-peer traffic looks like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pApp {
    pub key: String,
    pub name: String,
    pub last_seen: i64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoteLevel {
    Info,
    Warn,
    /// A VPN is up: shown as a header chip, not in the status strip.
    Vpn,
}

/// One line of the status strip: something that is degraded or unavailable, and why.
#[derive(Clone, Debug)]
pub struct StatusNote {
    pub level: NoteLevel,
    pub text: String,
}

impl StatusNote {
    pub fn warn(text: impl Into<String>) -> Self {
        Self { level: NoteLevel::Warn, text: text.into() }
    }
    pub fn vpn(text: impl Into<String>) -> Self {
        Self { level: NoteLevel::Vpn, text: text.into() }
    }
    pub fn info(text: impl Into<String>) -> Self {
        Self { level: NoteLevel::Info, text: text.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineState {
    Ready,
    /// Windows Firewall is off, so RustWarden's rules have no effect.
    WindowsFirewallOff,
    /// Can't read or write the firewall (no administrator, service stopped, ...).
    Unavailable(String),
}

#[derive(Clone, Debug)]
pub struct FirewallInfo {
    /// RustWarden's rules are switched on (the header toggle).
    pub enabled: bool,
    pub mode: FirewallMode,
    pub engine: EngineState,
    pub block_all_active: bool,
    /// Rules found in the RustWarden group.
    pub rule_count: usize,
    /// Why the tab is read-only, if it is.
    pub read_only: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ScanState {
    pub scanning: bool,
    /// Progress 0..1 while scanning.
    pub progress: f32,
    pub error: Option<String>,
}

/// How far a quota is used.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum QuotaLevel {
    #[default]
    Ok,
    /// At or over the warning percentage.
    Warn,
    /// The whole quota is used.
    Over,
}

/// A quota with its usage in the current period.
#[derive(Clone, Debug)]
pub struct QuotaStatus {
    pub quota: crate::settings::Quota,
    /// "All traffic" or the app's name.
    pub name: String,
    pub used: f64,
    pub limit: f64,
    pub level: QuotaLevel,
    /// RustWarden blocked the app for exceeding this quota and will lift it when the period resets.
    pub blocked: bool,
    /// RustWarden capped the app's upload rate for this quota and will lift it when the period resets.
    pub throttled: bool,
}

impl QuotaStatus {
    /// Used share of the limit, 0 to 1 for the bar (the text can show more than 100%).
    pub fn fraction(&self) -> f32 {
        if self.limit > 0.0 { (self.used / self.limit).clamp(0.0, 1.0) as f32 } else { 0.0 }
    }
}

/// Backend seam. The UI only talks to this trait.
///
/// All methods take `&self`: backends use interior mutability so collector threads
/// can update them while the UI reads. Reads never block on collection.
pub trait Backend: Send + Sync {
    /// Gives the backend a handle to wake the UI when new data arrives.
    fn set_repaint(&self, _ctx: egui::Context) {}
    fn capabilities(&self) -> Capabilities;
    fn status(&self) -> Vec<StatusNote>;

    /// Narrows history, totals, breakdown and detail to `filter` until it is set again.
    fn set_traffic_filter(&self, _filter: &TrafficFilter) {}
    fn map_data(&self, range: TimeRange) -> MapData;
    fn traffic_history(&self, range: TimeRange) -> TrafficHistory;
    /// `window` is the selected fraction (start, end) of the range.
    fn totals(&self, range: TimeRange, window: (f32, f32)) -> Totals;
    fn breakdown(&self, range: TimeRange, window: (f32, f32)) -> UsageBreakdown;
    /// Detail for one clicked usage row (`key` is [`UsageRow::key`]).
    fn usage_detail(&self, range: TimeRange, window: (f32, f32), kind: UsageKind, key: &str) -> Option<UsageDetail>;

    fn firewall_info(&self) -> FirewallInfo;
    fn firewall_apps(&self) -> Vec<FirewallApp>;
    fn set_verdict(&self, key: &str, direction: Direction, verdict: Verdict) -> Result<(), String>;
    /// Forgets the user's decisions for one app: deletes its RustWarden rules and takes it off the
    /// list until it is active again. It never touches rules RustWarden didn't create.
    fn remove_app(&self, key: &str) -> Result<(), String>;
    fn set_firewall_enabled(&self, on: bool) -> Result<(), String>;
    fn set_firewall_mode(&self, mode: FirewallMode) -> Result<(), String>;
    /// Removes only RustWarden's own rules and leaves Block All.
    fn restore_defaults(&self) -> Result<(), String>;
    /// Adopts another firewall's program rules as RustWarden rules, renamed or not; returns how many.
    fn import_firewall_rules(&self, rename: bool) -> Result<usize, String>;
    /// Blocks internet access for Windows programs that don't need it (see `live::windows_extras`); returns how many programs got new rules.
    fn block_windows_extras(&self) -> Result<usize, String>;
    /// Per group of those rules: (rules exist, paused).
    fn windows_extras_state(&self) -> Vec<(bool, bool)>;
    /// Unblocks, pauses or resumes one group of those rules; returns how many rules it touched.
    fn windows_extras_act(&self, group: usize, act: crate::live::firewall::ExtrasAct) -> Result<usize, String>;
    /// Turns Windows Firewall itself on (explicit user action behind a confirmation).
    fn enable_windows_firewall(&self) -> Result<(), String>;
    /// Firewall profile names and the active one.
    fn firewall_profiles(&self) -> (Vec<String>, String) {
        (vec!["Default".into()], "Default".into())
    }
    /// Permanently deletes an inactive profile and its saved rules; the last profile can't go.
    fn delete_firewall_profile(&self, _name: &str) -> Result<(), String> {
        Err("Firewall rulesets need Live mode.".into())
    }
    /// Parks the active profile's rules (switched off, never deleted) and brings in `name`'s,
    /// creating `name` empty when `create` is set.
    fn switch_firewall_profile(&self, _name: &str, _create: bool) -> Result<(), String> {
        Err("Firewall rulesets need Live mode.".into())
    }

    /// Programs that looked like peer-to-peer traffic, newest first (empty unless detection is on). Reads a cache; never blocks.
    fn p2p_apps(&self) -> Vec<P2pApp> {
        Vec::new()
    }

    /// Destination rules (domain, ASN, country) with their state. Reads a cache; never blocks.
    fn dest_rules(&self) -> Vec<crate::destrules::DestRuleView> {
        Vec::new()
    }
    /// Adds a rule (id 0) or replaces the one with that id, and applies it. Slow: call it off the UI thread.
    fn save_dest_rule(&self, _rule: crate::destrules::DestRule) -> Result<(), String> {
        Err("Destination rules need Live mode.".into())
    }
    fn remove_dest_rule(&self, _id: u32) -> Result<(), String> {
        Err("Destination rules need Live mode.".into())
    }
    /// The packet capture in progress or just finished (Driver mode), if any. Cheap; the UI asks every frame.
    fn capture_status(&self) -> Option<crate::pcap::CaptureStatus> {
        None
    }
    /// Starts capturing one connection to a .pcap file; returns the file's path.
    fn start_capture(&self, _conn: &LiveConn) -> Result<String, String> {
        Err("Capturing needs Live mode.".into())
    }
    fn stop_capture(&self) {}
    /// Block by domain (Driver mode): the saved rules, the imported list and the blocker's state.
    fn domain_blocks(&self) -> crate::domainblock::DomainView {
        crate::domainblock::DomainView::default()
    }
    /// Adds the rule (id 0) or replaces the one with that id.
    fn save_domain_block(&self, _rule: crate::domainblock::DomainRule) -> Result<(), String> {
        Err("Blocking by domain needs Live mode.".into())
    }
    fn remove_domain_block(&self, _id: u32) -> Result<(), String> {
        Err("Blocking by domain needs Live mode.".into())
    }
    /// Downloads a domain list from an https address; returns how many domains it holds. Slow.
    fn import_domain_list(&self, _url: &str) -> Result<usize, String> {
        Err("Blocking by domain needs Live mode.".into())
    }
    fn clear_domain_list(&self) -> Result<(), String> {
        Err("Blocking by domain needs Live mode.".into())
    }
    /// Whether the optional network driver (Driver mode) is installed.
    fn driver_state(&self) -> crate::driver::DriverState {
        crate::driver::DriverState::Missing
    }
    /// Downloads and installs the driver. Slow: call it off the UI thread.
    fn install_driver(&self) -> Result<(), String> {
        Err("The driver needs Live mode.".into())
    }
    fn remove_driver(&self) -> Result<(), String> {
        Err("The driver needs Live mode.".into())
    }
    /// Per-program upload limits (Windows QoS policies) with their state. Reads a cache; never blocks.
    fn qos_limits(&self) -> Vec<crate::qos::QosView> {
        Vec::new()
    }
    /// Adds a limit (id 0) or replaces the one with that id, and applies it. Slow: call it off the UI thread.
    fn save_qos_limit(&self, _limit: crate::qos::QosLimit) -> Result<(), String> {
        Err("Bandwidth limits need Live mode.".into())
    }
    fn remove_qos_limit(&self, _id: u32) -> Result<(), String> {
        Err("Bandwidth limits need Live mode.".into())
    }
    /// Whether the optional ASN database (needed by rules on an AS number) is on disk.
    fn asn_db_ready(&self) -> bool {
        false
    }
    /// Downloads the ASN database. Only after the user asked for it; slow.
    fn download_asn_db(&self) -> Result<(), String> {
        Err("The ASN database download needs Live mode.".into())
    }

    /// Usage of every configured quota in its current period (Demo: sample data). Reads a cache; never blocks.
    fn quotas(&self, _settings: &crate::settings::Settings) -> Vec<QuotaStatus> {
        Vec::new()
    }

    /// The most recent DNS lookups, newest first (Demo: sample data). Live reads the UI's own database connection, like `alerts`.
    fn dns_log(&self) -> Vec<DnsEntry> {
        Vec::new()
    }

    /// Open TCP connections, busiest first (Demo: sample data). Slow: call it off the UI thread.
    fn live_connections(&self) -> Vec<LiveConn> {
        Vec::new()
    }

    /// Resets one connection. IPv4 only; needs administrator rights in Live mode.
    fn kill_connection(&self, _conn: &LiveConn) -> Result<String, String> {
        Err("Ending a connection needs Live mode.".into())
    }

    /// Blocks a remote address in both directions with a RustWarden-owned firewall rule.
    fn block_remote(&self, _ip: std::net::IpAddr) -> Result<String, String> {
        Err("Blocking an address needs Live mode.".into())
    }

    fn alerts(&self) -> Vec<Alert>;
    /// `None` marks every alert as read.
    fn mark_read(&self, id: Option<u64>);
    /// Marks a behaviour-baseline alert as normal, so the baseline learns it. False when it isn't one.
    fn mark_alert_normal(&self, _id: u64) -> bool {
        false
    }
    /// `0` ends a snooze early.
    fn snooze_alerts(&self, minutes: u32);
    fn alerts_snoozed(&self) -> bool {
        false
    }
    /// Sends a sample alert of the kind with this key through its delivery channels in `s`, without storing it.
    fn test_alert(&self, _kind: &str, _s: &crate::settings::Settings) {}
    /// Looks the app up on VirusTotal (Live mode; needs an API key in settings).
    fn scan_virustotal(&self, _key: &str) {}
    /// Uploads the program's file to VirusTotal (Live mode). Only after the user confirmed that one file; lookups send the hash alone.
    fn upload_virustotal(&self, _key: &str) {}

    /// Score for a banner: `who` is a file hash or an app name. Starts a lookup when there is none
    /// yet; always `Vt::None` without an API key.
    fn virustotal(&self, _who: &str) -> Vt {
        Vt::None
    }

    /// "AS15169 · Google LLC" for an address or host name already seen; empty until the lookup finishes.
    fn net_info(&self, _host: &str) -> String {
        String::new()
    }

    /// New-program prompts raised by Prompt; always empty in any other mode.
    fn take_asks(&self) -> Vec<ConnectAsk> {
        Vec::new()
    }
    fn answer_ask(&self, _path: &str, _answer: Answer) -> Result<(), String> {
        Ok(())
    }
    /// Malicious-IP warnings waiting for the UI; always empty in Demo mode.
    fn take_threats(&self) -> Vec<Threat> {
        Vec::new()
    }
    /// Addresses currently blocked as malicious.
    fn blocked_ips(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    fn threat_whitelist(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    /// Which program reached the address and which lists carry it.
    fn threat_summary(&self, _ip: &str) -> String {
        String::new()
    }
    fn threat_act(&self, _ip: &str, _act: ThreatAct) -> Result<(), String> {
        Ok(())
    }
    /// Alerts to show as desktop popups; `visible` says whether the UI can show them itself.
    fn take_popups(&self, _visible: bool) -> Vec<Alert> {
        Vec::new()
    }

    fn networks(&self) -> Vec<String>;
    fn devices(&self, network: &str) -> Vec<Device>;
    fn scan_state(&self) -> ScanState;
    fn start_scan(&self, network: &str);
    fn stop_scan(&self);
    fn rename_device(&self, network: &str, mac: &str, name: &str);
    fn set_device_trusted(&self, network: &str, mac: &str, trusted: bool);
    fn forget_network(&self, network: &str);

    fn hardware(&self, seconds: usize) -> HardwareSnapshot;
    /// The last `window_secs` seconds of stored hardware history as `buckets` evenly spaced
    /// slots (oldest first, the last slot ends now); `None` where nothing was recorded.
    /// With `app`, only that program's CPU, memory and disk (GPU stays 0).
    fn hardware_history(&self, _window_secs: i64, _buckets: usize, _app: Option<&str>) -> Vec<Option<HardwareSample>> {
        Vec::new()
    }
    /// Programs with hardware history in the last `window_secs` seconds.
    fn hardware_apps(&self, _window_secs: i64) -> Vec<String> {
        Vec::new()
    }

    /// Where a speed test went: the test server and this connection on the map, when the GeoIP database knows both.
    fn speedtest_route(&self, _server_ip: &str, _client_ip: &str) -> Option<crate::ui::speed::SpeedRoute> {
        None
    }

    fn apply_settings(&self, settings: &crate::settings::Settings);
    /// Deletes stored traffic history (not alerts, apps or devices).
    fn clear_history(&self) -> Result<(), String>;
    /// Walks the alert log's hash chain. Reads the whole log, so callers run it off the UI thread.
    fn verify_alerts(&self) -> Result<AlertCheck, String>;
    /// The stored history as CSV or JSON text, from the last `days` days (`None` = everything kept). Reads the database, so callers run it off the UI thread.
    fn export_history(&self, data: HistoryData, format: HistoryFormat, days: Option<u32>) -> Result<String, String>;
    /// What the Prometheus endpoint reports for one scrape. Reads the database, so it runs on the endpoint's thread.
    fn metrics_snapshot(&self) -> Result<crate::metrics::Snapshot, String>;
    /// The last seven days in one summary. Reads the database, so callers run it off the UI thread.
    fn weekly_report(&self) -> Result<crate::report::Report, String>;
    /// Restart-as-administrator and similar actions are UI-side; this is for cleanup before exit.
    fn shutdown(&self) {}
    /// The app is closing for good: like `shutdown`, but Live may leave Prompt blocking (Settings > Firewall).
    fn exit(&self) {
        self.shutdown();
    }
}

/// Which usage column a row belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UsageKind {
    App,
    Host,
    TrafficType,
    Country,
}

#[derive(Clone, Debug)]
pub struct DetailRow {
    pub label: String,
    pub left: Glyph,
    /// Second picture and count, e.g. the first app of a host and "+2".
    pub right: Option<Glyph>,
    pub extra: String,
    pub down: f64,
    pub up: f64,
    /// What clicking the row opens next (a host row opens that host's detail).
    pub target: Option<(UsageKind, String)>,
}

/// The popup shown when a usage row is clicked.
#[derive(Clone, Debug)]
pub struct UsageDetail {
    pub title: String,
    pub glyph: Glyph,
    pub facts: Vec<(String, String)>,
    /// Column title of the table ("App", "Hosts", "Apps").
    pub heading: String,
    pub rows: Vec<DetailRow>,
}

impl UsageDetail {
    /// Puts an "All" row with the sums first when there is more than one row.
    pub fn with_all(mut self) -> Self {
        if self.rows.len() > 1 {
            let (down, up) = self.rows.iter().fold((0.0, 0.0), |a, r| (a.0 + r.down, a.1 + r.up));
            self.rows.insert(0, DetailRow { label: "All".into(), left: Glyph::Window, right: None, extra: String::new(), down, up, target: None });
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::Threat;

    #[test]
    fn only_the_made_up_threat_is_a_test() {
        assert!(Threat::test().is_test());
        let real = Threat { ip: "198.51.100.7".into(), ..Threat::test() };
        assert!(!real.is_test());
    }
}
