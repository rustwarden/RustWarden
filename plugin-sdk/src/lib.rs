//! The contract between RustWarden and a `.wasm` plugin, shared by both sides.
//!
//! A plugin is a core wasm module that exports two functions and imports one:
//! - `alloc(len: i32) -> i32`: returns a buffer of `len` bytes in the plugin's memory
//! - `call(ptr: i32, len: i32) -> i64`: takes a JSON [`Call`] at `ptr`, returns `(ptr << 32) | len` of a JSON [`Reply`]
//! - import `env.host(ptr: i32, len: i32) -> i64`: the same shape, a JSON [`HostCall`] in and a [`HostReply`] out
//!
//! Bump [`API_VERSION`] on any change an old plugin could not cope with.

pub mod guest;
pub mod notify;

use serde::{Deserialize, Serialize};

pub const API_VERSION: u32 = 1;

/// Which Settings > Plugins section a plugin is listed in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    System,
    Notification,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TabDef {
    pub id: String,
    pub title: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub api_version: u32,
    pub kind: Kind,
    /// PNG bytes.
    pub icon: Vec<u8>,
    pub tabs: Vec<TabDef>,
    pub settings_page: bool,
    /// Hosts `HostCall::HttpRequest` may reach; anything else is refused. `"*"` means any http(s) host, for plugins that
    /// post to an address the user types (a self-hosted server); the approval dialog says so.
    pub http_hosts: Vec<String>,
    /// Opt-in permissions the user approves at install, e.g. "ping", "alerts.read".
    pub permissions: Vec<String>,
    /// Seconds between `Call::Tick`; 0 = never.
    pub tick_secs: u32,
    /// The plugin may ask `HttpRaw` to accept a server's own (self-signed) certificate. The approval dialog says so;
    /// only for a router or server on the user's own network.
    pub allow_insecure_tls: bool,
    /// SQL creating this plugin's tables, which must all be named `p_<id>__*` (the id's dashes written as underscores).
    pub schema: String,
}

/// What the host draws for a plugin. The plugin sends a new tree after each [`Event`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiTree {
    Label(String),
    Heading(String),
    Weak(String),
    Button {
        id: String,
        text: String,
    },
    TextField {
        id: String,
        value: String,
    },
    Password {
        id: String,
        value: String,
    },
    Switch {
        id: String,
        text: String,
        on: bool,
    },
    Dropdown {
        id: String,
        options: Vec<String>,
        selected: usize,
    },
    Number {
        id: String,
        value: f64,
        min: f64,
        max: f64,
    },
    Link {
        text: String,
        url: String,
    },
    Grid {
        columns: usize,
        children: Vec<UiTree>,
    },
    Row(Vec<UiTree>),
    Column(Vec<UiTree>),
    Separator,
    /// PNG bytes.
    Image(Vec<u8>),
    /// Shown greyed out and not usable (a button that needs something first).
    Disabled(Box<UiTree>),
    /// The Speedtest page (gauge, route map, history chart and list of tests), drawn by RustWarden. It must be the
    /// only thing on its tab page.
    Speedtest(Box<SpeedPage>),
    /// A whole-tab page of latency and packet-loss charts, drawn by RustWarden (the layout Broadband Quality
    /// and Ping share). It must be the only thing on its tab page.
    LatencyChart(Box<LatencyChart>),
}

/// One chart on a [`LatencyChart`] page.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChartLine {
    pub id: u32,
    pub name: String,
}

/// What a [`UiTree::LatencyChart`] page needs. The samples are not sent: RustWarden reads them with `sql`,
/// from the plugin's own tables only (anything else fails), once per chart.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LatencyChart {
    pub lines: Vec<ChartLine>,
    /// `SELECT ts, min, avg, max, loss FROM <your table> WHERE <chart column> = ?1 AND ts >= ?2 ORDER BY ts`:
    /// ?1 is the chart's `id`, ?2 the first second wanted. Latency columns are milliseconds, loss is a percentage.
    pub sql: String,
    /// The saved layout (0 side by side, 1 stacked, 2 grid) and time range (0 3 hours, 1 24 hours, 2 7 days).
    pub layout: usize,
    pub range: usize,
    /// Unix time of the last round that worked, 0 for none yet.
    pub last_ok: i64,
    pub refresh_hint: String,
    /// What the chart area says when there is nothing to draw.
    pub text_not_live: String,
    pub text_no_lines: String,
    pub text_no_data_day: String,
    pub text_no_data: String,
    /// Extra buttons at the left of the toolbar; their events come back as usual.
    pub tools: Vec<UiTree>,
    /// A download is running (the Refresh button shows it).
    pub refreshing: bool,
    /// Rounds are on hold until the user signs in; with `signin_text`, a banner offers the way back in.
    pub paused: bool,
    /// Older data is being fetched for the day view; the charts fade out meanwhile.
    pub loading: bool,
    pub signin_text: String,
    pub signin_button: String,
    /// Ask for `Event::ChartMissing` when the day being looked at has nothing stored.
    pub wants_missing: bool,
    /// A form in a window of its own over the page (an "Add host" dialog). While it is `Some` the window is open;
    /// closing it with its X sends `chart.dialog_close`, and the plugin answers by leaving it `None`.
    pub dialog_title: String,
    pub dialog: Option<Box<UiTree>>,
}

/// Which part of a speed test a live reading belongs to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedPhase {
    #[default]
    Ping,
    Download,
    Upload,
}

/// One live reading of a running speed test.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpeedLive {
    pub phase: SpeedPhase,
    pub mbps: f32,
    /// How far through the phase, 0 to 1.
    pub progress: f32,
}

/// What a [`UiTree::Speedtest`] page needs. The finished tests are not sent: RustWarden reads them with `sql`
/// from the plugin's own tables.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpeedPage {
    /// `SELECT ts, ping, jitter, down, up, loss, server, isp, url, server_ip, client_ip FROM <your table> WHERE ts >= ?1 ORDER BY ts`:
    /// milliseconds, megabits per second, a percentage (negative when unknown), then text; ?1 is the first second wanted.
    pub sql: String,
    /// The saved history range: 0 24 hours, 1 7 days, 2 30 days.
    pub range: usize,
    /// Readings of the test in progress, oldest first.
    pub live: Vec<SpeedLive>,
    pub running: bool,
    pub installing: bool,
    /// The test program is downloaded.
    pub cli_ready: bool,
    /// Unix time of the last test that worked, 0 for none this session.
    pub last_ok: i64,
    /// Why the last download or test failed.
    pub error: String,
    /// The licence text RustWarden shows before it sends `speed.install`.
    pub install_title: String,
    pub install_text: Vec<String>,
}

/// Event ids a [`SpeedPage`] sends: `speed.run` and `speed.install` (Click, after the user accepted the licence
/// text), `speed.range` (Index).
pub const SPEED_RUN: &str = "speed.run";
pub const SPEED_INSTALL: &str = "speed.install";
pub const SPEED_RANGE: &str = "speed.range";

/// Event ids a [`LatencyChart`] page sends: `chart.refresh` (Click), `chart.layout` and `chart.range` (Index).
pub const CHART_REFRESH: &str = "chart.refresh";
pub const CHART_LAYOUT: &str = "chart.layout";
pub const CHART_RANGE: &str = "chart.range";
pub const CHART_DIALOG_CLOSE: &str = "chart.dialog_close";
/// Click: the banner's sign-in button was pressed.
pub const CHART_SIGNIN: &str = "chart.signin";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Click {
        id: String,
    },
    Text {
        id: String,
        value: String,
    },
    Bool {
        id: String,
        on: bool,
    },
    Index {
        id: String,
        index: usize,
    },
    Number {
        id: String,
        value: f64,
    },
    TabOpened {
        tab: String,
    },
    /// A chart page found charts with nothing stored for a day (`from` to `to`, unix seconds); see `LatencyChart::wants_missing`.
    ChartMissing {
        ids: Vec<u32>,
        from: i64,
        to: i64,
    },
}

/// Host to plugin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Call {
    Manifest,
    RenderTab {
        tab: String,
    },
    RenderSettings,
    Event(Event),
    Tick,
    /// An alert RustWarden raised. Only sent to plugins the user gave "alerts.read".
    Alert {
        important: bool,
        title: String,
        text: String,
    },
    /// A line the helper program printed (see `HostCall::HelperStart`).
    HelperLine {
        line: String,
    },
    /// The helper program ended. `ok` is false when it could not run to the end (it timed out, or would not start) and
    /// `message` says why; when `ok`, `message` is what it wrote to its error output, usually nothing.
    HelperDone {
        ok: bool,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Manifest(Manifest),
    Ui(UiTree),
    Done,
    Err(String),
}

/// Plugin to host. The first group is always available; the rest need the named permission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCall {
    ConfigGet {
        key: String,
    },
    ConfigSet {
        key: String,
        value: String,
    },
    SecretGet {
        key: String,
    },
    SecretSet {
        key: String,
        value: String,
    },
    /// Runs SQL; only tables named `p_<id>__*` are reachable.
    DbExec {
        sql: String,
    },
    /// Rows come back as a JSON array of arrays.
    DbQuery {
        sql: String,
    },
    HttpRequest {
        url: String,
        headers: Vec<String>,
        body: Option<String>,
    },
    Now,
    Log {
        msg: String,
    },
    NotifyInApp {
        msg: String,
    },
    /// Echoes `count` (1 to 10) pings to each address, several at once, and returns a JSON array with one
    /// `{"min","avg","max","loss"}` per address, in order (milliseconds; loss in percent). At most 64 addresses.
    /// Needs "ping".
    PingRound {
        addrs: Vec<String>,
        count: u32,
    },
    /// Like `HttpRequest`, but any HTTP status is an answer: replies `{"status": 404, "body": "..."}`. Only a failure to
    /// reach the server is an error. `insecure` accepts a self-signed certificate and needs `Manifest.allow_insecure_tls`.
    HttpRaw {
        url: String,
        headers: Vec<String>,
        body: Option<String>,
        insecure: bool,
    },
    /// Raises an alert of the given kind (only "packet-loss" so far) naming `who`, as RustWarden's own monitors do: it
    /// is shown, logged and sent on like any other, under the user's settings for that kind. Needs "alerts.write".
    RaiseAlert {
        kind: String,
        who: String,
        text: String,
    },
    /// Opens the sign-in window of the plugin's site (thinkbroadband) and waits for it. Needs "browser.session".
    BrowserSignIn,
    /// Fetches each URL from inside the signed-in browser session, one run for all: a JSON array of
    /// `{"status","body"}` in order. Every URL must be on one of the plugin's `http_hosts`. The error
    /// `"Sign in to thinkbroadband again."` means the session is gone. Needs "browser.session".
    BrowserFetch {
        urls: Vec<String>,
    },
    /// Forgets the saved sign-in. Needs "browser.session".
    BrowserSignOut,
    /// "1" in Demo mode (the plugin should make up its data), else "0".
    IsDemo,
    /// "1" when the helper program `exe` is downloaded (an elevated RustWarden first takes over a genuine copy an earlier
    /// run saved, judged by `exe_sha256`). Needs "helper.exe".
    HelperReady {
        exe: String,
        exe_sha256: String,
    },
    /// Downloads the zip at `url` (https, on one of the manifest's `http_hosts`), checks it against `zip_sha256`
    /// and unpacks `exe`. Blocks until done. Needs "helper.exe".
    HelperInstall {
        url: String,
        zip_sha256: String,
        exe: String,
    },
    /// Runs the downloaded `exe` with `args` (no shell) and returns at once; each line it prints comes back as
    /// `Call::HelperLine`, then one `Call::HelperDone`. One at a time. Needs "helper.exe".
    HelperStart {
        exe: String,
        args: Vec<String>,
        timeout_secs: u32,
    },
    /// How often the plugin wants `Call::Tick` from now on, in milliseconds (50 to an hour); 0 goes back to the manifest's.
    SetTick {
        millis: u32,
    },
    /// The devices the network scan has found, as a JSON array of `{"mac","ip","name"}` (empty in Demo mode).
    /// A plugin with this permission also fills its `p_<id>__devices` table (mac, found, name, area, kind, model, url),
    /// which RustWarden reads to name and mark those devices on the Scanner tab. Needs "devices.annotate".
    Devices,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostReply {
    Ok(String),
    Err(String),
}
