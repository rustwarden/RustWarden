//! Speedtest.net tab (Network > Speedtest). Speedtest.net has no public API, so this drives Ookla's
//! own `speedtest.exe` CLI: it is downloaded when the user asks for it, run on a worker and its JSON
//! result is stored. Nothing is contacted until the user downloads the CLI or runs a test.

pub mod cli;
pub mod store;
pub mod ui;
pub mod worker;

use crate::settings::Settings;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Switched on in Settings.
    pub show_tab: bool,
    /// Minutes between automatic tests; 0 = only when the user presses Run test.
    pub interval_mins: u32,
    /// Speedtest server to use; 0 = let Speedtest pick the closest.
    pub server_id: u32,
    /// History range kept between runs (0 = 24 hours, 1 = 7 days, 2 = 30 days).
    pub range: usize,
}

pub fn tab_visible(s: &Settings) -> bool {
    s.speedtest.show_tab
}

pub fn sanitize(s: &mut Settings) {
    s.speedtest.interval_mins = s.speedtest.interval_mins.min(24 * 60);
    s.speedtest.range = s.speedtest.range.min(2);
}

/// One finished test.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpeedResult {
    pub ts: i64,
    pub ping_ms: f32,
    pub jitter_ms: f32,
    pub down_mbps: f32,
    pub up_mbps: f32,
    /// Packet loss in percent; negative when the server didn't report it.
    pub loss: f32,
    pub server: String,
    pub isp: String,
    /// Link to the result on speedtest.net.
    pub url: String,
    /// Addresses of the test server and of this connection, for the route map; empty when unknown.
    pub server_ip: String,
    pub client_ip: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Phase {
    #[default]
    Idle,
    Ping,
    Download,
    Upload,
}

/// One live reading from a running test.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Progress {
    pub phase: Phase,
    pub mbps: f32,
    /// How far through the phase, 0 to 1.
    pub progress: f32,
}

/// Where a test went, as (lon, lat) pairs for the map.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SpeedRoute {
    pub home: (f32, f32),
    pub server: (f32, f32),
}

/// What the tab needs to know about the test runner besides the stored results.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpeedStatus {
    /// Readings of the running test so far, oldest first; empty when none is running.
    pub live: Vec<Progress>,
    pub cli_ready: bool,
    pub installing: bool,
    pub running: bool,
    /// Unix time of the last test that worked; 0 = none this session.
    pub last_ok: i64,
    /// Why the last download or test failed; empty when it didn't.
    pub error: String,
}
