//! thinkbroadband Broadband Quality Monitor: signs in with the account, downloads each chosen
//! monitor's daily XML, keeps the samples and draws them on their own tab. Packet loss raises an
//! alert, delivered like any other alert.

pub mod browser;
pub mod client;
pub mod store;
pub mod ui;
pub mod worker;

use crate::settings::Settings;
use serde::{Deserialize, Serialize};

/// One BQM graph on the account.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Monitor {
    pub id: u32,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Integration {
    pub enabled: bool,
    pub name: String,
    /// The graphs picked on import; only these are downloaded.
    pub monitors: Vec<Monitor>,
    pub show_tab: bool,
    /// Minutes between downloads.
    pub interval_mins: u32,
    /// A sample with at least this much packet loss (%) raises an alert.
    pub alert_pct: f32,
    /// Broadband tab choices, kept between runs: layout (0 side by side, 1 stacked, 2 grid) and time range.
    pub layout: usize,
    pub range: usize,
}

impl Default for Integration {
    fn default() -> Self {
        Self { enabled: true, name: "thinkbroadband".into(), monitors: Vec::new(), show_tab: true, interval_mins: 10, alert_pct: 1.0, layout: 0, range: 1 }
    }
}

impl Integration {
    pub fn ready(&self) -> bool {
        self.enabled && !self.monitors.is_empty()
    }
}

/// The integration in use: set up, switched on and with graphs chosen.
pub fn active(s: &Settings) -> Option<&Integration> {
    s.thinkbroadband.as_ref().filter(|i| i.ready())
}

/// The Broadband tab shows only while the integration is in use and the tab is switched on.
pub fn tab_visible(s: &Settings) -> bool {
    active(s).is_some_and(|i| i.show_tab)
}

pub fn sanitize(s: &mut Settings) {
    if let Some(i) = &mut s.thinkbroadband {
        i.interval_mins = i.interval_mins.clamp(1, 24 * 60);
        i.alert_pct = i.alert_pct.clamp(0.0, 100.0);
        i.layout = i.layout.min(2);
        i.range = i.range.min(2);
    }
}

pub use crate::plugins::core::latency::Sample;
