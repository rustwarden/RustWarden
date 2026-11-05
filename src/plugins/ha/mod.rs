//! Home Assistant: names and types for scanned devices, matched by MAC address only.
//! Each network device is looked up once (then hourly while unmatched, daily once matched), so
//! Home Assistant is never polled; devices Home Assistant knows but the network scan hasn't
//! seen are never stored.

pub mod client;
pub mod store;
pub mod ui;
pub mod worker;

use crate::settings::Settings;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Integration {
    pub enabled: bool,
    pub name: String,
    /// Base URL, e.g. http://homeassistant.local:8123
    pub url: String,
    /// Long-lived access token (encrypted in the settings file like the other API keys).
    #[serde(with = "crate::settings::secret")]
    pub token: String,
    /// Show the Home Assistant name instead of the network name on the Scanner tab.
    pub prefer_name: bool,
    /// Show an icon for what the device is (light, plug, sensor...).
    pub show_type: bool,
}

impl Default for Integration {
    fn default() -> Self {
        Self { enabled: true, name: "Home Assistant".into(), url: String::new(), token: String::new(), prefer_name: true, show_type: true }
    }
}

impl Integration {
    pub fn ready(&self) -> bool {
        self.enabled && !self.token.is_empty() && crate::plugins::external_notifications::valid(&self.url, &[])
    }
}

/// What Home Assistant knows about one network device.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HaInfo {
    pub name: String,
    pub area: String,
    pub model: String,
    /// "light", "switch", "sensor", "media" or "other".
    pub kind: String,
    /// Home Assistant's device id, for linking to its page.
    pub device_id: String,
}

/// The integration in use: the first one that is switched on and filled in.
pub fn active(s: &Settings) -> Option<&Integration> {
    s.integrations.iter().find(|i| i.ready())
}

pub fn sanitize(s: &mut Settings) {
    for i in &mut s.integrations {
        i.url = i.url.trim().trim_end_matches('/').to_owned();
        // Control characters would become extra headers in the request.
        i.token = i.token.trim().chars().filter(|c| !c.is_control()).collect();
    }
}
