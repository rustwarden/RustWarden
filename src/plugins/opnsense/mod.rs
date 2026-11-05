//! OPNsense router: what the router sees (leases, firewall log, gateways) comes into RustWarden,
//! and RustWarden's blocks can go back to it as a RustWarden-owned alias. Nothing is contacted until
//! the integration is added, and every option stays off until the API key has been probed to show
//! what it is allowed to do (read only, or read and write).

#![allow(dead_code)] // hidden from the UI until it is ready

pub mod client;
pub mod ui;

use crate::settings::Settings;
use serde::{Deserialize, Serialize};

/// What the API key is allowed to do, as found by the probe.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Caps {
    /// OPNsense version, when it said.
    pub version: String,
    pub leases: bool,
    pub arp: bool,
    pub log: bool,
    pub gateway: bool,
    pub traffic: bool,
    /// None: write access has not been checked (it is only checked when asked for).
    pub write: Option<bool>,
    /// Set when the write check left its test alias behind.
    pub warning: String,
}

impl Caps {
    pub fn any_read(&self) -> bool {
        self.leases || self.arp || self.log || self.gateway || self.traffic
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Integration {
    pub enabled: bool,
    pub name: String,
    /// Base URL of the web interface, e.g. https://192.168.1.1
    pub url: String,
    /// API key and secret (System > Access > Users > API keys), encrypted like the other tokens.
    #[serde(with = "crate::settings::secret")]
    pub key: String,
    #[serde(with = "crate::settings::secret")]
    pub secret: String,
    /// Accept the router's own (self-signed) certificate. Off unless the user turns it on.
    pub allow_self_signed: bool,
    /// Device names and addresses from the router's DHCP leases and ARP table.
    pub pull_devices: bool,
    /// The router's firewall log.
    pub pull_log: bool,
    /// Gateway status and interface traffic.
    pub pull_gateway: bool,
    /// Send RustWarden's blocked addresses to a RustWarden alias on the router.
    pub push_blocks: bool,
    /// What the last probe found, valid only for the address and key it was run with (`caps_for`).
    pub caps: Option<Caps>,
    pub caps_for: String,
}

impl Default for Integration {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "OPNsense".into(),
            url: String::new(),
            key: String::new(),
            secret: String::new(),
            allow_self_signed: false,
            pull_devices: false,
            pull_log: false,
            pull_gateway: false,
            push_blocks: false,
            caps: None,
            caps_for: String::new(),
        }
    }
}

impl Integration {
    pub fn ready(&self) -> bool {
        self.enabled && !self.key.is_empty() && !self.secret.is_empty() && crate::plugins::external_notifications::valid(&self.url, &[])
    }

    /// Why this can't be saved yet, if it can't.
    pub fn problem(&self) -> Option<&'static str> {
        if self.name.trim().is_empty() {
            Some("Enter a name.")
        } else if self.url.trim().is_empty() {
            Some("Enter the address of the OPNsense web interface.")
        } else if !crate::plugins::external_notifications::valid(self.url.trim(), &[]) {
            Some("The address must start with http:// or https://")
        } else if self.key.trim().is_empty() {
            Some("Enter the API key.")
        } else if self.secret.trim().is_empty() {
            Some("Enter the API secret.")
        } else {
            None
        }
    }

    /// Identifies the address and credentials a probe result belongs to.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for part in [&self.url, &self.key, &self.secret] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The probe result, only while it still matches the saved address and key.
    pub fn caps(&self) -> Option<&Caps> {
        self.caps.as_ref().filter(|_| self.caps_for == self.fingerprint())
    }

    pub fn can_pull_devices(&self) -> bool {
        self.caps().is_some_and(|c| c.leases || c.arp)
    }
    pub fn can_pull_log(&self) -> bool {
        self.caps().is_some_and(|c| c.log)
    }
    pub fn can_pull_gateway(&self) -> bool {
        self.caps().is_some_and(|c| c.gateway || c.traffic)
    }
    pub fn can_push(&self) -> bool {
        self.caps().is_some_and(|c| c.write == Some(true))
    }

    /// Switches off every option the key hasn't been shown to allow (also after the address or key changes).
    pub fn gate(&mut self) {
        self.pull_devices &= self.can_pull_devices();
        self.pull_log &= self.can_pull_log();
        self.pull_gateway &= self.can_pull_gateway();
        self.push_blocks &= self.can_push();
    }
}

pub fn sanitize(s: &mut Settings) {
    if let Some(i) = &mut s.opnsense {
        i.url = i.url.trim().trim_end_matches('/').to_owned();
        // Control characters would become extra headers in the request.
        i.key = i.key.trim().chars().filter(|c| !c.is_control()).collect();
        i.secret = i.secret.trim().chars().filter(|c| !c.is_control()).collect();
        i.gate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probed(write: Option<bool>) -> Integration {
        let mut i = Integration { url: "https://fw".into(), key: "k".into(), secret: "s".into(), ..Default::default() };
        i.caps = Some(Caps { leases: true, log: true, write, ..Default::default() });
        i.caps_for = i.fingerprint();
        i
    }

    #[test]
    fn options_stay_off_until_probed() {
        let mut i = Integration { pull_devices: true, pull_log: true, pull_gateway: true, push_blocks: true, ..Default::default() };
        i.gate();
        assert!(!i.pull_devices && !i.pull_log && !i.pull_gateway && !i.push_blocks);
    }

    #[test]
    fn a_read_only_key_cannot_push() {
        let mut i = probed(Some(false));
        (i.pull_devices, i.pull_log, i.pull_gateway, i.push_blocks) = (true, true, true, true);
        i.gate();
        assert!(i.pull_devices && i.pull_log);
        assert!(!i.pull_gateway, "gateway was denied");
        assert!(!i.push_blocks);
        assert!(!probed(None).can_push(), "unchecked write access is not write access");
        assert!(probed(Some(true)).can_push());
    }

    #[test]
    fn changing_the_key_discards_the_probe() {
        let mut i = probed(Some(true));
        i.push_blocks = true;
        i.secret = "other".into();
        assert!(i.caps().is_none());
        i.gate();
        assert!(!i.push_blocks);
    }

    #[test]
    fn saving_needs_a_name_address_key_and_secret() {
        let mut i = Integration::default();
        assert_eq!(i.problem(), Some("Enter the address of the OPNsense web interface."));
        i.url = "192.168.1.1".into();
        assert!(i.problem().unwrap().contains("http"));
        i.url = " https://192.168.1.1 ".into();
        assert_eq!(i.problem(), Some("Enter the API key."));
        i.key = "k".into();
        assert_eq!(i.problem(), Some("Enter the API secret."));
        i.secret = "s".into();
        assert_eq!(i.problem(), None);
        i.name = "  ".into();
        assert_eq!(i.problem(), Some("Enter a name."));
    }
}
