//! Opt-in permissions: a host call that needs one fails unless the user granted it at install.

use plugin_sdk::HostCall;
use std::collections::BTreeSet;

/// The permission a call needs; `None` for the always-available base calls.
pub fn needed(call: &HostCall) -> Option<&'static str> {
    match call {
        HostCall::PingRound { .. } => Some("ping"),
        HostCall::Devices => Some("devices.annotate"),
        HostCall::RaiseAlert { .. } => Some("alerts.write"),
        HostCall::BrowserSignIn | HostCall::BrowserFetch { .. } | HostCall::BrowserSignOut => Some("browser.session"),
        HostCall::HelperReady { .. } | HostCall::HelperInstall { .. } | HostCall::HelperStart { .. } | HostCall::HelperStop => Some("helper.exe"),
        HostCall::UpnpDiscover => Some("upnp"),
        _ => None,
    }
}

pub fn require(granted: &BTreeSet<String>, call: &HostCall) -> Result<(), String> {
    match needed(call) {
        Some(p) if !granted.contains(p) => Err(format!("permission \"{p}\" was not granted")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ungranted_permission_is_refused() {
        let ping = HostCall::PingRound { addrs: vec!["1.1.1.1".into()], count: 1 };
        assert!(require(&BTreeSet::new(), &ping).is_err());
        assert!(require(&BTreeSet::from(["ping".to_owned()]), &ping).is_ok());
        assert!(require(&BTreeSet::new(), &HostCall::Now).is_ok());
    }
}
