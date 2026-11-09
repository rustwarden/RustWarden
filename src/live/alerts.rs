//! Alert kinds and the pure "what changed" logic behind the monitors. The monitors in
//! `monitors.rs` read the OS and call these; the tests here need no OS.

use super::db::DeviceRow;
use crate::settings::{AlertLevel, AlertOpts, AlertSwitches, Settings};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertKind {
    FirstActivity,
    AppChanged,
    Internet,
    Arp,
    DnsServers,
    Proxy,
    HostsFile,
    NewDevice,
    DeviceSpoof,
    DeviceReturned,
    RemoteSession,
    DataPlan,
    Away,
    FirewallRules,
    Unlock,
    Threat,
    DnsThreat,
    ThinkBroadband,
    UserAccounts,
    ScheduledTasks,
    RootCerts,
    StartupEntries,
    NewServices,
    MicCamera,
    Quota,
    NewListener,
    DnsLeak,
    PublicIp,
    AnomalyContact,
    AnomalyVolume,
    AnomalyHour,
    InboundScan,
    Beaconing,
    DnsTunnel,
    RogueDhcp,
    TlsMismatch,
}

/// Keys of the behaviour-baseline alerts; they carry a "Mark as normal" action.
pub fn is_anomaly_key(key: &str) -> bool {
    matches!(key, "new_contact" | "volume_spike" | "unusual_hour")
}

impl AlertKind {
    /// Stable identifier stored in the database; never rename these.
    pub fn key(self) -> &'static str {
        match self {
            Self::FirstActivity => "first_activity",
            Self::AppChanged => "app_changed",
            Self::Internet => "internet",
            Self::Arp => "arp",
            Self::DnsServers => "dns_servers",
            Self::Proxy => "proxy",
            Self::HostsFile => "hosts_file",
            Self::NewDevice => "new_device",
            Self::DeviceSpoof => "device_spoof",
            Self::DeviceReturned => "device_returned",
            Self::RemoteSession => "remote_session",
            Self::DataPlan => "data_plan",
            Self::Away => "away",
            Self::FirewallRules => "firewall_rules",
            Self::Unlock => "unlock",
            Self::Threat => "threat",
            Self::DnsThreat => "dns_threat",
            Self::ThinkBroadband => "thinkbroadband",
            Self::UserAccounts => "user_accounts",
            Self::ScheduledTasks => "scheduled_tasks",
            Self::RootCerts => "root_certs",
            Self::StartupEntries => "startup_entries",
            Self::NewServices => "new_services",
            Self::MicCamera => "mic_camera",
            Self::Quota => "quota",
            Self::NewListener => "new_listener",
            Self::DnsLeak => "dns_leak",
            Self::PublicIp => "public_ip",
            Self::AnomalyContact => "new_contact",
            Self::AnomalyVolume => "volume_spike",
            Self::AnomalyHour => "unusual_hour",
            Self::InboundScan => "inbound_scan",
            Self::Beaconing => "beaconing",
            Self::DnsTunnel => "dns_tunnel",
            Self::RogueDhcp => "rogue_dhcp",
            Self::TlsMismatch => "tls_mismatch",
        }
    }

    /// Label shown at the right of the alert row.
    pub fn label_for_key(key: &str) -> &'static str {
        match key {
            "first_activity" => "First network activity",
            "app_changed" => "App info changed",
            "internet" => "Internet access",
            "arp" => "ARP table",
            "dns_servers" => "DNS server settings",
            "proxy" => "Proxy settings",
            "hosts_file" => "Hosts file",
            "new_device" => "New device",
            "device_spoof" => "Device spoofing",
            "device_returned" => "Device returned",
            "remote_session" => "Remote Desktop",
            "data_plan" => "Data plan",
            "away" => "While you were away",
            "firewall_rules" => "Firewall rules",
            "unlock" => "Computer unlocked",
            "threat" => "Malicious IP",
            "dns_threat" => "Malicious domain",
            "thinkbroadband" => "Packet loss",
            "user_accounts" => "User account",
            "scheduled_tasks" => "Scheduled task",
            "root_certs" => "Root certificate",
            "startup_entries" => "Startup entry",
            "new_services" => "New service",
            "mic_camera" => "Microphone or camera",
            "quota" => "Data quota",
            "new_listener" => "New listening port",
            "dns_leak" => "DNS leak",
            "public_ip" => "Public IP address",
            "new_contact" => "New country or network",
            "volume_spike" => "Traffic spike",
            "unusual_hour" => "Unusual hour",
            "inbound_scan" => "Port scan or flood",
            "beaconing" => "Regular check-ins",
            "dns_tunnel" => "DNS tunnelling",
            "rogue_dhcp" => "Second DHCP server",
            "tls_mismatch" => "Program fingerprint mismatch",
            _ => "Alert",
        }
    }

    pub const ALL: [AlertKind; 36] = [
        Self::FirstActivity,
        Self::AppChanged,
        Self::Internet,
        Self::Arp,
        Self::DnsServers,
        Self::Proxy,
        Self::HostsFile,
        Self::NewDevice,
        Self::DeviceSpoof,
        Self::DeviceReturned,
        Self::RemoteSession,
        Self::DataPlan,
        Self::Away,
        Self::FirewallRules,
        Self::Unlock,
        Self::Threat,
        Self::DnsThreat,
        Self::ThinkBroadband,
        Self::UserAccounts,
        Self::ScheduledTasks,
        Self::RootCerts,
        Self::StartupEntries,
        Self::NewServices,
        Self::MicCamera,
        Self::Quota,
        Self::NewListener,
        Self::DnsLeak,
        Self::PublicIp,
        Self::AnomalyContact,
        Self::AnomalyVolume,
        Self::AnomalyHour,
        Self::InboundScan,
        Self::Beaconing,
        Self::DnsTunnel,
        Self::RogueDhcp,
        Self::TlsMismatch,
    ];

    /// Name in the settings list.
    pub fn title(self) -> &'static str {
        match self {
            Self::FirstActivity => "First network activity",
            Self::AppChanged => "Application info monitor",
            Self::Internet => "Internet access monitor",
            Self::Arp => "ARP spoofing detection",
            Self::DnsServers => "DNS server settings monitor",
            Self::Proxy => "Proxy settings monitor",
            Self::HostsFile => "System file monitor",
            Self::NewDevice => "Network Scanner: new device",
            Self::DeviceSpoof => "Network Scanner: spoofing",
            Self::DeviceReturned => "Network Scanner: device returned",
            Self::RemoteSession => "RDP detection",
            Self::DataPlan => "Data plan",
            Self::Away => "While you were away",
            Self::FirewallRules => "Firewall rule monitor",
            Self::Unlock => "Computer unlock",
            Self::Threat => "Malicious IP protection",
            Self::DnsThreat => "Malicious domain alerts",
            Self::ThinkBroadband => "thinkbroadband packet loss",
            Self::UserAccounts => "Windows user account monitor",
            Self::ScheduledTasks => "Scheduled task monitor",
            Self::RootCerts => "Root certificate store monitor",
            Self::StartupEntries => "Startup entry monitor",
            Self::NewServices => "New service monitor",
            Self::MicCamera => "Microphone and camera access",
            Self::Quota => "Data quotas",
            Self::NewListener => "Listening port monitor",
            Self::DnsLeak => "VPN DNS leak check",
            Self::PublicIp => "Public IP address monitor",
            Self::AnomalyContact => "Behaviour: new country or network",
            Self::AnomalyVolume => "Behaviour: traffic spike",
            Self::AnomalyHour => "Behaviour: unusual hour",
            Self::InboundScan => "Inbound port scan and flood (Driver mode)",
            Self::Beaconing => "Beaconing detection",
            Self::DnsTunnel => "DNS tunnelling detection",
            Self::RogueDhcp => "Rogue DHCP server detection (Driver mode)",
            Self::TlsMismatch => "TLS fingerprint check (Driver mode)",
        }
    }

    /// Made-up (app, text, target) for the Settings test button.
    pub fn sample(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::FirstActivity => ("demo.exe", "connected to the network for the first time:", "203.0.113.7"),
            Self::AppChanged => ("demo.exe", "was updated: version 1.2 to 1.3", ""),
            Self::Internet => ("", "Internet connection lost, then reconnected", ""),
            Self::Arp => ("", "MAC address for 192.168.1.1 changed to", "aa:bb:cc:dd:ee:ff"),
            Self::DnsServers => ("", "DNS servers changed to", "203.0.113.53"),
            Self::Proxy => ("", "Proxy settings changed to", "203.0.113.80:8080"),
            Self::HostsFile => ("", "The hosts file was modified", ""),
            Self::NewDevice => ("Demo-Phone", "joined the network at", "192.168.1.77"),
            Self::DeviceSpoof => ("HomeNET", "192.168.1.1 now has a different MAC address (possible ARP spoofing):", "02:00:00:00:00:01 → 02:00:00:00:00:99"),
            Self::DeviceReturned => ("HomeNET", "has a device that returned after 21 days away:", "192.168.1.38 (Lamp, Living room)"),
            Self::RemoteSession => ("demouser", "started a Remote Desktop session from", "203.0.113.9"),
            Self::DataPlan => ("", "You have used 75% of your data plan", ""),
            Self::Away => ("", "While you were away: 3 apps used the network", ""),
            Self::FirewallRules => ("", "A RustWarden firewall rule was changed outside RustWarden", ""),
            Self::Unlock => ("", "This computer was unlocked", ""),
            Self::Threat => ("demo.exe", "connected to a malicious IP address", "203.0.113.66"),
            Self::DnsThreat => ("demo.exe", "looked up a malicious domain:", "malware.example"),
            Self::ThinkBroadband => ("", "Packet loss of 5% detected", ""),
            Self::UserAccounts => ("demouser", "Windows account was created", ""),
            Self::ScheduledTasks => ("DemoTask", "scheduled task was added", ""),
            Self::RootCerts => ("Root certificates", "added a trusted root certificate:", "machine 0123456789ABCDEF0123456789ABCDEF01234567"),
            Self::StartupEntries => ("Startup entries", "added a startup entry:", "user Run: Demo=demo.exe"),
            Self::MicCamera => ("demo.exe", "started using the microphone", ""),
            Self::NewServices => ("Services", "added a service or driver:", "DemoSvc"),
            Self::Quota => ("demo.exe", "has used 80% of its monthly quota:", "4.0 GB of 5.0 GB"),
            Self::PublicIp => ("Public IP address", "changed:", "203.0.113.7 → 203.0.113.99 (ISP changed: ExampleNet → OtherNet)"),
            Self::DnsLeak => ("VPN", "is up, but these adapters still use DNS servers outside it:", "Wi-Fi: 8.8.8.8, 1.1.1.1"),
            Self::NewListener => ("demo.exe", "started listening on all network interfaces:", "TCP port 4444"),
            Self::AnomalyContact => ("demo.exe", "contacted a country it never used before. Usual: US, NL.", "DE"),
            Self::AnomalyVolume => ("demo.exe", "sent or received 1.8 GB today. Usual: about 120 MB a day.", ""),
            Self::AnomalyHour => ("demo.exe", "was active at 03:00, an hour it is almost never active in the last 14 days.", ""),
            Self::InboundScan => ("Port scan", "from 203.0.113.7 tried 14 different ports on this PC in a few seconds:", "22, 80, 135, 139, 443, 445, 3389 …"),
            Self::Beaconing => ("demo.exe", "contacts 203.0.113.50 like clockwork, every 60 s (42 times, almost no variation):", "203.0.113.50"),
            Self::DnsTunnel => ("DNS", "sent an unusual number of long, random-looking lookups under one domain:", "x7f3k9q2.exfil.example (84 lookups in 5 minutes)"),
            Self::RogueDhcp => ("DHCP", "answered by more than one server; a second one is not your router:", "192.168.1.1 and 192.168.1.77"),
            Self::TlsMismatch => ("chrome.exe", "opened a TLS connection whose fingerprint belongs to a different program:", "looks like curl (JA3 e7d705a3286e19ea42f587b344ee6865)"),
        }
    }

    /// Text of the "notify me" checkbox.
    pub fn description(self) -> &'static str {
        match self {
            Self::FirstActivity => "Notify me if an application has initiated network activity for the first time.",
            Self::AppChanged => "Notify me if a version, publisher, certificate, or executable of an application has changed.",
            Self::Internet => "Notify me if my internet connection was disconnected or reconnected.",
            Self::Arp => "Notify me if my MAC address associated with my IP address was changed.",
            Self::DnsServers => "Notify me if my DNS server settings were changed or updated.",
            Self::Proxy => "Notify me if my proxy settings were changed.",
            Self::HostsFile => "Notify me if \"hosts\" or \"lmhosts\" files are modified.",
            Self::NewDevice => "Notify me when a device never seen before joins the network (mark devices as trusted in their details).",
            Self::DeviceSpoof => "Notify me when an IP address changes MAC address or one MAC claims several IPs (possible ARP spoofing). A gateway change is always Important.",
            Self::DeviceReturned => "Notify me when a known device comes back after being away for a number of days.",
            Self::RemoteSession => "Notify me about RDP connections.",
            Self::DataPlan => "Notify me when my data plan is nearly used up or over its limit.",
            Self::Away => "Show me a brief summary of any significant network activity that occurred while my computer was idle.",
            Self::FirewallRules => "Notify me when RustWarden's firewall rules are changed outside RustWarden.",
            Self::Unlock => "Record an alert whenever this computer is unlocked.",
            Self::Threat => "Notify me when a program connects to a known malicious or botnet IP address.",
            Self::DnsThreat => "Notify me when a program looks up a domain on a malicious-domain list (turn the lists on in Settings > Malicious IP protection).",
            Self::ThinkBroadband => "Notify me when thinkbroadband's Broadband Quality Monitor sees packet loss (set the level in Settings > Plugins).",
            Self::UserAccounts => "Notify me if a Windows user account is created, activated, deactivated or deleted.",
            Self::ScheduledTasks => "Notify me if a new Windows Task Scheduler task is added (malware often uses one to survive a reboot).",
            Self::RootCerts => "Notify me if a trusted root certificate is added to Windows (malware and interception tools add them to read encrypted traffic).",
            Self::StartupEntries => "Notify me if a program is added to the Run keys or the Startup folders, so it starts with Windows.",
            Self::NewServices => "Notify me if a new Windows service or driver is installed.",
            Self::MicCamera => "Notify me when an app starts using the microphone or camera (from the Windows privacy log).",
            Self::Quota => "Notify me when an app, or all traffic, nears or reaches a data quota (set them in Settings > Quotas).",
            Self::PublicIp => {
                "Notify me when this PC's public IP address (or its ISP) changes, e.g. a new lease, a VPN dropping or a move to another network. Turn the check on in Settings > Countries & Network; it asks a web service for the address."
            }
            Self::DnsLeak => "Notify me when a VPN is connected but a network adapter still points at public DNS servers that are not the VPN's own, so name lookups may bypass the tunnel.",
            Self::NewListener => {
                "Notify me when a program starts listening for connections on a new TCP port. The alert says whether it listens on every interface, the local network address or this PC only."
            }
            Self::AnomalyContact => "Notify me when an app talks to a country or network it has not used in its baseline (Settings > Behaviour baseline).",
            Self::AnomalyVolume => "Notify me when an app moves far more data in a day than its usual amount.",
            Self::AnomalyHour => "Notify me when an app is active at an hour of the day it is almost never active.",
            Self::InboundScan => "Notify me when one address tries many different ports on this PC in a few seconds (a port scan), or when connection attempts arrive in a flood. Needs Driver mode.",
            Self::Beaconing => {
                "Notify me when a program contacts the same address at near-perfectly regular intervals for a long time, the pattern of malware checking in with its controller. Many legitimate apps (updaters, mail, sync) do this too, so add the programs you trust to the ignore list below."
            }
            Self::DnsTunnel => "Notify me when many long, random-looking DNS names are looked up under one domain, the way data is smuggled out through DNS. Needs the DNS log (Settings > Logs).",
            Self::RogueDhcp => "Notify me when more than one device answers DHCP requests on the network, which can hand your PC a wrong gateway or DNS server. Needs Driver mode.",
            Self::TlsMismatch => {
                "Notify me when a program that identifies itself as a web browser makes TLS connections with the fingerprint of some other program, which can mean it is impersonating a browser. Needs Driver mode."
            }
        }
    }

    /// Delivery options used until the user changes them.
    pub fn default_opts(self) -> AlertOpts {
        let (desktop, level) = match self {
            Self::FirstActivity
            | Self::AppChanged
            | Self::Internet
            | Self::HostsFile
            | Self::RemoteSession
            | Self::UserAccounts
            | Self::ScheduledTasks
            | Self::RootCerts
            | Self::StartupEntries
            | Self::MicCamera
            | Self::NewListener
            | Self::DnsLeak
            | Self::InboundScan
            | Self::Beaconing
            | Self::DnsTunnel
            | Self::RogueDhcp
            | Self::TlsMismatch => (true, AlertLevel::Important),
            Self::NewDevice | Self::DeviceReturned | Self::FirewallRules | Self::Unlock => (true, AlertLevel::Logs),
            Self::DeviceSpoof => (true, AlertLevel::Important),
            Self::Arp | Self::DnsServers | Self::Proxy | Self::Away | Self::NewServices | Self::PublicIp => (false, AlertLevel::Logs),
            Self::DataPlan | Self::Quota | Self::DnsThreat | Self::AnomalyContact | Self::AnomalyVolume | Self::AnomalyHour => (false, AlertLevel::Important),
            // The persistent banner already is the desktop notice.
            Self::Threat => (false, AlertLevel::Important),
            Self::ThinkBroadband => (true, AlertLevel::Important),
        };
        AlertOpts { desktop, level, event_log: true, api: true }
    }

    pub fn opts(self, s: &Settings) -> AlertOpts {
        s.alert_opts.get(self.key()).copied().unwrap_or_else(|| self.default_opts())
    }

    pub fn switch_mut(self, s: &mut AlertSwitches) -> &mut bool {
        match self {
            Self::FirstActivity => &mut s.first_activity,
            Self::AppChanged => &mut s.app_changed,
            Self::Internet => &mut s.internet,
            Self::Arp => &mut s.arp,
            Self::DnsServers => &mut s.dns_servers,
            Self::Proxy => &mut s.proxy,
            Self::HostsFile => &mut s.hosts_file,
            Self::NewDevice => &mut s.new_device,
            Self::DeviceSpoof => &mut s.device_spoof,
            Self::DeviceReturned => &mut s.device_returned,
            Self::RemoteSession => &mut s.remote_session,
            Self::DataPlan => &mut s.data_plan,
            Self::Away => &mut s.away,
            Self::FirewallRules => &mut s.firewall_rules,
            Self::Unlock => &mut s.unlock,
            Self::Threat => &mut s.threat,
            Self::DnsThreat => &mut s.dns_threat,
            Self::ThinkBroadband => &mut s.thinkbroadband,
            Self::UserAccounts => &mut s.user_accounts,
            Self::ScheduledTasks => &mut s.scheduled_tasks,
            Self::RootCerts => &mut s.root_certs,
            Self::StartupEntries => &mut s.startup_entries,
            Self::NewServices => &mut s.new_services,
            Self::MicCamera => &mut s.mic_camera,
            Self::Quota => &mut s.quota,
            Self::NewListener => &mut s.new_listener,
            Self::DnsLeak => &mut s.dns_leak,
            Self::PublicIp => &mut s.public_ip,
            Self::AnomalyContact => &mut s.anomaly_contact,
            Self::AnomalyVolume => &mut s.anomaly_volume,
            Self::AnomalyHour => &mut s.anomaly_hour,
            Self::InboundScan => &mut s.inbound_scan,
            Self::Beaconing => &mut s.beaconing,
            Self::DnsTunnel => &mut s.dns_tunnel,
            Self::RogueDhcp => &mut s.rogue_dhcp,
            Self::TlsMismatch => &mut s.tls_mismatch,
        }
    }

    pub fn enabled(self, s: &AlertSwitches) -> bool {
        match self {
            Self::FirstActivity => s.first_activity,
            Self::AppChanged => s.app_changed,
            Self::Internet => s.internet,
            Self::Arp => s.arp,
            Self::DnsServers => s.dns_servers,
            Self::Proxy => s.proxy,
            Self::HostsFile => s.hosts_file,
            Self::NewDevice => s.new_device,
            Self::DeviceSpoof => s.device_spoof,
            Self::DeviceReturned => s.device_returned,
            Self::RemoteSession => s.remote_session,
            Self::DataPlan => s.data_plan,
            Self::Away => s.away,
            Self::FirewallRules => s.firewall_rules,
            Self::Unlock => s.unlock,
            Self::Threat => s.threat,
            Self::DnsThreat => s.dns_threat,
            Self::ThinkBroadband => s.thinkbroadband,
            Self::UserAccounts => s.user_accounts,
            Self::ScheduledTasks => s.scheduled_tasks,
            Self::RootCerts => s.root_certs,
            Self::StartupEntries => s.startup_entries,
            Self::NewServices => s.new_services,
            Self::MicCamera => s.mic_camera,
            Self::Quota => s.quota,
            Self::NewListener => s.new_listener,
            Self::DnsLeak => s.dns_leak,
            Self::PublicIp => s.public_ip,
            Self::AnomalyContact => s.anomaly_contact,
            Self::AnomalyVolume => s.anomaly_volume,
            Self::AnomalyHour => s.anomaly_hour,
            Self::InboundScan => s.inbound_scan,
            Self::Beaconing => s.beaconing,
            Self::DnsTunnel => s.dns_tunnel,
            Self::RogueDhcp => s.rogue_dhcp,
            Self::TlsMismatch => s.tls_mismatch,
        }
    }
}

/// What a scan noticed about one device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    New {
        ip: String,
        mac: String,
    },
    /// `ip` was held by `old_mac` and now answers with `mac`.
    MacChanged {
        ip: String,
        old_mac: String,
        mac: String,
        gateway: bool,
    },
    /// One MAC answered for several IPs in the same scan.
    MultiIp {
        mac: String,
        ips: Vec<String>,
    },
    Returned {
        ip: String,
        mac: String,
        days: i64,
    },
}

/// Compares one scan (`found` = (ip, mac) pairs) with the devices stored before it. An empty
/// `prev` is the first scan of a network: it only learns, so nothing is reported.
/// A new MAC on a known address is only `MacChanged` when it looks like spoofing: the address is a gateway, the old
/// device still answers in this scan (at another address), or the new MAC also answers for another address. Otherwise
/// the router simply handed the address to another device (DHCP), which is reported as that device being new.
pub fn device_events(prev: &[DeviceRow], found: &[(String, String)], gateways: &HashSet<String>, now: i64, return_days: u32) -> Vec<DeviceEvent> {
    let mut out = Vec::new();
    if prev.is_empty() {
        return out;
    }
    let mut by_mac: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (ip, mac) in found {
        let first = !by_mac.contains_key(mac.as_str());
        by_mac.entry(mac).or_default().push(ip);
        let (ip, mac) = (ip.clone(), mac.clone());
        match prev.iter().find(|d| d.mac == mac) {
            None if first => out.push(DeviceEvent::New { ip: ip.clone(), mac: mac.clone() }),
            Some(d) if first && return_days > 0 && !d.trusted && !d.online && now - d.last_seen >= i64::from(return_days) * 86_400 => {
                out.push(DeviceEvent::Returned { ip: ip.clone(), mac: mac.clone(), days: (now - d.last_seen) / 86_400 })
            }
            _ => {}
        }
        if let Some(old) = prev.iter().find(|d| d.ip == ip && d.mac != mac) {
            let gateway = gateways.contains(&ip);
            let old_still_here = found.iter().any(|(_, m)| *m == old.mac);
            let new_answers_twice = found.iter().filter(|(_, m)| *m == mac).count() > 1;
            if gateway || old_still_here || new_answers_twice {
                out.push(DeviceEvent::MacChanged { gateway, old_mac: old.mac.clone(), ip, mac });
            }
        }
    }
    for (mac, ips) in by_mac {
        if ips.len() > 1 {
            out.push(DeviceEvent::MultiIp { mac: mac.to_owned(), ips: ips.into_iter().map(str::to_owned).collect() });
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpChange {
    pub ip: IpAddr,
    pub old_mac: String,
    pub new_mac: String,
}

/// Neighbour entries keyed by (interface index, ip) with their MAC. Only entries that exist in
/// both snapshots with a different MAC count: new and vanished entries are normal churn.
pub fn diff_arp(old: &HashMap<(u32, IpAddr), String>, new: &HashMap<(u32, IpAddr), String>) -> Vec<ArpChange> {
    let mut out: Vec<ArpChange> = new
        .iter()
        .filter_map(|(key, mac)| {
            let before = old.get(key)?;
            (before != mac).then(|| ArpChange { ip: key.1, old_mac: before.clone(), new_mac: mac.clone() })
        })
        .collect();
    out.sort_by_key(|c| c.ip);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsChange {
    pub adapter: String,
    pub added: Vec<IpAddr>,
    pub removed: Vec<IpAddr>,
}

/// DNS servers per adapter. Adapters that appear or disappear are ignored (docking, VPN up/down
/// are separate events); a change on an adapter present in both snapshots is reported.
pub fn diff_dns(old: &BTreeMap<String, BTreeSet<IpAddr>>, new: &BTreeMap<String, BTreeSet<IpAddr>>) -> Vec<DnsChange> {
    new.iter()
        .filter_map(|(adapter, now)| {
            let before = old.get(adapter)?;
            let added: Vec<IpAddr> = now.difference(before).copied().collect();
            let removed: Vec<IpAddr> = before.difference(now).copied().collect();
            (!added.is_empty() || !removed.is_empty()).then(|| DnsChange { adapter: adapter.clone(), added, removed })
        })
        .collect()
}

/// What a new public-IP reading says against the saved "ip|isp" one. `None` for the first reading ever or no change.
pub fn public_ip_change(old: Option<&str>, ip: &str, isp: &str) -> Option<String> {
    let (old_ip, old_isp) = old?.split_once('|')?;
    if old_ip == ip {
        return None;
    }
    Some(match (old_isp.is_empty(), isp.is_empty(), old_isp == isp) {
        (false, false, false) => format!("{old_ip} → {ip} (ISP changed: {old_isp} → {isp})"),
        (_, false, _) => format!("{old_ip} → {ip} ({isp})"),
        _ => format!("{old_ip} → {ip}"),
    })
}

/// Whether `name` contains any of the comma-separated parts in `ignore` (ignoring case).
pub fn adapter_ignored(name: &str, ignore: &str) -> bool {
    let name = name.to_lowercase();
    ignore.split(',').map(|p| p.trim().to_lowercase()).any(|p| !p.is_empty() && name.contains(&p))
}

/// One up, non-loopback adapter as the DNS leak check sees it.
pub struct DnsAdapter {
    pub name: String,
    pub tunnel: bool,
    pub dns: Vec<IpAddr>,
}

/// A DNS server on the open internet: not loopback, private, link-local or carrier-grade NAT.
fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || (v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]))),
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// With a VPN tunnel up, the "adapter: servers" entries for other adapters whose public DNS servers
/// aren't the tunnel's own. Windows may ask those too, which sends lookups around the VPN.
/// shortcut: a router's private DNS forwarder is not flagged, though it forwards to the ISP; list it too if that matters.
pub fn dns_leaks(adapters: &[DnsAdapter]) -> Vec<String> {
    if !adapters.iter().any(|a| a.tunnel) {
        return Vec::new();
    }
    let tunnel_dns: BTreeSet<IpAddr> = adapters.iter().filter(|a| a.tunnel).flat_map(|a| a.dns.iter().copied()).collect();
    adapters
        .iter()
        .filter(|a| !a.tunnel)
        .filter_map(|a| {
            let leaking: Vec<String> = a.dns.iter().filter(|ip| is_public_ip(ip) && !tunnel_dns.contains(*ip)).map(ToString::to_string).collect();
            (!leaking.is_empty()).then(|| format!("{}: {}", a.name, leaking.join(", ")))
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccountChange {
    Created,
    Activated,
    Deactivated,
    Deleted,
}

/// Accounts (name to enabled) that appeared, flipped their enabled state or vanished.
/// Deleted ones come last, so an account created and removed between two polls is the only miss.
pub fn diff_accounts(old: &BTreeMap<String, bool>, new: &BTreeMap<String, bool>) -> Vec<(String, AccountChange)> {
    let mut out: Vec<(String, AccountChange)> = new
        .iter()
        .filter_map(|(name, &on)| match old.get(name) {
            None => Some((name.clone(), AccountChange::Created)),
            Some(&was) if was != on => Some((name.clone(), if on { AccountChange::Activated } else { AccountChange::Deactivated })),
            _ => None,
        })
        .collect();
    out.extend(old.keys().filter(|n| !new.contains_key(*n)).map(|n| (n.clone(), AccountChange::Deleted)));
    out
}

/// Tasks present now that weren't before.
pub fn diff_tasks(old: &BTreeSet<String>, new: &BTreeSet<String>) -> Vec<String> {
    new.difference(old).cloned().collect()
}

/// `CDPUserSvc` for `CDPUserSvc_869e1`: Windows' per-user service instances get a fresh hex suffix each login.
pub fn per_user_base(name: &str) -> Option<&str> {
    let (base, hex) = name.rsplit_once('_')?;
    (!base.is_empty() && (4..=8).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(base)
}

/// Entries whose last-use time moved on, or that are new, since `old`.
pub fn diff_uses(old: &BTreeMap<String, u64>, new: &BTreeMap<String, u64>) -> Vec<String> {
    new.iter().filter(|(k, v)| old.get(*k).is_none_or(|o| *v > o)).map(|(k, _)| k.clone()).collect()
}

/// Names of files whose hash differs between snapshots (including created and deleted ones).
/// An empty hash means "file missing".
pub fn diff_files(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) -> Vec<String> {
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    names.into_iter().filter(|n| old.get(*n).map(String::as_str).unwrap_or("") != new.get(*n).map(String::as_str).unwrap_or("")).cloned().collect()
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PlanLevel {
    Warning,
    Over,
}

/// The highest threshold crossed: 75% warns, 100% is over the limit.
pub fn plan_level(used: f64, limit: f64) -> Option<PlanLevel> {
    if limit <= 0.0 {
        None
    } else if used >= limit {
        Some(PlanLevel::Over)
    } else if used >= limit * 0.75 {
        Some(PlanLevel::Warning)
    } else {
        None
    }
}

/// Remote Desktop sessions by id with the user name; reports who appeared and who left.
pub fn diff_sessions(old: &BTreeMap<u32, String>, new: &BTreeMap<u32, String>) -> (Vec<String>, Vec<String>) {
    let started = new.iter().filter(|(id, _)| !old.contains_key(id)).map(|(_, u)| u.clone()).collect();
    let ended = old.iter().filter(|(id, _)| !new.contains_key(id)).map(|(_, u)| u.clone()).collect();
    (started, ended)
}

/// Two consecutive identical readings are needed before the internet state flips, so one
/// failed probe doesn't raise an alert.
#[derive(Default)]
pub struct Debounce {
    state: Option<bool>,
    candidate: Option<bool>,
}

impl Debounce {
    /// Feeds a reading; returns the new state when it has just changed (never on the first one).
    pub fn feed(&mut self, reading: bool) -> Option<bool> {
        match self.state {
            None => {
                self.state = Some(reading);
                None
            }
            Some(s) if s == reading => {
                self.candidate = None;
                None
            }
            Some(_) if self.candidate == Some(reading) => {
                self.state = Some(reading);
                self.candidate = None;
                Some(reading)
            }
            Some(_) => {
                self.candidate = Some(reading);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn arp_mac_change_is_reported_once() {
        let mut old = HashMap::new();
        old.insert((4, ip("192.168.1.1")), "aa:aa".to_string());
        old.insert((4, ip("192.168.1.9")), "bb:bb".to_string());
        let mut new = old.clone();
        new.insert((4, ip("192.168.1.1")), "cc:cc".into());
        new.insert((4, ip("192.168.1.50")), "dd:dd".into());
        new.remove(&(4, ip("192.168.1.9")));
        assert_eq!(diff_arp(&old, &new), vec![ArpChange { ip: ip("192.168.1.1"), old_mac: "aa:aa".into(), new_mac: "cc:cc".into() }]);
        assert!(diff_arp(&new, &new).is_empty());
    }

    #[test]
    fn dns_changes_per_adapter() {
        let set = |v: &[&str]| v.iter().map(|s| ip(s)).collect::<BTreeSet<_>>();
        let mut old = BTreeMap::new();
        old.insert("Wi-Fi".to_string(), set(&["192.168.1.1"]));
        old.insert("Ethernet".to_string(), set(&["1.1.1.1"]));
        let mut new = old.clone();
        new.insert("Wi-Fi".into(), set(&["8.8.8.8"]));
        new.insert("VPN".into(), set(&["10.0.0.1"]));
        let d = diff_dns(&old, &new);
        assert_eq!(d, vec![DnsChange { adapter: "Wi-Fi".into(), added: vec![ip("8.8.8.8")], removed: vec![ip("192.168.1.1")] }]);
    }

    #[test]
    fn file_hash_changes_include_created_and_deleted() {
        let m = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<BTreeMap<_, _>>();
        let old = m(&[("hosts", "h1"), ("lmhosts", "l1"), ("lmhosts.sam", "")]);
        let new = m(&[("hosts", "h2"), ("lmhosts", "l1"), ("lmhosts.sam", "s1")]);
        assert_eq!(diff_files(&old, &new), vec!["hosts", "lmhosts.sam"]);
        assert!(diff_files(&old, &old).is_empty());
    }

    #[test]
    fn account_and_task_changes() {
        let m = |v: &[(&str, bool)]| v.iter().map(|(n, e)| (n.to_string(), *e)).collect::<BTreeMap<_, _>>();
        let d = diff_accounts(&m(&[("a", true), ("b", true), ("c", false), ("gone", true)]), &m(&[("a", true), ("b", false), ("c", true), ("new", true)]));
        assert_eq!(d, vec![("b".into(), AccountChange::Deactivated), ("c".into(), AccountChange::Activated), ("new".into(), AccountChange::Created), ("gone".into(), AccountChange::Deleted)]);
        let t = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(diff_tasks(&t(&["x", "y"]), &t(&["y", "z"])), vec!["z"]);
    }

    #[test]
    fn per_user_service_suffix_is_recognised() {
        assert_eq!(per_user_base("CDPUserSvc_869e1"), Some("CDPUserSvc"));
        assert_eq!(per_user_base("P9RdrService_1a2b3c"), Some("P9RdrService"));
        assert_eq!(per_user_base("wuauserv"), None);
        assert_eq!(per_user_base("Foo_bar"), None);
    }

    #[test]
    fn device_use_reports_new_and_later_uses() {
        let m = |v: &[(&str, u64)]| v.iter().map(|(k, t)| (k.to_string(), *t)).collect::<BTreeMap<_, _>>();
        let d = diff_uses(&m(&[("a", 5), ("b", 5), ("gone", 1)]), &m(&[("a", 5), ("b", 9), ("c", 2)]));
        assert_eq!(d, vec!["b", "c"]);
    }

    #[test]
    fn data_plan_thresholds() {
        assert_eq!(plan_level(10.0, 100.0), None);
        assert_eq!(plan_level(75.0, 100.0), Some(PlanLevel::Warning));
        assert_eq!(plan_level(100.0, 100.0), Some(PlanLevel::Over));
        assert_eq!(plan_level(5.0, 0.0), None);
        assert!(PlanLevel::Over > PlanLevel::Warning);
    }

    #[test]
    fn sessions() {
        let m = |v: &[(u32, &str)]| v.iter().map(|(i, u)| (*i, u.to_string())).collect::<BTreeMap<_, _>>();
        let (started, ended) = diff_sessions(&m(&[(2, "bob")]), &m(&[(3, "amy")]));
        assert_eq!((started, ended), (vec!["amy".to_string()], vec!["bob".to_string()]));
    }

    #[test]
    fn internet_flips_need_two_readings() {
        let mut d = Debounce::default();
        assert_eq!(d.feed(true), None);
        assert_eq!(d.feed(false), None);
        assert_eq!(d.feed(true), None);
        assert_eq!(d.feed(false), None);
        assert_eq!(d.feed(false), Some(false));
        assert_eq!(d.feed(false), None);
        assert_eq!(d.feed(true), None);
        assert_eq!(d.feed(true), Some(true));
    }

    #[test]
    fn switches_and_keys() {
        let mut s = AlertSwitches::default();
        assert!(AlertKind::Arp.enabled(&s));
        s.arp = false;
        assert!(!AlertKind::Arp.enabled(&s));
        assert_eq!(AlertKind::label_for_key(AlertKind::Away.key()), "While you were away");
        assert_eq!(AlertKind::Away.default_opts().level, AlertLevel::Logs);
    }

    #[test]
    fn opts_override_defaults_and_old_configs_load() {
        let mut s = Settings::default();
        assert_eq!(AlertKind::Proxy.opts(&s), AlertOpts { desktop: false, level: AlertLevel::Logs, event_log: true, api: true });
        s.alert_opts.insert("proxy".into(), AlertOpts { desktop: true, level: AlertLevel::Important, event_log: true, api: true });
        assert_eq!(AlertKind::Proxy.opts(&s).level, AlertLevel::Important);
        *AlertKind::Proxy.switch_mut(&mut s.alerts) = false;
        assert!(!AlertKind::Proxy.enabled(&s.alerts));
        let old = Settings::from_toml("[alerts]\narp = false\n").unwrap();
        assert!(!old.alerts.arp && old.alert_opts.is_empty());
        let round = Settings::from_toml(&toml::to_string_pretty(&s).unwrap()).unwrap();
        assert_eq!(AlertKind::Proxy.opts(&round).level, AlertLevel::Important);
    }

    fn row(ip: &str, mac: &str, last_seen: i64, online: bool, trusted: bool) -> DeviceRow {
        DeviceRow { ip: ip.into(), mac: mac.into(), last_seen, online, trusted, ..Default::default() }
    }

    fn pair(ip: &str, mac: &str) -> (String, String) {
        (ip.into(), mac.into())
    }

    #[test]
    fn device_events_find_new_changed_multi_and_returned() {
        let day = 86_400;
        let now = 100 * day;
        let gw: HashSet<String> = ["192.168.1.1".to_owned()].into();
        let prev = vec![
            row("192.168.1.1", "gw", now, true, false),
            row("192.168.1.5", "tv", now - 30 * day, false, false),
            row("192.168.1.6", "pc", now - 30 * day, false, true),
            row("192.168.1.7", "ph", now - 2 * day, false, false),
        ];
        // First scan of a network only learns.
        assert!(device_events(&[], &[pair("192.168.1.9", "x")], &gw, now, 14).is_empty());
        let found = [pair("192.168.1.1", "evil"), pair("192.168.1.5", "tv"), pair("192.168.1.6", "pc"), pair("192.168.1.7", "ph"), pair("192.168.1.9", "new"), pair("192.168.1.10", "new")];
        let ev = device_events(&prev, &found, &gw, now, 14);
        assert!(ev.contains(&DeviceEvent::MacChanged { ip: "192.168.1.1".into(), old_mac: "gw".into(), mac: "evil".into(), gateway: true }));
        assert!(ev.contains(&DeviceEvent::Returned { ip: "192.168.1.5".into(), mac: "tv".into(), days: 30 }));
        assert!(ev.contains(&DeviceEvent::MultiIp { mac: "new".into(), ips: vec!["192.168.1.9".into(), "192.168.1.10".into()] }));
        // "evil" is new too; "new" is reported once although it answered twice.
        assert_eq!(ev.iter().filter(|e| matches!(e, DeviceEvent::New { .. })).count(), 2);
        // Trusted devices and short absences don't count as returning.
        assert_eq!(ev.iter().filter(|e| matches!(e, DeviceEvent::Returned { .. })).count(), 1);
        // 0 days turns "returned" off.
        assert!(!device_events(&prev, &found, &gw, now, 0).iter().any(|e| matches!(e, DeviceEvent::Returned { .. })));
    }

    #[test]
    fn a_reused_dhcp_address_is_not_spoofing() {
        let now = 100 * 86_400;
        let none = HashSet::new();
        let changed = |ev: &[DeviceEvent]| ev.iter().any(|e| matches!(e, DeviceEvent::MacChanged { .. }));
        let prev = vec![row("192.168.1.20", "laptop", now - 86_400, false, false), row("192.168.1.30", "nas", now, true, false)];
        // The laptop left and the router gave its address to a phone: a new device, not a changed one.
        let ev = device_events(&prev, &[pair("192.168.1.20", "phone"), pair("192.168.1.30", "nas")], &none, now, 14);
        assert!(!changed(&ev) && ev.contains(&DeviceEvent::New { ip: "192.168.1.20".into(), mac: "phone".into() }));
        // The laptop still answers elsewhere while another MAC claims its old address.
        assert!(changed(&device_events(&prev, &[pair("192.168.1.20", "evil"), pair("192.168.1.21", "laptop")], &none, now, 14)));
        // One MAC answering for its own address and the laptop's.
        assert!(changed(&device_events(&prev, &[pair("192.168.1.20", "evil"), pair("192.168.1.99", "evil")], &none, now, 14)));
    }

    #[test]
    fn anomaly_kinds_have_keys_and_switches() {
        for k in [AlertKind::AnomalyContact, AlertKind::AnomalyVolume, AlertKind::AnomalyHour] {
            assert!(is_anomaly_key(k.key()));
            assert_ne!(AlertKind::label_for_key(k.key()), "Alert");
            assert_eq!(k.default_opts().level, AlertLevel::Important);
        }
        assert!(!is_anomaly_key(AlertKind::Quota.key()));
        assert_eq!(AlertKind::ALL.iter().map(|k| k.key()).collect::<HashSet<_>>().len(), AlertKind::ALL.len());
        let mut sw = AlertSwitches::default();
        *AlertKind::AnomalyHour.switch_mut(&mut sw) = false;
        assert!(!AlertKind::AnomalyHour.enabled(&sw) && AlertKind::AnomalyVolume.enabled(&sw));
    }

    #[test]
    fn new_alert_kinds_have_their_own_switch() {
        let mut sw = AlertSwitches::default();
        for k in [AlertKind::DeviceSpoof, AlertKind::DeviceReturned] {
            assert!(k.enabled(&sw));
            *k.switch_mut(&mut sw) = false;
            assert!(!k.enabled(&sw));
        }
        assert_eq!(AlertKind::DeviceSpoof.default_opts().level, AlertLevel::Important);
    }

    #[test]
    fn dns_leak_needs_a_tunnel_and_a_public_server_outside_it() {
        let a = |name: &str, tunnel: bool, dns: &[&str]| DnsAdapter { name: name.into(), tunnel, dns: dns.iter().map(|d| d.parse().unwrap()).collect() };
        // No VPN: nothing to leak around.
        assert!(dns_leaks(&[a("Wi-Fi", false, &["8.8.8.8"])]).is_empty());
        // VPN up, Wi-Fi still on a public server.
        assert_eq!(dns_leaks(&[a("Wi-Fi", false, &["8.8.8.8", "192.168.1.1"]), a("VPN", true, &["10.2.0.1"])]), vec!["Wi-Fi: 8.8.8.8".to_string()]);
        // The tunnel's own server, local ones and a clean setup are fine.
        assert!(dns_leaks(&[a("Wi-Fi", false, &["10.2.0.1", "192.168.1.1", "fe80::1", "100.64.0.1"]), a("VPN", true, &["10.2.0.1"])]).is_empty());
        assert!(dns_leaks(&[a("Wi-Fi", false, &["1.1.1.1"]), a("VPN", true, &["1.1.1.1"])]).is_empty());
    }

    #[test]
    fn ignored_adapters_match_by_part_of_name() {
        let list = "VMware, VirtualBox,, vEthernet";
        assert!(adapter_ignored("VMware Network Adapter VMnet8", list));
        assert!(adapter_ignored("vethernet (WSL)", list));
        assert!(!adapter_ignored("Wi-Fi", list));
        assert!(!adapter_ignored("Wi-Fi", ""));
    }

    #[test]
    fn public_ip_change_text() {
        assert_eq!(public_ip_change(None, "1.1.1.1", "A"), None);
        assert_eq!(public_ip_change(Some("1.1.1.1|A"), "1.1.1.1", "A"), None);
        assert_eq!(public_ip_change(Some("1.1.1.1|A"), "2.2.2.2", "A").unwrap(), "1.1.1.1 → 2.2.2.2 (A)");
        assert_eq!(public_ip_change(Some("1.1.1.1|A"), "2.2.2.2", "B").unwrap(), "1.1.1.1 → 2.2.2.2 (ISP changed: A → B)");
        assert_eq!(public_ip_change(Some("1.1.1.1|"), "2.2.2.2", "").unwrap(), "1.1.1.1 → 2.2.2.2");
    }
}
