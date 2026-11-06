//! Demo mode: fixed placeholder data pinned to the evening in the screenshots.
//!
//! Interactions that change state (blocking an app, marking alerts read, scanning)
//! work, but only against in-memory state that is rebuilt every time Demo is entered.

use crate::data::*;
use crate::settings::{Quota, QuotaAction, Settings};
use crate::util::noise;
use std::sync::Mutex;
use std::time::Instant;

/// Demo mode's pretend driver: installing it only flips this.
static DRIVER_INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct DemoState {
    apps: Vec<FirewallApp>,
    firewall_on: bool,
    mode: FirewallMode,
    alerts: Vec<Alert>,
    /// Each demo network's own devices, so renaming or trusting one doesn't touch the others.
    devices: Vec<(String, Vec<Device>)>,
    scan_net: String,
    blocked: Vec<(String, String)>,
    allowed: Vec<(String, String)>,
    scanning_since: Option<Instant>,
    snooze_until: Option<Instant>,
    popups: Vec<Alert>,
    filter: TrafficFilter,
    dest: Vec<crate::destrules::DestRule>,
    qos: Vec<crate::qos::QosLimit>,
    /// Settings > General > "Split NT Kernel & System by service".
    split_kernel: bool,
    /// Driver mode, which is what lets a limit cover downloads.
    driver_mode: bool,
    domain_rules: Vec<crate::domainblock::DomainRule>,
    domain_list: Option<(String, usize)>,
    capture: Option<(String, Instant)>,
    /// Firewall profiles and the active one.
    profiles: Vec<String>,
    profile: String,
    /// The sample Prompt prompt and malicious-IP warning are raised once per run.
    ask_raised: bool,
    threat_raised: bool,
}

/// Replaces the sample "NT Kernel & System" row with one row per kernel service, as Live mode shows them.
fn split_kernel_rows(apps: Vec<FirewallApp>) -> Vec<FirewallApp> {
    const PARTS: [(&str, &str, &str, f64); 3] =
        [("smb", "Kernel: SMB file sharing", "192.168.1.20", 0.6), ("discovery", "Kernel: Device discovery", "239.255.255.250", 0.3), ("netbios", "Kernel: NetBIOS", "192.168.1.255", 0.1)];
    let mut out = Vec::new();
    for a in apps {
        if a.key != crate::live::apps::SYSTEM_KEY && a.name != "NT Kernel & System" {
            out.push(a);
            continue;
        }
        for (i, (part, name, host, share)) in PARTS.iter().enumerate() {
            let mut row = a.clone();
            row.key = crate::live::apps::service_key(crate::live::apps::SYSTEM_KEY, part);
            row.name = (*name).into();
            row.usage_key = (*name).into();
            row.host = (*host).into();
            row.more_hosts = if i == 0 { a.more_hosts.saturating_sub(2) } else { 1 };
            row.down_rate = a.down_rate * share;
            row.up_rate = a.up_rate * share;
            out.push(row);
        }
    }
    out
}

const DEMO_HW_APPS: [&str; 4] = ["chrome.exe", "Code.exe", "steam.exe", "Teams.exe"];

pub struct MockBackend {
    started: Instant,
    state: Mutex<DemoState>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            state: Mutex::new(DemoState {
                apps: demo_apps(),
                firewall_on: true,
                mode: FirewallMode::ClickToBlock,
                alerts: demo_alerts(),
                devices: demo_networks(),
                scan_net: String::new(),
                blocked: vec![("185.220.101.7".into(), "Blocked by sample threat list".into()), ("45.155.205.233".into(), "Blocked by sample threat list".into())],
                allowed: vec![("203.0.113.9".into(), "Whitelisted in Demo".into())],
                scanning_since: None,
                snooze_until: None,
                popups: Vec::new(),
                filter: TrafficFilter::default(),
                dest: demo_dest_rules(),
                qos: demo_qos_limits(),
                split_kernel: true,
                driver_mode: false,
                domain_rules: vec![crate::domainblock::DomainRule { id: 1, enabled: true, pattern: "ads.tracker-demo.example".into() }],
                domain_list: None,
                capture: None,
                profiles: vec!["Default".into(), "Gaming".into()],
                profile: "Default".into(),
                ask_raised: false,
                threat_raised: false,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, DemoState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How the Traffic filter shrinks the sample data: (download factor, upload factor). The shares are made up,
    /// like the rest of the sample data.
    fn filter_scale(&self) -> (f64, f64) {
        let f = self.state().filter.clone();
        let (mut down, mut up) = match f.dir {
            TrafficDir::Both => (1.0, 1.0),
            TrafficDir::In => (1.0, 0.0),
            TrafficDir::Out => (0.0, 1.0),
        };
        let k = match f.scope {
            Scope::Both => 1.0,
            Scope::Wan => 0.63,
            Scope::Lan => 0.37,
        } * if f.app.is_some() { 0.25 } else { 1.0 }
            * if f.network.trim().is_empty() { 1.0 } else { 0.3 };
        down *= k;
        up *= k;
        (down, up)
    }
}

/// Sample bandwidth limits, so the window has something to show.
fn demo_qos_limits() -> Vec<crate::qos::QosLimit> {
    use crate::qos::QosLimit;
    vec![
        QosLimit::upload(1, true, r"C:\Program Files\Dropbox\Client\Dropbox.exe", 2000),
        QosLimit::upload(2, false, r"C:\Program Files (x86)\Steam\steam.exe", 10_000),
        QosLimit { priority: crate::qos::Priority::High, ..QosLimit::upload(3, true, r"C:\Users\demo\AppData\Roaming\Zoom\bin\Zoom.exe", 0) },
    ]
}

/// Sample destination rules, so the window has something to show.
fn demo_dest_rules() -> Vec<crate::destrules::DestRule> {
    use crate::destrules::{DestRule, Mode, Target};
    vec![
        DestRule { id: 1, enabled: true, mode: Mode::OnlyAllow, target: Target::Domain("wikipedia.org".into()), program: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into() },
        DestRule { id: 2, enabled: true, mode: Mode::Block, target: Target::Country(*b"RU"), program: String::new() },
    ]
}

/// Made-up state line for a Demo destination rule; the ranges are invented, like the rest of the sample data.
fn demo_dest_status(r: &crate::destrules::DestRule) -> String {
    use crate::destrules::{Mode, Target};
    if !r.enabled {
        return "Off".into();
    }
    let n = match &r.target {
        Target::Domain(_) => 3 + crate::destrules::fingerprint(&r.target.text()) % 9,
        Target::Asn(_) => 40 + crate::destrules::fingerprint(&r.target.text()) % 300,
        Target::Country(_) => 8000 + crate::destrules::fingerprint(&r.target.text()) % 9000,
    };
    match r.mode {
        Mode::Block => format!("Blocking {n} address ranges"),
        Mode::OnlyAllow => format!("Allowing only {n} address ranges; the rest is blocked"),
    }
}

/// Made-up open connections for the Live connections tab. Byte counts grow with `now`; the last row is IPv6.
fn demo_connections(now: i64) -> Vec<LiveConn> {
    #[allow(clippy::type_complexity)]
    let rows: [(u32, &str, &str, &str, &str, &str, u64, Country, i64); 7] = [
        (4120, "chrome.exe", "Established", "192.168.1.20:51522", "208.80.154.224:443", "www.wikipedia.org", 900, Country::UnitedStates, 1260),
        (5310, "Spotify.exe", "Established", "192.168.1.20:51801", "35.186.224.25:443", "spclient.wg.spotify.com", 5200, Country::Sweden, 5400),
        (8844, "Steam.exe", "Established", "192.168.1.20:52010", "104.18.20.54:443", "cdn.cloudflare.steamstatic.com", 48_000, Country::UnitedStates, 310),
        (1032, "svchost.exe", "Time wait", "192.168.1.20:52111", "20.101.57.9:123", "time.windows.com", 0, Country::UnitedStates, 45),
        (7720, "curl.exe", "Connecting", "192.168.1.20:52200", "203.0.113.66:80", "cdn.badhost-demo.example", 0, Country::Other, 3),
        (2210, "OneDrive.exe", "Established", "192.168.1.20:52240", "13.107.42.12:443", "storage.live.com", 2300, Country::Ireland, 86_400),
        (4120, "chrome.exe", "Established", "[fd00::20]:52300", "[2620:0:861:ed1a::1]:443", "www.wikipedia.org", 400, Country::UnitedStates, 1260),
    ];
    let killed = DEMO_KILLED.lock().unwrap_or_else(|e| e.into_inner());
    let mut out: Vec<LiveConn> = rows
        .iter()
        .filter(|r| !killed.contains(&r.4.to_owned()))
        .map(|&(pid, app, state, local, remote, host, rate, country, age)| {
            let remote: std::net::SocketAddr = remote.parse().unwrap();
            let up = state == "Established";
            LiveConn {
                pid,
                app: app.into(),
                state: state.into(),
                local: local.parse().unwrap(),
                remote,
                host: host.into(),
                bytes: up.then(|| ((now as u64 % 100_000) * rate, (now as u64 % 100_000) * rate / 8)),
                killable: up && remote.is_ipv4(),
                country: Some(country),
                since: Some(now - age),
            }
        })
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.bytes.map_or(0, |(i, o)| i + o)));
    out
}

/// Remote endpoints "ended" or "blocked" in Demo mode, so the row disappears like it would in Live mode.
static DEMO_KILLED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Made-up lookups for the DNS Log tab, newest first, spread over the last minutes before `now`.
fn demo_dns(now: i64) -> Vec<DnsEntry> {
    // A sample name from a malicious-domain list; `.example` can never be a real address.
    const LISTED: &str = "cdn.badhost-demo.example";
    let rows: [(&str, &str, u16, &[&str], u32); 11] = [
        ("chrome.exe", "www.wikipedia.org", 1, &["208.80.154.224"], 0),
        ("chrome.exe", "www.wikipedia.org", 28, &["2620:0:861:ed1a::1"], 0),
        ("Spotify.exe", "spclient.wg.spotify.com", 1, &["35.186.224.25"], 0),
        ("svchost.exe", "time.windows.com", 1, &["20.101.57.9"], 0),
        ("Teams.exe", "teams.microsoft.com", 5, &["52.113.194.132"], 0),
        ("OneDrive.exe", "storage.live.com", 1, &["13.107.42.12"], 0),
        ("curl.exe", "does-not-exist.invalid", 1, &[], 9003),
        ("firefox.exe", "detectportal.firefox.com", 1, &["34.107.221.82"], 0),
        ("Steam.exe", "cdn.cloudflare.steamstatic.com", 1, &["104.18.20.54", "104.18.21.54"], 0),
        ("Code.exe", "update.code.visualstudio.com", 28, &[], 0),
        ("curl.exe", LISTED, 1, &["203.0.113.66"], 0),
    ];
    rows.iter()
        .enumerate()
        .map(|(i, (app, name, qtype, ips, status))| DnsEntry {
            ts: now - 20 - i as i64 * 37,
            app: (*app).into(),
            name: (*name).into(),
            qtype: *qtype,
            ips: ips.iter().map(|s| (*s).into()).collect(),
            status: *status,
            listed: *name == LISTED,
        })
        .collect()
}

/// How long the placeholder scan "runs".
const SCAN_SECS: f32 = 2.5;

/// "Now" for the mock traffic graph: 9:22 PM.
const MOCK_NOW_MINUTE: f32 = 21.0 * 60.0 + 22.0;

fn bump(x: f32, center: f32, width: f32) -> f32 {
    (-((x - center) / width).powi(2)).exp()
}

const KB: f64 = 1024.0;

fn row(label: &str, kb: f64, up_share: f32, left: Glyph, right: Option<Glyph>) -> UsageRow {
    UsageRow { label: label.into(), key: label.into(), bytes: kb * KB, up_share, left, right }
}

/// The sample quotas Demo shows until the user adds their own.
fn demo_quotas() -> Vec<Quota> {
    let q = |id, app: &str, limit, gb, period, action| Quota { id, app: app.to_lowercase(), app_name: app.into(), limit, gb, period, action, ..Quota::default() };
    use crate::settings::PlanPeriod::{Day, Month};
    vec![
        q(1, "", 50.0, true, Month, QuotaAction::AlertOnly),
        q(2, "Google Chrome", 5.0, true, Month, QuotaAction::AlertOnly),
        q(3, "Google Drive", 500.0, false, Day, QuotaAction::Block),
        q(4, "Claude Code", 2.0, true, Month, QuotaAction::None),
    ]
}

/// Sample VirusTotal verdict for a demo program: mostly clean, two with detections.
fn demo_vt(name: &str) -> Vt {
    match name {
        "Google Chrome" | "Visual Studio Code" | "Claude Code" | "Google Drive" => Vt::Result { bad: 0, total: 72 },
        "portmaster-core_v1-6-10.exe" => Vt::Result { bad: 2, total: 72 },
        "RustDesk Remote Desktop" => Vt::Result { bad: 5, total: 72 },
        _ => Vt::None,
    }
}

fn demo_apps() -> Vec<FirewallApp> {
    use AppIcon::*;
    use Country::*;
    use Verdict::*;
    let app = |name: &str, icon, version: &str, host: &str, country, more, down, up, seed: u64| FirewallApp {
        key: name.to_lowercase(),
        usage_key: name.into(),
        name: name.into(),
        path: String::new(),
        publisher: String::new(),
        signed: None,
        group: AppGroup::Active,
        icon,
        inbound: Blocked,
        outbound: Allowed,
        local: Allowed,
        locked: false,
        version: version.into(),
        host: host.into(),
        host_country: country,
        more_hosts: more,
        down_rate: down,
        up_rate: up,
        activity: (0..40).map(|i| (noise(seed * 100 + i) - 0.55).max(0.0) * 2.0).collect(),
        virustotal: Vt::None,
        hash: String::new(),
        pids: (0..(seed % 4 + 1) as u32).map(|i| 30_000 + seed as u32 * 100 + i * 37).collect(),
        service: String::new(),
        parent: "explorer.exe".into(),
    };
    // A row for one Windows service inside svchost.exe, started by services.exe. Keyed and locked the way Live mode keys them.
    let service = |mut a: FirewallApp, short: &str| {
        a.path = r"C:\Windows\System32\svchost.exe".into();
        a.key = crate::live::apps::service_key(&crate::live::apps::key_for_path(&a.path), &short.to_lowercase());
        a.locked = crate::live::apps::critical_reason(&a.key, &a.path, "", r"c:\windows").is_some();
        a.service = short.into();
        a.parent = "services.exe".into();
        a
    };
    let mut apps = vec![
        app("Google Chrome", Chrome, "155.0.8059.86", "a.nel.cloudflare.com", UnitedStates, 23, 0.0, 0.0, 1),
        app("NT Kernel & System", Generic, "10.0.26100.9712", "192.168.1.1", Local, 18, 0.0, 0.0, 2),
        app("Visual Studio Code", VsCode, "1.143.1", "waws-prod-par-003.cloudapp.net", France, 4, 0.0, 0.0, 3),
        service(app("DNS Client", Generic, "10.0.26100.8754", "192.168.1.1", Local, 3, 172.0, 72.0, 4), "Dnscache"),
        service(app("Windows Update", Generic, "10.0.26100.8754", "tlu.dl.delivery.mp.microsoft.com", UnitedStates, 2, 0.0, 0.0, 5), "wuauserv"),
        service(app("Windows Time", Generic, "10.0.26100.8754", "time.windows.com", UnitedStates, 0, 0.0, 0.0, 6), "W32Time"),
        app("Google Drive", Drive, "132.0", "play.googleapis.com", UnitedStates, 2, 21.0 * KB, 15.0 * KB, 5),
        app("LockApp.exe", Generic, "10.0.26100.9512", "a1834.dscg2.akamai.net", UnitedKingdom, 1, 0.0, 0.0, 6),
        app("Claude Code", ClaudeCode, "2.1.311", "claude.ai", UnitedStates, 1, 783.0, 7.0 * KB, 7),
        app("portmaster-core_v1-6-10.exe", Generic, "0.0", "1.1.1.2", Other, 1, 0.0, 0.0, 8),
        app("RustDesk Remote Desktop", RemoteDesktop, "1.4.1.59", "remote.vdevelopments.com", Germany, 0, 0.0, 0.0, 9),
        app("Microsoft Cross Device Service", Monitor, "1.26082.74", "signalrp2-relayhub-prod-eu.servicebus.windows.net", Netherlands, 0, 13.0, 0.0, 10),
        app("Claude", Claude, "4.29", "claude.ai", UnitedStates, 0, 0.0, 0.0, 11),
        app("pia-service.exe", Generic, "0.0", "apiv2.privateinternetaccess.com", Other, 0, 0.0, 0.0, 12),
        app("Bitwarden", Bitwarden, "2026.9.1", "192.168.1.1", Local, 0, 0.0, 0.0, 13),
    ];
    apps[1].inbound = Allowed;
    apps[1].locked = true;
    for a in apps.iter_mut().filter(|a| a.locked) {
        a.group = AppGroup::Windows;
    }
    apps
}

fn demo_alerts() -> Vec<Alert> {
    use AppIcon::*;
    use Country::*;
    let alert = |id, app: &str, icon, target: &str, country, time: &str, day: &str, unread| Alert {
        id,
        app: app.into(),
        icon,
        text: "initiated its first network connection to".into(),
        target: target.into(),
        country: Some(country),
        kind: "First network activity".into(),
        time: time.into(),
        day: day.into(),
        ts: 0,
        unread,
        important: true,
        anomaly: false,
    };
    let net = |id, kind: &str, text: &str, target: &str, time: &str, important| Alert {
        text: text.into(),
        target: target.into(),
        kind: kind.into(),
        country: Some(Local),
        important,
        ..alert(id, "HomeNET", Generic, "", Local, time, "Today", important)
    };
    let mut alerts = vec![
        alert(1, "Windows® installer", Installer, "eip-terr-eu.cdp1.digicert.com.akahost.net", Germany, "8:58 pm", "Today", true),
        alert(2, "FileDownloader", Generic, "crl.comodoca.com.cdn.cloudflare.net", Other, "8:53 pm", "Today", true),
        alert(3, "SamsungMagicianSVC", Generic, "5irh2yf.impervadns.net", UnitedStates, "8:53 pm", "Today", true),
        alert(4, "Bitwarden", Bitwarden, "192.168.1.1", Local, "8:52 pm", "Today", true),
        alert(5, "Claude", Claude, "192.168.1.1", Local, "8:49 pm", "Today", true),
        alert(6, "Claude Code", ClaudeCode, "api.anthropic.com", UnitedStates, "4:43 pm", "Today", true),
        alert(7, "Google Drive", Drive, "play.googleapis.com", UnitedStates, "11:02 am", "Today", true),
        alert(8, "Visual Studio Code", VsCode, "marketplace.visualstudio.com", UnitedStates, "9:15 pm", "Yesterday", false),
        alert(9, "RustDesk Remote Desktop", RemoteDesktop, "remote.vdevelopments.com", Germany, "6:40 pm", "Yesterday", false),
        alert(10, "Google Chrome", Chrome, "a.nel.cloudflare.com", UnitedStates, "2:04 pm", "Yesterday", false),
    ];
    alerts.extend([
        net(11, "Device spoofing", "gateway changed MAC address (possible ARP spoofing):", "192.168.1.1: 02:00:00:00:00:01 → 02:00:00:00:00:99", "8:40 pm", true),
        net(12, "Device returned", "has a device back after 21 days away:", "192.168.1.38 (02:00:00:00:00:38) – Lamp, Living room", "8:12 pm", false),
        net(13, "New device", "has a new device:", "192.168.1.77 (02:00:00:00:00:77) – Espressif", "7:55 pm", false),
        Alert {
            text: "looked up a malicious domain:".into(),
            kind: "Malicious domain".into(),
            country: None,
            ..alert(14, "curl.exe", Generic, "cdn.badhost-demo.example", Other, "7:40 pm", "Today", true)
        },
        Alert {
            text: "contacted a country it has not used before; usual: US, NL.".into(),
            target: "203.0.113.20 (DE)".into(),
            kind: "New country or network".into(),
            anomaly: true,
            ..alert(15, "demo.exe", Generic, "", Germany, "5:12 pm", "Today", true)
        },
        Alert {
            text: "moved 1.8 GB today; usual about 120 MB a day (limit 300 MB).".into(),
            target: String::new(),
            kind: "Traffic spike".into(),
            country: None,
            anomaly: true,
            ..alert(16, "demo.exe", Generic, "", Other, "4:30 pm", "Today", true)
        },
        Alert {
            text: "was active at 03:00, an hour it was active in on only 0 of the last 14 days.".into(),
            target: String::new(),
            kind: "Unusual hour".into(),
            country: None,
            anomaly: true,
            ..alert(17, "demo.exe", Generic, "", Other, "3:00 am", "Today", true)
        },
    ]);
    alerts
}

fn demo_devices() -> Vec<Device> {
    use DeviceKind::*;
    let seen = crate::clock::now_unix() - 4 * 86_400;
    let dev = |kind, description: &str, system: &str, ip: &str, mac: &str| Device {
        name: String::new(),
        online: false,
        kind,
        description: description.into(),
        system: system.into(),
        ip: ip.into(),
        mac: mac.into(),
        last_seen: seen,
        first_seen: seen,
        seen_count: 1,
        ports: if system.is_empty() { vec![80, 443] } else { vec![8008, 8443] },
        note: None,
        trusted: true,
    };
    let mut devices = vec![
        dev(Generic, "TP-Link", "", "192.168.1.2", "02:00:00:00:00:02"),
        dev(SmartDevice, "Espressif", "Chromecast", "192.168.1.38", "02:00:00:00:00:38"),
        dev(WiFi, "TP-Link, EAP723", "", "192.168.1.237", "02:00:00:00:01:37"),
        dev(Laptop, "Framework", "Windows", "192.168.1.32", "02:00:00:00:00:32"),
        dev(SmartDevice, "Tuya", "", "192.168.1.42", "02:00:00:00:00:42"),
        dev(SmartDevice, "Espressif", "Chromecast", "192.168.1.134", "02:00:00:00:01:34"),
        dev(WiFi, "TP-Link, EAP723", "", "192.168.1.62", "02:00:00:00:00:62"),
        dev(Raspberry, "Raspberry Pi", "Chromium OS", "192.168.1.4", "02:00:00:00:00:04"),
        dev(Generic, "Other VLAN or subnet", "", "10.20.0.14", "ip:10.20.0.14"),
    ];
    devices[3].online = true;
    devices[7].trusted = false;
    devices
}

/// The three demo networks, each seeing a different part of the sample devices.
fn demo_networks() -> Vec<(String, Vec<Device>)> {
    let all = demo_devices();
    let pick = |idx: &[usize]| idx.iter().map(|&i| all[i].clone()).collect();
    vec![("HomeNET".into(), all.clone()), ("HomeNET-5G".into(), pick(&[0, 2, 3])), ("Ethernet".into(), pick(&[0, 4]))]
}

impl Backend for MockBackend {
    fn speedtest_route(&self, _server_ip: &str, _client_ip: &str) -> Option<crate::ui::speed::SpeedRoute> {
        // Northampton to London.
        Some(crate::ui::speed::SpeedRoute { home: (-0.9, 52.24), server: (-0.13, 51.51) })
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities { live: false, elevated: true, per_app_traffic: true, firewall_write: true, firewall_modes: [true; 3], scanner: true, geo_db: true }
    }

    fn status(&self) -> Vec<StatusNote> {
        Vec::new()
    }

    fn map_data(&self, _range: TimeRange) -> MapData {
        let c = |lon, lat, count, key: &str| MapConnection { lon, lat, count, down: 1.0, up: if count > 2 { 1.0 } else { 0.0 }, blocked: 0, label: String::new(), key: key.into() };
        let blocked = |lon, lat, blocked, key: &str| MapConnection { blocked, ..c(lon, lat, 0, key) };
        MapData {
            home: (-1.0, 52.0),
            connections: vec![
                c(-98.0, 38.0, 8, "United States"),
                c(10.0, 51.0, 1, "Germany"),
                c(12.5, 42.0, 5, "France"),
                c(105.0, 58.0, 2, "Sweden"),
                blocked(37.6, 55.7, 14, "Russia"),
                blocked(116.4, 39.9, 6, "China"),
            ],
            active: ["USA", "GBR", "DEU", "ITA", "FRA", "ESP", "POL", "RUS", "UKR", "GRC", "ROU", "BGR", "SRB"].map(String::from).to_vec(),
        }
    }

    fn traffic_history(&self, range: TimeRange) -> TrafficHistory {
        let n = 180;
        let (dk, uk) = self.filter_scale();
        let span = range.minutes();
        let step = span / (n - 1) as f32;
        let samples = (0..n)
            .map(|i| {
                let x = i as f32 / (n - 1) as f32;
                let spike = bump(x, 0.035, 0.006) + 0.35 * bump(x, 0.042, 0.004);
                let tail = 0.06 * (bump(x, 0.83, 0.012) + bump(x, 0.89, 0.02) + 0.8 * bump(x, 0.96, 0.015)) + 0.04 * bump(x, 0.995, 0.01);
                let jitter = 0.004 * noise(i as u64);
                TrafficSample { down: dk as f32 * 70.0 * 1024.0 * (spike + tail + jitter), up: uk as f32 * 32.0 * 1024.0 * (bump(x, 0.034, 0.005) + 0.5 * tail + jitter) }
            })
            .collect();
        TrafficHistory { start_minute: MOCK_NOW_MINUTE - span, step_minutes: step, samples }
    }

    fn totals(&self, _range: TimeRange, window: (f32, f32)) -> Totals {
        // Placeholder: scale fixed totals by how much of the range is selected.
        let k = ((window.1 - window.0) / 0.15).clamp(0.05, 6.0) as f64;
        let (dk, uk) = self.filter_scale();
        let mix = |down: f64, share: f64| down * (1.0 - share) * dk + down * share * uk;
        // wan and lan are totals of both directions, so they follow the direction factors by their upload share.
        let (wan, lan) = (78.4 * KB * k, 46.2 * KB * k);
        Totals { down: 101.4 * KB * k * dk, up: 23.2 * KB * k * uk, down_rate: 0.0, up_rate: 0.0, wan: mix(wan, 0.18), lan: mix(lan, 0.17) }
    }

    fn breakdown(&self, _range: TimeRange, _window: (f32, f32)) -> UsageBreakdown {
        use AppIcon::*;
        use Country::*;
        use Glyph::{App, Flag, More};
        let win = Some(Glyph::Window);
        let filter = self.state().filter.clone();
        let (dk, uk) = self.filter_scale();
        let mut b = UsageBreakdown {
            apps: vec![
                row("DNS Client", 70.3, 0.1, App(Generic), Some(Flag(Local))),
                row("Windows Update", 17.2, 0.1, App(Generic), Some(Flag(UnitedStates))),
                row("Windows Time", 2.8, 0.0, App(Generic), Some(Flag(UnitedStates))),
                row("portmaster-core_v1-6-10.exe", 26.0, 0.1, App(Generic), Some(Flag(Other))),
                row("RustWarden Control Service", 6.1, 0.15, App(Generic), Some(Flag(Sweden))),
                row("NT Kernel & System", 2.0, 0.3, App(Generic), Some(Flag(Local))),
                row("HASS.Agent.Satellite.Service", 0.17, 0.5, App(Gear), Some(Flag(Local))),
            ],
            hosts: vec![
                row("239.255.255.250", 31.8, 0.3, Flag(Local), win),
                row("neu-7.frontdoor.licensing.microsoft.com", 20.1, 0.25, Flag(Ireland), win),
                row("1.1.1.2", 14.5, 0.3, Flag(Other), win),
                row("192.168.1.1", 12.3, 0.25, Flag(Local), win),
                row("e12358.d.akamaiedge.net", 11.5, 0.12, Flag(UnitedKingdom), win),
                row("wns.notify.trafficmanager.net", 10.6, 0.15, Flag(UnitedKingdom), win),
                row("cdn.infra.sfng.at", 10.4, 0.2, Flag(Germany), win),
                row("api-eu-north-1.protect.rustwarden.com", 6.1, 0.2, Flag(Sweden), win),
                row("array803.prod.do.dsp.mp.microsoft.com", 4.0, 0.2, Flag(UnitedStates), win),
                row("192.168.1.255", 0.89, 0.3, Flag(Local), win),
                row("+8 more", 2.6, 0.2, More, win),
            ],
            traffic_types: vec![
                row("Hypertext Transfer Protocol over TLS (HTTPS)", 62.7, 0.1, Glyph::Window, None),
                row("Microsoft SSDP Enables discovery of UPnP devices", 31.8, 0.3, Glyph::Window, None),
                row("Other", 14.1, 0.3, Glyph::Window, None),
                row("Domain Name System (DNS)", 13.5, 0.25, Glyph::Window, None),
                row("NetBIOS Name Service", 0.89, 0.2, Glyph::Window, None),
                row("Hypertext Transfer Protocol (HTTP)", 0.73, 0.2, Glyph::Window, None),
                row("Bootstrap Protocol (BOOTP)", 0.61, 0.2, Glyph::Window, None),
                row("MQ Telemetry Transport (MQTT)", 0.2, 0.2, Glyph::Window, None),
                row("Multicast DNS (mDNS)", 0.1, 0.2, Glyph::Window, None),
            ],
            countries: vec![
                row("Local Network", 46.2, 0.17, Flag(Local), None),
                row("United Kingdom", 22.6, 0.15, Flag(UnitedKingdom), None),
                row("Ireland", 20.1, 0.25, Flag(Ireland), None),
                row("Other", 15.0, 0.2, Flag(Other), None),
                row("Germany", 10.4, 0.2, Flag(Germany), None),
                row("Sweden", 6.1, 0.2, Flag(Sweden), None),
                row("United States", 4.0, 0.2, Flag(UnitedStates), None),
                row("France", 0.36, 0.3, Flag(France), None),
            ],
        };
        if let Some((key, _)) = &filter.app {
            b.apps.retain(|r| &r.key == key);
        }
        let network = filter.network.trim().to_lowercase();
        if !network.is_empty() {
            b.hosts.retain(|r| r.label.to_lowercase().contains(&network));
        }
        // The app and network narrowing is already in `dk`/`uk`; the rows only need the direction mix.
        for r in b.apps.iter_mut().chain(&mut b.hosts).chain(&mut b.traffic_types).chain(&mut b.countries) {
            let (down, up) = (r.bytes * f64::from(1.0 - r.up_share) * dk, r.bytes * f64::from(r.up_share) * uk);
            r.bytes = down + up;
            r.up_share = if r.bytes > 0.0 { (up / r.bytes) as f32 } else { 0.0 };
        }
        b
    }

    fn usage_detail(&self, range: TimeRange, window: (f32, f32), kind: UsageKind, key: &str) -> Option<UsageDetail> {
        // Placeholder: the clicked row's neighbours from the fixed data, split in plausible shares.
        let b = self.breakdown(range, window);
        let (rows, glyph) = match kind {
            UsageKind::App => (&b.hosts, b.apps.iter().find(|r| r.key == key)?.left),
            UsageKind::Host => (&b.apps, b.hosts.iter().find(|r| r.key == key)?.left),
            UsageKind::TrafficType => (&b.apps, Glyph::Window),
            UsageKind::Country => (&b.hosts, b.countries.iter().find(|r| r.key == key)?.left),
        };
        let detail_rows = rows
            .iter()
            .take(4)
            .enumerate()
            .map(|(i, r)| {
                let share = 1.0 / (i as f64 + 1.5);
                DetailRow {
                    label: r.label.clone(),
                    left: r.left,
                    right: (kind == UsageKind::Country).then_some(Glyph::Window),
                    extra: if kind == UsageKind::Country && i % 2 == 0 { "+1".into() } else { String::new() },
                    down: r.bytes * share * (1.0 - r.up_share as f64),
                    up: r.bytes * share * r.up_share as f64,
                    target: match kind {
                        UsageKind::App | UsageKind::Country => Some((UsageKind::Host, r.key.clone())),
                        UsageKind::Host | UsageKind::TrafficType => Some((UsageKind::App, r.key.clone())),
                    },
                }
            })
            .collect();
        let facts = if kind == UsageKind::Host { vec![("Region".to_owned(), "United States".to_owned()), ("IP".to_owned(), "160.79.104.10".to_owned())] } else { Vec::new() };
        let heading = match kind {
            UsageKind::App => "Hosts",
            UsageKind::Country => "Apps",
            _ => "App",
        };
        Some(UsageDetail { title: key.to_owned(), glyph, facts, heading: heading.into(), rows: detail_rows }.with_all())
    }

    fn firewall_info(&self) -> FirewallInfo {
        let s = self.state();
        FirewallInfo {
            enabled: s.firewall_on,
            mode: s.mode,
            engine: EngineState::Ready,
            block_all_active: s.mode == FirewallMode::BlockAll,
            rule_count: s.apps.iter().filter(|a| a.inbound == Verdict::Blocked || a.outbound == Verdict::Blocked).count(),
            read_only: None,
        }
    }

    fn firewall_apps(&self) -> Vec<FirewallApp> {
        // Sample VirusTotal verdicts, so the banner and the Firewall column show in Demo.
        let st = self.state();
        let apps = if st.split_kernel { split_kernel_rows(st.apps.clone()) } else { st.apps.clone() };
        apps.into_iter()
            .map(|mut a| {
                a.virustotal = demo_vt(&a.name);
                a
            })
            .collect()
    }

    /// Made-up "AS number · owner" for any address that isn't on the local network.
    fn net_info(&self, host: &str) -> String {
        if host.is_empty() || host.starts_with("192.168.") || host.starts_with("10.") {
            return String::new();
        }
        const NETS: [&str; 4] = ["AS15169 · Google LLC", "AS13335 · Cloudflare, Inc.", "AS8075 · Microsoft Corporation", "AS16509 · Amazon.com, Inc."];
        NETS[host.bytes().map(usize::from).sum::<usize>() % NETS.len()].into()
    }

    fn quotas(&self, settings: &Settings) -> Vec<QuotaStatus> {
        // Quotas added in Demo get made-up usage; with none, a sample set shows the feature.
        let own: Vec<Quota> = if settings.quotas.is_empty() { demo_quotas() } else { settings.quotas.iter().filter(|q| q.enabled).cloned().collect() };
        own.into_iter()
            .enumerate()
            .map(|(i, quota)| {
                let limit = quota.limit_bytes();
                let used = limit * [0.35, 0.86, 1.04, 0.62][i % 4];
                let level = crate::live::quota::level(used, limit, quota.warn_pct);
                let name = if quota.app.is_empty() { "All traffic".to_owned() } else { quota.app_name.clone() };
                let blocked = level == QuotaLevel::Over && quota.action.blocks();
                let throttled = !blocked && quota.action.throttles() && (level == QuotaLevel::Over || (level == QuotaLevel::Warn && quota.action == QuotaAction::ThrottleBlock));
                QuotaStatus { quota, name, used, limit, level, blocked, throttled }
            })
            .collect()
    }

    fn block_program(&self, path: &str) -> Result<String, String> {
        Ok(format!("Demo: {} would be blocked", path.rsplit(['\\', '/']).next().unwrap_or(path)))
    }

    fn set_verdict(&self, key: &str, direction: Direction, verdict: Verdict) -> Result<(), String> {
        let mut s = self.state();
        let app = s.apps.iter_mut().find(|a| a.key == key).ok_or("Unknown app")?;
        if app.locked {
            return Err(format!("{} can't be blocked", app.name));
        }
        match direction {
            Direction::In => app.inbound = verdict,
            Direction::Out => app.outbound = verdict,
            Direction::Local => app.local = verdict,
        }
        Ok(())
    }

    fn remove_app(&self, key: &str) -> Result<(), String> {
        self.state().apps.retain(|a| a.key != key || a.locked);
        Ok(())
    }

    fn set_firewall_enabled(&self, on: bool) -> Result<(), String> {
        self.state().firewall_on = on;
        Ok(())
    }

    fn test_alert(&self, kind: &str, _s: &Settings) {
        // Nothing is sent outside the app in Demo; only the popup shows.
        let Some(kind) = crate::live::alerts::AlertKind::ALL.into_iter().find(|k| k.key() == kind) else { return };
        let (app, text, target) = kind.sample();
        // Alert rules apply here too, so a rule can be tried with the test button.
        let (minute, weekday) = crate::alertrules::when(crate::clock::now_unix());
        let info = crate::alertrules::AlertInfo { kind: kind.key(), app, text, target, minute, weekday };
        let effect = crate::alertrules::decide(&_s.alert_rules, &info, &mut std::collections::HashMap::new(), crate::clock::now_unix());
        if effect.mute {
            return;
        }
        self.state().popups.push(Alert {
            id: 0,
            icon: AppIcon::Generic,
            app: app.into(),
            text: text.into(),
            target: target.into(),
            country: None,
            kind: kind.title().into(),
            time: String::new(),
            day: String::new(),
            ts: crate::clock::now_unix(),
            unread: true,
            important: effect.escalate,
            anomaly: false,
        });
    }

    fn take_popups(&self, _visible: bool) -> Vec<Alert> {
        std::mem::take(&mut self.state().popups)
    }

    fn blocked_ips(&self) -> Vec<(String, String)> {
        self.state().blocked.clone()
    }

    fn threat_whitelist(&self) -> Vec<(String, String)> {
        self.state().allowed.clone()
    }

    fn threat_act(&self, ip: &str, act: ThreatAct) -> Result<(), String> {
        let mut s = self.state();
        let meta = |l: &[(String, String)]| l.iter().find(|(i, _)| i == ip).map(|(_, m)| m.clone());
        let note = meta(&s.blocked).or_else(|| meta(&s.allowed)).unwrap_or_else(|| "Added in Demo".into());
        s.blocked.retain(|(i, _)| i != ip);
        match act {
            ThreatAct::Block => s.blocked.push((ip.into(), note)),
            ThreatAct::Whitelist => s.allowed.push((ip.into(), note)),
            ThreatAct::Unwhitelist => s.allowed.retain(|(i, _)| i != ip),
            ThreatAct::Unblock => {}
        }
        Ok(())
    }

    fn set_traffic_filter(&self, filter: &TrafficFilter) {
        self.state().filter = filter.clone();
    }

    fn set_firewall_mode(&self, mode: FirewallMode) -> Result<(), String> {
        self.state().mode = mode;
        Ok(())
    }

    fn import_firewall_rules(&self, _rename: bool) -> Result<usize, String> {
        Ok(0)
    }

    fn block_windows_extras(&self) -> Result<usize, String> {
        Ok(0)
    }

    fn windows_extras_state(&self) -> Vec<(bool, bool)> {
        Vec::new()
    }

    fn windows_extras_act(&self, _group: usize, _act: crate::live::firewall::ExtrasAct) -> Result<usize, String> {
        Ok(0)
    }

    fn p2p_apps(&self) -> Vec<crate::data::P2pApp> {
        let now = crate::clock::now_unix();
        [(r"c:\program files\qbittorrent\qbittorrent.exe", "qBittorrent", 90), (r"c:\users\demo\appdata\local\transmission\transmission-qt.exe", "Transmission", 3600)]
            .into_iter()
            .map(|(key, name, ago)| crate::data::P2pApp { key: key.into(), name: name.into(), last_seen: now - ago })
            .collect()
    }

    fn dest_rules(&self) -> Vec<crate::destrules::DestRuleView> {
        self.state().dest.iter().map(|r| crate::destrules::DestRuleView { status: demo_dest_status(r), rule: r.clone(), problem: false }).collect()
    }

    fn save_dest_rule(&self, mut rule: crate::destrules::DestRule) -> Result<(), String> {
        if let Some(problem) = rule.problem() {
            return Err(problem.into());
        }
        let mut s = self.state();
        if rule.id == 0 {
            rule.id = s.dest.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            s.dest.push(rule);
        } else if let Some(slot) = s.dest.iter_mut().find(|r| r.id == rule.id) {
            *slot = rule;
        }
        Ok(())
    }

    fn remove_dest_rule(&self, id: u32) -> Result<(), String> {
        self.state().dest.retain(|r| r.id != id);
        Ok(())
    }

    fn capture_status(&self) -> Option<crate::pcap::CaptureStatus> {
        self.state().capture.as_ref().map(|(path, at)| {
            let n = at.elapsed().as_secs() * 37;
            crate::pcap::CaptureStatus { path: path.clone(), packets: n, bytes: n * 900, what: "demo.exe (sample)".into() }
        })
    }

    fn start_capture(&self, conn: &LiveConn) -> Result<String, String> {
        let path = format!(r"C:\Users\Demo\AppData\Local\RustWarden\captures\{}-demo.pcap", conn.app);
        self.state().capture = Some((path.clone(), Instant::now()));
        Ok(path)
    }

    fn stop_capture(&self) {
        self.state().capture = None;
    }

    fn domain_blocks(&self) -> crate::domainblock::DomainView {
        let s = self.state();
        let n = s.domain_rules.iter().filter(|r| r.enabled).count() + s.domain_list.as_ref().map_or(0, |l| l.1);
        let status = if !s.driver_mode {
            "Blocking by domain needs Driver mode.".to_owned()
        } else if n == 0 {
            "Nothing to block yet.".to_owned()
        } else {
            format!("Active: {n} domain(s) blocked; 3 connection(s) stopped since start.")
        };
        crate::domainblock::DomainView {
            rules: s.domain_rules.clone(),
            list_count: s.domain_list.as_ref().map_or(0, |l| l.1),
            list_url: s.domain_list.as_ref().map_or_else(String::new, |l| l.0.clone()),
            status,
            problem: false,
        }
    }

    fn save_domain_block(&self, mut rule: crate::domainblock::DomainRule) -> Result<(), String> {
        rule.pattern = crate::domainblock::normalize(&rule.pattern).map_err(str::to_owned)?;
        let mut s = self.state();
        if s.domain_rules.iter().any(|r| r.id != rule.id && r.pattern == rule.pattern) {
            return Err("That domain is already in the list.".into());
        }
        if rule.id == 0 {
            rule.id = s.domain_rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            s.domain_rules.push(rule);
        } else if let Some(slot) = s.domain_rules.iter_mut().find(|r| r.id == rule.id) {
            *slot = rule;
        }
        Ok(())
    }

    fn remove_domain_block(&self, id: u32) -> Result<(), String> {
        self.state().domain_rules.retain(|r| r.id != id);
        Ok(())
    }

    fn import_domain_list(&self, url: &str) -> Result<usize, String> {
        if !url.trim().starts_with("https://") {
            return Err("The list address must start with https://".into());
        }
        self.state().domain_list = Some((url.trim().to_owned(), 12_345));
        Ok(12_345)
    }

    fn clear_domain_list(&self) -> Result<(), String> {
        self.state().domain_list = None;
        Ok(())
    }

    fn driver_state(&self) -> crate::driver::DriverState {
        if DRIVER_INSTALLED.load(std::sync::atomic::Ordering::Relaxed) { crate::driver::DriverState::Ready } else { crate::driver::DriverState::Missing }
    }

    fn install_driver(&self) -> Result<(), String> {
        for step in ["Downloading WinDivert…", "Checking the download…", "Unpacking…"] {
            crate::driver::set_progress(step);
            std::thread::sleep(std::time::Duration::from_millis(700));
        }
        DRIVER_INSTALLED.store(true, std::sync::atomic::Ordering::Relaxed);
        crate::driver::set_progress("");
        Ok(())
    }

    fn remove_driver(&self) -> Result<(), String> {
        DRIVER_INSTALLED.store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn qos_limits(&self) -> Vec<crate::qos::QosView> {
        let s = self.state();
        let driver = s.driver_mode;
        s.qos
            .iter()
            .map(|l| {
                let (status, problem) = match (l.enabled, driver, l.dir.down()) {
                    (false, _, _) => ("Off".to_owned(), false),
                    (true, false, _) if l.kbps == 0 && l.priority != crate::qos::Priority::Normal => {
                        (format!("Active: uploads marked {} priority. Sharing the line needs Driver mode.", l.priority.label()), false)
                    }
                    (true, true, _) => (format!("Active (driver): {}", l.rate_text(true)), false),
                    (true, false, true) => ("Download limits need Driver mode.".to_owned(), true),
                    (true, false, false) => (format!("Active: uploads capped at {}", crate::qos::fmt_rate(l.kbps)), false),
                };
                crate::qos::QosView { status, limit: l.clone(), problem }
            })
            .collect()
    }

    fn save_qos_limit(&self, mut limit: crate::qos::QosLimit) -> Result<(), String> {
        if let Some(problem) = limit.problem() {
            return Err(problem.into());
        }
        let mut s = self.state();
        if s.qos.iter().any(|l| l.id != limit.id && l.program.eq_ignore_ascii_case(&limit.program)) {
            return Err("That program already has a limit. Edit or remove it instead.".into());
        }
        if limit.id == 0 {
            limit.id = s.qos.iter().map(|l| l.id).max().unwrap_or(0) + 1;
            s.qos.push(limit);
        } else if let Some(slot) = s.qos.iter_mut().find(|l| l.id == limit.id) {
            *slot = limit;
        }
        Ok(())
    }

    fn remove_qos_limit(&self, id: u32) -> Result<(), String> {
        self.state().qos.retain(|l| l.id != id);
        Ok(())
    }

    fn asn_db_ready(&self) -> bool {
        true
    }

    fn download_asn_db(&self) -> Result<(), String> {
        Ok(())
    }

    fn restore_defaults(&self) -> Result<(), String> {
        let mut s = self.state();
        s.dest.clear();
        s.qos.clear();
        for a in s.apps.iter_mut().filter(|a| !a.locked) {
            a.inbound = Verdict::Blocked;
            a.outbound = Verdict::Allowed;
            a.local = Verdict::Allowed;
        }
        Ok(())
    }

    fn enable_windows_firewall(&self) -> Result<(), String> {
        Ok(())
    }

    fn dns_log(&self) -> Vec<DnsEntry> {
        demo_dns(crate::clock::now_unix())
    }

    fn live_connections(&self) -> Vec<LiveConn> {
        demo_connections(crate::clock::now_unix())
    }

    fn kill_connection(&self, c: &LiveConn) -> Result<String, String> {
        if !c.killable {
            return Err("Windows can only end established IPv4 connections.".into());
        }
        DEMO_KILLED.lock().unwrap_or_else(|e| e.into_inner()).push(c.remote.to_string());
        Ok(format!("Ended the connection from {} to {} (demo).", c.app, c.remote))
    }

    fn block_remote(&self, ip: std::net::IpAddr) -> Result<String, String> {
        let mut killed = DEMO_KILLED.lock().unwrap_or_else(|e| e.into_inner());
        killed.extend(demo_connections(crate::clock::now_unix()).iter().filter(|c| c.remote.ip() == ip).map(|c| c.remote.to_string()));
        Ok(format!("Blocked {ip} in both directions (demo)."))
    }

    fn alerts(&self) -> Vec<Alert> {
        self.state().alerts.clone()
    }

    fn mark_read(&self, id: Option<u64>) {
        for a in self.state().alerts.iter_mut().filter(|a| id.is_none_or(|i| i == a.id)) {
            a.unread = false;
        }
    }

    fn mark_alert_normal(&self, id: u64) -> bool {
        let mut st = self.state();
        let Some(a) = st.alerts.iter_mut().find(|a| a.id == id && a.anomaly) else { return false };
        a.anomaly = false;
        a.unread = false;
        true
    }

    fn snooze_alerts(&self, minutes: u32) {
        self.state().snooze_until = (minutes > 0).then(|| Instant::now() + std::time::Duration::from_secs(u64::from(minutes) * 60));
    }

    fn alerts_snoozed(&self) -> bool {
        self.state().snooze_until.is_some_and(|t| t > Instant::now())
    }

    fn networks(&self) -> Vec<String> {
        self.state().devices.iter().map(|(n, _)| n.clone()).collect()
    }

    fn devices(&self, network: &str) -> Vec<Device> {
        self.state().devices.iter().find(|(n, _)| n == network).map(|(_, d)| d.clone()).unwrap_or_default()
    }

    fn scan_state(&self) -> ScanState {
        let mut s = self.state();
        if let Some(t) = s.scanning_since {
            let elapsed = t.elapsed().as_secs_f32();
            if elapsed > SCAN_SECS {
                s.scanning_since = None;
                let net = std::mem::take(&mut s.scan_net);
                if let Some(d) = s.devices.iter_mut().find(|(n, _)| *n == net).and_then(|(_, d)| d.first_mut()) {
                    d.online = true;
                }
            } else {
                return ScanState { scanning: true, progress: elapsed / SCAN_SECS, error: None };
            }
        }
        ScanState { scanning: false, progress: 0.0, error: None }
    }

    fn start_scan(&self, network: &str) {
        let mut s = self.state();
        if s.scanning_since.is_none() {
            s.scanning_since = Some(Instant::now());
            s.scan_net = network.to_owned();
        }
    }

    fn stop_scan(&self) {
        self.state().scanning_since = None;
    }

    fn rename_device(&self, network: &str, mac: &str, name: &str) {
        if let Some(d) = self.state().devices.iter_mut().filter(|(n, _)| n == network).flat_map(|(_, d)| d).find(|d| d.mac == mac) {
            d.name = name.to_owned();
        }
    }

    fn set_device_trusted(&self, network: &str, mac: &str, trusted: bool) {
        if let Some(d) = self.state().devices.iter_mut().filter(|(n, _)| n == network).flat_map(|(_, d)| d).find(|d| d.mac == mac) {
            d.trusted = trusted;
        }
    }

    fn forget_network(&self, _network: &str) {}

    fn firewall_profiles(&self) -> (Vec<String>, String) {
        let s = self.state();
        (s.profiles.clone(), s.profile.clone())
    }

    fn delete_firewall_profile(&self, name: &str) -> Result<(), String> {
        let mut s = self.state();
        if s.profiles.len() < 2 || s.profile == name {
            return Err("The active or only ruleset can't be deleted.".into());
        }
        s.profiles.retain(|p| p != name);
        Ok(())
    }

    fn switch_firewall_profile(&self, name: &str, create: bool) -> Result<(), String> {
        let mut s = self.state();
        if create {
            crate::live::firewall::valid_profile_name(name, &s.profiles)?;
            s.profiles.push(name.into());
        } else if !s.profiles.iter().any(|p| p == name) {
            return Err(format!("No ruleset named \"{name}\"."));
        }
        s.profile = name.into();
        Ok(())
    }

    /// One sample prompt and one sample warning, a few seconds in, so both popups can be tried in Demo.
    fn take_asks(&self) -> Vec<ConnectAsk> {
        if self.started.elapsed().as_secs() < 8 || std::mem::replace(&mut self.state().ask_raised, true) {
            return Vec::new();
        }
        vec![ConnectAsk::demo()]
    }

    fn take_threats(&self) -> Vec<Threat> {
        let mut s = self.state();
        if self.started.elapsed().as_secs() < 8 || std::mem::replace(&mut s.threat_raised, true) {
            return Vec::new();
        }
        vec![Threat { ip: "185.220.101.7".into(), app: "updater.exe".into(), signed: Some(false), blocked: false, error: None }]
    }

    fn threat_summary(&self, _ip: &str) -> String {
        "Program: updater.exe
Listed on: sample threat list
Whitelisted: no"
            .into()
    }

    fn hardware_apps(&self, _window_secs: i64) -> Vec<String> {
        DEMO_HW_APPS.iter().map(|a| (*a).into()).collect()
    }

    fn hardware_history(&self, window_secs: i64, buckets: usize, app: Option<&str>) -> Vec<Option<HardwareSample>> {
        let now = crate::clock::now_unix();
        let salt = app.map_or(0, |a| a.bytes().map(u64::from).sum::<u64>());
        (0..buckets)
            .map(|i| {
                let t = (now - window_secs + window_secs * i as i64 / buckets.max(1) as i64) as u64 / 10;
                let n = |k: u64| noise(t * 7 + k + salt);
                let spike = |k: u64, p: f32| if n(k) > p { n(k + 1) } else { 0.0 };
                // An app that is only sometimes running leaves honest gaps.
                if app.is_some() && n(9) < 0.15 {
                    return None;
                }
                let scale = if app.is_some() { 0.4 } else { 1.0 };
                let (cpu, disk) = (12.0 + 6.0 * n(1) + 14.0 * spike(2, 0.93), 6.0 * n(4) + 80.0 * spike(5, 0.96));
                Some(HardwareSample { cpu: cpu * scale, memory: 13.8 * scale + 0.3 * n(3), disk: disk * scale, gpu: if app.is_some() { 0.0 } else { 2.0 + 3.0 * n(6) } })
            })
            .collect()
    }

    fn hardware(&self, seconds: usize) -> HardwareSnapshot {
        // Mock clock: starts at 9:20:30 PM and ticks with real time.
        let now_secs = 21 * 3600 + 20 * 60 + 30 + self.started.elapsed().as_secs() as i64;
        let samples: Vec<HardwareSample> = (0..seconds)
            .map(|i| {
                let t = (now_secs - (seconds - 1 - i) as i64).max(0) as u64;
                let n = |salt: u64| noise(t * 7 + salt);
                let spike = |salt: u64, p: f32| if n(salt) > p { n(salt + 1) } else { 0.0 };
                HardwareSample { cpu: 12.0 + 6.0 * n(1) + 14.0 * spike(2, 0.93), memory: 13.8 + 0.3 * n(3), disk: 6.0 * n(4) + 80.0 * spike(5, 0.96), gpu: 2.0 + 3.0 * n(6) + 30.0 * spike(7, 0.95) }
            })
            .collect();
        let last = samples.last().copied().unwrap_or_default();
        HardwareSnapshot {
            samples,
            now_secs,
            cpu_pct: last.cpu,
            memory_used: 14.8 * KB * KB * KB,
            memory_total: 74.0 * KB * KB * KB,
            gpu_available: true,
            disk_read: last.disk as f64 * KB * KB,
            disk_write: 63.0 * KB,
            gpu_pct: last.gpu,
            gpu_memory: 3.3 * KB * KB * KB,
        }
    }

    fn apply_settings(&self, settings: &Settings) {
        let mut s = self.state();
        s.split_kernel = settings.split_kernel;
        s.driver_mode = settings.app_mode == crate::settings::AppMode::Driver;
    }

    fn clear_history(&self) -> Result<(), String> {
        Ok(())
    }

    fn verify_alerts(&self) -> Result<AlertCheck, String> {
        Ok(AlertCheck { checked: self.state().alerts.len(), head: "demo".into(), ..Default::default() })
    }

    fn weekly_report(&self) -> Result<crate::report::Report, String> {
        Ok(crate::report::Report {
            until: crate::clock::now_unix(),
            top_apps: vec![("Chrome".into(), 4.2e9), ("Spotify".into(), 1.1e9), ("Steam".into(), 6.0e8)],
            new_hosts: Some(vec!["cdn.example.net".into(), "api.example.org".into()]),
            new_countries: Some(vec!["Brazil".into()]),
            alerts: vec![("New device".into(), 3), ("Data quotas".into(), 1)],
            blocked: 12,
            quota_events: 1,
            ping: vec![("1.1.1.1".into(), 12.0, 0.2)],
            broadband: vec![("Home line".into(), 18.0, 0.0)],
            daily: (0..7).map(|i| (crate::clock::now_unix() - (7 - i) * 86_400, [2.1e9, 1.4e9, 3.0e9, 0.9e9, 1.8e9, 2.6e9, 1.2e9][i as usize])).collect(),
        })
    }

    fn metrics_snapshot(&self) -> Result<crate::metrics::Snapshot, String> {
        Ok(crate::metrics::Snapshot {
            wan_down: 2_400_000.0,
            wan_up: 180_000.0,
            blocked: 12,
            alerts: vec![("new_device".into(), 2), ("arp".into(), 1)],
            apps: vec![("Chrome".into(), 2_400_000.0, 180_000.0), ("Spotify".into(), 900_000.0, 40_000.0)],
        })
    }

    fn export_history(&self, data: HistoryData, format: HistoryFormat, _days: Option<u32>) -> Result<String, String> {
        // Canned rows in the same shape as Live; the window is ignored because the sample has no real history.
        Ok(match data {
            HistoryData::Traffic => {
                let rows = [crate::export::TrafficRow { ts: 0, app: "Chrome".into(), remote: "142.250.0.1".into(), host: "google.com".into(), country: "US".into(), down: 2_400_000, up: 180_000 }];
                match format {
                    HistoryFormat::Csv => crate::export::traffic_csv(&rows),
                    HistoryFormat::Json => crate::export::json(&rows),
                }
            }
            HistoryData::Alerts => {
                let rows: Vec<crate::export::AlertRow> = self
                    .state()
                    .alerts
                    .iter()
                    .map(|a| crate::export::AlertRow {
                        ts: a.ts,
                        kind: a.kind.clone(),
                        app: a.app.clone(),
                        text: a.text.clone(),
                        target: a.target.clone(),
                        country: String::new(),
                        important: a.important,
                    })
                    .collect();
                match format {
                    HistoryFormat::Csv => crate::export::alerts_csv(&rows),
                    HistoryFormat::Json => crate::export::json(&rows),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_networks_keep_separate_devices_and_threat_lists() {
        let b = MockBackend::new();
        assert_ne!(b.devices("HomeNET").len(), b.devices("Ethernet").len());
        let mac = b.devices("HomeNET")[0].mac.clone();
        b.rename_device("HomeNET", &mac, "Router");
        assert_eq!(b.devices("HomeNET")[0].name, "Router");
        assert_ne!(b.devices("Ethernet")[0].name, "Router");
        let ip = b.blocked_ips()[0].0.clone();
        b.threat_act(&ip, ThreatAct::Whitelist).unwrap();
        assert!(b.blocked_ips().iter().all(|(i, _)| *i != ip) && b.threat_whitelist().iter().any(|(i, _)| *i == ip));
        b.threat_act(&ip, ThreatAct::Unwhitelist).unwrap();
        assert!(b.threat_whitelist().iter().all(|(i, _)| *i != ip));
    }

    #[test]
    fn demo_traffic_filter_narrows_the_sample_data() {
        let b = MockBackend::new();
        let all = b.totals(TimeRange::OneHour, (0.0, 0.15));
        b.set_traffic_filter(&TrafficFilter { dir: TrafficDir::In, ..Default::default() });
        let down = b.totals(TimeRange::OneHour, (0.0, 0.15));
        assert_eq!((down.down, down.up), (all.down, 0.0));
        let apps = TrafficFilter { app: Some(("DNS Client".into(), "DNS Client".into())), ..Default::default() };
        b.set_traffic_filter(&apps);
        let rows = b.breakdown(TimeRange::OneHour, (0.0, 0.15)).apps;
        assert_eq!(rows.len(), 1);
        assert!(rows[0].bytes < 70.3 * KB);
        b.set_traffic_filter(&TrafficFilter::default());
        assert_eq!(b.totals(TimeRange::OneHour, (0.0, 0.15)).down, all.down);
    }

    #[test]
    fn demo_test_alert_queues_one_popup() {
        let b = MockBackend::new();
        b.test_alert("device_returned", &Settings::default());
        assert_eq!(b.take_popups(true).len(), 1);
        assert!(b.take_popups(true).is_empty());
    }

    #[test]
    fn demo_block_all_shows_active() {
        let b = MockBackend::new();
        b.set_firewall_mode(FirewallMode::BlockAll).unwrap();
        assert!(b.firewall_info().block_all_active);
        b.set_firewall_mode(FirewallMode::ClickToBlock).unwrap();
        assert!(!b.firewall_info().block_all_active);
    }

    #[test]
    fn demo_snooze_net_info_and_virustotal_work() {
        let b = MockBackend::new();
        assert!(!b.alerts_snoozed());
        b.snooze_alerts(30);
        assert!(b.alerts_snoozed());
        b.snooze_alerts(0);
        assert!(!b.alerts_snoozed());
        assert!(b.net_info("192.168.1.1").is_empty() && b.net_info("claude.ai").starts_with("AS"));
        assert!(b.firewall_apps().iter().any(|a| a.virustotal != Vt::None));
    }

    #[test]
    fn demo_profiles_hardware_and_sample_prompts_work() {
        let b = MockBackend::new();
        b.switch_firewall_profile("Work", true).unwrap();
        assert!(b.switch_firewall_profile("work", true).is_err());
        assert!(b.delete_firewall_profile("Work").is_err() && b.delete_firewall_profile("Gaming").is_ok());
        assert_eq!(b.firewall_profiles().1, "Work");
        assert_eq!(b.hardware_history(300, 30, Some("chrome.exe")).len(), 30);
        assert!(!b.hardware_apps(300).is_empty() && b.take_asks().is_empty() && b.take_threats().is_empty());
    }

    #[test]
    fn locked_rows_sit_in_the_windows_group() {
        let apps = MockBackend::new().firewall_apps();
        assert!(apps.iter().any(|a| a.group == AppGroup::Windows));
        assert!(apps.iter().all(|a| (a.group == AppGroup::Windows) == a.locked));
    }

    #[test]
    fn kernel_row_splits_by_service_and_follows_the_setting() {
        let b = MockBackend::new();
        let kernel = |b: &MockBackend| b.firewall_apps().into_iter().filter(|a| a.name.contains("Kernel")).collect::<Vec<_>>();
        let split = kernel(&b);
        assert!(split.len() > 1 && split.iter().all(|a| a.locked && a.key.starts_with("system|svc:")));
        let mut off = Settings::default();
        off.split_kernel = false;
        b.apply_settings(&off);
        assert_eq!(kernel(&b).len(), 1);
    }

    #[test]
    fn demo_dns_log_has_ordered_sample_rows() {
        let rows = demo_dns(1_000_000);
        assert!(rows.len() >= 5);
        assert!(rows.windows(2).all(|w| w[0].ts > w[1].ts), "newest first");
        assert!(rows.iter().any(|e| !e.ok()), "a failed lookup shows the status column");
        assert_eq!(rows.iter().filter(|e| e.listed).count(), 1, "one sample malicious domain");
    }

    #[test]
    fn demo_connections_have_sample_rows() {
        let rows = demo_connections(1_000_000);
        assert!(rows.len() >= 5);
        assert!(rows.iter().any(|c| c.killable) && rows.iter().any(|c| !c.killable && c.remote.is_ipv6()), "an IPv6 row can't be killed");
        let size = |c: &LiveConn| c.bytes.map_or(0, |(i, o)| i + o);
        assert!(rows.windows(2).all(|w| size(&w[0]) >= size(&w[1])), "busiest first");
    }

    #[test]
    fn live_conn_search() {
        let c = demo_connections(1_000_000).into_iter().find(|c| c.app == "chrome.exe").unwrap();
        assert!(c.matches("") && c.matches("CHROME") && c.matches("wikipedia") && c.matches("established") && c.matches("4120"));
        assert!(!c.matches("firefox"));
    }

    #[test]
    fn dns_entry_labels_and_search() {
        let e = DnsEntry { ts: 0, app: "Chrome.exe".into(), name: "www.example.com".into(), qtype: 28, ips: vec!["2606:2800::1".into()], status: 0, listed: false };
        assert_eq!((e.type_label().as_str(), e.status_label().as_str()), ("AAAA", "OK"));
        assert!(e.matches("") && e.matches("CHROME") && e.matches("example.com") && e.matches("2606") && e.matches("aaaa"));
        assert!(!e.matches("firefox"));
        let nx = DnsEntry { status: 9003, ips: vec![], ..e.clone() };
        assert_eq!(nx.status_label(), "Name not found");
        assert!(!nx.ok() && nx.matches("name not found"));
        let bad = DnsEntry { listed: true, ..e.clone() };
        assert!(!bad.ok() && bad.status_label() == "Malicious domain" && bad.matches("malicious"));
        assert_eq!(DnsEntry { qtype: 99, ..e }.type_label(), "99");
    }

    #[test]
    fn demo_keeps_core_services_locked_and_lets_others_be_blocked() {
        use crate::data::{Backend, Direction, Verdict};
        let demo = MockBackend::new();
        let key = |short: &str| crate::live::apps::service_key(r"c:\windows\system32\svchost.exe", &short.to_lowercase());
        assert!(demo.set_verdict(&key("Dnscache"), Direction::Out, Verdict::Blocked).is_err());
        assert!(demo.set_verdict(&key("wuauserv"), Direction::Out, Verdict::Blocked).is_ok());
    }

    #[test]
    fn demo_destination_rules_add_replace_remove_and_reset() {
        use crate::destrules::{DestRule, Mode, Target};
        let demo = MockBackend::new();
        let start = demo.dest_rules().len();
        let rule = DestRule { id: 0, enabled: true, mode: Mode::Block, target: Target::Asn(15169), program: String::new() };
        demo.save_dest_rule(rule.clone()).unwrap();
        let saved = demo.dest_rules().pop().unwrap();
        assert_eq!(demo.dest_rules().len(), start + 1);
        assert!(saved.rule.id > 0 && saved.status.starts_with("Blocking"));
        demo.save_dest_rule(DestRule { enabled: false, ..saved.rule.clone() }).unwrap();
        assert_eq!(demo.dest_rules().len(), start + 1);
        assert_eq!(demo.dest_rules().pop().unwrap().status, "Off");
        assert!(demo.save_dest_rule(DestRule { mode: Mode::OnlyAllow, ..rule }).is_err(), "only-allow for every program is refused");
        demo.remove_dest_rule(saved.rule.id).unwrap();
        assert_eq!(demo.dest_rules().len(), start);
        demo.restore_defaults().unwrap();
        assert!(demo.dest_rules().is_empty());
    }

    #[test]
    fn demo_bandwidth_limits_can_be_added_changed_and_cleared() {
        use crate::qos::QosLimit;
        let demo = MockBackend::new();
        let start = demo.qos_limits().len();
        let limit = QosLimit::upload(0, true, r"C:\Apps\game.exe", 2500);
        demo.save_qos_limit(limit.clone()).unwrap();
        let saved = demo.qos_limits().pop().unwrap();
        assert_eq!(demo.qos_limits().len(), start + 1);
        assert!(saved.status.contains("2.5 Mbps"));
        assert!(demo.save_qos_limit(QosLimit { program: saved.limit.program.to_uppercase(), ..limit.clone() }).is_err(), "one limit per program");
        demo.save_qos_limit(QosLimit { enabled: false, ..saved.limit.clone() }).unwrap();
        assert_eq!(demo.qos_limits().pop().unwrap().status, "Off");
        assert!(demo.save_qos_limit(QosLimit { kbps: 1, ..limit }).is_err(), "too slow a limit is refused");
        demo.remove_qos_limit(saved.limit.id).unwrap();
        assert_eq!(demo.qos_limits().len(), start);
        demo.restore_defaults().unwrap();
        assert!(demo.qos_limits().is_empty());
    }

    #[test]
    fn demo_splits_svchost_into_services_started_by_services_exe() {
        let apps = demo_apps();
        let services: Vec<_> = apps.iter().filter(|a| !a.service.is_empty()).collect();
        assert_eq!(services.len(), 3);
        assert!(services.iter().all(|a| a.parent == "services.exe"));
        assert!(apps.iter().any(|a| a.service.is_empty() && a.parent == "explorer.exe"));
    }
}
