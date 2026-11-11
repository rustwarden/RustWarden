//! Network scanner: ARP sweep of the adapter's own subnet, reverse DNS, SSDP and
//! NetBIOS name hints, vendor from the IEEE OUI table. Cancellable and rate-limited, and it
//! only probes private IPv4 ranges that are directly attached to an adapter of this machine.
//!
//! Not done: mDNS, SNMP and DHCP observation (the original's other discovery methods).

use super::alerts::{AlertKind, DeviceEvent, device_events};
use super::db::DeviceRow;
use super::store::{NetworkInfo, Shared};
use crate::data::{DeviceKind, ScanState, StatusNote};
use crate::sys::netinfo::{self, Adapter};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, SendARP};

const OUI_TABLE: &str = include_str!("../../assets/oui.tsv");
const WORKERS: usize = 16;
/// Largest sweep: a /24. Bigger attached networks are scanned around this machine's address only.
const MAX_PREFIX_HOSTS: u32 = 254;

fn oui_map() -> &'static HashMap<u32, &'static str> {
    static MAP: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        OUI_TABLE
            .lines()
            .filter_map(|l| {
                let (prefix, name) = l.split_once('\t')?;
                Some((u32::from_str_radix(prefix, 16).ok()?, name))
            })
            .collect()
    })
}

/// Vendor name for a MAC. Locally administered addresses (set by phones and PCs to hide their
/// identity) are not in the registry, so they are labelled as such rather than guessed.
pub fn vendor_for(mac: &[u8; 6]) -> String {
    if mac[0] & 2 != 0 {
        return "Private address".into();
    }
    let key = u32::from_be_bytes([0, mac[0], mac[1], mac[2]]);
    oui_map().get(&key).map(|s| shorten_vendor(s)).unwrap_or_default()
}

/// "TP-Link Technologies Co.,Ltd." -> "TP-Link Technologies".
pub fn shorten_vendor(name: &str) -> String {
    let mut s = name.trim().to_owned();
    for suffix in [", Inc.", ", Inc", " Inc.", " Inc", " Co.,Ltd.", " Co.,Ltd", " Co., Ltd.", " Co., Ltd", " Ltd.", " Ltd", " Corporation", " Corp.", " Corp", " GmbH", " LLC", " CO.,LTD."] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.trim_end_matches([',', ' ']).to_owned();
        }
    }
    s
}

/// Device type from evidence only: the vendor name, or being the default gateway.
pub fn guess_kind(vendor: &str, is_gateway: bool) -> DeviceKind {
    let v = vendor.to_lowercase();
    if v.contains("raspberry") {
        DeviceKind::Raspberry
    } else if ["espressif", "tuya", "shelly", "sonoff", "ring", "philips lighting", "signify", "ecobee", "nest", "sonos", "roku"].iter().any(|k| v.contains(k)) {
        DeviceKind::SmartDevice
    } else if is_gateway {
        DeviceKind::WiFi
    } else {
        DeviceKind::Generic
    }
}

/// First product token of an SSDP `SERVER:` header, e.g. "Linux/3.14 UPnP/1.0 X/1" -> "Linux".
pub fn ssdp_system(server: &str) -> String {
    let first = server.split_whitespace().next().unwrap_or("");
    let product = first.split('/').next().unwrap_or("").trim_matches(',');
    if product.eq_ignore_ascii_case("upnp") { String::new() } else { product.chars().take(24).collect() }
}

/// NetBIOS node-status request for the wildcard name `*`.
pub fn nbstat_request() -> Vec<u8> {
    let mut q = vec![0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
    q.extend(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    q.extend([0, 0, 0x21, 0, 1]);
    q
}

/// Machine name from a node-status response: the first unique name with suffix 0x00.
pub fn parse_nbstat(resp: &[u8]) -> Option<String> {
    // Header 12, echoed name 34, type 2, class 2, ttl 4, rdlength 2 -> names count at 56.
    let count = *resp.get(56)? as usize;
    (0..count).find_map(|i| {
        let e = resp.get(57 + i * 18..57 + i * 18 + 18)?;
        let (suffix, flags) = (e[15], u16::from_be_bytes([e[16], e[17]]));
        (suffix == 0 && flags & 0x8000 == 0).then(|| String::from_utf8_lossy(&e[..15]).trim().to_owned()).filter(|n| !n.is_empty())
    })
}

/// Addresses to probe for an adapter address `ip/prefix`: the subnet, never beyond a /24 and
/// never a public range. `Err` explains why nothing is scanned.
pub fn sweep_targets(ip: Ipv4Addr, prefix: u8) -> Result<Vec<Ipv4Addr>, String> {
    if !(ip.is_private() || ip.is_link_local()) {
        return Err(format!("{ip} is not a private address, so RustWarden won't probe its network"));
    }
    let prefix = prefix.clamp(24, 30);
    let mask = u32::MAX << (32 - prefix);
    let base = u32::from(ip) & mask;
    let count = (!mask).min(MAX_PREFIX_HOSTS + 1);
    Ok((1..count).map(|i| Ipv4Addr::from(base + i)).filter(|a| *a != ip).collect())
}

/// One ICMP echo; true only for a real reply (not a router's "unreachable").
fn ping(target: Ipv4Addr, timeout_ms: u32) -> bool {
    let Ok(h) = (unsafe { IcmpCreateFile() }) else { return false };
    let mut buf = [0u8; 128];
    let n = unsafe { IcmpSendEcho(h, u32::from_le_bytes(target.octets()), [0u8; 1].as_ptr().cast(), 1, None, buf.as_mut_ptr().cast(), buf.len() as u32, timeout_ms) };
    let _ = unsafe { IcmpCloseHandle(h) };
    n > 0 && buf[4..8] == [0; 4] // status IP_SUCCESS
}

/// The /24 networks worth probing for other VLANs: every /24 of our /16, plus, inside 10/8, the first /24 of each /16.
fn vlan_candidates(ip: Ipv4Addr) -> Vec<[u8; 3]> {
    let [a, b, c, _] = ip.octets();
    let mut v: Vec<[u8; 3]> = (0..=255).map(|x| [a, b, x]).collect();
    if a == 10 {
        v.extend((0..=255).map(|x| [a, x, 0]));
    }
    v.retain(|n| *n != [a, b, c]);
    v.sort_unstable();
    v.dedup();
    v
}

/// Pings `targets` from a pool of workers; the ones that answer. `progress` gets the number done so far.
fn ping_pool(targets: &[Ipv4Addr], timeout_ms: u32, cancelled: &(impl Fn() -> bool + Sync), progress: impl Fn(usize) + Sync) -> Vec<Ipv4Addr> {
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let alive = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..WORKERS * 2 {
            scope.spawn(|| {
                while !cancelled() {
                    let Some(&t) = targets.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
                    if ping(t, timeout_ms) {
                        alive.lock().unwrap_or_else(|e| e.into_inner()).push(t);
                    }
                    progress(done.fetch_add(1, Ordering::Relaxed) + 1);
                }
            });
        }
    });
    alive.into_inner().unwrap_or_default()
}

pub fn networks() -> Vec<(NetworkInfo, Adapter)> {
    netinfo::adapters()
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.up && !a.loopback && a.addrs.iter().any(|(ip, _)| matches!(ip, IpAddr::V4(v4) if v4.is_private() || v4.is_link_local())))
        .map(|a| {
            let gw = a.gateways.iter().find(|g| g.is_ipv4()).map(ToString::to_string).unwrap_or_default();
            (NetworkInfo { key: format!("{}|{gw}", a.name), label: a.name.clone() }, a)
        })
        .collect()
}

fn arp_probe(target: Ipv4Addr, source: Ipv4Addr) -> Option<[u8; 6]> {
    let mut mac = [0u8; 8];
    let mut len = 6u32;
    let rc = unsafe { SendARP(u32::from_le_bytes(target.octets()), u32::from_le_bytes(source.octets()), mac.as_mut_ptr() as *mut _, &mut len) };
    let m = [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
    (rc == 0 && len == 6 && netinfo::is_unicast_mac(&m)).then_some(m)
}

/// The DNS PTR name for an address: 203.0.113.7 -> 7.113.0.203.in-addr.arpa.
fn ptr_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

/// The address's name from a DNS PTR record only. GetNameInfoW falls back to a NetBIOS node-status query sent
/// straight to the address when there is no PTR, which leaks this PC's name to internet hosts and shows up as
/// unexplained "Kernel: NetBIOS" traffic. LAN names come from `nbstat` instead.
pub fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    use windows::Win32::NetworkManagement::Dns::{DNS_QUERY_NO_NETBT, DNS_QUERY_OPTIONS, DNS_QUERY_STANDARD, DNS_RECORDA, DNS_TYPE_PTR, DnsFree, DnsFreeRecordList, DnsQuery_A};
    use windows::core::PCSTR;
    let name = std::ffi::CString::new(ptr_name(ip)).ok()?;
    let mut records: *mut DNS_RECORDA = std::ptr::null_mut();
    let options = DNS_QUERY_OPTIONS(DNS_QUERY_STANDARD.0 | DNS_QUERY_NO_NETBT.0);
    unsafe {
        if DnsQuery_A(PCSTR(name.as_ptr().cast()), DNS_TYPE_PTR, options, None, &mut records, None).0 != 0 || records.is_null() {
            return None;
        }
        let mut found = None;
        let mut at = records;
        while !at.is_null() && found.is_none() {
            let rec = &*at;
            if rec.wType == DNS_TYPE_PTR.0 && !rec.Data.PTR.pNameHost.is_null() {
                found = rec.Data.PTR.pNameHost.to_string().ok();
            }
            at = rec.pNext;
        }
        DnsFree(Some(records as *const _), DnsFreeRecordList);
        found.map(|h: String| h.trim_end_matches('.').to_owned()).filter(|h| !h.is_empty() && h.parse::<IpAddr>().is_err())
    }
}

fn ssdp_probe(source: Ipv4Addr, wait: Duration) -> HashMap<Ipv4Addr, String> {
    let mut found = HashMap::new();
    let Ok(sock) = UdpSocket::bind((source, 0)) else { return found };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
    let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    if sock.send_to(msg.as_bytes(), (Ipv4Addr::new(239, 255, 255, 250), 1900)).is_err() {
        return found;
    }
    let end = Instant::now() + wait;
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((n, std::net::SocketAddr::V4(from))) = sock.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]);
            if let Some(server) = text.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("server")).map(|(_, v)| v.trim().to_owned())) {
                found.entry(*from.ip()).or_insert(server);
            }
        }
    }
    found
}

fn nbstat(ip: Ipv4Addr) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(300))).ok()?;
    sock.send_to(&nbstat_request(), (ip, 137)).ok()?;
    let mut buf = [0u8; 1024];
    let n = sock.recv(&mut buf).ok()?;
    parse_nbstat(&buf[..n])
}

#[derive(Clone, Debug)]
struct Found {
    ip: Ipv4Addr,
    mac: [u8; 6],
    is_self: bool,
    /// Behind a router (another VLAN or subnet): no MAC is visible, so it is identified by IP.
    remote: bool,
}

/// Ports worth probing on a home network: remote access, web, file sharing, media and IoT services.
pub const PORTS: [u16; 32] =
    [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 515, 554, 631, 1883, 1900, 3000, 3389, 5000, 5357, 5900, 8000, 8008, 8080, 8081, 8123, 8443, 8888, 9000, 9100, 32400, 49152];

/// TCP connect scan of `PORTS`; ascending open ports. Stops early when `cancelled`.
fn port_scan(ip: Ipv4Addr, cancelled: &(impl Fn() -> bool + Sync)) -> Vec<u16> {
    let next = AtomicUsize::new(0);
    let open = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                while !cancelled() {
                    let Some(&port) = PORTS.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
                    if std::net::TcpStream::connect_timeout(&(ip, port).into(), Duration::from_millis(400)).is_ok() {
                        open.lock().unwrap_or_else(|e| e.into_inner()).push(port);
                    }
                }
            });
        }
    });
    let mut open = open.into_inner().unwrap_or_default();
    open.sort_unstable();
    open
}

/// Runs one scan of `network` to completion or cancellation. Called on its own thread.
fn scan(shared: &Shared, network: &NetworkInfo, adapter: &Adapter) -> Result<(), String> {
    let (ip, prefix) = adapter
        .addrs
        .iter()
        .find_map(|(ip, p)| match ip {
            IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() => Some((*v4, *p)),
            _ => None,
        })
        .ok_or("This network has no private IPv4 address to scan")?;
    let targets = sweep_targets(ip, prefix)?;
    let delay = Duration::from_millis(u64::from(shared.settings().scan_delay_ms));
    let cancelled = || shared.scan_cancel.load(Ordering::Relaxed) || shared.stopping();

    // 1. What the ARP cache already knows on this interface.
    let in_subnet = |a: &Ipv4Addr| targets.contains(a);
    let mut found: HashMap<Ipv4Addr, Found> = HashMap::new();
    for n in netinfo::neighbors()?.into_iter().filter(|n| n.if_index == adapter.if_index && n.resolved && netinfo::is_unicast_mac(&n.mac)) {
        if let IpAddr::V4(v4) = n.ip
            && in_subnet(&v4)
        {
            found.insert(v4, Found { ip: v4, mac: n.mac, is_self: false, remote: false });
        }
    }
    found.insert(ip, Found { ip, mac: adapter.mac, is_self: true, remote: false });

    // 2. Sweep: rate-limited ARP probes from a small pool of workers.
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let gate = Mutex::new(Instant::now());
    let hits: Mutex<Vec<Found>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                loop {
                    if cancelled() {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(target) = targets.get(i) else { break };
                    // One probe starts per `delay`, whichever worker takes it.
                    {
                        let mut at = gate.lock().unwrap_or_else(|e| e.into_inner());
                        let wait = at.saturating_duration_since(Instant::now());
                        *at = Instant::now().max(*at) + delay;
                        drop(at);
                        std::thread::sleep(wait);
                    }
                    if let Some(mac) = arp_probe(*target, ip) {
                        hits.lock().unwrap_or_else(|e| e.into_inner()).push(Found { ip: *target, mac, is_self: false, remote: false });
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    shared.state().scan.progress = 0.85 * d as f32 / targets.len().max(1) as f32;
                }
            });
        }
    });
    if cancelled() {
        return Err("Scan stopped".into());
    }
    for f in hits.into_inner().unwrap_or_default() {
        found.insert(f.ip, f);
    }
    if ip.is_private() && shared.settings().scan_other_vlans {
        // ARP stops at the router, so other VLANs are found by pinging each candidate /24's .1 and .254, then every host of those that answer.
        let probes: Vec<Ipv4Addr> = vlan_candidates(ip).into_iter().flat_map(|[a, b, c]| [1, 254].map(|h| Ipv4Addr::new(a, b, c, h))).collect();
        let gateways = ping_pool(&probes, 250, &cancelled, |d| shared.state().scan.progress = 0.85 + 0.025 * d as f32 / probes.len() as f32);
        let mut nets: Vec<[u8; 3]> = gateways.iter().map(|g| [g.octets()[0], g.octets()[1], g.octets()[2]]).collect();
        nets.sort_unstable();
        nets.dedup();
        let hosts: Vec<Ipv4Addr> = nets.iter().flat_map(|&[a, b, c]| (1..=254).map(move |h| Ipv4Addr::new(a, b, c, h))).filter(|h| !gateways.contains(h)).collect();
        let alive = ping_pool(&hosts, 400, &cancelled, |d| shared.state().scan.progress = 0.875 + 0.025 * d as f32 / hosts.len() as f32);
        for a in gateways.into_iter().chain(alive) {
            found.entry(a).or_insert(Found { ip: a, mac: [0; 6], is_self: false, remote: true });
        }
        if cancelled() {
            return Err("Scan stopped".into());
        }
    }

    // 3. Names and hints for what answered.
    shared.state().scan.progress = 0.9;
    let list: Vec<Found> = found.values().cloned().collect();
    let names: Mutex<HashMap<Ipv4Addr, String>> = Mutex::new(HashMap::new());
    let idx = AtomicUsize::new(0);
    let ssdp = std::thread::scope(|scope| {
        // The 1.5 s SSDP wait overlaps the name lookups instead of preceding them.
        let probe = scope.spawn(|| ssdp_probe(ip, Duration::from_millis(1500)));
        for _ in 0..8 {
            scope.spawn(|| {
                while !cancelled() {
                    let Some(f) = list.get(idx.fetch_add(1, Ordering::Relaxed)) else { break };
                    let name = if f.is_self { std::env::var("COMPUTERNAME").ok() } else { nbstat(f.ip).or_else(|| reverse_dns(f.ip)) };
                    if let Some(n) = name {
                        names.lock().unwrap_or_else(|e| e.into_inner()).insert(f.ip, n);
                    }
                }
            });
        }
        probe.join().unwrap_or_default()
    });
    if cancelled() {
        return Err("Scan stopped".into());
    }
    let names = names.into_inner().unwrap_or_default();

    // 4. Store, alert on new devices, mark the rest offline.
    let db = shared.open_db().map_err(|e| e.to_string())?;
    let now = crate::clock::now_unix();
    let prev = db.devices(&network.key).unwrap_or_default();
    let notes = db.device_notes(&crate::plugins::wasm::manager::annotator_ids()).unwrap_or_default();
    let gateways: HashSet<IpAddr> = adapter.gateways.iter().copied().collect();
    let mut online = Vec::new();
    let mut seen = Vec::new();
    let mut fresh = Vec::new();
    for f in &list {
        let mac = if f.remote { format!("ip:{}", f.ip) } else { netinfo::fmt_mac(&f.mac) };
        let vendor = if f.remote { "Other VLAN or subnet".to_owned() } else { vendor_for(&f.mac) };
        let system = if f.is_self { "Windows (this computer)".to_owned() } else { ssdp.get(&f.ip).map(|s| ssdp_system(s)).unwrap_or_default() };
        let row = DeviceRow {
            network: network.key.clone(),
            mac: mac.clone(),
            ip: f.ip.to_string(),
            name: names.get(&f.ip).cloned().unwrap_or_default(),
            vendor: vendor.clone(),
            system,
            kind: kind_to_i64(guess_kind(&vendor, gateways.contains(&IpAddr::V4(f.ip)))),
            first_seen: now,
            last_seen: now,
            online: true,
            seen_count: 1,
            ports: String::new(),
            trusted: false,
        };
        let _ = db.upsert_device(&row);
        if !f.is_self {
            seen.push((row.ip.clone(), mac.clone()));
        }
        online.push(mac);
        fresh.push(row);
    }
    let settings = shared.settings();
    let gw: HashSet<String> = gateways.iter().map(ToString::to_string).collect();
    // How a device reads in an alert: a plugin's name and area when matched (Home Assistant), else its name or vendor.
    let label = |mac: &str| -> String {
        if let Some(h) = notes.get(mac) {
            return if h.area.is_empty() { h.name.clone() } else { format!("{}, {}", h.name, h.area) };
        }
        prev.iter().chain(&fresh).find(|d| d.mac == mac).map(|d| if d.name.is_empty() { d.vendor.clone() } else { d.name.clone() }).unwrap_or_default()
    };
    let tag = |ip: &str, mac: &str| {
        let who = label(mac);
        format!("{ip} ({mac}){}", if who.is_empty() { String::new() } else { format!(" – {who}") })
    };
    for e in device_events(&prev, &seen, &gw, now, settings.device_return_days) {
        let net = &network.label;
        match e {
            DeviceEvent::New { ip, mac } => shared.alert(&db, AlertKind::NewDevice, net, "has a new device:", &tag(&ip, &mac), "LOCAL"),
            DeviceEvent::Returned { ip, mac, days } => shared.alert(&db, AlertKind::DeviceReturned, net, &format!("has a device back after {days} days away:"), &tag(&ip, &mac), "LOCAL"),
            DeviceEvent::MacChanged { ip, old_mac, mac, gateway } => {
                let text = if gateway { "gateway changed MAC address (possible ARP spoofing):" } else { "address now has a different MAC address (possible ARP spoofing):" };
                let target = format!("{ip}: {} → {}", tag("", &old_mac).trim(), tag("", &mac).trim());
                shared.alert_as(&db, AlertKind::DeviceSpoof, net, text, &target, "LOCAL", gateway.into());
            }
            DeviceEvent::MultiIp { mac, ips } => {
                let target = format!("{} → {}", tag("", &mac).trim(), ips.join(", "));
                shared.alert(&db, AlertKind::DeviceSpoof, net, "has one MAC address answering for several IPs (possible ARP spoofing):", &target, "LOCAL")
            }
        }
    }
    let _ = db.set_devices_offline(&network.key, &online);

    // 5. Port-scan online devices that never were: new ones and those stored before this existed.
    shared.state().scan.progress = 0.95;
    let todo: Vec<(String, Ipv4Addr)> =
        db.unscanned_devices(&network.key).unwrap_or_default().into_iter().filter(|(m, _)| online.contains(m)).filter_map(|(m, ip)| Some((m, ip.parse().ok()?))).collect();
    // A few devices at once (each already uses 8 port threads). Results are written here, as `db` isn't shared across threads.
    let next = AtomicUsize::new(0);
    let scanned: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while !cancelled() {
                    let Some((mac, ip)) = todo.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
                    let ports = port_scan(*ip, &cancelled);
                    // A stopped scan is partial: don't store it as the device's ports.
                    if !cancelled() {
                        scanned.lock().unwrap_or_else(|e| e.into_inner()).push((mac.clone(), ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",")));
                    }
                }
            });
        }
    });
    for (mac, ports) in scanned.into_inner().unwrap_or_default() {
        let _ = db.set_ports(&network.key, &mac, &ports);
    }
    if cancelled() {
        return Err("Scan stopped".into());
    }
    let _ = db.kv_set(&format!("last_scan:{}", network.key), &now.to_string());
    Ok(())
}

pub fn kind_to_i64(k: DeviceKind) -> i64 {
    match k {
        DeviceKind::Generic => 0,
        DeviceKind::SmartDevice => 1,
        DeviceKind::WiFi => 2,
        DeviceKind::Laptop => 3,
        DeviceKind::Raspberry => 4,
    }
}

pub fn kind_from_i64(v: i64) -> DeviceKind {
    match v {
        1 => DeviceKind::SmartDevice,
        2 => DeviceKind::WiFi,
        3 => DeviceKind::Laptop,
        4 => DeviceKind::Raspberry,
        _ => DeviceKind::Generic,
    }
}

/// Starts a scan of the network with this key on a new thread, unless one is already running.
pub fn start(shared: &Arc<Shared>, key: &str) {
    {
        let mut st = shared.state();
        if st.scan.scanning {
            return;
        }
        st.scan = ScanState { scanning: true, progress: 0.0, ..st.scan.clone() };
    }
    shared.scan_cancel.store(false, Ordering::Relaxed);
    let finish = |shared: &Shared, result: Result<(), String>| {
        let mut st = shared.state();
        st.scan.scanning = false;
        st.scan.progress = 0.0;
        st.scan.error = result.err();
        drop(st);
        shared.repaint();
    };
    let (sh, key) = (shared.clone(), key.to_owned());
    let spawned = std::thread::Builder::new().name("scan".into()).spawn(move || {
        // A panic must still clear `scanning`, or no scan could ever start again.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match networks().into_iter().find(|(n, _)| n.key == key) {
            Some((n, a)) => scan(&sh, &n, &a),
            None => Err("That network is no longer connected".into()),
        }))
        .unwrap_or_else(|_| Err("The scan stopped unexpectedly".into()));
        finish(&sh, result);
    });
    if let Err(e) = spawned {
        finish(shared, Err(format!("Couldn't start the scan: {e}")));
    }
}

/// Refreshes the list of networks and starts scheduled scans.
pub fn run(shared: Arc<Shared>) {
    let mut tick = 0u64;
    while shared.sleep(1.0) {
        if tick.is_multiple_of(5) {
            let nets: Vec<NetworkInfo> = networks().into_iter().map(|(n, _)| n).collect();
            let missing = nets.is_empty();
            shared.state().networks = nets.clone();
            shared.set_note("scanner", missing.then(|| StatusNote::info("No local network found: the scanner has nothing to scan")));
            let settings = shared.settings();
            let target = nets.iter().find(|n| n.label == settings.scan_network).or(nets.first());
            if settings.auto_scan
                && !shared.state().scan.scanning
                && let (Some(target), Ok(db)) = (target, shared.open_db())
            {
                let last = db.kv_get(&format!("last_scan:{}", target.key)).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                let now = crate::clock::now_unix();
                if now - last >= i64::from(settings.auto_scan_minutes) * 60 {
                    // Stamped now, so a stopped or failed scan waits out the interval instead of restarting at once.
                    let _ = db.kv_set(&format!("last_scan:{}", target.key), &now.to_string());
                    start(&shared, &target.key);
                }
            }
        }
        tick += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_names_are_reversed() {
        assert_eq!(ptr_name(Ipv4Addr::new(199, 123, 188, 54)), "54.188.123.199.in-addr.arpa");
        assert_eq!(ptr_name(Ipv4Addr::new(10, 0, 0, 1)), "1.0.0.10.in-addr.arpa");
    }

    #[test]
    fn sweep_stays_inside_the_private_subnet() {
        let t = sweep_targets(Ipv4Addr::new(192, 168, 1, 32), 24).unwrap();
        assert_eq!(t.len(), 253); // 254 hosts minus ourselves
        assert!(t.iter().all(|a| a.octets()[..3] == [192, 168, 1]));
        assert!(!t.contains(&Ipv4Addr::new(192, 168, 1, 32)));
        // A /16 is narrowed to the /24 around our own address.
        let wide = sweep_targets(Ipv4Addr::new(10, 1, 7, 9), 16).unwrap();
        assert!(wide.iter().all(|a| a.octets()[..3] == [10, 1, 7]));
        // Small subnets are honoured.
        assert_eq!(sweep_targets(Ipv4Addr::new(192, 168, 4, 1), 30).unwrap().len(), 1);
        assert!(sweep_targets(Ipv4Addr::new(8, 8, 8, 8), 24).is_err());
    }

    #[test]
    fn vlan_candidates_skip_our_own_subnet() {
        let c = vlan_candidates(Ipv4Addr::new(10, 1, 7, 9));
        assert!(!c.contains(&[10, 1, 7]) && c.contains(&[10, 1, 8]) && c.contains(&[10, 20, 0]));
        assert!(vlan_candidates(Ipv4Addr::new(192, 168, 1, 5)).iter().all(|n| n[..2] == [192, 168]));
    }

    #[test]
    fn vendors_come_from_the_oui_table() {
        assert_eq!(vendor_for(&[0xB8, 0x27, 0xEB, 1, 2, 3]), "Raspberry Pi Foundation");
        // Locally administered bit set: not in any registry.
        assert_eq!(vendor_for(&[0x02, 0, 0, 0, 0, 1]), "Private address");
        assert_eq!(shorten_vendor("TP-Link Technologies Co.,Ltd."), "TP-Link Technologies");
        assert_eq!(shorten_vendor("Apple, Inc."), "Apple");
    }

    #[test]
    fn device_kind_needs_evidence() {
        assert_eq!(guess_kind("Raspberry Pi Foundation", false), DeviceKind::Raspberry);
        assert_eq!(guess_kind("Espressif Inc.", false), DeviceKind::SmartDevice);
        assert_eq!(guess_kind("TP-Link", true), DeviceKind::WiFi);
        assert_eq!(guess_kind("Dell", false), DeviceKind::Generic);
        assert_eq!(kind_from_i64(kind_to_i64(DeviceKind::Laptop)), DeviceKind::Laptop);
    }

    #[test]
    fn ssdp_server_header() {
        assert_eq!(ssdp_system("Linux/3.14 UPnP/1.0 MiniUPnPd/2.1"), "Linux");
        assert_eq!(ssdp_system("Windows/10.0 UPnP/1.0"), "Windows");
        assert_eq!(ssdp_system("UPnP/1.0"), "");
        assert_eq!(ssdp_system(""), "");
    }

    #[test]
    fn nbstat_names() {
        let mut resp = vec![0u8; 56];
        resp.push(2); // two names
        let mut group = b"WORKGROUP      ".to_vec();
        group.extend([0x00, 0x84, 0x00]); // group flag set
        let mut unique = b"LAPTOP-ABC     ".to_vec();
        unique.extend([0x00, 0x04, 0x00]);
        resp.extend(group);
        resp.extend(unique);
        assert_eq!(parse_nbstat(&resp).as_deref(), Some("LAPTOP-ABC"));
        assert_eq!(parse_nbstat(&[0u8; 10]), None);
        assert_eq!(nbstat_request().len(), 50);
    }

    #[test]
    fn this_machine_networks_are_listed() {
        // Must not panic; the list depends on the machine.
        let _ = networks();
    }
}
