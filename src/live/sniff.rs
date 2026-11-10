//! Driver mode's listener: learns host names the system can't show. It copies (never holds back) the first
//! data packet of outgoing TLS connections to read the server name (SNI), and DNS answers on port 53, and
//! feeds them into the same stream ETW uses, so the Connections tab shows `youtube.com` instead of an
//! address, and the DNS Log gains lookups that bypass Windows' resolver (a browser's own, for instance).
//! The flow handle names the process behind each connection. The same copies feed three watchers: a second DHCP server
//! answering, a browser-named program whose TLS fingerprint is a command-line tool's, and inbound port scans.

use crate::netpkt::{self, FlowKey};
use crate::sys::etw::{self, NetEvent};
use crate::sys::windivert::{self as wd, Address, Handle, Lib};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Outgoing TLS first packets, DNS in both directions, inbound connection attempts and DHCP replies; loopback is left out.
const FILTER: &str =
    "!loopback and ((outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.SrcPort == 53 or (inbound and tcp.Syn and !tcp.Ack) or (inbound and udp.SrcPort == 67 and udp.DstPort == 68))";
/// Flows remembered at most; a leak guard if delete events are missed.
const MAX_FLOWS: usize = 100_000;

struct Running {
    flows: Flows,
    stop: Arc<AtomicBool>,
    handles: [Arc<Handle>; 2],
    threads: Vec<std::thread::JoinHandle<()>>,
}

#[derive(Default)]
pub struct Sniffer {
    running: Mutex<Option<Running>>,
}

impl Sniffer {
    /// Starts or stops the listener so it matches `on`. Slow when it starts (opens the driver).
    pub fn apply(&self, on: bool, hostnames: Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>, shared: Arc<super::store::Shared>) -> Result<(), String> {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = running.as_ref()
            && (!on || r.threads.iter().any(|t| t.is_finished()))
        {
            stop(&mut running);
        }
        if on && running.is_none() {
            *running = Some(start(hostnames, shared)?);
        }
        Ok(())
    }

    pub fn stop(&self) {
        stop(&mut self.running.lock().unwrap_or_else(|e| e.into_inner()));
    }

    /// The UDP flows open now as (process id, local end, remote end), while the listener runs.
    pub fn udp_flows(&self) -> Vec<(u32, std::net::SocketAddr, std::net::SocketAddr)> {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let Some(r) = running.as_ref() else { return Vec::new() };
        let map = r.flows.read().unwrap_or_else(|e| e.into_inner());
        map.iter().filter(|(k, _)| k.proto == netpkt::UDP && k.rport != 0 && !k.remote.is_multicast()).take(500).map(|(k, pid)| (*pid, (k.local, k.lport).into(), (k.remote, k.rport).into())).collect()
    }
}

fn stop(running: &mut Option<Running>) {
    let Some(r) = running.take() else { return };
    r.stop.store(true, Ordering::Relaxed);
    for h in &r.handles {
        h.shutdown();
    }
    for t in r.threads {
        let _ = t.join();
    }
}

type Flows = Arc<RwLock<HashMap<FlowKey, u32>>>;

fn start(known: Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>, shared: Arc<super::store::Shared>) -> Result<Running, String> {
    if crate::driver::state() != crate::driver::DriverState::Ready {
        return Err("The driver isn't installed. Install it in Settings.".into());
    }
    let lib = Lib::load(&crate::driver::dir().join("WinDivert.dll"))?;
    let flow = Arc::new(lib.open("true", wd::LAYER_FLOW, 0, wd::FLAG_SNIFF | wd::FLAG_RECV_ONLY)?);
    let net = Arc::new(lib.open(FILTER, wd::LAYER_NETWORK, 0, wd::FLAG_SNIFF | wd::FLAG_RECV_ONLY)?);
    let (flows, stop) = (Flows::default(), Arc::new(AtomicBool::new(false)));
    let (f2, n2, fl2, keep) = (flow.clone(), net.clone(), flows.clone(), flows.clone());
    let a = std::thread::Builder::new().name("driver-sniff-flows".into()).spawn(move || flow_loop(&f2, &fl2)).map_err(|e| e.to_string())?;
    let b = std::thread::Builder::new().name("driver-sniff-packets".into()).spawn(move || packet_loop(&n2, &flows, &known, &shared)).map_err(|e| e.to_string())?;
    Ok(Running { flows: keep, stop, handles: [flow, net], threads: vec![a, b] })
}

fn flow_loop(flow: &Handle, flows: &Flows) {
    let (mut buf, mut addr) = (vec![0u8; 64], Address::zeroed());
    while flow.recv(&mut buf, &mut addr).is_ok() {
        let f = addr.flow();
        let key = FlowKey { proto: f.proto, local: f.local, lport: f.lport, remote: f.remote, rport: f.rport };
        let mut map = flows.write().unwrap_or_else(|e| e.into_inner());
        match addr.event() {
            wd::EVENT_FLOW_ESTABLISHED => {
                if map.len() >= MAX_FLOWS {
                    map.clear();
                }
                map.insert(key, f.pid);
            }
            wd::EVENT_FLOW_DELETED => {
                map.remove(&key);
            }
            _ => {}
        }
    }
}

fn packet_loop(net: &Handle, flows: &Flows, known: &Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>, shared: &super::store::Shared) {
    let (mut buf, mut addr) = (vec![0u8; wd::MAX_PACKET], Address::zeroed());
    let (mut detector, began) = (crate::scandetect::Detector::default(), std::time::Instant::now());
    let (mut dhcp, mut prints) = (crate::netwatch::DhcpWatch::default(), crate::netwatch::Prints::default());
    // Which of the two alerts are on, read every few seconds rather than for every packet.
    let (mut checked, mut watch) = (std::time::Instant::now(), (true, true));
    while let Ok(len) = net.recv(&mut buf, &mut addr) {
        if checked.elapsed().as_secs() >= 5 {
            let s = shared.settings();
            (checked, watch) = (std::time::Instant::now(), (s.alerts.rogue_dhcp, s.alerts.tls_mismatch));
        }
        let packet = &buf[..len];
        let Some(p) = netpkt::parse(packet) else { continue };
        let payload = &packet[p.payload.min(packet.len())..];
        if !addr.outbound() && p.proto == netpkt::TCP {
            // An incoming connection attempt (SYN without ACK).
            if let Some(found) = detector.syn(began.elapsed().as_millis() as u64, p.src, p.dport) {
                report(shared, &found);
            }
        } else if p.proto == netpkt::TCP {
            // Every server name goes in with the program that asked for it, so its own traffic is named right; the address's
            // general label still only takes it when nothing named the address yet (the collector decides that).
            if let Some(name) = crate::netparse::sni(payload) {
                let pid = flows.read().unwrap_or_else(|e| e.into_inner()).get(&p.flow(true)).copied().unwrap_or(0);
                if pid != 0 || !known(p.dst) {
                    etw::inject(NetEvent::Sni { pid, name, ip: p.dst });
                }
            }
            if watch.1
                && let Some(hello) = crate::tlsprint::parse(payload)
            {
                let pid = flows.read().unwrap_or_else(|e| e.into_inner()).get(&p.flow(true)).copied().unwrap_or(0);
                if let Some(program) = crate::sys::apps::pid_path(pid).map(|path| super::apps::file_name(&path.to_ascii_lowercase()).to_owned())
                    && let Some(m) = prints.note(&program, &crate::tlsprint::ja4(&hello))
                {
                    report_print(shared, &m, &crate::tlsprint::ja3(&hello));
                }
            }
        } else if p.proto == netpkt::UDP && !addr.outbound() && p.sport == 67 && p.dport == 68 {
            // Only an offer or an acknowledgement says "I am a DHCP server"; the server's own id beats the packet's sender.
            if watch.0
                && let Some(reply) = crate::netwatch::dhcp_reply(payload).filter(|r| matches!(r.msg_type, 2 | 5))
                && let std::net::IpAddr::V4(sender) = p.src
            {
                let offer = crate::netwatch::Offer { server: reply.server.unwrap_or(sender), gateway: reply.gateway, dns: reply.dns };
                dhcp_reply(shared, &mut dhcp, addr.if_idx(), offer);
            }
        } else if let Some(m) = crate::netparse::dns(payload).filter(|m| m.response) {
            // Windows' own resolver is already in the DNS log through ETW; only other programs' lookups are new.
            let pid = flows.read().unwrap_or_else(|e| e.into_inner()).get(&p.flow(false)).copied().unwrap_or(0);
            let by_resolver = crate::sys::apps::pid_path(pid).is_some_and(|path| path.to_ascii_lowercase().ends_with("\\svchost.exe"));
            let log = pid != 0 && !by_resolver;
            if log || !m.ips.is_empty() {
                etw::inject(NetEvent::Dns { pid: if log { pid } else { 0 }, name: m.question.0, qtype: m.question.1, status: u32::from(m.rcode), ips: m.ips, log });
            }
        }
    }
}

/// How long an ended UDP flow stays blocked. UDP has no connection to close, so the flow's packets are dropped for a while
/// and the program (or the other end) gives up.
const UDP_KILL_SECS: u64 = 60;

/// The driver filter for both directions of one UDP flow; `None` when the two ends are not the same IP version.
pub fn udp_filter(local: std::net::SocketAddr, remote: std::net::SocketAddr) -> Option<String> {
    let (ip, l, r) = match (local, remote) {
        (std::net::SocketAddr::V4(l), std::net::SocketAddr::V4(r)) => ("ip", (l.ip().to_string(), l.port()), (r.ip().to_string(), r.port())),
        (std::net::SocketAddr::V6(l), std::net::SocketAddr::V6(r)) => ("ipv6", (l.ip().to_string(), l.port()), (r.ip().to_string(), r.port())),
        _ => return None,
    };
    let leg = |(sa, sp): &(String, u16), (da, dp): &(String, u16)| format!("{ip}.SrcAddr == {sa} and udp.SrcPort == {sp} and {ip}.DstAddr == {da} and udp.DstPort == {dp}");
    Some(format!("udp and (({}) or ({}))", leg(&l, &r), leg(&r, &l)))
}

/// Ends a UDP flow by dropping its packets for [`UDP_KILL_SECS`] seconds (Driver mode; needs administrator rights).
pub fn kill_udp(local: std::net::SocketAddr, remote: std::net::SocketAddr) -> Result<String, String> {
    if !crate::driver::ready() {
        return Err("The driver isn't installed. Install it in Settings.".into());
    }
    let filter = udp_filter(local, remote).ok_or("That flow mixes IPv4 and IPv6 addresses.")?;
    let lib = Lib::load(&crate::driver::dir().join("WinDivert.dll"))?;
    let handle = lib.open(&filter, wd::LAYER_NETWORK, 0, wd::FLAG_DROP)?;
    std::thread::Builder::new()
        .name("driver-udp-kill".into())
        .spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(UDP_KILL_SECS));
            drop(handle);
        })
        .map_err(|e| e.to_string())?;
    Ok(format!("Blocked the UDP flow between {local} and {remote} for {UDP_KILL_SECS} seconds."))
}

/// Keeps the listener in step with the settings (Driver mode, "Learn host names") and the driver's state.
pub fn run(shared: Arc<super::store::Shared>, sniffer: Arc<Sniffer>) {
    loop {
        refresh(&shared, &sniffer);
        if !shared.sleep(30.0) {
            break;
        }
    }
    sniffer.stop();
}

pub fn refresh(shared: &Arc<super::store::Shared>, sniffer: &Sniffer) {
    let s = shared.settings();
    let on = shared.elevated && s.app_mode == crate::settings::AppMode::Driver && s.driver_names;
    let st = shared.clone();
    let known: Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync> = Arc::new(move |ip| st.state().hostnames.contains_key(&ip));
    let result = sniffer.apply(on, known, shared.clone());
    let note = if on { result.err().map(|e| crate::data::StatusNote::warn(format!("Driver host names unavailable: {e}"))) } else { None };
    shared.set_note("driver-names", note);
}

/// Files a DHCP offer under the interface it arrived on (servers on different adapters are not rivals), skips trusted
/// servers, and leaves virtual adapters at a status note unless the setting asks for alerts there too.
fn dhcp_reply(shared: &super::store::Shared, dhcp: &mut crate::netwatch::DhcpWatch, if_idx: u32, offer: crate::netwatch::Offer) {
    let s = shared.settings();
    let adapter = crate::sys::netinfo::adapters().ok().and_then(|all| all.into_iter().find(|a| a.if_index == if_idx));
    let name = adapter.as_ref().map_or_else(|| format!("interface {if_idx}"), |a| a.name.clone());
    if crate::netwatch::trusted(&s.dhcp_trusted, &name, offer.server) {
        return;
    }
    let Some(found) = dhcp.note(if_idx, offer, crate::clock::now_unix()) else { return };
    let list = found.offers.iter().map(crate::netwatch::Offer::describe).collect::<Vec<_>>().join("; ");
    if adapter.is_some_and(|a| a.virtual_nic) && !s.dhcp_virtual_alert {
        let note = format!("Several DHCP servers answer on the virtual adapter {name}: {list}. Not alerted (Settings > Alerts > Second DHCP server).");
        shared.set_note("dhcp-virtual", Some(crate::data::StatusNote::info(note)));
        return;
    }
    let Ok(db) = shared.open_db() else { return };
    let text = format!("answered by more than one server on {name}; one of them may not be your router:");
    shared.alert_as(&db, super::alerts::AlertKind::RogueDhcp, "DHCP", &text, &list, "", found.critical);
}

fn report_print(shared: &super::store::Shared, m: &crate::netwatch::Mismatch, ja3: &str) {
    let Ok(db) = shared.open_db() else { return };
    let text = format!("opened a TLS connection with the same fingerprint as {}, a command-line tool, not a web browser:", m.looks_like);
    shared.alert(&db, super::alerts::AlertKind::TlsMismatch, &m.program, &text, &format!("JA4 {} / JA3 {ja3}", m.print), "");
}

fn report(shared: &super::store::Shared, found: &crate::scandetect::Finding) {
    use crate::scandetect::Finding;
    let Ok(db) = shared.open_db() else { return };
    let (app, text, target) = match found {
        Finding::PortScan { src, ports } => {
            ("Port scan", format!("from {src} tried {ports} different ports on this PC in a few seconds:"), "Firewall > Live Connections shows what is listening".to_owned())
        }
        Finding::SynFlood { per_second, busiest } => ("Connection flood", format!("{per_second} connection attempts arrived in one second. The busiest source:"), busiest.to_string()),
    };
    shared.alert(&db, super::alerts::AlertKind::InboundScan, app, &text, &target, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_udp_flow_filter_names_both_directions_and_one_ip_version() {
        let f = udp_filter("192.168.1.20:51000".parse().unwrap(), "142.250.1.1:443".parse().unwrap()).unwrap();
        assert!(f.starts_with("udp and ((ip.SrcAddr == 192.168.1.20 and udp.SrcPort == 51000 and ip.DstAddr == 142.250.1.1 and udp.DstPort == 443)"));
        assert!(f.contains("or (ip.SrcAddr == 142.250.1.1 and udp.SrcPort == 443 and ip.DstAddr == 192.168.1.20 and udp.DstPort == 51000)"));
        assert!(udp_filter("[fd00::20]:5000".parse().unwrap(), "[2620:0:861:ed1a::1]:443".parse().unwrap()).unwrap().contains("ipv6.SrcAddr == fd00::20"));
        assert!(udp_filter("192.168.1.20:5000".parse().unwrap(), "[2620::1]:443".parse().unwrap()).is_none());
    }
}
