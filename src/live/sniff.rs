//! Driver mode's listener: learns host names the system can't show. It copies (never holds back) the first
//! data packet of outgoing TLS connections to read the server name (SNI), and DNS answers on port 53, and
//! feeds them into the same stream ETW uses, so the Connections tab shows `youtube.com` instead of an
//! address, and the DNS Log gains lookups that bypass Windows' resolver (a browser's own, for instance).
//! The flow handle names the process behind each connection.

use crate::netpkt::{self, FlowKey};
use crate::sys::etw::{self, NetEvent};
use crate::sys::windivert::{self as wd, Address, Handle, Lib};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Outgoing TLS first packets and DNS in both directions; loopback is left out.
const FILTER: &str = "!loopback and ((outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.SrcPort == 53 or (inbound and tcp.Syn and !tcp.Ack))";
/// Flows remembered at most; a leak guard if delete events are missed.
const MAX_FLOWS: usize = 100_000;

struct Running {
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
    let (f2, n2, fl2) = (flow.clone(), net.clone(), flows.clone());
    let a = std::thread::Builder::new().name("driver-sniff-flows".into()).spawn(move || flow_loop(&f2, &fl2)).map_err(|e| e.to_string())?;
    let b = std::thread::Builder::new().name("driver-sniff-packets".into()).spawn(move || packet_loop(&n2, &flows, &known, &shared)).map_err(|e| e.to_string())?;
    Ok(Running { stop, handles: [flow, net], threads: vec![a, b] })
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
    while let Ok(len) = net.recv(&mut buf, &mut addr) {
        let packet = &buf[..len];
        let Some(p) = netpkt::parse(packet) else { continue };
        let payload = &packet[p.payload.min(packet.len())..];
        if !addr.outbound() && p.proto == netpkt::TCP {
            // An incoming connection attempt (SYN without ACK).
            if let Some(found) = detector.syn(began.elapsed().as_millis() as u64, p.src, p.dport) {
                report(shared, &found);
            }
        } else if p.proto == netpkt::TCP {
            // The server name fills a gap only: an address a DNS answer already named keeps that name.
            if let Some(name) = crate::netparse::sni(payload)
                && !known(p.dst)
            {
                etw::inject(NetEvent::Dns { pid: 0, name, qtype: 1, status: 0, ips: vec![p.dst], log: false });
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
