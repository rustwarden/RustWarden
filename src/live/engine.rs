//! The Driver-mode engine: holds programs to the upload and download limits of `qos::QosLimit` using the
//! WinDivert driver. A flow handle (sniff only) learns which process owns each connection; a network handle
//! receives only the packets of limited programs' connections (its filter is rebuilt from the flow handle's
//! findings, so the VPN tunnel, DNS and every other program never go through it), and paces them with a `netpkt::Shaper` (late packets are dropped, which makes TCP slow
//! down). One receive thread, one send thread for the delayed packets, one flow thread; `apply` is the only
//! way in, so the UI never touches a handle.
//!
//! Limits: a connection that was already open when the engine started is found through the TCP table, but
//! an open UDP flow (QUIC) is only limited once it is re-established.

use crate::netpkt::{self, FlowKey, Shaper};
use crate::qos::{Priority, QosLimit};
use crate::sys::windivert::{self as wd, Address, Handle, Lib};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

/// A delayed packet may wait this long before it is dropped instead.
const MAX_DELAY_MS: u64 = 150;
/// Packets held at once, at most.
const MAX_QUEUED: usize = 20_000;
/// The packet thread taking longer than this over one packet means it is stuck; the engine lets go of the traffic.
const STALL_MS: u64 = 2_000;
/// This many packets in a row that could not be handed back means they are being lost; the engine lets go.
const MAX_SEND_FAILS: u64 = 200;
const LOG: &str = "engine.log";
/// Outbound TCP/UDP drops attributed to "System" (what the firewall does to the engine's own packets when they are not
/// allowed), counted by Prompt's blocked-connection listener.
static SYSTEM_DROPS: AtomicU64 = AtomicU64::new(0);
/// Set once the engine shut itself off because of those drops; `apply` then refuses to start it until the limits are cleared.
static TRIPPED: AtomicBool = AtomicBool::new(false);
/// This many such drops within [`DROP_WINDOW_MS`] means the firewall is eating the engine's packets.
const DROP_LIMIT: u64 = 15;
const DROP_WINDOW_MS: u128 = 3_000;

/// Whether the engine switched itself off because the firewall was dropping its packets.
pub fn tripped() -> bool {
    TRIPPED.load(Ordering::Relaxed)
}

pub fn note_system_drop() {
    SYSTEM_DROPS.fetch_add(1, Ordering::Relaxed);
}

/// Whether `drops` in one window is a flood.
fn is_flood(drops: u64) -> bool {
    drops >= DROP_LIMIT
}

fn log(msg: &str) {
    crate::applog::line(LOG, msg);
}

/// The line's capacity shared by the priority classes, per direction (0 = up, 1 = down). High is counted but never held back;
/// Normal may use what High leaves, Low what both leave. Re-balanced about once a second from what each class actually used.
struct Line {
    kbps: [u32; 2],
    /// Bytes seen since the last re-balance, by direction and class (High, Normal, Low).
    used: [[AtomicU64; 3]; 2],
    /// The Normal and Low classes' shared shapers.
    shaper: [[Mutex<Shaper>; 2]; 2],
    tuned_ns: AtomicU64,
}

impl Line {
    /// `None` when no line speed is set.
    fn new(up_mbps: u32, down_mbps: u32) -> Option<Arc<Line>> {
        let kbps = [up_mbps.saturating_mul(1000), down_mbps.saturating_mul(1000)];
        let shaper = |d: usize| [0, 1].map(|_| Mutex::new(Shaper::new(kbps[d].max(1), MAX_DELAY_MS)));
        (kbps != [0, 0]).then(|| Arc::new(Line { kbps, used: Default::default(), shaper: [shaper(0), shaper(1)], tuned_ns: AtomicU64::new(0) }))
    }

    /// When a packet of `len` bytes may go, or `None` to drop it.
    fn admit(&self, dir: usize, prio: Priority, now_ns: u64, len: usize) -> Option<u64> {
        self.retune(now_ns);
        let class = prio as usize;
        self.used[dir][class].fetch_add(len as u64, Ordering::Relaxed);
        if self.kbps[dir] == 0 || prio == Priority::High {
            return Some(now_ns);
        }
        self.shaper[dir][class - 1].lock().unwrap_or_else(|e| e.into_inner()).admit(now_ns, len)
    }

    fn retune(&self, now_ns: u64) {
        let last = self.tuned_ns.load(Ordering::Relaxed);
        let dt = now_ns.saturating_sub(last);
        if dt < 1_000_000_000 || self.tuned_ns.compare_exchange(last, now_ns, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            return;
        }
        for dir in 0..2 {
            let line = u64::from(self.kbps[dir]);
            if line == 0 {
                continue;
            }
            let [high, normal, _] = [0, 1, 2].map(|c| self.used[dir][c].swap(0, Ordering::Relaxed) * 8_000_000 / dt);
            let normal_pool = line.saturating_sub(high).max(line / 10);
            let low_pool = line.saturating_sub(high + normal).max(line / 20);
            for (shaper, pool) in self.shaper[dir].iter().zip([normal_pool, low_pool]) {
                shaper.lock().unwrap_or_else(|e| e.into_inner()).set_rate(pool.min(u64::from(u32::MAX)) as u32);
            }
        }
    }
}

/// One program's limit as the packet threads see it.
struct Limit {
    program: String,
    prio: Priority,
    line: Option<Arc<Line>>,
    up: Option<Mutex<Shaper>>,
    down: Option<Mutex<Shaper>>,
    /// Simulated conditions, for both directions: added delay and the share of packets lost.
    delay_ns: u64,
    loss_pct: u8,
}

/// What to do with one packet of a limited program.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Pass,
    Drop,
    /// Send at this time (nanoseconds on the engine's clock).
    At(u64),
}

impl Limit {
    fn of(l: &QosLimit, now_secs: i64) -> Limit {
        // A rate of 0 means no cap (a pure simulation); an ended simulation adds nothing.
        let shaper = |on: bool, kbps: u32| (on && kbps > 0).then(|| Mutex::new(Shaper::new(kbps, MAX_DELAY_MS)));
        let sim = l.simulating(now_secs);
        Limit {
            program: l.program.to_lowercase(),
            prio: l.priority,
            line: None,
            up: shaper(l.dir.up(), l.kbps),
            down: shaper(l.dir.down(), l.down_kbps),
            delay_ns: if sim { u64::from(l.delay_ms) * 1_000_000 } else { 0 },
            loss_pct: if sim { l.loss_pct } else { 0 },
        }
    }

    /// `roll` is a random number from 0 to 99.
    fn plan(&self, outbound: bool, now_ns: u64, len: usize, roll: u8) -> Plan {
        if roll < self.loss_pct {
            return Plan::Drop;
        }
        let shaper = if outbound { &self.up } else { &self.down };
        let at = match shaper.as_ref().map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).admit(now_ns, len)) {
            Some(None) => return Plan::Drop,
            Some(Some(at)) => at,
            None => now_ns,
        };
        let at = match &self.line {
            Some(line) => match line.admit(usize::from(!outbound), self.prio, now_ns, len) {
                Some(t) => at.max(t),
                None => return Plan::Drop,
            },
            None => at,
        };
        match at + self.delay_ns {
            t if t <= now_ns => Plan::Pass,
            t => Plan::At(t),
        }
    }
}

/// What the three threads share.
struct State {
    limits: RwLock<Vec<Arc<Limit>>>,
    /// Connections of limited programs.
    flows: RwLock<HashMap<FlowKey, Arc<Limit>>>,
    queue: Mutex<BinaryHeap<Reverse<Held>>>,
    wake: Condvar,
    stop: AtomicBool,
    alive: AtomicBool,
    began: Instant,
    rng: AtomicU64,
    /// For the log and the watchdog.
    stats: Stats,
    /// The packet handle. Its filter names only the connections of limited programs (so nothing else is ever touched), and
    /// is replaced by a new handle whenever those connections change.
    net: RwLock<Option<Arc<Handle>>>,
    /// Bumped on each replacement, so the packet thread can tell a swap from a failure.
    net_gen: AtomicU64,
    /// Wakes the filter thread the moment a limited program opens a connection, so its packets are captured
    /// within milliseconds instead of at the next timer tick.
    filter_wake: Condvar,
    filter_lock: Mutex<()>,
    /// Set by the packet thread when it captures a TCP packet that matches no tracked connection: the filter thread then
    /// re-reads the TCP table at once (not at the next second), so a limited program's connection that the events missed
    /// is limited within about a tenth of a second.
    resync_wanted: AtomicBool,
}

#[derive(Default)]
struct Stats {
    seen: AtomicU64,
    passed: AtomicU64,
    shaped: AtomicU64,
    dropped: AtomicU64,
    send_errors: AtomicU64,
    /// Consecutive failures to hand a packet back.
    send_streak: AtomicU64,
    /// When the packet thread began its current packet (ns on the engine's clock, 0 while it waits for one).
    busy_since: AtomicU64,
}

impl State {
    /// A quick xorshift roll from 0 to 99; losses only need to look random.
    fn roll(&self) -> u8 {
        let mut x = self.rng.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng.store(x, Ordering::Relaxed);
        (x % 100) as u8
    }

    fn now_ns(&self) -> u64 {
        self.began.elapsed().as_nanos() as u64
    }

    fn net(&self) -> Option<Arc<Handle>> {
        self.net.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn limit_for(&self, program: &str) -> Option<Arc<Limit>> {
        let lc = program.to_lowercase();
        self.limits.read().unwrap_or_else(|e| e.into_inner()).iter().find(|l| l.program == lc).cloned()
    }

    /// Records a new connection; true when it belongs to a limited program.
    fn track(&self, pid: u32, key: FlowKey) -> bool {
        let limit = crate::sys::apps::pid_path(pid).and_then(|p| self.limit_for(&p));
        let mut flows = self.flows.write().unwrap_or_else(|e| e.into_inner());
        match limit {
            Some(l) => {
                flows.insert(key, l);
                true
            }
            None => {
                flows.remove(&key);
                false
            }
        }
    }

    /// Brings the TCP part of the connection map in line with the TCP table: adds the open connections of limited programs
    /// the events missed (or erased: a closing connection's late "deleted" event can remove a new one that reuses its port),
    /// and drops the TCP connections that are gone. UDP is left to the events.
    fn resync(&self) {
        let Ok(rows) = crate::sys::conns::table(false) else { return };
        let mut by_pid: HashMap<u32, Option<Arc<Limit>>> = HashMap::new();
        let mut alive: HashMap<FlowKey, Arc<Limit>> = HashMap::new();
        for r in rows {
            let limit = by_pid.entry(r.pid).or_insert_with(|| crate::sys::apps::pid_path(r.pid).and_then(|p| self.limit_for(&p))).clone();
            if let Some(l) = limit {
                alive.insert(FlowKey { proto: netpkt::TCP, local: r.local.ip(), lport: r.local.port(), remote: r.remote.ip(), rport: r.remote.port() }, l);
            }
        }
        let mut flows = self.flows.write().unwrap_or_else(|e| e.into_inner());
        flows.retain(|k, _| k.proto != netpkt::TCP || alive.contains_key(k));
        for (k, l) in alive {
            flows.entry(k).or_insert(l);
        }
    }

    /// Finds the connections already open (TCP only) that belong to limited programs.
    fn seed(&self) {
        // The slow part (the connection table, and a program lookup per owner) comes first and touches nothing shared;
        // the map is then updated in one short step. Emptying it while this ran let every packet through unlimited.
        let rows = crate::sys::conns::table(false).unwrap_or_default();
        let mut by_pid: HashMap<u32, Option<Arc<Limit>>> = HashMap::new();
        let mut seeded: HashMap<FlowKey, Arc<Limit>> = HashMap::new();
        for r in rows {
            let limit = by_pid.entry(r.pid).or_insert_with(|| crate::sys::apps::pid_path(r.pid).and_then(|p| self.limit_for(&p))).clone();
            if let Some(l) = limit {
                seeded.insert(FlowKey { proto: netpkt::TCP, local: r.local.ip(), lport: r.local.port(), remote: r.remote.ip(), rport: r.remote.port() }, l);
            }
        }
        // Keep what the connection events have learned (UDP, and connections too new for the table), pointing each at the
        // program's current limit; a program that is no longer limited loses its connections.
        let mut flows = self.flows.write().unwrap_or_else(|e| e.into_inner());
        flows.retain(|_, l| match self.limit_for(&l.program) {
            Some(now) => {
                *l = now;
                true
            }
            None => false,
        });
        flows.extend(seeded);
    }
}

/// A packet waiting for its time.
struct Held {
    at: u64,
    seq: u64,
    packet: Vec<u8>,
    addr: Address,
}

impl PartialEq for Held {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.seq) == (o.at, o.seq)
    }
}
impl Eq for Held {}
impl PartialOrd for Held {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Held {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.at, self.seq).cmp(&(o.at, o.seq))
    }
}

struct Running {
    state: Arc<State>,
    flow: Arc<Handle>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

#[derive(Default)]
pub struct Engine {
    running: Mutex<Option<Running>>,
}

impl Engine {
    /// Makes the engine enforce exactly `limits` (the enabled, valid ones), starting it if it isn't
    /// running and stopping it when there are none. Slow: opens the driver; call it off the UI thread.
    pub fn apply(&self, limits: &[QosLimit], line_mbps: (u32, u32)) -> Result<(), String> {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if limits.is_empty() {
            TRIPPED.store(false, Ordering::Relaxed);
            stop(&mut running);
            return Ok(());
        }
        if TRIPPED.load(Ordering::Relaxed) {
            return Err("Windows Firewall blocked the driver's packets, so the engine was switched off to keep your internet working. Remove the limits and add them again to retry.".into());
        }
        if running.as_ref().is_some_and(|r| !r.state.alive.load(Ordering::Relaxed)) {
            stop(&mut running);
        }
        if running.is_none() {
            *running = Some(start()?);
        }
        let r = running.as_ref().ok_or("The driver engine did not start.")?;
        let line = Line::new(line_mbps.0, line_mbps.1);
        *r.state.limits.write().unwrap_or_else(|e| e.into_inner()) = limits
            .iter()
            .map(|l| {
                let mut limit = Limit::of(l, crate::clock::now_unix());
                limit.line = line.clone();
                Arc::new(limit)
            })
            .collect();
        r.state.seed();
        let flows = r.state.flows.read().unwrap_or_else(|e| e.into_inner()).len();
        log(&format!(
            "limits applied: {}; {flows} open connections found",
            limits.iter().map(|l| format!("{} (up {} kbps, down {} kbps, {:?})", l.program, l.kbps, l.down_kbps, l.dir)).collect::<Vec<_>>().join(", ")
        ));
        Ok(())
    }

    pub fn stop(&self) {
        stop(&mut self.running.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

fn stop(running: &mut Option<Running>) {
    let Some(r) = running.take() else { return };
    r.state.stop.store(true, Ordering::Relaxed);
    report(&r.state);
    log("engine stopped");
    r.flow.shutdown();
    if let Some(n) = r.state.net() {
        n.shutdown();
    }
    r.state.wake.notify_all();
    r.state.filter_wake.notify_all();
    for t in r.threads {
        let _ = t.join();
    }
}

fn start() -> Result<Running, String> {
    if crate::driver::state() != crate::driver::DriverState::Ready {
        return Err("The driver isn't installed. Install it in Settings.".into());
    }
    let lib = Lib::load(&crate::driver::dir().join("WinDivert.dll"))?;
    let flow = Arc::new(lib.open("true", wd::LAYER_FLOW, 0, wd::FLAG_SNIFF | wd::FLAG_RECV_ONLY)?);
    // Nothing is captured until a limited program has a connection (see `filter_loop`).
    let net = Arc::new(lib.open("false", wd::LAYER_NETWORK, 0, 0)?);
    let state = Arc::new(State {
        limits: RwLock::default(),
        flows: RwLock::default(),
        queue: Mutex::default(),
        wake: Condvar::new(),
        stop: AtomicBool::new(false),
        alive: AtomicBool::new(true),
        began: Instant::now(),
        rng: AtomicU64::new(0x9e37_79b9_7f4a_7c15),
        stats: Stats::default(),
        net: RwLock::new(Some(net)),
        net_gen: AtomicU64::new(0),
        filter_wake: Condvar::new(),
        filter_lock: Mutex::new(()),
        resync_wanted: AtomicBool::new(false),
    });
    let mut threads = Vec::new();
    let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| std::thread::Builder::new().name(name.into()).spawn(f).map_err(|e| format!("Can't start the driver engine: {e}"));
    let (s, h) = (state.clone(), flow.clone());
    threads.push(spawn("driver-flows", Box::new(move || flow_loop(&s, &h)))?);
    let s = state.clone();
    threads.push(spawn("driver-packets", Box::new(move || packet_loop(&s)))?);
    let s = state.clone();
    threads.push(spawn("driver-release", Box::new(move || release_loop(&s)))?);
    let (s, f) = (state.clone(), flow.clone());
    threads.push(spawn("driver-watch", Box::new(move || watch_loop(&s, &f)))?);
    let (s, l) = (state.clone(), lib.clone());
    threads.push(spawn("driver-filter", Box::new(move || filter_loop(&s, &l)))?);
    log("engine started");
    Ok(Running { state, flow, threads })
}

/// Ends the engine from inside: the other threads see `alive` go false and the next `apply` restarts it.
fn die(state: &State, handles: &[&Handle], why: &str) {
    if !state.stop.load(Ordering::Relaxed) && state.alive.swap(false, Ordering::Relaxed) {
        log(&format!("engine ended itself and released all traffic: {why}"));
    }
    for h in handles {
        h.shutdown();
    }
    if let Some(n) = state.net() {
        n.shutdown();
    }
    state.wake.notify_all();
    state.filter_wake.notify_all();
}

fn flow_loop(state: &State, flow: &Handle) {
    let (mut buf, mut addr) = (vec![0u8; 64], Address::zeroed());
    while flow.recv(&mut buf, &mut addr).is_ok() {
        let f = addr.flow();
        let key = FlowKey { proto: f.proto, local: f.local, lport: f.lport, remote: f.remote, rport: f.rport };
        match addr.event() {
            wd::EVENT_FLOW_ESTABLISHED => {
                if state.track(f.pid, key) {
                    state.filter_wake.notify_one();
                }
            }
            wd::EVENT_FLOW_DELETED => {
                state.flows.write().unwrap_or_else(|e| e.into_inner()).remove(&key);
            }
            _ => {}
        }
    }
    die(state, &[flow], "the connection-tracking handle stopped");
}

fn packet_loop(state: &State) {
    let mut buf = vec![0u8; wd::MAX_PACKET];
    let mut addr = Address::zeroed();
    let mut seq = 0u64;
    let st = &state.stats;
    let mut generation = state.net_gen.load(Ordering::Relaxed);
    let Some(mut net) = state.net() else { return die(state, &[], "the packet handle is gone") };
    let reason = loop {
        let len = match net.recv(&mut buf, &mut addr) {
            Ok(len) => len,
            // The filter thread replaced the handle and stopped it taking new packets; this one has now handed over everything
            // it had queued, so carry on with the new one.
            Err(_) if state.net_gen.load(Ordering::Relaxed) != generation && !state.stop.load(Ordering::Relaxed) => {
                generation = state.net_gen.load(Ordering::Relaxed);
                match state.net() {
                    Some(n) => net = n,
                    None => break "the packet handle is gone".to_owned(),
                }
                continue;
            }
            Err(code) => break format!("receiving packets failed (Windows error {code})"),
        };
        st.busy_since.store(state.now_ns().max(1), Ordering::Relaxed);
        st.seen.fetch_add(1, Ordering::Relaxed);
        let packet = &buf[..len];
        let parsed = netpkt::parse(packet);
        let limit = parsed.as_ref().and_then(|p| state.flows.read().unwrap_or_else(|e| e.into_inner()).get(&p.flow(addr.outbound())).cloned());
        // A TCP packet of no tracked connection: the table is re-read at once, so a limited program's connection that the
        // events missed is limited within about a tenth of a second.
        if limit.is_none() && parsed.is_some_and(|p| p.proto == netpkt::TCP) && !state.resync_wanted.swap(true, Ordering::Relaxed) {
            state.filter_wake.notify_one();
        }
        let plan = limit.map_or(Plan::Pass, |limit| limit.plan(addr.outbound(), state.now_ns(), len, state.roll()));
        match plan {
            // Not limited (or nothing to do in this direction): straight back.
            Plan::Pass => {
                st.passed.fetch_add(1, Ordering::Relaxed);
                // The current handle: the one that received it may have been replaced a moment ago.
                match state.net().ok_or(0).and_then(|n| n.send(packet, &addr)) {
                    Ok(()) => st.send_streak.store(0, Ordering::Relaxed),
                    Err(code) => {
                        if st.send_errors.fetch_add(1, Ordering::Relaxed) < 10 {
                            log(&format!("couldn't hand a packet back (Windows error {code}, {len} bytes, outbound {})", addr.outbound()));
                        }
                        if st.send_streak.fetch_add(1, Ordering::Relaxed) + 1 >= MAX_SEND_FAILS {
                            break format!("{MAX_SEND_FAILS} packets in a row could not be handed back (last Windows error {code})");
                        }
                    }
                }
            }
            Plan::Drop => {
                st.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Plan::At(at) => {
                st.shaped.fetch_add(1, Ordering::Relaxed);
                let mut q = state.queue.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() < MAX_QUEUED {
                    seq += 1;
                    q.push(Reverse(Held { at, seq, packet: packet.to_vec(), addr }));
                    state.wake.notify_one();
                }
            }
        }
        st.busy_since.store(0, Ordering::Relaxed);
    };
    die(state, &[], &reason);
}

/// One line of counters for engine.log.
fn report(state: &State) {
    let st = &state.stats;
    let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let (flows, queued) = (state.flows.read().unwrap_or_else(|e| e.into_inner()).len(), state.queue.lock().unwrap_or_else(|e| e.into_inner()).len());
    log(&format!(
        "packets seen {} passed {} paced {} dropped {} send errors {}; tracked connections {flows}, queued {queued}",
        get(&st.seen),
        get(&st.passed),
        get(&st.shaped),
        get(&st.dropped),
        get(&st.send_errors)
    ));
}

/// Logs a line of counters every half minute, and lets go of all traffic if the packet thread is stuck.
fn watch_loop(state: &State, flow: &Handle) {
    let st = &state.stats;
    let mut last_report = Instant::now();
    let (mut window_start, mut window_base) = (Instant::now(), SYSTEM_DROPS.load(Ordering::Relaxed));
    while !state.stop.load(Ordering::Relaxed) && state.alive.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(250));
        if window_start.elapsed().as_millis() >= DROP_WINDOW_MS {
            let now = SYSTEM_DROPS.load(Ordering::Relaxed);
            if is_flood(now - window_base) {
                TRIPPED.store(true, Ordering::Relaxed);
                die(
                    state,
                    &[flow],
                    &format!("Windows Firewall dropped {} of the engine's packets in {} s (outbound is blocked by default and nothing allows them)", now - window_base, DROP_WINDOW_MS / 1000),
                );
                return;
            }
            (window_start, window_base) = (Instant::now(), now);
        }
        let busy = st.busy_since.load(Ordering::Relaxed);
        if busy != 0 && state.now_ns().saturating_sub(busy) > STALL_MS * 1_000_000 {
            die(state, &[flow], &format!("the packet thread was stuck on one packet for over {STALL_MS} ms"));
            return;
        }
        if last_report.elapsed() >= Duration::from_secs(30) {
            last_report = Instant::now();
            report(state);
        }
    }
}

/// Most connections the filter names at once; more than WinDivert accepts is halved until it fits (the rest go unlimited).
const MAX_FILTER_PORTS: usize = 60;

/// The WinDivert filter that selects only packets of the given local ports, TCP and UDP.
fn net_filter(tcp: &[u16], udp: &[u16]) -> String {
    let terms: Vec<String> = tcp.iter().map(|p| format!("tcp.SrcPort == {p} or tcp.DstPort == {p}")).chain(udp.iter().map(|p| format!("udp.SrcPort == {p} or udp.DstPort == {p}"))).collect();
    if terms.is_empty() { "false".into() } else { format!("!loopback and ({})", terms.join(" or ")) }
}

/// The sorted, de-duplicated local ports of the limited connections: (TCP, UDP).
fn limited_ports(flows: &HashMap<FlowKey, Arc<Limit>>) -> (Vec<u16>, Vec<u16>) {
    let pick = |proto: u8| {
        let mut ports: Vec<u16> = flows.keys().filter(|k| k.proto == proto).map(|k| k.lport).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    };
    (pick(netpkt::TCP), pick(netpkt::UDP))
}

/// Whether the open filter (naming `open_*`) should be replaced by one for `tcp`/`udp`: when a connection is missing from it,
/// or when it names many more than are open now.
fn filter_needs_swap(open_tcp: &[u16], open_udp: &[u16], tcp: &[u16], udp: &[u16]) -> bool {
    const STALE: usize = 20;
    let missing = tcp.iter().any(|p| !open_tcp.contains(p)) || udp.iter().any(|p| !open_udp.contains(p));
    missing || (open_tcp.len() + open_udp.len()).saturating_sub(tcp.len() + udp.len()) >= STALE
}

/// Keeps the packet handle's filter equal to the limited connections. Everything else on the machine (the VPN's own
/// tunnel, other programs) never reaches the engine, so it keeps its identity: a packet sent back by the engine belongs to
/// no program, and identity-based filters such as a VPN kill switch or a default-deny firewall drop it.
fn filter_loop(state: &State, lib: &Arc<Lib>) {
    let mut wanted = String::from("false");
    // The ports the open handle's filter names.
    let (mut open_tcp, mut open_udp): (Vec<u16>, Vec<u16>) = (Vec::new(), Vec::new());
    let mut last_resync = Instant::now();
    while !state.stop.load(Ordering::Relaxed) && state.alive.load(Ordering::Relaxed) {
        // Wakes at once for a new connection of a limited program (or after 200 ms anyway), then waits a few
        // milliseconds so a burst of new connections is one swap, not one each.
        {
            let guard = state.filter_lock.lock().unwrap_or_else(|e| e.into_inner());
            let _ = state.filter_wake.wait_timeout(guard, Duration::from_millis(200));
        }
        std::thread::sleep(Duration::from_millis(5));
        let asked = state.resync_wanted.load(Ordering::Relaxed) && last_resync.elapsed() >= Duration::from_millis(100);
        if asked || last_resync.elapsed() >= Duration::from_secs(1) {
            last_resync = Instant::now();
            state.resync_wanted.store(false, Ordering::Relaxed);
            state.resync();
        }
        let (mut tcp, mut udp) = limited_ports(&state.flows.read().unwrap_or_else(|e| e.into_inner()));
        tcp.truncate(MAX_FILTER_PORTS);
        udp.truncate(MAX_FILTER_PORTS.saturating_sub(tcp.len()));
        // A closed connection left in the filter costs nothing, so only a new one (or a pile of stale ones) is worth a swap.
        if !filter_needs_swap(&open_tcp, &open_udp, &tcp, &udp) {
            continue;
        }
        let want = net_filter(&tcp, &udp);
        if want == wanted {
            continue;
        }
        wanted = want;
        (open_tcp, open_udp) = (tcp.clone(), udp.clone());
        let opened = loop {
            let filter = net_filter(&tcp, &udp);
            match lib.open(&filter, wd::LAYER_NETWORK, 0, 0) {
                Ok(h) => break Some(h),
                Err(e) if tcp.len() + udp.len() > 1 => {
                    // Too long a filter: name fewer connections.
                    log(&format!("the packet filter for {} connections was refused ({e}); trying fewer", tcp.len() + udp.len()));
                    tcp.truncate(tcp.len() / 2);
                    udp.truncate(udp.len() / 2);
                }
                Err(e) => {
                    log(&format!("couldn't open the packet filter: {e}"));
                    break None;
                }
            }
        };
        let Some(handle) = opened else {
            die(state, &[], "the packet filter could not be updated");
            return;
        };
        let old = state.net.write().unwrap_or_else(|e| e.into_inner()).replace(Arc::new(handle));
        state.net_gen.fetch_add(1, Ordering::Relaxed);
        if let Some(old) = old {
            // Packets already queued in it are still delivered, so the swap loses none.
            old.shutdown_recv();
        }
    }
}

fn release_loop(state: &State) {
    let mut q = state.queue.lock().unwrap_or_else(|e| e.into_inner());
    while !state.stop.load(Ordering::Relaxed) && state.alive.load(Ordering::Relaxed) {
        let now = state.now_ns();
        match q.peek().map(|Reverse(h)| h.at) {
            Some(at) if at <= now => {
                let Some(Reverse(h)) = q.pop() else { continue };
                drop(q);
                if let Some(n) = state.net() {
                    let _ = n.send(&h.packet, &h.addr);
                }
                q = state.queue.lock().unwrap_or_else(|e| e.into_inner());
            }
            Some(at) => q = state.wake.wait_timeout(q, Duration::from_nanos(at - now)).unwrap_or_else(|e| e.into_inner()).0,
            None => q = state.wake.wait_timeout(q, Duration::from_millis(500)).unwrap_or_else(|e| e.into_inner()).0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qos::LimitDir;

    #[test]
    fn a_limit_only_paces_the_directions_it_names() {
        let l = QosLimit { dir: LimitDir::Down, down_kbps: 500, ..QosLimit::upload(1, true, r"C:\Apps\Game.exe", 0) };
        let rt = Limit::of(&l, 0);
        assert!(rt.up.is_none() && rt.down.is_some());
        assert_eq!(rt.program, r"c:\apps\game.exe");
        assert_eq!(rt.down.as_ref().unwrap().lock().unwrap().rate(), 500);
        let both = Limit::of(&QosLimit { dir: LimitDir::Both, down_kbps: 9, ..QosLimit::upload(2, true, "x", 8) }, 0);
        assert!(both.up.is_some() && both.down.is_some());
    }

    #[test]
    fn simulated_loss_and_delay_apply_to_both_directions() {
        let sim = QosLimit { delay_ms: 100, loss_pct: 30, sim_until: 1000, ..QosLimit::upload(1, true, "x", 0) };
        let l = Limit::of(&sim, 0);
        assert!(l.up.is_none(), "a rate of 0 is no cap");
        assert_eq!(l.plan(true, 5, 1000, 29), Plan::Drop, "the roll is under the loss share");
        assert_eq!(l.plan(true, 5, 1000, 30), Plan::At(5 + 100_000_000));
        assert_eq!(l.plan(false, 5, 1000, 99), Plan::At(5 + 100_000_000));
        let over = Limit::of(&sim, 1000);
        assert_eq!(over.plan(true, 5, 1000, 0), Plan::Pass, "an ended simulation does nothing");
        let capped = Limit::of(&QosLimit::upload(2, true, "y", 8), 0);
        assert_eq!(capped.plan(true, 0, 100, 99), Plan::Pass, "the first packet of a cap goes at once");
        assert_eq!(capped.plan(false, 0, 100, 99), Plan::Pass, "downloads aren't capped by an upload limit");
    }

    #[test]
    fn a_burst_of_system_drops_trips_the_guard_but_a_trickle_does_not() {
        assert!(is_flood(DROP_LIMIT) && is_flood(200));
        assert!(!is_flood(0) && !is_flood(DROP_LIMIT - 1));
    }

    #[test]
    fn the_packet_filter_names_only_the_limited_connections() {
        assert_eq!(net_filter(&[], &[]), "false", "nothing limited, nothing captured");
        assert_eq!(net_filter(&[50000], &[]), "!loopback and (tcp.SrcPort == 50000 or tcp.DstPort == 50000)");
        let f = net_filter(&[1, 2], &[3]);
        assert!(f.contains("tcp.SrcPort == 2") && f.contains("udp.DstPort == 3") && f.starts_with("!loopback and ("));
        let limit = Arc::new(Limit::of(&QosLimit::upload(1, true, "x", 8), 0));
        let key = |proto, lport| FlowKey { proto, local: "10.0.0.2".parse().unwrap(), lport, remote: "1.1.1.1".parse().unwrap(), rport: 443 };
        let flows: HashMap<_, _> =
            [key(netpkt::TCP, 50002), key(netpkt::TCP, 50001), key(netpkt::UDP, 50003), FlowKey { rport: 80, ..key(netpkt::TCP, 50001) }].into_iter().map(|k| (k, limit.clone())).collect();
        assert_eq!(limited_ports(&flows), (vec![50001, 50002], vec![50003]), "sorted, one entry per port");
    }

    #[test]
    fn the_filter_is_swapped_for_a_new_connection_but_not_for_a_closed_one() {
        assert!(filter_needs_swap(&[], &[], &[5000], &[]), "the first connection");
        assert!(filter_needs_swap(&[5000], &[], &[5000, 5001], &[]), "a new one");
        assert!(filter_needs_swap(&[5000], &[], &[5000], &[6000]), "a new UDP one");
        assert!(!filter_needs_swap(&[5000, 5001], &[], &[5000], &[]), "one closed: leave it");
        let many: Vec<u16> = (1..=25).collect();
        assert!(filter_needs_swap(&many, &[], &[1], &[]), "a pile of closed ones is cleared");
        assert!(!filter_needs_swap(&[], &[], &[], &[]));
    }

    #[test]
    fn rolls_cover_the_range() {
        let state = State {
            limits: RwLock::default(),
            flows: RwLock::default(),
            queue: Mutex::default(),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
            alive: AtomicBool::new(true),
            began: Instant::now(),
            rng: AtomicU64::new(0x9e37_79b9_7f4a_7c15),
            stats: Stats::default(),
            net: RwLock::default(),
            net_gen: AtomicU64::new(0),
            filter_wake: Condvar::new(),
            filter_lock: Mutex::new(()),
            resync_wanted: AtomicBool::new(false),
        };
        let rolls: Vec<u8> = (0..2000).map(|_| state.roll()).collect();
        assert!(rolls.iter().all(|r| *r < 100));
        let low = rolls.iter().filter(|r| **r < 10).count();
        assert!((100..300).contains(&low), "about a tenth of rolls are under 10, got {low}");
    }

    #[test]
    fn held_packets_come_out_earliest_first() {
        let held = |at, seq| Reverse(Held { at, seq, packet: vec![], addr: Address::zeroed() });
        let mut q = BinaryHeap::new();
        for (at, seq) in [(30, 1), (10, 2), (10, 3), (20, 4)] {
            q.push(held(at, seq));
        }
        let order: Vec<_> = std::iter::from_fn(|| q.pop().map(|Reverse(h)| (h.at, h.seq))).collect();
        assert_eq!(order, [(10, 2), (10, 3), (20, 4), (30, 1)]);
    }

    #[test]
    fn nothing_starts_without_the_driver() {
        let e = Engine::default();
        assert!(e.apply(&[], (0, 0)).is_ok(), "no limits means nothing to run");
        if crate::driver::state() != crate::driver::DriverState::Ready {
            assert!(e.apply(&[QosLimit::upload(1, true, r"C:\a.exe", 100)], (0, 0)).is_err());
        }
    }

    #[test]
    fn the_line_serves_high_first_and_squeezes_the_rest() {
        let line = Line::new(8, 0).unwrap(); // 8 Mbps up = 1 MB/s
        // High is never held back; 750 kB of it in the first second leaves 2 Mbps for the rest.
        for i in 0..750 {
            assert_eq!(line.admit(0, Priority::High, i * 1_000_000, 1000), Some(i * 1_000_000));
        }
        assert_eq!(line.admit(0, Priority::High, 1_000_000_000, 1000), Some(1_000_000_000));
        assert_eq!(line.shaper[0][0].lock().unwrap().rate(), 2000, "Normal gets what High left");
        assert_eq!(line.shaper[0][1].lock().unwrap().rate(), 2000, "Low gets what High and Normal left");
        assert!(Line::new(0, 0).is_none());
        assert_eq!(line.admit(1, Priority::Low, 5, 1000), Some(5), "an unset direction is not shaped");
    }
}
