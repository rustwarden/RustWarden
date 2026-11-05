//! Real-time ETW session for per-process network bytes and observed DNS answers.
//!
//! Stands in for a kernel driver: user-mode only, administrator required.
//! Providers:
//! * `Microsoft-Windows-Kernel-Network`: per-pid TCP/UDP data sent and received (ids 10/11,
//!   26/27, 42/43, 58/59).
//! * `Microsoft-Windows-DNS-Client`: completed lookups, whose result list maps IPs to names.
//!
//! The payload layouts below come from the providers' manifests as recalled; they could not be
//! exercised on the machine this was written on (no administrator rights there), so the parsers
//! are covered by unit tests on hand-built payloads and `TESTING.md` lists the manual check.

use super::wide;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::SyncSender;
use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Instant;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW, TRACE_LEVEL_INFORMATION,
    WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

const SESSION_NAME: &str = "RustWarden-Net";
const KERNEL_NETWORK: GUID = GUID::from_u128(0x7DD42A49_5329_4832_8DFD_43D979153A88);
const DNS_CLIENT: GUID = GUID::from_u128(0x1C95126E_7EEA_49A9_A3FE_A378B03DDB4D);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    /// Payload bytes seen on a flow. `src`/`dst` are the packet's own source and destination
    /// as the provider reports them; the caller decides which end is remote.
    Data { pid: u32, bytes: u32, udp: bool, send: bool, src: (IpAddr, u16), dst: (IpAddr, u16) },
    /// A finished DNS lookup: who asked (0 when unknown), the name, record type, status code and the
    /// addresses it resolved to. `log` is false for per-server responses, which only feed the name map.
    Dns { pid: u32, name: String, qtype: u16, status: u32, ips: Vec<IpAddr>, log: bool },
}

fn u16_be(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

fn u32_le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

/// Decodes a Kernel-Network data event. `id` selects IP version, transport and direction.
pub fn parse_kernel_network(id: u16, d: &[u8]) -> Option<NetEvent> {
    let (udp, send, v6) = match id {
        10 => (false, true, false),
        11 => (false, false, false),
        26 => (false, true, true),
        27 => (false, false, true),
        42 => (true, true, false),
        43 => (true, false, false),
        58 => (true, true, true),
        59 => (true, false, true),
        _ => return None,
    };
    let pid = u32_le(d, 0)?;
    let bytes = u32_le(d, 4)?;
    let (dst, src, dport, sport) = if v6 {
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(d.get(8..24)?).ok()?);
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(d.get(24..40)?).ok()?);
        (IpAddr::V6(dst), IpAddr::V6(src), u16_be(d, 40)?, u16_be(d, 42)?)
    } else {
        let dst = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(8..12)?).ok()?);
        let src = Ipv4Addr::from(<[u8; 4]>::try_from(d.get(12..16)?).ok()?);
        (IpAddr::V4(dst), IpAddr::V4(src), u16_be(d, 16)?, u16_be(d, 18)?)
    };
    Some(NetEvent::Data { pid, bytes, udp, send, src: (src, sport), dst: (dst, dport) })
}

/// Decodes a DNS-Client lookup event (3008 completed, 3020 per-server response): a NUL-terminated
/// UTF-16 name, then 16 bytes of numbers (type u32 first, status u32 last in both layouts), then a
/// result string with the addresses. Only 3008 is logged. `pid` is the event header's process:
/// 3008 is raised inside the asking process; 3020 comes from the DNS service, so it isn't used.
pub fn parse_dns(id: u16, pid: u32, d: &[u8]) -> Option<NetEvent> {
    let units: Vec<u16> = d.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let end = units.iter().position(|u| *u == 0)?;
    let name = String::from_utf16_lossy(&units[..end]);
    if name.is_empty() {
        return None;
    }
    let at = (end + 1) * 2;
    let qtype = u32_le(d, at)? as u16;
    let status = u32_le(d, at + 12)?;
    let results = String::from_utf16_lossy(units.get(end + 9..).unwrap_or(&[]));
    let ips = crate::live::net::ips_in_dns_results(&results.replace('\0', ";"));
    let log = id == 3008;
    // A failed lookup is worth a log row; a server response without addresses is not.
    (log || !ips.is_empty()).then_some(NetEvent::Dns { pid: if log { pid } else { 0 }, name, qtype, status, ips, log })
}

fn decode(provider: &GUID, id: u16, pid: u32, data: &[u8]) -> Option<NetEvent> {
    if *provider == KERNEL_NETWORK {
        parse_kernel_network(id, data)
    } else if *provider == DNS_CLIENT && (id == 3008 || id == 3020) {
        parse_dns(id, pid, data)
    } else {
        None
    }
}

/// The callback has no closure state, so the sink is global. One session exists at a time.
static SINK: OnceLock<Mutex<Option<SyncSender<NetEvent>>>> = OnceLock::new();

fn sink() -> &'static Mutex<Option<SyncSender<NetEvent>>> {
    SINK.get_or_init(|| Mutex::new(None))
}

/// Feeds an event from another source (the driver's listener) into the collector's stream. Dropped when
/// no session is running or the queue is full.
pub fn inject(event: NetEvent) {
    if let Ok(guard) = sink().try_lock()
        && let Some(tx) = guard.as_ref()
    {
        let _ = tx.try_send(event);
    }
}

/// Paths of processes seen in events, resolved when their first event arrives: a short-lived
/// program (curl, an updater) is gone by the time the collector looks it up once a second.
/// Each entry keeps when it was made, so [`forget_dead`] can drop it once the pid may be reused.
static PATHS: OnceLock<Mutex<std::collections::HashMap<u32, (String, Instant)>>> = OnceLock::new();

fn paths() -> std::sync::MutexGuard<'static, std::collections::HashMap<u32, (String, Instant)>> {
    PATHS.get_or_init(|| Mutex::new(std::collections::HashMap::new())).lock().unwrap_or_else(|e| e.into_inner())
}

/// Executable path remembered for `pid` from an earlier event.
pub fn cached_path(pid: u32) -> Option<String> {
    paths().get(&pid).map(|(p, _)| p.clone())
}

/// Parent process id, from a process snapshot.
pub fn parent_of(pid: u32) -> Option<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut e = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut found = None;
        let mut more = Process32FirstW(snap, &mut e).is_ok();
        while more {
            if e.th32ProcessID == pid {
                found = Some(e.th32ParentProcessID);
                break;
            }
            more = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
        found
    }
}

type SpawnHook = std::sync::Arc<dyn Fn(&std::path::Path) + Send + Sync>;

/// Called with the program just before any helper is started (Live mode uses it to open the firewall for downloads).
static SPAWN_HOOK: Mutex<Option<SpawnHook>> = Mutex::new(None);

pub fn set_spawn_hook(hook: Option<SpawnHook>) {
    *SPAWN_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = hook;
}

/// Spawns a helper program and files its pid under RustWarden before any of its traffic is
/// reported, because a quick `curl` is gone by the time ETW delivers its first event.
pub fn spawn_own(cmd: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    let hook = SPAWN_HOOK.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(hook) = hook {
        hook(std::path::Path::new(cmd.get_program()));
    }
    let child = cmd.spawn()?;
    if let Ok(own) = std::env::current_exe() {
        paths().insert(child.id(), (own.to_string_lossy().into_owned(), Instant::now()));
    }
    Ok(child)
}

/// Drops remembered pids whose process has exited, at most once a minute, so a reused pid isn't
/// filed under the program that had it before. Late ETW events still need the label, so an entry
/// is kept for at least 30 seconds.
fn forget_dead() {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    {
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed().as_secs() < 15) {
            return;
        }
        *last = Some(Instant::now());
    }
    let old: Vec<u32> = paths().iter().filter(|(_, (_, at))| at.elapsed().as_secs() >= 30).map(|(&pid, _)| pid).collect();
    // No handle (already gone) or signalled means it exited.
    let dead: Vec<u32> = old
        .into_iter()
        .filter(|&pid| unsafe {
            !OpenProcess(PROCESS_SYNCHRONIZE, false, pid).is_ok_and(|h| {
                let running = WaitForSingleObject(h, 0) != WAIT_OBJECT_0;
                let _ = CloseHandle(h);
                running
            })
        })
        .collect();
    let mut map = paths();
    for pid in dead {
        map.remove(&pid);
    }
}

/// Remembers who `pid` is the first time it shows up. The helpers RustWarden launches for
/// lookups (curl, nslookup, powershell) count as RustWarden itself.
fn remember(pid: u32) {
    forget_dead();
    if pid == 0 || paths().contains_key(&pid) {
        return;
    }
    let Some(mut path) = super::apps::pid_path(pid) else { return };
    if parent_of(pid) == Some(std::process::id())
        && let Ok(own) = std::env::current_exe()
    {
        path = own.to_string_lossy().into_owned();
    }
    paths().insert(pid, (path, Instant::now()));
}

/// Events dropped because the collector's queue was full.
pub static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    let r = unsafe { &*record };
    let data = if r.UserData.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(r.UserData as *const u8, r.UserDataLength as usize) } };
    let event = decode(&r.EventHeader.ProviderId, r.EventHeader.EventDescriptor.Id, r.EventHeader.ProcessId, data);
    if let Some(NetEvent::Data { pid, .. } | NetEvent::Dns { pid, .. }) = &event {
        remember(*pid);
    }
    if let Some(event) = event
        && let Ok(guard) = sink().try_lock()
        && let Some(tx) = guard.as_ref()
    {
        // Dropping events when the collector is behind is better than blocking the kernel's buffers; they are counted.
        if tx.try_send(event).is_err() {
            DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// A buffer holding `EVENT_TRACE_PROPERTIES` followed by the session name, as the API wants.
struct Props {
    buf: Vec<u8>,
}

impl Props {
    fn new() -> Self {
        let name_bytes = (SESSION_NAME.len() + 1) * 2;
        let total = size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + 1024;
        let mut buf = vec![0u8; total];
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*p).Wnode.BufferSize = total as u32;
            (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*p).Wnode.ClientContext = 1; // QueryPerformanceCounter timestamps
            (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*p).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        }
        Self { buf }
    }

    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }
}

pub struct EtwSession {
    control: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    thread: Option<JoinHandle<()>>,
}

fn stop_by_name(name: &[u16]) {
    let mut props = Props::new();
    unsafe {
        let _ = ControlTraceW(CONTROLTRACE_HANDLE::default(), PCWSTR(name.as_ptr()), props.ptr(), EVENT_TRACE_CONTROL_STOP);
    }
}

impl EtwSession {
    /// Starts the session and a thread that feeds `tx`. Fails with a readable reason when not elevated.
    pub fn start(tx: SyncSender<NetEvent>) -> Result<Self, String> {
        let name = wide(SESSION_NAME);
        let mut control = CONTROLTRACE_HANDLE::default();
        let mut props = Props::new();
        let mut rc = unsafe { StartTraceW(&mut control, PCWSTR(name.as_ptr()), props.ptr()) };
        if rc == ERROR_ALREADY_EXISTS {
            // A previous run that crashed left its session behind.
            stop_by_name(&name);
            props = Props::new();
            rc = unsafe { StartTraceW(&mut control, PCWSTR(name.as_ptr()), props.ptr()) };
        }
        if rc == ERROR_ACCESS_DENIED {
            return Err("starting the ETW session needs administrator rights".into());
        }
        if rc.0 != 0 {
            return Err(format!("StartTrace failed ({})", rc.0));
        }
        for provider in [&KERNEL_NETWORK, &DNS_CLIENT] {
            let rc = unsafe { EnableTraceEx2(control, provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER.0, TRACE_LEVEL_INFORMATION as u8, u64::MAX, 0, 0, None) };
            if rc.0 != 0 && *provider == KERNEL_NETWORK {
                stop_by_name(&name);
                return Err(format!("enabling the Kernel-Network provider failed ({})", rc.0));
            }
        }

        *sink().lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let thread_name = name.clone();
        let (opened_tx, opened_rx) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("etw".into())
            .spawn(move || {
                let mut log = EVENT_TRACE_LOGFILEW { LoggerName: PWSTR(thread_name.as_ptr() as *mut u16), ..Default::default() };
                log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                log.Anonymous2.EventRecordCallback = Some(on_event);
                let handle: PROCESSTRACE_HANDLE = unsafe { OpenTraceW(&mut log) };
                let _ = opened_tx.send(handle.Value != u64::MAX);
                if handle.Value == u64::MAX {
                    return;
                }
                // Blocks until the session is stopped.
                unsafe {
                    let _ = ProcessTrace(&[handle], None, None);
                    let _ = CloseTrace(handle);
                }
            })
            .map_err(|e| e.to_string())?;
        // Without an open trace nothing is ever delivered, so say so instead of showing zero traffic.
        if !opened_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap_or(false) {
            *sink().lock().unwrap_or_else(|e| e.into_inner()) = None;
            stop_by_name(&name);
            return Err("opening the trace failed".into());
        }
        Ok(Self { control, name, thread: Some(thread) })
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        let mut props = Props::new();
        unsafe {
            let _ = ControlTraceW(self.control, PCWSTR(self.name.as_ptr()), props.ptr(), EVENT_TRACE_CONTROL_STOP);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        *sink().lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_payload(pid: u32, size: u32, dst: [u8; 4], src: [u8; 4], dport: u16, sport: u16) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend(pid.to_le_bytes());
        d.extend(size.to_le_bytes());
        d.extend(dst);
        d.extend(src);
        d.extend(dport.to_be_bytes());
        d.extend(sport.to_be_bytes());
        d.extend([0u8; 16]);
        d
    }

    #[test]
    fn tcp_v4_send() {
        let d = v4_payload(1234, 1448, [93, 184, 216, 34], [192, 168, 1, 5], 443, 51000);
        let e = parse_kernel_network(10, &d).unwrap();
        assert_eq!(e, NetEvent::Data { pid: 1234, bytes: 1448, udp: false, send: true, src: ("192.168.1.5".parse().unwrap(), 51000), dst: ("93.184.216.34".parse().unwrap(), 443) });
    }

    #[test]
    fn udp_v6_receive() {
        let mut d = Vec::new();
        d.extend(7u32.to_le_bytes());
        d.extend(100u32.to_le_bytes());
        d.extend("fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        d.extend("2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        d.extend(5353u16.to_be_bytes());
        d.extend(40000u16.to_be_bytes());
        match parse_kernel_network(59, &d).unwrap() {
            NetEvent::Data { udp, send, dst, src, .. } => {
                assert!(udp && !send);
                assert_eq!(dst.1, 5353);
                assert_eq!(src.0, "2001:db8::9".parse::<IpAddr>().unwrap());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn short_and_unknown_events_are_ignored() {
        assert!(parse_kernel_network(10, &[0u8; 10]).is_none());
        assert!(parse_kernel_network(12, &[0u8; 64]).is_none());
        assert!(parse_dns(3008, 1, &[]).is_none());
    }

    /// Name, type, 12 more bytes holding the status in the last four, then the results.
    fn dns_payload(name: &str, qtype: u32, status: u32, results: &str) -> Vec<u8> {
        let mut d: Vec<u8> = Vec::new();
        for u in format!("{name}\0").encode_utf16() {
            d.extend(u.to_le_bytes());
        }
        d.extend(qtype.to_le_bytes());
        d.extend([0u8; 8]);
        d.extend(status.to_le_bytes());
        for u in format!("{results}\0").encode_utf16() {
            d.extend(u.to_le_bytes());
        }
        d
    }

    #[test]
    fn dns_answer_maps_name_to_addresses() {
        let d = dns_payload("example.com", 1, 0, "93.184.216.34;2606:2800:220:1::1;");
        match parse_dns(3008, 4242, &d).unwrap() {
            NetEvent::Dns { pid, name, qtype, status, ips, log } => {
                assert_eq!((pid, name.as_str(), qtype, status, log), (4242, "example.com", 1, 0, true));
                assert_eq!(ips.len(), 2);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn failed_lookup_is_logged_without_addresses() {
        let d = dns_payload("nope.invalid", 28, 9003, "");
        match parse_dns(3008, 7, &d).unwrap() {
            NetEvent::Dns { status, ips, log, .. } => assert!(log && status == 9003 && ips.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn server_response_only_maps_names() {
        let d = dns_payload("example.com", 1, 0, "93.184.216.34;");
        match parse_dns(3020, 1000, &d).unwrap() {
            NetEvent::Dns { pid, log, .. } => assert!(!log && pid == 0),
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_dns(3020, 1000, &dns_payload("example.com", 1, 9003, "")).is_none());
    }
}
