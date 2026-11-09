//! Who has which connection open right now: the TCP table with owning process ids.
//! Needs no administrator rights, so it is what "first network activity" and the host column
//! use when the ETW session can't run.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Mutex;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats, MIB_TCP_STATE, MIB_TCP_STATE_DELETE_TCB, MIB_TCP6ROW, MIB_TCP6TABLE_OWNER_MODULE, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPTABLE_OWNER_MODULE, MIB_TCPTABLE_OWNER_PID, SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats, SetTcpEntry, TCP_ESTATS_DATA_ROD_v0, TCP_TABLE_CLASS,
    TCP_TABLE_OWNER_MODULE_ALL, TCP_TABLE_OWNER_PID_ALL, TcpConnectionEstatsData,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0};

#[derive(Clone, Debug)]
pub struct Conn {
    pub pid: u32,
    pub remote: IpAddr,
    pub established: bool,
}

const STATE_ESTABLISHED: u32 = 5;
const STATE_SYN_SENT: u32 = 2;

fn fetch(family: u32) -> Result<Vec<u8>, String> {
    fetch_class(family, TCP_TABLE_OWNER_PID_ALL)
}

fn fetch_class(family: u32, class: TCP_TABLE_CLASS) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    let mut buf: Vec<u8> = Vec::new();
    // The first call reports the size; the table can grow between calls, so retry a few times.
    for _ in 0..4 {
        let rc = unsafe { GetExtendedTcpTable(if buf.is_empty() { None } else { Some(buf.as_mut_ptr() as *mut _) }, &mut size, false, family, class, 0) };
        match rc {
            0 => return Ok(buf),
            122 => buf = vec![0u8; size as usize + 1024], // ERROR_INSUFFICIENT_BUFFER
            e => return Err(format!("GetExtendedTcpTable failed ({e})")),
        }
    }
    Err("GetExtendedTcpTable: table kept growing".into())
}

/// Connections that have a remote end (connected or connecting). Listeners are skipped.
pub fn tcp() -> Result<Vec<Conn>, String> {
    let mut out = Vec::new();
    let v4 = fetch(AF_INET.0 as u32)?;
    unsafe {
        let t = &*(v4.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
        for r in rows {
            if r.dwState == STATE_ESTABLISHED || r.dwState == STATE_SYN_SENT {
                out.push(Conn { pid: r.dwOwningPid, remote: IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_le_bytes())), established: r.dwState == STATE_ESTABLISHED });
            }
        }
    }
    // IPv6 may be disabled; that is not an error for the caller.
    if let Ok(v6) = fetch(AF_INET6.0 as u32) {
        unsafe {
            let t = &*(v6.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
            for r in rows {
                if r.dwState == STATE_ESTABLISHED || r.dwState == STATE_SYN_SENT {
                    out.push(Conn { pid: r.dwOwningPid, remote: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)), established: r.dwState == STATE_ESTABLISHED });
                }
            }
        }
    }
    Ok(out)
}

/// A TCP port a process is listening on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub pid: u32,
    pub addr: IpAddr,
    pub port: u16,
}

impl Listener {
    /// Who can reach the port: every interface, this PC only, or one network address.
    pub fn scope(&self) -> &'static str {
        if self.addr.is_unspecified() {
            "all interfaces"
        } else if self.addr.is_loopback() {
            "this PC only"
        } else {
            "one network address"
        }
    }
}

/// Every TCP port in the listening state, IPv4 and IPv6.
/// Windows 11 builds report a socket that is listening (and accepts connections) with state 0 instead of LISTEN (2) when
/// it was set up by newer runtimes, so a state-less row with no remote end counts too.
fn is_listening(state: u32, remote_port: u32) -> bool {
    TcpState::from_raw(state) == Some(TcpState::Listen) || (state == 0 && remote_port == 0)
}

pub fn listeners() -> Result<Vec<Listener>, String> {
    let mut out = Vec::new();
    let v4 = fetch(AF_INET.0 as u32)?;
    unsafe {
        let t = &*(v4.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
            if is_listening(r.dwState, r.dwRemotePort) {
                out.push(Listener { pid: r.dwOwningPid, addr: Ipv4Addr::from(r.dwLocalAddr.to_le_bytes()).into(), port: port_of(r.dwLocalPort) });
            }
        }
    }
    if let Ok(v6) = fetch(AF_INET6.0 as u32) {
        unsafe {
            let t = &*(v6.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
                if is_listening(r.dwState, r.dwRemotePort) {
                    out.push(Listener { pid: r.dwOwningPid, addr: Ipv6Addr::from(r.ucLocalAddr).into(), port: port_of(r.dwLocalPort) });
                }
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
}

impl TcpState {
    /// The MIB_TCP_STATE number; `None` for a value Windows doesn't define.
    pub fn from_raw(n: u32) -> Option<Self> {
        Some(match n {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynRcvd,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Closed => "Closed",
            Self::Listen => "Listening",
            Self::SynSent => "Connecting",
            Self::SynRcvd => "SYN received",
            Self::Established => "Established",
            Self::FinWait1 => "FIN wait 1",
            Self::FinWait2 => "FIN wait 2",
            Self::CloseWait => "Close wait",
            Self::Closing => "Closing",
            Self::LastAck => "Last ACK",
            Self::TimeWait => "Time wait",
            Self::DeleteTcb => "Deleting",
        }
    }
}

/// One TCP connection with both ends. `bytes` is (received, sent) since collection started; `None` without administrator rights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnRow {
    pub pid: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
    pub bytes: Option<(u64, u64)>,
    /// Unix time Windows created the connection; `None` when it doesn't say.
    pub started: Option<i64>,
}

/// Windows FILETIME ticks (100 ns since 1601) as Unix seconds; 0 means "not recorded".
fn filetime_to_unix(t: i64) -> Option<i64> {
    (t > 0).then(|| t / 10_000_000 - 11_644_473_600).filter(|s| *s > 0)
}

/// The port as the table stores it: network byte order in the low 16 bits.
fn port_of(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn raw_port(port: u16) -> u32 {
    u32::from(port.to_be())
}

/// Every TCP connection that has a remote end (listeners are skipped). With `elevated`, also reads
/// per-connection byte counters, switching collection on the first time a connection is seen.
pub fn table(elevated: bool) -> Result<Vec<ConnRow>, String> {
    let mut out = Vec::new();
    let v4 = fetch_class(AF_INET.0 as u32, TCP_TABLE_OWNER_MODULE_ALL)?;
    unsafe {
        let t = &*(v4.as_ptr() as *const MIB_TCPTABLE_OWNER_MODULE);
        for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
            let Some(state) = TcpState::from_raw(r.dwState).filter(|s| *s != TcpState::Listen) else { continue };
            let local = SocketAddr::new(Ipv4Addr::from(r.dwLocalAddr.to_le_bytes()).into(), port_of(r.dwLocalPort));
            let remote = SocketAddr::new(Ipv4Addr::from(r.dwRemoteAddr.to_le_bytes()).into(), port_of(r.dwRemotePort));
            out.push(ConnRow { pid: r.dwOwningPid, local, remote, state, bytes: None, started: filetime_to_unix(r.liCreateTimestamp) });
        }
    }
    if let Ok(v6) = fetch_class(AF_INET6.0 as u32, TCP_TABLE_OWNER_MODULE_ALL) {
        unsafe {
            let t = &*(v6.as_ptr() as *const MIB_TCP6TABLE_OWNER_MODULE);
            for r in std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize) {
                let Some(state) = TcpState::from_raw(r.dwState).filter(|s| *s != TcpState::Listen) else { continue };
                let local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(r.ucLocalAddr), port_of(r.dwLocalPort), 0, r.dwLocalScopeId));
                let remote = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(r.ucRemoteAddr), port_of(r.dwRemotePort), 0, r.dwRemoteScopeId));
                out.push(ConnRow { pid: r.dwOwningPid, local, remote, state, bytes: None, started: filetime_to_unix(r.liCreateTimestamp) });
            }
        }
    }
    if elevated {
        fill_bytes(&mut out);
    }
    Ok(out)
}

/// Connections whose byte collection we switched on, so each is enabled once and forgotten when it ends.
static ENABLED: Mutex<Option<HashSet<(SocketAddr, SocketAddr)>>> = Mutex::new(None);

fn fill_bytes(rows: &mut [ConnRow]) {
    let mut guard = ENABLED.lock().unwrap_or_else(|e| e.into_inner());
    let enabled = guard.get_or_insert_with(HashSet::new);
    enabled.retain(|k| rows.iter().any(|r| (r.local, r.remote) == *k));
    for r in rows.iter_mut().filter(|r| r.state == TcpState::Established) {
        let key = (r.local, r.remote);
        if !enabled.contains(&key) && set_collection(r) {
            enabled.insert(key);
        }
        if enabled.contains(&key) {
            r.bytes = read_bytes(r);
        }
    }
}

fn set_collection(r: &ConnRow) -> bool {
    let on = [1u8]; // TCP_ESTATS_DATA_RW_v0 { EnableCollection: true }
    unsafe {
        match (r.local, r.remote) {
            (SocketAddr::V4(l), SocketAddr::V4(d)) => SetPerTcpConnectionEStats(&tcp_row(l, d, TcpState::Established), TcpConnectionEstatsData, &on, 0, 0) == 0,
            (SocketAddr::V6(l), SocketAddr::V6(d)) => SetPerTcp6ConnectionEStats(&tcp6_row(l, d, TcpState::Established), TcpConnectionEstatsData, &on, 0, 0) == 0,
            _ => false,
        }
    }
}

fn read_bytes(r: &ConnRow) -> Option<(u64, u64)> {
    let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
    let buf = unsafe { std::slice::from_raw_parts_mut(&mut rod as *mut _ as *mut u8, std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>()) };
    let rc = unsafe {
        match (r.local, r.remote) {
            (SocketAddr::V4(l), SocketAddr::V4(d)) => GetPerTcpConnectionEStats(&tcp_row(l, d, r.state), TcpConnectionEstatsData, None, 0, None, 0, Some(buf), 0),
            (SocketAddr::V6(l), SocketAddr::V6(d)) => GetPerTcp6ConnectionEStats(&tcp6_row(l, d, r.state), TcpConnectionEstatsData, None, 0, None, 0, Some(buf), 0),
            _ => return None,
        }
    };
    (rc == 0).then_some((rod.DataBytesIn, rod.DataBytesOut))
}

fn tcp_row(local: SocketAddrV4, remote: SocketAddrV4, state: TcpState) -> MIB_TCPROW_LH {
    MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { dwState: state_raw(state) },
        dwLocalAddr: u32::from_le_bytes(local.ip().octets()),
        dwLocalPort: raw_port(local.port()),
        dwRemoteAddr: u32::from_le_bytes(remote.ip().octets()),
        dwRemotePort: raw_port(remote.port()),
    }
}

fn tcp6_row(local: SocketAddrV6, remote: SocketAddrV6, state: TcpState) -> MIB_TCP6ROW {
    MIB_TCP6ROW {
        State: MIB_TCP_STATE(state_raw(state) as i32),
        LocalAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: local.ip().octets() } },
        dwLocalScopeId: local.scope_id(),
        dwLocalPort: raw_port(local.port()),
        RemoteAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: remote.ip().octets() } },
        dwRemoteScopeId: remote.scope_id(),
        dwRemotePort: raw_port(remote.port()),
    }
}

fn state_raw(s: TcpState) -> u32 {
    (1..=12).find(|n| TcpState::from_raw(*n) == Some(s)).unwrap_or(1)
}

/// Whether Windows can end this connection: only IPv4 TCP has an API for it.
pub fn killable(r: &ConnRow) -> bool {
    r.local.is_ipv4() && r.remote.is_ipv4() && r.state != TcpState::Listen
}

/// Resets one IPv4 connection (the application sees it drop). Needs administrator rights.
pub fn kill(r: &ConnRow) -> Result<(), String> {
    let (SocketAddr::V4(l), SocketAddr::V4(d)) = (r.local, r.remote) else {
        return Err("Windows can only end IPv4 connections. Block the remote address instead.".into());
    };
    let mut row = tcp_row(l, d, TcpState::DeleteTcb);
    row.Anonymous = MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_DELETE_TCB };
    match unsafe { SetTcpEntry(&row) } {
        0 => Ok(()),
        5 => Err("Ending a connection needs administrator rights. Use \"Restart as administrator\".".into()),
        e => Err(format!("SetTcpEntry failed ({e}); the connection may already be closed.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_reads_this_machines_connections() {
        assert!(table(false).is_ok());
    }

    #[test]
    fn state_numbers_round_trip() {
        for n in 1..=12 {
            assert_eq!(state_raw(TcpState::from_raw(n).unwrap()), n);
        }
        assert_eq!(TcpState::from_raw(0), None);
        assert_eq!(TcpState::from_raw(5).unwrap().label(), "Established");
    }

    #[test]
    fn row_uses_network_byte_order() {
        let row = tcp_row("127.0.0.1:80".parse().unwrap(), "10.0.0.2:443".parse().unwrap(), TcpState::DeleteTcb);
        assert_eq!(row.dwLocalAddr, 0x0100_007f);
        assert_eq!(row.dwLocalPort, 0x5000);
        assert_eq!(row.dwRemotePort, 0xbb01);
        assert_eq!(port_of(row.dwRemotePort), 443);
        assert_eq!(unsafe { row.Anonymous.dwState }, 12);
    }

    #[test]
    fn listener_scope_and_live_table() {
        let l = |a: &str| Listener { pid: 1, addr: a.parse().unwrap(), port: 1 };
        assert_eq!(l("0.0.0.0").scope(), "all interfaces");
        assert_eq!(l("::").scope(), "all interfaces");
        assert_eq!(l("127.0.0.1").scope(), "this PC only");
        assert_eq!(l("192.168.1.5").scope(), "one network address");
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        assert!(listeners().unwrap().iter().any(|x| x.port == port && x.pid == std::process::id()));
    }

    #[test]
    fn a_stateless_row_with_no_remote_end_is_a_listener() {
        assert!(is_listening(2, 0) && is_listening(0, 0));
        assert!(!is_listening(5, 0) && !is_listening(0, raw_port(443)));
    }

    #[test]
    fn filetime_converts_to_unix_seconds() {
        assert_eq!(filetime_to_unix(0), None);
        assert_eq!(filetime_to_unix((11_644_473_600 + 1_700_000_000) * 10_000_000), Some(1_700_000_000));
    }

    #[test]
    fn only_ipv4_is_killable() {
        let mk = |l: &str, r: &str| ConnRow { pid: 1, local: l.parse().unwrap(), remote: r.parse().unwrap(), state: TcpState::Established, bytes: None, started: None };
        assert!(killable(&mk("10.0.0.1:5000", "1.2.3.4:443")));
        assert!(!killable(&mk("[::1]:5000", "[2001:db8::1]:443")));
    }

    #[test]
    fn reads_this_machines_table() {
        // Must not fail or panic; the contents depend on the machine.
        assert!(tcp().is_ok());
    }
}
