//! WinDivert (see `driver`), loaded from the downloaded DLL at run time, so RustWarden's own exe never
//! links it. Handles are thread-safe for receiving and sending at once; `shutdown` unblocks a waiting `recv`.
//! The DLL installs and starts its driver service by itself on the first successful open (administrator).

use std::path::Path;
use std::sync::Arc;
use windows::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{PCSTR, PCWSTR};

pub const LAYER_NETWORK: i32 = 0;
pub const LAYER_FLOW: i32 = 2;
pub const FLAG_SNIFF: u64 = 1;
pub const FLAG_RECV_ONLY: u64 = 4;
/// Matching packets are dropped; the handle never has to read them.
pub const FLAG_DROP: u64 = 2;
/// `WinDivertShutdown(how)`: stop receiving and sending.
const SHUTDOWN_BOTH: i32 = 3;
/// Stop new packets being queued; what is already queued can still be received.
const SHUTDOWN_RECV: i32 = 1;
/// `WINDIVERT_EVENT_*` from windivert.h (0 is a network packet, so a flow starts at 1).
pub const EVENT_FLOW_ESTABLISHED: u8 = 1;
pub const EVENT_FLOW_DELETED: u8 = 2;
/// The largest packet WinDivert hands over.
pub const MAX_PACKET: usize = 65_535;

/// `WINDIVERT_ADDRESS`: 16 bytes of header, then 64 bytes whose meaning depends on the layer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    /// Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1, checksum flags, reserved.
    bits: u32,
    reserved: u32,
    data: [u8; 64],
}

const _: () = assert!(size_of::<Address>() == 80);

/// What a flow event says about one connection (the `Flow` member of the address union).
#[derive(Clone, Copy, Debug)]
pub struct FlowInfo {
    pub pid: u32,
    pub local: std::net::IpAddr,
    pub remote: std::net::IpAddr,
    pub lport: u16,
    pub rport: u16,
    pub proto: u8,
}

impl Address {
    pub fn zeroed() -> Self {
        Self { timestamp: 0, bits: 0, reserved: 0, data: [0; 64] }
    }

    pub fn event(&self) -> u8 {
        (self.bits >> 8) as u8
    }

    pub fn outbound(&self) -> bool {
        self.bits & (1 << 17) != 0
    }

    fn ipv6(&self) -> bool {
        self.bits & (1 << 20) != 0
    }

    /// For the flow layer. Addresses are stored in host byte order, IPv6 as four words with the last first.
    pub fn flow(&self) -> FlowInfo {
        let d = &self.data;
        let word = |at: usize| u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
        let addr = |at: usize| {
            if self.ipv6() {
                let mut b = [0u8; 16];
                for i in 0..4 {
                    b[i * 4..i * 4 + 4].copy_from_slice(&word(at + (3 - i) * 4).to_be_bytes());
                }
                std::net::IpAddr::V6(b.into())
            } else {
                std::net::IpAddr::V4(word(at).into())
            }
        };
        FlowInfo { pid: word(16), local: addr(20), remote: addr(36), lport: u16::from_le_bytes([d[52], d[53]]), rport: u16::from_le_bytes([d[54], d[55]]), proto: d[56] }
    }
}

type OpenFn = unsafe extern "system" fn(*const u8, i32, i16, u64) -> isize;
type RecvFn = unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "system" fn(isize, i32) -> i32;
type CloseFn = unsafe extern "system" fn(isize) -> i32;
type ChecksumFn = unsafe extern "system" fn(*mut u8, u32, *mut Address, u64) -> i32;

pub struct Lib {
    /// The loaded DLL; freed on drop so that its file can be deleted.
    module: isize,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    checksums: ChecksumFn,
}

impl Lib {
    /// Loads `WinDivert.dll` from `dll`; its driver file must sit in the same folder.
    pub fn load(dll: &Path) -> Result<Arc<Lib>, String> {
        let wide = super::wide(&dll.to_string_lossy());
        let module: HMODULE = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }.map_err(|e| format!("Can't load the driver library ({e}). The file may have been removed by antivirus."))?;
        macro_rules! sym {
            ($name:literal, $ty:ty) => {{
                let f = unsafe { GetProcAddress(module, PCSTR(concat!($name, "\0").as_ptr())) }.ok_or_else(|| format!("The driver library has no {}", $name))?;
                // SAFETY: the exported function has the documented WinDivert signature.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f) }
            }};
        }
        Ok(Arc::new(Lib {
            module: module.0 as isize,
            open: sym!("WinDivertOpen", OpenFn),
            recv: sym!("WinDivertRecv", RecvFn),
            send: sym!("WinDivertSend", SendFn),
            shutdown: sym!("WinDivertShutdown", ShutdownFn),
            close: sym!("WinDivertClose", CloseFn),
            checksums: sym!("WinDivertHelperCalcChecksums", ChecksumFn),
        }))
    }

    /// Opens a handle. `filter` uses WinDivert's filter language ("true", "tcp.DstPort == 443").
    pub fn open(self: &Arc<Self>, filter: &str, layer: i32, priority: i16, flags: u64) -> Result<Handle, String> {
        let c = format!("{filter}\0");
        let h = unsafe { (self.open)(c.as_ptr(), layer, priority, flags) };
        if h == -1 || h == 0 {
            return Err(open_error(unsafe { GetLastError() }.0));
        }
        Ok(Handle { lib: self.clone(), h })
    }
}

impl Drop for Lib {
    fn drop(&mut self) {
        // SAFETY: `module` came from LoadLibraryW and every handle (which holds an Arc of this) is already closed.
        unsafe { FreeLibrary(HMODULE(self.module as *mut _)).ok() };
    }
}

fn open_error(code: u32) -> String {
    match code {
        5 => "The driver needs administrator rights.".into(),
        2 | 3 => "The driver file is missing. Reinstall it in Settings.".into(),
        87 => "The driver rejected the packet filter (internal error).".into(),
        577 | 1275 => "Windows refused to load the driver (it is not trusted on this PC, or it is on Microsoft's blocklist).".into(),
        1060 | 1058 => "The driver service is missing or disabled. Reinstall it in Settings.".into(),
        1117 | 1062 | 1056 => "The driver is busy or stuck. Restart Windows and try again.".into(),
        other => format!("The driver could not be opened (Windows error {other})."),
    }
}

pub struct Handle {
    lib: Arc<Lib>,
    h: isize,
}

// SAFETY: WinDivert handles may be used from several threads at once.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    /// Waits for the next packet or event; `Err` once the handle is shut down.
    pub fn recv(&self, buf: &mut [u8], addr: &mut Address) -> Result<usize, u32> {
        let mut got = 0u32;
        let ok = unsafe { (self.lib.recv)(self.h, buf.as_mut_ptr(), buf.len() as u32, &mut got, addr) };
        if ok == 0 { Err(unsafe { GetLastError() }.0) } else { Ok(got as usize) }
    }

    pub fn send(&self, packet: &[u8], addr: &Address) -> Result<(), u32> {
        let mut sent = 0u32;
        let ok = unsafe { (self.lib.send)(self.h, packet.as_ptr(), packet.len() as u32, &mut sent, addr) };
        if ok == 0 { Err(unsafe { GetLastError() }.0) } else { Ok(()) }
    }

    /// Fixes the IP/TCP/UDP checksums of a packet whose addresses were changed.
    pub fn fix_checksums(&self, packet: &mut [u8], addr: &mut Address) {
        unsafe { (self.lib.checksums)(packet.as_mut_ptr(), packet.len() as u32, addr, 0) };
    }

    /// Stops new packets reaching the handle but lets `recv` hand over what is already queued, then fail.
    pub fn shutdown_recv(&self) {
        unsafe { (self.lib.shutdown)(self.h, SHUTDOWN_RECV) };
    }

    /// Makes a `recv` waiting on another thread return an error.
    pub fn shutdown(&self) {
        unsafe { (self.lib.shutdown)(self.h, SHUTDOWN_BOTH) };
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { (self.lib.close)(self.h) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_address(ipv6: bool) -> Address {
        let mut a = Address::zeroed();
        a.bits = (u32::from(EVENT_FLOW_ESTABLISHED) << 8) | (1 << 17) | if ipv6 { 1 << 20 } else { 0 };
        a.data[16..20].copy_from_slice(&1234u32.to_le_bytes());
        a.data[52..54].copy_from_slice(&51000u16.to_le_bytes());
        a.data[54..56].copy_from_slice(&443u16.to_le_bytes());
        a.data[56] = 6;
        a
    }

    #[test]
    fn flow_event_numbers_are_the_ones_in_windivert_h() {
        // WINDIVERT_EVENT_NETWORK_PACKET = 0, FLOW_ESTABLISHED = 1, FLOW_DELETED = 2: an off-by-one here made the engine
        // treat every new connection as a closed one.
        assert_eq!((EVENT_FLOW_ESTABLISHED, EVENT_FLOW_DELETED), (1, 2));
    }

    #[test]
    fn flow_events_are_read_from_the_address_union() {
        let mut a = flow_address(false);
        a.data[20..24].copy_from_slice(&0x0a00_0002u32.to_le_bytes());
        a.data[36..40].copy_from_slice(&0x5db8_d822u32.to_le_bytes());
        let f = a.flow();
        assert_eq!((f.pid, f.lport, f.rport, f.proto), (1234, 51000, 443, 6));
        assert_eq!((f.local.to_string().as_str(), f.remote.to_string().as_str()), ("10.0.0.2", "93.184.216.34"));
        assert!(a.outbound());
        assert_eq!(a.event(), EVENT_FLOW_ESTABLISHED);
    }

    #[test]
    fn ipv6_words_come_last_first() {
        let mut a = flow_address(true);
        // ::1 is the words [0,0,0,1] with the last first, so the 1 sits in the first slot.
        a.data[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(a.flow().local.to_string(), "::1");
    }

    #[test]
    fn friendly_errors() {
        assert!(open_error(5).contains("administrator"));
        assert!(open_error(577).contains("refused"));
        assert!(open_error(9999).contains("9999"));
    }
}
