//! Windows Filtering Platform drop events, for Prompt.
//!
//! Subscribes (user mode, administrator required) to the events WFP raises when it stops a
//! connection. Each one names the program and the remote address, which is all the prompt
//! needs. This only observes: nothing here can allow, hold or block a connection.

use super::{from_wide, wide};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::SyncSender;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_DIRECTION_OUTBOUND, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWPM_NET_EVENT_FLAG_APP_ID_SET, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET, FWPM_NET_EVENT_FLAG_IP_VERSION_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET, FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_NET_EVENT1, FwpmEngineClose0, FwpmEngineOpen0, FwpmNetEventSubscribe0,
    FwpmNetEventUnsubscribe0,
};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

const RPC_C_AUTHN_DEFAULT: u32 = u32::MAX;

/// An outbound connection that Windows Firewall stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocked {
    /// The program as WFP names it: an NT device path (`\device\harddiskvolume3\...\ssh.exe`).
    /// "System" (or empty) for a ping: Windows sends those from the kernel, so the real program is not known.
    pub app: String,
    pub remote: IpAddr,
    /// IP protocol number (1 ICMP, 6 TCP, 17 UDP, 58 ICMPv6); 0 when the event doesn't say.
    pub proto: u8,
}

/// ICMP and ICMPv6, which is what a ping is.
pub fn is_icmp(proto: u8) -> bool {
    matches!(proto, 1 | 58)
}

/// App id blobs are NUL-terminated UTF-16.
fn app_name(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    from_wide(&units)
}

unsafe fn decode(ev: &FWPM_NET_EVENT1) -> Option<Blocked> {
    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return None;
    }
    let drop = unsafe { ev.Anonymous.classifyDrop.as_ref()? };
    // The docs allow either form for outbound: FWP_DIRECTION_OUTBOUND (0) or FWP_DIRECTION_OUT (0x3901).
    if ![FWP_DIRECTION_OUTBOUND.0 as u32, 0x3901].contains(&drop.msFwpDirection) || drop.isLoopback.as_bool() {
        return None;
    }
    let h = &ev.header;
    let need = FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET | FWPM_NET_EVENT_FLAG_IP_VERSION_SET;
    let proto = if h.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET != 0 { h.ipProtocol } else { 0 };
    let has_app = h.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET != 0 && !h.appId.data.is_null();
    // A ping can arrive with no program at all; anything else without one is of no use.
    if h.flags & need != need || (!has_app && !is_icmp(proto)) {
        return None;
    }
    let remote = match h.ipVersion {
        v if v == FWP_IP_VERSION_V4 => IpAddr::V4(Ipv4Addr::from(unsafe { h.Anonymous2.remoteAddrV4 })),
        v if v == FWP_IP_VERSION_V6 => IpAddr::V6(Ipv6Addr::from(unsafe { h.Anonymous2.remoteAddrV6.byteArray16 })),
        _ => return None,
    };
    let app = if has_app { app_name(unsafe { std::slice::from_raw_parts(h.appId.data, h.appId.size as usize) }) } else { String::new() };
    Some(Blocked { app, remote, proto })
}

unsafe extern "system" fn on_event(context: *mut c_void, event: *const FWPM_NET_EVENT1) {
    if context.is_null() || event.is_null() {
        return;
    }
    let tx = unsafe { &*(context as *const SyncSender<Blocked>) };
    if let Some(b) = unsafe { decode(&*event) } {
        // A full queue means the collector is behind; a retry will raise the event again.
        let _ = tx.try_send(b);
    }
}

pub struct Subscription {
    engine: HANDLE,
    events: HANDLE,
    context: *mut SyncSender<Blocked>,
}

impl Subscription {
    pub fn start(tx: SyncSender<Blocked>) -> Result<Self, String> {
        let mut engine = HANDLE::default();
        let rc = unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_DEFAULT, None, None, &mut engine) };
        if rc == 5 {
            return Err("watching blocked connections needs administrator rights".into());
        }
        if rc != 0 {
            return Err(format!("FwpmEngineOpen failed ({rc:#x})"));
        }
        let context = Box::into_raw(Box::new(tx));
        let template = FWPM_NET_EVENT_SUBSCRIPTION0::default();
        let mut events = HANDLE::default();
        let rc = unsafe { FwpmNetEventSubscribe0(engine, &template, Some(on_event), Some(context as *const c_void), &mut events) };
        if rc != 0 {
            unsafe {
                drop(Box::from_raw(context));
                FwpmEngineClose0(engine);
            }
            return Err(format!("FwpmNetEventSubscribe failed ({rc:#x})"));
        }
        Ok(Self { engine, events, context })
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // Unsubscribing returns only after running callbacks finish, so freeing the sender is safe.
        unsafe {
            FwpmNetEventUnsubscribe0(self.engine, self.events);
            FwpmEngineClose0(self.engine);
            drop(Box::from_raw(self.context));
        }
    }
}

/// `nt` with its device prefix swapped for a drive letter, given what `drive` maps to.
fn swap_device(nt: &str, device: &str, drive: char) -> Option<String> {
    let head = nt.get(..device.len())?;
    let rest = nt.get(device.len()..)?;
    (head.eq_ignore_ascii_case(device) && rest.starts_with('\\')).then(|| format!("{drive}:{rest}"))
}

/// `C:\...` path for an NT device path, or `None` for anything that isn't on a lettered drive.
pub fn dos_path(nt: &str) -> Option<String> {
    ('A'..='Z').find_map(|letter| {
        let drive = wide(&format!("{letter}:"));
        let mut buf = [0u16; 520];
        let n = unsafe { QueryDosDeviceW(PCWSTR(drive.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            return None;
        }
        swap_device(nt, &from_wide(&buf), letter)
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_icmp_and_icmpv6_count_as_a_ping() {
        assert!(super::is_icmp(1) && super::is_icmp(58));
        assert!(!super::is_icmp(6) && !super::is_icmp(17) && !super::is_icmp(0));
    }

    use super::*;

    #[test]
    fn app_id_blob_decodes_utf16() {
        let mut bytes: Vec<u8> = r"\device\harddiskvolume3\a.exe".encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes.extend([0, 0]);
        assert_eq!(app_name(&bytes), r"\device\harddiskvolume3\a.exe");
    }

    #[test]
    fn device_prefix_becomes_a_drive_letter() {
        let nt = r"\device\harddiskvolume3\windows\system32\ssh.exe";
        assert_eq!(swap_device(nt, r"\Device\HarddiskVolume3", 'C').as_deref(), Some(r"C:\windows\system32\ssh.exe"));
        // HarddiskVolume3 must not match HarddiskVolume31.
        assert_eq!(swap_device(r"\device\harddiskvolume31\x.exe", r"\Device\HarddiskVolume3", 'C'), None);
        assert_eq!(swap_device("System", r"\Device\HarddiskVolume3", 'C'), None);
    }

    #[test]
    fn real_system_file_resolves_to_a_dos_path() {
        let exe = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        // Round trip: find the device for our own drive and rebuild the NT path.
        let drive = exe.chars().next().unwrap();
        let d = wide(&format!("{drive}:"));
        let mut buf = [0u16; 520];
        assert!(unsafe { QueryDosDeviceW(PCWSTR(d.as_ptr()), Some(&mut buf)) } > 0);
        let nt = format!("{}{}", from_wide(&buf), &exe[2..]);
        assert_eq!(dos_path(&nt).as_deref(), Some(exe.as_str()));
    }
}
