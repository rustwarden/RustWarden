//! Network configuration the alert monitors and the scanner read: adapters (addresses, gateways,
//! DNS servers), the ARP/neighbour table, proxy settings, idle time and internet reachability.

use super::{from_wide, wide};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIpForwardTable2, GetIpNetTable2, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_TABLE2,
    MIB_IPNET_TABLE2,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW};
use windows::core::PCWSTR;

#[derive(Clone, Debug, Default)]
pub struct Adapter {
    pub name: String,
    pub if_index: u32,
    pub mac: [u8; 6],
    /// Unicast addresses with prefix length.
    pub addrs: Vec<(IpAddr, u8)>,
    pub gateways: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    pub up: bool,
    pub loopback: bool,
    /// A VPN / tunnel interface (traffic on it is the apps' own, before the VPN client encrypts it).
    pub tunnel: bool,
}

/// IfType 131 is a tunnel and 53 a proprietary virtual adapter; the description catches the rest (TAP, Wintun, WireGuard...).
fn is_tunnel(if_type: u32, text: &str) -> bool {
    const HINTS: &[&str] = &[
        "wintun",
        "tap-windows",
        "tap-",
        "wireguard",
        "nordlynx",
        "openvpn",
        "anyconnect",
        "vpn",
        "tailscale",
        "zerotier",
        "mullvad",
        "proton",
        "private internet access",
        "pia-",
        "wgpia",
        "nordvpn",
        "surfshark",
        "windscribe",
    ];
    let t = text.to_lowercase();
    if_type == 131 || if_type == 53 || HINTS.iter().any(|h| t.contains(h))
}

unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    unsafe {
        match (*sa).sa_family {
            f if f == AF_INET => Some(IpAddr::V4(Ipv4Addr::from((*(sa as *const SOCKADDR_IN)).sin_addr.S_un.S_addr.to_le_bytes()))),
            f if f == AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from((*(sa as *const SOCKADDR_IN6)).sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

unsafe fn socket_ip(a: &SOCKET_ADDRESS) -> Option<IpAddr> {
    unsafe { sockaddr_ip(a.lpSockaddr) }
}

pub fn adapters() -> Result<Vec<Adapter>, String> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 16 * 1024u32;
    let mut buf: Vec<u8>;
    loop {
        buf = vec![0u8; size as usize];
        let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut size) };
        if rc == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if rc != NO_ERROR.0 {
            return Err(format!("GetAdaptersAddresses failed ({rc})"));
        }
        break;
    }
    let mut out = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    unsafe {
        while !cur.is_null() {
            let a = &*cur;
            let mut ad =
                Adapter { name: a.FriendlyName.to_string().unwrap_or_default(), if_index: a.Anonymous1.Anonymous.IfIndex, up: a.OperStatus.0 == 1, loopback: a.IfType == 24, ..Adapter::default() };
            let desc = a.Description.to_string().unwrap_or_default();
            ad.tunnel = is_tunnel(a.IfType, &format!("{} {desc}", ad.name));
            let len = (a.PhysicalAddressLength as usize).min(6);
            ad.mac[..len].copy_from_slice(&a.PhysicalAddress[..len]);
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                if let Some(ip) = socket_ip(&(*u).Address) {
                    ad.addrs.push((ip, (*u).OnLinkPrefixLength));
                }
                u = (*u).Next;
            }
            let mut g = a.FirstGatewayAddress;
            while !g.is_null() {
                if let Some(ip) = socket_ip(&(*g).Address) {
                    ad.gateways.push(ip);
                }
                g = (*g).Next;
            }
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                if let Some(ip) = socket_ip(&(*d).Address) {
                    ad.dns.push(ip);
                }
                d = (*d).Next;
            }
            out.push(ad);
            cur = a.Next;
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct Neighbor {
    pub if_index: u32,
    pub ip: IpAddr,
    pub mac: [u8; 6],
    /// Reachable, stale, delay, probe or permanent: the entry has a resolved MAC.
    pub resolved: bool,
}

pub fn neighbors() -> Result<Vec<Neighbor>, String> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    let mut out = Vec::new();
    unsafe {
        GetIpNetTable2(AF_UNSPEC, &mut table).ok().map_err(|e| format!("GetIpNetTable2 failed: {e}"))?;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for r in rows {
            let ip = match r.Address.si_family {
                f if f == AF_INET => IpAddr::V4(Ipv4Addr::from(r.Address.Ipv4.sin_addr.S_un.S_addr.to_le_bytes())),
                f if f == AF_INET6 => IpAddr::V6(Ipv6Addr::from(r.Address.Ipv6.sin6_addr.u.Byte)),
                _ => continue,
            };
            let mut mac = [0u8; 6];
            let len = (r.PhysicalAddressLength as usize).min(6);
            mac[..len].copy_from_slice(&r.PhysicalAddress[..len]);
            // NlnsUnreachable = 0, Incomplete = 1; everything above has a MAC.
            out.push(Neighbor { if_index: r.InterfaceIndex, ip, mac, resolved: r.State.0 >= 2 && len == 6 });
        }
        FreeMibTable(table as *const _);
    }
    Ok(out)
}

/// Single-address routes that go through a gateway: the way a VPN client keeps the packets to its own server outside the
/// tunnel. Each is (address, adapter index).
pub fn host_routes() -> Result<Vec<(IpAddr, u32)>, String> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let mut out = Vec::new();
    unsafe {
        GetIpForwardTable2(AF_UNSPEC, &mut table).ok().map_err(|e| format!("GetIpForwardTable2 failed: {e}"))?;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for r in rows {
            let prefix = &r.DestinationPrefix;
            let (dest, next, whole) = match prefix.Prefix.si_family {
                f if f == AF_INET => (IpAddr::V4(Ipv4Addr::from(prefix.Prefix.Ipv4.sin_addr.S_un.S_addr.to_le_bytes())), r.NextHop.Ipv4.sin_addr.S_un.S_addr != 0, prefix.PrefixLength == 32),
                f if f == AF_INET6 => (IpAddr::V6(Ipv6Addr::from(prefix.Prefix.Ipv6.sin6_addr.u.Byte)), r.NextHop.Ipv6.sin6_addr.u.Byte != [0; 16], prefix.PrefixLength == 128),
                _ => continue,
            };
            if whole && next {
                out.push((dest, r.InterfaceIndex));
            }
        }
        FreeMibTable(table as *const _);
    }
    Ok(out)
}

pub fn fmt_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Whether the address is a MAC that identifies a unicast device (not broadcast/multicast/zero).
pub fn is_unicast_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 1 == 0 && mac.iter().any(|b| *b != 0)
}

fn reg_string(subkey: &str, name: &str) -> Option<String> {
    let (k, n) = (wide(subkey), wide(name));
    let mut len = 0u32;
    unsafe {
        let rc = RegGetValueW(HKEY_CURRENT_USER, PCWSTR(k.as_ptr()), PCWSTR(n.as_ptr()), RRF_RT_REG_SZ, None, None, Some(&mut len));
        if rc.0 != 0 || len == 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize / 2 + 1];
        let rc = RegGetValueW(HKEY_CURRENT_USER, PCWSTR(k.as_ptr()), PCWSTR(n.as_ptr()), RRF_RT_REG_SZ, None, Some(buf.as_mut_ptr() as *mut _), Some(&mut len));
        (rc.0 == 0).then(|| from_wide(&buf))
    }
}

fn reg_dword(subkey: &str, name: &str) -> Option<u32> {
    let (k, n) = (wide(subkey), wide(name));
    let mut value = 0u32;
    let mut len = 4u32;
    let rc = unsafe { RegGetValueW(HKEY_CURRENT_USER, PCWSTR(k.as_ptr()), PCWSTR(n.as_ptr()), RRF_RT_REG_DWORD, None, Some(&mut value as *mut _ as *mut _), Some(&mut len)) };
    (rc.0 == 0).then_some(value)
}

/// The per-user proxy configuration as one comparable string.
pub fn proxy_snapshot() -> String {
    let key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    format!(
        "enabled={}; server={}; bypass={}; pac={}",
        reg_dword(key, "ProxyEnable").unwrap_or(0),
        reg_string(key, "ProxyServer").unwrap_or_default(),
        reg_string(key, "ProxyOverride").unwrap_or_default(),
        reg_string(key, "AutoConfigURL").unwrap_or_default(),
    )
}

/// Seconds since the last keyboard or mouse input in this session, or 0 while the user is
/// evidently present but not touching anything (fullscreen/presentation, or media playing).
pub fn idle_seconds() -> u64 {
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    let mut info = LASTINPUTINFO { cbSize: size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    if !unsafe { GetLastInputInfo(&mut info) }.as_bool() {
        return 0;
    }
    let idle = u64::from(unsafe { GetTickCount() }.wrapping_sub(info.dwTime)) / 1000;
    if idle > 30 && watching() { 0 } else { idle }
}

/// A fullscreen app/presentation is up, or any app reports media as playing (video, music).
fn watching() -> bool {
    use windows::Media::Control::{GlobalSystemMediaTransportControlsSessionManager as Mgr, GlobalSystemMediaTransportControlsSessionPlaybackStatus as Status};
    use windows::Win32::UI::Shell::{QUNS_ACCEPTS_NOTIFICATIONS, QUNS_QUIET_TIME, SHQueryUserNotificationState};
    if let Ok(state) = unsafe { SHQueryUserNotificationState() }
        && state != QUNS_ACCEPTS_NOTIFICATIONS
        && state != QUNS_QUIET_TIME
    {
        return true;
    }
    super::com_init();
    let Ok(sessions) = Mgr::RequestAsync().and_then(|r| r.join()).and_then(|m| m.GetSessions()) else { return false };
    sessions.into_iter().any(|s| s.GetPlaybackInfo().and_then(|i| i.PlaybackStatus()).is_ok_and(|p| p == Status::Playing))
}

/// Windows' own verdict on internet reachability (the network location awareness service).
pub fn internet_connected() -> Option<bool> {
    use windows::Win32::Networking::NetworkListManager::{INetworkListManager, NetworkListManager};
    use windows::Win32::System::Com::{CLSCTX_ALL, CoCreateInstance};
    super::com_init();
    let nlm: INetworkListManager = unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }.ok()?;
    let connected = unsafe { nlm.IsConnectedToInternet() }.ok()?;
    Some(connected.as_bool())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_helpers() {
        assert_eq!(fmt_mac(&[0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]), "AA:BB:CC:01:02:03");
        assert!(is_unicast_mac(&[0x02, 0, 0, 0, 0, 1]));
        assert!(!is_unicast_mac(&[0xff; 6]));
        assert!(!is_unicast_mac(&[0x01, 0, 0x5e, 0, 0, 1]));
        assert!(!is_unicast_mac(&[0; 6]));
    }

    #[test]
    fn adapters_and_neighbors_are_readable() {
        assert!(adapters().is_ok());
        assert!(neighbors().is_ok());
        let _ = proxy_snapshot();
        let _ = idle_seconds();
    }
}
