//! Finds the UPnP internet gateway (the router) for plugins with the `upnp` permission. Discovery is UDP
//! multicast, which a wasm plugin can't do; the plugin then talks to the router over plain HTTP itself.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const SEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";

/// The gateway's description address and this PC's address on the network that reaches it.
pub struct Gateway {
    pub location: String,
    pub local_ip: String,
}

/// Asks every local network for gateways and listens for three seconds. Blocks, so callers run it on a worker.
/// The question goes out of each network card on its own: with a VPN on, a plain multicast leaves through the
/// VPN and the router never hears it. The answers are ordered with the network's real router (its default gateway)
/// first, because other things answer too (VMware's virtual networks, a second router behind the first).
pub fn discover() -> Result<Vec<Gateway>, String> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{IP_MULTICAST_IF, IPPROTO_IP, SOCKET, setsockopt};
    let (nets, routers) = local_networks();
    let mut socks = Vec::new();
    for ip in nets {
        let Ok(sock) = UdpSocket::bind((ip, 0)) else { continue };
        let _ = sock.set_nonblocking(true);
        // SAFETY: the socket is open for the whole call; the option is the 4 address bytes.
        unsafe { setsockopt(SOCKET(sock.as_raw_socket() as usize), IPPROTO_IP.0, IP_MULTICAST_IF, Some(&ip.octets())) };
        if sock.send_to(SEARCH.as_bytes(), "239.255.255.250:1900").is_ok() {
            socks.push((sock, ip));
        }
    }
    // Last resort: let Windows pick the way out.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.set_nonblocking(true);
        if sock.send_to(SEARCH.as_bytes(), "239.255.255.250:1900").is_ok() {
            socks.push((sock, Ipv4Addr::UNSPECIFIED));
        }
    }
    if socks.is_empty() {
        return Err("can't ask the network for a router: no usable network connection".into());
    }
    let mut found: Vec<(Gateway, IpAddr)> = Vec::new();
    let (started, mut buf) = (Instant::now(), [0u8; 2048]);
    while started.elapsed() < Duration::from_secs(3) {
        for (sock, ip) in &socks {
            while let Ok((n, _)) = sock.recv_from(&mut buf) {
                let Some(location) = location_of(&String::from_utf8_lossy(&buf[..n])) else { continue };
                let Some(addr) = lan_addr(&location) else { continue };
                if found.iter().any(|(g, _)| g.location == location) {
                    continue;
                }
                let local = if ip.is_unspecified() {
                    UdpSocket::bind("0.0.0.0:0").and_then(|s| s.connect(addr).and_then(|()| s.local_addr())).map(|a| a.ip()).unwrap_or(IpAddr::V4(*ip))
                } else {
                    IpAddr::V4(*ip)
                };
                found.push((Gateway { location, local_ip: local.to_string() }, addr.ip()));
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if found.is_empty() {
        return Err(format!(
            "No UPnP router answered on {} network(s). UPnP may be switched off on the router, or a firewall is blocking the answer (UDP, from port 1900).",
            socks.len().saturating_sub(1)
        ));
    }
    found.sort_by_key(|(_, ip)| !routers.contains(ip));
    Ok(found.into_iter().map(|(g, _)| g).collect())
}

/// This PC's private IPv4 addresses on real (not VPN) network cards that are up, and those cards' default gateways.
fn local_networks() -> (Vec<Ipv4Addr>, Vec<IpAddr>) {
    let Ok(adapters) = super::netinfo::adapters() else { return Default::default() };
    let real = || adapters.iter().filter(|a| a.up && !a.loopback && !a.tunnel);
    let nets = real()
        .flat_map(|a| a.addrs.iter())
        .filter_map(|(ip, _)| match ip {
            IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() => Some(*v4),
            _ => None,
        })
        .collect();
    (nets, real().flat_map(|a| a.gateways.iter().copied()).collect())
}

/// The LOCATION header of an SSDP reply.
fn location_of(reply: &str) -> Option<String> {
    reply.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim().eq_ignore_ascii_case("location").then(|| value.trim().to_owned())
    })
}

/// The address behind `url` when it is http on a private network, else None: a router never lives anywhere else,
/// and a reply pointing at an internet address must not make this PC contact it.
fn lan_addr(url: &str) -> Option<SocketAddr> {
    let rest = url.strip_prefix("http://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // No port means http's 80, which `to_socket_addrs` needs spelled out.
    let with_port = if authority.contains(':') { authority.to_owned() } else { format!("{authority}:80") };
    let addr = with_port.to_socket_addrs().ok()?.next()?;
    private(addr.ip()).then_some(addr)
}

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_location_header_in_any_case() {
        let reply = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: x\r\n\r\n";
        assert_eq!(location_of(reply).as_deref(), Some("http://192.168.1.1:5000/rootDesc.xml"));
        assert_eq!(location_of("HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn only_a_private_address_is_a_router() {
        assert!(lan_addr("http://192.168.1.1:5000/desc.xml").is_some());
        assert!(lan_addr("http://10.0.0.1/desc.xml").is_some());
        assert!(lan_addr("http://8.8.8.8/desc.xml").is_none());
        assert!(lan_addr("https://192.168.1.1/desc.xml").is_none());
    }
}
