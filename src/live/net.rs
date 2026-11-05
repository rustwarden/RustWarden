//! Pure network helpers: address classification, protocol names, DNS result parsing.
//!
//! RustWarden names a flow from
//! its transport, well-known ports and well-known multicast groups only, and says "Other"
//! for the rest. It does not inspect payloads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Locality {
    /// Never counted.
    Loopback,
    /// Private, link-local, multicast or broadcast: stays on the local network.
    Local,
    Wan,
}

pub fn classify(ip: IpAddr) -> Locality {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> Locality {
    if ip.is_loopback() {
        Locality::Loopback
    } else if ip.is_private() || is_cgnat(ip) || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() {
        Locality::Local
    } else {
        Locality::Wan
    }
}

/// 100.64.0.0/10, the shared address space carriers and Tailscale use: not the public internet.
fn is_cgnat(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 0x40
}

fn classify_v6(ip: Ipv6Addr) -> Locality {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        Locality::Loopback
    } else if ip.is_unspecified() || ip.is_multicast() || first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00 {
        Locality::Local
    } else {
        Locality::Wan
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    Tcp,
    Udp,
}

const SSDP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Name for a flow's traffic type. `remote_port` is tried first, then `local_port`
/// (inbound connections to a local service).
pub fn protocol_label(transport: Transport, remote_ip: IpAddr, remote_port: u16, local_port: u16) -> &'static str {
    if let IpAddr::V4(v4) = remote_ip {
        if v4 == SSDP_V4 {
            return "Simple Service Discovery Protocol (SSDP)";
        }
        if v4 == MDNS_V4 {
            return "Multicast DNS (mDNS)";
        }
    }
    if let IpAddr::V6(v6) = remote_ip
        && v6.segments() == [0xff02, 0, 0, 0, 0, 0, 0, 0xfb]
    {
        return "Multicast DNS (mDNS)";
    }
    port_name(transport, remote_port).or_else(|| port_name(transport, local_port)).unwrap_or("Other")
}

fn port_name(transport: Transport, port: u16) -> Option<&'static str> {
    use Transport::*;
    Some(match (transport, port) {
        (Tcp, 443) => "Hypertext Transfer Protocol over TLS (HTTPS)",
        (Udp, 443) => "QUIC (HTTP/3)",
        (Tcp, 80 | 8080) => "Hypertext Transfer Protocol (HTTP)",
        (_, 53) => "Domain Name System (DNS)",
        (Udp, 5353) => "Multicast DNS (mDNS)",
        (Udp, 5355) => "Link-Local Multicast Name Resolution (LLMNR)",
        (Udp, 1900) => "Simple Service Discovery Protocol (SSDP)",
        (Udp, 137) => "NetBIOS Name Service",
        (Udp, 138) => "NetBIOS Datagram Service",
        (Tcp, 139) => "NetBIOS Session Service",
        (Tcp, 445) => "Server Message Block (SMB)",
        (Udp, 67 | 68) => "Bootstrap Protocol (BOOTP)",
        (Udp, 123) => "Network Time Protocol (NTP)",
        (Tcp, 1883 | 8883) => "MQ Telemetry Transport (MQTT)",
        (Tcp, 22) => "Secure Shell (SSH)",
        (Tcp, 21) => "File Transfer Protocol (FTP)",
        (Tcp, 25 | 465 | 587) => "Simple Mail Transfer Protocol (SMTP)",
        (Tcp, 110 | 995) => "Post Office Protocol (POP3)",
        (Tcp, 143 | 993) => "Internet Message Access Protocol (IMAP)",
        (Tcp, 3389) => "Remote Desktop Protocol (RDP)",
        _ => return None,
    })
}

/// Which kernel-mode service a PID 4 ("NT Kernel & System") flow belongs to, by port: `(key part, row name)`.
/// Windows gives these flows no driver or app, so the port is the only evidence.
pub fn kernel_service(udp: bool, remote_port: u16, local_port: u16) -> (&'static str, &'static str) {
    let on = |p: u16| remote_port == p || local_port == p;
    if !udp && on(445) {
        ("smb", "Kernel: SMB file sharing")
    } else if (udp && (on(137) || on(138))) || (!udp && on(139)) {
        ("netbios", "Kernel: NetBIOS")
    } else if (udp && (on(1900) || on(3702))) || (!udp && on(5357)) {
        ("discovery", "Kernel: Device discovery")
    } else if !udp && [80, 443, 2869, 5985, 5986, 8080].contains(&local_port) {
        ("http", "Kernel: HTTP.sys listeners")
    } else {
        ("other", "Kernel: Other")
    }
}

/// Every IP address mentioned in a DNS-Client "query results" string, which looks like
/// `"198.51.100.7;2001:db8::1;type:  5 alias.example.com;"`.
pub fn ips_in_dns_results(results: &str) -> Vec<IpAddr> {
    results.split(|c: char| c == ';' || c.is_whitespace() || c == ',').filter_map(|tok| tok.trim().parse::<IpAddr>().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn shared_address_space_is_not_wan() {
        assert_eq!(classify(ip("100.64.0.1")), Locality::Local);
        assert_eq!(classify(ip("100.127.255.254")), Locality::Local);
        assert_eq!(classify(ip("100.63.255.255")), Locality::Wan);
        assert_eq!(classify(ip("100.128.0.1")), Locality::Wan);
    }

    #[test]
    fn locality() {
        assert_eq!(classify(ip("127.0.0.1")), Locality::Loopback);
        assert_eq!(classify(ip("::1")), Locality::Loopback);
        assert_eq!(classify(ip("192.168.1.1")), Locality::Local);
        assert_eq!(classify(ip("10.1.2.3")), Locality::Local);
        assert_eq!(classify(ip("169.254.3.4")), Locality::Local);
        assert_eq!(classify(ip("239.255.255.250")), Locality::Local);
        assert_eq!(classify(ip("255.255.255.255")), Locality::Local);
        assert_eq!(classify(ip("fe80::1")), Locality::Local);
        assert_eq!(classify(ip("fd12::1")), Locality::Local);
        assert_eq!(classify(ip("ff02::fb")), Locality::Local);
        assert_eq!(classify(ip("::ffff:192.168.0.9")), Locality::Local);
        assert_eq!(classify(ip("8.8.8.8")), Locality::Wan);
        assert_eq!(classify(ip("2606:4700::1111")), Locality::Wan);
    }

    #[test]
    fn protocol_names() {
        let t = Transport::Tcp;
        assert_eq!(protocol_label(t, ip("1.1.1.1"), 443, 50000), "Hypertext Transfer Protocol over TLS (HTTPS)");
        assert_eq!(protocol_label(Transport::Udp, ip("239.255.255.250"), 1900, 1900), "Simple Service Discovery Protocol (SSDP)");
        assert_eq!(protocol_label(Transport::Udp, ip("224.0.0.251"), 5353, 5353), "Multicast DNS (mDNS)");
        assert_eq!(protocol_label(Transport::Udp, ip("1.1.1.1"), 53, 51000), "Domain Name System (DNS)");
        // Inbound connection to a local SMB service: the remote port is ephemeral.
        assert_eq!(protocol_label(t, ip("192.168.1.9"), 52000, 445), "Server Message Block (SMB)");
        assert_eq!(protocol_label(t, ip("93.184.216.34"), 9999, 51234), "Other");
    }

    #[test]
    fn kernel_flows_are_told_apart_by_port() {
        assert_eq!(kernel_service(false, 445, 51000).0, "smb");
        assert_eq!(kernel_service(false, 52000, 445).0, "smb");
        assert_eq!(kernel_service(true, 137, 137).0, "netbios");
        assert_eq!(kernel_service(false, 139, 50000).0, "netbios");
        assert_eq!(kernel_service(true, 1900, 1900).0, "discovery");
        assert_eq!(kernel_service(false, 50000, 5357).0, "discovery");
        assert_eq!(kernel_service(false, 50000, 5985).0, "http");
        assert_eq!(kernel_service(false, 9999, 50000).0, "other");
        // UDP 445 is not SMB.
        assert_eq!(kernel_service(true, 445, 445).0, "other");
    }

    #[test]
    fn dns_results_are_scanned_for_addresses() {
        let found = ips_in_dns_results("type:  5 alias.example.com;93.184.216.34;2606:2800:220:1::1;");
        assert_eq!(found, vec![ip("93.184.216.34"), ip("2606:2800:220:1::1")]);
        assert!(ips_in_dns_results("").is_empty());
    }
}
