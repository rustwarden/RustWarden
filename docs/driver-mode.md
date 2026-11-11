# Driver mode

RustWarden normally needs **no driver**: everything is done with the Windows Firewall, Windows QoS and Windows' own event tracing. **Driver mode** is an optional extra that adds features which need to see individual packets.

## What it adds

| Feature | Where | Read more |
|---|---|---|
| **Download limits**, both-direction limits, per-program pacing, priority sharing | Firewall > Limits / QoS | [Limits / QoS](firewall/limits-qos.md#driver-mode-downloads-both-directions-and-pacing) |
| **Network-condition simulator** (added delay and packet loss) | Firewall > Limits / QoS | [Simulator](firewall/limits-qos.md#network-condition-simulator-driver-mode) |
| **Block by domain** for every program, including on shared servers | Firewall > Destination Rules | [Block by domain](firewall/destination-rules.md#block-by-domain-driver-mode) |
| **UDP flows** in Live Connections, and **End** for them | Firewall > Live Connections | [Live Connections](firewall/live-connections.md#driver-mode-extras) |
| **Packet capture** to a `.pcap` file | Firewall > Live Connections | [Live Connections](firewall/live-connections.md#driver-mode-extras) |
| **Host names** from SNI and DNS answers | Everywhere hosts are shown, and the DNS Log | [Below](#host-names) |
| **QUIC fallback** | Settings > Other > Advanced | [Below](#quic-fallback) |
| **Force DNS** | Settings > Firewall > Advanced | [Below](#force-dns) |
| **Inbound port scan and flood** alerts | Settings > Alerts | [Alert types](alerts/alert-types.md#inbound-port-scan-and-flood-driver-mode) |
| **Rogue DHCP server** alerts | Settings > Alerts | [Alert types](alerts/alert-types.md#rogue-dhcp-server-detection-driver-mode) |
| **TLS fingerprint** check | Settings > Alerts | [Alert types](alerts/alert-types.md#tls-fingerprint-check-driver-mode) |

Every one of these controls is **hidden** unless Driver mode is on **and** the driver is installed, so if you don't want a driver you never see a feature that needs one.

## The driver

RustWarden uses [WinDivert](https://github.com/basil00/WinDivert), an open-source packet driver with a Microsoft-accepted signature. Windows test mode isn't needed.

- It's **never bundled** with RustWarden.
- **Download and install…** fetches the official WinDivert 2.2.2 release zip from github.com, checks it against a **pinned SHA-256**, and keeps only the DLL and driver file in `C:\Program Files\RustWarden\driver`, where only administrators can change them.
- **Remove driver…** deletes the files and the driver service.
- An older install in the data folder is removed and reinstalled in Program Files automatically the next time RustWarden runs as administrator.

This needs administrator rights.

WinDivert is made by basil00 and licensed under the LGPL-3.0 or GPL-2.0; the Driver row shows its **Source** line. See [Third-party data and credits](credits.md).

## Turning it on

1. **Settings > Other > Advanced > App mode > Driver**.
2. The **Driver** row appears. Press **Download and install…** and confirm.
3. Once it says **Installed**, the Driver mode features appear, along with three more rows on this page (below).

Switching back to **Normal** hides the features again. Bandwidth limits fall back to Windows QoS.

### Microsoft Defender

Defender often flags WinDivert, because some game-cheat and bypass tools bundle it. RustWarden asks first, then adds a Defender **exclusion for its driver folder only**, and removes that exclusion again when you remove the driver.

If Defender's Tamper Protection refuses the exclusion, or Defender removes the files anyway, the Driver row says so. Allow the item under **Windows Security > Virus & threat protection > Protection history**, then install again.

## Settings that appear in Driver mode

**Settings > Other > Advanced**, once the driver is installed:

### Line speed

**Line speed (up / down, Mbps)** is your connection's speed, used for [priority sharing](firewall/limits-qos.md#priority). `0` means not set, so there's no sharing.

### Host names

**Learn host names from the driver** (on by default). The driver reads the server name of new HTTPS connections (**SNI**) and **DNS answers** on this PC. Nothing leaves it.

- More connections show a name such as `youtube.com` instead of a bare IP.
- Each server name is filed under the **program** that opened the connection. On an address shared by many sites (a CDN), each program's traffic is named after the site **it** asked for, even when its own DNS is encrypted and another program's lookup named the address first.
- The [DNS Log](network/dns-log.md) also lists lookups made by programs with their own resolver, such as some browsers. Windows' own resolver is already logged, so those lookups aren't doubled.

**Limits:** Encrypted Client Hello and DNS-over-HTTPS hide names, and QUIC isn't read.

### QUIC fallback

**QUIC fallback (programs)**: a comma-separated list such as `chrome.exe, msedge.exe`. QUIC (HTTP/3, UDP port 443) is blocked for those programs, so they use HTTPS over TCP. There the server name is readable for Block by domain and the host names. It's a plain per-program firewall rule, so it costs nothing per packet. This needs administrator rights.

## Force DNS

**Settings > Firewall > Advanced > Force DNS through my resolver** (off by default). Enter a resolver such as `1.1.1.1`. Every program's plain DNS lookups (UDP port 53, IPv4) are then sent there, whatever server they were aimed at, and the answers are made to look as if the original server sent them.

This closes **DNS leaks**, for example a VPN's split setup, or a program using your ISP's resolver.

- Encrypted DNS isn't touched.
- The resolver must be reachable on your normal connection.

## Logs

The driver engine writes its start, stop and a counter line every 30 seconds to `engine.log` in `%LOCALAPPDATA%\RustWarden`.

## Demo mode

Demo mode simulates the driver install, so you can explore every Driver mode feature without installing anything.
