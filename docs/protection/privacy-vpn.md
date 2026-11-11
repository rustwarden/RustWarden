# Privacy and VPN

**Settings > Privacy** has four tabs: **Incognito**, **Hidden Apps**, **VPN** and **P2P**.

## Incognito and hidden apps

| | Incognito | Hidden |
|---|---|---|
| Shown on the Firewall tab | No | No |
| Traffic **recorded** | **No** | Yes |
| Shown in the DNS log | No | No |
| How to add | Info popup **••• More > Add to Incognito…**, or type the full executable path in **Settings > Privacy > Incognito** | Info popup **••• More > Hide App** |
| How to undo | **Remove** in Settings > Privacy > Incognito | **Unhide** in Settings > Privacy > Hidden Apps |

Use **Hidden** for programs you don't care about seeing. Use **Incognito** for programs whose activity you don't want recorded at all.

## VPN

**Settings > Privacy > VPN**

### VPN kill switch

While a VPN is connected, the kill switch blocks everything on your **real** network cards except your local network and the VPN's own server, so nothing can leave outside the tunnel. If the VPN drops, the block **stays** and the internet is cut until the VPN is back.

- **It arms itself.** Some VPNs, such as PIA, only create their network adapter when you press Connect, so the switch arms itself the first time it sees a VPN connected.
- **It learns the VPN's servers** from the host routes the VPN client adds, and remembers them.
- **Let the VPN connect** opens the network for **two minutes**, so the VPN client can reach a new server.
- **Let the VPN reconnect by itself** (off by default) does the same automatically: once the VPN has been down for 15 seconds the network opens for two minutes, once per outage, then the block returns if the VPN is still down. Traffic can leave outside the tunnel during that window.
- Turning the switch off, closing RustWarden, or **Restore firewall defaults** lifts the block.

This needs administrator rights.

### Block DNS-over-HTTPS resolvers

Blocks encrypted DNS (HTTPS and DNS-over-TLS, ports **443** and **853**) to well-known public resolvers: Google, Cloudflare, Quad9, OpenDNS, AdGuard, NextDNS and others. Browsers set to "secure DNS" then fall back to the system resolver, where the [DNS log](../network/dns-log.md), [destination rules](../firewall/destination-rules.md) and domain blocks can see their lookups. Plain DNS isn't touched.

It's off by default and needs administrator rights.

### Don't count VPN tunnel traffic

A VPN client's encrypted traffic duplicates what your apps send through it, so it would always top the traffic list. With this on, the VPN client's own traffic isn't counted **while a VPN is connected**; your apps' own traffic still is. Common clients (OpenVPN, WireGuard, NordVPN, ExpressVPN, Proton, Mullvad, Tailscale and more) are recognised. Add others by executable name under **Other VPN programs**.

### Related

- [VPN DNS leak check](../alerts/alert-types.md#vpn-dns-leak-check) alerts when an adapter's DNS bypasses the tunnel.
- [Force DNS](../driver-mode.md#force-dns) *(Driver mode)* sends every plain DNS lookup to the resolver you choose.
- [Bandwidth limits in Driver mode](../firewall/limits-qos.md#driver-mode-downloads-both-directions-and-pacing) work over a VPN.

## Peer-to-peer guard

**Settings > Privacy > P2P**

Spots programs that behave like **torrent clients** and can keep them offline while no VPN is connected.

1. Switch on **Detect peer-to-peer traffic** (off by default). RustWarden watches, on this PC only, for well-known torrent programs, and for any other program that exchanges data with many internet addresses that **no website lookup ever named**. Browsers are never flagged.
2. Flagged programs are listed under **Block without a VPN** with when they were last seen.
3. Switch a program **on** there, and it's blocked **completely, in both directions**, whenever no VPN adapter is connected, then let through again when one is. A firewall can't single out just the peer-to-peer part of a program, so the whole program is blocked.
4. **Not P2P** marks a false alarm. The program moves to **Not flagged (false alarms)**, where **Flag again** undoes it.

This is a guess from traffic patterns: RustWarden doesn't look inside the traffic, and nothing leaves your PC. It needs Live mode with administrator rights. Its rules are tagged as RustWarden's and are removed by **Restore firewall defaults**. Demo mode shows sample programs.
