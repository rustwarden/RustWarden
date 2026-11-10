# Alert types

Every monitor RustWarden has, grouped by what it watches. Each one has its own switch and delivery options in **Settings > Alerts > Alert types** (see [Setting up alerts](index.md#setting-up-alerts)). Monitors marked *(Driver mode)* appear only when [Driver mode](../driver-mode.md) is on and the driver is installed.

## Programs

### First network activity
A program uses the network for the first time. This is the best way to notice new software going online.

### Application info monitor
A known program's version, publisher, certificate or executable has changed. That's usually an update, but it can also mean a file was replaced.

### Listening port monitor
A program starts **listening** for connections on a new TCP port below 49152. The alert says whether it listens on every interface, on one network address, or on this PC only. The first check only sets a baseline. It reads the TCP table, so it doesn't need administrator rights.

### Microphone and camera access
An app starts using the microphone or camera. This is read from the Windows privacy log.

### Data quotas
A program, or all traffic, reaches the warning level or the limit of a [quota](../protection/quotas.md).

### Data plan
Your whole [data plan](../protection/quotas.md#data-plan) is at 75% or over its limit.

## Network and connection

### Internet access monitor
Your internet connection dropped or came back. Short blips are smoothed out so they don't each raise an alert.

### DNS server settings monitor
The DNS servers your adapters use have changed. Malware that redirects your lookups does this.

### Proxy settings monitor
The Windows proxy settings have changed.

### ARP spoofing detection
The MAC address behind your own IP address has changed in the ARP table.

### VPN DNS leak check
A VPN tunnel is up, but another adapter still uses **public** DNS servers that aren't the VPN's, so Windows may send name lookups around the tunnel.

- A router's private DNS address isn't flagged.
- Adapters whose name contains anything on the ignore list are skipped. The list is editable in the alert's settings and defaults to *VMware, VirtualBox, vEthernet*, because bridged virtual machines never use the VPN.
- No administrator rights needed.

### Public IP address monitor
This PC's public IP address changed, for example after a new lease, a VPN dropping or a move to another network. If an [AS lookup](../protection/countries.md#as-number-and-company) is on, it also says when the **ISP** changed.

This needs the check switched on in **Settings > Countries & Network > Lookups > Watch my public IP address**. It's **off by default because it goes online**: every ten minutes it asks an https service of your choice (`api.ipify.org` by default) for your address. Only a bare IP address is accepted as the answer. The first check only sets the baseline.

### While you were away
When you come back to an idle PC, this gives a short summary of significant network activity while you were gone. **Away after N minutes idle** is set in the alert's settings.

## Your local network (Network Scanner)

These come from the [network scanner](../network/scanner.md). The first scan of a network only learns what's there. If [Home Assistant](../plugins/built-in.md#home-assistant) is set up, alerts include the device's Home Assistant name and area.

### Network Scanner: new device
A device never seen before has joined the network. Mark devices you know as **Trusted** in their details.

### Network Scanner: spoofing
An IP address now has a different MAC address, or one MAC answers for several IPs. Either can mean ARP spoofing. A change on the **gateway** is always Important.

### Network Scanner: device returned
A known device came back after being away for **N days** (set in the alert's settings).

## Windows system changes

### System file monitor
The `hosts` or `lmhosts` file was modified. Malware edits these to redirect sites.

### Windows user account monitor
A Windows user account was created, enabled, disabled or deleted.

### Scheduled task monitor
A new Task Scheduler task was added. Malware often uses one to survive a reboot.

### Root certificate store monitor
A trusted root certificate was added to Windows. Malware and interception tools add them to read encrypted traffic.

### Startup entry monitor
A program was added to the Run keys or the Startup folders, so it starts with Windows.

### New service monitor
A new Windows service or driver was installed.

### Firewall rule monitor
One of RustWarden's firewall rules was removed, changed or added **outside** RustWarden, including while RustWarden was closed. See [Rule drift check](../firewall/index.md#rule-drift-check).

### RDP detection
A Remote Desktop session started, with the address it came from.

### Computer unlock
Records each time the computer is unlocked.

## Threats

### Malicious IP protection
A program connected to an address on a malicious IP list. See [Malicious IP protection](../protection/malicious-ip.md). This one has its own red popup with **Block** and **Whitelist**, so its normal desktop notification is off by default.

### Malicious domain alerts
A program looked up a domain on a malicious-domain list (or a subdomain of one). This needs the [DNS log](../network/dns-log.md) and the domain lists turned on. It only warns; nothing is blocked.

### Beaconing detection
A program contacts the same internet address at near-perfectly even intervals, the pattern of malware checking in with its controller.

- It looks for intervals **between 15 seconds and an hour**, at least **12 times in a row**.
- Regular timing alone isn't enough. The series gets a **score from 0 to 100** based on:
    - the **size** of the contacts: small, uniform ones score up; media-sized ones, or downloads over 1 MB/min, score down hard;
    - whether the destination is a known **media / CDN** domain (`live-video.net`, `googlevideo.com`, `cloudfront.net` and others; the list is editable);
    - the **program**: unsigned, or talking to few destinations, scores up; a browser with many destinations scores down;
    - how **rare** the destination is.
- The alert says why the series scored high. Each program and address pair is reported at most once a day.

**Options** (in the alert's settings):

- **Ignore list.** Pick trusted programs from a list with icons; they aren't watched at all. Add a domain next to the picker to ignore only that program's contacts with that domain. These are stored as `program@domain`, for example `chrome@live-video.net`.
- **Watch at least N seconds**, **report from score N** and **jitter up to N**: the timing limits.
- **Media / CDN domains that lower the score.**

Many legitimate apps (updaters, mail, sync) check in regularly too, so expect to add a few to the ignore list.

### DNS tunnelling detection
Many long, random-looking lookups under one domain within five minutes, which is how data is smuggled out through DNS. This needs the [DNS log](../network/dns-log.md).

### Inbound port scan and flood *(Driver mode)*
The driver watches incoming connection attempts:

- **Port scan:** one address tries **12 or more** different ports on this PC within **10 seconds**.
- **Connection flood:** **300 or more** attempts in a second. The alert names the busiest source.

Each is reported at most once every ten minutes. Nothing is blocked.

### Rogue DHCP server detection *(Driver mode)*
More than one DHCP server answers on the network. A rogue one can hand your PC a wrong gateway or DNS server.

- The driver sees the answers to your own PC's requests, so the check runs when your lease is obtained or renewed.
- Servers are tracked **per network adapter**, so the DHCP services of VMware, Hyper-V and VirtualBox on their virtual adapters don't count as rivals to your router. They're only noted, unless you tick **Also watch virtual adapters**.
- A second server on one adapter is **critical** if it hands out a different gateway or DNS server, and a warning otherwise. The alert names the adapter and what each server offered.
- **Trusted DHCP servers** (an address, or `adapter name=address`, comma-separated) are skipped.

### TLS fingerprint check *(Driver mode)*
The driver reads the TLS ClientHello of each new HTTPS connection (JA3 and JA4 fingerprints). It alerts when a program **named like a web browser** opens connections with the fingerprint of a command-line tool such as curl or Python, which can mean something is pretending to be a browser. A hello that spans two packets is skipped.

## Behaviour baseline

These three need the [behaviour baseline](../protection/baseline.md) switched on. Their pins on the Traffic graph are purple.

### Behaviour: new country or network
A program contacted a country, or a network, that isn't in its usual set.

### Behaviour: traffic spike
A program moved far more data in a day than it usually does.

### Behaviour: unusual hour
A program was busy at an hour of the day when it's almost never active.
