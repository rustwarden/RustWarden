# Settings reference

Every page of **Settings**, with a link to where each feature is explained. Most changes apply when you press **Save**. **Cancel** throws them away.

## General

| Tab | Setting | Default | See |
|---|---|---|---|
| General | Start RustWarden when Windows starts / Start hidden in the tray (applies straight away) | Off | [Install](getting-started/install.md#start-with-windows) |
| General | Show rates in bits | Off | [The window](getting-started/interface.md#look-and-feel) |
| General | Split "NT Kernel & System" by service | On | [Traffic](traffic.md#kernel-system-split) |
| History | Traffic history | 30 days | [Traffic](traffic.md#history-and-retention) |
| History | Hardware history | 24 hours | [Hardware](hardware.md) |
| History | DNS log / DNS log history | On / 7 days | [DNS Log](network/dns-log.md) |
| History | Clear traffic history… | — | [Upkeep](maintenance.md#history-and-storage) |
| Security | Tamper protection password | None | [Upkeep](maintenance.md#tamper-protection) |

## Personalise

| Tab | Setting | See |
|---|---|---|
| Theme | Follow the Windows theme, Theme, Accent colour, Use Windows accent colour, Acrylic intensity, Tint with wallpaper colour, UI scale | [The window](getting-started/interface.md#look-and-feel) |
| Popups | Popup opacity, Popup corner, Popup duration, Popups shown at once | [Popups](getting-started/interface.md#popups) |

## Data Plan

Warn at 75% and over the limit, the allowance (direction, period, GB), and don't count local traffic. See [Data plan](protection/quotas.md#data-plan).

## Quotas

Per-app and all-traffic quotas. See [Quotas](protection/quotas.md#quotas).

## Alerts

| Tab | What | See |
|---|---|---|
| Alert types | Per type: on/off, desktop notification, event log, notification plugins, level, and type-specific options | [Alerts](alerts/index.md#setting-up-alerts), [Alert types](alerts/alert-types.md) |
| Options | Windows event log master switch, Behaviour baseline | [Baseline](protection/baseline.md) |

## Network Scanner

Scan automatically (off), Time between scans (30 min), Time between probes (20 ms), Scan other VLANs and subnets (on). See [Network Scanner](network/scanner.md#scanning-automatically).

## Firewall

| Tab | Setting | See |
|---|---|---|
| Blocking | Keep Prompt blocking when RustWarden is closed | [Prompt](firewall/index.md#prompt) |
| Blocking | Remove block rules of uninstalled apps, after N days (7) | [Housekeeping](firewall/index.md#rule-housekeeping) |
| Blocking | Import existing firewall rules / Import and rename | [Importing](firewall/index.md#importing-rules-from-another-firewall-app) |
| Windows components | Block Windows components that don't need internet, Pause / Resume / Unblock per group, Keep these components blocked (checks every 24 h) | [Housekeeping](firewall/index.md#rule-housekeeping) |
| Rulesets | Switch, create, delete rulesets | [Rulesets](firewall/index.md#firewall-rulesets) |
| Advanced | Let RustWarden's own downloads through the firewall (on) | [Helpers](firewall/index.md#letting-rustwardens-own-helpers-through) |
| Advanced | Force DNS through my resolver *(Driver mode)* | [Force DNS](driver-mode.md#force-dns) |
| Advanced | Restore firewall defaults | [Rescue](firewall/rescue.md) |

## Malicious IPs

| Tab | What | See |
|---|---|---|
| IP lists | Warn, block automatically, update interval, list URLs | [Malicious IPs](protection/malicious-ip.md#malicious-ips) |
| Domain lists | Warn, update interval, list URLs | [Malicious domains](protection/malicious-ip.md#malicious-domains) |
| Blocked & whitelisted | Unblock, whitelist, details | [Blocked & whitelisted](protection/malicious-ip.md#blocked-whitelisted) |

## Privacy

| Tab | What | See |
|---|---|---|
| Incognito | Programs not shown or recorded | [Privacy](protection/privacy-vpn.md#incognito-and-hidden-apps) |
| Hidden Apps | Programs hidden from the Firewall tab | [Privacy](protection/privacy-vpn.md#incognito-and-hidden-apps) |
| VPN | Kill switch, Block DNS-over-HTTPS resolvers, Don't count VPN tunnel traffic, Other VPN programs | [VPN](protection/privacy-vpn.md#vpn) |
| P2P | Detect peer-to-peer traffic, Block without a VPN | [Peer-to-peer guard](protection/privacy-vpn.md#peer-to-peer-guard) |

## Countries & Network

| Tab | What | See |
|---|---|---|
| Downloads | Country, city and ASN databases, auto-update | [Countries](protection/countries.md#downloads) |
| Geolocation | Custom country database, city database on the map | [Countries](protection/countries.md#geolocation) |
| Lookups | AS number and company, Public IP address, Whois | [Lookups](protection/countries.md#lookups) |

## Plugins

System Plugins, Notification Plugins, Install from file, Reinstall default plugins, Create a Plugin, weekly summary. See [Plugins](plugins/index.md) and [Notifications](plugins/notifications.md).

## Other

| Tab | Setting | See |
|---|---|---|
| General | Use demo data | [Live and Demo](getting-started/concepts.md#live-and-demo-mode) |
| General | Send a test notification | [Testing](alerts/index.md#testing) |
| General | Reset window | [Upkeep](maintenance.md#window) |
| Backup | Export / Import rules and settings | [Backup](maintenance.md#backup-and-restore) |
| Backup | Clean up downloaded components | [Clean up](maintenance.md#clean-up) |
| Updates | Update channel (Release / Dev), Run wizard (Dev) | [Updates](maintenance.md#updates) |
| Advanced | App mode (Normal / Driver), Driver install, Line speed, Learn host names, QUIC fallback | [Driver mode](driver-mode.md) |
| Advanced | Windows service: Install / Uninstall | [Service](maintenance.md#the-windows-service) |
