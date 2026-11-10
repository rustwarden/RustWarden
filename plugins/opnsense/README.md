# OPNsense plugin

The OPNsense plugin connects RustWarden to an [OPNsense](https://opnsense.org) router over its REST API. It is a
built-in plugin (source: `plugins/opnsense/src/lib.rs`), compiled to WebAssembly and loaded from memory like the other
first-party plugins. Turn it on under **Settings > Plugins > OPNsense**.

Nothing is contacted until you enter an address, an API key and an API secret, and **every option stays off until the
key has been probed** to show what it is allowed to do.

> **Status.** The connection test, the write check and the option gating are older and well covered by tests. The
> three "bring in" options and "send blocked addresses" were added later (see [History](#history)). Their code is
> unit-tested against sample API replies written from OPNsense's API documentation, but it has **not been run against a
> live router** by its author. If a reply on your OPNsense version looks different, the page shows the error in the
> yellow status line and logs it; please report it.

## What it does

| Option (Settings > Plugins > OPNsense) | Needs on the key | What RustWarden does |
| --- | --- | --- |
| **Test connection** | any read privilege | Signs in and finds out which parts of the API the key can read. Nothing is changed. |
| **Check write access** | alias edit | Creates an alias called `RustWarden_probe` and deletes it again, to see whether the key can write. Nothing is applied. |
| **Device names and addresses** | DHCP leases or Diagnostics: ARP | Names the devices on the **Scanner** tab from the router's DHCP leases and ARP table. |
| **Router firewall log** | Diagnostics: firewall log | Shows the router's newest firewall log lines on the **OPNsense** tab. |
| **Gateway status and traffic** | gateways | Shows each gateway's status, delay and loss on the **OPNsense** tab. |
| **Blocked addresses** | alias edit | Keeps an alias on the router, `RustWarden_blocked`, equal to the addresses RustWarden has blocked. |

The plugin refreshes once a minute (and when you press **Refresh now** on its tab). Each option runs only if it is
switched on **and** the last probe showed the key may do it. Changing the address, key or secret throws the probe
result away and switches every option off again until you test the connection.

### Device names

With the `devices.annotate` permission RustWarden gives the plugin the devices its network scan found (MAC, address,
name). The plugin asks the router for its DHCP leases (ISC `/api/dhcpv4/leases/searchLease`, or Kea
`/api/kea/leases4/search`) and its ARP table (`/api/diagnostics/interface/getArp`), and matches by **MAC address only**,
ignoring case and separators. For every scanned device whose MAC has a host name on the router it stores one row in its
own table `p_opnsense__devices`. RustWarden reads that table for the Scanner tab (the same mechanism Home Assistant
uses). Devices the router knows but the scan has not seen are never stored. A device without a host name on the router
is left alone, so another annotating plugin (for example Home Assistant) can still name it; the first plugin that has a
name for a MAC wins.

### Gateways and the firewall log

Read-only. The newest 25 log lines and every gateway are kept in the plugin's settings store (not in a table) and drawn
on the **OPNsense** tab. The log request is `/api/diagnostics/firewall/log?limit=25`; gateways come from
`/api/routes/gateway/status`.

### Sending blocked addresses to the router

With the `firewall.blocks.read` permission the plugin can read the list of addresses RustWarden has blocked (its
malicious-address blocks, and addresses you blocked by hand). The plugin then:

1. Keeps only valid IPv4/IPv6 addresses, once each, sorted. Anything else never reaches the router.
2. Asks the router for the alias named `RustWarden_blocked` (`/api/firewall/alias/getAliasUUID/RustWarden_blocked`).
3. Creates it (`addItem`) or updates it (`setItem/<uuid>`) as a **host** alias whose content is the address list, with
   the description *"Addresses blocked by RustWarden. Managed by RustWarden: edits here are overwritten."*
4. Calls `/api/firewall/alias/reconfigure`, which loads the alias on the router.

It only does this when the list (or the router address) has changed since the last successful send; the hash of what was
sent is kept in the plugin's settings. **RustWarden never creates or edits a firewall rule.** An alias on its own blocks
nothing: to enforce it, add a rule on the router yourself (Firewall > Rules > WAN or LAN, action *Block*, destination or
source *RustWarden_blocked*). That is deliberate: a rule is your policy, an alias is data.

## Names and prefixes

Everything RustWarden creates, on the router or in its own database, is named so it can be found and removed.

| Where | Name | Meaning |
| --- | --- | --- |
| Router alias | `RustWarden_blocked` | The addresses RustWarden has blocked. Overwritten on every change; do not hand-edit. |
| Router alias | `RustWarden_probe` | A throw-away alias made and deleted by **Check write access**. If it is still there, the delete failed: the page warns and you can delete it in Firewall > Aliases. A leftover is removed automatically by the next check. |
| RustWarden database | `p_opnsense__devices` | The names found for scanned devices. A plugin may only touch tables starting `p_<id>__` (dashes in the id become underscores; the double underscore ends the id, so no plugin's prefix is the start of another's). Other plugins' tables are invisible to it. |
| Plugin settings | `url`, `allow_self_signed`, `pull_devices`, `pull_log`, `pull_gateway`, `push_blocks`, `caps`, `gw`, `fwlog`, `named`, `pushed`, `pushed_n`, `status`, `updated`, `msg` | The plugin's own key/value store. |
| Plugin secrets (DPAPI) | `key`, `secret`, `caps_for` | Encrypted for the current Windows user (`dpapi:<hex>` in the config file). `caps_for` is a fingerprint of the address, key and secret the probe result belongs to, so a probe is never trusted for different credentials. |

The names are fixed in the code: `BLOCK_ALIAS`, `PROBE_ALIAS`, `SCHEMA` in `plugins/opnsense/src/lib.rs`.

Removing the plugin with **Remove Plugin Data** ticked deletes its settings, its secrets and its tables from RustWarden.
It does **not** reach out to the router: delete the `RustWarden_blocked` alias (and any rule that uses it) yourself.

## Permissions

The plugin's manifest asks for two opt-in permissions. Built-in plugins are trusted like the exe itself, so they are
granted when the plugin is switched on; the list is shown in the plugin's Permissions dialog.

| Permission | Why |
| --- | --- |
| `devices.annotate` | Read the scanned devices, and fill `p_opnsense__devices` so the Scanner tab shows the names. |
| `firewall.blocks.read` | Read RustWarden's list of blocked addresses to put in the alias. |

It may contact **any** http(s) host (`http_hosts = ["*"]`), because your router is wherever you put it, and it may accept
the router's own certificate (`allow_insecure_tls`), because OPNsense ships a self-signed one. Both are shown in the
approval dialog. The self-signed option is **off** until you switch on *Allow self-signed certificate*, and it is only
applied to requests to the address you entered.

## Setting it up

1. On the router: **System > Access > Users**, pick (or make) a user, and under **API keys** create a key. Download the
   file: it holds the key and the secret. Give the user only what you want to use: *Diagnostics*, *Firewall: Log Files*,
   *Services: DHCP* (or Kea), and, for sending blocks, *Firewall: Aliases* edit. A read-only user is fine for everything
   except **Blocked addresses**.
2. In RustWarden: **Settings > Plugins > OPNsense > Settings**. Enter the address of the web interface
   (`https://192.168.1.1`), the key and the secret. Turn on *Allow self-signed certificate* if the router uses its own.
3. Press **Test connection**. The result shows the OPNsense version and which parts the key can read.
4. Optionally press **Check write access** (needed before **Blocked addresses** can be switched on).
5. Switch on the options you want. The ones the key can't do stay greyed out with the reason.

## Demo mode

Everything works in Demo mode with made-up data and no network: the probe finds a router ("25.1 (demo)") that can read
everything (a key containing `readonly` can't write), the tab shows two sample gateways and two sample log lines, and
**Blocked addresses** pretends to send the two sample blocked addresses. Device naming has nothing to do in Demo mode
because the Demo scan list is not shared with plugins.

## Privacy and safety

* Credentials are sent as HTTP Basic authentication to the address you typed, over the connection you chose
  (use `https://`). They are passed to curl on its standard input, never on a command line.
* Control characters are stripped from the key and secret, so they cannot add headers to a request.
* The plugin cannot read or write anything outside its own settings, secrets and `p_opnsense__*` tables.
* The only things written to the router are the two aliases above. The write check never applies anything.
* An address is only sent to the router if it parses as an IP address.

## What it does not do

* It does not create firewall rules, NAT rules, DHCP reservations or users.
* It does not remove aliases when you switch an option off or remove the plugin.
* It does not read the router's configuration, passwords or logs other than the firewall log lines described.
* It does not support OPNsense versions whose API paths differ from the ones listed here; the probe reports which parts
  are missing.

## Troubleshooting

| Message | Meaning |
| --- | --- |
| *OPNsense rejected the API key or secret.* | HTTP 401: wrong key or secret, or the user is disabled. |
| *That address doesn't look like OPNsense's web interface.* | HTTP 404 on the status call: wrong address, or a different product. |
| *The router's certificate isn't trusted.* | Turn on *Allow self-signed certificate* (only for a router on your own network). |
| *This key can't read anything useful.* | The user lacks the Diagnostics / DHCP / Firewall log privileges. |
| *Press Check write access first.* | **Blocked addresses** needs a write check that succeeded. |
| *Blocked addresses: The router refused to change the alias* | The key is read only. |
| *The alias was saved, but the router didn't load it* | `reconfigure` failed; apply aliases in the router's UI. |

The plugin's own log lines are in `plugins.log` in RustWarden's data folder.

## History

* **Probe and settings** (earlier): address, key and secret; *Test connection*; *Check write access*; the options
  were gated on the probe. The four options themselves did nothing yet.
* **This version**: the options work. Device names go to the Scanner; gateways and the firewall log have a tab; blocked
  addresses are kept in `RustWarden_blocked` using the new `firewall.blocks.read` host call. The plugin now declares the
  `devices.annotate` and `firewall.blocks.read` permissions, a once-a-minute tick and the `p_opnsense__devices` table.
