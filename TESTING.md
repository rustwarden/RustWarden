# Testing RustWarden

## Automated

```
cargo build
cargo clippy --all-targets
cargo test
```

The pure logic is unit tested without administrator rights or any firewall change: time bucketing, retention and windowing (`live::bucket`, `live::db`), address and protocol classification and DNS result parsing (`live::net`), ETW payload decoding on hand-built bytes (`sys::etw`), flow attribution and per-second aggregation (`live::traffic`), alert diffing for ARP, DNS servers, hosts files, sessions, internet debounce and data-plan thresholds (`live::alerts`), rule naming, group filtering and cleanup thresholds (`live::firewall`), scanner target selection, OUI/vendor and NetBIOS/SSDP parsing (`live::scanner`), config round trips and mode parsing (`settings`), alert filtering (`ui::log`), the app resolver (`live::apps`), and the integrations: notification requests and curl config quoting (`plugins::external_notifications`), Home Assistant templates and device matches (`plugins::ha`), the shared latency chart columns (`plugins::core::latency`), and ping storage and a loopback echo (`plugins::ping`). Some tests read the real OS read-only (adapters, ARP table, firewall rule list, PDH names) and must pass on any Windows machine.

## Manual checks on a real machine

Start Live mode with `RUSTWARDEN_MODE=live` or the DEMO/LIVE chip. The strip under the header lists what is degraded.

### Unelevated (a normal user)
1. **Mode.** With no config and no environment variable the app opens in DEMO and looks as it always did. Click the chip: it becomes LIVE and the strip says per-app traffic needs administrator rights. Quit and restart: it reopens in LIVE (`%APPDATA%\RustWarden\config.toml` has `mode = "live"`). `RUSTWARDEN_MODE=demo` wins for that run.
2. **Traffic.** Open a few web pages. After a few seconds the graph on the Traffic tab shows activity, the footer shows rates and totals, and the 5 Minutes / 1 Hour / 3 Hours / 24 Hours selector changes the time axis. Compare the totals with Task Manager → Performance → Ethernet/Wi-Fi. The Apps/Hosts/Traffic Type/Countries lists show "Not available without administrator rights".
3. **Hardware.** CPU, memory, disk and GPU charts move; start a CPU-heavy task and the CPU chart rises. Compare the numbers with Task Manager. A machine without GPU counters shows "n/a".
4. **First network activity.** Start a program that has not talked to the network before (portable app, a new browser). Within about 4 s an alert "… initiated its first network connection to …" appears and the Log tab badge counts it. (The first 20 s after the very first run are a baseline and don't alert.)
5. **Alert monitors.** In an elevated PowerShell (these change real settings; undo them afterwards):
   * Internet: disable the adapter for ~15 s and re-enable it → "Internet connection lost" then "restored".
   * DNS servers: `Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses 9.9.9.9`, then restore → "changed its DNS servers".
   * Proxy: Settings → Network → Proxy, toggle "Use a proxy server" → "Proxy settings changed".
   * Hosts file: append a comment line to `C:\Windows\System32\drivers\etc\hosts` and remove it → "Hosts file changed".
   * ARP: `arp -d *` then browse; a MAC *change* needs a second device taking over an IP, so this one is only checked by the unit tests.
   * Remote Desktop: connect to the machine with mstsc → "started a Remote Desktop session".
   Each monitor can be switched off in Settings → Alerts; "Snooze 1 h" makes new alerts arrive already read; the search box and the Important/All/Unread filters work.
6. **Data plan.** Settings → Data plan: enable, set a limit of 0.1 GB, generate traffic → "has used 75% / the whole data plan" once each per period.
7. **Away.** Set "Away after" to 1 minute, leave the computer idle for 2 minutes, move the mouse → "While you were away" with the traffic recorded meanwhile.
8. **Scanner.** Network Scanner → Scan. Progress percent counts up, devices appear with vendor names (look one up by MAC to check), your own computer is marked "Windows (this computer)". Press "Scanning…" to stop mid-scan. Rename a device by clicking its row. "Forget network" empties the list. A second scan after plugging in a phone raises "has a new device". Wireshark on the same segment shows only ARP requests inside your own /24, spaced by the scan delay.
9. **Incognito.** Settings → Incognito: add the full path of a program, generate traffic with it; it appears in neither the usage lists nor the Firewall tab (elevated) and raises no alert.
10. **Settings.** Retention, units (bits), text size, and the GeoIP path are saved to the config and take effect immediately. **Snapshot** (brand menu) writes `RustWarden-<time>.png` to Pictures.
11. **Firewall tab, read-only.** Chips and the toggle are refused with a toast; the banner says "Read-only: run RustWarden as administrator…". Existing RustWarden rules are shown.

### Elevated (use "Restart as administrator")
12. **ETW.** The warning about per-app traffic disappears. Browse: Apps, Hosts (names after the first DNS lookups), Traffic Type (e.g. HTTPS, DNS), Countries and the WAN/LAN split fill in. With a GeoLite2 country or city database at `%LOCALAPPDATA%\RustWarden\GeoLite2-Country.mmdb` (download your own from MaxMind) the countries get names and the map gets arcs. **These payload layouts were never run on live data by the author**; if the totals look wrong (e.g. every host is "Other", ports are nonsense) compare against `Get-NetTCPConnection` and Resource Monitor → Network and report it. Check there is no stale ETW session afterwards: `logman query -ets` must not list `RustWarden-Net` after the app exits.
13. **Block a program.** In Firewall, click a program's Out chip. Confirm in `Get-NetFirewallRule -Group RustWarden | Format-List DisplayName,Direction,Action,Enabled` that one rule `RustWarden block out: <file> [hash]` exists with Action Block. With the RustWarden firewall toggle off the rule is disabled; turn it on (confirmation dialog) and the program loses network access. Try to block `System` or `svchost.exe`: refused ("can't be blocked"). Try RustWarden itself: refused.
14. **Outside changes.** Disable one of the rules in `wf.msc`: within 5 s the chip/state updates and a "Firewall rules" alert appears.
15. **Windows Firewall off.** Turn Windows Firewall off for the active profile in Windows Security: the Firewall tab shows the banner "Windows Firewall is off…" with a button; the button asks for confirmation before turning it on.
16. **Restore defaults removes only RustWarden rules.**
    ```
    # an unrelated rule in another group, plus one with a RustWarden-like name but no group
    New-NetFirewallRule -DisplayName "Test keep me A" -Group "Some Other Group" -Direction Outbound -Action Block -Program "C:\Windows\System32\notepad.exe"
    New-NetFirewallRule -DisplayName "RustWarden block out: lookalike" -Direction Outbound -Action Block -Program "C:\Windows\System32\calc.exe"
    ```
    Block two programs in RustWarden, then brand menu → Restore firewall defaults → confirm. Then:
    ```
    Get-NetFirewallRule -Group RustWarden                     # nothing
    Get-NetFirewallRule -DisplayName "Test keep me A","RustWarden block out: lookalike"   # both still there
    Get-NetFirewallRule -DisplayName "Test keep me A","RustWarden block out: lookalike" | Remove-NetFirewallRule
    ```
    Switching to Demo with RustWarden rules present offers the same cleanup ("Remove rules and switch" / "Keep rules and switch" / Cancel).
17. **Block All.** *Not exercised by the author on a real machine.* Run it with a console or a second device ready to recover, not over a remote session (it cuts the machine's outbound traffic). Choose Block All → read and accept the confirmation. The banner "Block All is active" appears; browsers lose the internet, RustWarden keeps running. Click "Undo Block All": `Get-NetFirewallProfile | Select Name,DefaultOutboundAction` returns to what it was (Allow on a stock machine) and `Get-NetFirewallRule -Group RustWarden` no longer lists the `block-all exception` rules. Repeat, but this time kill the app from Task Manager while Block All is on; `%LOCALAPPDATA%\RustWarden\blockall.marker` exists; start RustWarden as administrator in either mode: it undoes Block All on start. Start it unelevated instead: a dialog says Block All is still active and how to fix it.
18. **Cleanup.** Settings → Firewall cleanup: tick the option, set "uninstalled" to 1 day, block a portable program, delete it, wait for the app records to mark it missing (a minute), then adjust the clock or the stored `missing_since` and wait for the hourly pass. (The threshold logic is unit tested; this is a slow end-to-end check.)
19. **Home Assistant.** Settings → Integrations → + → Home Assistant; enter the address and a long-lived token (HA profile → Security), press Test connection ("Connected."), tick both options, Done, OK. Run a network scan: devices whose MAC is a Home Assistant device get the HA icon (and a type icon) beside their name, with the HA name (area first) when "Prefer HA entity name" is on; devices HA doesn't know get nothing. HA's log shows one `/api/template` request per device, about one a second, then none. `ha_devices` in `%LOCALAPPDATA%\RustWarden\rustwarden.db` holds only scanned MACs. Turn HA off or give a wrong token: the status line warns and retries within the hour; "Sync now" re-checks everything. (Parsing, the lookup schedule and settings are unit tested; the template needs a real HA.)
20. **DNS Log.** *The payload layout and the process attribution were never run on live data by the author.* Elevated, open Network > DNS Log. Run `nslookup example.com`, `curl https://example.org` and `Resolve-DnsName nope.invalid` (use a browser too): rows appear within about a second, with the right process (the shell, curl.exe, powershell.exe), type A/AAAA, the addresses, and "Name not found" for the bogus name. If lookups show as `svchost.exe` the header process id is the DNS service, not the caller: report it (the fix is to read the client PID in the service-side events 3010/3018). Search by process, name and address. Browsers with DNS over HTTPS won't show their lookups. Turn the log off in Settings > General: no new rows. `ipconfig /all` must show the same DNS servers before and after.
21. **Malicious-domain alerts.** Elevated, with the DNS log on: Settings > Malicious IP protection > Malicious domains, tick the switch (the status strip warns if the download fails and it retries within the hour; `%LOCALAPPDATA%\RustWarden\dns_threats.txt` appears once it works). Add a list URL you control whose file contains the line `0.0.0.0 test-bad.example` (changing the URLs doesn't re-download by itself: delete `dns_threats.txt` and restart RustWarden), then run `nslookup test-bad.example` and `nslookup www.test-bad.example`: one "Malicious domain" alert per program and name, the name is red in Network > DNS Log with status "Malicious domain". Untick the switch: no new alerts and the list is dropped. Nothing is blocked and `ipconfig /all` is unchanged.
