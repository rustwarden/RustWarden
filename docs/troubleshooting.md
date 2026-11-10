# Troubleshooting and FAQ

## A program (or everything) lost its internet

1. Open the **Firewall** tab and check the program's **Incoming / Outgoing / Local** chips. Look out for an orange hourglass, which is a [scheduled block](firewall/index.md#block-after-n-minutes).
2. Check the **Mode**. **Block All** blocks almost everything, and **Prompt** holds new programs until you answer (look for waiting popups, or press **Review**).
3. Check **Firewall > Destination Rules** for an *Only allow* rule, and **Limits / QoS** for a very low limit.
4. Check **Settings > Privacy > VPN**. The **kill switch** cuts the internet while a VPN is down. Use **Let the VPN connect** or turn it off.
5. Check **Settings > Privacy > P2P**. A program picked there is blocked whenever no VPN is connected.
6. Check [quotas](protection/quotas.md). A quota may have blocked the program at 100%.
7. Still stuck? **Mode > Disabled** turns RustWarden's blocks off. **Restore firewall defaults** removes them all. If you can't open the app, use the [rescue command](firewall/rescue.md).

## The Traffic tab is empty / "needs administrator rights"

Per-program traffic, the DNS log and firewall changes need administrator rights. Use **RustWarden menu > Restart as administrator**, or install the [Windows service](getting-started/install.md#run-as-administrator-without-a-prompt-every-time) so you aren't prompted each time.

## No country flags or map

Download the country database in **Settings > Countries & Network > Downloads**. For city-level positions, also download the city database and switch on **Use the city database on the map**.

## The DNS log doesn't show my browser's lookups

Your browser is probably using its own encrypted DNS (DNS-over-HTTPS), which bypasses Windows. Switch on [Block DNS-over-HTTPS resolvers](protection/privacy-vpn.md#block-dns-over-https-resolvers), or turn off "secure DNS" in the browser, or use [Driver mode host names](driver-mode.md#host-names).

## "Windows Firewall is off, so RustWarden's rules have no effect"

RustWarden's rules live in the Windows Firewall, so they only work while it's on. Press **Turn on Windows Firewall** in the banner.

## I got a "Firewall rule monitor" alert

Something outside RustWarden changed one of its rules: another security tool, a script, or a change by hand in Windows Firewall. The alert names the rules, and the full list is in `%LOCALAPPDATA%\RustWarden\rustwarden.log`. If the change was expected, you can ignore it. Otherwise, set the rule again from the Firewall tab.

## Too many alerts

- Turn off the desktop popup for the noisy type in **Settings > Alerts > Alert types**, or set its level to **Logs**.
- Add an [alert rule](alerts/alert-rules.md): **Mute** at night, or **Limit repeats**.
- For [beaconing](alerts/alert-types.md#beaconing-detection), add trusted programs (or `program@domain`) to its ignore list.
- **Snooze alerts** for an hour from the tray.

## Microsoft Defender flagged the driver

That's WinDivert, used by [Driver mode](driver-mode.md#microsoft-defender). Allow it under **Windows Security > Virus & threat protection > Protection history** and install again, or switch back to Normal mode and **Remove driver**.

## Bandwidth limits don't affect downloads

In Normal mode, Windows can only cap **uploads**. Download limits need [Driver mode](driver-mode.md).

## The window opened off-screen

Use **tray menu > Settings… > Other > General > Reset window**.

## I forgot the tamper-protection password

There's no built-in recovery, because that would defeat the point of the lock. Ask whoever set the password, or open an issue if you're the owner of the PC and are locked out.

## Where are the logs?

All in `%LOCALAPPDATA%\RustWarden`:

| File | What |
|---|---|
| `rustwarden.log` | General log, rule drift details, VirusTotal uploads |
| `lists.log` | Skipped and refused threat lists |
| `rescue.log` | What `--remove-all-rules` removed |
| `engine.log` | The Driver mode bandwidth engine |

## Reporting a bug

Open an issue on [GitHub](https://github.com/rustwarden/RustWarden/issues). Include your RustWarden version (**RustWarden menu > About**), whether you're in Live or Demo, Normal or Driver mode, and a [snapshot](maintenance.md#snapshots) if it's visual. Check logs for anything private before attaching them. For security problems, see [SECURITY.md](https://github.com/rustwarden/RustWarden/blob/main/SECURITY.md).
