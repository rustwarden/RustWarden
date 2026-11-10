# Updates, backup and upkeep

## Updates

RustWarden checks for a new version when it starts and every few hours. If the check fails, it quietly does nothing. **RustWarden menu > Check for updates** checks straight away.

- Releases are read from the [GitHub releases](https://github.com/rustwarden/RustWarden/releases) of this project.
- Each download is checked against its **signed SHA-256 checksum** before it's installed.

**Settings > Other > Updates > Update channel**:

| Channel | What you get |
|---|---|
| **Release** | Tested releases (recommended) |
| **Dev** | Alpha builds with the newest features. They may break. |

Switching from Dev back to Release installs the latest release at the next check. On the Dev channel, a **Run wizard** button re-runs the [first-run wizard](getting-started/install.md#the-first-run-wizard).

If the Windows service is installed and you run a **newer** `RustWarden.exe` than the service's copy, RustWarden offers to update the service first.

## Backup and restore

**Settings > Other > Backup > Back up rules and settings**

**Export…** saves to one JSON file:

- the programs you've blocked,
- your destination rules,
- all your settings.

The tamper-protection password is left out. Tokens and webhook addresses stay **encrypted for your Windows user**, so they only come back on the same Windows account.

**Import…** reads a file from Export:

- It shows a **summary first**, then applies only what's **different** from now, just like clicking the chips on the Firewall tab. It **never removes** anything.
- Settings are applied key by key. Settings the file doesn't have keep their current value, and ones this version can't read are skipped, so files from older or newer versions import without failing.
- Demo/Live mode and window position aren't changed.

Rules are named after the app, so export and import is how you keep them across a reinstall or after renaming the exe. It works in Demo mode too.

## Clean up

RustWarden has no installer, so anything it downloads stays on disk. **Settings > Other > Backup > Clean up > Remove…** deletes:

- `speedtest-cli`,
- the GeoIP and ASN databases,
- the malicious IP and domain lists,
- any saved web sign-in sessions,

and switches off the features that used them (the Speedtest plugin and its schedule, the city map and database updates, Malicious IP protection). You can turn them back on in Settings and download again.

History, alerts, firewall rules and settings are kept. This can't be undone.

## Tamper protection

**Settings > General > Security > Tamper protection** (off by default).

Set a **password**, and **Settings**, **Exit** and **Restart** ask for it. It's meant for shared or family PCs.

- The password is stored **hashed** and sealed with DPAPI.
- Stopping the service from `services.msc` or `sc stop` also asks for it.
- An administrator can still end the process, but the service restarts itself a second later.
- **Remove** clears the password.

It deters casual changes. It isn't a defence against an administrator who's determined to remove it.

## The Windows service

**Settings > Other > Advanced > Windows service** installs or removes the service, which lets RustWarden open as administrator **without a UAC prompt**. Installing or removing it asks for administrator approval once, then restarts RustWarden. **Restart service** in the RustWarden and tray menus restarts the app.

## Window

**Settings > Other > General > Window > Reset window** puts the window back at its default size in the middle of the screen, in case it ever opens somewhere you can't see it.

## History and storage

**Settings > General > History**:

| Setting | Default | Notes |
|---|---|---|
| Traffic history | 30 days | How long Live mode keeps per-app traffic |
| Hardware history | 24 hours | CPU, memory, disk and GPU history (up to 30 days) |
| DNS log | on | Needs administrator rights |
| DNS log history | 7 days | |
| Clear traffic history… | | Deletes stored traffic; alerts, apps and devices are kept |

## Snapshots

**RustWarden menu > Save snapshot** saves a PNG of the current view, which is handy for bug reports.

## Uninstalling RustWarden

1. **RustWarden menu > Restore firewall defaults** to remove every rule and QoS policy.
2. If you installed them: **Settings > Other > Advanced > Remove driver…** and **Uninstall service…**.
3. **Settings > General > General**: switch off **Start RustWarden when Windows starts**.
4. **Settings > Other > Backup > Clean up** (optional, deletes downloads).
5. Exit RustWarden and delete `RustWarden.exe`. To remove all data, also delete `%APPDATA%\RustWarden`, `%LOCALAPPDATA%\RustWarden` and `C:\Program Files\RustWarden`.
