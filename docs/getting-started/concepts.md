# Key ideas

The rest of the guide relies on a few ideas. Each one is explained once here.

## Live and Demo mode

| | Live mode | Demo mode |
|---|---|---|
| Data | Real traffic, connections, devices and hardware from this PC | Made-up sample data |
| Firewall | Creates and removes real Windows Firewall rules | Simulated; nothing is changed |
| Downloads | Only the ones you switch on | None (threat lists, VirusTotal and similar stay offline) |
| Header | Normal | A **DEMO** tag next to the logo |

Switch between them in **Settings > Other > General > Use demo data**. Every feature works in both modes, so you can try something in Demo mode before you use it for real.

## Normal and Driver mode

RustWarden works in two **app modes** (**Settings > Other > Advanced > App mode**):

- **Normal mode** (the default) needs **no driver**. Everything is done with what Windows already has: the Windows Firewall, Windows QoS policies and Windows' own event tracing (ETW).
- **Driver mode** adds features that need to see individual packets. They use [WinDivert](https://github.com/basil00/WinDivert), an open-source driver with a Microsoft-accepted signature. It is downloaded only when you ask, from the official GitHub release, and checked against a pinned SHA-256.

Features that need the driver stay **hidden** unless Driver mode is on **and** the driver is installed, so if you never turn on Driver mode you never see them. All of them are described on the [Driver mode](../driver-mode.md) page and marked with *(Driver mode)* elsewhere in the guide.

## Administrator rights

Reading traffic per program, changing the firewall and setting QoS policies all need administrator rights. Without them RustWarden still runs and shows what it can't do. See [Administrator rights](install.md#administrator-rights) for the full list, and install the [Windows service](install.md#run-as-administrator-without-a-prompt-every-time) to skip the UAC prompt.

## RustWarden's own rules

Every firewall rule RustWarden creates goes in the Windows Firewall group **"RustWarden"** and is named after the program. Every QoS policy is named `RustWarden QoS <id> <program>`. Because of this:

- RustWarden only changes **its own** rules. Rules made by Windows, other firewall apps or by hand are left alone, unless you [import them](../firewall/index.md#importing-rules-from-another-firewall-app).
- **Restore firewall defaults** (RustWarden menu, or **Settings > Firewall > Advanced**) removes all of RustWarden's rules in one go.
- If you can't open the app, the [rescue command](../firewall/rescue.md) does the same from a terminal.
- RustWarden checks its rules each time it starts and [alerts you](../alerts/alert-types.md#firewall-rule-monitor) if something outside RustWarden changed them.

## Local first

RustWarden doesn't go online unless you've switched on a feature that needs to. Each such feature is **off by default** and says what it sends and where. Examples:

- Country, city and AS databases are downloaded only when you press **Download**.
- Malicious IP and domain lists are downloaded only once you turn them on.
- VirusTotal sends only a file's SHA-256 hash, and uploads a file only after you confirm.
- Notification plugins send only the alerts you route to them.
- The Prometheus endpoint listens on `127.0.0.1` only.

Tokens, API keys, webhook addresses and the tamper-protection password are encrypted with **Windows DPAPI** for your Windows account.

## Where RustWarden keeps things

| Folder | What is in it |
|---|---|
| `%APPDATA%\RustWarden` | `config.toml` (your settings), plugin settings under `plugins\` |
| `%LOCALAPPDATA%\RustWarden` | The history database, icon cache, downloaded databases and lists, logs (`rustwarden.log`, `lists.log`, `rescue.log`, `engine.log`), packet captures |
| `C:\Program Files\RustWarden` | Third-party plugins (`plugins\`), the WinDivert driver (`driver\`), `speedtest-cli` when run as administrator. Only administrators can write here. |

## Programs, services and the kernel

- **Programs** are identified by their full executable path.
- **Windows services** that share `svchost.exe` are shown as separate entries, for example "Windows Update (wuauserv)", so you can see and block them one by one where Windows allows it.
- **"NT Kernel & System"** covers all networking done inside Windows itself. RustWarden splits it by service (SMB file sharing, NetBIOS, device discovery, HTTP.sys listeners and "Other"), told apart by port. See [Kernel & System split](../traffic.md#kernel-system-split).
