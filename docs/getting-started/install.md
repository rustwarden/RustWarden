# Installing and first run

## Download

Download `RustWarden.exe` from the [latest release on GitHub](https://github.com/rustwarden/RustWarden/releases/latest). When there are changes, a new release is built every night. Each release has a `RustWarden.exe.sha256` file beside it so you can check the download.

It is one self-contained file. There is no installer, and you don't need Rust or a Visual C++ redistributable. All it needs is Windows 10 or 11.

!!! tip "Where to put it"
    Put it somewhere permanent, such as `C:\Program Files\RustWarden\RustWarden.exe`. The Windows service, start-with-Windows and the [rescue command](../firewall/rescue.md) all point at the exe's path, so they break if you move it later.

### Checking the download (optional)

In PowerShell:

```powershell
Get-FileHash .\RustWarden.exe -Algorithm SHA256
```

Compare the result with the contents of `RustWarden.exe.sha256`.

## Running it

Double-click `RustWarden.exe`. Windows SmartScreen may warn you the first time because the exe is new; choose **More info > Run anyway**.

### Administrator rights

RustWarden works without administrator rights, but a lot of Live mode needs them:

| Needs administrator | Works without |
|---|---|
| Live traffic capture (ETW), per-app traffic and the map | Demo mode (everything) |
| Creating and removing firewall rules, all firewall modes | The network scanner |
| DNS Log, byte counts in Live Connections | Listening port, VPN DNS leak and other system monitors |
| Bandwidth limits (QoS), VPN kill switch, Driver mode | Hardware history |

Without administrator rights, RustWarden still runs and tells you what it can't do. A thin strip under the header lists the missing features, and the RustWarden menu has **Restart as administrator**.

### Run as administrator without a prompt every time

Install the **Windows service** so RustWarden can open as administrator without a UAC prompt each time:

- Use the **Install service** button in the header, or
- go to **Settings > Other > Advanced > Windows service > Install service…**

Installing or removing the service asks for administrator approval once, then restarts RustWarden.

### Start with Windows

Go to **Settings > General > General** and switch on **Start RustWarden when Windows starts**. A second switch, **Start hidden in the tray**, keeps the window closed at startup (on by default when you first enable it). These switches take effect straight away; you don't need to press Save.

## The first-run wizard

On a new install, RustWarden opens a short setup wizard. **Skip setup** always works, and you can change everything later in Settings.

1. **Live or Demo.** Live measures this PC. Demo shows made-up data and changes nothing, which is good for exploring. See [Live and Demo mode](concepts.md#live-and-demo-mode).
2. **Firewall mode.** Choose how RustWarden treats programs (see [Firewall modes](../firewall/index.md#firewall-modes)):
    - **Manual Blocking:** everything is allowed until you block it. The safest place to start.
    - **Prompt:** you are asked the first time a program tries to connect.
    - **Block All:** almost nothing gets online.

    The mode is only applied, and confirmed, when you finish the wizard.
3. **Alerts.** A pointer to **Settings > Alerts**. A new install starts with every desktop alert popup **off** so you aren't flooded with them; turn on the ones you care about. See [Alerts](../alerts/index.md).
4. **Databases.** Choose the features you want (country flags and the map, city-level map positions, company / AS names) and RustWarden offers to download the matching free databases from db-ip.com. Nothing is downloaded until you confirm. See [Countries and lookups](../protection/countries.md).

!!! note
    On the Dev update channel, **Settings > Other > Updates > Run wizard** opens the wizard again.

## Building from source

```powershell
git clone https://github.com/rustwarden/RustWarden.git
cd RustWarden
cargo build --release
```

You need Windows 10/11 and a recent Rust toolchain (edition 2024). The exe is written to `target\release\RustWarden.exe`.

## Next steps

- Read [Key ideas](concepts.md) for the few ideas the rest of the guide relies on.
- Take a [tour of the window](interface.md).
- Choose a [firewall mode](../firewall/index.md).
