# Plugins

**Settings > Plugins**

Every integration in RustWarden is a **plugin**: Home Assistant, Speedtest, Ping Monitor, VirusTotal, the notification services and more. Built-in plugins ship inside `RustWarden.exe`. You can also add **third-party** plugins: `.wasm` files that run in a sandbox.

The page has two sections:

- **System Plugins**: Home Assistant, Ping Monitor, Speedtest, VirusTotal, Prometheus Metrics, UPnP Port Forwarding, Cloudflare Tunnel, Shodan InternetDB, AbuseIPDB, and any third-party plugins.
- **Notification Plugins**: Discord, Slack / Mattermost / Rocket.Chat, Pushbullet, ntfy, Gotify and a generic webhook. See [Notifications](notifications.md).

Use the **search** box to find a plugin.

## Using a plugin

- **The switch** turns a plugin on or off. A plugin that's switched off never runs.
- **Settings** opens the plugin's own settings page. You can open it before pressing Save.
- Press **Save** at the bottom of Settings to keep changes. **Cancel** puts the switches back.

Many plugins add a sub-tab under **Network** (Ping Monitor, Speedtest, Port Forwarding, Cloudflare Tunnel, Shodan, AbuseIPDB).

See [Built-in plugins](built-in.md) for what each one does.

## Uninstalling and reinstalling built-in plugins

**Uninstall** hides a built-in plugin and switches it off. A line at the bottom of the page shows how many built-in plugins are uninstalled, with a **Reinstall default plugins…** button. It opens a dialog where you tick which ones to bring back.

## Third-party plugins

A third-party plugin is one `.wasm` file. RustWarden runs it in a **sandbox**:

- It has **no file or network access of its own**. It can only call the functions RustWarden gives it.
- Out of the box it can only add **tabs** and a **settings page**.
- It can only contact the websites its manifest lists. The approval dialog shows them.
- It can only use its **own** database tables.
- Each call has a fixed instruction budget, so a plugin that loops forever is stopped. Memory is capped at 64 MB.

Anything more is an **opt-in permission** that you tick when you approve it, like phone app permissions:

| Permission | Lets the plugin |
|---|---|
| Read your alerts | Receive alerts and send them on to the sites it may contact |
| Raise alerts of its own | Raise alerts that are shown, logged and sent on like RustWarden's |
| Send pings | Ping addresses you enter |
| Serve metrics | Serve RustWarden's metrics on 127.0.0.1 at a port you set |
| Find your router (UPnP) | Discover the router and open or close ports on it |
| See program hashes | See the file hash and name of programs that use the network |
| Download a helper program | Download a program (checked against a SHA-256 it declares) and run it |
| Read blocked addresses | Read RustWarden's list of blocked addresses |
| Annotate devices | Read the scanned devices and add names or badges to them |

A permission this version of RustWarden doesn't recognise is shown as unknown and grants nothing.

### Installing one

1. **Settings > Plugins > Install from file…** and choose the `.wasm` file. It's copied into `C:\Program Files\RustWarden\plugins`, which needs administrator rights, because only administrators can write there.
2. The plugin shows as **Third-party plugin: needs your approval**. Press **Review…**.
3. Check what it can contact, its **file fingerprint (SHA-256)**, and the permissions it asks for. Tick the ones you allow.
4. **Approve and turn on**, then **Save**.

Each file is approved **once**. If the file changes (a new build), RustWarden says **The file changed: approve it again**. Unapproved or switched-off plugins never run.

### Removing one

**Remove** deletes the file. Tick **Remove Plugin Data** to also delete its settings, saved secrets and stored data. This needs administrator rights.

### Where plugin data lives

- Settings: `%APPDATA%\RustWarden\plugins`, one folder per plugin.
- Secrets: encrypted with Windows DPAPI for your account, like every other token.
- Data: in RustWarden's database, in tables that only the plugin can use.

## Writing your own

**Create a Plugin** opens the step-by-step walkthrough on GitHub: [CREATING_A_PLUGIN.md](https://github.com/rustwarden/RustWarden/blob/main/plugin-sdk/CREATING_A_PLUGIN.md). The full reference is [PLUGINS.md](https://github.com/rustwarden/RustWarden/blob/main/PLUGINS.md), and [`plugins/example-hello`](https://github.com/rustwarden/RustWarden/tree/main/plugins/example-hello) is a 50-line starting point.
