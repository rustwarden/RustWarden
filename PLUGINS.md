# Writing a RustWarden plugin

A plugin is one `.wasm` file. RustWarden runs it in a sandbox: it has no file or network access of its own and can only call the functions RustWarden gives it. Out of the box a plugin can add **tabs** and a **settings page**; anything more is an **opt-in permission** the user ticks when approving it.

Start from [plugins/example-hello](plugins/example-hello) (about 60 lines). Your own private plugin can live anywhere; it only needs the `plugin-sdk` crate.

## Build

```
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
```

The crate is a `cdylib` that depends on `plugin-sdk`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
plugin-sdk = { path = "../../plugin-sdk" }
```

## The code

Implement `Guest` and export it once:

```rust
use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Manifest, Reply, TabDef, UiTree};

struct Mine;

impl Guest for Mine {
    fn manifest() -> Manifest {
        Manifest { id: "mine".into(), name: "Mine".into(), version: "0.1.0".into(), author: "me".into(),
                   api_version: API_VERSION, tabs: vec![TabDef { id: "main".into(), title: "Mine".into() }],
                   ..Manifest::default() }
    }
    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => Reply::Ui(UiTree::Label("Hello".into())),
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Mine);
```

### Calls into your plugin

| Call | When |
|---|---|
| `RenderTab { tab }` | the tab is on screen (and after every event and tick) |
| `RenderSettings` | the plugin's Settings button |
| `Event(..)` | the user clicked, typed, switched or picked something; answer `Reply::Done`, the page is drawn again after |
| `Tick` | every `tick_secs` seconds (0 = never), for background work |
| `Alert { .. }` | an alert was raised (needs `alerts.read`). While the internet is down alerts are held (up to 50) and arrive once it is back, with "(Delayed ...)" added to the text |

Each call gets a fixed budget of instructions; a plugin that loops forever is stopped and the call fails. Memory is capped at 64 MB.

### Pages

Return a `UiTree`: `Card { title, rows }` draws a Windows 11 Settings style card, whose rows are `Setting { title, sub, control }` (title and a dim line at the left, the control at the right) or any other widget; `Disabled(widget)` greys a control out, and two whole-page widgets are drawn by RustWarden from data you send: `LatencyChart` (the Broadband Quality / Ping charts; it reads samples with the SQL you give, from your own tables, and can show a form in a window of its own and a sign-in banner) and `Speedtest` (dial, route map, history). Otherwise return: `Label`, `Heading`, `Weak`, `Button`, `TextField`, `Password`, `Switch`, `Dropdown`, `Number`, `Link` (http/https only), `FileButton` (opens the Windows file dialog; RustWarden reads the chosen text file, at most 256 KiB, and sends it as `Event::File` with its name and content, so the plugin never sees a path), `Grid`, `Row`, `Column`, `Separator`, `Image` (PNG). RustWarden draws them, so plugins always match the app's look. Every control has an `id`; you get it back in the `Event`.

### What you may ask RustWarden for

Always available (`plugin_sdk::guest`):

- `config_get` / `config_set`: your own settings
- `secret_get` / `secret_set`: like config, but stored encrypted for the user's Windows account
- `db_exec` / `db_query`: SQLite, but only tables named `p_<id>__*` (your id with dashes as underscores, then two underscores). Put the `CREATE TABLE IF NOT EXISTS` statements in `Manifest.schema`; they run when the plugin starts.
- `http_request`: only to the hosts in `Manifest.http_hosts`. `"*"` means any http(s) host, for plugins that post to an address the user types; the approval dialog says so.
- `now`, `log`, `notify_in_app`
- `http_raw`: like `http_request`, but any status is an answer (`(404, body)`); `http_raw_cookie` also returns the answer's first `Set-Cookie` header, for a router or server that keeps its session in a cookie. `insecure: true` accepts a server's own certificate and needs `allow_insecure_tls: true` in the manifest, which the approval dialog shows
- `set_tick(ms)`: ask for `Call::Tick` at your own rhythm (a dial that animates), `0` to go back to the manifest's

Permissions (list them in `Manifest.permissions`; the user ticks each one):

| Permission | Lets the plugin |
|---|---|
| `alerts.read` | receive `Call::Alert` |
| `ping` | ping addresses with `ping_round` |
| `metrics.serve` | marks a plugin as the settings half of RustWarden's Prometheus endpoint: while it runs, RustWarden serves its metrics on 127.0.0.1 at the plugin's `port` setting (only the bundled Prometheus plugin uses it) |
| `upnp` | find the UPnP router with `upnp_discover()` (UDP discovery a plugin can't do itself; the answer is always a private-network address). The plugin then talks to the router over http with `http_raw` (the bundled UPnP Port Forwarding plugin) |
| `programs.hash` | marks a plugin as the settings half of RustWarden's own VirusTotal lookups (only the bundled VirusTotal plugin uses it) |
| `alerts.write` | raise a packet-loss alert with `raise_alert`, delivered like RustWarden's own (only the thinkbroadband plugin uses it today) |
| `helper.exe` | download a helper program from an address in `http_hosts` (checked against a SHA-256 you declare), run it with arguments you give, and get each line it prints as `Call::HelperLine` (`helper_ready`, `helper_install`, `helper_start`, `helper_stop`). A download whose address ends in `.exe` is the program itself instead of a zip. With a timeout of 0 the program runs until `helper_stop` or until RustWarden closes, and the lines it prints to its error output come back as `HelperLine` too (the bundled Cloudflare Tunnel plugin) |
| `browser.session` | use RustWarden's sign-in browser window and signed-in fetches for one site (only thinkbroadband today) |
| `devices.annotate` | read the scanned devices (`devices()`), and have RustWarden show what you store in `p_<id>__devices` (columns `mac`, `found`, `name`, `area`, `kind`, `model`, `url`) on the Scanner tab |

Any other permission name in a manifest is shown to the user as unknown and grants nothing.

## Rules your plugin must follow

- `id`: lowercase letters, digits and single dashes, at most 40 characters. It becomes your file name, your config file and your table prefix.
- Bump `api_version` handling only through `plugin_sdk::API_VERSION`; a plugin built for another version is refused.
- The user approves the exact file. A rebuilt file asks again.

## Install

Settings > Plugins > Install from file… copies the file into `Program Files\RustWarden\plugins` (administrator rights needed), where only administrators can write. Then press Review…, tick any permissions you allow, Approve, and Save.

## Notification services

A chat or push service is even shorter: describe it with `plugin_sdk::notify::Service` (the address fields, the request to post) and `export!` it. See the six bundled ones in [plugins/](plugins) and `plugin-sdk/src/notify.rs`.
