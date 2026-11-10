# Creating a RustWarden plugin

This guide takes you from an empty folder to a working plugin in RustWarden, using the **plugin SDK** in this folder (the `plugin-sdk` crate). For the full list of calls, widgets and permissions, see the reference in [PLUGINS.md](../PLUGINS.md).

## What a plugin is

A plugin is a single `.wasm` file written in Rust. RustWarden runs it in a sandbox (wasmtime):

- It has **no file, network or system access of its own.** Everything goes through functions RustWarden provides (`plugin_sdk::guest`), and RustWarden checks each call.
- It **never draws pixels.** It describes its page as a tree of widgets (`UiTree`) and RustWarden draws it, so plugins always match the app's look, in light and dark themes.
- It is **event driven.** RustWarden calls your plugin when something happens (a tab is shown, a button is clicked, a timer fires) and your plugin answers.

Out of the box a plugin can add **tabs** (under Network) and a **settings page**. Anything more, such as reading alerts or pinging hosts, is an **opt-in permission** the user approves when installing it.

## 1. Set up

You need Rust (stable) and the WebAssembly target:

```
rustup target add wasm32-wasip1
```

## 2. Create the crate

The quickest start is to copy [plugins/example-hello](../plugins/example-hello) (about 50 lines: a tab, a button and a settings page). To start from scratch instead:

```
cargo new --lib my-plugin
```

Then make `Cargo.toml` a `cdylib` that depends on the SDK:

```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
# Inside the RustWarden repo:
plugin-sdk = { path = "../../plugin-sdk" }
# Anywhere else:
# plugin-sdk = { git = "https://github.com/rustwarden/RustWarden" }
```

## 3. Write the plugin

A plugin is a type that implements `Guest`, with two functions:

- `manifest()` says who the plugin is and what it needs.
- `handle(call)` answers each call RustWarden makes.

Then `plugin_sdk::export!` it once. Here is a complete plugin with a tab, a counter button and a setting:

```rust
use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, TabDef, UiTree};

struct Counter;

fn count() -> u32 {
    guest::config_get("count").parse().unwrap_or(0)
}

impl Guest for Counter {
    fn manifest() -> Manifest {
        Manifest {
            id: "counter".into(),              // lowercase letters, digits and dashes
            name: "Counter".into(),            // shown in Settings > Plugins
            version: "0.1.0".into(),
            author: "you".into(),
            api_version: API_VERSION,          // always this constant
            kind: Kind::System,                // or Kind::Notification
            tabs: vec![TabDef { id: "main".into(), title: "Counter".into() }],
            settings_page: true,
            ..Manifest::default()              // keeps you compatible when fields are added
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            // The tab is on screen: describe it.
            Call::RenderTab { .. } => Reply::Ui(UiTree::Card {
                title: "Counter".into(),
                rows: vec![
                    UiTree::Heading(format!("{} clicks", count())),
                    UiTree::Button { id: "add".into(), text: "Add one".into() },
                ],
            }),
            // The Settings button in Settings > Plugins.
            Call::RenderSettings => Reply::Ui(UiTree::Setting {
                title: "Reset".into(),
                sub: "Start counting from zero".into(),
                control: Box::new(UiTree::Button { id: "reset".into(), text: "Reset".into() }),
            }),
            // The user did something. Change your state and answer Done; the page is drawn again.
            Call::Event(Event::Click { id }) if id == "add" => {
                guest::config_set("count", &(count() + 1).to_string());
                Reply::Done
            }
            Call::Event(Event::Click { id }) if id == "reset" => {
                guest::config_set("count", "0");
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Counter);
```

### How the conversation works

| RustWarden calls | You answer |
|---|---|
| `Call::RenderTab { tab }` | `Reply::Ui(tree)` for that tab (`tab` is your `TabDef.id`) |
| `Call::RenderSettings` | `Reply::Ui(tree)` for the settings window |
| `Call::Event(event)` | update your state, then `Reply::Done` |
| `Call::Tick` | do background work, then `Reply::Done` |
| anything else | `Reply::Done` |

Return `Reply::Err(message)` when something fails; RustWarden shows the message.

Every control in a `UiTree` has an `id`, and the matching `Event` carries it back:

| Widget | Event |
|---|---|
| `Button { id, text }` | `Event::Click { id }` |
| `TextField` / `Password { id, value }` | `Event::Text { id, value }` |
| `Switch { id, text, on }` | `Event::Bool { id, on }` |
| `Dropdown { id, options, selected }` | `Event::Index { id, index }` |
| `Number { id, value, min, max }` | `Event::Number { id, value }` |
| `FileButton { id, text, accept }` | `Event::File { id, name, content, error }` |

Lay pages out with `Card { title, rows }` and `Setting { title, sub, control }` (the Windows 11 Settings look), or with `Row`, `Column` and `Grid`. Text comes from `Heading`, `Label`, `Weak` and `Info`, plus `Link` and `Image` (PNG bytes). Wrap any widget in `Disabled(Box::new(..))` to grey it out.

## 4. Keep state

Ordinary Rust statics (a `thread_local!` or `static Mutex`) last while the plugin runs, but they're lost on restart, on switching it off or on an update. Keep anything that should survive in RustWarden:

- **Settings:** `guest::config_get(key)` and `guest::config_set(key, value)`. Plain strings, saved per plugin.
- **Secrets** (API keys, tokens, webhook URLs): `guest::secret_get` and `guest::secret_set`. These are encrypted for the user's Windows account (DPAPI). Show them in a `Password` widget.
- **History:** SQLite through `guest::db_exec(sql)` and `guest::db_query(sql)` (rows come back as a JSON array of arrays). Your tables must be named `p_<id>__<name>`, with dashes in the id written as underscores (`my-plugin` becomes `p_my_plugin__samples`). Put the `CREATE TABLE IF NOT EXISTS ...` statements in `Manifest.schema`, and they run every time the plugin starts.

## 5. Talk to the network (optional)

List every host you call in the manifest, then use `guest::http_request`:

```rust
http_hosts: vec!["api.example.com".into()],
```

```rust
// GET (no body) or POST (with a body). Errors are "HTTP <status>" or what went wrong.
let json = guest::http_request("https://api.example.com/status", &["Accept: application/json".into()], None)?;
```

A host that isn't listed is refused. Use `"*"` only when the user types the address, such as a self-hosted server; the approval dialog warns about it. `http_raw` returns any status code (a 404 is an answer, not an error). PLUGINS.md covers cookies, self-signed certificates and pinned CAs.

RustWarden is local-first, so a plugin should do nothing on the network until the user has set it up and switched it on.

## 6. Run in the background (optional)

Set `tick_secs` in the manifest to get a `Call::Tick` every N seconds (0 means never). Call `guest::set_tick(ms)` for a faster rhythm while something animates, and `guest::set_tick(0)` to go back to `tick_secs`.

Each call has a fixed instruction budget, and memory is capped at 64 MB. A plugin that loops forever is stopped, so split long work across ticks.

## 7. Ask for permissions (optional)

Anything beyond tabs, settings, storage and your own HTTP hosts needs a permission. List it in `Manifest.permissions`, and the user ticks each one when approving the plugin:

```rust
permissions: vec!["alerts.read".into()],
```

With `alerts.read` you receive `Call::Alert { important, title, text }` for every alert. The full table (ping, UPnP, devices, blocked addresses, helper programs and more) is in [PLUGINS.md](../PLUGINS.md#what-you-may-ask-rustwarden-for). Ask only for what you use, because users see the list.

## 8. Build

```
cargo build --release --target wasm32-wasip1
```

Your plugin is `target/wasm32-wasip1/release/my_plugin.wasm` (dashes in the crate name become underscores).

## 9. Install and test

1. In RustWarden, open **Settings > Plugins** and press **Install from file…**. Pick your `.wasm` file. It is copied to `Program Files\RustWarden\plugins`, which needs administrator rights.
2. Your plugin appears with **Third-party plugin: needs your approval**. Press **Review…**, tick the permissions, then **Approve**.
3. Switch it on and press **Save**. Its tab appears under **Network**, and **Settings** opens its settings page.

RustWarden approves the exact file. After every rebuild, install the new file again and approve it again; until then it doesn't run.

**Demo mode** is a safe place to try your pages without touching live data. `guest::is_demo()` tells you when you are in it, so you can show sample data there.

## Debugging

- `guest::log("message")` writes a line to `%LOCALAPPDATA%\RustWarden\plugins.log`, prefixed with your plugin id.
- `guest::notify_in_app("message")` shows a short notice in RustWarden's window.
- If the file fails to load, Settings > Plugins shows the reason under the System Plugins list.
- Keep logic that doesn't touch `guest` in plain functions, so you can unit test it with `cargo test` on your own machine.

## Notification plugins

A chat or push service (like Discord, ntfy or Gotify) needs no `Guest` code at all. Implement `plugin_sdk::notify::Service`, giving the id, name, hosts, the fields the user fills in and how to build the request for one alert. Then `export!` it, and the SDK supplies the settings page, the test button and alert delivery:

```rust
use plugin_sdk::notify::{Field, Req, Service, json_headers};

pub struct MyChat;

impl Service for MyChat {
    const ID: &'static str = "mychat";
    const NAME: &'static str = "MyChat";
    const HOSTS: &'static [&'static str] = &["hooks.mychat.example"];
    const FIELDS: &'static [Field] = &[Field { key: "url", label: "Webhook URL", hint: "https://hooks.mychat.example/...", prefixes: Some(&["https://hooks.mychat.example/"]) }];

    fn request(get: &dyn Fn(&str) -> String, important: bool, title: &str, text: &str) -> Option<Req> {
        let url = get("url");
        if url.is_empty() {
            return None; // not set up yet
        }
        let body = serde_json::json!({ "text": format!("{}{title}: {text}", if important { "⚠ " } else { "" }) }).to_string();
        Some(Req { url, headers: json_headers(""), body })
    }
}

plugin_sdk::export!(MyChat);
```

(Add `serde_json` to your dependencies for the `json!` macro.) The six bundled services in [plugins/](../plugins) and [src/notify.rs](src/notify.rs) are good examples.

## Checklist before you share it

- [ ] `id` is lowercase letters, digits and single dashes, at most 40 characters, and won't clash with another plugin.
- [ ] `api_version: API_VERSION`, and the manifest ends with `..Manifest::default()`.
- [ ] Every host you call is in `http_hosts`, and nothing goes out until the user has set the plugin up.
- [ ] Keys and tokens use `secret_set`, not `config_set`.
- [ ] Tables are named `p_<id>__*` and created in `Manifest.schema`.
- [ ] Only the permissions you use are listed.
- [ ] Pages make sense in Demo mode.
