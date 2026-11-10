//! A tab with a greeting and a click counter, and a settings page to change the greeting. Copy this
//! folder to start your own plugin; see PLUGINS.md.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, TabDef, UiTree};

struct Hello;

fn greeting() -> String {
    let g = guest::config_get("greeting");
    if g.is_empty() { "Hello from a plugin!".to_owned() } else { g }
}

fn clicks() -> u32 {
    guest::config_get("clicks").parse().unwrap_or(0)
}

impl Guest for Hello {
    fn manifest() -> Manifest {
        Manifest {
            id: "example-hello".into(),
            name: "Example: Hello".into(),
            version: "0.1.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "hello".into(), title: "Hello".into() }],
            settings_page: true,
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => {
                Reply::Ui(UiTree::Column(vec![UiTree::Heading(greeting()), UiTree::Weak(format!("Clicked {} times", clicks())), UiTree::Button { id: "click".into(), text: "Click me".into() }]))
            }
            Call::RenderSettings => Reply::Ui(UiTree::Column(vec![UiTree::Label("Greeting".into()), UiTree::TextField { id: "greeting".into(), value: greeting() }])),
            Call::Event(Event::Click { id }) if id == "click" => {
                guest::config_set("clicks", &(clicks() + 1).to_string());
                Reply::Done
            }
            Call::Event(Event::Text { id, value }) if id == "greeting" => {
                guest::config_set("greeting", &value);
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Hello);
