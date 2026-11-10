//! Prometheus metrics: this plugin holds the port. With the `metrics.serve` permission RustWarden itself
//! serves the metrics (programs, traffic, blocked connections, alerts) on 127.0.0.1 at that port for as long
//! as the plugin runs; nothing leaves this computer.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, UiTree};

struct Prometheus;

const DEFAULT_PORT: u16 = 9877;

/// A port above 1023 (RustWarden refuses lower ones), else the default.
fn port() -> u16 {
    guest::config_get("port").parse().ok().filter(|p| *p >= 1024).unwrap_or(DEFAULT_PORT)
}

fn page() -> UiTree {
    let p = port();
    UiTree::Column(vec![
        UiTree::Label("Serves Prometheus text metrics for programs on this computer only (127.0.0.1), while this plugin is switched on.".into()),
        UiTree::Row(vec![UiTree::Label("Port".into()), UiTree::Number { id: "port".into(), value: f64::from(p), min: 1024.0, max: 65535.0 }]),
        UiTree::Weak(format!("http://127.0.0.1:{p}/metrics. A new port applies when you press Save.")),
    ])
}

impl Guest for Prometheus {
    fn manifest() -> Manifest {
        Manifest {
            id: "prometheus".into(),
            name: "Prometheus Metrics".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            settings_page: true,
            permissions: vec!["metrics.serve".into()],
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderSettings => Reply::Ui(page()),
            Call::Event(Event::Number { id, value }) if id == "port" => {
                guest::config_set("port", &(value.round() as u32).clamp(1024, 65535).to_string());
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Prometheus);

#[cfg(test)]
mod tests {
    #[test]
    fn default_port_is_unprivileged() {
        assert!(super::DEFAULT_PORT >= 1024);
    }
}
