//! VirusTotal: checks each program that uses the network by file hash. This plugin holds the API key (as a
//! secret) and the auto-scan switch. With the `programs.hash` permission, RustWarden itself does the work the
//! plugin cannot: it hashes the programs, asks VirusTotal for each hash (only the SHA-256 is sent), shows the
//! verdict in the Firewall column, and uploads a file only after the user confirms that one file.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, UiTree};

struct VirusTotal;

fn auto() -> bool {
    guest::config_get("auto") == "1"
}

/// A key is a plain token: letters and digits only (RustWarden refuses anything else before using it).
fn key_ok(key: &str) -> bool {
    key.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn page() -> UiTree {
    let key = guest::secret_get("key");
    let mut rows = vec![
        UiTree::Label("Checks each program that uses the network against VirusTotal. Only the SHA-256 of each file is sent. A file is uploaded (up to 32 MB) only when you choose \"Upload to VirusTotal…\" for that program and confirm it.".into()),
        UiTree::Link { text: "Get a free API key".into(), url: "https://www.virustotal.com/gui/my-apikey".into() },
        UiTree::Label("API key".into()),
        UiTree::Password { id: "key".into(), value: key.clone() },
    ];
    if !key.is_empty() && !key_ok(&key) {
        rows.push(UiTree::Label("⚠ A key is letters and digits only; this one will not be used.".into()));
    }
    rows.push(UiTree::Switch { id: "auto".into(), text: "Scan new programs automatically".into(), on: auto() });
    rows.push(UiTree::Weak(
        if key.is_empty() { "Enter a key to turn on the VirusTotal column on the Firewall tab." } else { "The free key allows 4 lookups a minute, so a long list takes a while." }.into(),
    ));
    UiTree::Column(rows)
}

impl Guest for VirusTotal {
    fn manifest() -> Manifest {
        Manifest {
            id: "virustotal".into(),
            name: "VirusTotal".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            settings_page: true,
            http_hosts: vec!["www.virustotal.com".into()],
            permissions: vec!["programs.hash".into()],
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderSettings => Reply::Ui(page()),
            Call::Event(Event::Text { id, value }) if id == "key" => {
                guest::secret_set("key", value.trim());
                Reply::Done
            }
            Call::Event(Event::Bool { id, on }) if id == "auto" => {
                guest::config_set("auto", if on { "1" } else { "0" });
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(VirusTotal);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_tokens_are_keys() {
        assert!(key_ok("abcDEF0123"));
        assert!(!key_ok("ab\"cd"));
        assert!(!key_ok("ab cd"));
        assert!(key_ok(""));
    }
}
