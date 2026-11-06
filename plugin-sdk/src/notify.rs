//! A notification service as a plugin: describe the service with [`Service`] and `export!` it. This
//! module supplies the settings page, the test button and the delivery of every alert.

use crate::guest::{self, Guest};
use crate::{API_VERSION, Call, Event, Kind, Manifest, Reply, UiTree};
use serde_json::json;

pub const RED: u32 = 0xE74C3C;
pub const GREEN: u32 = 0x2ECC71;

/// What to post: sent as an HTTP POST with `headers` and `body`.
pub struct Req {
    pub url: String,
    pub headers: Vec<String>,
    pub body: String,
}

/// One value the user types on the plugin's settings page. All are kept as secrets (webhook addresses carry keys).
pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub hint: &'static str,
    /// Allowed URL starts (see [`valid`]); `None` for a field that isn't a URL.
    pub prefixes: Option<&'static [&'static str]>,
}

pub trait Service {
    /// The plugin id: lowercase letters, digits and dashes.
    const ID: &'static str;
    const NAME: &'static str;
    /// The manifest's `http_hosts`.
    const HOSTS: &'static [&'static str];
    const FIELDS: &'static [Field];
    /// The request for one alert, or `None` while the service isn't set up. `get` reads a field's value.
    fn request(get: &dyn Fn(&str) -> String, important: bool, title: &str, text: &str) -> Option<Req>;
}

/// A URL the service would take: a prefix match, or any http(s) address when `prefixes` is empty.
/// Either way it can't be `file://` and the like.
pub fn valid(url: &str, prefixes: &[&str]) -> bool {
    let url = url.trim();
    if prefixes.is_empty() { url.starts_with("https://") || url.starts_with("http://") } else { prefixes.iter().any(|p| url.starts_with(p)) }
}

/// Content-Type JSON plus, when given, one more header.
pub fn json_headers(extra: &str) -> Vec<String> {
    ["Content-Type: application/json", extra].into_iter().filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

pub fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn send<S: Service>(important: bool, title: &str, text: &str) -> Result<(), String> {
    let req = S::request(&guest::secret_get, important, title, text).ok_or("not set up yet")?;
    guest::http_request(&req.url, &req.headers, Some(&req.body)).map(|_| ())
}

fn page<S: Service>() -> UiTree {
    let mut rows = vec![UiTree::Weak(format!("Posts RustWarden's alerts to {}. Red alerts are sent red and the rest green where the service supports colours.", S::NAME))];
    for f in S::FIELDS {
        let value = guest::secret_get(f.key);
        rows.push(UiTree::Label(f.label.into()));
        rows.push(UiTree::Password { id: f.key.into(), value: value.clone() });
        if let Some(p) = f.prefixes
            && !value.is_empty()
            && !valid(&value, p)
        {
            rows.push(UiTree::Label("⚠ This isn't a valid URL for this service.".into()));
        } else if value.is_empty() && !f.hint.is_empty() {
            rows.push(UiTree::Weak(format!("For example {}", f.hint)));
        }
    }
    rows.push(UiTree::Button { id: "test".into(), text: "Send test alert".into() });
    let status = guest::config_get("status");
    if !status.is_empty() {
        rows.push(UiTree::Weak(status));
    }
    UiTree::Column(rows)
}

impl<S: Service> Guest for S {
    fn manifest() -> Manifest {
        Manifest {
            id: S::ID.into(),
            name: S::NAME.into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::Notification,
            settings_page: true,
            http_hosts: S::HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            permissions: vec!["alerts.read".into()],
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderSettings => Reply::Ui(page::<S>()),
            Call::Event(Event::Text { id, value }) if S::FIELDS.iter().any(|f| f.key == id) => {
                guest::secret_set(&id, value.trim());
                Reply::Done
            }
            Call::Event(Event::Click { id }) if id == "test" => {
                let status = match send::<S>(false, "RustWarden test", "This is a test alert from RustWarden.") {
                    Ok(()) => "Test alert sent.".to_owned(),
                    Err(e) => format!("Couldn't send: {e}"),
                };
                guest::config_set("status", &status);
                Reply::Done
            }
            // A dead service must not hold anything up: failures are only logged.
            Call::Alert { important, title, text } => {
                if let Err(e) = send::<S>(important, &title, &text)
                    && e != "not set up yet"
                {
                    guest::log(&format!("couldn't post an alert: {e}"));
                }
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

// ---- the six services ----

pub struct Discord;
impl Service for Discord {
    const ID: &'static str = "discord";
    const NAME: &'static str = "Discord";
    const HOSTS: &'static [&'static str] = &["discord.com", "discordapp.com"];
    const FIELDS: &'static [Field] = &[Field { key: "webhook", label: "Discord webhook", hint: "https://discord.com/api/webhooks/...", prefixes: Some(DISCORD_URLS) }];
    fn request(get: &dyn Fn(&str) -> String, important: bool, title: &str, text: &str) -> Option<Req> {
        let url = get("webhook");
        if !valid(&url, DISCORD_URLS) {
            return None;
        }
        // Discord rejects an embed with a title over 256 or a description over 4096 characters.
        let (color, icon) = if important { (RED, "🔴") } else { (GREEN, "🟢") };
        let body = json!({"embeds": [{"title": format!("{icon} **{}**", cut(title, 240)), "description": cut(text, 4000), "color": color}]});
        Some(Req { url: url.trim().to_owned(), headers: json_headers(""), body: body.to_string() })
    }
}
const DISCORD_URLS: &[&str] = &["https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/"];

/// Slack; Mattermost and Rocket.Chat take the same payload, so their URLs work too.
pub struct Slack;
impl Service for Slack {
    const ID: &'static str = "slack";
    const NAME: &'static str = "Slack / Mattermost / Rocket.Chat";
    const HOSTS: &'static [&'static str] = &["*"];
    const FIELDS: &'static [Field] = &[Field { key: "webhook", label: "Slack webhook (also Mattermost, Rocket.Chat)", hint: "https://hooks.slack.com/services/...", prefixes: Some(&[]) }];
    fn request(get: &dyn Fn(&str) -> String, important: bool, title: &str, text: &str) -> Option<Req> {
        let url = get("webhook");
        let color = format!("#{:06X}", if important { RED } else { GREEN });
        valid(&url, &[]).then(|| Req { url: url.trim().to_owned(), headers: json_headers(""), body: json!({"attachments": [{"color": color, "title": title, "text": text}]}).to_string() })
    }
}

pub struct Pushbullet;
impl Service for Pushbullet {
    const ID: &'static str = "pushbullet";
    const NAME: &'static str = "Pushbullet";
    const HOSTS: &'static [&'static str] = &["api.pushbullet.com"];
    const FIELDS: &'static [Field] = &[Field { key: "token", label: "Pushbullet access token", hint: "o.xxxxxxxx", prefixes: None }];
    fn request(get: &dyn Fn(&str) -> String, _important: bool, title: &str, text: &str) -> Option<Req> {
        let token = get("token");
        (!token.is_empty()).then(|| Req {
            url: "https://api.pushbullet.com/v2/pushes".into(),
            headers: json_headers(&format!("Access-Token: {token}")),
            body: json!({"type": "note", "title": title, "body": text}).to_string(),
        })
    }
}

/// An ntfy topic URL; the text goes in raw and the rest in headers.
pub struct Ntfy;
impl Service for Ntfy {
    const ID: &'static str = "ntfy";
    const NAME: &'static str = "ntfy";
    const HOSTS: &'static [&'static str] = &["*"];
    const FIELDS: &'static [Field] = &[Field { key: "url", label: "ntfy topic URL", hint: "https://ntfy.sh/my-topic", prefixes: Some(&[]) }];
    fn request(get: &dyn Fn(&str) -> String, important: bool, title: &str, text: &str) -> Option<Req> {
        let url = get("url");
        if !valid(&url, &[]) {
            return None;
        }
        let (prio, tag) = if important { (4, "red_circle") } else { (3, "green_circle") };
        let title = title.replace(['\r', '\n'], " ");
        Some(Req { url: url.trim().to_owned(), headers: vec![format!("Title: {title}"), format!("Priority: {prio}"), format!("Tags: {tag}")], body: text.to_owned() })
    }
}

pub struct Gotify;
impl Service for Gotify {
    const ID: &'static str = "gotify";
    const NAME: &'static str = "Gotify";
    const HOSTS: &'static [&'static str] = &["*"];
    const FIELDS: &'static [Field] = &[
        Field { key: "url", label: "Gotify server URL", hint: "https://gotify.example.com", prefixes: Some(&[]) },
        Field { key: "token", label: "Gotify application token", hint: "", prefixes: None },
    ];
    fn request(get: &dyn Fn(&str) -> String, important: bool, title: &str, text: &str) -> Option<Req> {
        let (url, token) = (get("url"), get("token"));
        (valid(&url, &[]) && !token.is_empty()).then(|| Req {
            url: format!("{}/message", url.trim().trim_end_matches('/')),
            headers: json_headers(&format!("X-Gotify-Key: {token}")),
            body: json!({"title": title, "message": text, "priority": if important { 8 } else { 4 }}).to_string(),
        })
    }
}

/// A generic JSON webhook: `level`, `title`, `text`.
pub struct Webhook;
impl Service for Webhook {
    const ID: &'static str = "webhook";
    const NAME: &'static str = "Generic webhook";
    const HOSTS: &'static [&'static str] = &["*"];
    const FIELDS: &'static [Field] = &[Field { key: "url", label: "Generic webhook (JSON: level, title, text)", hint: "https://example.com/hook", prefixes: Some(&[]) }];
    fn request(get: &dyn Fn(&str) -> String, important: bool, title: &str, text: &str) -> Option<Req> {
        let url = get("url");
        valid(&url, &[]).then(|| Req {
            url: url.trim().to_owned(),
            headers: json_headers(""),
            body: json!({"level": if important { "important" } else { "log" }, "title": title, "text": text}).to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> String + 'a {
        move |k| pairs.iter().find(|(a, _)| *a == k).map(|(_, v)| (*v).to_owned()).unwrap_or_default()
    }

    #[test]
    fn nothing_is_posted_until_a_service_is_set_up() {
        let none = with(&[]);
        assert!(Discord::request(&none, true, "t", "d").is_none());
        assert!(Slack::request(&none, true, "t", "d").is_none());
        assert!(Pushbullet::request(&none, true, "t", "d").is_none());
        assert!(Ntfy::request(&none, true, "t", "d").is_none());
        assert!(Gotify::request(&none, true, "t", "d").is_none());
        assert!(Webhook::request(&none, true, "t", "d").is_none());
    }

    #[test]
    fn requests_follow_configuration() {
        let d = Discord::request(&with(&[("webhook", "https://discord.com/api/webhooks/1/x")]), true, "A\"B", "x\\y\nz").unwrap();
        // Quotes, backslashes and newlines are escaped, and important alerts are red.
        assert!(d.body.contains(r#"A\"B"#) && d.body.contains(r"x\\y\nz") && d.body.contains(&RED.to_string()));
        // Slack takes any http(s) address but never file://.
        assert!(Slack::request(&with(&[("webhook", "file:///c:/x")]), true, "t", "d").is_none());
        let s = Slack::request(&with(&[("webhook", "https://hooks.slack.com/services/x")]), false, "t", "d").unwrap();
        assert!(s.body.contains("#2ECC71"));
        // Discord takes only its own hosts.
        assert!(Discord::request(&with(&[("webhook", "https://example.com/x")]), true, "t", "d").is_none());
        let g = Gotify::request(&with(&[("url", "http://h:80/"), ("token", "k")]), true, "t", "d").unwrap();
        assert_eq!(g.url, "http://h:80/message");
        assert!(g.headers.contains(&"X-Gotify-Key: k".to_owned()) && g.body.contains(r#""priority":8"#));
        assert!(Gotify::request(&with(&[("url", "http://h:80/")]), true, "t", "d").is_none(), "needs the token too");
        let n = Ntfy::request(&with(&[("url", "https://ntfy.sh/mine")]), true, "two\nlines", "body").unwrap();
        assert_eq!((n.body.as_str(), n.headers[0].as_str()), ("body", "Title: two lines"));
        let p = Pushbullet::request(&with(&[("token", "tok")]), false, "t", "d").unwrap();
        assert_eq!(p.url, "https://api.pushbullet.com/v2/pushes");
        let w = Webhook::request(&with(&[("url", "https://example.com/h")]), false, "t", "d").unwrap();
        assert!(w.body.contains(r#""level":"log""#));
    }

    #[test]
    fn long_discord_text_is_cut() {
        let long = "x".repeat(5000);
        let d = Discord::request(&with(&[("webhook", "https://discord.com/api/webhooks/1/x")]), false, &long, &long).unwrap();
        assert!(d.body.len() < 4400);
    }
}
