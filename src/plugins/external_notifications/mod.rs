//! External Notifications: posts alerts to the web services set up on Settings > Integrations >
//! External Notifications (Discord, Slack, Pushbullet, ntfy, Gotify, or any JSON webhook), using
//! `curl.exe` like the other web lookups.

mod discord;
mod gotify;
mod ntfy;
mod pushbullet;
mod slack;
pub mod ui;
mod webhook;

use crate::settings::Settings;
use egui::Ui;

const RED: u32 = 0xE74C3C;
const GREEN: u32 = 0x2ECC71;

pub struct Req {
    pub url: String,
    pub headers: Vec<String>,
    pub body: String,
}

/// One notification service. To add one, write its file like the others and list it in `SERVICES`;
/// it then appears in the add menu of Settings > Integrations > External Notifications.
pub trait Service: Sync {
    /// Stable key saved in the settings file once the service is added.
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    /// True when any of its fields is filled in.
    fn configured(&self, s: &Settings) -> bool;
    /// Empties its fields (Remove).
    fn clear(&self, s: &mut Settings);
    /// The message to post, or `None` while the service isn't usable.
    fn request(&self, s: &Settings, important: bool, title: &str, text: &str) -> Option<Req>;
    fn fields(&self, ui: &mut Ui, s: &mut Settings);
}

/// Order here is the order of the table and of the posts.
pub const SERVICES: &[&dyn Service] = &[&discord::Discord, &slack::Slack, &pushbullet::Pushbullet, &webhook::Webhook, &ntfy::Ntfy, &gotify::Gotify];

/// Shown once added, and always while any field is filled in (settings saved before the page had an add menu).
pub fn present(s: &Settings, v: &dyn Service) -> bool {
    s.notify_added.iter().any(|i| i == v.id()) || v.configured(s)
}

/// Discord and Slack accept only their own hosts; the self-hosted kinds accept any http(s) URL.
/// Either way curl can't be pointed at file:// and the like.
pub fn valid(url: &str, prefixes: &[&str]) -> bool {
    if prefixes.is_empty() { url.starts_with("https://") || url.starts_with("http://") } else { prefixes.iter().any(|p| url.starts_with(p)) }
}

/// No host restriction: any http(s) URL.
pub const ANY: &[&str] = &[];

use crate::sys::curl::quote;
use crate::util::json_escape as esc;

fn json(h: &str) -> Vec<String> {
    vec!["Content-Type: application/json".to_owned(), h.to_owned()].into_iter().filter(|s| !s.is_empty()).collect()
}

fn requests(s: &Settings, important: bool, title: &str, text: &str) -> Vec<Req> {
    SERVICES.iter().filter_map(|v| v.request(s, important, title, text)).collect()
}

/// The whole request as a curl config, so tokens and webhook URLs go in on stdin and never show in the process list.
fn config(r: &Req) -> String {
    let mut c = format!("url = {}\ndata-raw = {}\n", quote(&r.url), quote(&r.body));
    for h in &r.headers {
        c += &format!("header = {}\n", quote(h));
    }
    c
}

/// Sends to every configured service on background threads; failures are dropped, as a dead
/// service must not hold up alerts.
pub fn send_all(s: &Settings, important: bool, title: &str, text: &str) {
    for r in requests(s, important, title, text) {
        std::thread::spawn(move || {
            let _ = crate::sys::curl::run(&format!("silent\nmax-time = 10\n{}", config(&r)), None);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_follow_configuration() {
        let mut s = Settings::default();
        assert!(requests(&s, true, "t", "d").is_empty());
        s.discord_webhook = "https://discord.com/api/webhooks/1/x".into();
        s.slack_webhook = "file:///c:/x".into();
        s.pushbullet_token = "tok".into();
        s.ntfy_url = "https://ntfy.sh/mine".into();
        s.gotify_url = "http://h:80/".into();
        s.gotify_token = "k".into();
        s.generic_webhook = "https://example.com/h".into();
        let r = requests(&s, true, "A\"B", "x\\y\nz");
        assert_eq!(r.len(), 5); // slack rejected
        assert!(r[0].body.contains(r#"A\"B"#) && r[0].body.contains(r"x\\y\nz") && r[0].body.contains(&RED.to_string()));
        assert_eq!(r[4].url, "http://h:80/message");
        s.slack_webhook = "https://hooks.slack.com/services/x".into();
        assert!(requests(&s, false, "t", "d").iter().any(|r| r.body.contains("#2ECC71")));
    }

    #[test]
    fn config_quotes_every_value() {
        let r = Req { url: "https://h/x".into(), headers: vec!["X-Key: a\"b".into()], body: r#"{"m":"x\\y\nz"}"#.into() };
        assert_eq!(config(&r), "url = \"https://h/x\"\ndata-raw = \"{\\\"m\\\":\\\"x\\\\\\\\y\\\\nz\\\"}\"\nheader = \"X-Key: a\\\"b\"\n");
    }
}
