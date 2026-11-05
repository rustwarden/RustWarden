//! Slack webhook; Mattermost and Rocket.Chat take the same payload, so their URLs work too.

use super::{ANY, GREEN, RED, Req, Service, esc, json, valid};
use crate::settings::Settings;
use egui::Ui;

pub struct Slack;

impl Service for Slack {
    fn id(&self) -> &'static str {
        "slack"
    }
    fn name(&self) -> &'static str {
        "Slack / Mattermost / Rocket.Chat"
    }
    fn configured(&self, s: &Settings) -> bool {
        !s.slack_webhook.is_empty()
    }
    fn clear(&self, s: &mut Settings) {
        s.slack_webhook.clear();
    }
    fn request(&self, s: &Settings, important: bool, title: &str, text: &str) -> Option<Req> {
        let (t, x) = (esc(title), esc(text));
        let color = if important { RED } else { GREEN };
        valid(&s.slack_webhook, ANY).then(|| Req {
            url: s.slack_webhook.trim().to_owned(),
            headers: json(""),
            body: format!(r##"{{"attachments":[{{"color":"#{color:06X}","title":"{t}","text":"{x}"}}]}}"##),
        })
    }
    fn fields(&self, ui: &mut Ui, s: &mut Settings) {
        super::ui::field(ui, "Slack webhook (also Mattermost, Rocket.Chat)", "https://hooks.slack.com/services/...", &mut s.slack_webhook, Some(ANY));
    }
}
