//! Generic JSON webhook: `level`, `title`, `text`.

use super::{ANY, Req, Service, esc, json, valid};
use crate::settings::Settings;
use egui::Ui;

pub struct Webhook;

impl Service for Webhook {
    fn id(&self) -> &'static str {
        "webhook"
    }
    fn name(&self) -> &'static str {
        "Generic webhook"
    }
    fn configured(&self, s: &Settings) -> bool {
        !s.generic_webhook.is_empty()
    }
    fn clear(&self, s: &mut Settings) {
        s.generic_webhook.clear();
    }
    fn request(&self, s: &Settings, important: bool, title: &str, text: &str) -> Option<Req> {
        let (t, x) = (esc(title), esc(text));
        valid(&s.generic_webhook, ANY).then(|| Req {
            url: s.generic_webhook.trim().to_owned(),
            headers: json(""),
            body: format!(r#"{{"level":"{}","title":"{t}","text":"{x}"}}"#, if important { "important" } else { "log" }),
        })
    }
    fn fields(&self, ui: &mut Ui, s: &mut Settings) {
        super::ui::field(ui, "Generic webhook (JSON: level, title, text)", "https://example.com/hook", &mut s.generic_webhook, Some(ANY));
    }
}
