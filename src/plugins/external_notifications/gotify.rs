//! Gotify server (URL plus application token).

use super::{ANY, Req, Service, esc, json, valid};
use crate::settings::Settings;
use egui::Ui;

pub struct Gotify;

impl Service for Gotify {
    fn id(&self) -> &'static str {
        "gotify"
    }
    fn name(&self) -> &'static str {
        "Gotify"
    }
    fn configured(&self, s: &Settings) -> bool {
        !s.gotify_url.is_empty() || !s.gotify_token.is_empty()
    }
    fn clear(&self, s: &mut Settings) {
        s.gotify_url.clear();
        s.gotify_token.clear();
    }
    fn request(&self, s: &Settings, important: bool, title: &str, text: &str) -> Option<Req> {
        let (t, x) = (esc(title), esc(text));
        (valid(&s.gotify_url, ANY) && !s.gotify_token.is_empty()).then(|| Req {
            url: format!("{}/message", s.gotify_url.trim().trim_end_matches('/')),
            headers: json(&format!("X-Gotify-Key: {}", s.gotify_token)),
            body: format!(r#"{{"title":"{t}","message":"{x}","priority":{}}}"#, if important { 8 } else { 4 }),
        })
    }
    fn fields(&self, ui: &mut Ui, s: &mut Settings) {
        super::ui::field(ui, "Gotify server URL", "https://gotify.example.com", &mut s.gotify_url, Some(ANY));
        super::ui::field(ui, "Gotify application token", "", &mut s.gotify_token, None);
    }
}
