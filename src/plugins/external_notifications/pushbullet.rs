//! Pushbullet push (access token only).

use super::{Req, Service, esc, json};
use crate::settings::Settings;
use egui::Ui;

pub struct Pushbullet;

impl Service for Pushbullet {
    fn id(&self) -> &'static str {
        "pushbullet"
    }
    fn name(&self) -> &'static str {
        "Pushbullet"
    }
    fn configured(&self, s: &Settings) -> bool {
        !s.pushbullet_token.is_empty()
    }
    fn clear(&self, s: &mut Settings) {
        s.pushbullet_token.clear();
    }
    fn request(&self, s: &Settings, _important: bool, title: &str, text: &str) -> Option<Req> {
        let (t, x) = (esc(title), esc(text));
        (!s.pushbullet_token.is_empty()).then(|| Req {
            url: "https://api.pushbullet.com/v2/pushes".into(),
            headers: json(&format!("Access-Token: {}", s.pushbullet_token)),
            body: format!(r#"{{"type":"note","title":"{t}","body":"{x}"}}"#),
        })
    }
    fn fields(&self, ui: &mut Ui, s: &mut Settings) {
        super::ui::field(ui, "Pushbullet access token", "o.xxxxxxxx", &mut s.pushbullet_token, None);
    }
}
