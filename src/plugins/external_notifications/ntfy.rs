//! ntfy topic URL; takes the raw text as the body and the rest as headers.

use super::{ANY, Req, Service, valid};
use crate::settings::Settings;
use egui::Ui;

pub struct Ntfy;

impl Service for Ntfy {
    fn id(&self) -> &'static str {
        "ntfy"
    }
    fn name(&self) -> &'static str {
        "ntfy"
    }
    fn configured(&self, s: &Settings) -> bool {
        !s.ntfy_url.is_empty()
    }
    fn clear(&self, s: &mut Settings) {
        s.ntfy_url.clear();
    }
    fn request(&self, s: &Settings, important: bool, title: &str, text: &str) -> Option<Req> {
        if !valid(&s.ntfy_url, ANY) {
            return None;
        }
        let (prio, tag) = if important { (4, "red_circle") } else { (3, "green_circle") };
        let title = title.replace(['\r', '\n'], " ");
        Some(Req { url: s.ntfy_url.trim().to_owned(), headers: vec![format!("Title: {title}"), format!("Priority: {prio}"), format!("Tags: {tag}")], body: text.to_owned() })
    }
    fn fields(&self, ui: &mut Ui, s: &mut Settings) {
        super::ui::field(ui, "ntfy topic URL", "https://ntfy.sh/my-topic", &mut s.ntfy_url, Some(ANY));
    }
}
