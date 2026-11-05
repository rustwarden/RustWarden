//! Discord webhook (embed, red for important alerts, green for the rest).

use super::{GREEN, RED, Req, Service, esc, json, valid};
use crate::settings::Settings;
use egui::Ui;

const HOSTS: &[&str] = &["https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/"];

pub struct Discord;

impl Service for Discord {
    fn id(&self) -> &'static str {
        "discord"
    }
    fn name(&self) -> &'static str {
        "Discord"
    }
    fn configured(&self, s: &Settings) -> bool {
        !s.discord_webhook.is_empty()
    }
    fn clear(&self, s: &mut Settings) {
        s.discord_webhook.clear();
    }
    fn request(&self, s: &Settings, important: bool, title: &str, text: &str) -> Option<Req> {
        if !valid(&s.discord_webhook, HOSTS) {
            return None;
        }
        // Discord rejects an embed with a title over 256 or a description over 4096 characters.
        let cut = |s: &str, n: usize| s.chars().take(n).collect::<String>();
        let (t, x) = (esc(&cut(title, 240)), esc(&cut(text, 4000)));
        let (color, icon) = if important { (RED, "🔴") } else { (GREEN, "🟢") };
        Some(Req { url: s.discord_webhook.trim().to_owned(), headers: json(""), body: format!(r#"{{"embeds":[{{"title":"{icon} **{t}**","description":"{x}","color":{color}}}]}}"#) })
    }
    fn fields(&self, ui: &mut Ui, s: &mut Settings) {
        super::ui::field(ui, "Discord webhook", "https://discord.com/api/webhooks/...", &mut s.discord_webhook, Some(HOSTS));
    }
}
