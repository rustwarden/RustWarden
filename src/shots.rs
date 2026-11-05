//! README screenshots. `RUSTYWIRE_SHOTS=<folder>` starts RustWarden in Demo mode, walks through the screens
//! below, saves each as a PNG in that folder and exits (non-zero if a PNG could not be written).
//! `.github/workflows/screenshots.yml` runs it on a Windows runner and commits the result.

use crate::app::{RustWarden, Tab};
use crate::data::Threat;
use egui::{ViewportCommand, ViewportId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Frames to let a screen lay out and load before it is captured (the app repaints every frame while a window is open).
const SETTLE: u32 = 90;

/// Which window a screen is captured from.
#[derive(Clone, Copy)]
enum Window {
    Main,
    /// The Prompt prompt most recently added.
    Ask,
    /// The Malicious IP banner most recently added.
    Threat,
}

type Setup = fn(&mut RustWarden);

/// Each screen: its file name, what to put on screen, and the window to capture.
const SCREENS: &[(&str, Setup, Window)] = &[
    ("traffic", |_| {}, Window::Main),
    ("traffic-map", |app| app.traffic.view = 1, Window::Main),
    ("protect", |app| app.tab = Tab::Protect, Window::Main),
    ("log", |app| app.tab = Tab::Log, Window::Main),
    ("network-scanner", |app| app.tab = Tab::Scanner, Window::Main),
    ("hardware", |app| app.tab = Tab::Hardware, Window::Main),
    ("live-connections", |app| app.tab = Tab::Connections, Window::Main),
    ("dns-log", |app| app.tab = Tab::Dns, Window::Main),
    ("speedtest", |app| app.tab = Tab::Speedtest, Window::Main),
    ("ping", |app| app.tab = Tab::Ping, Window::Main),
    (
        "ask-to-connect",
        |app| {
            app.popup_seq += 1;
            app.asks.push((app.popup_seq, crate::data::ConnectAsk::demo()));
        },
        Window::Ask,
    ),
    (
        "malicious-ip",
        |app| {
            app.popup_seq += 1;
            app.threats.push((app.popup_seq, Threat::test(), None));
        },
        Window::Threat,
    ),
];

pub struct Shots {
    dir: PathBuf,
    /// Index into `SCREENS` of the screen being shown.
    at: usize,
    /// Frames shown so far on the current screen.
    frame: u32,
    /// Captures requested but not yet written.
    pending: Arc<AtomicUsize>,
    /// Captures that failed to write, with the reason.
    failed: Arc<Mutex<Vec<String>>>,
}

/// The settings a screenshot run starts from: Demo mode, dark theme, with the optional Ping and Speedtest tabs on (the user's own settings are not used).
pub fn settings() -> crate::settings::Settings {
    let mut s = crate::settings::Settings::default();
    s.mode = crate::settings::Mode::Demo;
    s.follow_windows_theme = false;
    s.theme = crate::settings::Theme::Dark;
    s.ping.show_tab = true;
    // Four charts in the grid layout and the 24 hour range; Demo mode draws made-up rounds for them, so the addresses are only labels.
    for (name, host) in [("Cloudflare", "1.1.1.1"), ("Google DNS", "8.8.8.8"), ("Quad9", "9.9.9.9"), ("Home router", "192.168.1.1")] {
        s.ping.add(name, host);
    }
    (s.ping.layout, s.ping.range) = (2, 1);
    s.speedtest.show_tab = true;
    s
}

/// The folder named by `RUSTYWIRE_SHOTS`, when this run is a screenshot run.
pub fn folder() -> Option<PathBuf> {
    std::env::var_os("RUSTYWIRE_SHOTS").map(PathBuf::from)
}

impl Shots {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, at: 0, frame: 0, pending: Arc::default(), failed: Arc::default() }
    }

    /// Called once per frame: sets up the current screen, requests its capture after it settles, and quits when all are written.
    pub fn step(&mut self, app: &mut RustWarden, ctx: &egui::Context) {
        let Some(&(name, setup, window)) = SCREENS.get(self.at) else {
            if self.pending.load(Ordering::SeqCst) == 0 {
                let failed = self.failed.lock().unwrap_or_else(|e| e.into_inner());
                for reason in failed.iter() {
                    eprintln!("screenshot failed: {reason}");
                }
                std::process::exit(i32::from(!failed.is_empty()));
            }
            return;
        };
        // The app only repaints on events, and a screen needs a steady run of frames to settle.
        ctx.request_repaint();
        if self.frame == 0 {
            app.asks.clear();
            app.threats.clear();
            app.popups.clear();
            app.popup_info = None;
            app.ask_info = None;
            app.dialog = None;
            setup(app);
        }
        self.frame += 1;
        if self.frame == SETTLE {
            self.capture(app, ctx, name, window);
        }
        if self.frame > SETTLE {
            self.at += 1;
            self.frame = 0;
        }
    }

    fn capture(&self, app: &RustWarden, ctx: &egui::Context, name: &str, window: Window) {
        let viewport = match window {
            Window::Main => ViewportId::ROOT,
            Window::Ask => app.asks.last().map_or(ViewportId::ROOT, |(id, _)| ViewportId::from_hash_of(("ask", *id))),
            Window::Threat => app.threats.last().map_or(ViewportId::ROOT, |(id, _, _)| ViewportId::from_hash_of(("threat", *id))),
        };
        let path = self.dir.join(format!("{name}.png"));
        let pending = self.pending.clone();
        let failed = self.failed.clone();
        pending.fetch_add(1, Ordering::SeqCst);
        let repaint = ctx.clone();
        let callback = egui::ScreenshotCallback::new(move |image| {
            if let Err(e) = crate::snapshot::save(&image, path.clone()) {
                failed.lock().unwrap_or_else(|e| e.into_inner()).push(format!("{}: {e}", path.display()));
            }
            pending.fetch_sub(1, Ordering::SeqCst);
            repaint.request_repaint();
        });
        ctx.send_viewport_cmd_to(viewport, ViewportCommand::Screenshot(callback));
    }
}
