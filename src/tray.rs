//! System tray icon.
//!
//! Icon clicks arrive on the tray's own callback; they are forwarded over a channel
//! and wake the UI, which handles them in `RustWarden::poll_tray`.

use std::sync::mpsc::{Receiver, channel};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

pub enum TrayCmd {
    Toggle,
    /// Right click: the cursor in physical pixels, where the styled menu opens.
    Menu(f32, f32),
}

pub struct Tray {
    icon: TrayIcon,
    badged: bool,
    pub rx: Receiver<TrayCmd>,
}

/// The tray icon at the size Windows will actually show it (16 px at 100% scaling), so we do the
/// downscale ourselves with a proper filter instead of leaving it to the shell, plus an optional red unread dot.
fn icon(badge: bool) -> Icon {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSMICON};
    let size = (unsafe { GetSystemMetrics(SM_CXSMICON) }).clamp(16, 64) as u32;
    let (rgba, w, h) = crate::util::small_icon_rgba();
    let mut small = crate::util::downscale_rgba(&rgba, w, h, size);
    if badge {
        crate::util::paint_dot(&mut small, size, [0xe5, 0x39, 0x35]);
    }
    Icon::from_rgba(small, size, size).expect("icon RGBA buffer")
}

impl Tray {
    pub fn new(ctx: &egui::Context) -> Result<Self, String> {
        let (tx, rx) = channel();
        let ctx2 = ctx.clone();
        // No native menu: Windows can't style one, so right click opens our own popup (`ui::tray_menu`).
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            if let TrayIconEvent::Click { button, button_state: MouseButtonState::Up, position, .. } = e {
                match button {
                    MouseButton::Left => _ = tx.send(TrayCmd::Toggle),
                    MouseButton::Right => _ = tx.send(TrayCmd::Menu(position.x as f32, position.y as f32)),
                    _ => return,
                }
                // A minimised window runs no ui pass, only `App::logic`; ask for one so the click is handled now.
                ctx2.send_viewport_cmd(egui::ViewportCommand::RequestPaintWhileHidden);
                ctx2.request_repaint();
            }
        }));

        let tray = TrayIconBuilder::new().with_tooltip("RustWarden").with_icon(icon(false)).build().map_err(|e| e.to_string())?;
        Ok(Self { icon: tray, badged: false, rx })
    }

    /// Shows or hides the red "something to look at" dot on the tray icon.
    pub fn set_badge(&mut self, on: bool) {
        if on != self.badged {
            self.badged = on;
            let _ = self.icon.set_icon(Some(icon(on)));
        }
    }
}
