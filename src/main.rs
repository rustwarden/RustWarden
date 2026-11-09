//! RustWarden: a Windows network monitor and firewall front-end.
//!
//! Two modes share one UI through the `data::Backend` trait: Demo (`demo::MockBackend`,
//! placeholder data) and Live (`live::LiveBackend`, measurements of this machine).

// A GUI app: without this Windows gives the exe a console window of its own.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod alertrules;
mod app;
mod applog;
mod cleanup;
mod clock;
mod countries;
mod data;
mod demo;
mod destrules;
mod domainblock;
mod driver;
mod export;
mod flag_data;
mod geo;
mod icons;
mod live;
mod metrics;
mod migrate;
mod netparse;
mod netpkt;
mod netwatch;
mod pcap;
mod plugins;
mod qos;
mod report;
mod rescue;
mod rules_file;
mod scandetect;
mod settings;
mod shots;
mod snapshot;
mod sys;
mod tamper;
mod theme;
mod tlsprint;
mod traffic_load;
mod tray;
mod ui;
mod update;
mod util;
mod verify_log;
mod widgets;

/// The window rectangle saved by the last run as (position, size) in points, when enough of it is still on a screen to be reachable.
fn saved_window() -> Option<([f32; 2], [f32; 2])> {
    use windows::Win32::UI::HiDpi::GetDpiForSystem;
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN};
    let [x, y, w, h] = settings::Settings::load().window?;
    // SAFETY: plain metric queries.
    let (vx, vy, vw, vh) = unsafe { (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN), GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN)) };
    if w < 300 || h < 300 || x + 200 > vx + vw || y + 100 > vy + vh || x + w < vx + 200 || y < vy {
        return None;
    }
    // SAFETY: plain query.
    let scale = unsafe { GetDpiForSystem() }.max(96) as f32 / 96.0;
    Some(([x as f32 / scale, y as f32 / scale], [w as f32 / scale, h as f32 / scale]))
}

fn main() -> eframe::Result {
    // Before any file is touched: an elevated run must not follow a junction a non-administrator made (see sys::redirection_guard).
    sys::redirection_guard();
    // A screenshot run (shots.rs) is a plain start: no elevation, service hand-off or single-instance check.
    let shots = shots::folder();
    match std::env::args().nth(1).as_deref() {
        Some("--service") => {
            let _ = sys::autostart::run_dispatcher();
            return Ok(());
        }
        // Re-runs of this exe, elevated by Settings > Install/Remove service; the exit code is the result.
        Some("--install-service") => std::process::exit(i32::from(sys::autostart::install_elevated().is_err())),
        Some("--uninstall-service") => std::process::exit(i32::from(sys::autostart::uninstall_elevated().is_err())),
        // Rescue for a scheduled task: removes every RustWarden firewall rule, with no window (see rescue.rs).
        Some("--remove-all-rules") => std::process::exit(rescue::run()),
        // Checks the alert log's hash chain from a terminal (see verify_log.rs).
        Some("--verify-alert-log") => std::process::exit(verify_log::run()),
        // The thinkbroadband browser helper: a small window of its own, not the app.
        Some("--tbb-browser") => std::process::exit(sys::webview::run(&std::env::args().skip(2).collect::<Vec<_>>())),
        // Started by the service (already elevated).
        Some("--elevated") => {}
        _ if shots.is_some() => {}
        // A debug build never goes through the installed service (which would open the installed exe):
        // it asks for admin itself, then clears the installed copy out of its way and says so.
        _ if cfg!(debug_assertions) => {
            if !sys::is_elevated() {
                if sys::runas_self(false).is_ok() {
                    return Ok(());
                }
            } else if let Some(msg) = sys::autostart::prepare_debug() {
                sys::message("RustWarden (debug build)", &msg);
            }
        }
        // The installed service is older than this exe: reinstall it from this one, then it opens the window.
        _ if !sys::hidden_start() && sys::autostart::refresh_stale_service() => return Ok(()),
        // Any other start: bring an already-running window forward, else let the service open the elevated one.
        // With no service installed (e.g. testing), ask for admin directly; if declined, run unelevated.
        _ if !sys::is_elevated()
            && (sys::autostart::signal_show() || sys::autostart::run_service(sys::hidden_start()) || (!sys::autostart::service_installed() && sys::restart_elevated().is_ok())) =>
        {
            return Ok(());
        }
        // Elevated by hand ("Run as administrator") while one is open: a second copy would take over its ETW session.
        _ if sys::autostart::signal_show() => return Ok(()),
        _ => {}
    }
    // Settings, history, rules and the service from before the rename to RustWarden; true: the service has opened the new window.
    if shots.is_none() && migrate::run() {
        return Ok(());
    }
    // Safeguard whichever way we got here (service, hand-elevated, `--elevated` restart): only one window per session.
    if shots.is_none() && !sys::autostart::claim_instance(std::env::args().any(|a| a == "--elevated")) {
        return Ok(());
    }
    // No console in release, so a panic would vanish: keep the last one. Elevated, it goes where only administrators can
    // write: %TEMP% belongs to the user, and a link planted there could aim an elevated write at any file.
    let panic_log = if sys::is_elevated() { settings::admin_dir().join("panic.log") } else { std::env::temp_dir().join("rustwarden-panic.log") };
    std::panic::set_hook(Box::new(move |info| {
        let _ = panic_log.parent().map(std::fs::create_dir_all);
        let _ = std::fs::write(&panic_log, format!("{info}\n{}", std::backtrace::Backtrace::force_capture()));
    }));
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("RustWarden")
        .with_icon(egui::IconData { rgba: util::app_icon_rgba().0, width: 256, height: 256 })
        .with_inner_size([1190.0, 780.0])
        .with_min_inner_size([1160.0, 640.0])
        .with_decorations(false)
        .with_transparent(true);
    // Where the last run left the window, if that is still on a screen; otherwise the middle of the screen.
    let saved = if shots.is_none() { saved_window() } else { None };
    if let Some((pos, size)) = saved {
        viewport = viewport.with_inner_size([size[0].max(1160.0), size[1].max(640.0)]).with_position(pos);
    }
    let options = eframe::NativeOptions { viewport, centered: saved.is_none(), ..Default::default() };
    eframe::run_native("RustWarden", options, Box::new(|cc| Ok(Box::new(app::RustWarden::new(cc)))))
}
