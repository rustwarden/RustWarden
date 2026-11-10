//! thinkbroadband sits behind a Cloudflare browser check that `curl` can't pass, so the site is
//! reached through a real browser engine (WebView2) in a helper process: this same exe started
//! with `--tbb-browser`. Its profile folder keeps the sign-in between runs.
//!
//! `--tbb-browser login`          shows a window until the user is signed in (exit 0).
//! `--tbb-browser fetch <dir> <url>...`  hidden; fetches each URL from inside the signed-in page and
//!                                writes `<dir>/<n>.txt` as "status\nbody". Exit 0 done, 2 sign-in needed, 3 gave up.

use std::path::PathBuf;
use std::process::Command;
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use wry::{PageLoadEvent, WebContext, WebViewBuilder};

pub const HOST: &str = "https://www.thinkbroadband.com";
const LOGIN: &str = "/my-profile/login";
const START: &str = "/my-profile/broadband-quality-monitor";
const GIVE_UP_SECS: u64 = 90;

/// An address on the site itself: `starts_with(HOST)` alone would accept `https://www.thinkbroadband.com.evil.example`.
pub fn on_site(url: &str) -> bool {
    url.strip_prefix(HOST).is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
}

/// True while a helper is showing Cloudflare's "extra check" for the user to clear.
pub static CHECK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How long the user gets to clear the extra check before the helper gives up.
const CHECK_SECS: u64 = 240;

/// Tells the caller the user has to sign in again.
pub const NEED_LOGIN: &str = "Sign in to thinkbroadband again.";

/// Forgets the saved sign-in by deleting the helper's browser profile.
pub fn sign_out() -> std::io::Result<()> {
    match std::fs::remove_dir_all(profile_dir()) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub(crate) fn profile_dir() -> PathBuf {
    let dir = crate::settings::data_dir().join("thinkbroadband-webview");
    // Earlier versions put it one `RustWarden` folder too deep; move it up so the saved sign-in is kept.
    let old = crate::settings::data_dir().join("RustWarden").join("thinkbroadband-webview");
    if !dir.exists() && old.is_dir() && std::fs::rename(&old, &dir).is_ok() {
        let _ = std::fs::remove_dir(old.parent().unwrap_or(&old));
    }
    dir
}

/// Helper-side: the window is up for an extra check.
static SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

enum Ev {
    Loaded(String),
    Msg(String),
    GiveUp,
}

/// Helper-process entry point (`args` are those after `--tbb-browser`); returns the exit code.
pub fn run(args: &[String]) -> i32 {
    let login = args.first().map(String::as_str) == Some("login");
    let (out, urls): (PathBuf, Vec<String>) = if login {
        (PathBuf::new(), Vec::new())
    } else {
        let out = args.get(1).map(PathBuf::from).unwrap_or_default();
        // Addresses come in the `urls.txt` beside the answers, or (an older caller) as arguments.
        let listed = std::fs::read_to_string(out.join("urls.txt")).unwrap_or_default();
        (out, if args.len() > 2 { args.iter().skip(2).cloned().collect() } else { listed.lines().map(str::to_owned).collect() })
    };
    let js_urls = urls.iter().filter(|u| on_site(u)).map(|u| format!("\"{}\"", u.replace(['\\', '"'], ""))).collect::<Vec<_>>().join(",");

    let event_loop = EventLoopBuilder::<Ev>::with_user_event().build();
    let window = match WindowBuilder::new().with_title("ThinkBroadband Quality Monitor sign in").with_inner_size(LogicalSize::new(560.0, 760.0)).with_visible(login).build(&event_loop) {
        Ok(w) => w,
        Err(_) => return 3,
    };
    let (p1, p2) = (event_loop.create_proxy(), event_loop.create_proxy());
    let mut ctx = WebContext::new(Some(profile_dir()));
    let start = if login { format!("{HOST}{LOGIN}") } else { format!("{HOST}{START}") };
    let webview = match WebViewBuilder::new_with_web_context(&mut ctx)
        .with_url(start)
        .with_on_page_load_handler(move |e, url| {
            if matches!(e, PageLoadEvent::Finished) {
                let _ = p1.send_event(Ev::Loaded(url));
            }
        })
        .with_ipc_handler(move |r| {
            let _ = p2.send_event(Ev::Msg(r.into_body()));
        })
        .build(&window)
    {
        Ok(w) => w,
        Err(_) => return 3,
    };
    if !login {
        let proxy = event_loop.create_proxy();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(GIVE_UP_SECS));
            if SHOWN.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(CHECK_SECS));
            }
            let _ = proxy.send_event(Ev::GiveUp);
        });
    }

    let js = format!(
        "(async()=>{{if(/Checking your browser|Just a moment/i.test(document.title)||document.querySelector('#challenge-running,#challenge-stage,.cf-turnstile,#challenge-form')){{window.ipc.postMessage('WAIT');return}}\
         const u=[{js_urls}];for(let i=0;i<u.length;i++){{let s=0,t='';try{{if(u[i]===location.href){{s=200;t=document.documentElement.outerHTML}}else{{const r=await fetch(u[i],{{credentials:'include'}});s=r.status;t=await r.text()}}}}catch(e){{t=String(e)}}window.ipc.postMessage(i+'\\n'+s+'\\n'+t)}}\
         window.ipc.postMessage('DONE')}})()"
    );
    let mut started = false;
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        let _keep = (&webview, &ctx);
        let mark = |on: bool| {
            if login {
                return;
            }
            SHOWN.store(on, std::sync::atomic::Ordering::Relaxed);
            window.set_visible(on);
            if on {
                window.set_title("thinkbroadband: complete the extra check");
                window.set_focus();
                let _ = std::fs::write(out.join("check"), "");
            } else {
                let _ = std::fs::remove_file(out.join("check"));
            }
        };
        match event {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => std::process::exit(if login { 1 } else { 3 }),
            Event::UserEvent(Ev::GiveUp) => std::process::exit(4),
            Event::UserEvent(Ev::Loaded(url)) => {
                let path = url.strip_prefix(HOST).unwrap_or("");
                if path.starts_with(LOGIN) {
                    // Not signed in: the login helper waits for the user, the fetch helper tells the caller.
                    if !login {
                        std::process::exit(2);
                    }
                } else if path.starts_with("/my-profile") {
                    if login {
                        std::process::exit(0);
                    }
                    if !started {
                        started = true;
                        mark(false);
                        let _ = webview.evaluate_script(&js);
                    }
                }
            }
            Event::UserEvent(Ev::Msg(m)) => match m.as_str() {
                "WAIT" => {
                    started = false;
                    mark(true);
                } // still on the Cloudflare check; the redirect loads the page again
                "DONE" => std::process::exit(0),
                _ => {
                    let mut p = m.splitn(2, '\n');
                    if let (Some(i), Some(rest)) = (p.next().and_then(|i| i.parse::<usize>().ok()), p.next()) {
                        let _ = std::fs::write(out.join(format!("{i}.txt")), rest);
                    }
                }
            },
            _ => {}
        }
    })
}

/// Opens the sign-in window and waits for it; `Err` when it was closed without signing in.
pub fn sign_in() -> Result<(), String> {
    let status = wait(helper(&["login"])).map_err(|e| format!("Can't open the sign-in window: {e}"))?;
    if status.success() { Ok(()) } else { Err("The sign-in window was closed before signing in.".into()) }
}

/// Fetches each URL as the signed-in user: (HTTP status, body) per URL, in order.
pub fn fetch(urls: &[String]) -> Result<Vec<(u16, String)>, String> {
    // One folder per call: the poll, a day backfill and an import can overlap.
    static RUN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let run = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // The helper runs with the user's normal rights and writes its answers here, so this is the user's own temp folder; what it
    // wrote is read as untrusted text (it is web content anyway).
    let dir = std::env::temp_dir().join(format!("rustwarden-tbb-{}-{run}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // The addresses go in a file: a program started with the user's rights may have a command line of 1024 characters at most.
    if urls.iter().any(|u| u.chars().any(char::is_control)) {
        return Err("an address has a control character in it".into());
    }
    std::fs::write(dir.join("urls.txt"), urls.join("\n")).map_err(|e| e.to_string())?;
    let args = ["fetch".to_owned(), dir.to_string_lossy().into_owned()];
    let status = wait_watching(helper(&args.iter().map(String::as_str).collect::<Vec<_>>()), &dir.join("check")).map_err(|e| format!("Can't start the browser helper: {e}"));
    let result = status.and_then(|s| match s.code() {
        Some(0) => Ok(()),
        Some(2) => Err(NEED_LOGIN.to_owned()),
        // A slow answer (or Cloudflare's check) is not a sign-out: the next poll tries again.
        Some(4) => Err("thinkbroadband was too slow to answer (or the extra check wasn't completed); trying again later.".to_owned()),
        c => Err(format!("The browser helper failed ({c:?}). WebView2 may be missing.")),
    });
    let out = result.and_then(|()| {
        (0..urls.len())
            .map(|i| {
                let text = std::fs::read_to_string(dir.join(format!("{i}.txt"))).map_err(|_| "thinkbroadband didn't answer.".to_owned())?;
                let (s, body) = text.split_once('\n').unwrap_or(("0", ""));
                Ok((s.parse().unwrap_or(0), body.to_owned()))
            })
            .collect()
    });
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// Starts the helper and waits for it; its traffic is filed under RustWarden like the other helpers.
fn wait(cmd: Command) -> std::io::Result<std::process::ExitStatus> {
    crate::sys::etw::spawn_user(&cmd, crate::sys::proc::Pipes::NONE, true)?.wait()
}

/// Like `wait`, but raises `CHECK` while the helper's `check` file exists (its window is up for the extra check).
fn wait_watching(cmd: Command, marker: &std::path::Path) -> std::io::Result<std::process::ExitStatus> {
    let mut child = crate::sys::etw::spawn_user(&cmd, crate::sys::proc::Pipes::NONE, true)?;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        CHECK.store(marker.exists(), std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(300));
    };
    CHECK.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(status)
}

fn helper(args: &[&str]) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap_or_default());
    cmd.arg("--tbb-browser").args(args);
    cmd
}
