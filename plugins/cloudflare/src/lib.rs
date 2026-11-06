//! Cloudflare Tunnel: downloads Cloudflare's `cloudflared` (a pinned version, checked against its SHA-256) and
//! runs a tunnel with it, so a service on this PC can be reached from the internet without opening a port.
//!
//! Two ways in: paste the token of a tunnel made in the Cloudflare dashboard, or log in with Cloudflare here
//! (cloudflared opens the browser) and let the plugin create a tunnel and point a hostname at it.
//! The tunnel runs while RustWarden does and is stopped when it closes.

use plugin_sdk::guest::{self, Guest};
use plugin_sdk::{API_VERSION, Call, Event, Kind, Manifest, Reply, TabDef, UiTree};
use std::cell::RefCell;

struct Cloudflare;

const VERSION: &str = "2026.10.7";
const URL: &str = "https://github.com/cloudflare/cloudflared/releases/download/2026.10.7/cloudflared-windows-amd64.exe";
const SHA256: &str = "2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343";
const EXE: &str = "cloudflared.exe";
const MODES: [&str; 2] = ["Log in with Cloudflare", "Tunnel token"];
const LOG_LINES: usize = 14;

/// What the helper program is doing now.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
enum Step {
    #[default]
    Idle,
    Login,
    Create,
    Route,
    Run,
}

#[derive(Default)]
struct State {
    step: Step,
    log: Vec<String>,
    login_url: String,
    /// What the last finished step said, for the page.
    message: String,
}

thread_local! {
    static ST: RefCell<State> = RefCell::new(State::default());
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    ST.with(|s| f(&mut s.borrow_mut()))
}

// ---- pure helpers (tested below) ----

/// The first https address in a line, as cloudflared prints the sign-in address.
fn url_in(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let url: String = line[start..].chars().take_while(|c| !c.is_whitespace()).collect();
    (url.len() > 12).then_some(url)
}

/// The arguments for each step. The token is a command-line argument (cloudflared has no other way in), so it is
/// visible to administrators of this PC in the process list while the tunnel runs.
fn args_for(step: Step, name: &str, host: &str, service: &str, token: &str) -> Vec<String> {
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    match step {
        Step::Login => v(&["tunnel", "login"]),
        Step::Create => v(&["tunnel", "create", name]),
        Step::Route => v(&["tunnel", "route", "dns", name, host]),
        Step::Run if !token.is_empty() => v(&["tunnel", "--no-autoupdate", "run", "--token", token]),
        Step::Run => v(&["tunnel", "--no-autoupdate", "run", "--url", service, name]),
        Step::Idle => Vec::new(),
    }
}

/// Did a finished step do what it was for? cloudflared reports in text; its exit code isn't passed on.
fn step_succeeded(step: Step, text: &str) -> bool {
    let t = text.to_lowercase();
    match step {
        Step::Login => t.contains("cert.pem") && !t.contains("error"),
        Step::Create => t.contains("created tunnel") || t.contains("already exists"),
        Step::Route => t.contains("added cname") || t.contains("already exists") || t.contains("already configured"),
        Step::Run | Step::Idle => true,
    }
}

/// A name for the tunnel: letters, digits and dashes only.
fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// A hostname such as `home.example.com`.
fn valid_host(s: &str) -> bool {
    s.len() <= 253 && s.contains('.') && !s.starts_with(['.', '-']) && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// Where traffic is sent: an http(s) address on this PC or another one on the network.
fn valid_service(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://")) && s.len() <= 200 && !s.contains(char::is_whitespace)
}

/// A tunnel token is base64 text.
fn valid_token(s: &str) -> bool {
    s.len() >= 20 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

// ---- running steps ----

fn cfg(key: &str, default: &str) -> String {
    let v = guest::config_get(key);
    if v.is_empty() { default.to_owned() } else { v }
}

fn token_mode() -> bool {
    guest::config_get("mode") == "token"
}

fn say(msg: impl Into<String>) {
    with(|s| s.message = msg.into());
}

/// Starts one step of the helper. `timeout` is 0 for the tunnel itself, which runs until stopped.
fn begin(step: Step) {
    let token = if token_mode() { guest::secret_get("token") } else { String::new() };
    let args = args_for(step, &cfg("name", "rustwarden"), &guest::config_get("host"), &cfg("service", "http://localhost:80"), &token);
    let timeout = match step {
        Step::Run => 0,
        Step::Login => 600,
        _ => 120,
    };
    with(|s| {
        s.step = step;
        s.log.clear();
        if step == Step::Login {
            s.login_url.clear();
        }
    });
    if guest::is_demo() {
        demo_step(step);
        return;
    }
    if let Err(e) = guest::helper_start(EXE, &args, timeout) {
        with(|s| s.step = Step::Idle);
        say(format!("⚠ {e}"));
    }
}

/// Demo mode runs nothing: the tunnel just looks as if it were up.
fn demo_step(step: Step) {
    match step {
        Step::Run => with(|s| s.log = vec!["Registered tunnel connection connIndex=0 location=AMS (demo)".into()]),
        Step::Login => {
            guest::config_set("logged_in", "1");
            with(|s| s.step = Step::Idle);
        }
        _ => with(|s| s.step = Step::Idle),
    }
}

fn start() {
    if token_mode() {
        if !valid_token(&guest::secret_get("token")) {
            return say("⚠ Paste the tunnel's token first.");
        }
        return begin(Step::Run);
    }
    let (name, host, service) = (cfg("name", "rustwarden"), guest::config_get("host"), cfg("service", "http://localhost:80"));
    if !valid_name(&name) {
        return say("⚠ The tunnel name can use letters, digits and dashes.");
    }
    if !valid_host(&host) {
        return say("⚠ Enter the public hostname, a name on your Cloudflare domain such as home.example.com.");
    }
    if !valid_service(&service) {
        return say("⚠ \"Send traffic to\" must be an http:// or https:// address, such as http://localhost:80.");
    }
    say("");
    begin(Step::Create);
}

fn finished(ok: bool, message: &str) {
    let (step, log) = with(|s| (s.step, s.log.join("\n")));
    if !ok {
        with(|s| s.step = Step::Idle);
        return say(format!("⚠ {}", message.lines().next().unwrap_or("it stopped")));
    }
    let text = format!("{log}\n{message}");
    if step == Step::Run {
        with(|s| s.step = Step::Idle);
        let why = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
        return say(format!("The tunnel stopped. {why}"));
    }
    if !step_succeeded(step, &text) {
        with(|s| s.step = Step::Idle);
        let why = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("it did not finish");
        return say(format!("⚠ That step failed: {why}"));
    }
    match step {
        Step::Login => {
            guest::config_set("logged_in", "1");
            with(|s| s.step = Step::Idle);
            say("Logged in. Fill in the tunnel details and press Start.");
        }
        Step::Create => begin(Step::Route),
        Step::Route => begin(Step::Run),
        _ => with(|s| s.step = Step::Idle),
    }
}

fn install() {
    say("");
    match guest::helper_install(URL, SHA256, EXE) {
        Ok(()) => say("cloudflared is installed."),
        Err(e) => say(format!("⚠ {e}")),
    }
}

// ---- the page ----

fn page() -> UiTree {
    let (step, log, url, message) = with(|s| (s.step, s.log.clone(), s.login_url.clone(), s.message.clone()));
    let running = step == Step::Run;
    let mut rows = vec![UiTree::Weak(
        "Makes a service on this PC reachable from the internet through Cloudflare, without opening a port. You need a free Cloudflare account. The tunnel runs while RustWarden does.".into(),
    )];
    if !guest::is_demo() && !guest::helper_ready(EXE, SHA256) {
        rows.push(UiTree::Button { id: "install".into(), text: "Download cloudflared (about 55 MB)".into() });
        rows.push(UiTree::Weak(format!("From github.com/cloudflare/cloudflared, version {VERSION}. It is only kept if its SHA-256 is {SHA256}.")));
    } else {
        rows.push(UiTree::Row(vec![
            UiTree::Label("Sign in with".into()),
            UiTree::Dropdown { id: "mode".into(), options: MODES.iter().map(|m| (*m).to_owned()).collect(), selected: usize::from(token_mode()) },
        ]));
        if token_mode() {
            rows.push(UiTree::Weak("Make the tunnel and its public hostname in the Cloudflare dashboard (Zero Trust > Networks > Tunnels), then paste its token.".into()));
            rows.push(UiTree::Password { id: "token".into(), value: guest::secret_get("token") });
            rows.push(UiTree::Weak("The token is passed to cloudflared on its command line, so administrators of this PC can see it while the tunnel runs.".into()));
        } else if guest::config_get("logged_in") != "1" {
            rows.push(UiTree::Weak("Opens Cloudflare in your browser. Choose the domain the tunnel may use.".into()));
            let login = UiTree::Button { id: "login".into(), text: "Log in with Cloudflare".into() };
            rows.push(if step == Step::Idle { login } else { UiTree::Disabled(Box::new(login)) });
            if step == Step::Login {
                rows.push(UiTree::Weak("Waiting for you to finish in the browser…".into()));
            }
            if !url.is_empty() {
                rows.push(UiTree::Link { text: "Browser didn't open? Open the sign-in page".into(), url });
            }
        } else {
            rows.push(UiTree::Grid {
                columns: 2,
                children: vec![
                    UiTree::Label("Tunnel name".into()),
                    UiTree::TextField { id: "name".into(), value: cfg("name", "rustwarden") },
                    UiTree::Label("Public hostname".into()),
                    UiTree::TextField { id: "host".into(), value: guest::config_get("host") },
                    UiTree::Label("Send traffic to".into()),
                    UiTree::TextField { id: "service".into(), value: cfg("service", "http://localhost:80") },
                ],
            });
            rows.push(UiTree::Weak("The hostname must be on the domain you chose when logging in; a DNS record for it is added.".into()));
            rows.push(UiTree::Button { id: "relogin".into(), text: "Log in again".into() });
        }
        let start = UiTree::Button { id: "start".into(), text: "Start tunnel".into() };
        let stop = UiTree::Button { id: "stop".into(), text: "Stop tunnel".into() };
        rows.push(UiTree::Row(vec![if step == Step::Idle { start } else { UiTree::Disabled(Box::new(start)) }, if step == Step::Idle { UiTree::Disabled(Box::new(stop)) } else { stop }]));
        rows.push(UiTree::Label(match step {
            Step::Idle => "Stopped".to_owned(),
            Step::Login => "Logging in…".to_owned(),
            Step::Create => "Creating the tunnel…".to_owned(),
            Step::Route => "Adding the DNS record…".to_owned(),
            Step::Run => "Running".to_owned(),
        }));
    }
    if !message.is_empty() {
        rows.push(UiTree::Label(message));
    }
    if running || !log.is_empty() {
        rows.push(UiTree::Separator);
        rows.extend(log.into_iter().map(UiTree::Weak));
    }
    UiTree::Column(rows)
}

fn event(e: Event) {
    match e {
        Event::Click { id } => match id.as_str() {
            "install" => install(),
            "login" | "relogin" => {
                say("");
                begin(Step::Login);
            }
            "start" => start(),
            "stop" => {
                guest::helper_stop();
                if guest::is_demo() {
                    with(|s| {
                        s.step = Step::Idle;
                        s.log.clear();
                    });
                }
            }
            _ => {}
        },
        Event::Index { id, index } if id == "mode" => guest::config_set("mode", if index == 1 { "token" } else { "login" }),
        Event::Text { id, value } => match id.as_str() {
            "token" => guest::secret_set("token", value.trim()),
            "name" | "host" | "service" => guest::config_set(&id, value.trim()),
            _ => {}
        },
        _ => {}
    }
}

impl Guest for Cloudflare {
    fn manifest() -> Manifest {
        Manifest {
            id: "cloudflare".into(),
            name: "Cloudflare Tunnel".into(),
            version: "1.0.0".into(),
            author: "RustWarden".into(),
            api_version: API_VERSION,
            kind: Kind::System,
            tabs: vec![TabDef { id: "tunnel".into(), title: "Cloudflare Tunnel".into() }],
            http_hosts: vec!["github.com".into()],
            permissions: vec!["helper.exe".into()],
            ..Manifest::default()
        }
    }

    fn handle(call: Call) -> Reply {
        match call {
            Call::RenderTab { .. } => Reply::Ui(page()),
            Call::Event(e) => {
                event(e);
                Reply::Done
            }
            Call::HelperLine { line } => {
                with(|s| {
                    if s.step == Step::Login
                        && let Some(url) = url_in(&line)
                    {
                        s.login_url = url;
                    }
                    s.log.push(line.chars().take(200).collect());
                    if s.log.len() > LOG_LINES {
                        s.log.remove(0);
                    }
                });
                Reply::Done
            }
            Call::HelperDone { ok, message } => {
                finished(ok, &message);
                Reply::Done
            }
            _ => Reply::Done,
        }
    }
}

plugin_sdk::export!(Cloudflare);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_sign_in_address() {
        let line = "Please open the following URL and log in with your Cloudflare account:  https://dash.cloudflare.com/argotunnel?aud=&callback=https%3A%2F%2Flogin.example";
        assert!(url_in(line).unwrap().starts_with("https://dash.cloudflare.com/argotunnel"));
        assert_eq!(url_in("no address here"), None);
    }

    #[test]
    fn each_step_runs_the_right_command() {
        assert_eq!(args_for(Step::Create, "home", "", "", ""), ["tunnel", "create", "home"]);
        assert_eq!(args_for(Step::Route, "home", "a.example.com", "", ""), ["tunnel", "route", "dns", "home", "a.example.com"]);
        assert_eq!(args_for(Step::Run, "home", "", "http://localhost:80", ""), ["tunnel", "--no-autoupdate", "run", "--url", "http://localhost:80", "home"]);
        assert_eq!(args_for(Step::Run, "home", "", "", "TOKEN"), ["tunnel", "--no-autoupdate", "run", "--token", "TOKEN"]);
    }

    #[test]
    fn judges_a_step_by_what_it_printed() {
        assert!(step_succeeded(Step::Create, "Created tunnel home with id 1234"));
        assert!(step_succeeded(Step::Create, "tunnel with name home already exists"));
        assert!(!step_succeeded(Step::Create, "failed to create tunnel"));
        assert!(step_succeeded(Step::Route, "Added CNAME a.example.com which will route to this tunnel"));
        assert!(step_succeeded(Step::Login, "You have successfully logged in. ... saved to: C:\\Users\\x\\.cloudflared\\cert.pem"));
        assert!(!step_succeeded(Step::Login, "error: could not open the browser"));
    }

    #[test]
    fn checks_what_you_typed() {
        assert!(valid_name("my-tunnel") && !valid_name("my tunnel") && !valid_name(""));
        assert!(valid_host("home.example.com") && !valid_host("example") && !valid_host("a..com") && !valid_host("-a.com"));
        assert!(valid_service("http://localhost:80") && !valid_service("localhost:80") && !valid_service("http://a b"));
        assert!(valid_token("eyJhIjoiYWJjZGVmZ2hpamtsbW5vcCJ9") && !valid_token("short") && !valid_token("has space has space has space"));
    }
}
