//! The one way RustWarden runs `curl.exe` with a request: the whole request goes in on stdin as a curl config,
//! so tokens and addresses never show in the process list, and only http(s) can ever be reached.

use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Output, Stdio};

/// Refuses `file://` and the like, whatever address the settings hold.
pub const PROTO: &str = "proto = \"=http,https\"\n";

/// A quoted value for a curl config.
pub fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r"))
}

/// Runs curl with `config`, in `dir` if given (where relative files in the config live), and waits for it.
pub fn run(config: &str, dir: Option<&Path>) -> Result<Output, String> {
    let mut cmd = super::tool("curl.exe");
    cmd.args(["-K", "-"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(super::NO_WINDOW);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let mut child = super::etw::spawn_own(&mut cmd).map_err(|e| format!("Can't run curl.exe: {e}"))?;
    // Dropped at the end of the block, so curl sees the end of its config.
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(PROTO.as_bytes()).and_then(|()| stdin.write_all(config.as_bytes())).map_err(|e| e.to_string())?;
    }
    child.wait_with_output().map_err(|e| e.to_string())
}

/// A call to a REST API: `body` makes it a JSON POST, and the output ends with "\n<http status>".
pub fn api_config(url: &str, auth: &str, body: Option<&str>) -> String {
    let mut c = format!("silent\nshow-error\nmax-time = 10\nwrite-out = \"\\n%{{http_code}}\"\nheader = {}\n", quote(auth));
    if let Some(b) = body {
        c += &format!("header = \"Content-Type: application/json\"\ndata-raw = {}\n", quote(b));
    }
    c + &format!("url = {}\n", quote(url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_cannot_break_out_of_the_config() {
        let c = api_config("https://h/\"\nurl = \"evil", "Authorization: Bearer a\nb", Some("{\"x\":1}"));
        assert_eq!(c.lines().filter(|l| l.starts_with("url")).count(), 1);
        assert!(c.contains("Bearer a\\nb"));
        assert!(c.contains("data-raw = \"{\\\"x\\\":1}\""));
    }

    #[test]
    fn refuses_other_protocols() {
        let out = run("silent\nurl = \"file:///c:/windows/win.ini\"\n", None).unwrap();
        assert!(!out.status.success() && out.stdout.is_empty());
    }

    #[test]
    fn tools_come_from_the_system_folder() {
        for (name, tail) in [("curl.exe", r"\curl.exe"), ("sc", r"\sc.exe"), ("powershell", r"\v1.0\powershell.exe")] {
            let p = super::super::tool_path(name).to_lowercase();
            assert!(p.starts_with(|c: char| c.is_ascii_alphabetic()) && p.contains("system32") && p.ends_with(tail), "{p}");
        }
    }
}
