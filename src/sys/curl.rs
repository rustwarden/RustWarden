//! The one way RustWarden runs `curl.exe` with a request: the whole request goes in on stdin as a curl config,
//! so tokens and addresses never show in the process list, and only http(s) can ever be reached.

use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Output, Stdio};

/// Refuses `file://` and the like, whatever address the settings hold, and turns curl's URL globbing off: an address
/// such as `https://host/[1-1000000]` (from a plugin or a setting) would otherwise become a million requests.
pub const PROTO: &str = "proto = \"=http,https\"\ngloboff\n";

/// A quoted value for a curl config.
pub fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r"))
}

/// Runs curl with `config`, in `dir` if given (where relative files in the config live), and waits for it.
pub fn run(config: &str, dir: Option<&Path>) -> Result<Output, String> {
    let mut cmd = super::tool("curl.exe");
    cmd.args(["-K", "-"]);
    // A request that only reads an answer needs no administrator rights, so it runs without them. One that writes a file in
    // `dir` (the update, the driver) stays as it was: that folder may be one only administrators can write.
    if dir.is_none() {
        let mut child = super::etw::spawn_user(&cmd, super::proc::Pipes::ALL, false).map_err(|e| format!("Can't run curl.exe: {e}"))?;
        // Dropped at the end of the block, so curl sees the end of its config.
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(PROTO.as_bytes()).and_then(|()| stdin.write_all(config.as_bytes())).map_err(|e| e.to_string())?;
        }
        return child.wait_with_output().map_err(|e| e.to_string());
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(super::NO_WINDOW);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_other_protocols() {
        let out = run("silent\nurl = \"file:///c:/windows/win.ini\"\n", None).unwrap();
        assert!(!out.status.success() && out.stdout.is_empty());
    }

    #[test]
    fn globbing_is_off() {
        // With globbing on, curl reads the brackets as a range and asks for /1 and /2; off, it sends them as they are
        // (and fails here only because nothing listens on that port).
        let out = run("silent\nurl = \"http://127.0.0.1:9/[1-2]\"\nwrite-out = \"%{url_effective}\"\n", None).unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("[1-2]"), "{}", String::from_utf8_lossy(&out.stdout));
    }

    #[test]
    fn tools_come_from_the_system_folder() {
        for (name, tail) in [("curl.exe", r"\curl.exe"), ("sc", r"\sc.exe"), ("powershell", r"\v1.0\powershell.exe")] {
            let p = super::super::tool_path(name).to_lowercase();
            assert!(p.starts_with(|c: char| c.is_ascii_alphabetic()) && p.contains("system32") && p.ends_with(tail), "{p}");
        }
    }
}
