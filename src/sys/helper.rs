//! Helper programs for plugins with the `helper.exe` permission: a program a plugin needs but RustWarden
//! cannot ship (Ookla's licence forbids bundling speedtest.exe). The plugin names the download and the
//! checksums it expects; RustWarden downloads it from an address the plugin declared, checks the checksum,
//! keeps it in a folder only it uses, and runs it with the arguments the plugin gives, handing back each
//! line the program prints.

use std::io::{BufRead, Read};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn user_dir(plugin: &str) -> PathBuf {
    crate::settings::data_dir().join(plugin)
}

/// Elevated runs use an admin-only folder: any program could swap an exe in the data folder, or plant a DLL beside it.
pub fn dir(plugin: &str) -> PathBuf {
    if super::is_elevated() { crate::settings::admin_dir().join(plugin) } else { user_dir(plugin) }
}

/// A plain file name ending in .exe: no folders, no tricks.
pub fn valid_exe_name(name: &str) -> bool {
    name.len() <= 64 && name.to_ascii_lowercase().ends_with(".exe") && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn sha_of(path: &Path) -> String {
    crate::sys::apps::hash_file(&path.to_string_lossy())
}

/// Elevated: moves a genuine copy from the data folder to the admin-only one, so nobody has to download it again.
fn adopt_user_copy(plugin: &str, exe: &str, wanted: &str) {
    if super::is_elevated() && adopt(&user_dir(plugin).join(exe), &dir(plugin), exe, wanted) {
        let _ = std::fs::remove_dir_all(user_dir(plugin));
    }
}

/// Hashes the copy, not the original, because the original can still change after it is checked.
fn adopt(from: &Path, to_dir: &Path, exe: &str, wanted: &str) -> bool {
    let to = to_dir.join(exe);
    if to.exists() || !from.is_file() || std::fs::create_dir_all(to_dir).is_err() || std::fs::copy(from, &to).is_err() {
        return false;
    }
    let genuine = sha_of(&to).eq_ignore_ascii_case(wanted);
    if !genuine {
        let _ = std::fs::remove_file(&to);
    }
    genuine
}

/// True when the program is there (after taking over a genuine copy from an earlier non-elevated run).
pub fn ready(plugin: &str, exe: &str, exe_sha256: &str) -> bool {
    if !valid_exe_name(exe) {
        return false;
    }
    adopt_user_copy(plugin, exe, exe_sha256);
    dir(plugin).join(exe).is_file()
}

/// Downloads `url`, checks the zip against `zip_sha256` and unpacks `exe` from it. Blocks, so callers run it on a worker.
pub fn install(plugin: &str, url: &str, zip_sha256: &str, exe: &str) -> Result<(), String> {
    if !valid_exe_name(exe) {
        return Err("that isn't a program name".into());
    }
    let dir = dir(plugin);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Can't create {}: {e}", dir.display()))?;
    let mut curl = crate::sys::tool("curl.exe");
    curl.args(["-fsSL", "--proto", "=https", "--max-time", "300", "-o", "download.zip", url]).current_dir(&dir);
    run_tool(&mut curl, "Can't download it")?;
    let zip = dir.join("download.zip");
    if !sha_of(&zip).eq_ignore_ascii_case(zip_sha256) {
        let _ = std::fs::remove_file(&zip);
        return Err("The download did not match the expected checksum, so it was thrown away.".into());
    }
    // tar.exe ships with Windows 10+ and reads zip files, so no archive crate is needed.
    let mut tar = crate::sys::tool("tar.exe");
    tar.args(["-xf", "download.zip", exe]).current_dir(&dir);
    let unpacked = run_tool(&mut tar, "Can't unpack it");
    let _ = std::fs::remove_file(&zip);
    unpacked?;
    if dir.join(exe).is_file() { Ok(()) } else { Err(format!("The download didn't contain {exe}")) }
}

fn run_tool(cmd: &mut Command, what: &str) -> Result<(), String> {
    cmd.stdout(Stdio::null()).stderr(Stdio::piped()).creation_flags(crate::sys::NO_WINDOW);
    let child = crate::sys::etw::spawn_own(cmd).map_err(|e| format!("{what}: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("{what}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(format!("{what}: {}", err.lines().next().unwrap_or("it failed").trim()))
}

/// Runs the program on its own thread. `on_line` gets each line it prints as it prints it; `on_done` gets the end
/// (what the program wrote to stderr, or an error for a timeout or a program that wouldn't start). Returns at once.
pub fn start(
    plugin: &str,
    exe: &str,
    args: Vec<String>,
    timeout: Duration,
    on_line: impl Fn(String) + Send + 'static,
    on_done: impl FnOnce(Result<String, String>) + Send + 'static,
) -> Result<(), String> {
    if !valid_exe_name(exe) {
        return Err("that isn't a program name".into());
    }
    let path = dir(plugin).join(exe);
    if !path.is_file() {
        return Err(format!("{exe} isn't downloaded yet"));
    }
    std::thread::spawn(move || {
        let mut cmd = Command::new(&path);
        cmd.args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null()).creation_flags(crate::sys::NO_WINDOW);
        let mut child = match crate::sys::etw::spawn_own(&mut cmd) {
            Ok(c) => c,
            Err(e) => return on_done(Err(format!("Can't run the program: {e}"))),
        };
        let (stdout, mut stderr) = (child.stdout.take(), child.stderr.take());
        let reader = std::thread::spawn(move || {
            if let Some(o) = stdout {
                for line in std::io::BufReader::new(o).lines().map_while(Result::ok) {
                    on_line(line);
                }
            }
            let mut rest = String::new();
            if let Some(e) = &mut stderr {
                let _ = e.read_to_string(&mut rest);
            }
            rest
        });
        let started = Instant::now();
        let end = loop {
            match child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Ok(None) if started.elapsed() > timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err("The program timed out".to_owned());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => break Err(format!("Can't wait for the program: {e}")),
            }
        };
        let stderr = reader.join().unwrap_or_default();
        on_done(end.map(|()| stderr));
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_exe_names_are_programs() {
        assert!(valid_exe_name("speedtest.exe") && valid_exe_name("My-Tool_2.EXE"));
        for bad in ["", "tool", "tool.dll", "..\\tool.exe", "dir/tool.exe", "a b.exe", "tool.exe;calc"] {
            assert!(!valid_exe_name(bad), "{bad}");
        }
    }

    #[test]
    fn adopts_only_a_genuine_copy() {
        let root = std::env::temp_dir().join(format!("rustwarden-helper-test-{}", std::process::id()));
        let (from, to) = (root.join("from.exe"), root.join("to"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&from, b"program").unwrap();
        let real = sha_of(&from);
        assert!(!adopt(&from, &to, "tool.exe", &"0".repeat(64)));
        assert!(!to.join("tool.exe").exists(), "a wrong copy must not stay");
        assert!(adopt(&from, &to, "tool.exe", &real));
        assert!(to.join("tool.exe").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_program_that_isnt_downloaded_is_refused_before_anything_runs() {
        let e = start("rustwarden-test-no-such-plugin", "nothing.exe", vec![], Duration::from_secs(1), |_| {}, |_| {}).unwrap_err();
        assert!(e.contains("isn't downloaded"));
        assert!(start("p", "..\\evil.exe", vec![], Duration::from_secs(1), |_| {}, |_| {}).is_err());
    }
}
