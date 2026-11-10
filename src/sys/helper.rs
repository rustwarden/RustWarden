//! Helper programs for plugins with the `helper.exe` permission: a program a plugin needs but RustWarden
//! cannot ship (Ookla's licence forbids bundling speedtest.exe). The plugin names the download and the
//! checksums it expects; RustWarden downloads it from an address the plugin declared, checks the checksum,
//! keeps it in a folder only it uses, and runs it with the arguments the plugin gives, handing back each
//! line the program prints.

use std::io::{BufRead, Read};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Each plugin's running helper, with the flag that asks it to stop.
static RUNNING: Mutex<Vec<(String, Arc<AtomicBool>)>> = Mutex::new(Vec::new());

/// Asks the plugin's running helper to stop; it is killed within a fraction of a second.
pub fn stop(plugin: &str) {
    for (p, flag) in RUNNING.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if p == plugin {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

/// Stops every helper as RustWarden closes, so none is left running (a tunnel, say) with nothing to manage it.
pub fn stop_all() {
    let running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    running.iter().for_each(|(_, flag)| flag.store(true, Ordering::SeqCst));
    if !running.is_empty() {
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn user_dir(plugin: &str) -> PathBuf {
    crate::settings::data_dir().join(plugin)
}

/// Elevated runs use an admin-only folder: any program could swap an exe in the data folder, or plant a DLL beside it.
pub fn dir(plugin: &str) -> PathBuf {
    if super::is_elevated() { crate::settings::admin_dir().join(plugin) } else { user_dir(plugin) }
}

/// Separates the `env:NAME=value` arguments from the real ones. Only USERPROFILE and HOME can be set, and only to a place
/// inside the plugin's own folder.
type Split = (Vec<(String, String)>, Vec<String>);

fn split_env(args: Vec<String>, folder: &str) -> Result<Split, String> {
    let inside = |v: &str| {
        let (v, f) = (v.replace('/', "\\").to_ascii_lowercase(), folder.to_ascii_lowercase());
        !v.split('\\').any(|part| part == "..") && (v == f || v.starts_with(&format!("{}\\", f.trim_end_matches('\\'))))
    };
    let (mut env, mut rest) = (Vec::new(), Vec::new());
    for a in args {
        let Some(spec) = a.strip_prefix("env:") else {
            rest.push(a);
            continue;
        };
        match spec.split_once('=') {
            Some((name @ ("USERPROFILE" | "HOME"), value)) if inside(value) => env.push((name.to_owned(), value.to_owned())),
            _ => return Err("that environment variable can't be set".into()),
        }
    }
    Ok((env, rest))
}

/// A plain file name ending in .exe: no folders, no tricks.
pub fn valid_exe_name(name: &str) -> bool {
    name.len() <= 64 && name.to_ascii_lowercase().ends_with(".exe") && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn sha_of(path: &Path) -> String {
    crate::sys::apps::hash_file(&path.to_string_lossy())
}

/// Elevated: moves a genuine copy from the data folder to the admin-only one, so nobody has to download it again.
/// The rest of that folder stays: it is the program's own folder for its files (see [`start`]).
fn adopt_user_copy(plugin: &str, exe: &str, wanted: &str) {
    if super::is_elevated() && adopt(&user_dir(plugin).join(exe), &dir(plugin), exe, wanted) {
        let _ = std::fs::remove_file(user_dir(plugin).join(exe));
    }
}

/// A program runs without administrator rights, so it can't write beside its exe in the admin-only folder. Its own files
/// (cloudflared's login, say) live in the user's folder for the plugin; folders an earlier version kept beside the exe are
/// copied there once (a move would keep the old folder's permissions).
fn migrate_state(plugin: &str) {
    if !super::is_elevated() {
        return;
    }
    let (from, to) = (dir(plugin), user_dir(plugin));
    for e in std::fs::read_dir(&from).into_iter().flatten().flatten() {
        let target = to.join(e.file_name());
        if e.path().is_dir() && !target.exists() && copy_dir(&e.path(), &target).is_ok() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        // `AppData` is what Windows builds under a home folder it is pointed at (browser caches, history): nothing in it is worth keeping.
        if e.file_name() == "AppData" {
            continue;
        }
        let target = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &target)?;
        } else {
            std::fs::copy(e.path(), target)?;
        }
    }
    Ok(())
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

/// The checksum `ready` last confirmed per plugin and program, which `start` holds the file to before running it.
static CHECKED: Mutex<Vec<(String, String, String)>> = Mutex::new(Vec::new());
/// Hashes by (path, size, modified time), so a plugin that asks `ready` on every tick doesn't read a 50 MB file each time.
static HASHES: Mutex<Vec<(PathBuf, u64, std::time::SystemTime, String)>> = Mutex::new(Vec::new());

fn cached_sha(path: &Path) -> String {
    let Ok(meta) = std::fs::metadata(path) else { return String::new() };
    let Ok(modified) = meta.modified() else { return sha_of(path) };
    let mut hashes = HASHES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, _, sha)) = hashes.iter().find(|(p, len, m, _)| p == path && *len == meta.len() && *m == modified) {
        return sha.clone();
    }
    let sha = sha_of(path);
    hashes.retain(|(p, ..)| p != path);
    hashes.push((path.to_owned(), meta.len(), modified, sha.clone()));
    sha
}

/// True when the program is there and is the one the plugin expects (after taking over a genuine copy from an
/// earlier non-elevated run). A copy that no longer matches reads as missing, so the plugin offers to download it again.
pub fn ready(plugin: &str, exe: &str, exe_sha256: &str) -> bool {
    if !valid_exe_name(exe) {
        return false;
    }
    adopt_user_copy(plugin, exe, exe_sha256);
    let path = dir(plugin).join(exe);
    let genuine = path.is_file() && cached_sha(&path).eq_ignore_ascii_case(exe_sha256);
    let mut checked = CHECKED.lock().unwrap_or_else(|e| e.into_inner());
    checked.retain(|(p, e, _)| !(p == plugin && e == exe));
    if genuine {
        checked.push((plugin.to_owned(), exe.to_owned(), exe_sha256.to_ascii_lowercase()));
    }
    genuine
}

/// The checksum `ready` confirmed for this program, if it did.
fn confirmed(plugin: &str, exe: &str) -> Option<String> {
    CHECKED.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(p, e, _)| p == plugin && e == exe).map(|(.., sha)| sha.clone())
}

/// Downloads `url`, checks it against `zip_sha256` and unpacks `exe` from it (a url ending in `.exe` is the program
/// itself, so it is only checked). Blocks, so callers run it on a worker.
pub fn install(plugin: &str, url: &str, zip_sha256: &str, exe: &str) -> Result<(), String> {
    if !valid_exe_name(exe) {
        return Err("that isn't a program name".into());
    }
    let dir = dir(plugin);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Can't create {}: {e}", dir.display()))?;
    // curl needs no administrator rights, so it downloads into the user's folder; the file is copied into the admin-only
    // folder and checked there, because the original could still change after it is checked.
    let scratch = user_dir(plugin);
    std::fs::create_dir_all(&scratch).map_err(|e| format!("Can't create {}: {e}", scratch.display()))?;
    let mut curl = crate::sys::tool("curl.exe");
    curl.args(["-fsSLg", "--proto", "=https", "--proto-redir", "=https", "--max-time", "300", "-o", "download.zip", url]).current_dir(&scratch);
    run_user_tool(&curl, "Can't download it")?;
    let zip = dir.join("download.zip");
    if scratch != dir {
        let copied = std::fs::copy(scratch.join("download.zip"), &zip);
        let _ = std::fs::remove_file(scratch.join("download.zip"));
        copied.map_err(|e| format!("Can't save the download: {e}"))?;
    }
    if !sha_of(&zip).eq_ignore_ascii_case(zip_sha256) {
        let _ = std::fs::remove_file(&zip);
        return Err("The download did not match the expected checksum, so it was thrown away.".into());
    }
    if url.to_ascii_lowercase().ends_with(".exe") {
        let _ = std::fs::remove_file(dir.join(exe));
        return std::fs::rename(&zip, dir.join(exe)).map_err(|e| format!("Can't save {exe}: {e}"));
    }
    // tar.exe ships with Windows 10+ and reads zip files, so no archive crate is needed.
    let mut tar = crate::sys::tool("tar.exe");
    tar.args(["-xf", "download.zip", exe]).current_dir(&dir);
    let unpacked = run_tool(&mut tar, "Can't unpack it");
    let _ = std::fs::remove_file(&zip);
    unpacked?;
    if dir.join(exe).is_file() { Ok(()) } else { Err(format!("The download didn't contain {exe}")) }
}

/// Runs a tool that needs no administrator rights (see `proc`) and waits; its first line of errors is the reason it failed.
fn run_user_tool(cmd: &Command, what: &str) -> Result<(), String> {
    let child = crate::sys::etw::spawn_user(cmd, crate::sys::proc::Pipes { stdin: false, stdout: false, stderr: true }, false).map_err(|e| format!("{what}: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("{what}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(format!("{what}: {}", err.lines().next().unwrap_or("it failed").trim()))
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
    on_line: impl Fn(String) + Send + Sync + 'static,
    on_done: impl FnOnce(Result<String, String>) + Send + 'static,
) -> Result<(), String> {
    if !valid_exe_name(exe) {
        return Err("that isn't a program name".into());
    }
    let path = dir(plugin).join(exe);
    if !path.is_file() {
        return Err(format!("{exe} isn't downloaded yet"));
    }
    // Hashed again in full (not from the cache) right before it runs: the file could have been swapped since `ready`.
    let Some(wanted) = confirmed(plugin, exe) else { return Err(format!("{exe} hasn't been checked yet")) };
    if !sha_of(&path).eq_ignore_ascii_case(&wanted) {
        CHECKED.lock().unwrap_or_else(|e| e.into_inner()).retain(|(p, e, _)| !(p == plugin && e == exe));
        return Err(format!("{exe} has changed since it was downloaded, so it wasn't run. Download it again."));
    }
    // "{dir}" in an argument is the plugin's own folder, so a program can keep its files there (removed with the plugin's data).
    // The program runs without administrator rights, so that is the user's folder for the plugin, not the one beside the exe.
    migrate_state(plugin);
    let folder = user_dir(plugin).to_string_lossy().into_owned();
    let _ = std::fs::create_dir_all(&folder);
    let args: Vec<String> = args.into_iter().map(|a| a.replace("{dir}", &folder)).collect();
    // "env:NAME=value" arguments set an environment variable for the program instead of being passed to it. Only the
    // home folder may be set (a program that keeps its sign-in under it, such as cloudflared, then keeps it in the plugin's folder).
    let (env, args) = split_env(args, &folder)?;
    for (_, value) in &env {
        let _ = std::fs::create_dir_all(value);
    }
    let stop = Arc::new(AtomicBool::new(false));
    {
        let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        // A helper this plugin left running (its worker was replaced) is stopped, not just forgotten.
        running.iter().filter(|(p, _)| p == plugin).for_each(|(_, f)| f.store(true, Ordering::SeqCst));
        running.retain(|(p, f)| p != plugin && !Arc::ptr_eq(f, &stop));
        running.push((plugin.to_owned(), stop.clone()));
    }
    std::thread::spawn(move || {
        let mut cmd = Command::new(&path);
        cmd.args(&args).envs(env.iter().map(|(k, v)| (k, v)));
        // Without administrator rights: a downloaded program (a tunnel, a speed test) has no use for them.
        let mut child = match crate::sys::etw::spawn_user(&cmd, crate::sys::proc::Pipes::OUT, false) {
            Ok(c) => c,
            Err(e) => {
                RUNNING.lock().unwrap_or_else(|e| e.into_inner()).retain(|(_, f)| !Arc::ptr_eq(f, &stop));
                return on_done(Err(format!("Can't run the program: {e}")));
            }
        };
        let (stdout, mut stderr) = (child.stdout.take(), child.stderr.take());
        // A program that runs until stopped (a tunnel) logs to stderr as it goes, so those lines are passed on too
        // (and read while it runs, so the pipe never fills); otherwise stderr is only read at the end.
        let stream_err = timeout.is_zero();
        let on_line = Arc::new(on_line);
        let reader = std::thread::spawn(move || {
            let err_lines = stderr.take().filter(|_| stream_err).map(|e| {
                let on_line = on_line.clone();
                std::thread::spawn(move || {
                    let mut tail = std::collections::VecDeque::new();
                    for line in std::io::BufReader::new(e).lines().map_while(Result::ok) {
                        on_line(line.clone());
                        if tail.len() == 20 {
                            tail.pop_front();
                        }
                        tail.push_back(line);
                    }
                    Vec::from(tail).join("\n")
                })
            });
            if let Some(o) = stdout {
                for line in std::io::BufReader::new(o).lines().map_while(Result::ok) {
                    on_line(line);
                }
            }
            let mut rest = String::new();
            if let Some(e) = &mut stderr {
                let _ = e.read_to_string(&mut rest);
            }
            err_lines.map_or(rest, |t| t.join().unwrap_or_default())
        });
        let started = Instant::now();
        let end = loop {
            match child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Ok(None) if stop.load(Ordering::SeqCst) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err("The program was stopped".to_owned());
                }
                Ok(None) if !timeout.is_zero() && started.elapsed() > timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err("The program timed out".to_owned());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => break Err(format!("Can't wait for the program: {e}")),
            }
        };
        let stderr = reader.join().unwrap_or_default();
        RUNNING.lock().unwrap_or_else(|e| e.into_inner()).retain(|(_, f)| !Arc::ptr_eq(f, &stop));
        on_done(end.map(|()| stderr));
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_home_folder_can_be_set() {
        let p = r"C:\p";
        let (env, rest) = split_env(vec![r"env:HOME=C:\p\home".into(), "tunnel".into()], p).unwrap();
        assert_eq!(env, [("HOME".to_owned(), r"C:\p\home".to_owned())]);
        assert_eq!(rest, ["tunnel"]);
        assert!(split_env(vec![r"env:PATH=C:\evil".into()], p).is_err());
        assert!(split_env(vec![r"env:HOME=C:\p\..\x".into()], p).is_err());
        assert!(split_env(vec![r"env:HOME=C:\Windows\Foo".into()], p).is_err(), "outside the plugin's folder");
        assert!(split_env(vec![r"env:HOME=C:\pother".into()], p).is_err(), "a sibling that starts the same");
    }

    #[test]
    fn a_programs_folders_are_copied_with_their_files() {
        let root = std::env::temp_dir().join(format!("rustwarden-helper-copy-{}", std::process::id()));
        let (from, to) = (root.join("from"), root.join("to"));
        std::fs::create_dir_all(from.join("login-1/.cloudflared")).unwrap();
        std::fs::create_dir_all(from.join("login-1/AppData/Local")).unwrap();
        std::fs::write(from.join("login-1/.cloudflared/cert.pem"), b"cert").unwrap();
        copy_dir(&from, &to).unwrap();
        assert_eq!(std::fs::read(to.join("login-1/.cloudflared/cert.pem")).unwrap(), b"cert");
        assert!(!to.join("login-1/AppData").exists(), "Windows' own skeleton is not carried over");
        assert!(from.join("login-1").is_dir(), "the source is left for the caller to remove");
        let _ = std::fs::remove_dir_all(&root);
    }

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
    fn only_a_program_that_still_matches_its_checksum_runs() {
        let plugin = format!("rustwarden-test-helper-{}", std::process::id());
        let folder = dir(&plugin);
        std::fs::create_dir_all(&folder).unwrap();
        let exe = folder.join("tool.exe");
        std::fs::write(&exe, b"program").unwrap();
        let real = sha_of(&exe);
        let start_it = || start(&plugin, "tool.exe", vec![], Duration::from_secs(1), |_| {}, |_| {});
        assert!(start_it().unwrap_err().contains("checked"), "never confirmed by ready");
        assert!(!ready(&plugin, "tool.exe", &"0".repeat(64)), "a wrong checksum is not ready");
        assert!(ready(&plugin, "tool.exe", &real));
        // Swapped after the check (same size, so only a full hash catches it).
        std::fs::write(&exe, b"PROGRAM").unwrap();
        assert!(start_it().unwrap_err().contains("changed"));
        assert!(start_it().unwrap_err().contains("checked"), "the confirmation is dropped");
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_program_that_isnt_downloaded_is_refused_before_anything_runs() {
        let e = start("rustwarden-test-no-such-plugin", "nothing.exe", vec![], Duration::from_secs(1), |_| {}, |_| {}).unwrap_err();
        assert!(e.contains("isn't downloaded"));
        assert!(start("p", "..\\evil.exe", vec![], Duration::from_secs(1), |_| {}, |_| {}).is_err());
    }
}
