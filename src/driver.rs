//! Driver mode's optional network driver: WinDivert, a signed third-party packet driver. It is never
//! bundled: the user presses a button, the official release zip is downloaded, checked against a pinned
//! SHA-256, and only its DLL and driver file are kept in `Program Files\RustWarden\driver`: elevated code loads
//! that DLL, so a program without administrator rights must not be able to replace it. The DLL starts the
//! driver service itself the first time it is used. This module is the part that doesn't need Windows
//! APIs: what is pinned, what state the folder is in, and the install/remove steps.

use crate::settings::{admin_dir, data_dir};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const VERSION: &str = "2.2.2";
pub const URL: &str = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";
/// SHA-256 of that zip. A new WinDivert release means a new pin here; "latest" is never fetched blindly.
pub const ZIP_SHA256: &str = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";
/// Name of the Windows service the driver runs as.
pub const SERVICE: &str = "WinDivert";
const DLL: &str = "WinDivert.dll";
const SYS: &str = "WinDivert64.sys";
const MARKER: &str = "installed.txt";

pub const BLOCKED_HELP: &str = "Windows Defender (or another antivirus) removed the driver files, because WinDivert is also used by some game-cheat and bypass tools. Open Windows Security > Virus & threat protection > Protection history, allow the item, then press Install again. WinDivert is open source (reqrypt.org / github.com/basil00/WinDivert).";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriverState {
    Missing,
    Ready,
    /// Was installed, but its files are gone or unreadable; the text says why and what to do.
    Blocked(String),
}

pub fn dir() -> PathBuf {
    admin_dir().join("driver")
}

/// Removes an install from the user-writable data folder older versions used, with its Defender exclusion and its
/// service (which points at the old driver file). Needs administrator rights. True when a working install was there,
/// so the caller can put it back in the new folder.
pub fn retire_old_folder() -> bool {
    let mut was_installed = false;
    // The second is where versions before the rename to RustWarden kept it.
    for old in [data_dir().join("driver"), crate::settings::legacy_admin_dir().join("driver")] {
        if !old.exists() {
            continue;
        }
        was_installed |= state_in(&old) == DriverState::Ready;
        let _ = crate::sys::defender::remove_exclusion(&old.to_string_lossy());
        let _ = remove_steps(&old);
    }
    // Empty once the driver is gone; migrate.rs moved the rest.
    let _ = std::fs::remove_dir(crate::settings::legacy_admin_dir());
    was_installed
}

/// What the folder says about the driver: installed and complete, never installed, or damaged.
pub fn state_in(dir: &Path) -> DriverState {
    let have = |f: &str| dir.join(f).is_file();
    match (have(DLL) && have(SYS), have(MARKER)) {
        (true, _) => DriverState::Ready,
        (false, true) => DriverState::Blocked(BLOCKED_HELP.into()),
        (false, false) => DriverState::Missing,
    }
}

pub fn state() -> DriverState {
    state_in(&dir())
}

/// The driver is installed and complete. Every feature that needs it stays out of the UI until this is true.
pub fn ready() -> bool {
    state() == DriverState::Ready
}

/// What an install or removal in progress is doing; empty when idle. Read by the Settings card.
static PROGRESS: Mutex<String> = Mutex::new(String::new());

pub fn progress() -> String {
    PROGRESS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn set_progress(text: &str) {
    *PROGRESS.lock().unwrap_or_else(|e| e.into_inner()) = text.to_owned();
}

/// Whether `actual` (hex, any case) is the pinned zip.
pub fn hash_matches(actual: &str) -> bool {
    actual.eq_ignore_ascii_case(ZIP_SHA256)
}

/// Downloads, checks and unpacks the driver. Slow: call it off the UI thread.
pub fn install() -> Result<(), String> {
    if !crate::sys::is_elevated() {
        return Err("Installing the driver needs administrator rights. Use \"Restart as administrator\".".into());
    }
    // Defender flags WinDivert, so its folder is excluded first (the user agreed to this before the download started).
    set_progress("Allowing the driver folder in Windows Defender…");
    let _ = std::fs::create_dir_all(dir());
    let excluded = crate::sys::defender::add_exclusion(&dir().to_string_lossy());
    let result = install_steps().map_err(|e| match &excluded {
        Err(x) => format!("{e} {x}"),
        Ok(()) => e,
    });
    set_progress("");
    result
}

fn install_steps() -> Result<(), String> {
    let dir = dir();
    let (zip, tmp) = (dir.join("WinDivert.zip"), dir.join("unpacked"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Can't create the driver folder: {e}"))?;
    let tidy = || {
        let _ = std::fs::remove_file(&zip);
        let _ = std::fs::remove_dir_all(&tmp);
    };
    set_progress(&format!("Downloading WinDivert {VERSION}…"));
    match crate::update::get(URL, "application/octet-stream", Some((&dir, "WinDivert.zip"))) {
        Ok((200, _)) => {}
        Ok((0, _)) => return Err("Could not reach github.com to download the driver.".into()),
        Ok((status, _)) => return Err(format!("GitHub answered HTTP {status} for the driver download.")),
        Err(e) => return Err(e),
    }
    set_progress("Checking the download…");
    let hash = crate::sys::apps::hash_file(&zip.to_string_lossy());
    if hash.is_empty() {
        tidy();
        return Err(format!("The download could not be read, which usually means antivirus blocked it. {BLOCKED_HELP}"));
    }
    if !hash_matches(&hash) {
        tidy();
        return Err("The download did not match the expected checksum, so it was thrown away.".into());
    }
    set_progress("Unpacking…");
    std::fs::create_dir_all(&tmp).map_err(|e| format!("Can't create a folder to unpack into: {e}"))?;
    let mut tar = crate::sys::tool("tar.exe");
    tar.arg("-xf").arg(&zip).arg("-C").arg(&tmp).creation_flags(crate::sys::NO_WINDOW);
    let status = crate::sys::etw::spawn_own(&mut tar).and_then(|mut c| c.wait()).map_err(|e| format!("Can't unpack the driver: {e}"))?;
    if !status.success() {
        tidy();
        return Err("Windows could not unpack the driver zip.".into());
    }
    let src = tmp.join(format!("WinDivert-{VERSION}-A")).join("x64");
    let copied = [DLL, SYS].iter().all(|f| std::fs::copy(src.join(f), dir.join(f)).is_ok());
    tidy();
    if !copied {
        return Err(format!("The driver files were not there after unpacking. {BLOCKED_HELP}"));
    }
    std::fs::write(dir.join(MARKER), VERSION).map_err(|e| format!("Can't record the install: {e}"))
}

/// Stops and deletes the driver service, then the files. The service goes first because a running
/// driver keeps its file locked.
pub fn remove() -> Result<(), String> {
    set_progress("Removing the driver…");
    let result = remove_steps(&dir());
    set_progress("");
    result
}

fn remove_steps(dir: &Path) -> Result<(), String> {
    for verb in ["stop", "delete"] {
        let mut sc = crate::sys::tool("sc.exe");
        sc.args([verb, SERVICE]).creation_flags(crate::sys::NO_WINDOW);
        // The service may never have been started; an error here is fine as long as the files can go.
        let _ = sc.output();
    }
    // The marker goes first so a half-finished removal never still reads as installed.
    let _ = std::fs::remove_file(dir.join(MARKER));
    // A file that is still locked (a loaded DLL) can be renamed even when it can't be deleted; the
    // leftovers are swept on the next install or removal.
    for f in [DLL, SYS] {
        let path = dir.join(f);
        if std::fs::remove_file(&path).is_err() && path.exists() {
            let _ = std::fs::rename(&path, dir.join(format!("{f}.old")));
        }
    }
    let deleted = match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) if state_in(dir) == DriverState::Missing => Ok(()),
        Err(e) => Err(format!("Couldn't delete the driver files ({e}). Restart Windows and try again.")),
    };
    if deleted.is_ok() {
        let _ = crate::sys::defender::remove_exclusion(&dir.to_string_lossy());
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rustwarden-driver-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn folder_state_tells_missing_ready_and_blocked_apart() {
        let d = scratch("state");
        assert_eq!(state_in(&d), DriverState::Missing);
        std::fs::write(d.join(MARKER), VERSION).unwrap();
        assert!(matches!(state_in(&d), DriverState::Blocked(_)), "installed once but the files are gone");
        std::fs::write(d.join(DLL), "x").unwrap();
        assert!(matches!(state_in(&d), DriverState::Blocked(_)), "one file is not enough");
        std::fs::write(d.join(SYS), "x").unwrap();
        assert_eq!(state_in(&d), DriverState::Ready);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn driver_folder_is_not_user_writable_data() {
        assert!(dir().starts_with(admin_dir()));
        assert!(!dir().starts_with(data_dir()));
    }

    #[test]
    fn only_the_pinned_zip_passes() {
        assert!(hash_matches(&ZIP_SHA256.to_uppercase()));
        assert!(!hash_matches(""));
        assert!(!hash_matches(&"0".repeat(64)));
        assert_eq!(ZIP_SHA256.len(), 64);
        assert!(URL.starts_with("https://github.com/basil00/WinDivert/"));
    }
}
