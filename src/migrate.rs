//! One-time move from the old name (RustyWire) to RustWarden, so settings, history, firewall rules, the
//! service, the start-with-Windows entry and shortcuts all carry over. Called at every start: the user-folder
//! move is a couple of existence checks once done, and the elevated part stops at [`DONE`].

use crate::settings::{admin_dir, data_dir, legacy_admin_dir};
use crate::sys::{autostart, is_elevated};
use std::path::{Path, PathBuf};

const OLD: &str = "RustyWire";
/// Written in the data folder when an elevated run has moved everything; later starts skip that part.
const DONE: &str = "migrated-from-rustywire";

/// Moves what `from` holds into `to`, keeping anything `to` already has; `from` goes once it is empty.
fn merge_dir(from: &Path, to: &Path) {
    if !from.is_dir() {
        return;
    }
    if !to.exists() && std::fs::rename(from, to).is_ok() {
        return;
    }
    let _ = std::fs::create_dir_all(to);
    for e in std::fs::read_dir(from).into_iter().flatten().flatten() {
        let dest = to.join(e.file_name());
        if e.path().is_dir() && dest.is_dir() {
            merge_dir(&e.path(), &dest);
        } else if !dest.exists() {
            let _ = std::fs::rename(e.path(), dest);
        }
    }
    let _ = std::fs::remove_dir(from);
}

/// Config and data folders, and the `rustywire.*` files (database, log) in the data folder.
fn move_user_data() {
    for var in ["APPDATA", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(var).map(PathBuf::from) {
            merge_dir(&base.join(OLD), &base.join("RustWarden"));
        }
    }
    let dir = data_dir();
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        if let Some(rest) = e.file_name().to_string_lossy().strip_prefix("rustywire") {
            let dest = dir.join(format!("rustwarden{rest}"));
            if !dest.exists() {
                let _ = std::fs::rename(e.path(), dest);
            }
        }
    }
}

/// Everything in the old Program Files folder but the driver (see `driver::retire_old_folder`) moves over, except
/// the old exe, which goes. Returns true when only the driver, or nothing, is left.
fn move_program_files(old: &Path) -> bool {
    let new = admin_dir();
    let _ = std::fs::create_dir_all(&new);
    for e in std::fs::read_dir(old).into_iter().flatten().flatten() {
        let name = e.file_name();
        if name == "driver" {
            continue;
        }
        if name.to_string_lossy().to_lowercase().starts_with("rustywire.exe") {
            let _ = std::fs::remove_file(e.path());
        } else if e.path().is_dir() {
            merge_dir(&e.path(), &new.join(&name));
        } else if !new.join(&name).exists() {
            let _ = std::fs::rename(e.path(), new.join(&name));
        }
    }
    std::fs::read_dir(old).is_ok_and(|d| d.flatten().all(|e| e.file_name() == "driver"))
}

/// Rule names saved in the database (the drift baseline, paused rules, leases) get the new name too.
fn rename_in_db() {
    let path = crate::live::db_path();
    if path.exists()
        && let Ok(db) = rusqlite::Connection::open(path)
    {
        let _ = db.execute("UPDATE kv SET v = replace(v, 'RustyWire', 'RustWarden') WHERE instr(v, 'RustyWire') > 0", []);
    }
}

/// Runs the migration. True when it reinstalled the service, which then opens the new window: this process should exit.
pub fn run() -> bool {
    let done = data_dir().join(DONE);
    let pending = is_elevated() && !done.exists();
    // First, so the old processes no longer hold the folders and database open.
    let had_service = pending && autostart::remove_legacy_service();
    move_user_data();
    if !pending {
        return false;
    }
    let me = std::env::current_exe().unwrap_or_default();
    let exe = if had_service { autostart::installed_exe().unwrap_or(me) } else { me };
    autostart::adopt_legacy_entries(&exe);
    let tidy = move_program_files(&legacy_admin_dir());
    rename_in_db();
    // Defender: the old driver folder's exclusion goes (`driver::retire_old_folder` also does, but only while the
    // folder exists); a driver already in the new folder gets its own.
    let _ = crate::sys::defender::remove_exclusion(&legacy_admin_dir().join("driver").to_string_lossy());
    if crate::driver::state_in(&crate::driver::dir()) == crate::driver::DriverState::Ready {
        let _ = crate::sys::defender::add_exclusion(&crate::driver::dir().to_string_lossy());
    }
    let rules = crate::live::firewall::adopt_legacy_rules(&exe.to_string_lossy());
    if let Err(e) = &rules {
        crate::applog::line("rustwarden.log", &format!("Moving the firewall rules to the RustWarden name failed: {e}"));
    }
    // Before the service starts the new window, which would otherwise run this again.
    if tidy && rules.is_ok() {
        let _ = std::fs::create_dir_all(data_dir());
        let _ = std::fs::write(done, "");
    }
    if !had_service {
        return false;
    }
    let reinstalled = autostart::install_elevated();
    if let Err(e) = &reinstalled {
        crate::applog::line("rustwarden.log", &format!("Reinstalling the service after the rename failed: {e}"));
    }
    reinstalled.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_what_the_new_folder_has() {
        let root = std::env::temp_dir().join(format!("rustwarden-migrate-test-{}", std::process::id()));
        let (old, new) = (root.join("old"), root.join("new"));
        std::fs::create_dir_all(old.join("sub")).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join("config.toml"), "old").unwrap();
        std::fs::write(old.join("sub").join("a"), "a").unwrap();
        std::fs::write(new.join("config.toml"), "new").unwrap();
        merge_dir(&old, &new);
        assert_eq!(std::fs::read_to_string(new.join("config.toml")).unwrap(), "new");
        assert!(new.join("sub").join("a").exists());
        // The clash stays behind rather than being lost.
        assert!(old.join("config.toml").exists() && !old.join("sub").exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
