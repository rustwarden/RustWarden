//! "Clean up": RustWarden has no installer, so everything it downloads stays on disk until the user removes it here.
//! The history database, config and firewall rules are not touched; they have their own controls.

use crate::settings::Settings;
use crate::util::fmt_bytes;
use std::path::{Path, PathBuf};

/// What RustWarden downloads, with where it lives.
pub fn targets() -> Vec<(&'static str, PathBuf)> {
    vec![
        ("speedtest-cli (Network > Speedtest)", crate::sys::helper::dir("speedtest")),
        ("GeoIP country database", crate::live::geo::default_db_path()),
        ("GeoIP city database", crate::live::geo::city_db_path()),
        ("ASN database", crate::live::geo::asn_db_path()),
        ("Malicious IP lists", crate::live::threat::cache_path()),
        ("Malicious domain list", crate::live::dns::cache_path()),
        ("ThinkBroadband Quality Monitor sign-in", crate::sys::webview::profile_dir()),
    ]
}

/// Size of a file or of everything under a folder.
fn size(path: &Path) -> u64 {
    match std::fs::metadata(path) {
        Ok(m) if m.is_dir() => std::fs::read_dir(path).map_or(0, |d| d.flatten().map(|e| size(&e.path())).sum()),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

/// The text of the confirmation: what is there now, and what switches off.
pub fn warning() -> String {
    let found: Vec<String> = targets().into_iter().filter(|(_, p)| p.exists()).map(|(name, p)| format!("  • {name} ({})", fmt_bytes(size(&p) as f64))).collect();
    let list = if found.is_empty() { "Nothing has been downloaded, so there is nothing to delete.".to_owned() } else { format!("This deletes:\n{}", found.join("\n")) };
    format!(
        "{list}\n\nIt also switches off what used them: the Speedtest plugin and its schedule, the city map and database updates, Malicious IP protection and the ThinkBroadband Quality Monitor plugin. You can turn them on again in Settings (and download again where needed).\n\nYour history, alerts, firewall rules and settings are kept. This cannot be undone."
    )
}

/// Switches off the features that need the downloaded files.
pub fn disable(s: &mut Settings) {
    s.plugins.entry("speedtest".to_owned()).or_default().enabled = false;
    s.geoip_city = false;
    s.geo_auto_update = false;
    s.threat_protect = false;
    s.plugins.entry("thinkbroadband".to_owned()).or_default().enabled = false;
}

/// Deletes `paths` (missing ones are fine); returns the bytes freed and what could not be removed.
pub fn remove(paths: &[PathBuf]) -> (u64, Vec<String>) {
    let (mut freed, mut failed) = (0, Vec::new());
    for p in paths.iter().filter(|p| p.exists()) {
        let bytes = size(p);
        match if p.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) } {
            Ok(()) => freed += bytes,
            Err(e) => failed.push(format!("{}: {e}", p.display())),
        }
    }
    (freed, failed)
}

/// Deletes everything in `targets` and reports it as the toast text.
pub fn run() -> Result<String, String> {
    let paths: Vec<PathBuf> = targets().into_iter().map(|(_, p)| p).collect();
    let (freed, failed) = remove(&paths);
    if failed.is_empty() { Ok(format!("Removed downloaded components ({} freed)", fmt_bytes(freed as f64))) } else { Err(format!("Some files could not be removed: {}", failed.join("; "))) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_files_and_folders_and_ignores_missing() {
        let dir = std::env::temp_dir().join(format!("rw_cleanup_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.mmdb"), [0u8; 10]).unwrap();
        std::fs::write(dir.join("sub").join("b.exe"), [0u8; 20]).unwrap();
        let (freed, failed) = remove(&[dir.join("a.mmdb"), dir.join("sub"), dir.join("missing")]);
        assert_eq!((freed, failed.len()), (30, 0));
        assert!(!dir.join("a.mmdb").exists() && !dir.join("sub").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disables_the_features_that_use_downloads() {
        let mut s = Settings::default();
        (s.threat_protect, s.geoip_city) = (true, true);
        s.plugins.insert("speedtest".into(), crate::settings::PluginState { enabled: true, ..Default::default() });
        disable(&mut s);
        assert!(!s.threat_protect && !s.geoip_city && !s.plugins["speedtest"].enabled);
    }
}
