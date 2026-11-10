//! Self-update from the private GitHub repo's releases, through the user's update server (Settings > Other):
//! a script that holds the GitHub token and lists releases (`?updatecheck=true`, added here, never typed by the
//! user) with direct download links. Everything goes through `curl.exe`; the download is only installed if its SHA-256 matches the
//! `RustWarden.exe.sha256` asset published beside it, and that file carries an ECDSA P-256 signature
//! (`RustWarden.exe.sha256.sig`, made in CI with a key only the repo's secrets hold) that must verify
//! against the public key built in below. A tampered release or a hostile update server can't pass that.

use crate::settings::UpdateChannel;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// From 1.0.0 the code is public and releases are read straight from GitHub, so no update server is needed.
const PUBLIC_RELEASES: &str = "https://api.github.com/repos/rustwarden/RustWarden/releases?per_page=30";

/// True for 1.0.0 and later: the update server setting is then ignored and hidden.
pub fn uses_public_repo() -> bool {
    public_from(env!("CARGO_PKG_VERSION"))
}

fn public_from(version: &str) -> bool {
    version_parts(version)[0] >= 1
}

/// Query the update server is asked with; hardcoded so the user only enters the address of the script.
const CHECK_QUERY: &str = "updatecheck=true";
/// Release assets are named after the exe. Releases made right after the rebrand carry `RustWarden.exe*`, earlier and later ones
/// `RustyWire.exe*`, so both are accepted (the current name first).
const ASSET_STEMS: [&str; 2] = ["RustWarden.exe", "RustyWire.exe"];
const SHA_SUFFIX: &str = ".sha256";
const SIG_SUFFIX: &str = ".sha256.sig";
/// Public half of the release signing key (uncompressed P-256 point; the private half is the repo secret `UPDATE_SIGNING_KEY`).
const SIGNING_KEY: [u8; 65] = [
    0x04, 0x2e, 0x58, 0x1b, 0x53, 0xe1, 0xf5, 0xc3, 0x00, 0x4f, 0x43, 0x8e, 0x22, 0x78, 0x03, 0x6b, 0x27, 0x71, 0x1d, 0x19, 0xb0, 0x90, 0x33, 0x5b, 0xa1, 0xd3, 0x6d, 0x72, 0xc6, 0x67, 0x78, 0xaf,
    0x9e, 0x24, 0x27, 0x9f, 0xb4, 0xc5, 0xe4, 0xcb, 0x7d, 0x73, 0x82, 0xd0, 0x0e, 0x59, 0xb4, 0x0b, 0xc2, 0xc1, 0x4a, 0x2d, 0x81, 0x1f, 0xb9, 0xeb, 0xa5, 0x70, 0xd9, 0xee, 0x23, 0x2a, 0x7f, 0xb9,
    0x9f,
];

/// A newer release than the running one.
#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    /// Newest first: every release newer than the running one (`missed`), padded with older ones to a few entries.
    pub history: Vec<Note>,
    exe_url: String,
    exe_size: u64,
    sha_url: String,
    sig_url: String,
}

/// One release's notes in the update dialog.
#[derive(Clone, Debug)]
pub struct Note {
    pub version: String,
    pub notes: String,
    /// Newer than the running version.
    pub missed: bool,
}

/// Entries the dialog shows at least, so a one-version jump still has context (the app changes fast).
const MIN_NOTES: usize = 10;
/// Most entries shown, so a long-skipped install doesn't get a wall of text.
const MAX_NOTES: usize = 15;

#[derive(Deserialize)]
struct Api {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    /// The update server's direct link (a GitHub API address when read from GitHub, which needs a token header).
    url: String,
    /// GitHub's public download link; empty when the update server listed the release.
    #[serde(default)]
    browser_download_url: String,
    #[serde(default)]
    size: u64,
    name: String,
}

impl ApiAsset {
    fn link(&self) -> String {
        if self.browser_download_url.is_empty() { self.url.clone() } else { self.browser_download_url.clone() }
    }
}

impl Api {
    /// A dev build: flagged as a pre-release, or tagged `-dev` (an older server script doesn't send the flag).
    fn is_dev(&self) -> bool {
        self.prerelease || self.tag_name.ends_with("-dev")
    }
}

/// What a check found.
pub enum Checked {
    /// The running version is the newest; its latest few releases' notes, newest first.
    Latest(Vec<Note>),
    Newer(Release),
}

pub fn check(server: &str, channel: UpdateChannel) -> Result<Checked, String> {
    let url = if uses_public_repo() { PUBLIC_RELEASES.to_owned() } else { check_url(server)? };
    let (status, body) = get(&url, "application/json", None)?;
    expect_ok(status)?;
    let all: Vec<Api> = serde_json::from_slice(&body).map_err(|e| format!("Unexpected answer from the update server ({e})"))?;
    let mut all: Vec<Api> = all.into_iter().filter(|r| !r.draft && r.is_dev() == (channel == UpdateChannel::Dev)).collect();
    all.sort_by_key(|a| std::cmp::Reverse(version_parts(&a.tag_name)));
    // A release whose files are still being uploaded (or missing one) is skipped for the newest complete one.
    let complete = |r: &&Api| ["", SHA_SUFFIX, SIG_SUFFIX].iter().all(|s| find_asset(&r.assets, s).is_some());
    let Some(api) = all.iter().find(complete).or(all.first()) else { return Ok(Checked::Latest(Vec::new())) };
    let version = api.tag_name.trim_start_matches('v').to_owned();
    // Leaving dev for Release offers the latest release even though its number is lower than the dev build's.
    let leaving_dev = channel == UpdateChannel::Release && env!("CARGO_PKG_VERSION").ends_with("-dev");
    // Nothing is offered when the newest complete release is not newer than this one (a newer one is still uploading).
    let missed = if leaving_dev {
        1
    } else if is_newer(&api.tag_name, env!("CARGO_PKG_VERSION")) {
        all.iter().filter(|r| is_newer(&r.tag_name, env!("CARGO_PKG_VERSION"))).count()
    } else {
        0
    };
    let history: Vec<Note> = all
        .iter()
        .take(missed.clamp(MIN_NOTES, MAX_NOTES))
        .enumerate()
        .map(|(i, r)| Note { version: r.tag_name.trim_start_matches('v').to_owned(), notes: r.body.clone().unwrap_or_default(), missed: i < missed })
        .collect();
    if missed == 0 {
        return Ok(Checked::Latest(history));
    }
    let url = |suffix: &str| find_asset(&api.assets, suffix).map(ApiAsset::link).ok_or_else(|| format!("Release {version} has no {}{suffix} file", ASSET_STEMS[0]));
    let exe_size = find_asset(&api.assets, "").map_or(0, |a| a.size);
    Ok(Checked::Newer(Release { exe_url: url("")?, exe_size, sha_url: url(SHA_SUFFIX)?, sig_url: url(SIG_SUFFIX)?, history, version }))
}

/// The release asset named after the exe plus `suffix`, under either exe name.
fn find_asset<'a>(assets: &'a [ApiAsset], suffix: &str) -> Option<&'a ApiAsset> {
    ASSET_STEMS.iter().find_map(|stem| assets.iter().find(|a| a.name == format!("{stem}{suffix}")))
}

/// Percent (0..=100) of the new exe downloaded so far; 0 until the download starts or when the size is unknown.
pub static PROGRESS: AtomicU32 = AtomicU32::new(0);

/// Downloads the release next to the running exe, checks its SHA-256, swaps it in and returns the exe's path.
/// The running exe is renamed to `.old` (Windows allows that, not deleting), so a restart picks up the new one.
pub fn install(rel: &Release) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let new = exe.with_extension("exe.new");
    let old = exe.with_extension("exe.old");
    let dir = exe.parent().ok_or("RustWarden's folder is unknown")?;

    let wanted = download_sha(&rel.sha_url, &rel.sig_url, &rel.version)?;
    let _ = std::fs::remove_file(&new);
    let name = new.file_name().and_then(|n| n.to_str()).ok_or("Bad file name")?;
    PROGRESS.store(0, Ordering::Relaxed);
    // curl writes straight to the file, so its growth against the published size is the progress.
    let done = AtomicBool::new(false);
    let got = std::thread::scope(|s| {
        s.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                if let (Ok(m), true) = (std::fs::metadata(&new), rel.exe_size > 0) {
                    PROGRESS.store((m.len() * 100 / rel.exe_size).min(100) as u32, Ordering::Relaxed);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        let r = get(&rel.exe_url, "application/octet-stream", Some((dir, name)));
        done.store(true, Ordering::Relaxed);
        r
    });
    let (status, _) = got?;
    let verified = expect_ok(status).and_then(|()| verify(&new, &wanted));
    if let Err(e) = verified {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }

    // A leftover `.old` that is still locked (the service runs from it) can be renamed but not deleted; move it aside, `cleanup` removes it later.
    if old.exists() && std::fs::remove_file(&old).is_err() {
        let aside = exe.with_extension(format!("exe.old{}", crate::clock::now_unix()));
        if let Err(e) = std::fs::rename(&old, &aside) {
            let _ = std::fs::remove_file(&new);
            return Err(format!("Could not move the previous update's .exe.old aside ({e})"));
        }
    }
    std::fs::rename(&exe, &old).map_err(|e| format!("Could not replace the running exe ({e}). Run RustWarden as administrator if it is installed in Program Files."))?;
    if let Err(e) = std::fs::rename(&new, &exe) {
        let _ = std::fs::rename(&old, &exe);
        let _ = std::fs::remove_file(&new);
        return Err(format!("Could not put the new exe in place ({e})"));
    }
    Ok(exe)
}

/// Removes files an earlier update left behind.
pub fn cleanup() {
    let Ok(exe) = std::env::current_exe() else { return };
    let _ = std::fs::remove_file(exe.with_extension("exe.new"));
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_stem().and_then(|s| s.to_str())) else { return };
    let prefix = format!("{name}.exe.old");
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The address to list releases from: the user's server address plus the hardcoded query. Both channels use the same
/// address; the check picks the builds of its channel from the list.
fn check_url(server: &str) -> Result<String, String> {
    let server = server.trim();
    if server.is_empty() {
        return Err("No update server set (Settings > Other > Update server)".into());
    }
    let base = server.split('#').next().unwrap_or("");
    let (path, query) = base.split_once('?').unwrap_or((base, ""));
    let query = if query.contains(CHECK_QUERY) {
        query.to_owned()
    } else if query.is_empty() {
        CHECK_QUERY.to_owned()
    } else {
        format!("{query}&{CHECK_QUERY}")
    };
    Ok(format!("{path}?{query}"))
}

/// The signed checksum file names the version too, so a server can't pass an old signed build off as a new release.
fn download_sha(sha_url: &str, sig_url: &str, version: &str) -> Result<String, String> {
    let (status, body) = get(sha_url, "application/octet-stream", None)?;
    expect_ok(status)?;
    let (status, sig) = get(sig_url, "application/octet-stream", None)?;
    expect_ok(status)?;
    check_signature(&SIGNING_KEY, &body, &sig)?;
    let text = String::from_utf8_lossy(&body);
    if signed_version(&text) != Some(version) {
        return Err("The release's signed version does not match its name. Nothing was installed.".into());
    }
    parse_sha(&text)
}

/// The `version=` line of the checksum file.
fn signed_version(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.trim().strip_prefix("version="))
}

/// The release's checksum file must carry a valid ECDSA P-256 (SHA-256) signature from the release key,
/// checked by Windows CNG. `sig` is the DER form `openssl dgst -sha256 -sign` writes.
fn check_signature(key: &[u8; 65], signed: &[u8], sig: &[u8]) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use windows::Win32::Security::Cryptography::{
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALG_HANDLE, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE, BCryptDestroyKey, BCryptImportKeyPair, BCryptVerifySignature,
    };
    let bad = || "The release's signature is not valid. Nothing was installed.".to_owned();
    if key[0] != 4 {
        return Err(bad());
    }
    let raw = der_to_raw(sig).ok_or_else(bad)?;
    let mut blob = Vec::with_capacity(8 + 64);
    blob.extend_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
    blob.extend_from_slice(&32u32.to_le_bytes());
    blob.extend_from_slice(&key[1..]);
    let hash = Sha256::digest(signed);
    let mut handle = BCRYPT_KEY_HANDLE::default();
    unsafe {
        if BCryptImportKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, None, BCRYPT_ECCPUBLIC_BLOB, &mut handle, &blob, 0).is_err() {
            return Err(bad());
        }
        let ok = BCryptVerifySignature(handle, None, &hash, &raw, BCRYPT_FLAGS(0)).is_ok();
        let _ = BCryptDestroyKey(handle);
        if ok { Ok(()) } else { Err(bad()) }
    }
}

/// `SEQUENCE { INTEGER r, INTEGER s }` to the 64-byte r||s form CNG wants.
fn der_to_raw(der: &[u8]) -> Option<[u8; 64]> {
    fn int(b: &[u8]) -> Option<(&[u8], &[u8])> {
        let (&tag, b) = b.split_first()?;
        let (&len, b) = b.split_first()?;
        if tag != 2 || len >= 0x80 || b.len() < len as usize {
            return None;
        }
        Some(b.split_at(len as usize))
    }
    let (&tag, rest) = der.split_first()?;
    let (&len, rest) = rest.split_first()?;
    if tag != 0x30 || len >= 0x80 || rest.len() != len as usize {
        return None;
    }
    let (r, rest) = int(rest)?;
    let (s, rest) = int(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, v) in [r, s].into_iter().enumerate() {
        let v = &v[v.iter().position(|&b| b != 0).unwrap_or(v.len())..];
        if v.is_empty() || v.len() > 32 {
            return None;
        }
        out[i * 32 + 32 - v.len()..(i + 1) * 32].copy_from_slice(v);
    }
    Some(out)
}

/// The hash is the first word of the `.sha256` file (an optional file name may follow).
fn parse_sha(text: &str) -> Result<String, String> {
    let word = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    if word.len() == 64 && word.bytes().all(|b| b.is_ascii_hexdigit()) { Ok(word) } else { Err("The published checksum file is not a SHA-256 hash".into()) }
}

fn verify(file: &Path, wanted: &str) -> Result<(), String> {
    let mut head = [0u8; 2];
    let is_exe = std::fs::File::open(file).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok() && &head == b"MZ";
    if !is_exe {
        return Err("The download is not a Windows program".into());
    }
    let got = crate::sys::apps::hash_file(&file.to_string_lossy());
    if got.is_empty() {
        return Err("Could not read the downloaded file".into());
    }
    if got != wanted {
        return Err(format!("Checksum mismatch: the download's SHA-256 is {got}, the release says {wanted}. Nothing was installed."));
    }
    Ok(())
}

fn expect_ok(status: u32) -> Result<(), String> {
    match status {
        200 => Ok(()),
        // GitHub answers 403 (or 429) when this IP has used up the API's limit for visitors who aren't signed in.
        403 | 429 => Err("Updates are not available right now (GitHub's request limit was reached). Try again later.".into()),
        404 => Err("The update server was not found (HTTP 404). Check the address in Settings".into()),
        0 => Err("Could not reach the update server".into()),
        s => Err(format!("The update server answered HTTP {s}")),
    }
}

/// GET `url`. With `save` = (folder, file name) the body goes to that file and the returned body is empty.
/// Returns (http status, body); status 0 means curl failed.
pub(crate) fn get(url: &str, accept: &str, save: Option<(&Path, &str)>) -> Result<(u32, Vec<u8>), String> {
    // The address goes into a curl config file, so anything that could break out of its quotes is refused.
    if !url.starts_with("https://") || url.bytes().any(|b| b <= b' ' || b == b'"' || b == b'\\' || b == 0x7f) {
        return Err("The update server address must be a plain https:// address".into());
    }
    let mut config = format!("silent\nlocation\nmax-time = {}\nwrite-out = \"\\n%{{http_code}}\"\nheader = \"Accept: {accept}\"\nurl = \"{url}\"\n", if save.is_some() { 600 } else { 30 });
    if let Some((_, name)) = save {
        config.push_str(&format!("output = \"{name}\"\n"));
    }
    let out = crate::sys::curl::run(&config, save.map(|(dir, _)| dir))?.stdout;
    let cut = out.iter().rposition(|&b| b == b'\n').unwrap_or(0);
    let status = String::from_utf8_lossy(&out[cut..]).trim().parse().unwrap_or(0);
    Ok((status, out[..cut].to_vec()))
}

fn version_parts(v: &str) -> Vec<u64> {
    // "0.99.3-dev" counts as 0.99.3
    let mut p: Vec<u64> = v.trim_start_matches('v').split('-').next().unwrap_or("").split('.').map(|p| p.parse().unwrap_or(0)).collect();
    while p.len() < 3 {
        p.push(0);
    }
    p
}

/// True when dotted version `a` is greater than `b` (missing parts count as 0).
fn is_newer(a: &str, b: &str) -> bool {
    let (a, b) = (version_parts(a), version_parts(b));
    (0..a.len().max(b.len())).map(|i| (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0))).find(|(x, y)| x != y).is_some_and(|(x, y)| x > y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(is_newer("0.14.1", "0.14.0"));
        assert!(is_newer("0.15", "0.14.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.14.0", "0.14.0"));
        assert!(!is_newer("0.14", "0.14.0"));
        assert!(!is_newer("0.13.9", "0.14.0"));
        assert!(is_newer("v0.99.4-dev", "0.99.3-dev"));
        assert!(!is_newer("0.99.3-dev", "0.99.3"));
    }

    #[test]
    fn finds_assets_under_either_exe_name() {
        let a = |n: &str| ApiAsset { url: n.into(), browser_download_url: String::new(), size: 1, name: n.into() };
        let old = [a("RustyWire.exe"), a("RustyWire.exe.sha256")];
        let rebranded = [a("RustWarden.exe"), a("RustWarden.exe.sha256.sig")];
        assert_eq!(find_asset(&old, SHA_SUFFIX).unwrap().url, "RustyWire.exe.sha256");
        assert_eq!(find_asset(&rebranded, "").unwrap().url, "RustWarden.exe");
        assert_eq!(find_asset(&rebranded, SIG_SUFFIX).unwrap().url, "RustWarden.exe.sha256.sig");
        assert!(find_asset(&old, SIG_SUFFIX).is_none());
    }

    #[test]
    fn version_one_reads_releases_from_github() {
        assert!(!public_from("0.99.190"));
        assert!(!public_from("0.99.190-dev"));
        assert!(public_from("1.0.0"));
        assert!(public_from("1.2.3-dev"));
        let github = ApiAsset { url: "https://api.github.com/a".into(), browser_download_url: "https://github.com/b".into(), size: 1, name: "x".into() };
        assert_eq!(github.link(), "https://github.com/b");
    }

    #[test]
    fn reads_the_checksum_file() {
        let h = "A".repeat(64);
        assert_eq!(parse_sha(&format!("{h}  RustyWire.exe\n")).unwrap(), "a".repeat(64));
        assert!(parse_sha("not a hash").is_err());
        assert!(parse_sha("").is_err());
    }

    #[test]
    fn reads_the_signed_version() {
        let h = "a".repeat(64);
        assert_eq!(signed_version(&format!("{h}\nversion=0.99.9\n")), Some("0.99.9"));
        assert_eq!(signed_version(&format!("{h}  RustyWire.exe\n")), None);
        assert_eq!(parse_sha(&format!("{h}\nversion=0.99.9\n")).unwrap(), h);
    }

    #[test]
    fn refuses_a_wrong_hash() {
        let dir = std::env::temp_dir().join("rustwarden-update-test");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("x.exe");
        std::fs::write(&file, b"MZ fake program").unwrap();
        let real = crate::sys::apps::hash_file(&file.to_string_lossy());
        assert!(verify(&file, &real).is_ok());
        assert!(verify(&file, &"0".repeat(64)).unwrap_err().contains("mismatch"));
        std::fs::write(&file, b"not an exe").unwrap();
        assert!(verify(&file, &crate::sys::apps::hash_file(&file.to_string_lossy())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn checks_the_release_signature() {
        let hex = |t: &str| -> Vec<u8> { (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect() };
        // A throwaway key's signature of "abc", made with `openssl dgst -sha256 -sign`.
        let key: [u8; 65] = hex("04bb5a1fe047d0ae5915b39935baceadf89882bd6f5ec3fa248d8cceee033d395261ce2fa8d4c47d78a69e81eed9e22cdb7b4c5fab11a1c1f296fa54d54d1dc46b").try_into().unwrap();
        let sig = hex("3046022100d08afd1c739ec480ff0553a8342c3eaaabdb8c24352ab3ce1efe47433b476f83022100c404a6946fff08c83e737aec3e845f3bb19dc968da3b3af906355cee4c18a189");
        assert!(check_signature(&key, b"abc", &sig).is_ok());
        assert!(check_signature(&key, b"abd", &sig).is_err());
        assert!(check_signature(&key, b"abc", &sig[..10]).is_err());
        assert!(check_signature(&SIGNING_KEY, b"abc", &sig).is_err());
    }

    #[test]
    fn a_rate_limited_check_says_updates_are_unavailable() {
        for status in [403, 429] {
            assert!(expect_ok(status).unwrap_err().starts_with("Updates are not available"));
        }
        assert!(expect_ok(200).is_ok());
        assert!(expect_ok(500).unwrap_err().contains("500"));
    }

    #[test]
    fn refuses_odd_urls() {
        assert!(get("http://x", "a", None).is_err());
        assert!(get("https://x/\"\nurl = \"evil", "a", None).unwrap_err().contains("https://"));
        assert!(get("https://x/a b", "a", None).is_err());
    }

    #[test]
    fn builds_the_check_url() {
        assert_eq!(check_url("https://x.com/u.php").unwrap(), "https://x.com/u.php?updatecheck=true");
        assert_eq!(check_url(" https://x.com/u.php?k=1 ").unwrap(), "https://x.com/u.php?k=1&updatecheck=true");
        assert_eq!(check_url("https://x.com/u.php?updatecheck=true").unwrap(), "https://x.com/u.php?updatecheck=true");
        assert!(check_url("").is_err());
        assert_eq!(check_url("https://x.com/up/").unwrap(), "https://x.com/up/?updatecheck=true");
    }

    #[test]
    fn dev_builds_are_told_apart_without_the_flag() {
        let api = |tag: &str, prerelease| Api { tag_name: tag.into(), draft: false, prerelease, body: None, assets: Vec::new() };
        assert!(api("v0.99.10-dev", false).is_dev());
        assert!(api("v0.99.10", true).is_dev());
        assert!(!api("v0.99.2", false).is_dev());
    }
}
