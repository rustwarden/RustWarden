//! Offline IP-to-country lookup with a MaxMind database the user supplies (GeoLite2 or
//! GeoIP2, country or city edition). RustWarden does not bundle one: MaxMind's licence
//! terms for GeoLite2 require each user to accept them and download their own copy.

use super::net::{Locality, classify};
use crate::data::Country;
use maxminddb::{Reader, path};
use std::net::IpAddr;
use std::path::PathBuf;

/// Where the database is looked for when the settings don't name one.
pub fn default_db_path() -> PathBuf {
    crate::settings::data_dir().join("GeoLite2-Country.mmdb")
}

/// Where the city-level database lives; used for the map when `Settings::geoip_city` is on.
pub fn city_db_path() -> PathBuf {
    crate::settings::data_dir().join("dbip-city-lite.mmdb")
}

/// Where the optional DB-IP "IP to ASN Lite" database lives; only destination rules by AS number use it.
pub fn asn_db_path() -> PathBuf {
    crate::settings::data_dir().join("dbip-asn-lite.mmdb")
}

/// A database RustWarden can download, as the download confirmation describes it.
pub struct DbInfo {
    pub name: &'static str,
    /// The DB-IP edition: "country", "city" or "asn".
    pub edition: &'static str,
    pub used_for: &'static str,
    /// Rough download size, which also weights the overall progress bar.
    pub mb: u32,
}

pub const DATABASES: [DbInfo; 3] = [
    DbInfo { name: "Country database", edition: "country", used_for: "flags and countries", mb: 5 },
    DbInfo { name: "City database", edition: "city", used_for: "the city map", mb: 120 },
    DbInfo { name: "ASN database", edition: "asn", used_for: "AS number rules", mb: 8 },
];

pub fn db_path(edition: &str) -> PathBuf {
    match edition {
        "city" => city_db_path(),
        "asn" => asn_db_path(),
        _ => default_db_path(),
    }
}

/// Every network the ASN database at `path` assigns to `asn`, as (address, prefix length).
pub fn asn_networks(path: &std::path::Path, asn: u32) -> Result<Vec<(IpAddr, u8)>, String> {
    let reader = Reader::open_readfile(path).map_err(|e| format!("can't read {}: {e}", path.display()))?;
    let all = reader.networks(Default::default()).map_err(|e| format!("can't read {}: {e}", path.display()))?;
    Ok(all
        .filter_map(Result::ok)
        .filter(|l| l.decode_path::<u32>(&path!["autonomous_system_number"]).ok().flatten() == Some(asn))
        .filter_map(|l| l.network().ok().map(|n| (n.network(), n.prefix())))
        .collect())
}

/// Downloads the free DB-IP "IP to Country Lite" or "IP to City Lite" (`edition` "country" or "city";
/// CC BY 4.0, no account needed) to `dest`. Tries this month's release, then the two before. Blocking: run it off the UI thread.
/// Uses PowerShell so the app needs no HTTP client of its own.
/// `progress` is kept at 0..=100 for a progress bar.
pub fn download_dbip(dest: &std::path::Path, edition: &str, progress: &std::sync::atomic::AtomicU32) -> Result<(), String> {
    // Downloaded beside the real file and only swapped in once `verify` passes, so a bad file never replaces a good one.
    let part = dest.with_extension("mmdb.part");
    let r = download_script(&part, edition, progress).and_then(|()| verify(&part, edition));
    match r {
        Ok(()) => std::fs::rename(&part, dest).map_err(|e| format!("can't save {}: {e}", dest.display())),
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

/// Checks that `path` is the DB-IP database `edition` ("country", "city" or "asn"): it must open as a MaxMind DB
/// whose type names that edition and that holds data. A wrong, truncated or HTML-error file fails here.
pub fn verify(path: &std::path::Path, edition: &str) -> Result<(), String> {
    let reader = Reader::open_readfile(path).map_err(|e| format!("the downloaded file is not a valid database ({e})"))?;
    let kind = reader.metadata().database_type.to_ascii_lowercase();
    if !kind.contains("dbip") || !kind.contains(edition) {
        return Err(format!("the downloaded file is a \"{}\" database, not the {edition} one", reader.metadata().database_type));
    }
    if reader.metadata().node_count == 0 {
        return Err("the downloaded database is empty".into());
    }
    Ok(())
}

fn download_script(dest: &std::path::Path, edition: &str, progress: &std::sync::atomic::AtomicU32) -> Result<(), String> {
    use std::io::BufRead;
    use std::os::windows::process::CommandExt;
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dest = $env:CC_GEO_DEST
New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
$gz = "$dest.gz"; $tmp = "$dest.tmp"
$last = $null
foreach ($back in 0, 1, 2) {
    $month = (Get-Date).AddMonths(-$back).ToString('yyyy-MM')
    try {
        $resp = [Net.HttpWebRequest]::Create("https://download.db-ip.com/free/dbip-${env:CC_GEO_EDITION}-lite-$month.mmdb.gz").GetResponse()
        $len = $resp.ContentLength; $s = $resp.GetResponseStream(); $f = [IO.File]::Create($gz)
        $buf = New-Object byte[] 262144; $got = 0; $shown = -1
        while (($n = $s.Read($buf, 0, $buf.Length)) -gt 0) {
            $f.Write($buf, 0, $n); $got += $n
            if ($len -gt 0) { $p = [int](90 * $got / $len); if ($p -ne $shown) { $shown = $p; "P $p" } }
        }
        $f.Close(); $s.Close(); $resp.Close()
        $in = [IO.File]::OpenRead($gz); $z = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
        $out = [IO.File]::Create($tmp); $z.CopyTo($out); $out.Close(); $z.Close(); $in.Close()
        Move-Item -Force $tmp $dest; Remove-Item -Force $gz
        "P 100"
        exit 0
    } catch { $last = $_.Exception.Message }
}
Write-Error $last
exit 1
"#;
    let mut cmd = crate::sys::tool("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("CC_GEO_DEST", dest)
        .env("CC_GEO_EDITION", edition)
        .creation_flags(crate::sys::NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    progress.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut child = crate::sys::etw::spawn_own(&mut cmd).map_err(|e| format!("can't start PowerShell: {e}"))?;
    if let Some(stdout) = child.stdout.take() {
        for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(p) = line.strip_prefix("P ").and_then(|p| p.trim().parse().ok()) {
                progress.store(p, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    let out = child.wait_with_output().map_err(|e| format!("can't start PowerShell: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr);
        Err(format!("download failed: {}", msg.lines().find(|l| !l.trim().is_empty()).unwrap_or("unknown error").trim()))
    }
}

/// Background check: re-downloads each database already on disk once it is older than the update interval
/// (Settings > Countries & Network), if the setting is still on. A loaded database is only swapped on restart.
pub fn spawn_auto_update() {
    std::thread::spawn(|| {
        // Sleeps in one-second steps so exiting the app ends the thread (and starts no download).
        let nap = |secs: u64| {
            for _ in 0..secs {
                if QUIT.load(std::sync::atomic::Ordering::Relaxed) {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            !QUIT.load(std::sync::atomic::Ordering::Relaxed)
        };
        if !nap(60) {
            return;
        }
        loop {
            let s = crate::settings::Settings::load();
            let every = u64::from(s.geo_update_hours.max(1)) * 3600;
            if s.geo_auto_update {
                for (path, edition) in [(default_db_path(), "country"), (city_db_path(), "city")] {
                    let old = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age.as_secs() >= every);
                    if old {
                        let _ = download_dbip(&path, edition, &Default::default());
                    }
                }
            }
            if !nap(every.min(6 * 3600)) {
                return;
            }
        }
    });
}

/// Set when the app exits, to stop the auto-update thread.
pub static QUIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Place {
    /// Private, link-local or multicast address.
    Local,
    Country([u8; 2]),
    /// A public address the database doesn't know, or no database.
    Unknown,
}

impl Place {
    pub fn country(self) -> Country {
        match self {
            Place::Local => Country::Local,
            Place::Country(code) => Country::from_a2(code),
            Place::Unknown => Country::Other,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Place::Local => "Local Network",
            Place::Country(code) => Country::from_a2(code).name(),
            Place::Unknown => "Unknown",
        }
    }

    /// "LOCAL", the alpha-2 code, or "" — how alerts store it.
    pub fn code(self) -> String {
        match self {
            Place::Local => "LOCAL".into(),
            Place::Country(code) => String::from_utf8_lossy(&code).into_owned(),
            Place::Unknown => String::new(),
        }
    }
}

pub struct Geo {
    reader: Option<Reader<Vec<u8>>>,
    pub path: PathBuf,
    pub error: Option<String>,
}

impl Geo {
    pub fn open(configured: Option<&str>) -> Self {
        let path = configured.map(PathBuf::from).unwrap_or_else(default_db_path);
        match Reader::open_readfile(&path) {
            Ok(reader) => Self { reader: Some(reader), path, error: None },
            Err(e) => {
                let error = if path.exists() { Some(format!("can't read {}: {e}", path.display())) } else { None };
                Self { reader: None, path, error }
            }
        }
    }

    /// The open database is the downloaded city edition.
    pub fn city_db(&self) -> bool {
        self.reader.is_some() && self.path == city_db_path()
    }

    pub fn available(&self) -> bool {
        self.reader.is_some()
    }

    /// A database file showed up where there was none. A file that exists but can't be read is not retried here.
    pub fn appeared(&self) -> bool {
        self.reader.is_none() && self.error.is_none() && self.path.exists()
    }

    pub fn place(&self, ip: IpAddr) -> Place {
        match classify(ip) {
            Locality::Local | Locality::Loopback => return Place::Local,
            Locality::Wan => {}
        }
        let Some(reader) = &self.reader else { return Place::Unknown };
        let code = reader.lookup(ip).ok().and_then(|r| r.decode_path::<String>(&path!["country", "iso_code"]).ok().flatten()).and_then(|c| crate::countries::parse_a2(&c));
        code.map_or(Place::Unknown, Place::Country)
    }

    /// Every network the database places in `code`, as (address, prefix length). Walks the whole
    /// database (about 0.3 s), so callers keep the result.
    pub fn country_networks(&self, code: [u8; 2]) -> Vec<(IpAddr, u8)> {
        let Some(reader) = &self.reader else { return Vec::new() };
        let Ok(all) = reader.networks(Default::default()) else { return Vec::new() };
        let want = String::from_utf8_lossy(&code).into_owned();
        all.filter_map(Result::ok)
            .filter(|l| l.decode_path::<String>(&path!["country", "iso_code"]).ok().flatten().is_some_and(|c| c.eq_ignore_ascii_case(&want)))
            .filter_map(|l| l.network().ok().map(|n| (n.network(), n.prefix())))
            .collect()
    }

    /// City name from a city edition, for the map labels.
    pub fn city(&self, ip: IpAddr) -> Option<String> {
        self.reader.as_ref()?.lookup(ip).ok()?.decode_path::<String>(&path!["city", "names", "en"]).ok().flatten()
    }

    /// (lon, lat) for the map: the database's own coordinates when it has them (city editions),
    /// otherwise the country's centre from the built-in table.
    pub fn position(&self, ip: IpAddr, place: Place) -> Option<(f32, f32)> {
        if let Some(reader) = &self.reader
            && let Ok(r) = reader.lookup(ip)
        {
            let lat = r.decode_path::<f64>(&path!["location", "latitude"]).ok().flatten();
            let lon = r.decode_path::<f64>(&path!["location", "longitude"]).ok().flatten();
            if let (Some(lat), Some(lon)) = (lat, lon) {
                return Some((lon as f32, lat as f32));
            }
        }
        match place {
            Place::Country(code) => crate::countries::by_a2(code).map(|e| (e.lon, e.lat)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn verify_refuses_a_file_that_is_not_a_database() {
        let path = std::env::temp_dir().join("rustwarden-not-a-db.mmdb");
        std::fs::write(&path, "<html>rate limited</html>").unwrap();
        assert!(super::verify(&path, "country").is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn country_networks_cover_addresses_the_database_places_there() {
        // Needs the user's country database; passes without one.
        let g = Geo::open(None);
        if !g.available() {
            return;
        }
        let nets = g.country_networks(*b"DE");
        assert!(nets.len() > 1000);
        let mut set = crate::destrules::RangeSet::new();
        for (ip, prefix) in &nets {
            set.add_net(*ip, *prefix);
        }
        set.tidy();
        let (ip, _) = nets[0];
        assert_eq!(g.place(ip), Place::Country(*b"DE"));
        assert!(set.contains(ip));
    }

    use super::*;

    #[test]
    fn without_a_database_public_addresses_are_unknown_and_private_are_local() {
        let geo = Geo { reader: None, path: PathBuf::new(), error: None };
        assert_eq!(geo.place("192.168.1.1".parse().unwrap()), Place::Local);
        assert_eq!(geo.place("8.8.8.8".parse().unwrap()), Place::Unknown);
        assert_eq!(Place::Unknown.label(), "Unknown");
        assert_eq!(Place::Local.country(), Country::Local);
        assert_eq!(Place::Country(*b"DE").country(), Country::Germany);
        assert_eq!(Place::Country(*b"JP").code(), "JP");
    }

    #[test]
    fn missing_file_is_not_an_error_message() {
        let geo = Geo::open(Some(r"Z:\nope\missing.mmdb"));
        assert!(!geo.available());
        assert!(geo.error.is_none());
    }
}
