//! The Windows programs "Block Windows components that don't need internet" cuts off. Edge, WebView2,
//! the Store and App Installer are deliberately not here: they are left to the user, rule by rule.

use super::apps::{file_name, system_root};

pub struct Target {
    pub name: &'static str,
    /// Paths with `{win}` / `{pf}` for the Windows and Program Files folders and at most one `*` per
    /// folder or file name. A System32 path also covers its SysWOW64 twin.
    pub files: &'static [&'static str],
    pub what: &'static str,
    /// What the user may notice; empty means nothing.
    pub effect: &'static str,
}

pub struct Group {
    pub title: &'static str,
    pub intro: &'static str,
    pub targets: &'static [Target],
}

const fn t(name: &'static str, files: &'static [&'static str], what: &'static str, effect: &'static str) -> Target {
    Target { name, files, what, effect }
}

pub const GROUPS: &[Group] = &[
    Group {
        title: "Tools that malware uses to download things",
        intro: "Normal programs never need these to reach the internet, but attackers use them because they are already on every PC.",
        targets: &[
            t("certutil", &[r"{win}\System32\certutil.exe"], "A certificate command-line tool. Attackers abuse it to download files.", ""),
            t(
                "bitsadmin",
                &[r"{win}\System32\bitsadmin.exe"],
                "An old command for the background-transfer service. Abused to fetch malware. Windows Update uses the service itself, not this tool.",
                "",
            ),
            t("mshta", &[r"{win}\System32\mshta.exe"], "Runs old web-style mini programs (.hta). A common malware launcher.", ""),
            t("regsvr32", &[r"{win}\System32\regsvr32.exe"], "Registers add-ins. Can be tricked into loading code from a web address.", ""),
            t("hh (Help viewer)", &[r"{win}\hh.exe", r"{win}\System32\hh.exe"], "Opens old .chm help files, which can pull in and run remote content.", "Old help files can't load web content."),
            t("certreq", &[r"{win}\System32\certreq.exe"], "Certificate request tool; can send and fetch data.", ""),
            t("cmstp", &[r"{win}\System32\cmstp.exe"], "Installs VPN connection profiles; abused to run remote scripts.", ""),
            t(
                "wscript / cscript",
                &[r"{win}\System32\wscript.exe", r"{win}\System32\cscript.exe"],
                "Run .vbs and .js script files, the usual way e-mailed scripts download malware.",
                "A script of your own that fetches from the internet will stop working.",
            ),
            t(
                "ftp, tftp, telnet, finger",
                &[r"{win}\System32\ftp.exe", r"{win}\System32\tftp.exe", r"{win}\System32\telnet.exe", r"{win}\System32\finger.exe"],
                "Ancient command-line network tools nobody uses by accident but handy for stealing data.",
                "The commands can't connect.",
            ),
            t(
                "Utility programs",
                &[
                    r"{win}\System32\esentutl.exe",
                    r"{win}\System32\expand.exe",
                    r"{win}\System32\extrac32.exe",
                    r"{win}\System32\replace.exe",
                    r"{win}\System32\forfiles.exe",
                    r"{win}\System32\pcalua.exe",
                    r"{win}\System32\infdefaultinstall.exe",
                    r"{win}\System32\odbcconf.exe",
                    r"{win}\System32\ieexec.exe",
                    r"{win}\System32\presentationhost.exe",
                    r"{win}\System32\syncappvpublishingserver.exe",
                    r"{win}\System32\mavinject.exe",
                    r"{win}\Microsoft.NET\Framework*\v*\installutil.exe",
                    r"{win}\Microsoft.NET\Framework*\v*\regasm.exe",
                    r"{win}\Microsoft.NET\Framework*\v*\regsvcs.exe",
                ],
                "File, driver and .NET helper tools (esentutl, expand, extrac32, replace, forfiles, pcalua, infdefaultinstall, odbcconf, ieexec, presentationhost, syncappvpublishingserver, mavinject, installutil, regasm, regsvcs) with no internet role that attackers borrow to fetch or run code.",
                "",
            ),
        ],
    },
    Group {
        title: "Reporting back to Microsoft",
        intro: "Programs that send usage data and crash reports. Windows Update is not touched.",
        targets: &[
            t(
                "Compatibility Telemetry (CompatTelRunner)",
                &[r"{win}\System32\CompatTelRunner.exe"],
                "Scans your PC and sends app and usage data to Microsoft.",
                "Windows upgrade assistants may skip their online compatibility check.",
            ),
            t("Customer Experience data (wsqmcons)", &[r"{win}\System32\wsqmcons.exe"], "Sends \"Customer Experience\" usage data.", ""),
            t("Device Census", &[r"{win}\System32\DeviceCensus.exe"], "Reports your hardware details to Microsoft.", ""),
            t("Diagnostics collector", &[r"{win}\System32\DiagnosticsHub.StandardCollector.Service.exe"], "Collects diagnostic traces.", ""),
            t(
                "Error Reporting (WerFault, WerFaultSecure, wermgr)",
                &[r"{win}\System32\WerFault.exe", r"{win}\System32\WerFaultSecure.exe", r"{win}\System32\wermgr.exe"],
                "Uploads crash reports when a program fails.",
                "You still see \"app stopped working\"; the report just isn't uploaded.",
            ),
            t("Telemetry aggregator", &[r"{win}\System32\AggregatorHost.exe"], "Gathers telemetry from other Windows parts.", ""),
            t("Xbox presence (GameBarPresenceWriter)", &[r"{win}\System32\GameBarPresenceWriter.exe"], "Tells Xbox what you are playing.", ""),
        ],
    },
    Group {
        title: "Windows programs that don't need the internet",
        intro: "These keep working locally; only their own internet access is cut. That removes web results, ads and sync from them.",
        targets: &[
            t(
                "File Explorer",
                &[r"{win}\explorer.exe", r"{win}\SysWOW64\explorer.exe"],
                "Desktop, taskbar and file windows. Its internet use is cloud previews and OneDrive nags.",
                "Folders on your local network still work.",
            ),
            t("Host for Windows Tasks (taskhostw)", &[r"{win}\System32\taskhostw.exe"], "Runs Windows background tasks, some of which phone home.", ""),
            t(
                "Start menu and shell panels",
                &[r"{win}\SystemApps\Microsoft.Windows.StartMenuExperienceHost_*\StartMenuExperienceHost.exe", r"{win}\SystemApps\ShellExperienceHost_*\ShellExperienceHost.exe"],
                "The Start menu and the pop-up panels (calendar, quick settings).",
                "No web results or ads in Start.",
            ),
            t(
                "Search box",
                &[r"{win}\SystemApps\MicrosoftWindows.Client.CBS_*\SearchHost.exe", r"{win}\SystemApps\Microsoft.Windows.Search_*\SearchApp.exe"],
                "The Windows search box.",
                "No Bing results or suggestions; searching your own files still works.",
            ),
            t("Text input panel", &[r"{win}\SystemApps\MicrosoftWindows.Client.CBS_*\TextInputHost.exe"], "The emoji panel and cloud clipboard.", "Cloud clipboard won't sync."),
            t("Widgets", &[r"{pf}\WindowsApps\MicrosoftWindows.Client.WebExperience_*\Dashboard\*.exe"], "The news and weather widgets board.", "The Widgets panel has no feed."),
            t("Lock screen", &[r"{win}\SystemApps\Microsoft.LockApp_*\LockApp.exe"], "The lock screen picture and tips.", "No Spotlight pictures or tips."),
            t("Photos", &[r"{pf}\WindowsApps\Microsoft.Windows.Photos_*\*.exe"], "The Photos app.", "No OneDrive or iCloud photo sync inside Photos."),
            t(
                "Calculator, Notepad, Clipchamp",
                &[r"{pf}\WindowsApps\Microsoft.WindowsCalculator_*\*.exe", r"{pf}\WindowsApps\Microsoft.WindowsNotepad_*\Notepad\*.exe", r"{pf}\WindowsApps\Clipchamp.Clipchamp_*\*.exe"],
                "Store-version apps that upload usage data or advertise.",
                "",
            ),
            t("Phone Link", &[r"{pf}\WindowsApps\Microsoft.YourPhone_*\*.exe"], "Connects your phone to the PC.", "Phone Link can't connect."),
            t(
                "Copilot, Xbox, Get Help, News",
                &[
                    r"{pf}\WindowsApps\Microsoft.Copilot_*\*.exe",
                    r"{pf}\WindowsApps\Microsoft.GamingApp_*\*.exe",
                    r"{pf}\WindowsApps\Microsoft.GetHelp_*\*.exe",
                    r"{pf}\WindowsApps\Microsoft.BingNews_*\*.exe",
                ],
                "Inbox apps that need an account or advertise.",
                "They can't go online.",
            ),
            t(
                "OneDrive installer",
                &[r"{win}\SysWOW64\OneDriveSetup.exe", r"{win}\System32\OneDriveSetup.exe"],
                "The installer Windows uses to put OneDrive back. Your existing OneDrive is not blocked.",
                "",
            ),
        ],
    },
];

/// Never blocked, whatever the table says: Windows Update, Defender and what RustWarden itself relies on.
const PROTECTED: &[&str] = &[
    "curl.exe",
    "nslookup.exe",
    "powershell.exe",
    "msiexec.exe",
    "usoclient.exe",
    "sihclient.exe",
    "wuauclt.exe",
    "tiworker.exe",
    "trustedinstaller.exe",
    "mousocoreworker.exe",
    "musnotification.exe",
    "musnotificationux.exe",
    "wusa.exe",
    "dismhost.exe",
    "wuapihost.exe",
    "waasmedic.exe",
    "windows10upgrade.exe",
    "msmpeng.exe",
    "mpcmdrun.exe",
    "nissrv.exe",
    "mssense.exe",
    "securityhealthsystray.exe",
    "securityhealthservice.exe",
    "smartscreen.exe",
    "dllhost.exe",
    "runtimebroker.exe",
    "systemsettings.exe",
    "dmclient.exe",
];

pub fn is_protected(path: &str, own_exe: &str) -> bool {
    path.eq_ignore_ascii_case(own_exe) || PROTECTED.contains(&file_name(path).to_lowercase().as_str())
}

/// Plain-English text of the confirmation box.
pub fn description() -> String {
    let mut s = String::from(
        "Blocks internet access, in and out, for the Windows programs below. Only ones that exist on this PC get a rule. Nothing is uninstalled or switched off, so they keep working offline.\n\nNot touched: Windows Update, Windows Defender, the Microsoft Store, Edge and WebView2, and everything RustWarden needs. Undo any of them on the Firewall tab, or all with Restore firewall defaults.\n",
    );
    for g in GROUPS {
        s += &format!("\n{}\n{}\n", g.title.to_uppercase(), g.intro);
        for t in g.targets {
            s += &format!("\n• {}: {}", t.name, t.what);
            if !t.effect.is_empty() {
                s += &format!(" Blocking it: {}", t.effect);
            }
        }
        s.push('\n');
    }
    s
}

/// `pattern` with one optional `*` matches `name`, ignoring case.
fn matches(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.to_lowercase(), name.to_lowercase());
    match p.split_once('*') {
        Some((a, b)) => n.len() >= a.len() + b.len() && n.starts_with(a) && n.ends_with(b),
        None => p == n,
    }
}

/// Existing files for one path pattern, one folder level at a time.
fn expand(pattern: &str) -> Vec<String> {
    let mut found = vec![String::new()];
    for (i, seg) in pattern.split('\\').enumerate() {
        let mut next = Vec::new();
        for base in &found {
            if i == 0 {
                next.push(seg.to_owned());
            } else if seg.contains('*') {
                let Ok(dir) = std::fs::read_dir(format!("{base}\\")) else { continue };
                next.extend(dir.flatten().filter(|e| matches(seg, &e.file_name().to_string_lossy())).map(|e| format!("{base}\\{}", e.file_name().to_string_lossy())));
            } else {
                next.push(format!("{base}\\{seg}"));
            }
        }
        found = next;
    }
    found.into_iter().filter(|p| std::path::Path::new(p).is_file()).collect()
}

/// Every file of every target that exists on this PC (SysWOW64 twins included), minus the protected
/// ones, with the index of its group in [`GROUPS`].
pub fn resolve(own_exe: &str) -> Vec<(usize, String)> {
    let win = std::env::var("SystemRoot").unwrap_or_else(|_| system_root());
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let mut out: Vec<(usize, String)> = Vec::new();
    for (gi, pattern) in GROUPS.iter().enumerate().flat_map(|(gi, g)| g.targets.iter().flat_map(|t| t.files).map(move |f| (gi, f))) {
        let pattern = pattern.replace("{win}", &win).replace("{pf}", &pf);
        let twin = pattern.replace(r"\System32\", r"\SysWOW64\");
        for p in expand(&pattern).into_iter().chain((twin != pattern).then(|| expand(&twin)).into_iter().flatten()) {
            if !is_protected(&p, own_exe) && !out.iter().any(|(_, o)| o.eq_ignore_ascii_case(&p)) {
                out.push((gi, p));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_protected_is_a_target() {
        for t in GROUPS.iter().flat_map(|g| g.targets) {
            for f in t.files {
                assert!(!is_protected(f, ""), "{f} is protected");
                assert!(super::super::apps::critical_reason("", &f.replace("{win}", r"c:\windows"), "", r"c:\windows").is_none(), "{f} is critical");
            }
            assert!(!t.what.is_empty());
        }
    }

    #[test]
    fn rustwarden_needs_are_protected() {
        for f in ["curl.exe", "NSLookup.exe", "powershell.exe", "usoclient.exe", "TiWorker.exe", "MsMpEng.exe"] {
            assert!(is_protected(&format!(r"C:\Windows\System32\{f}"), "x"));
        }
        assert!(is_protected(r"C:\x\RustWarden.exe", r"c:\x\rustwarden.exe"));
        assert!(!is_protected(r"C:\Windows\explorer.exe", "x"));
    }

    #[test]
    fn wildcard_matching() {
        assert!(matches("Microsoft.Windows.Photos_*", "microsoft.windows.photos_2024.1_x64__8wekyb3d8bbwe"));
        assert!(matches("*.exe", "Photos.exe"));
        assert!(!matches("v*", "x4"));
    }
}
