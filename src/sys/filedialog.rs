//! The Windows "Open" file dialog, and reading a small text file the user picked.

use std::path::{Path, PathBuf};
use windows::Win32::UI::Controls::Dialogs::{GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows::core::{PCWSTR, PWSTR};

/// The most a plugin is given of a chosen file.
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

/// The double-null-terminated filter list the dialog wants: `Name (*.ext)\0*.ext\0...\0`, then "All files".
fn filter_list(filters: &[(&str, &str)]) -> Vec<u16> {
    let mut out = Vec::new();
    for (name, pattern) in filters.iter().copied().chain([("All files", "*.*")]) {
        out.extend(format!("{name} ({pattern})").encode_utf16());
        out.push(0);
        out.extend(pattern.encode_utf16());
        out.push(0);
    }
    out.push(0);
    out
}

/// `*.conf;*.ovpn` from a plugin's `.conf,.ovpn`: only plain letters, digits, `-` and `_` survive, so nothing odd reaches the dialog.
pub fn patterns(accept: &str) -> String {
    accept
        .split(',')
        .map(|e| e.trim().trim_start_matches('.').chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).collect::<String>())
        .filter(|e| !e.is_empty())
        .take(8)
        .map(|e| format!("*.{e}"))
        .collect::<Vec<_>>()
        .join(";")
}

/// Shows the dialog and waits for the answer, so call it from a worker thread, never the UI thread.
pub fn open(title: &str, filters: &[(&str, &str)]) -> Option<PathBuf> {
    let filter = filter_list(filters);
    let title: Vec<u16> = title.encode_utf16().chain([0]).collect();
    let mut buf = vec![0u16; 32768];
    // SAFETY: every pointer outlives the call; the dialog writes at most `nMaxFile` characters into `buf`.
    let ok = unsafe {
        let mut ofn = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            hwndOwner: GetForegroundWindow(),
            lpstrFilter: PCWSTR(filter.as_ptr()),
            lpstrFile: PWSTR(buf.as_mut_ptr()),
            nMaxFile: buf.len() as u32,
            lpstrTitle: PCWSTR(title.as_ptr()),
            Flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
            ..Default::default()
        };
        GetOpenFileNameW(&mut ofn).as_bool()
    };
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    (ok && len > 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len])))
}

/// Runs the dialog on its own thread and calls `then` with the chosen file (never when cancelled); repaints afterwards.
pub fn open_async(ctx: &egui::Context, title: &'static str, filters: Vec<(String, String)>, then: impl FnOnce(PathBuf) + Send + 'static) {
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let f: Vec<(&str, &str)> = filters.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        if let Some(p) = open(title, &f) {
            then(p);
        }
        ctx.request_repaint();
    });
}

/// (file name, text) of a file, or why it can't be handed over: too big, or not text.
pub fn read_text(path: &Path) -> Result<(String, String), String> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let meta = std::fs::metadata(path).map_err(|e| format!("can't read {name}: {e}"))?;
    if meta.len() > MAX_TEXT_BYTES as u64 {
        return Err(format!("{name} is too big ({} KB; the limit is {} KB)", meta.len() / 1024, MAX_TEXT_BYTES / 1024));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("can't read {name}: {e}"))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{name} isn't a text file"))?;
    Ok((name, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_list_is_double_null_terminated_with_all_files_last() {
        let f = filter_list(&[("Plugins", "*.wasm")]);
        assert_eq!(&f[f.len() - 2..], &[0, 0]);
        let text = String::from_utf16_lossy(&f).replace('\0', "|");
        assert_eq!(text, "Plugins (*.wasm)|*.wasm|All files (*.*)|*.*||");
    }

    #[test]
    fn patterns_keep_only_plain_extensions() {
        assert_eq!(patterns(".conf, .ovpn"), "*.conf;*.ovpn");
        assert_eq!(patterns("txt;|..\\x,"), "*.txtx");
        assert_eq!(patterns(""), "");
    }

    #[test]
    fn small_text_files_are_read_and_others_refused() {
        let dir = std::env::temp_dir().join(format!("rw-filedialog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("a.conf");
        std::fs::write(&ok, "[Interface]\nMTU = 1500\n").unwrap();
        assert_eq!(read_text(&ok).unwrap(), ("a.conf".to_owned(), "[Interface]\nMTU = 1500\n".to_owned()));
        let bin = dir.join("b.bin");
        std::fs::write(&bin, [0xff, 0xfe, 0x00]).unwrap();
        assert!(read_text(&bin).unwrap_err().contains("isn't a text file"));
        let big = dir.join("c.txt");
        std::fs::write(&big, vec![b'a'; MAX_TEXT_BYTES + 1]).unwrap();
        assert!(read_text(&big).unwrap_err().contains("too big"));
        assert!(read_text(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
