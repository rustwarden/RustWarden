//! Plain-text logs in the data folder (`rescue.log`, `lists.log`). A file that grows past [`MAX`]
//! is moved to `<name>.log.old`, so the newest lines are always kept and the disk use is bounded.

use std::io::Write;
use std::path::Path;

const MAX: u64 = 512 * 1024;

/// Appends a timestamped line to `file` in the data folder. Logging never fails the caller.
pub fn line(file: &str, msg: &str) {
    let _ = append(&crate::settings::data_dir().join(file), &format!("{} {msg}", crate::clock::fmt_stamp(crate::clock::now_unix())));
}

fn append(path: &Path, text: &str) -> std::io::Result<()> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > MAX) {
        std::fs::rename(path, path.with_extension("log.old"))?;
    }
    writeln!(std::fs::OpenOptions::new().create(true).append(true).open(path)?, "{text}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_log_moves_aside_and_restarts() {
        let dir = std::env::temp_dir().join(format!("rw-applog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        std::fs::write(&path, vec![b'x'; MAX as usize + 1]).unwrap();
        append(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");
        assert_eq!(std::fs::metadata(dir.join("test.log.old")).unwrap().len(), MAX + 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
