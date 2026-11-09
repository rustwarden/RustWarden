//! Tamper protection: an optional password that guards Settings, Exit and Restart.
//!
//! Stored as `salt:digest` (hex, salted and iterated SHA-256) and sealed with DPAPI by `settings::secret`.
//! This keeps casual users out of the app; an administrator can still end the process or the service.

use sha2::{Digest, Sha256};
use std::hash::{BuildHasher, Hasher};

const ROUNDS: u32 = 50_000;

fn digest(salt: &[u8], password: &str) -> Vec<u8> {
    let mut d = Sha256::digest([salt, password.as_bytes()].concat()).to_vec();
    for _ in 0..ROUNDS {
        d = Sha256::digest([&d[..], salt].concat()).to_vec();
    }
    d
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// A random 16-byte salt from the OS-seeded hasher keys.
fn salt() -> [u8; 16] {
    let state = std::collections::hash_map::RandomState::new();
    let mut out = [0u8; 16];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = state.build_hasher();
        h.write_usize(i);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

pub fn hash(password: &str) -> String {
    let salt = salt();
    format!("{}:{}", hex(&salt), hex(&digest(&salt, password)))
}

fn copy_path() -> std::path::PathBuf {
    crate::settings::admin_dir().join("tamper.dat")
}

/// Keeps a copy of the password hash in Program Files (sealed for this user), or removes it when the password is removed.
/// Only an elevated run can write there; without administrator rights the config file alone holds the password.
pub fn remember(hash: &str) {
    if hash.is_empty() {
        let _ = std::fs::remove_file(copy_path());
    } else if let Some(sealed) = crate::settings::secret::seal(hash) {
        let _ = std::fs::create_dir_all(crate::settings::admin_dir()).and_then(|()| std::fs::write(copy_path(), sealed));
    }
}

/// The hash `remember` kept, or empty.
pub fn recall() -> String {
    let text = std::fs::read_to_string(copy_path()).unwrap_or_default();
    let hash = crate::settings::secret::open(text.trim());
    if hash.starts_with("dpapi:") { String::new() } else { hash }
}

/// False for an empty or unreadable stored value, so a damaged setting never unlocks anything.
pub fn verify(stored: &str, password: &str) -> bool {
    let Some((salt, want)) = stored.split_once(':') else { return false };
    let Some(salt) = (0..salt.len()).step_by(2).map(|i| u8::from_str_radix(salt.get(i..i + 2)?, 16).ok()).collect::<Option<Vec<u8>>>() else { return false };
    !salt.is_empty() && hex(&digest(&salt, password)) == want
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_only_the_right_password() {
        let stored = super::hash("hunter2");
        assert!(super::verify(&stored, "hunter2"));
        assert!(!super::verify(&stored, "hunter3"));
        assert!(!super::verify(&stored, ""));
    }

    #[test]
    fn same_password_gets_different_salts_and_junk_never_verifies() {
        assert_ne!(super::hash("a"), super::hash("a"));
        assert!(!super::verify("", ""));
        assert!(!super::verify("zz:00", "x"));
        assert!(!super::verify("dpapi:abcd", "x"));
    }
}
