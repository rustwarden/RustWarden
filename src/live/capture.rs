//! Packet capture of one connection to a .pcap file (Driver mode). A sniff-only WinDivert handle copies the
//! connection's packets (traffic is never held back); they are written as they arrive and the capture ends
//! at the size or time limit, or when stopped. Captures live in RustWarden's data folder.

use super::store::{Shared, lock};
use crate::data::LiveConn;
use crate::pcap::{self, CaptureStatus};
use crate::sys::windivert::{self as wd, Address, Handle, Lib};
use std::io::BufWriter;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct Session {
    handle: Arc<Handle>,
    thread: std::thread::JoinHandle<()>,
    packets: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    path: String,
    what: String,
}

#[derive(Default)]
pub struct Capture {
    session: Mutex<Option<Session>>,
}

fn dir() -> std::path::PathBuf {
    crate::settings::data_dir().join("captures")
}

impl Capture {
    pub fn status(&self) -> Option<CaptureStatus> {
        // A capture that hit its limit stays listed, marked finished, until it is stopped or another starts.
        lock(&self.session).as_ref().map(|s| CaptureStatus {
            path: s.path.clone(),
            packets: s.packets.load(Ordering::Relaxed),
            bytes: s.bytes.load(Ordering::Relaxed),
            what: if s.thread.is_finished() { format!("{} (finished)", s.what) } else { s.what.clone() },
        })
    }

    pub fn stop(&self) {
        if let Some(s) = lock(&self.session).take() {
            s.handle.shutdown();
            let _ = s.thread.join();
        }
    }

    /// Starts capturing `conn`; returns the file being written.
    pub fn start(&self, shared: &Shared, conn: &LiveConn) -> Result<String, String> {
        if !shared.elevated {
            return Err("Capturing needs administrator rights. Use \"Restart as administrator\".".into());
        }
        if shared.settings().app_mode != crate::settings::AppMode::Driver {
            return Err("Capturing needs Driver mode.".into());
        }
        if crate::driver::state() != crate::driver::DriverState::Ready {
            return Err("The driver isn't installed. Install it in Settings.".into());
        }
        self.stop();
        std::fs::create_dir_all(dir()).map_err(|e| format!("Can't create the captures folder: {e}"))?;
        let name: String = conn.app.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
        let path = dir().join(format!("{name}-{}.pcap", crate::clock::now_unix()));
        let file = std::fs::File::create(&path).map_err(|e| format!("Can't create the capture file: {e}"))?;
        let mut writer = pcap::Writer::new(BufWriter::new(file)).map_err(|e| format!("Can't write the capture file: {e}"))?;
        let lib = Lib::load(&crate::driver::dir().join("WinDivert.dll"))?;
        let handle = Arc::new(lib.open(&pcap::tcp_filter(conn.local, conn.remote), wd::LAYER_NETWORK, 0, wd::FLAG_SNIFF | wd::FLAG_RECV_ONLY)?);
        let (packets, bytes) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let (h, p, b) = (handle.clone(), packets.clone(), bytes.clone());
        let thread = std::thread::Builder::new()
            .name("driver-capture".into())
            .spawn(move || {
                let (mut buf, mut addr) = (vec![0u8; wd::MAX_PACKET], Address::zeroed());
                let began = crate::clock::now_unix();
                while let Ok(len) = h.recv(&mut buf, &mut addr) {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                    if writer.packet(now.as_secs() as u32, now.subsec_micros(), &buf[..len]).is_err() {
                        break;
                    }
                    p.fetch_add(1, Ordering::Relaxed);
                    if b.fetch_add(len as u64, Ordering::Relaxed) + len as u64 >= pcap::MAX_BYTES || crate::clock::now_unix() - began >= pcap::MAX_SECS {
                        break;
                    }
                }
                let _ = writer.flush();
                h.shutdown();
            })
            .map_err(|e| e.to_string())?;
        let shown = path.to_string_lossy().into_owned();
        *lock(&self.session) = Some(Session { handle, thread, packets, bytes, path: shown.clone(), what: format!("{} to {}", conn.app, conn.remote) });
        Ok(shown)
    }
}
