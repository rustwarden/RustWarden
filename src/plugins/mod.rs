//! Optional integrations with other systems. Each plugin lives in its own folder and reaches the
//! rest of the app through a few thin hooks (settings, database schema, a worker, the UI).

pub mod core;
pub mod external_notifications;
pub mod ha;
pub mod opnsense;
pub mod ping;
pub mod speedtest;
pub mod thinkbroadband;
pub mod virustotal;
