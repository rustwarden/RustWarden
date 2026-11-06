//! Optional integrations with other systems. Each plugin lives in its own folder and reaches the
//! rest of the app through a few thin hooks (settings, database schema, a worker, the UI).

pub mod core;
pub mod legacy;
pub mod wasm;
