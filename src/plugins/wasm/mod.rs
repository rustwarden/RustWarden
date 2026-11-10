//! Host side of the `.wasm` plugin system (contract in the `plugin-sdk` crate): the sandbox that
//! loads a module, the functions it may call, the permission checks and the egui renderer for what
//! it draws.

// Wired into the app by the Plugin Manager (next step), so nothing calls this yet.
#![allow(dead_code)]

pub mod bundled;
pub mod host;
pub mod loader;
pub mod manager;
pub mod perms;
pub mod ui_tree;
