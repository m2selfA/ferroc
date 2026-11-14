//! Experimental fleet/1 peer-record primitives, NOT an enabled transfer service.
//!
//! No CLI, MCP, websocket or GUI entrypoint uses this module. Record crypto uses
//! approved pins; identity persists protected keys/explicit approvals, and journal
//! attaches to existing SQLite for metadata. Operational enrollment/pairing and
//! production transport/lifecycle integration are pending. Local receiver commit
//! and typed source observations remain candidate components. A published stage alone
//! is not a durable protocol receipt.
//! See the P0 contract for remaining integration gates.
pub mod allocation;
pub mod auth;
pub mod control;
pub mod crypto;
pub mod fence;
pub mod host;
pub mod identity;
mod identity_protection;
#[cfg(windows)]
mod identity_windows;
pub mod inventory;
pub mod job;
pub mod journal;
pub mod lease;
pub mod manifest;
pub mod manifest_scan;
pub mod protocol;
pub mod ranges;
pub mod reconcile;
pub mod relay_channel;
pub mod relay_io;
pub mod source;
pub mod source_file;
pub mod source_window;
pub mod stage;
pub mod state;
pub mod sync_exec;
pub mod sync_grant;
pub mod sync_plan;
pub mod sync_run;
pub mod target_preflight;

#[cfg(test)]
mod tests;
