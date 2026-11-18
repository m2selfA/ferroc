//! Experimental fleet/1 peer-record primitives, NOT an enabled transfer service.
//!
//! Explicitly provisioned agents can drive DATA and local MCP task tools;
//! default builds/agents and unconfigured GUI do not enable them. Record crypto uses
//! approved pins; identity persists protected keys/explicit approvals, and journal
//! attaches to existing SQLite for metadata. Operational enrollment/pairing and
//! production transport/lifecycle integration are pending. Local receiver commit
//! and typed source observations remain candidate components. A published stage alone
//! is not a durable protocol receipt.
//! See the P0 contract for remaining integration gates.
pub mod admin_cli;
pub mod adopt_stage;
pub mod allocation;
pub mod auth;
pub mod checkpoint_readback;
pub mod control;
pub mod crypto;
pub mod directory_cli;
pub mod fence;
#[cfg(all(test, windows, feature = "gui"))]
#[path = "gui_peer_tests.rs"]
mod gui_peer_tests;
pub mod host;
pub mod identity;
mod identity_protection;
#[cfg(windows)]
mod identity_windows;
pub mod inventory;
#[cfg(feature = "fleet-core")]
pub mod inventory_cli;
pub mod issuance;
pub mod job;
pub mod journal;
pub mod lease;
#[cfg(target_os = "linux")]
pub(crate) mod linux_stage;
pub mod manifest;
pub mod manifest_scan;
pub mod manifest_view;
pub(crate) mod mcp_transfer;
pub mod protocol;
pub mod ranges;
pub mod reconcile;
pub mod relay_channel;
pub mod relay_io;
#[cfg(feature = "fleet-core")]
pub mod release_cli;
pub mod renewal;
#[cfg(feature = "fleet-core")]
pub mod resume_admission;
pub mod resume_condition;
pub mod resume_lease;
pub(crate) mod resume_route;
pub mod route_control;
pub mod setup;
pub mod setup_agent;
pub(crate) mod setup_broker;
pub mod setup_config;
pub mod setup_lease;
pub mod setup_resume;
pub mod source;
pub mod source_file;
pub mod source_window;
pub mod stage;
pub mod state;
pub mod sync_exec;
pub mod sync_grant;
pub mod sync_plan;
pub mod sync_run;
pub(crate) mod target_directories;
pub mod target_preflight;
pub mod transfer_tasks;
pub(crate) mod transport_driver;

#[cfg(test)]
mod tests;
