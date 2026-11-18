//! LOCAL read-only fleet obligation view. No admission, release, transfer,
//! deletion or network: it only reports what the database already records and
//! what the bounded inventory scan observed.
#[cfg(test)]
#[path = "inventory_cli_tests.rs"]
mod tests;

use super::{inventory::InventoryLimits, journal::JobKey};
use crate::runtime::Runtime;
use anyhow::{Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Args)]
pub struct InventoryArgs {
    /// Absolute path to an EXISTING private host database.
    #[arg(long)]
    db: PathBuf,
    /// LOCAL root whose stage obligations are checked (repeatable).
    #[arg(long, required = true)]
    root: Vec<PathBuf>,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Opens the SAME host/database the agent uses, but only reads. The host stays
/// paused: nothing here admits, resumes, publishes or releases anything.
pub fn run(runtime: &Runtime, args: InventoryArgs) -> Result<Value> {
    ensure!(args.db.is_absolute(), "database path must be absolute");
    for root in &args.root {
        ensure!(root.is_absolute(), "root must be absolute");
    }
    let host = runtime.open_fleet_host(&args.db, InventoryLimits::default())?;
    let report = host.inventory()?;
    let (recorded_bytes, recorded_slots) = report.recorded_usage();
    let findings: Vec<Value> = report
        .findings()
        .iter()
        .map(|f| json!({"kind": format!("{:?}", f.kind), "path": f.path.display().to_string()}))
        .collect();
    let mut obligations = Vec::new();
    for row in host.obligations()? {
        let stage = row.stage();
        // Read-only reconciliation view: says whether an absence release would be
        // ELIGIBLE, never grants or performs one.
        let reconciliation = host
            .inspect_allocation(&JobKey::from_job(row.job()))
            .ok()
            .map(|r| {
                json!({
                    "state": format!("{:?}", r.state()),
                    "databaseMatches": r.database_matches(),
                    "originStopped": r.origin_stopped(),
                    "eligibleForAbsenceRelease": r.eligible_for_absence_release(),
                    "fingerprint": hex(&r.fingerprint()),
                })
            });
        obligations.push(json!({
            "digest": hex(&row.job().digest()?),
            "phase": format!("{:?}", row.phase()),
            "owner": row.owner().to_string(),
            "revision": row.revision(),
            "stagePath": stage.map(|s| s.path().display().to_string()),
            "reservedBytes": stage.map_or(0, |s| s.reserved_bytes()),
            "hasReceipt": row.receipt().is_some(),
            "reconciliation": reconciliation,
        }));
    }
    host.close()?;
    Ok(json!({
        "authority": false,
        "complete": report.complete(),
        "recordedBytes": recorded_bytes,
        "recordedSlots": recorded_slots,
        "entriesSeen": report.entries_seen(),
        "findings": findings,
        "obligations": obligations,
    }))
}
