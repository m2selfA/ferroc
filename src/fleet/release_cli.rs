//! LOCAL explicit recovery of a STOPPED owner's absent allocation.
//!
//! Two separate, explicit steps, both local and both requiring the database to be
//! free of a live owner. Step one is `--recover-owner <uuid>`: metadata ownership
//! takeover from a stopped owner. Step two is `--release --digest <hex>`: retire an
//! allocation whose stage object is CONFIRMED ABSENT. Nothing here deletes files,
//! admits transfers, publishes or talks to a peer.
#[cfg(test)]
#[path = "release_cli_tests.rs"]
mod tests;

use super::{journal::JobKey, reconcile::AbsenceApproval};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Args)]
pub struct ReleaseArgs {
    /// Absolute path to an EXISTING private host database.
    #[arg(long)]
    db: PathBuf,
    /// LOCAL root whose stage obligations are checked (repeatable).
    #[arg(long, required = true)]
    root: Vec<PathBuf>,
    /// Step 1: take over metadata ownership from this STOPPED owner.
    #[arg(long)]
    recover_owner: Option<Uuid>,
    /// Step 2: retire the absent allocation of `--digest`.
    #[arg(long)]
    release: bool,
    /// Job digest (hex) of the obligation to release.
    #[arg(long)]
    digest: Option<String>,
    /// Optional extra guard: must equal the FRESH observation made in this run.
    /// A fingerprint from an earlier process can never match, because it binds the
    /// owning fence instance, which changes whenever the owning process changes.
    #[arg(long)]
    fingerprint: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn parse32(text: &str, what: &str) -> Result<[u8; 32]> {
    ensure!(text.len() == 64, "{what} must be 64 hex characters");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("{what} is not hex"))?;
    }
    Ok(out)
}

pub fn run(runtime: &Runtime, args: ReleaseArgs) -> Result<Value> {
    ensure!(args.db.is_absolute(), "database path must be absolute");
    for root in &args.root {
        ensure!(root.is_absolute(), "root must be absolute");
    }
    ensure!(
        args.recover_owner.is_some() || args.release,
        "nothing to do: pass --recover-owner <uuid> and/or --release"
    );
    let host = runtime.open_fleet_host(&args.db, super::inventory::InventoryLimits::default())?;
    let mut out = json!({"authority": false});
    if let Some(stopped) = args.recover_owner {
        let rows = host.recover_stopped_owner(stopped)?;
        out["recovered"] = json!(
            rows.iter()
                .map(|r| json!({
                    "digest": hex(&r.job().digest().unwrap_or_default()),
                    "phase": format!("{:?}", r.phase()),
                    "owner": r.owner().to_string(),
                    "revision": r.revision(),
                }))
                .collect::<Vec<_>>()
        );
    }
    if args.release {
        let digest = parse32(
            args.digest.as_deref().context("--release needs --digest")?,
            "digest",
        )?;
        let row = host
            .obligations()?
            .into_iter()
            .find(|r| r.job().digest().is_ok_and(|d| d == digest))
            .context("no obligation with that digest")?;
        let key = JobKey::from_job(row.job());
        // The approval MUST bind this process's own fresh observation: the
        // fingerprint includes the owning fence instance, so it is stale as soon as
        // the owner changes. Naming the digest plus an explicit --release is the
        // operator's decision; eligibility is then re-proved here.
        let report = host.inspect_allocation(&key)?;
        ensure!(
            report.eligible_for_absence_release(),
            "allocation is not eligible for absence release (state {:?}, databaseMatches {}, originStopped {})",
            report.state(),
            report.database_matches(),
            report.origin_stopped()
        );
        if let Some(expected) = args.fingerprint.as_deref() {
            ensure!(
                report.fingerprint() == parse32(expected, "fingerprint")?,
                "fingerprint does not match this process's fresh observation"
            );
        }
        let released = host.release_absent_allocation(
            &key,
            row.revision(),
            AbsenceApproval::approve_expected_fingerprint(report.fingerprint()),
        )?;
        out["released"] = json!({
            "digest": hex(&digest),
            "phase": format!("{:?}", released.phase()),
            "revision": released.revision(),
            "stagePresent": released.stage().is_some(),
        });
    }
    let report = host.inventory()?;
    let (bytes, slots) = report.recorded_usage();
    out["recordedBytes"] = json!(bytes);
    out["recordedSlots"] = json!(slots);
    out["complete"] = json!(report.complete());
    host.close()?;
    Ok(out)
}
