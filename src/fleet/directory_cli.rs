//! LOCAL read-only bounded directory observations and checksum dry-run.
//! No identities, authorization signing, network, apply, deletion or new service.
use super::{
    manifest::{Comparison, DiffPlan, Manifest, diff},
    manifest_scan::ScanLimits,
    manifest_view::{ManifestPages, PageLimits, ScanRules},
    sync_exec::CancelToken,
    sync_plan::{SyncTemplate, plan_add_only},
    target_preflight::PreflightLimits,
};
use crate::runtime::Runtime;
use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Args)]
pub struct DirectoryArgs {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Emit LOCAL Windows/Linux manifest pages as NDJSON, then a complete-stream digest.
    Scan {
        #[arg(long)]
        root: PathBuf,
        #[command(flatten)]
        view: ViewArgs,
    },
    /// Read-only add-only destination check; emits observations, creates nothing.
    Preflight {
        #[arg(long)]
        source_root: PathBuf,
        #[arg(long)]
        target_root: PathBuf,
        /// Explicit heuristic size+mtime mode (may miss content changes).
        #[arg(long)]
        quick: bool,
        /// Treat the plan's own declared-but-absent directories as expected.
        #[arg(long)]
        allow_planned_directories: bool,
        #[command(flatten)]
        view: ViewArgs,
    },
    /// Observe two LOCAL roots and emit descriptive differences; never apply.
    DryRun {
        #[arg(long)]
        source_root: PathBuf,
        #[arg(long)]
        target_root: PathBuf,
        /// Explicit heuristic size+mtime mode (may miss content changes).
        #[arg(long)]
        quick: bool,
        #[command(flatten)]
        view: ViewArgs,
    },
}
#[derive(Args)]
struct ViewArgs {
    /// Exact relative UTF8 subtree (repeatable), NOT glob/gitignore/case folding.
    #[arg(long)]
    exclude_subtree: Vec<String>,
    /// Per-root read budget, hard maximum 1 GiB. No automatic widening.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_hashed_bytes: u64,
    #[arg(long, default_value_t = 256)]
    page_entries: usize,
    /// Maximum serialized NDJSON record bytes, excluding its LF delimiter.
    #[arg(long, default_value_t = 256 * 1024)]
    page_bytes: usize,
}
struct Records<'a, W> {
    writer: &'a mut W,
    digest: Sha256,
    count: u64,
    max: usize,
}
impl<W: Write> Records<'_, W> {
    fn emit(&mut self, record: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(record)?;
        ensure!(
            bytes.len() <= self.max,
            "directory output record exceeds byte budget"
        );
        self.writer.write_all(&bytes)?;
        self.writer.write_all(b"\n")?;
        self.digest.update(bytes);
        self.digest.update(b"\n");
        self.count += 1;
        Ok(())
    }
    fn pages(&mut self, pages: &ManifestPages, side: &str) -> Result<usize> {
        let mut cursor = None;
        let mut count = 0;
        loop {
            let page = pages.page(cursor.as_deref())?;
            cursor = page.next_cursor.clone();
            self.emit(&json!({"record":"manifestPage","side":side,"page":page}))?;
            count += 1;
            if cursor.is_none() {
                return Ok(count);
            }
        }
    }
    fn finish(&mut self, details: serde_json::Value) -> Result<()> {
        let digest: [u8; 32] = self.digest.clone().finalize().into();
        self.emit(&json!({"record":"complete","version":1,"precedingRecords":self.count,"streamSha256":digest,"details":details}))?;
        self.writer.flush()?;
        Ok(())
    }
}
struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Local observation-identity template. These identifiers exist only so the
/// add-only planner can produce per-file job keys; they are NOT a fleet
/// identity, grant, lease or expiry, and nothing is signed or sent.
fn local_preflight_template<'a>(source: &'a str, target: &'a str) -> SyncTemplate<'a> {
    SyncTemplate {
        fleet_id: uuid::Uuid::from_bytes([0x5A; 16]),
        source_device: [0x11; 32],
        target_device: [0x22; 32],
        transfer_id: uuid::Uuid::from_bytes([0x33; 16]),
        source_root: source,
        target_root: target,
        deadline_ms: 3_600_000,
        idempotency_prefix: "localpreflight",
        chunk_bytes: 65_536,
    }
}
/// Read-only add-only destination observation. Creates nothing; a refused plan or
/// refused destination emits no partial approval stream.
#[allow(clippy::too_many_arguments)]
fn preflight<W: Write>(
    runtime: &Runtime,
    source_root: &Path,
    target_root: &Path,
    source: &Manifest,
    plan: &DiffPlan,
    allow: bool,
    cancel: &CancelToken,
    out: &mut Records<'_, W>,
) -> Result<()> {
    let source_text = source_root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("source root not UTF8"))?;
    let target_text = target_root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("target root not UTF8"))?;
    let template = local_preflight_template(source_text, target_text);
    let job_plan = plan_add_only(source, plan, &template)?;
    let observed = runtime.preflight_fleet_target(
        target_root,
        &job_plan,
        PreflightLimits {
            allow_planned_directories: allow,
            ..PreflightLimits::default()
        },
        cancel,
    )?;
    let mut digest = HashWriter(Sha256::new());
    digest.write_all(b"ferroc/local-preflight/v1\0")?;
    serde_json::to_writer(
        &mut digest,
        &json!({
            "sourceRoot": source_text,
            "targetRoot": target_text,
            "plannedFiles": observed.len(),
            "plannedBytes": observed.planned_bytes(),
            "plannedDirectories": observed.planned_directories().len(),
            "preflightPlanDigest": observed.plan_digest(),
        }),
    )?;
    let preflight_digest: [u8; 32] = digest.0.finalize().into();
    out.emit(&json!({"record":"preflightHeader","version":1,"localOnly":true,"authorization":false,"lease":false,"snapshot":false,"applySupported":false,"deleteSupported":false,"sourceRoot":source_text,"targetRoot":target_text,"plannedDirectoriesAllowed":allow,"rootId":observed.root_id()}))?;
    for entry in observed.entries() {
        out.emit(&json!({"record":"preflightEntry","preflightDigest":preflight_digest,"path":entry.path(),"destination":entry.destination(),"bytes":entry.bytes(),"parentId":entry.parent_id()}))?;
    }
    for directory in observed.planned_directories() {
        out.emit(&json!({"record":"plannedDirectory","preflightDigest":preflight_digest,"path":directory.path(),"destination":directory.destination()}))?;
    }
    out.finish(json!({"preflightDigest":preflight_digest,"planDigest":observed.plan_digest(),"entries":observed.len(),"plannedBytes":observed.planned_bytes(),"plannedDirectories":observed.planned_directories().len(),"rootId":observed.root_id()}))?;
    Ok(())
}
#[cfg(test)]
#[path = "directory_cli_tests.rs"]
mod tests;
/// Every invocation owns its cursors; output is accepted ONLY with the final
/// complete record and matching hash over all preceding raw NDJSON lines + LF.
/// A truncated/error stream is not an observation artifact or plan approval.
pub fn run<W: Write>(runtime: &Runtime, args: DirectoryArgs, writer: &mut W) -> Result<()> {
    ensure!(
        runtime.policy.allow_transfers,
        "fleet directory observation disabled by --no-transfers"
    );
    // The preflight action shares the two-root observation path and is
    // dispatched after both manifests exist.
    let mut preflight_dirs = None;
    let (root, target, quick, view) = match args.action {
        Action::Scan { root, view } => (root, None, false, view),
        Action::DryRun {
            source_root,
            target_root,
            quick,
            view,
        } => (source_root, Some(target_root), quick, view),
        Action::Preflight {
            source_root,
            target_root,
            quick,
            allow_planned_directories,
            view,
        } => {
            preflight_dirs = Some(allow_planned_directories);
            (source_root, Some(target_root), quick, view)
        }
    };
    ensure!(
        root.is_absolute() && target.as_ref().is_none_or(|p| p.is_absolute()),
        "directory roots must be absolute trusted LOCAL paths"
    );
    let rules = ScanRules::new(view.exclude_subtree)?;
    let output_limits = PageLimits {
        max_entries: view.page_entries,
        max_json_bytes: view.page_bytes,
    };
    output_limits.validate()?;
    // Reserve wrapper bytes; each actual emitted NDJSON record is checked too.
    ensure!(
        view.page_bytes >= 1024,
        "directory output page byte budget must be at least 1024"
    );
    let limits = PageLimits {
        max_json_bytes: view.page_bytes - 128,
        ..output_limits
    };
    let scan_limits = ScanLimits {
        max_hashed_bytes: view.max_hashed_bytes,
        ..ScanLimits::default()
    };
    ensure!(
        scan_limits.max_hashed_bytes <= super::manifest_scan::MAX_HASHED_BYTES,
        "hash budget outside hard ceiling"
    );
    let cancel = CancelToken::new();
    let source = runtime.scan_fleet_manifest_with_rules(&root, scan_limits, &rules, &cancel)?;
    let source_stats =
        json!({"filesHashed":source.files_hashed(),"bytesHashed":source.bytes_hashed()});
    let mut out = Records {
        writer,
        digest: Sha256::new(),
        count: 0,
        max: view.page_bytes,
    };
    let header = json!({"record":"directoryObservation","version":1,"localOnly":true,"sourceRoot":root,"targetRoot":target,"exclusionProfile":"exactUtf8Subtree/v1","exclusions":rules.paths(),"rulesDigest":rules.digest(),"consistency":"readSequence","namespace":"exactUtf8Unqualified","snapshot":false,"dryRun":true,"applySupported":false,"deleteSupported":false,"permission":false});
    if let Some(target) = target {
        // Scan both before emitting. Failure is never interpreted as empty target.
        let destination =
            runtime.scan_fleet_manifest_with_rules(&target, scan_limits, &rules, &cancel)?;
        let target_stats = json!({"filesHashed":destination.files_hashed(),"bytesHashed":destination.bytes_hashed()});
        let comparison = if quick {
            Comparison::Quick
        } else {
            Comparison::Checksum
        };
        let plan = diff(source.manifest(), destination.manifest(), comparison)?;
        if let Some(allow) = preflight_dirs {
            return preflight(
                runtime,
                &root,
                &target,
                source.manifest(),
                &plan,
                allow,
                &cancel,
                &mut out,
            );
        }
        let source = ManifestPages::observed(source, limits)?;
        let target = ManifestPages::observed(destination, limits)?;
        // Domain-separated full descriptive plan binding, not a grant or permit.
        // Serialize directly into SHA, not a giant intermediate output record.
        let mut digest = HashWriter(Sha256::new());
        digest.write_all(b"ferroc/local-directory-dry-run/v1\0")?;
        serde_json::to_writer(
            &mut digest,
            &json!({"header":header,"sourceManifestDigest":source.manifest_digest(),"targetManifestDigest":target.manifest_digest(),"diff":plan}),
        )?;
        let plan_digest: [u8; 32] = digest.0.finalize().into();
        out.emit(&header)?;
        let source_pages = out.pages(&source, "source")?;
        let target_pages = out.pages(&target, "target")?;
        for change in plan.changes() {
            out.emit(&json!({"record":"difference","planDigest":plan_digest,"entry":change}))?;
        }
        for retained in plan.retained_target_only() {
            out.emit(
                &json!({"record":"retainedTargetOnly","planDigest":plan_digest,"entry":retained}),
            )?;
        }
        out.finish(json!({"planDigest":plan_digest,"sourceManifestDigest":source.manifest_digest(),"targetManifestDigest":target.manifest_digest(),"rulesDigest":rules.digest(),"comparison":comparison,"changes":plan.changes().len(),"unchangedFiles":plan.unchanged_files(),"matchingDirectories":plan.matching_directories(),"selectedFileBytes":plan.file_bytes_selected(),"retainedTargetOnly":plan.retained_target_only().len(),"sourcePages":source_pages,"targetPages":target_pages,"source":source_stats,"target":target_stats}))?;
    } else {
        let source = ManifestPages::observed(source, limits)?;
        out.emit(&header)?;
        let pages = out.pages(&source, "source")?;
        out.finish(json!({"manifestDigest":source.manifest_digest(),"rulesDigest":rules.digest(),"pages":pages,"source":source_stats}))?;
    }
    Ok(())
}
