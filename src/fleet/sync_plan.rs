//! Bounded, pure `sync_dir` PLANNING over one existing DiffPlan.
//! No scan, IO, apply, delete, overwrite, network or restart capability.
//! Manifest digests are caller claims; this module only orders them into jobs.
use super::{
    job::{JobSpec, RoutePolicy},
    manifest::{Comparison, CopyReason, CopyTarget, DiffPlan, Difference, EntryKind, Manifest},
    protocol::MAX_FILE_BYTES,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const MAX_PLAN_FILES: usize = 4096;
pub const MAX_PLAN_BYTES: u64 = 512 * 1024 * 1024 * 1024;

/// One transfer per sync run. Roots are caller paths, not verified directories.
#[derive(Clone, Debug)]
pub struct SyncTemplate<'a> {
    pub fleet_id: Uuid,
    pub source_device: [u8; 32],
    pub target_device: [u8; 32],
    pub transfer_id: Uuid,
    pub source_root: &'a str,
    pub target_root: &'a str,
    pub deadline_ms: u64,
    pub idempotency_prefix: &'a str,
    pub chunk_bytes: u32,
}

/// Only additive runs are representable: the current publisher is no-clobber.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanMode {
    AddOnly,
}

#[derive(Clone, Debug)]
pub struct PlannedFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub reason: CopyReason,
    job: JobSpec,
}
impl PlannedFile {
    pub fn job(&self) -> &JobSpec {
        &self.job
    }
    pub fn job_digest(&self) -> Result<[u8; 32]> {
        self.job.digest()
    }
}

/// Descriptive plan only. Consuming it still needs per-file grants, live
/// re-observation and admission; nothing here authorizes IO.
/// ```compile_fail
/// fn no_apply(p:ferroc::fleet::sync_plan::SyncPlan){p.apply().unwrap();}
/// ```
/// ```compile_fail
/// fn no_delete(p:ferroc::fleet::sync_plan::SyncPlan){p.delete_extra_targets().unwrap();}
/// ```
#[derive(Clone, Debug)]
pub struct SyncPlan {
    mode: PlanMode,
    comparison: Comparison,
    files: Vec<PlannedFile>,
    /// Ordered (ancestor-first) relative directories the receiver must create.
    directories: Vec<String>,
    directories_ensured: usize,
    retained_target_only: usize,
    unchanged_files: usize,
    planned_bytes: u64,
}
impl SyncPlan {
    pub fn mode(&self) -> PlanMode {
        self.mode
    }
    pub fn comparison(&self) -> Comparison {
        self.comparison
    }
    pub fn files(&self) -> &[PlannedFile] {
        &self.files
    }
    /// Selected source sizes only; NOT traffic, encoded, received or durable.
    pub fn planned_bytes(&self) -> u64 {
        self.planned_bytes
    }
    /// Missing target directories the receiver/preparation must still create.
    pub fn directories_ensured(&self) -> usize {
        self.directories_ensured
    }
    /// Ancestor-first relative directories, in the diff's ascending order.
    /// Declared intent only: nothing here creates a directory.
    pub fn directories(&self) -> &[String] {
        &self.directories
    }
    /// Target-only entries kept, never deleted or overwritten by this plan.
    pub fn retained_target_only(&self) -> usize {
        self.retained_target_only
    }
    pub fn unchanged_files(&self) -> usize {
        self.unchanged_files
    }
    pub fn summary_json(&self) -> Result<String> {
        let mut digests = Vec::with_capacity(self.files.len());
        for file in &self.files {
            digests.push(serde_json::json!({
                "path": file.path,
                "bytes": file.bytes,
                "digest": hex(&file.job_digest()?),
            }));
        }
        Ok(serde_json::to_string(&serde_json::json!({
            "mode": self.mode,
            "comparison": self.comparison,
            "files": digests,
            "plannedBytes": self.planned_bytes,
            "directoriesEnsured": self.directories_ensured,
            "retainedTargetOnly": self.retained_target_only,
            "unchangedFiles": self.unchanged_files,
        }))?)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest_of(text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ferroc-fleet-sync-key\0");
    h.update(text.as_bytes());
    h.finalize().into()
}
fn rooted(root: &str, relative: &str, what: &str) -> Result<String> {
    ensure!(
        !root.is_empty() && !root.ends_with(['/', '\\']) && !root.chars().any(char::is_control),
        "{what} root must be a rooted directory path without trailing slash"
    );
    Ok(format!("{root}/{relative}"))
}
fn file_id(transfer: Uuid, relative: &str) -> Result<Uuid> {
    let mut h = Sha256::new();
    h.update(b"ferroc-fleet-sync-file\0");
    h.update(transfer.as_bytes());
    h.update(relative.as_bytes());
    let d: [u8; 32] = h.finalize().into();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    let id = Uuid::from_bytes(id);
    ensure!(!id.is_nil(), "derived file id is nil");
    Ok(id)
}

#[cfg(test)]
#[path = "sync_plan_tests.rs"]
mod tests;

/// Additive planning only. Any update, type conflict or blocked subtree makes
/// the WHOLE plan fail: silently dropping those would misrepresent a sync.
pub fn plan_add_only(
    source: &Manifest,
    diff: &DiffPlan,
    template: &SyncTemplate<'_>,
) -> Result<SyncPlan> {
    ensure!(
        diff.comparison() == Comparison::Checksum,
        "sync planning requires checksum comparison, not the quick heuristic"
    );
    ensure!(
        template.chunk_bytes > 0 && template.chunk_bytes <= 65536,
        "sync chunk ceiling outside fleet bound"
    );
    // Job keys accept only ASCII alphanumerics and `._:-`; a relative path is
    // neither, so the per-file suffix is a digest, never the path text.
    ensure!(
        !template.idempotency_prefix.is_empty()
            && template.idempotency_prefix.len() <= 96
            && template
                .idempotency_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        "idempotency prefix invalid"
    );
    let mut files: Vec<PlannedFile> = Vec::new();
    let mut ids = BTreeSet::new();
    let mut planned_bytes = 0u64;
    let mut directories: Vec<String> = Vec::new();
    let mut last = String::new();
    for change in diff.changes() {
        match &change.difference {
            Difference::CopyWholeFile {
                bytes,
                reason,
                target,
            } => {
                ensure!(
                    matches!(target, CopyTarget::Absent),
                    "sync plan refused: {} needs an overwrite the no-clobber engine does not have",
                    change.path
                );
                ensure!(
                    change.path.as_str() > last.as_str(),
                    "diff order is not strictly increasing"
                );
                last.clone_from(&change.path);
                let entry = source
                    .entries()
                    .find(|(path, _)| *path == change.path.as_str())
                    .with_context(|| format!("source manifest missing {}", change.path))?;
                let EntryKind::File { size, sha256, .. } = entry.1 else {
                    anyhow::bail!("diff selects non-file {}", change.path)
                };
                let sha = sha256.context("source entry lacks a stored digest")?;
                ensure!(sha != [0; 32], "source digest is a placeholder");
                ensure!(
                    *size == *bytes && *size <= MAX_FILE_BYTES,
                    "source size disagrees with diff for {}",
                    change.path
                );
                planned_bytes = planned_bytes
                    .checked_add(*bytes)
                    .context("planned byte overflow")?;
                ensure!(files.len() < MAX_PLAN_FILES, "sync plan file limit reached");
                ensure!(
                    planned_bytes <= MAX_PLAN_BYTES,
                    "sync plan byte limit reached"
                );
                let relative = change.path.as_str();
                let job = JobSpec {
                    version: 1,
                    fleet_id: template.fleet_id,
                    source_device: template.source_device,
                    target_device: template.target_device,
                    transfer_id: template.transfer_id,
                    file_id: file_id(template.transfer_id, relative)?,
                    source_path: rooted(template.source_root, relative, "source")?,
                    destination_path: rooted(template.target_root, relative, "target")?,
                    bytes_total: *bytes,
                    sha256: sha,
                    overwrite: false,
                    route: RoutePolicy::RelayOnly,
                    deadline_ms: template.deadline_ms,
                    idempotency_key: format!(
                        "{}:{}",
                        template.idempotency_prefix,
                        hex(&digest_of(relative)[..8])
                    ),
                };
                job.validate()?;
                ensure!(ids.insert(job.file_id), "derived file id collision");
                files.push(PlannedFile {
                    path: relative.to_string(),
                    bytes: *bytes,
                    sha256: sha,
                    reason: *reason,
                    job,
                });
            }
            Difference::EnsureDirectory => {
                // Lexicographic ascending order already places every ancestor
                // before its descendants; keep that as an explicit invariant.
                ensure!(
                    directories.len() < MAX_PLAN_FILES,
                    "sync plan directory limit reached"
                );
                directories.push(change.path.clone());
            }
            Difference::TypeConflict { .. } | Difference::BlockedByAncestor { .. } => {
                anyhow::bail!(
                    "sync plan refused: {} is a conflict/blocked subtree",
                    change.path
                )
            }
        }
    }
    Ok(SyncPlan {
        mode: PlanMode::AddOnly,
        comparison: Comparison::Checksum,
        files,
        directories_ensured: directories.len(),
        directories,
        retained_target_only: diff.retained_target_only().len(),
        unchanged_files: diff.unchanged_files(),
        planned_bytes,
    })
}
