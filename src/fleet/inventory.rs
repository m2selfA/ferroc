//! Bounded read-only inventory and permanently quarantined logical debt.
//! No filesystem deletion, state transition, coverage reconstruction or resume.
//! Legacy StageReference has NO historical file identity: present file IDs are
//! observations only. Paths/lengths never confer ownership or a cleanup right.
use super::{
    fence::file_id,
    identity::{open_private, open_stage},
    journal::Snapshot,
    protocol::MAX_FILE_BYTES,
    stage::StageBudget,
};
use crate::config::Policy;
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
#[derive(Clone, Copy, Debug)]
pub struct InventoryLimits {
    pub max_directories: usize,
    pub max_entries: usize,
    pub max_findings: usize,
    pub byte_limit: u64,
    pub max_active: usize,
}
impl Default for InventoryLimits {
    fn default() -> Self {
        Self {
            max_directories: 128,
            max_entries: 4096,
            max_findings: 256,
            byte_limit: MAX_FILE_BYTES,
            max_active: 4,
        }
    }
}
impl InventoryLimits {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            (1..=128).contains(&self.max_directories)
                && (1..=65536).contains(&self.max_entries)
                && (1..=1024).contains(&self.max_findings),
            "inventory bounds invalid"
        );
        let _ = StageBudget::new(self.byte_limit, self.max_active)?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingKind {
    LegacyIdentityUnproven,
    AllocationUnbound,
    AllocationDatabaseUnproven,
    AllocationDatabaseMismatch,
    RecordedIdentityMismatch,
    UnknownStage,
    ForeignControl,
    ControlReference,
    DuplicatePath,
    DuplicateFile,
    MissingStage,
    UnsafeStage,
    OversizedStage,
    ScopeUnavailable,
    ScanLimit,
    QuotaExceeded,
}
#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: FindingKind,
    pub path: PathBuf,
}
#[derive(Clone, Debug)]
pub struct StageObservation {
    pub path: PathBuf,
    pub reserved: u64,
    pub observed_len: u64,
    pub current_file_id: String,
    /// Equality to recorded IDs only; not tamper-proof historical ownership.
    pub recorded_identity_matches: bool,
}
/// A point-in-time diagnostic report, NOT a trusted ownership token or a live
/// global quota coordinator. Even an empty/complete report never opens receive.
/// ```compile_fail
/// fn cannot_reopen(r:ferroc::fleet::inventory::RecoveryInventory){
///     r.quarantined_budget().unwrap().reopen();
/// }
/// ```
/// ```no_run
/// use ferroc::{config::Policy,fleet::{fence::FencedConnection,inventory::{InventoryLimits,RecoveryInventory}}};
/// fn observe(db:&mut FencedConnection,p:&Policy,root:std::path::PathBuf)->anyhow::Result<RecoveryInventory>{
///     db.inventory(p,&[root],std::sync::Arc::default(),InventoryLimits::default())
/// }
/// ```
#[derive(Debug)]
pub struct RecoveryInventory {
    owner: Uuid,
    recorded_bytes: u64,
    recorded_slots: usize,
    entries_seen: usize,
    complete: bool,
    truncated: bool,
    findings: Vec<Finding>,
    stages: Vec<StageObservation>,
    budget: Option<StageBudget>,
}
impl RecoveryInventory {
    pub fn owner(&self) -> Uuid {
        self.owner
    }
    pub fn recorded_usage(&self) -> (u64, usize) {
        (self.recorded_bytes, self.recorded_slots)
    }
    pub fn entries_seen(&self) -> usize {
        self.entries_seen
    }
    /// Bounded scan/obligation checks finished without a hard finding, NOT
    /// historical identity verification or permission to admit/clean/resume.
    pub fn complete(&self) -> bool {
        self.complete
    }
    pub fn findings_truncated(&self) -> bool {
        self.truncated
    }
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    pub fn stages(&self) -> &[StageObservation] {
        &self.stages
    }
    pub fn quarantined_budget(&self) -> Option<&StageBudget> {
        self.budget.as_ref()
    }
    fn finding(&mut self, kind: FindingKind, path: &Path, limits: InventoryLimits) {
        if kind != FindingKind::LegacyIdentityUnproven {
            self.complete = false;
        }
        if self.findings.len() == limits.max_findings {
            self.truncated = true;
            self.complete = false;
            return;
        }
        self.findings.push(Finding {
            kind,
            path: if path.as_os_str().len() <= 4096 {
                path.into()
            } else {
                PathBuf::from("<overlong-local-path>")
            },
        });
    }
}
// Native canonical paths, never Unicode/ASCII case folding or lossy keys.
// Distinct filesystem objects can have the same Unicode lowercase spelling.
fn key(path: &Path) -> PathBuf {
    path.to_path_buf()
}
fn root(policy: &Policy, path: &Path) -> Result<PathBuf> {
    super::fence::local_path(path)?;
    let resolved = policy.resolve(path.to_str().context("inventory path UTF8 required")?)?;
    // Do not silently follow a final directory reparse/symlink.
    super::fence::local_path(&resolved)?;
    let _original = open_private(path, true)?;
    let _resolved = open_private(&resolved, true)?;
    Ok(resolved)
}
fn reserved_name(path: &Path) -> bool {
    path.file_name().is_some_and(|n| {
        n.to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(".ferroc-fleet-")
    })
}
pub(super) fn inspect(
    policy: &Policy,
    roots: &[PathBuf],
    rows: &[Snapshot],
    fence: &super::fence::FenceDomain,
    limits: InventoryLimits,
) -> Result<RecoveryInventory> {
    limits.validate()?;
    let owner = fence.owner;
    let database_id = fence.database_id();
    let database_parent_id = fence.database_parent_id()?;
    let controls = fence.control_paths();
    ensure!(
        rows.len() <= 128 && roots.len() <= limits.max_directories,
        "inventory scope exceeds bounds"
    );
    ensure!(
        !roots.is_empty() || !rows.is_empty(),
        "inventory scope is empty"
    );
    let mut report = RecoveryInventory {
        owner,
        recorded_bytes: 0,
        recorded_slots: 0,
        entries_seen: 0,
        complete: true,
        truncated: false,
        findings: Vec::new(),
        stages: Vec::new(),
        budget: None,
    };
    let control: BTreeSet<_> = controls.iter().map(|p| key(p)).collect();
    for path in roots {
        super::fence::local_path(path)?;
    }
    let mut requested = roots.to_vec();
    // Queued jobs also contribute parents: creation can precede attach_stage.
    for row in rows {
        requested.push(
            PathBuf::from(&row.job().destination_path)
                .parent()
                .context("job destination has no parent")?
                .into(),
        );
        if let Some(s) = row.stage() {
            report.recorded_bytes = report
                .recorded_bytes
                .checked_add(s.reserved_bytes())
                .context("inventory obligation overflow")?;
            report.recorded_slots = report
                .recorded_slots
                .checked_add(1)
                .context("inventory slot overflow")?;
        }
    }
    let mut dirs = BTreeMap::new();
    for candidate in requested {
        match root(policy, &candidate) {
            Ok(path) => {
                let k = key(&path);
                if !dirs.contains_key(&k) && dirs.len() == limits.max_directories {
                    report.finding(FindingKind::ScanLimit, &candidate, limits);
                    break;
                }
                dirs.insert(k, path);
            }
            Err(_) => report.finding(FindingKind::ScopeUnavailable, &candidate, limits),
        }
    }
    // Keep directory handles live during the whole observation. This is still
    // cooperative/local, not protection against malicious ancestor replacement.
    let mut held = Vec::new();
    for path in dirs.values() {
        match open_private(path, true) {
            Ok(f) => held.push(f),
            Err(_) => report.finding(FindingKind::ScopeUnavailable, path, limits),
        }
    }
    let mut known = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut charges = Vec::new();
    for row in rows {
        let Some(s) = row.stage() else { continue };
        let path = s.path();
        charges.push((path.to_path_buf(), s.reserved_bytes()));
        if s.allocation().is_some_and(|a| a.file_id().is_none()) {
            report.finding(FindingKind::AllocationUnbound, path, limits);
        }
        if let Some(a) = s.allocation() {
            match a.database_id() {
                None => report.finding(FindingKind::AllocationDatabaseUnproven, path, limits),
                Some(id)
                    if id != database_id
                        || a.database_parent_id() != Some(database_parent_id.as_str()) =>
                {
                    report.finding(FindingKind::AllocationDatabaseMismatch, path, limits)
                }
                _ => {}
            }
        }
        let observed = (|| -> Result<Option<(PathBuf, String, u64)>> {
            let parent = root(policy, path.parent().context("missing stage parent")?)?;
            ensure!(
                dirs.contains_key(&key(&parent)),
                "stage parent outside inventory scope"
            );
            ensure!(
                parent
                    == root(
                        policy,
                        Path::new(&row.job().destination_path)
                            .parent()
                            .context("missing destination parent")?
                    )?,
                "stage/destination parent mismatch"
            );
            let p = parent.join(path.file_name().context("missing stage name")?);
            if control.contains(&key(&p)) {
                return Ok(None);
            }
            let file = open_stage(&p)?;
            let id = file_id(&file)?;
            let canonical = fs::canonicalize(&p)?;
            ensure!(
                canonical.parent() == Some(parent.as_path()),
                "stage canonical parent changed"
            );
            ensure!(
                file_id(&open_stage(&canonical)?)? == id,
                "stage changed during observation"
            );
            if control.contains(&key(&canonical)) {
                return Ok(None);
            }
            let size = file.metadata()?.len();
            Ok(Some((canonical, id, size)))
        })();
        let lexical = key(path);
        if control.contains(&lexical) {
            report.finding(FindingKind::ControlReference, path, limits);
            continue;
        }
        if !known.insert(lexical) {
            report.finding(FindingKind::DuplicatePath, path, limits);
            continue;
        }
        match observed {
            Ok(Some((p, id, size))) => {
                known.insert(key(&p));
                if !ids.insert(id.clone()) {
                    report.finding(FindingKind::DuplicateFile, &p, limits);
                }
                if size > s.reserved_bytes() {
                    report.finding(FindingKind::OversizedStage, &p, limits);
                }
                let mut recorded_identity_matches = false;
                if let Some(a) = s.allocation() {
                    recorded_identity_matches = a.file_id() == Some(id.as_str())
                        && super::fence::directory_id(&open_private(
                            p.parent().context("missing stage parent")?,
                            true,
                        )?)
                        .is_ok_and(|v| v == a.parent_id());
                    if a.file_id().is_some() && !recorded_identity_matches {
                        report.finding(FindingKind::RecordedIdentityMismatch, &p, limits);
                    }
                } else {
                    report.finding(FindingKind::LegacyIdentityUnproven, &p, limits);
                }
                report.stages.push(StageObservation {
                    path: p.clone(),
                    reserved: s.reserved_bytes(),
                    observed_len: size,
                    current_file_id: id,
                    recorded_identity_matches,
                });
            }
            Ok(None) => report.finding(FindingKind::ControlReference, path, limits),
            Err(error) => {
                // Do not probe an original path after Policy/scope validation failed.
                let kind = if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    FindingKind::MissingStage
                } else {
                    FindingKind::UnsafeStage
                };
                report.finding(kind, path, limits);
            }
        }
    }
    'scan: for dir in dirs.values() {
        let stream = match fs::read_dir(dir) {
            Ok(s) => s,
            Err(_) => {
                report.finding(FindingKind::ScopeUnavailable, dir, limits);
                continue;
            }
        };
        for entry in stream {
            if report.entries_seen == limits.max_entries || report.truncated {
                report.finding(FindingKind::ScanLimit, dir, limits);
                break 'scan;
            }
            report.entries_seen += 1;
            let path = match entry {
                Ok(e) => e.path(),
                Err(_) => {
                    report.finding(FindingKind::ScopeUnavailable, dir, limits);
                    continue;
                }
            };
            if !reserved_name(&path) || control.contains(&key(&path)) || known.contains(&key(&path))
            {
                continue;
            }
            let lower = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_ascii_lowercase();
            report.finding(
                if lower.starts_with(".ferroc-fleet-owner-") {
                    FindingKind::ForeignControl
                } else {
                    FindingKind::UnknownStage
                },
                &path,
                limits,
            );
        }
    }
    if report.complete {
        match StageBudget::reconstruct_quarantined(limits.byte_limit, limits.max_active, &charges) {
            Ok(b) => report.budget = Some(b),
            Err(_) => report.finding(
                FindingKind::QuotaExceeded,
                Path::new("<logical-debt>"),
                limits,
            ),
        }
    }
    Ok(report)
}
#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
