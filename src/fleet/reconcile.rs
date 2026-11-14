//! Explicit LOCAL absence-only reconciliation, not peer authorization or cleanup.
//! No delete/adopt/restore/resume. IDs are observations under a cooperative native
//! same-DB fence, NOT content proof or protection against hostile backup/ID reuse.
use super::{
    fence::{FenceDomain, FencedConnection, directory_id, file_id, local_path},
    identity::{open_private, open_stage},
    journal::{JobKey, Snapshot, StageReference},
    state::Phase,
};
use crate::config::Policy;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    path::Path,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ObjectState {
    Absent,
    PresentBoundIdsMatch,
    PresentUnbound,
    PresentMismatch,
    UnsafeOrUnreadable,
    ParentMismatch,
    ScopeUnavailable,
}
/// Read-only diagnostic snapshot; no IO or reusable release authority.
#[derive(Debug, Serialize)]
pub struct Reconciliation {
    fingerprint: [u8; 32],
    state: ObjectState,
    database_matches: bool,
    origin_stopped: bool,
    owner_recovered: bool,
    eligible: bool,
}
impl Reconciliation {
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub fn state(&self) -> ObjectState {
        self.state
    }
    pub fn database_matches(&self) -> bool {
        self.database_matches
    }
    pub fn origin_stopped(&self) -> bool {
        self.origin_stopped
    }
    pub fn owner_recovered(&self) -> bool {
        self.owner_recovered
    }
    pub fn eligible_for_absence_release(&self) -> bool {
        self.eligible
    }
}
/// Explicit trusted-local caller approval of the exact observation fingerprint.
/// This does NOT detect human approval, validate a wire grant or authorize IO.
/// Never construct automatically just because an inventory says "absent".
/// ```compile_fail
/// use ferroc::fleet::reconcile::AbsenceApproval;
/// fn cannot_import_wire_approval(){let _:AbsenceApproval=serde_json::from_str("{}").unwrap();}
/// ```
pub struct AbsenceApproval {
    expected: [u8; 32],
}
impl AbsenceApproval {
    pub fn approve_expected_fingerprint(expected: [u8; 32]) -> Self {
        Self { expected }
    }
}
/// Durable factual cancellation record, not a file deletion/remote receipt or
/// proof that the same path stays absent forever. Original allocation retained.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsenceRelease {
    pub(super) id: Uuid,
    pub(super) by: Uuid,
    pub(super) previous_revision: u64,
    pub(super) fingerprint: [u8; 32],
    pub(super) allocation: StageReference,
}
impl AbsenceRelease {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn by(&self) -> Uuid {
        self.by
    }
    pub fn previous_revision(&self) -> u64 {
        self.previous_revision
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub fn original_allocation(&self) -> &StageReference {
        &self.allocation
    }
    pub(super) fn validate(&self, s: &Snapshot) -> Result<()> {
        self.allocation.validate()?;
        let a = self
            .allocation
            .allocation()
            .context("release needs original allocation")?;
        ensure!(
            !self.id.is_nil()
                && !self.by.is_nil()
                && self.by != a.original_owner()
                && a.database_id().is_some()
                && a.database_parent_id().is_some()
                && self.previous_revision < s.revision()
                && self.allocation.reserved_bytes() == s.job().bytes_total
                && s.phase() == Phase::Cancelled
                && s.stage().is_none()
                && s.received() == 0
                && s.intent().is_none()
                && s.receipt().is_none(),
            "invalid absence release record"
        );
        Ok(())
    }
}
fn observe(
    s: &Snapshot,
    fence: &FenceDomain,
    p: &Policy,
) -> Result<(Reconciliation, Option<File>)> {
    let r = s.stage().context("no outstanding stage allocation")?;
    let a = r
        .allocation()
        .context("legacy stage lacks allocation identity")?;
    let database_matches = a.database_id() == Some(fence.database_id())
        && a.database_parent_id() == Some(fence.database_parent_id()?.as_str());
    let origin_stopped = database_matches && a.original_owner() != fence.owner;
    let owner_recovered = s.owner() == fence.owner;
    let mut held = None;
    let state = (|| -> Result<ObjectState> {
        local_path(r.path())?;
        let parent = r.path().parent().context("missing stage parent")?;
        local_path(parent)?;
        let job_parent = Path::new(&s.job().destination_path)
            .parent()
            .context("missing job parent")?;
        local_path(job_parent)?;
        let original = open_private(parent, true)?;
        let canonical = p.resolve(parent.to_str().context("non-UTF8 parent")?)?;
        let job_original = open_private(job_parent, true)?;
        let canonical_job = p.resolve(job_parent.to_str().context("non-UTF8 job parent")?)?;
        let directory = open_private(&canonical, true)?;
        let id = directory_id(&directory)?;
        if canonical != parent
            || canonical_job != canonical
            || directory_id(&original)? != id
            || directory_id(&job_original)? != id
            || id != a.parent_id()
        {
            return Ok(ObjectState::ParentMismatch);
        }
        held = Some(directory);
        match fs::symlink_metadata(r.path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ObjectState::Absent),
            Err(_) => Ok(ObjectState::UnsafeOrUnreadable),
            Ok(_) => {
                let file = match open_stage(r.path()) {
                    Ok(f) => f,
                    Err(_) => return Ok(ObjectState::UnsafeOrUnreadable),
                };
                let id = match file_id(&file) {
                    Ok(id) => id,
                    Err(_) => return Ok(ObjectState::UnsafeOrUnreadable),
                };
                if file.metadata()?.len() > r.reserved_bytes() {
                    return Ok(ObjectState::PresentMismatch);
                }
                Ok(match a.file_id() {
                    None => ObjectState::PresentUnbound,
                    Some(saved) if saved == id => ObjectState::PresentBoundIdsMatch,
                    _ => ObjectState::PresentMismatch,
                })
            }
        }
    })()
    .unwrap_or(ObjectState::ScopeUnavailable);
    let eligible = database_matches
        && origin_stopped
        && owner_recovered
        && state == ObjectState::Absent
        && s.is_absence_candidate();
    let encoded = serde_json::to_vec(&(
        s,
        fence.owner,
        fence.database_id(),
        state,
        database_matches,
        origin_stopped,
        owner_recovered,
        eligible,
    ))?;
    let mut hash = Sha256::new();
    hash.update(b"ferroc:local-absence-reconciliation:v1\0");
    hash.update(encoded);
    let fingerprint = hash.finalize().into();
    Ok((
        Reconciliation {
            fingerprint,
            state,
            database_matches,
            origin_stopped,
            owner_recovered,
            eligible,
        },
        held,
    ))
}
pub(super) fn authorize(
    s: &Snapshot,
    fence: &FenceDomain,
    p: &Policy,
    approval: &AbsenceApproval,
) -> Result<(AbsenceRelease, File)> {
    let (fresh, parent) = observe(s, fence, p)?;
    ensure!(
        fresh.eligible && fresh.fingerprint == approval.expected,
        "absence release denied: stale approval, live/unproven origin or unresolved object"
    );
    let original = s.stage().context("lost allocation")?.clone();
    Ok((
        AbsenceRelease {
            id: Uuid::new_v4(),
            by: fence.owner,
            previous_revision: s.revision(),
            fingerprint: fresh.fingerprint,
            allocation: original,
        },
        parent.context("no pinned parent")?,
    ))
}
impl FencedConnection {
    /// No transfers-enabled check: policy pause must not forbid read-only recovery
    /// or cancellation settlement. Directory policy/private-parent checks remain.
    /// ```no_run
    /// use ferroc::{config::Policy,fleet::{fence::FencedConnection,journal::JobKey,reconcile::Reconciliation}};
    /// fn inspect(db:&mut FencedConnection,k:&JobKey,p:&Policy)->anyhow::Result<Reconciliation>{db.inspect_allocation(k,p,std::sync::Arc::default())}
    /// ```
    pub fn inspect_allocation(
        &mut self,
        key: &JobKey,
        p: &Policy,
        fs_gate: Arc<Mutex<()>>,
    ) -> Result<Reconciliation> {
        let _gate = fs_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.fence.check_connection(&self.connection)?;
        let s = self
            .journal()?
            .get(key)?
            .context("unknown allocation job")?;
        let (report, _parent) = observe(&s, &self.fence, p)?;
        self.fence.check_connection(&self.connection)?;
        Ok(report)
    }
    /// Explicit absent-path retirement ONLY for the original native SAME DB domain
    /// after origin fence takeover and separate metadata owner recovery. Re-observe
    /// under fs_gate+IMMEDIATE revision CAS. Existing objects are never touched.
    /// Any stale/failed/uncertain COMMIT requires get()/inspection, never blind retry.
    /// No auto-admission: subsequent reserve still runs complete inventory.
    pub fn release_absent_allocation(
        &mut self,
        key: &JobKey,
        revision: u64,
        p: &Policy,
        approval: AbsenceApproval,
        fs_gate: Arc<Mutex<()>>,
    ) -> Result<Snapshot> {
        let _gate = fs_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.fence.check_connection(&self.connection)?;
        self.journal()?
            .release_reference(key, revision, p, &approval)
    }
}
#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod tests;
