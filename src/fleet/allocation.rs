//! Durable LOCAL pre-creation obligations and empty-file object observations.
//! No writable handle/StageFile, receiving, automatic cleanup/release or resume.
//! Object IDs are recorded observations, NOT tamper-proof ownership evidence or
//! protection against object-ID reuse, hostile same-user actors or power loss.
use super::{
    control::ParentDurability,
    fence::{FencedConnection, directory_id, file_id, local_path},
    identity::{new_stage_private, open_private, open_stage},
    inventory::{self, InventoryLimits},
    journal::{JobKey, Journal, Snapshot, StageReference},
    state::Phase,
};
use crate::config::Policy;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageAllocation {
    pub(super) id: Uuid,
    pub(super) owner: Uuid,
    pub(super) parent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) database_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) database_parent_id: Option<String>,
    pub(super) file_id: Option<String>,
    pub(super) parent_durability: Option<ParentDurability>,
}
impl StageAllocation {
    pub fn database_parent_id(&self) -> Option<&str> {
        self.database_parent_id.as_deref()
    }
    pub fn database_id(&self) -> Option<&str> {
        self.database_id.as_deref()
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn original_owner(&self) -> Uuid {
        self.owner
    }
    pub fn parent_id(&self) -> &str {
        &self.parent_id
    }
    pub fn file_id(&self) -> Option<&str> {
        self.file_id.as_deref()
    }
    pub fn parent_durability(&self) -> Option<ParentDurability> {
        self.parent_durability
    }
    pub(super) fn validate(&self, path: &Path) -> Result<()> {
        ensure!(
            !self.id.is_nil()
                && !self.owner.is_nil()
                && path.file_name().and_then(|n| n.to_str())
                    == Some(format!(".ferroc-fleet-alloc-{}", self.id).as_str()),
            "invalid allocated stage identity/name"
        );
        fn valid(id: &str) -> bool {
            let p: Vec<_> = id.split('-').collect();
            p.len() == 3
                && ((p[0] == "win" && p[1].len() == 8) || (p[0] == "unix" && p[1].len() == 16))
                && p[2].len() == 16
                && p[1]
                    .bytes()
                    .chain(p[2].bytes())
                    .all(|b| b.is_ascii_hexdigit())
        }
        ensure!(
            valid(&self.parent_id)
                && self.database_id.as_ref().is_none_or(|id| valid(id))
                && self.database_parent_id.as_ref().is_none_or(|id| valid(id))
                && self.database_parent_id.is_some() == self.database_id.is_some()
                && self.file_id.as_ref().is_none_or(|id| valid(id))
                && self.file_id.is_some() == self.parent_durability.is_some(),
            "invalid allocated object observation"
        );
        Ok(())
    }
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => anyhow::bail!("allocation path/destination already exists"),
    }
}
pub(super) fn parent(policy: &Policy, s: &Snapshot) -> Result<(PathBuf, File, String)> {
    parent_checked(policy, s, true)
}
pub(super) fn published_parent(policy: &Policy, s: &Snapshot) -> Result<(PathBuf, File, String)> {
    parent_checked(policy, s, false)
}
fn parent_checked(
    policy: &Policy,
    s: &Snapshot,
    require_absent: bool,
) -> Result<(PathBuf, File, String)> {
    ensure!(policy.allow_transfers, "transfers disabled by local policy");
    let input = Path::new(&s.job().destination_path);
    local_path(input)?;
    let original = open_private(input.parent().context("destination parent missing")?, true)?;
    let dest = policy.resolve(&s.job().destination_path)?;
    local_path(&dest)?;
    ensure!(
        !dest
            .file_name()
            .context("destination filename missing")?
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(".ferroc-fleet-"),
        "reserved fleet destination namespace"
    );
    if require_absent {
        absent(&dest)?;
    }
    let dir = open_private(dest.parent().context("destination parent missing")?, true)?;
    let id = directory_id(&dir)?;
    ensure!(directory_id(&original)? == id, "destination parent changed");
    Ok((dest, dir, id))
}
impl FencedConnection {
    /// Persist an isolated obligation BEFORE creating any stage file. All existing
    /// stage debt/unknown scopes block this conservative one-at-a-time primitive.
    /// Atomic metadata version3 excludes old unbound-domain readers. Not lease admission.
    /// ```no_run
    /// use ferroc::{config::Policy,fleet::{fence::FencedConnection,journal::{JobKey,Snapshot},inventory::InventoryLimits}};
    /// fn reserve(db:&mut FencedConnection,k:&JobKey,r:u64,p:&Policy)->anyhow::Result<Snapshot>{db.reserve_stage(k,r,p,std::sync::Arc::default(),InventoryLimits::default())}
    /// ```
    pub fn reserve_stage(
        &mut self,
        key: &JobKey,
        revision: u64,
        policy: &Policy,
        fs_gate: Arc<Mutex<()>>,
        limits: InventoryLimits,
    ) -> Result<Snapshot> {
        limits.validate()?;
        let _gate = fs_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.fence.check_connection(&self.connection)?;
        let rows = Journal::inventory_rows(&mut self.connection, &self.fence)?;
        let s = rows
            .iter()
            .find(|s| JobKey::from_job(s.job()) == *key)
            .context("unknown allocation job")?;
        ensure!(
            s.owner() == self.fence.owner
                && s.revision() == revision
                && s.phase() == Phase::Queued
                && s.stage().is_none(),
            "allocation owner/revision/phase conflict"
        );
        let (destination, _directory, parent_id) = parent(policy, s)?;
        let report = inventory::inspect(
            policy,
            &[destination.parent().unwrap().into()],
            &rows,
            &self.fence,
            limits,
        )?;
        ensure!(
            report.complete() && report.recorded_usage() == (0, 0),
            "unresolved inventory/debt blocks allocation"
        );
        ensure!(
            s.job().bytes_total <= limits.byte_limit,
            "allocation byte quota exceeded"
        );
        let id = Uuid::new_v4();
        let path = destination
            .parent()
            .unwrap()
            .join(format!(".ferroc-fleet-alloc-{id}"));
        absent(&path)?;
        let mut reference = StageReference::observed_local(path, s.job().bytes_total)?;
        reference.allocation = Some(StageAllocation {
            id,
            owner: self.fence.owner,
            parent_id,
            database_id: Some(self.fence.database_id().into()),
            database_parent_id: Some(self.fence.database_parent_id()?),
            file_id: None,
            parent_durability: None,
        });
        self.fence.check_connection(&self.connection)?;
        self.journal()?.reserve_reference(key, revision, reference)
    }
    /// Creates ONLY an empty private CREATE_NEW file, then records observed IDs.
    /// Drop/errors never unlink it or erase debt. No returned write/receive handle.
    /// Failed SQL after creation leaves a persistent unresolved reservation.
    /// ```compile_fail
    /// fn cannot_get_writable_stage(db:&mut ferroc::fleet::fence::FencedConnection,k:&ferroc::fleet::journal::JobKey,p:&ferroc::config::Policy){
    /// let s=db.create_reserved_stage(k,1,p,std::sync::Arc::default()).unwrap();s.write_chunk(0,b"unauthorized").unwrap();
    /// }
    /// ```
    pub fn create_reserved_stage(
        &mut self,
        key: &JobKey,
        revision: u64,
        policy: &Policy,
        fs_gate: Arc<Mutex<()>>,
    ) -> Result<Snapshot> {
        self.create_reserved_inner(key, revision, policy, fs_gate, |_, _| Ok(()))
    }
    // Fresh CREATE_NEW only. The clone never escapes a failed binding; ordinary
    // File close preserves the object/debt. Not an adoption/reopen capability.
    pub(super) fn create_receive_reserved(
        &mut self,
        key: &JobKey,
        revision: u64,
        policy: &Policy,
        gate: Arc<Mutex<()>>,
    ) -> Result<(Snapshot, File)> {
        let mut writable = None;
        let s = self.create_reserved_inner(key, revision, policy, gate, |f, _| {
            writable = Some(f.try_clone()?);
            Ok(())
        })?;
        Ok((s, writable.context("no fresh stage handle")?))
    }

    fn create_reserved_inner(
        &mut self,
        key: &JobKey,
        revision: u64,
        policy: &Policy,
        fs_gate: Arc<Mutex<()>>,
        after_create: impl FnOnce(&File, &StageReference) -> Result<()>,
    ) -> Result<Snapshot> {
        let _gate = fs_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.fence.check_connection(&self.connection)?;
        let s = self
            .journal()?
            .get(key)?
            .context("unknown allocation job")?;
        ensure!(
            s.owner() == self.fence.owner
                && s.revision() == revision
                && s.phase() == Phase::Interrupted,
            "allocation owner/revision/phase conflict"
        );
        let reference = s.stage().context("missing stage reservation")?;
        let a = reference
            .allocation()
            .context("legacy reference is not a creation permit")?;
        ensure!(
            a.owner == self.fence.owner
                && a.file_id.is_none()
                && a.database_id() == Some(self.fence.database_id())
                && a.database_parent_id() == Some(self.fence.database_parent_id()?.as_str()),
            "allocation is bound or belongs to stopped owner"
        );
        let (dest, directory, parent_id) = parent(policy, &s)?;
        ensure!(
            dest.parent() == reference.path().parent() && parent_id == a.parent_id,
            "reserved parent object changed"
        );
        let file = new_stage_private(reference.path())?;
        file.sync_all()?;
        // Ordinary File: closing this handle cannot implicitly delete an unbound file.
        after_create(&file, reference)?;
        let object = file_id(&file)?;
        ensure!(
            file.metadata()?.len() == 0
                && file_id(&open_stage(reference.path())?)? == object
                && directory_id(&open_private(reference.path().parent().unwrap(), true)?)?
                    == parent_id,
            "created stage/parent changed"
        );
        #[cfg(unix)]
        let durability = {
            directory.sync_all()?;
            ParentDurability::Synced
        };
        #[cfg(not(unix))]
        let durability = {
            let _ = directory;
            ParentDurability::Unsupported
        };
        self.fence.check_connection(&self.connection)?;
        self.journal()?
            .bind_reference(key, revision, &object, durability)
    }
}
#[cfg(test)]
#[path = "allocation_tests.rs"]
mod tests;
