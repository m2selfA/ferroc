//! File-backed SQLite metadata journal, attached to an existing connection.
//! Not an authority clock, filesystem transaction, replay authenticator or
//! recovery sandbox. The host owns DB permissions and must fence stopped owners
//! before recovery. No persisted byte counter proves range coverage/readback.
use super::{
    control::{ParentDurability, Receipt},
    job::{JobSpec, MAX_JOBS},
    stage::{ParentSync, Publication},
    state::Phase,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
const MAX_ROW: usize = 32768;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobKey {
    fleet: Uuid,
    transfer: Uuid,
    file: Uuid,
}
impl JobKey {
    pub fn from_job(job: &JobSpec) -> Self {
        Self {
            fleet: job.fleet_id,
            transfer: job.transfer_id,
            file: job.file_id,
        }
    }
    pub(super) fn id(&self) -> String {
        format!("{}:{}:{}", self.fleet, self.transfer, self.file)
    }
}
/// Metadata supplied by a trusted LOCAL stage owner, not peer input or an IO
/// capability. Journal never deletes/opens this path for writing. Recovery must
/// validate policy/ownership and scan orphan stages before new receive admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageReference {
    path: PathBuf,
    reserved: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) allocation: Option<super::allocation::StageAllocation>,
}
impl StageReference {
    pub fn observed_local(path: PathBuf, reserved: u64) -> Result<Self> {
        let s = Self {
            path,
            reserved,
            allocation: None,
        };
        s.validate()?;
        Ok(s)
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.path.is_absolute()
                && self.path.to_str().is_some_and(|s| s.len() <= 4096)
                && !self
                    .path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "invalid local stage reference"
        );
        ensure!(
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(".ferroc-fleet-")),
            "stage reference outside reserved namespace"
        );
        if let Some(a) = &self.allocation {
            a.validate(&self.path)?;
        }
        Ok(())
    }
    pub fn allocation(&self) -> Option<&super::allocation::StageAllocation> {
        self.allocation.as_ref()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataSeal {
    id: Uuid,
    binding: super::protocol::Binding,
    job_digest: [u8; 32],
    file_id: String,
    original_owner: Uuid,
}
impl DataSeal {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn binding(&self) -> &super::protocol::Binding {
        &self.binding
    }
    fn validate(&self, s: &Snapshot) -> Result<()> {
        self.binding.validate()?;
        let a = s
            .provenance_stage()
            .and_then(|r| r.allocation.as_ref())
            .context("seal allocation missing")?;
        ensure!(
            !self.id.is_nil()
                && self.job_digest == s.job.digest()?
                && a.file_id() == Some(self.file_id.as_str())
                && a.database_id().is_some()
                && a.original_owner() == self.original_owner
                && self.binding.fleet_id == s.job.fleet_id
                && self.binding.transfer_id == s.job.transfer_id
                && self.binding.file_id == s.job.file_id
                && self.binding.source_device == s.job.source_device
                && self.binding.target_device == s.job.target_device,
            "seal job/file/creator/binding mismatch"
        );
        Ok(())
    }
}
/// Historical LOCAL target observation, not control::Receipt or COMMIT_ACK.
/// Does not release stage debt, guarantee directory durability, describe current
/// bytes after return, or authorize IO/recovery. Only the live Windows owner
/// records it after fresh same-File hashing under the actual Runtime gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetObservationReceipt {
    observation_id: Uuid,
    commit_intent: Uuid,
    binding: super::protocol::Binding,
    size: u64,
    sha256: [u8; 32],
    target_file_id: String,
    parent_id: String,
    parent_durability: ParentDurability,
}
impl TargetObservationReceipt {
    pub fn observation_id(&self) -> Uuid {
        self.observation_id
    }
    pub fn binding(&self) -> &super::protocol::Binding {
        &self.binding
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn parent_durability(&self) -> ParentDurability {
        self.parent_durability
    }
    fn validate(&self, s: &Snapshot) -> Result<()> {
        self.binding.validate()?;
        let a = s
            .provenance_stage()
            .and_then(|r| r.allocation())
            .context("target observation allocation missing")?;
        let b = s
            .intent_binding
            .as_ref()
            .context("target observation intent binding missing")?;
        ensure!(
            !self.observation_id.is_nil()
                && Some(self.commit_intent) == s.intent
                && self.size == s.job.bytes_total
                && self.sha256 == s.job.sha256
                && a.file_id() == Some(self.target_file_id.as_str())
                && a.parent_id() == self.parent_id
                && self.parent_durability == ParentDurability::Unsupported
                && self.binding.fleet_id == b.fleet_id
                && self.binding.transfer_id == b.transfer_id
                && self.binding.file_id == b.file_id
                && self.binding.source_device == b.source_device
                && self.binding.target_device == b.target_device
                && self.binding.source_session == b.source_session
                && self.binding.target_session == b.target_session,
            "target observation job/object/binding/durability mismatch"
        );
        Ok(())
    }
}

// DATA seal is descriptive metadata, not a verification or commit capability.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    version: u16,
    job: JobSpec,
    owner: Uuid,
    revision: u64,
    phase: Phase,
    stage: Option<StageReference>,
    received: u64,
    verified: bool,
    intent: Option<Uuid>,
    receipt: Option<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    absence_release: Option<super::reconcile::AbsenceRelease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_seal: Option<DataSeal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent_binding: Option<super::protocol::Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_observation: Option<TargetObservationReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settlement_origin: Option<StageReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settlement_binding: Option<super::protocol::Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained: Option<Box<RetainedStageState>>,
}
#[path = "checkpoint_journal.rs"]
mod checkpoint;
pub use checkpoint::{PrefixCheckpoint, RetainedStageState};
#[path = "journal_migration.rs"]
mod migration;
#[path = "stopped_recovery.rs"]
mod stopped_recovery;

impl Snapshot {
    pub fn retained_stage(&self) -> Option<&RetainedStageState> {
        self.retained.as_deref()
    }
    /// Historical allocation after explicit settlement; NOT a live reservation,
    /// file location, recovery permission or IO capability.
    pub fn settlement_origin(&self) -> Option<&StageReference> {
        self.settlement_origin.as_ref()
    }
    pub fn settlement_binding(&self) -> Option<&super::protocol::Binding> {
        self.settlement_binding.as_ref()
    }
    fn provenance_stage(&self) -> Option<&StageReference> {
        self.stage.as_ref().or(self.settlement_origin.as_ref())
    }
    pub(super) fn is_publication_attempt(&self) -> bool {
        matches!(self.version, 7 | 8)
    }
    pub fn target_observation(&self) -> Option<&TargetObservationReceipt> {
        self.target_observation.as_ref()
    }
    pub fn intent_binding(&self) -> Option<&super::protocol::Binding> {
        self.intent_binding.as_ref()
    }
    pub fn data_seal(&self) -> Option<&DataSeal> {
        self.data_seal.as_ref()
    }
    pub fn job(&self) -> &JobSpec {
        &self.job
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn owner(&self) -> Uuid {
        self.owner
    }
    pub fn stage(&self) -> Option<&StageReference> {
        self.stage.as_ref()
    }
    pub fn received(&self) -> u64 {
        self.received
    }
    pub fn absence_release(&self) -> Option<&super::reconcile::AbsenceRelease> {
        self.absence_release.as_ref()
    }
    pub(super) fn is_absence_candidate(&self) -> bool {
        self.version == 3
            && matches!(self.phase, Phase::Interrupted | Phase::CancelRequested)
            && self.stage.is_some()
            && self.absence_release.is_none()
            && self.received == 0
            && !self.verified
            && self.intent.is_none()
            && self.receipt.is_none()
    }
    pub fn receipt(&self) -> Option<&Receipt> {
        self.receipt.as_ref()
    }
    pub fn intent(&self) -> Option<Uuid> {
        self.intent
    }
    fn validate(&self) -> Result<()> {
        self.job.validate()?;
        if let Some(retained) = &self.retained {
            retained.validate(self, self.version)?;
        }
        if self.version == 10 {
            ensure!(
                self.retained
                    .as_ref()
                    .and_then(|r| r.migration.as_ref())
                    .is_some(),
                "migration history missing"
            );
            return Ok(());
        }
        // Anonymous stages may now carry a REPLACEMENT job: the publish step
        // links once under a job-derived reserved name and renames over the
        // destination. Only the legacy-phase guard remains for anonymous rows.
        ensure!(
            !self
                .provenance_stage()
                .and_then(|s| s.allocation())
                .is_some_and(|a| a.is_anonymous())
                || self.version >= 3,
            "anonymous allocation requires the current phase"
        );
        ensure!(
            matches!(self.version, 5..=9) == self.data_seal.is_some()
                && (self.version >= 6) == self.intent_binding.is_some()
                && (self.version >= 8) == self.target_observation.is_some()
                && (self.version == 9) == self.settlement_origin.is_some()
                && (self.version == 9) == self.settlement_binding.is_some(),
            "seal/version mismatch"
        );
        if let Some(b) = &self.intent_binding {
            b.validate()?;
            let old = &self
                .data_seal
                .as_ref()
                .context("intent requires DATA seal")?
                .binding;
            ensure!(
                b.fleet_id == old.fleet_id
                    && b.source_device == old.source_device
                    && b.target_device == old.target_device
                    && b.transfer_id == old.transfer_id
                    && b.file_id == old.file_id
                    && b.source_session == old.source_session
                    && b.target_session == old.target_session,
                "intent binding differs from sealed task/sessions"
            );
        }

        if let Some(origin) = &self.settlement_origin {
            origin.validate()?;
            let a = origin
                .allocation()
                .context("settlement origin allocation missing")?;
            let b = self
                .settlement_binding
                .as_ref()
                .context("settlement binding missing")?;
            b.validate()?;
            let old = self
                .intent_binding
                .as_ref()
                .context("settlement intent binding missing")?;
            ensure!(
                origin.reserved == self.job.bytes_total
                    && a.database_id().is_some()
                    && a.file_id().is_some()
                    && b.fleet_id == old.fleet_id
                    && b.transfer_id == old.transfer_id
                    && b.file_id == old.file_id
                    && b.source_device == old.source_device
                    && b.target_device == old.target_device
                    && b.source_session == old.source_session
                    && b.target_session == old.target_session
                    && self
                        .receipt
                        .as_ref()
                        .is_some_and(|r| r.parent_durability == ParentDurability::Unsupported),
                "settlement origin/binding/durability mismatch"
            );
        }
        if let Some(observation) = &self.target_observation {
            observation.validate(self)?;
        }
        if let Some(seal) = &self.data_seal {
            seal.validate(self)?;
        }
        ensure!(
            (match self.version {
                1 =>
                    self.stage.as_ref().is_none_or(|s| s.allocation.is_none())
                        && self.absence_release.is_none(),
                2 =>
                    self.stage
                        .as_ref()
                        .and_then(|s| s.allocation.as_ref())
                        .is_some_and(|a| a.database_id().is_none())
                        && self.absence_release.is_none(),
                3 =>
                    (self.is_absence_candidate()
                        && self
                            .stage
                            .as_ref()
                            .and_then(|s| s.allocation.as_ref())
                            .is_some_and(|a| a.database_id().is_some()))
                        || (self.stage.is_none()
                            && self.absence_release.is_some()
                            && self.phase == Phase::Cancelled),
                4 =>
                    matches!(
                        self.phase,
                        Phase::Transferring | Phase::Interrupted | Phase::CancelRequested
                    ) && !self.verified
                        && self.intent.is_none()
                        && self.receipt.is_none()
                        && self.absence_release.is_none()
                        && self
                            .stage
                            .as_ref()
                            .and_then(|s| s.allocation.as_ref())
                            .is_some_and(|a| a.database_id().is_some() && a.file_id().is_some()),
                5 =>
                    matches!(
                        self.phase,
                        Phase::Transferring | Phase::Interrupted | Phase::CancelRequested
                    ) && self.received == self.job.bytes_total
                        && !self.verified
                        && self.intent.is_none()
                        && self.receipt.is_none()
                        && self.absence_release.is_none(),
                6..=8 =>
                    matches!(self.phase, Phase::Committing | Phase::CommitUnknown)
                        && (self.version == 6 || self.phase == Phase::CommitUnknown)
                        && self.received == self.job.bytes_total
                        && self.verified
                        && self.intent.is_some_and(|id| !id.is_nil())
                        && self.receipt.is_none()
                        && self.absence_release.is_none(),
                9 =>
                    matches!(self.phase, Phase::Completed | Phase::CommitUnknown)
                        && self.stage.is_none()
                        && self.receipt.is_some()
                        && self.verified
                        && self.received == self.job.bytes_total
                        && self.intent.is_some_and(|id| !id.is_nil())
                        && self.absence_release.is_none(),
                _ => false,
            }) && !self.owner.is_nil()
                && self.revision <= i64::MAX as u64,
            "invalid journal version/owner/revision"
        );
        ensure!(
            self.received <= self.job.bytes_total,
            "journal progress exceeds authorized bytes"
        );
        if let Some(s) = &self.stage {
            s.validate()?;
            ensure!(
                s.reserved == self.job.bytes_total,
                "journal reservation differs from task size"
            );
        }
        if let Some(r) = &self.absence_release {
            r.validate(self)?;
            ensure!(!self.verified, "absence release cannot prove readback");
        }
        if self.verified {
            ensure!(
                self.received == self.job.bytes_total,
                "verified journal coverage count incomplete"
            );
        }
        match self.phase {
            Phase::Queued => ensure!(
                self.stage.is_none()
                    && self.received == 0
                    && !self.verified
                    && self.intent.is_none()
                    && self.receipt.is_none(),
                "invalid queued journal state"
            ),
            Phase::Transferring => ensure!(
                self.stage.is_some()
                    && !self.verified
                    && self.intent.is_none()
                    && self.receipt.is_none(),
                "invalid receiving journal state"
            ),
            Phase::Verifying => ensure!(
                self.stage.is_some()
                    && self.verified
                    && self.intent.is_none()
                    && self.receipt.is_none(),
                "invalid verified journal state"
            ),
            Phase::Committing => ensure!(
                self.intent.is_some_and(|id| !id.is_nil())
                    && self.verified
                    && self.stage.is_some()
                    && self.receipt.is_none(),
                "invalid pending commit reservation"
            ),
            Phase::CommitUnknown => ensure!(
                self.intent.is_some_and(|id| !id.is_nil())
                    && self.verified
                    && (self.stage.is_some() != self.receipt.is_some()),
                "unknown commit requires either retained stage or archived receipt"
            ),
            Phase::Completed => ensure!(
                self.stage.is_none() && self.verified && self.receipt.is_some(),
                "invalid completed journal state"
            ),
            Phase::Cancelled => ensure!(
                self.stage.is_none() && self.intent.is_none() && self.receipt.is_none(),
                "invalid cancelled journal state"
            ),
            Phase::CancelRequested | Phase::Interrupted => ensure!(
                self.intent.is_none() && self.receipt.is_none(),
                "precommit cleanup cannot erase commit intent"
            ),
            _ => anyhow::bail!("journal phase unsupported by this contract"),
        }
        if let Some(r) = &self.receipt {
            ensure!(
                Some(r.receipt_id) == self.intent
                    && r.size == self.job.bytes_total
                    && r.sha256 == self.job.sha256
                    && matches!(self.phase, Phase::Completed | Phase::CommitUnknown),
                "journal receipt/task/intent mismatch"
            );
        }
        Ok(())
    }
}
struct StoredRow {
    fleet: String,
    idem: String,
    parameters: Vec<u8>,
    digest: Vec<u8>,
    revision: i64,
    body: String,
}

/// Borrow the same fenced SQLite connection; FULL metadata commits are not
/// filesystem power-loss proof. Only the guard's factory is a normal entrypoint.
/// ```compile_fail
/// fn cannot_attach_unfenced(c:&mut rusqlite::Connection) {
///     let _=ferroc::fleet::journal::Journal::attach(c,uuid::Uuid::new_v4());
/// }
/// ```
/// ```compile_fail
/// fn cannot_export_raw(j:ferroc::fleet::journal::Journal<'_>) {
///     let _=j.into_connection();
/// }
/// ```
pub struct Journal<'c> {
    connection: &'c mut Connection,
    owner: Uuid,
    fence: Option<&'c super::fence::FenceDomain>,
}
impl<'c> Journal<'c> {
    #[cfg(test)]
    pub fn attach(connection: &'c mut Connection, owner: Uuid) -> Result<Self> {
        Self::attach_inner(connection, owner, None)
    }
    pub(super) fn attach_fenced(
        connection: &'c mut Connection,
        fence: &'c super::fence::FenceDomain,
    ) -> Result<Self> {
        fence.check_connection(connection)?;
        Self::attach_inner(connection, fence.owner, Some(fence))
    }
    /// Existing schema only: NO DDL, implicit migration or busy-handler reset.
    /// Caller owns the real DB mutex and sets/restores a zero busy timeout.
    pub(super) fn existing_fenced(
        connection: &'c mut Connection,
        fence: &'c super::fence::FenceDomain,
    ) -> Result<Self> {
        ensure!(
            connection.is_autocommit(),
            "existing journal needs autocommit"
        );
        fence.check_connection(connection)?;
        let sync: i64 = connection.query_row("PRAGMA main.synchronous", [], |r| r.get(0))?;
        let mode: String = connection.query_row("PRAGMA main.journal_mode", [], |r| r.get(0))?;
        ensure!(
            sync >= 2 && ["wal", "delete", "truncate", "persist"].contains(&mode.as_str()),
            "existing journal requires FULL atomic storage"
        );
        let versions: Vec<i64> = {
            let mut q = connection.prepare("SELECT version FROM ferroc_fleet_meta LIMIT 2")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        ensure!(
            matches!(
                versions.as_slice(),
                [1] | [2] | [3] | [4] | [5] | [6] | [7] | [8] | [9] | [10] | [11] | [12] | [13]
            ),
            "unsupported existing journal schema"
        );
        Ok(Self {
            connection,
            owner: fence.owner,
            fence: Some(fence),
        })
    }

    fn check_owner(&self) -> Result<()> {
        if let Some(f) = self.fence {
            return f.check_connection(self.connection);
        }
        #[cfg(test)]
        {
            Ok(())
        }
        #[cfg(not(test))]
        {
            anyhow::bail!("unfenced fleet journal is forbidden")
        }
    }
    fn attach_inner(
        connection: &'c mut Connection,
        owner: Uuid,
        fence: Option<&'c super::fence::FenceDomain>,
    ) -> Result<Self> {
        ensure!(
            !owner.is_nil() && connection.is_autocommit(),
            "journal requires owner and an autocommit connection"
        );
        let file: String = connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |r| r.get(0),
        )?;
        let sync: i64 = connection.query_row("PRAGMA main.synchronous", [], |r| r.get(0))?;
        let mode: String = connection.query_row("PRAGMA main.journal_mode", [], |r| r.get(0))?;
        ensure!(
            !file.is_empty()
                && sync >= 2
                && ["wal", "delete", "truncate", "persist"].contains(&mode.as_str()),
            "journal requires file-backed DB, FULL sync and an atomic journal mode"
        );
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS ferroc_fleet_meta(version INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS ferroc_fleet_jobs_v1(k TEXT PRIMARY KEY,fleet TEXT NOT NULL,idem TEXT NOT NULL,parameters BLOB NOT NULL CHECK(length(parameters)=32),digest BLOB NOT NULL CHECK(length(digest)=32),revision INTEGER NOT NULL CHECK(revision>=0),body TEXT NOT NULL CHECK(length(body)<=32768),UNIQUE(fleet,idem));")?;
        let versions: Vec<i64> = {
            let mut s = tx.prepare("SELECT version FROM ferroc_fleet_meta LIMIT 2")?;
            s.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        if versions.is_empty() {
            tx.execute("INSERT INTO ferroc_fleet_meta(version) VALUES(1)", [])?;
        } else {
            ensure!(
                matches!(
                    versions.as_slice(),
                    [1] | [2] | [3] | [4] | [5] | [6] | [7] | [8] | [9] | [10] | [11] | [12] | [13]
                ),
                "unsupported/ambiguous fleet journal schema version"
            );
        }
        tx.commit()?;
        Ok(Self {
            connection,
            owner,
            fence,
        })
    }
    // A bounded existing-schema snapshot; no creation or implicit upgrade.
    pub(super) fn inventory_rows(
        connection: &mut Connection,
        fence: &super::fence::FenceDomain,
    ) -> Result<Vec<Snapshot>> {
        fence.check_connection(connection)?;
        ensure!(connection.is_autocommit(), "inventory requires autocommit");
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rows = Self::read_rows(&tx)?;
        tx.commit()?;
        fence.check_connection(connection)?;
        Ok(rows)
    }
    fn read_rows(c: &Connection) -> Result<Vec<Snapshot>> {
        let versions: Vec<i64> = {
            let mut q = c.prepare("SELECT version FROM ferroc_fleet_meta LIMIT 2")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        ensure!(
            matches!(
                versions.as_slice(),
                [1] | [2] | [3] | [4] | [5] | [6] | [7] | [8] | [9] | [10] | [11] | [12] | [13]
            ),
            "inventory schema unsupported"
        );
        let keys: Vec<String> = {
            let mut q=c.prepare("SELECT CASE WHEN typeof(k)='text' AND length(CAST(k AS BLOB))=110 AND typeof(fleet)='text' AND length(CAST(fleet AS BLOB))<=36 AND typeof(idem)='text' AND length(CAST(idem AS BLOB))<=32768 AND typeof(parameters)='blob' AND length(parameters)=32 AND typeof(digest)='blob' AND length(digest)=32 AND typeof(body)='text' AND length(CAST(body AS BLOB))<=32768 THEN k ELSE NULL END FROM ferroc_fleet_jobs_v1 ORDER BY k LIMIT 129")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        ensure!(keys.len() <= MAX_JOBS, "inventory journal over capacity");
        let mut rows = Vec::with_capacity(keys.len());
        for text in keys {
            let p: Vec<_> = text.split(':').collect();
            ensure!(p.len() == 3, "corrupt inventory key");
            let key = JobKey {
                fleet: Uuid::parse_str(p[0])?,
                transfer: Uuid::parse_str(p[1])?,
                file: Uuid::parse_str(p[2])?,
            };
            rows.push(Self::load(c, &key)?.context("lost inventory row")?);
        }
        Ok(rows)
    }
    fn load(c: &Connection, key: &JobKey) -> Result<Option<Snapshot>> {
        let s = Self::load_one(c, key)?;
        if let Some(s) = &s {
            migration::MigrationLink::check_pair(c, s)?;
        }
        Ok(s)
    }
    fn load_one(c: &Connection, key: &JobKey) -> Result<Option<Snapshot>> {
        let raw:Option<StoredRow>=c.query_row("SELECT fleet,idem,parameters,digest,revision,CASE WHEN length(CAST(body AS BLOB))<=32768 THEN body ELSE NULL END FROM ferroc_fleet_jobs_v1 WHERE k=?1",[key.id()],|r|Ok(StoredRow{fleet:r.get(0)?,idem:r.get(1)?,parameters:r.get(2)?,digest:r.get(3)?,revision:r.get(4)?,body:r.get(5)?})).optional()?;
        let Some(StoredRow {
            fleet,
            idem,
            parameters,
            digest,
            revision,
            body,
        }) = raw
        else {
            return Ok(None);
        };
        ensure!(body.len() <= MAX_ROW, "oversized journal record");
        let s: Snapshot = serde_json::from_str(&body).context("invalid fleet journal JSON")?;
        s.validate()?;
        let schema: Vec<i64> = {
            let mut q = c.prepare("SELECT version FROM ferroc_fleet_meta LIMIT 2")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        ensure!(
            schema.len() == 1
                && (1..=13).contains(&schema[0])
                && i64::from(s.version) <= schema[0]
                && (!(s.job.overwrite && s.version >= 7) || schema[0] >= 10)
                && (!s
                    .provenance_stage()
                    .and_then(|r| r.allocation())
                    .is_some_and(|a| a.is_anonymous())
                    || matches!(schema[0], 11..=13))
                && (s.retained.is_none() || schema[0] >= 12)
                && (s.retained.as_ref().is_none_or(|r| r.migration.is_none()) || schema[0] == 13),
            "journal row exceeds schema gate"
        );
        ensure!(
            JobKey::from_job(&s.job) == *key
                && fleet == s.job.fleet_id.to_string()
                && idem == s.job.idempotency_key
                && parameters == s.job.parameter_digest()?
                && digest == s.job.digest()?
                && revision >= 0
                && revision as u64 == s.revision,
            "journal indexed context/digest/revision mismatch"
        );
        Ok(Some(s))
    }
    /// End the borrow explicitly; the host retains the original connection.
    #[cfg(test)]
    pub fn into_connection(self) -> &'c mut Connection {
        self.connection
    }
    pub fn get(&self, key: &JobKey) -> Result<Option<Snapshot>> {
        self.check_owner()?;
        Self::load(self.connection, key)
    }
    /// Read-only listing of every persisted row. Grants no admission, release or
    /// publication authority; the caller still owns fence/domain verification.
    pub(super) fn rows(&mut self) -> Result<Vec<Snapshot>> {
        self.check_owner()?;
        Self::read_rows(self.connection)
    }
    fn save(c: &Connection, key: &JobKey, old: u64, s: &Snapshot) -> Result<()> {
        s.validate()?;
        let body = serde_json::to_string(s)?;
        ensure!(body.len() <= MAX_ROW, "journal row bound exceeded");
        ensure!(
            c.execute(
                "UPDATE ferroc_fleet_jobs_v1 SET revision=?1,body=?2 WHERE k=?3 AND revision=?4",
                params![s.revision as i64, body, key.id(), old as i64]
            )? == 1,
            "journal concurrent revision conflict"
        );
        Ok(())
    }
    fn change(
        &mut self,
        key: &JobKey,
        revision: u64,
        action: impl FnOnce(&mut Snapshot, &Connection) -> Result<()>,
    ) -> Result<Snapshot> {
        self.check_owner()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut s = Self::load(&tx, key)?.context("unknown fleet journal job")?;
        ensure!(
            s.owner == self.owner && s.revision == revision,
            "journal owner/revision conflict"
        );
        ensure!(
            !s.is_migrated_origin(),
            "migrated origin history is immutable"
        );
        action(&mut s, &tx)?;
        s.revision = s
            .revision
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .context("journal revision exhausted")?;
        Self::save(&tx, key, revision, &s)?;
        tx.commit()?;
        Ok(s)
    }
    pub fn admit(&mut self, job: JobSpec, now_ms: u64) -> Result<(bool, Snapshot)> {
        self.check_owner()?;
        let parameter = job.parameter_digest()?;
        let digest = job.digest()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT k FROM ferroc_fleet_jobs_v1 WHERE fleet=?1 AND idem=?2",
                params![job.fleet_id.to_string(), job.idempotency_key],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            let key_text: Vec<_> = existing.split(':').collect();
            ensure!(key_text.len() == 3, "corrupt journal key index");
            let key = JobKey {
                fleet: Uuid::parse_str(key_text[0])?,
                transfer: Uuid::parse_str(key_text[1])?,
                file: Uuid::parse_str(key_text[2])?,
            };
            let s = Self::load(&tx, &key)?.context("missing idempotent journal row")?;
            ensure!(
                s.job.parameter_digest()? == parameter,
                "idempotency key reused with different parameters"
            );
            tx.commit()?;
            return Ok((false, s));
        }
        ensure!(now_ms < job.deadline_ms, "new journal job deadline expired");
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM ferroc_fleet_jobs_v1 LIMIT 129)",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            count < MAX_JOBS as i64,
            "journal capacity exhausted; no automatic receipt eviction"
        );
        let s = Snapshot {
            version: 1,
            job,
            owner: self.owner,
            revision: 0,
            phase: Phase::Queued,
            stage: None,
            received: 0,
            verified: false,
            intent: None,
            receipt: None,
            absence_release: None,
            data_seal: None,
            intent_binding: None,
            target_observation: None,
            settlement_origin: None,
            settlement_binding: None,
            retained: None,
        };
        s.validate()?;
        let body = serde_json::to_string(&s)?;
        ensure!(body.len() <= MAX_ROW, "journal row bound exceeded");
        tx.execute("INSERT INTO ferroc_fleet_jobs_v1(k,fleet,idem,parameters,digest,revision,body) VALUES(?1,?2,?3,?4,?5,0,?6)",params![JobKey::from_job(&s.job).id(),s.job.fleet_id.to_string(),s.job.idempotency_key,parameter.as_slice(),digest.as_slice(),body])?;
        tx.commit()?;
        Ok((true, s))
    }
    fn require_no_quarantine(c: &Connection, owner: Uuid) -> Result<()> {
        let keys: Vec<String> = {
            let mut q=c.prepare("SELECT CASE WHEN length(k)<=128 THEN k ELSE NULL END FROM ferroc_fleet_jobs_v1 LIMIT 129")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        ensure!(keys.len() <= MAX_JOBS, "journal over capacity");
        for id in keys {
            let parts: Vec<_> = id.split(':').collect();
            ensure!(parts.len() == 3, "invalid indexed journal key");
            let key = JobKey {
                fleet: Uuid::parse_str(parts[0])?,
                transfer: Uuid::parse_str(parts[1])?,
                file: Uuid::parse_str(parts[2])?,
            };
            let r = Self::load(c, &key)?.context("missing recovery row")?;
            ensure!(
                !(r.stage.is_some()
                    && (r.owner != owner
                        || matches!(
                            r.phase,
                            Phase::Interrupted | Phase::CancelRequested | Phase::CommitUnknown
                        ))),
                "new stage blocked by unresolved reservation/recovery"
            );
        }
        Ok(())
    }

    pub fn attach_stage(
        &mut self,
        key: &JobKey,
        revision: u64,
        stage: StageReference,
    ) -> Result<Snapshot> {
        self.change(key, revision, |s, c| {
            Self::require_no_quarantine(c, s.owner)?;
            ensure!(
                s.phase == Phase::Queued && stage.reserved == s.job.bytes_total,
                "invalid stage admission"
            );
            ensure!(
                stage.allocation.is_none(),
                "allocated stages require fenced allocation factory"
            );
            stage.validate()?;
            s.stage = Some(stage);
            s.phase = Phase::Transferring;
            Ok(())
        })
    }
    pub(super) fn reserve_reference(
        &mut self,
        key: &JobKey,
        revision: u64,
        stage: StageReference,
    ) -> Result<Snapshot> {
        let owner = self.owner;
        let fence = self.fence.context("allocation requires native fence")?;
        let database_id = fence.database_id();
        let database_parent_id = fence.database_parent_id()?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.phase == Phase::Queued
                    && s.stage.is_none()
                    && stage.reserved == s.job.bytes_total,
                "invalid allocation reservation"
            );
            let a = stage
                .allocation
                .as_ref()
                .context("missing allocation metadata")?;
            ensure!(
                a.owner == owner
                    && a.file_id.is_none()
                    && a.database_id() == Some(database_id)
                    && a.database_parent_id() == Some(database_parent_id.as_str()),
                "invalid reservation origin"
            );
            stage.validate()?;
            let anonymous = a.is_anonymous();
            ensure!(
                !anonymous || !s.job.overwrite || s.job.pre_image_sha256.is_some(),
                "anonymous replacement requires the authorized pre-image"
            );
            ensure!(
                Self::read_rows(c)?.iter().all(|r| r.stage.is_none()),
                "existing durable obligations block allocation"
            );
            ensure!(
                c.execute(
                    if anonymous { "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(12,13) THEN version ELSE 11 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)" } else { "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(4,5,6,7,8,9,10,11,12,13) THEN version ELSE 3 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)" },
                    []
                )? == 1,
                "ambiguous allocation schema"
            );
            s.version = 3;
            s.stage = Some(stage);
            s.phase = Phase::Interrupted;
            Ok(())
        })
    }
    /// Recovery-side rebinding: the allocation still names the STOPPED origin
    /// owner (that is what recover_stopped_owner preserved). Only an unbound
    /// allocation in Interrupted phase owned by the CURRENT fence may be
    /// bound to a freshly observed object id. NOT a debt release or publication.
    /// Reachable only from the adopt takeover path (tests until FleetHost
    /// wiring lands); explicit allow keeps strict lint clean.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn rebind_recovered_reference(
        &mut self,
        key: &JobKey,
        revision: u64,
        file: &str,
        durability: ParentDurability,
        expected_old_owner: uuid::Uuid,
    ) -> Result<Snapshot> {
        let owner = self.owner;
        self.change(key, revision, |s, _| {
            ensure!(
                s.phase == Phase::Interrupted,
                "allocation no longer isolated"
            );
            let a = s
                .stage
                .as_mut()
                .and_then(|r| r.allocation.as_mut())
                .context("missing allocation")?;
            ensure!(
                a.owner == expected_old_owner && a.owner != owner,
                "recovery binding conflict"
            );
            // The original admission already bound an object id. The takeover
            // re-observes the SAME live object; a different id means the file
            // changed hands and must fail closed.
            if let Some(existing) = a.file_id.as_ref() {
                ensure!(existing == file, "recovered stage object changed");
            } else {
                a.file_id = Some(file.into());
            }
            a.parent_durability = Some(durability);
            Ok(())
        })
    }
    pub(super) fn bind_reference(
        &mut self,
        key: &JobKey,
        revision: u64,
        file: &str,
        durability: ParentDurability,
    ) -> Result<Snapshot> {
        let owner = self.owner;
        self.change(key, revision, |s, _| {
            ensure!(
                s.phase == Phase::Interrupted,
                "allocation no longer isolated"
            );
            let a = s
                .stage
                .as_mut()
                .and_then(|r| r.allocation.as_mut())
                .context("missing allocation")?;
            ensure!(
                a.owner == owner && a.file_id.is_none(),
                "allocation owner/binding conflict"
            );
            a.file_id = Some(file.into());
            a.parent_durability = Some(durability);
            Ok(())
        })
    }

    pub(super) fn release_reference(
        &mut self,
        key: &JobKey,
        revision: u64,
        policy: &crate::config::Policy,
        approval: &super::reconcile::AbsenceApproval,
    ) -> Result<Snapshot> {
        let fence = self
            .fence
            .context("absence release requires native fence")?;
        let mut held_parent = None;
        let result = self.change(key, revision, |s, c| {
            fence.check_connection(c)?;
            let (record, parent) = super::reconcile::authorize(s, fence, policy, approval)?;
            held_parent = Some(parent);
            s.stage = None;
            s.absence_release = Some(record);
            s.phase = Phase::Cancelled;
            fence.check_connection(c)?;
            Ok(())
        });
        // Keep the parent handle pinned until after COMMIT or rollback.
        drop(held_parent);
        result
    }

    // Crash-persistent receive marker BEFORE any writable capability/DATA. Old
    // v3 readers must refuse schema4; count is NOT persisted interval coverage.
    pub(super) fn begin_receive(&mut self, key: &JobKey, revision: u64) -> Result<Snapshot> {
        let fence = self.fence.context("receive requires native fence")?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.is_absence_candidate() && s.phase == Phase::Interrupted,
                "receive needs fresh isolated allocation"
            );
            let a = s
                .stage
                .as_ref()
                .and_then(|r| r.allocation.as_ref())
                .context("missing bound allocation")?;
            ensure!(
                a.original_owner() == fence.owner
                    && a.file_id().is_some()
                    && a.database_id() == Some(fence.database_id())
                    && a.database_parent_id() == Some(fence.database_parent_id()?.as_str()),
                "receive allocation owner/domain mismatch"
            );
            ensure!(
                c.execute(
                    "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(5,6,7,8,9,10,11,12,13) THEN version ELSE 4 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)",
                    []
                )? == 1,
                "ambiguous receive schema"
            );
            s.version = 4;
            s.phase = Phase::Transferring;
            Ok(())
        })
    }

    /// Trusted live LOCAL coordinator only. Count is not coverage; no digest
    /// readback is asserted here. Fresh FINISH/memory coverage/lease/file checks
    /// belong to HostReceiver, and restart can never mint a sealed capability.
    pub(super) fn seal_data(
        &mut self,
        key: &JobKey,
        revision: u64,
        binding: super::protocol::Binding,
    ) -> Result<Snapshot> {
        let fence = self.fence.context("DATA seal requires native fence")?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.version == 4
                    && s.phase == Phase::Transferring
                    && s.data_seal.is_none()
                    && s.received == s.job.bytes_total,
                "not fresh complete receiving state"
            );
            let a = s
                .stage
                .as_ref()
                .and_then(|r| r.allocation.as_ref())
                .context("missing seal allocation")?;
            ensure!(
                s.owner == fence.owner
                    && a.original_owner() == fence.owner
                    && a.database_id() == Some(fence.database_id())
                    && a.database_parent_id() == Some(fence.database_parent_id()?.as_str()),
                "seal owner/domain mismatch"
            );
            let file_id = a
                .file_id()
                .context("seal file identity missing")?
                .to_owned();
            ensure!(
                c.execute(
                    "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(6,7,8,9,10,11,12,13) THEN version ELSE 5 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)",
                    []
                )? == 1,
                "ambiguous seal schema"
            );
            s.data_seal = Some(DataSeal {
                id: Uuid::new_v4(),
                binding,
                job_digest: s.job.digest()?,
                file_id,
                original_owner: s.owner,
            });
            s.version = 5;
            fence.check_connection(c)?;
            Ok(())
        })
    }

    /// Trusted LOCAL assertion under Runtime gate+live lease+fresh full hash.
    /// This is a durable event, NOT a later publish permit or file immutability.
    pub(super) fn reserve_sealed_commit(
        &mut self,
        key: &JobKey,
        revision: u64,
        binding: super::protocol::Binding,
    ) -> Result<Snapshot> {
        let fence = self.fence.context("sealed intent requires fence")?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.version == 5
                    && s.phase == Phase::Transferring
                    && s.received == s.job.bytes_total
                    && s.data_seal.is_some()
                    && !s.verified
                    && s.intent.is_none(),
                "sealed commit admission out of order"
            );
            let a = s
                .stage
                .as_ref()
                .and_then(|r| r.allocation.as_ref())
                .context("intent allocation missing")?;
            ensure!(
                s.owner == fence.owner
                    && a.original_owner() == fence.owner
                    && a.database_id() == Some(fence.database_id())
                    && a.database_parent_id() == Some(fence.database_parent_id()?.as_str()),
                "intent owner/domain mismatch"
            );
            ensure!(
                c.execute(
                    "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(7,8,9,10,11,12,13) THEN version ELSE 6 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)",
                    []
                )? == 1,
                "ambiguous intent schema"
            );
            s.version = 6;
            s.verified = true;
            s.intent = Some(Uuid::new_v4());
            s.intent_binding = Some(binding);
            s.phase = Phase::Committing;
            fence.check_connection(c)?;
            Ok(())
        })
    }

    // Before ONE native publication attempt. A crash/cancel remains unknown,
    // never a restart/adoption/publish/receipt permission or absence release.
    #[cfg(any(windows, target_os = "linux"))]
    pub(super) fn mark_publication_attempt(
        &mut self,
        key: &JobKey,
        revision: u64,
    ) -> Result<Snapshot> {
        let fence = self.fence.context("publication attempt requires fence")?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.version == 6
                    && s.phase == Phase::Committing
                    && s.owner == fence.owner
                    && s.intent.is_some()
                    && s.verified,
                "publication attempt out of order"
            );
            fence.check_connection(c)?;
            // A replacement database is marked 10 so every v7/v8/v9 reader
            // refuses it at open: those readers would otherwise see the same row
            // version 7 and treat a replacing rename as a no-clobber one. The
            // pre-image was re-checked under this same gate immediately before.
            let statement = if s.job.overwrite {
                "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(11,12,13) THEN version ELSE 10 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)"
            } else {
                "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(8,9,10,11,12,13) THEN version ELSE 7 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)"
            };
            ensure!(
                c.execute(statement, [])? == 1,
                "ambiguous publication schema"
            );
            s.version = 7;
            s.phase = Phase::CommitUnknown;
            Ok(())
        })
    }

    /// Crate-internal LOCAL observation assertion; never a final wire receipt.
    /// Only fresh live Windows ownership can call through the real IO path.
    #[cfg(any(windows, target_os = "linux"))]
    pub(super) fn record_target_observation(
        &mut self,
        key: &JobKey,
        revision: u64,
        binding: super::protocol::Binding,
        target_file_id: String,
        parent_id: String,
    ) -> Result<Snapshot> {
        let fence = self
            .fence
            .context("target observation requires native fence")?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.version == 7
                    && s.phase == Phase::CommitUnknown
                    && s.target_observation.is_none()
                    && s.receipt.is_none(),
                "target observation out of order"
            );
            let a = s
                .stage
                .as_ref()
                .and_then(|r| r.allocation())
                .context("target observation allocation missing")?;
            ensure!(
                s.owner == fence.owner
                    && a.original_owner() == fence.owner
                    && a.database_id() == Some(fence.database_id())
                    && a.database_parent_id() == Some(fence.database_parent_id()?.as_str()),
                "target observation domain mismatch"
            );
            fence.check_connection(c)?;
            ensure!(
                c.execute(
                    "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(9,10,11,12,13) THEN version ELSE 8 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)",
                    []
                )? == 1,
                "ambiguous target observation schema"
            );
            s.version = 8;
            s.target_observation = Some(TargetObservationReceipt {
                observation_id: Uuid::new_v4(),
                commit_intent: s.intent.context("target observation missing intent")?,
                binding,
                size: s.job.bytes_total,
                sha256: s.job.sha256,
                target_file_id,
                parent_id,
                parent_durability: ParentDurability::Unsupported,
            });
            Ok(())
        })
    }

    /// LOCAL explicit settlement assertion from the current retained File owner.
    /// Not a restart/peer/metadata completion path. FULL commit may precede error.
    #[cfg(any(windows, target_os = "linux"))]
    pub(super) fn settle_live_target(
        &mut self,
        key: &JobKey,
        revision: u64,
        binding: super::protocol::Binding,
        file: String,
        parent: String,
    ) -> Result<Snapshot> {
        let fence = self.fence.context("settlement requires native fence")?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.version == 8
                    && s.phase == Phase::CommitUnknown
                    && s.receipt.is_none()
                    && s.target_observation.is_some(),
                "not a fresh live target settlement"
            );
            let origin = s.stage.as_ref().context("settlement stage missing")?;
            let a = origin
                .allocation()
                .context("settlement allocation missing")?;
            ensure!(
                s.owner == fence.owner
                    && a.original_owner() == fence.owner
                    && a.database_id() == Some(fence.database_id())
                    && a.database_parent_id() == Some(fence.database_parent_id()?.as_str())
                    && a.file_id() == Some(file.as_str())
                    && a.parent_id() == parent,
                "settlement owner/object/domain mismatch"
            );
            fence.check_connection(c)?;
            ensure!(
                c.execute(
                    "UPDATE ferroc_fleet_meta SET version=CASE WHEN version IN(10,11,12,13) THEN version ELSE 9 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)",
                    []
                )? == 1,
                "ambiguous settlement schema"
            );
            s.settlement_origin = s.stage.take();
            s.settlement_binding = Some(binding);
            s.version = 9;
            s.receipt = Some(Receipt {
                receipt_id: s.intent.context("settlement intent missing")?,
                size: s.job.bytes_total,
                sha256: s.job.sha256,
                parent_durability: ParentDurability::Unsupported,
            });
            s.phase = Phase::Completed;
            Ok(())
        })
    }

    pub fn progress(&mut self, key: &JobKey, revision: u64, received: u64) -> Result<Snapshot> {
        self.change(key, revision, |s, _| {
            ensure!(
                s.phase == Phase::Transferring
                    && s.data_seal.is_none()
                    && received >= s.received
                    && received <= s.job.bytes_total,
                "invalid received progress"
            );
            s.received = received;
            Ok(())
        })
    }
    /// Trusted LOCAL readback assertion, not source-offered SHA or proof of IO.
    /// Coordinator still must verify real coverage/readback/lease at fs admission.
    pub fn readback(&mut self, key: &JobKey, revision: u64, actual: [u8; 32]) -> Result<Snapshot> {
        self.change(key, revision, |s, _| {
            ensure!(
                s.phase == Phase::Transferring
                    && s.received == s.job.bytes_total
                    && actual == s.job.sha256,
                "readback/coverage assertion mismatch"
            );
            s.verified = true;
            s.phase = Phase::Verifying;
            Ok(())
        })
    }
    /// Durable intent BEFORE effects, not a reusable authorization/commit permit.
    pub fn begin_commit(&mut self, key: &JobKey, revision: u64) -> Result<Snapshot> {
        self.change(key, revision, |s, _| {
            ensure!(
                s.phase == Phase::Verifying && s.verified,
                "unverified/out-of-order commit intent"
            );
            s.intent = Some(Uuid::new_v4());
            s.phase = Phase::Committing;
            Ok(())
        })
    }
    pub fn cancel(&mut self, key: &JobKey, revision: u64) -> Result<Snapshot> {
        self.change(key, revision, |s, _| {
            s.phase = match s.phase {
                Phase::Completed | Phase::Cancelled => s.phase,
                Phase::Committing | Phase::CommitUnknown => Phase::CommitUnknown,
                _ => Phase::CancelRequested,
            };
            Ok(())
        })
    }
    /// Read-only absence confirmation of a trusted recorded path. A permission
    /// failure/remaining link never releases reservation. Never deletes a file.
    pub fn confirm_removed(&mut self, key: &JobKey, revision: u64) -> Result<Snapshot> {
        self.change(key,revision,|s,_|{ensure!(s.stage.as_ref().is_none_or(|r|r.allocation.is_none()),"allocated obligations require explicit object reconciliation");ensure!(matches!(s.phase,Phase::CancelRequested|Phase::Interrupted|Phase::Cancelled),"cleanup cannot cancel a possible publication");if let Some(stage)=&s.stage {ensure!(matches!(fs::symlink_metadata(stage.path()),Err(e) if e.kind()==std::io::ErrorKind::NotFound),"stage removal not confirmed; reservation retained");}s.stage=None;s.phase=Phase::Cancelled;Ok(())})
    }
    /// Supply actual local StageFile::publish result, not an unauthenticated peer
    /// assertion. Receipt is returned only AFTER database COMMIT succeeds.
    /// ParentDurability::Unsupported explicitly does not promise file survival.
    pub fn publication(&mut self, key: &JobKey, revision: u64, p: Publication) -> Result<Snapshot> {
        self.change(key, revision, |s, _| {
            ensure!(
                s.version == 1,
                "allocated publication requires current live owner; no metadata replay"
            );
            let (size, sha) = match &p {
                Publication::Published { size, sha256, .. }
                | Publication::Uncertain { size, sha256, .. } => (*size, *sha256),
            };
            ensure!(
                size == s.job.bytes_total && sha == s.job.sha256,
                "publication differs from authorized job"
            );
            ensure!(
                matches!(
                    s.phase,
                    Phase::Committing | Phase::CommitUnknown | Phase::Completed
                ) && s.verified,
                "publication lacks verified durable intent"
            );
            match p {
                Publication::Published { parent_sync, .. } => {
                    let r = Receipt {
                        receipt_id: s.intent.context("missing commit intent")?,
                        size,
                        sha256: sha,
                        parent_durability: match parent_sync {
                            ParentSync::Synced => ParentDurability::Synced,
                            ParentSync::Unsupported => ParentDurability::Unsupported,
                        },
                    };
                    if let Some(old) = &s.receipt {
                        ensure!(*old == r, "conflicting commit receipt");
                    }
                    s.receipt = Some(r);
                    s.stage = None;
                    s.phase = Phase::Completed;
                }
                Publication::Uncertain { .. } => {
                    ensure!(
                        s.receipt.is_none(),
                        "uncertain event cannot erase observed completion"
                    );
                    s.phase = Phase::CommitUnknown;
                }
            }
            Ok(())
        })
    }
    /// ONLY after an external coordinator proved old owner stopped/fenced. Not
    /// heartbeat expiry, a wall-clock guess, or a multi-writer automatic resume.
    pub fn recover_stopped_owner(&mut self, stopped: Uuid) -> Result<Vec<Snapshot>> {
        self.check_owner()?;
        ensure!(
            !stopped.is_nil() && stopped != self.owner,
            "invalid stopped owner"
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let keys: Vec<String> = {
            let mut q = tx.prepare("SELECT k FROM ferroc_fleet_jobs_v1 LIMIT 129")?;
            q.query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        ensure!(keys.len() <= MAX_JOBS, "journal over capacity");
        let mut recovered = Vec::new();
        for key in keys {
            let parts: Vec<_> = key.split(':').collect();
            ensure!(parts.len() == 3, "corrupt journal key");
            let key = JobKey {
                fleet: Uuid::parse_str(parts[0])?,
                transfer: Uuid::parse_str(parts[1])?,
                file: Uuid::parse_str(parts[2])?,
            };
            let mut s = Self::load(&tx, &key)?.context("lost recovery row")?;
            if s.owner != stopped || s.is_migrated_origin() {
                continue;
            }
            let old = s.revision;
            s.owner = self.owner;
            s.phase = match s.phase {
                Phase::Queued | Phase::Cancelled => s.phase,
                Phase::Completed | Phase::Committing | Phase::CommitUnknown => Phase::CommitUnknown,
                Phase::CancelRequested => Phase::CancelRequested,
                _ => Phase::Interrupted,
            };
            // Archived receipts survive. Completed becomes unknown after restart
            // until local destination reconciliation; DB bytes are not file truth.
            s.revision = s
                .revision
                .checked_add(1)
                .context("recovery revision overflow")?;
            Self::save(&tx, &key, old, &s)?;
            recovered.push(s);
        }
        tx.commit()?;
        Ok(recovered)
    }
}
#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
