//! Runtime-bound, synchronous LOCAL metadata/empty-file admission coordinator.
//! Not wired to any CLI/MCP/network. No writable stages or second DB/service.
//! One Runtime attachment and native SAME-DB fence; no raw DB/fence/gate export.
use super::{
    fence::{FencedConnection, OwnerFence},
    inventory::{InventoryLimits, RecoveryInventory},
    job::JobSpec,
    journal::{JobKey, Snapshot},
    reconcile::{AbsenceApproval, Reconciliation},
};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use std::{
    path::Path,
    sync::{Arc, Condvar, Mutex},
};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostMode {
    Paused,
    /// Explicit retained-stage admissions only; ordinary fresh work stays closed.
    RecoveryOnly,
    Running,
    Closing,
    Closed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostStatus {
    pub mode: HostMode,
    pub in_flight: usize,
}
/// A local result only. An existing queued/interrupted job is NEVER recreated
/// on replay; inspect its Snapshot. new_job does not mean DATA was received.
pub struct HostAdmission {
    pub new_job: bool,
    pub snapshot: Snapshot,
}
/// In-process, one-use evidence of a cooperative host's TERMINAL creator drain
/// and DB/fence close. Not a lease, disk receipt or authorization to retire debt.
/// Not crash-persistent: crash recovery keeps using the existing native takeover
/// contract. Copying IDs/UUIDs never constructs this proof. No file IDs resist
/// hostile rollback or object-ID reuse; those remain outside this local contract.
/// ```compile_fail
/// use ferroc::fleet::host::StoppedCreators;
/// fn cannot_import_wire(){let _:StoppedCreators=serde_json::from_str("{}").unwrap();}
/// ```
/// ```compile_fail
/// fn cannot_clone(p:ferroc::fleet::host::StoppedCreators){let _=p.clone();}
/// ```
/// ```compile_fail
/// fn cannot_replay(h:&ferroc::fleet::host::FleetHost<'_>,p:ferroc::fleet::host::StoppedCreators){let _=h.recover_creators(p);let _=h.recover_creators(p);}
/// ```
/// ```compile_fail
/// fn cannot_forge(){let _=ferroc::fleet::host::StoppedCreators{origin:uuid::Uuid::new_v4(),database:String::new(),parent:String::new()};}
/// ```
pub struct StoppedCreators {
    origin: Uuid,
    database: String,
    parent: String,
}
impl StoppedCreators {
    pub fn origin_owner(&self) -> Uuid {
        self.origin
    }
}

#[derive(Default)]
pub(crate) struct HostRegistration {
    pub(crate) attached: bool,
    pub(crate) stopped: bool,
    pub(crate) control: std::sync::Weak<HostControl>,
    pub(crate) tasks: Option<super::transfer_tasks::TransferTasks>,
    pub(crate) setup: std::sync::Weak<super::setup_agent::SetupControl>,
    pub(crate) mcp: Option<std::sync::Arc<super::mcp_transfer::McpTransfer>>,
}
// Shared lifecycle only, not DB ownership; Runtime holds just a Weak registration.
pub(crate) struct HostControl {
    control: Arc<Mutex<HostStatus>>,
    idle: Arc<Condvar>,
}
impl HostControl {
    /// Terminally reject new host operations without waiting on live owners.
    /// Runtime uses this BEFORE cancelling/draining its owned task futures.
    pub(crate) fn stop_admission(&self) -> Result<()> {
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        if state.mode != HostMode::Closed {
            state.mode = HostMode::Closing;
        }
        Ok(())
    }
    pub(crate) fn stop_and_drain(&self) -> Result<()> {
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        if state.mode == HostMode::Closed {
            return Ok(());
        }
        state.mode = HostMode::Closing;
        while state.in_flight != 0 {
            state = self
                .idle
                .wait(state)
                .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        }
        Ok(())
    }
}

/// Must not outlive its Runtime or detach asynchronous creators. All operations
/// are synchronous: async hosts must use an appropriate blocking execution lane.
/// Call close() to stop new work, wait for all accepted operations and close DB.
/// Pause stops NEW admissions only; already accepted work can produce effects.
/// Runtime::shutdown also terminally stops admissions and drains this same
/// control, but deliberately leaves the externally held DB/fence for close/Drop.
/// Drop merely closes retained handles (no cleanup or quota forgiveness).
/// ```compile_fail
/// fn cannot_export_database(h:ferroc::fleet::host::FleetHost<'_>){let _=h.database;}
/// ```
/// ```compile_fail
/// use ferroc::{runtime::Runtime,config::Policy,fleet::{host::FleetHost,inventory::InventoryLimits}};
/// fn cannot_outlive_runtime(p:Policy,path:&std::path::Path)->FleetHost<'static>{let r=Runtime::new(p);r.open_fleet_host(path,InventoryLimits::default()).unwrap()}
/// ```
pub struct FleetHost<'runtime> {
    // Database/guard drop BEFORE attachment releases Runtime's one-host slot.
    database: Mutex<Option<FencedConnection>>,
    gate: Arc<Mutex<()>>,
    limits: InventoryLimits,
    control: Arc<Mutex<HostStatus>>,
    idle: Arc<Condvar>,
    _lifecycle: Arc<HostControl>,
    attachment: Attachment<'runtime>,
}
struct Attachment<'r> {
    runtime: &'r Runtime,
}
impl Drop for Attachment<'_> {
    fn drop(&mut self) {
        self.runtime.fleet_host_detach();
    }
}
struct Operation<'a, 'r> {
    host: &'a FleetHost<'r>,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        let mut state = self
            .host
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight -= 1;
        self.host.idle.notify_all();
    }
}
impl<'r> FleetHost<'r> {
    pub(crate) fn open(
        runtime: &'r Runtime,
        path: &Path,
        gate: Arc<Mutex<()>>,
        limits: InventoryLimits,
    ) -> Result<Self> {
        limits.validate()?;
        let mut registration = runtime.fleet_host_claim()?;
        let _fs = gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        let fence = OwnerFence::acquire(path)?;
        let mut db = fence.open_connection()?;
        {
            let _journal = db.journal()?;
        }
        let control = Arc::new(Mutex::new(HostStatus {
            mode: HostMode::Paused,
            in_flight: 0,
        }));
        let idle = Arc::new(Condvar::new());
        let lifecycle = Arc::new(HostControl {
            control: control.clone(),
            idle: idle.clone(),
        });
        registration.control = Arc::downgrade(&lifecycle);
        registration.attached = true;
        drop(registration);
        let attachment = Attachment { runtime };
        Ok(Self {
            database: Mutex::new(Some(db)),
            gate: gate.clone(),
            limits,
            control,
            idle,
            _lifecycle: lifecycle,
            attachment,
        })
    }
    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn runtime(&self) -> &Runtime {
        self.attachment.runtime
    }
    pub fn status(&self) -> Result<HostStatus> {
        Ok(*self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?)
    }
    /// Explicit LOCAL operator selection. Does not forgive debt or permit
    /// ordinary fresh admissions, and does not authenticate a recovery itself.
    pub fn resume_retained_recovery(&self) -> Result<()> {
        ensure!(
            self.attachment.runtime.policy.allow_transfers,
            "transfers disabled by local policy"
        );
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        ensure!(
            !matches!(state.mode, HostMode::Closing | HostMode::Closed),
            "fleet host closing or closed"
        );
        state.mode = HostMode::RecoveryOnly;
        Ok(())
    }
    fn enter_recovery(&self) -> Result<Operation<'_, 'r>> {
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        ensure!(
            state.mode == HostMode::RecoveryOnly,
            "fleet host not in explicit recovery-only mode"
        );
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .context("host operation count overflow")?;
        Ok(Operation { host: self })
    }
    fn enter(&self, admission: bool) -> Result<Operation<'_, 'r>> {
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        ensure!(
            !matches!(state.mode, HostMode::Closing | HostMode::Closed),
            "fleet host closing or closed"
        );
        ensure!(
            !admission || state.mode == HostMode::Running,
            "fleet host paused"
        );
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .context("host operation count overflow")?;
        Ok(Operation { host: self })
    }
    fn with_database<T>(
        &self,
        admission: bool,
        action: impl FnOnce(&mut FencedConnection) -> Result<T>,
    ) -> Result<T> {
        let _operation = self.enter(admission)?;
        let mut db = self
            .database
            .lock()
            .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
        action(db.as_mut().context("host database closed")?)
    }
    pub fn pause(&self) -> Result<()> {
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        ensure!(
            !matches!(state.mode, HostMode::Closing | HostMode::Closed),
            "fleet host closing or closed"
        );
        state.mode = HostMode::Paused;
        Ok(())
    }
    /// Explicit clean-inventory check. This snapshot is not a reusable budget:
    /// every admission again verifies the fixed limits and persistent obligations.
    pub fn resume(&self) -> Result<()> {
        let report = self.inventory()?;
        if !report.complete() || report.recorded_usage() != (0, 0) {
            // Actionable, bounded diagnostics: counts and finding KINDS only, never
            // a path, digest or peer detail. The operator still needs
            // `fleet-inventory` to see the rows and `fleet-release` to retire one.
            let (bytes, slots) = report.recorded_usage();
            let kinds: Vec<&str> = report
                .findings()
                .iter()
                .map(|f| match f.kind {
                    super::inventory::FindingKind::AnonymousStageUnobservable => {
                        "anonymousStageUnobservable"
                    }
                    super::inventory::FindingKind::ForeignControl => "foreignControl",
                    super::inventory::FindingKind::ScopeUnavailable => "scopeUnavailable",
                    super::inventory::FindingKind::MissingStage => "missingStage",
                    super::inventory::FindingKind::UnsafeStage => "unsafeStage",
                    super::inventory::FindingKind::OversizedStage => "oversizedStage",
                    super::inventory::FindingKind::ScanLimit => "scanLimit",
                    super::inventory::FindingKind::QuotaExceeded => "quotaExceeded",
                    _ => "other",
                })
                .collect();
            anyhow::bail!(
                "unresolved inventory/debt blocks host admission: complete={} reservedBytes={} slots={} findings={:?}; inspect with `ferroc fleet-inventory`",
                report.complete(),
                bytes,
                slots,
                kinds
            );
        }
        ensure!(
            self.attachment.runtime.policy.allow_transfers,
            "transfers disabled by local policy"
        );
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        ensure!(
            !matches!(state.mode, HostMode::Closing | HostMode::Closed),
            "fleet host closing or closed"
        );
        state.mode = HostMode::Running;
        Ok(())
    }
    /// Closing is terminal and counts operations already queued behind the DB mutex.
    /// No forced timeout, fake cancellation or debt release. The Runtime attachment
    /// remains occupied until this object is dropped, even after close returns.
    pub fn close(&self) -> Result<()> {
        self.close_inner(|_| Ok(()))?;
        Ok(())
    }
    /// Terminally consumes the creator lifecycle, NOT merely pause. Waits for
    /// accepted/queued operations, validates the actual domain under Runtime's
    /// gate, then closes DB/fence BEFORE issuing the one-use proof. The closed
    /// host must still Drop before its Runtime attachment can be reused.
    /// Errors mint no proof and retain the Closing host/fence until close/Drop.
    /// A previously closed host cannot reconstruct or issue another proof.
    pub fn stop_creators(&self) -> Result<StoppedCreators> {
        self.close_inner(|db| {
            let _gate = self
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            db.fence.check_connection(&db.connection)?;
            Ok(StoppedCreators {
                origin: db.fence.owner,
                database: db.fence.database_id().into(),
                parent: db.fence.database_parent_id()?,
            })
        })?
        .context("host already closed: no fresh creator proof")
    }
    /// Consumes a real previous host's stop proof AFTER this host acquired its
    /// own native fence. Revalidates original DB+parent objects, not filenames.
    /// Only recovers journal ownership; leaves every file/debt unchanged and
    /// never resumes admission. Failure consumes the proof too: reload/inspect
    /// after SQL uncertainty; no blind replay or automatic absence approval.
    pub fn recover_creators(&self, proof: StoppedCreators) -> Result<Vec<Snapshot>> {
        self.with_database(false, |db| {
            let _gate = self
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            db.fence.check_connection(&db.connection)?;
            ensure!(
                proof.origin != db.fence.owner
                    && proof.database == db.fence.database_id()
                    && proof.parent == db.fence.database_parent_id()?,
                "creator proof belongs to another native DB/parent domain"
            );
            let rows = db.journal()?.recover_stopped_owner(proof.origin)?;
            db.fence.check_connection(&db.connection)?;
            Ok(rows)
        })
    }

    fn close_inner<T>(
        &self,
        observe: impl FnOnce(&FencedConnection) -> Result<T>,
    ) -> Result<Option<T>> {
        let mut state = self
            .control
            .lock()
            .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        if state.mode == HostMode::Closed {
            return Ok(None);
        }
        state.mode = HostMode::Closing;
        while state.in_flight != 0 {
            state = self
                .idle
                .wait(state)
                .map_err(|_| anyhow::anyhow!("host control poisoned"))?;
        }
        let mut connection = self
            .database
            .lock()
            .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
        let observation = observe(connection.as_ref().context("host database closed")?)?;
        // Hold admission control until the retained connection (and fence) is closed.
        let db = connection.take();
        drop(db);
        state.mode = HostMode::Closed;
        self.idle.notify_all();
        Ok(Some(observation))
    }
    /// One serialized metadata/empty-file workflow. Each filesystem phase reuses
    /// Runtime's actual gate and rechecks paths; a mutation BETWEEN reserve/create
    /// can cause failure but never rolls back the durable reservation. No automatic
    /// create retry/resume on idempotent job replay. Not lease/network admission.
    pub fn admit(&self, job: JobSpec, now_ms: u64) -> Result<HostAdmission> {
        self.admit_inner(job, now_ms, |_| Ok(()))
    }
    fn admit_inner(
        &self,
        job: JobSpec,
        now_ms: u64,
        after_reservation: impl FnOnce(&Snapshot) -> Result<()>,
    ) -> Result<HostAdmission> {
        self.with_database(true, |db| {
            let key = JobKey::from_job(&job);
            let (new, snapshot) = db.journal()?.admit(job, now_ms)?;
            if !new {
                return Ok(HostAdmission {
                    new_job: false,
                    snapshot,
                });
            }
            let reserved = db.reserve_stage(
                &key,
                snapshot.revision(),
                &self.attachment.runtime.policy,
                self.gate.clone(),
                self.limits,
            )?;
            after_reservation(&reserved)?;
            let snapshot = db.create_reserved_stage(
                &key,
                reserved.revision(),
                &self.attachment.runtime.policy,
                self.gate.clone(),
            )?;
            Ok(HostAdmission {
                new_job: true,
                snapshot,
            })
        })
    }
    pub fn get(&self, key: &JobKey) -> Result<Option<Snapshot>> {
        self.with_database(false, |db| db.journal()?.get(key))
    }
    /// Read-only: every persisted obligation row. No admission, release, stage
    /// creation or publication; callers still need the real fence/database.
    pub fn obligations(&self) -> Result<Vec<Snapshot>> {
        self.with_database(false, |db| db.journal()?.rows())
    }
    pub fn inventory(&self) -> Result<RecoveryInventory> {
        self.with_database(false, |db| {
            db.inventory(
                &self.attachment.runtime.policy,
                &self.attachment.runtime.policy.roots,
                self.gate.clone(),
                self.limits,
            )
        })
    }
    pub fn cancel(&self, key: &JobKey, revision: u64) -> Result<Snapshot> {
        self.with_database(false, |db| db.journal()?.cancel(key, revision))
    }
    /// Explicit recovery only; metadata takeover alone does NOT prove stopped origin.
    /// Actual release still verifies persisted DB+parent domain and original owner.
    pub fn recover_stopped_owner(&self, stopped: Uuid) -> Result<Vec<Snapshot>> {
        self.with_database(false, |db| db.journal()?.recover_stopped_owner(stopped))
    }
    /// Explicit LOCAL stopped-owner selection under this host's exclusive native
    /// DB fence. Only the exact retained precommit row is taken over; unrelated
    /// obligations stay unchanged. This never constructs StoppedCreators, releases
    /// debt or returns an IO owner. Caller must independently know the old process
    /// has stopped; PID/timeout/UUID alone is not that evidence. BOTH recovery
    /// proofs and original-object readback remain required by receiver admission.
    pub fn recover_retained_job(
        &self,
        key: &JobKey,
        stopped: Uuid,
        revision: u64,
    ) -> Result<Snapshot> {
        let _operation = self.enter_recovery()?;
        let mut guard = self
            .database
            .lock()
            .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
        let db = guard.as_mut().context("host database closed")?;
        db.fence.check_connection(&db.connection)?;
        let row = db.journal()?.recover_retained_job(key, stopped, revision)?;
        db.fence.check_connection(&db.connection)?;
        Ok(row)
    }
    /// Read-only verification of the selected recovered prefix. Still not an IO
    /// capability: receiver admission repeats this against its live typed lease.
    pub fn inspect_retained_checkpoint(
        &self,
        key: &JobKey,
        max_prefix_bytes: u64,
    ) -> Result<super::checkpoint_readback::CheckpointReadback> {
        let _operation = self.enter_recovery()?;
        let mut guard = self
            .database
            .lock()
            .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
        let db = guard.as_mut().context("host database closed")?;
        db.inspect_retained_checkpoint(
            key,
            &self.attachment.runtime.policy,
            self.gate.clone(),
            max_prefix_bytes,
        )
    }
    pub fn inspect_allocation(&self, key: &JobKey) -> Result<Reconciliation> {
        self.with_database(false, |db| {
            db.inspect_allocation(key, &self.attachment.runtime.policy, self.gate.clone())
        })
    }
    pub fn release_absent_allocation(
        &self,
        key: &JobKey,
        revision: u64,
        approval: AbsenceApproval,
    ) -> Result<Snapshot> {
        self.with_database(false, |db| {
            db.release_absent_allocation(
                key,
                revision,
                &self.attachment.runtime.policy,
                approval,
                self.gate.clone(),
            )
        })
    }
}
#[cfg(test)]
#[path = "creator_tests.rs"]
mod creator_tests;
#[path = "receive.rs"]
pub mod receiver;
#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
