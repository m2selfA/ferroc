//! Bounded LOCAL background task ownership for the future MCP fleet backend.
//! Not enrollment, file admission, a network service, restart recovery or an MCP
//! entrypoint. The caller supplies a locally approved grant and the real worker.
//! Success accepts only an authenticated peer observation for that exact job;
//! it remains a peer statement, never proof of remote private IO.
use super::{
    job::{LeaseProfile, ValidatedGrant},
    source::PeerCommitObservation,
    sync_exec::CancelToken,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskPhase {
    Queued,
    Running,
    CancelRequested,
    Interrupted,
    PeerReportedCompleted,
    Failed,
}
impl TaskPhase {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Interrupted | Self::PeerReportedCompleted | Self::Failed
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskFailure {
    WorkerFailed,
    WorkerDropped,
    ReceiptMismatch,
    LocalStop,
    TaskDeadline,
}
/// No payload, paths, device token or worker error text is exposed. Unknown
/// remote coverage is None, NOT zero; encoded bytes are not network bytes.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskSnapshot {
    pub id: Uuid,
    pub phase: TaskPhase,
    pub planned_bytes: u64,
    pub encoded_bytes: Option<u64>,
    pub peer_reported_coverage_bytes: Option<u64>,
    pub peer_reported_committed_bytes: Option<u64>,
    pub peer_observation: Option<PeerCommitObservation>,
    pub failure: Option<TaskFailure>,
    /// False for local interruption, failure AND receipt acceptance: this
    /// registry does not perform or attest remote cleanup.
    pub remote_cleanup_confirmed: bool,
}
struct Entry {
    job_digest: [u8; 32],
    snapshot: Mutex<TaskSnapshot>,
    cancel: CancelToken,
    done: AtomicBool,
}
struct State {
    closed: bool,
    entries: BTreeMap<Uuid, Arc<Entry>>,
}
struct Inner {
    capacity: usize,
    state: Mutex<State>,
    active: AtomicUsize,
    drained: Notify,
}
/// Retains terminal records until explicit forget. Unknown effects are never
/// automatically evicted to admit another task. Clones share one id space.
#[derive(Clone)]
pub struct TransferTasks {
    inner: Arc<Inner>,
}
impl TransferTasks {
    pub fn new(capacity: usize) -> Result<Self> {
        ensure!((1..=128).contains(&capacity), "invalid fleet task capacity");
        Ok(Self {
            inner: Arc::new(Inner {
                capacity,
                state: Mutex::new(State {
                    closed: false,
                    entries: BTreeMap::new(),
                }),
                active: AtomicUsize::new(0),
                drained: Notify::new(),
            }),
        })
    }
    /// Prevalidate one local MCP batch before any task factory is registered.
    /// The MCP caller serializes its registrations; shutdown may still win and
    /// cause a later launch to fail, in which case it must cancel earlier ids.
    pub(crate) fn check_batch(&self, expected: &[ValidatedGrant], budget: Duration) -> Result<()> {
        ensure!(
            !budget.is_zero() && budget <= Duration::from_secs(300),
            "invalid fleet task budget"
        );
        tokio::runtime::Handle::try_current()
            .context("fleet tasks need an active Tokio runtime")?;
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet task table poisoned"))?;
        ensure!(!state.closed, "fleet tasks stopped");
        ensure!(
            expected.len() <= self.inner.capacity.saturating_sub(state.entries.len()),
            "fleet task capacity exhausted"
        );
        let mut jobs = std::collections::BTreeSet::new();
        for grant in expected {
            ensure!(
                grant.lease_profile() == LeaseProfile::SingleOwner,
                "fleet task requires explicit local SingleOwner profile"
            );
            let digest = grant.grant().job_digest;
            ensure!(
                jobs.insert(digest)
                    && !state
                        .entries
                        .values()
                        .any(|entry| entry.job_digest == digest),
                "fleet task already registered for job"
            );
        }
        Ok(())
    }
    /// Local trusted backend API only. Task registration is not file/peer
    /// authorization. Capacity is reserved BEFORE the factory is ever invoked.
    /// The factory owns its worker futures; it must not detach IO elsewhere.
    /// A dropped task RPC observer does not cancel the owned worker.
    pub fn launch<F, W>(
        &self,
        expected: ValidatedGrant,
        budget: Duration,
        worker: W,
    ) -> Result<Uuid>
    where
        F: Future<Output = Result<PeerCommitObservation>> + Send + 'static,
        W: FnOnce(CancelToken) -> F + Send + 'static,
    {
        ensure!(
            expected.lease_profile() == LeaseProfile::SingleOwner,
            "fleet task requires explicit local SingleOwner profile"
        );
        ensure!(
            !budget.is_zero() && budget <= Duration::from_secs(300),
            "invalid fleet task budget"
        );
        let runtime = tokio::runtime::Handle::try_current()
            .context("fleet tasks need an active Tokio runtime")?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet task table poisoned"))?;
        ensure!(!state.closed, "fleet tasks stopped");
        ensure!(
            !state
                .entries
                .values()
                .any(|v| v.job_digest == expected.grant().job_digest),
            "fleet task already registered for job"
        );
        ensure!(
            state.entries.len() < self.inner.capacity,
            "fleet task capacity exhausted"
        );
        let id = Uuid::new_v4();
        let entry = Arc::new(Entry {
            job_digest: expected.grant().job_digest,
            snapshot: Mutex::new(TaskSnapshot {
                id,
                phase: TaskPhase::Queued,
                planned_bytes: expected.job().bytes_total,
                encoded_bytes: None,
                peer_reported_coverage_bytes: None,
                peer_reported_committed_bytes: None,
                peer_observation: None,
                failure: None,
                remote_cleanup_confirmed: false,
            }),
            cancel: CancelToken::new(),
            done: AtomicBool::new(false),
        });
        state.entries.insert(id, entry.clone());
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        // Construct outside the async block: even a never-polled/cancelled Tokio
        // task must drop this guard and release the active task count.
        let work = OwnedWork {
            worker: Some(worker),
            _operation: Operation {
                inner: self.inner.clone(),
                entry: entry.clone(),
            },
        };
        drop(state);
        runtime.spawn(async move {
            // Capture the WHOLE owner, not disjoint fields: this also orders
            // resource release for tasks the executor never gets to poll.
            let mut work = work;
            if entry.cancel.is_cancelled() {
                drop(work.worker.take());
                finish(
                    &entry,
                    TaskPhase::Interrupted,
                    None,
                    Some(TaskFailure::LocalStop),
                );
                return;
            }
            {
                let mut s = entry.snapshot.lock().expect("task snapshot");
                if s.phase != TaskPhase::CancelRequested {
                    s.phase = TaskPhase::Running;
                }
            }
            enum End {
                Observation(Box<PeerCommitObservation>),
                Failed,
                Stop,
                Deadline,
            }
            // Inner scope ensures the losing worker is dropped BEFORE the
            // terminal status and drain count are published.
            let end = {
                let factory = work.worker.take().expect("task factory already consumed");
                let future = Box::pin(factory(entry.cancel.clone()));
                tokio::select! {
                    biased;
                    result = future => match result { Ok(v) => End::Observation(Box::new(v)), Err(_) => End::Failed },
                    _ = entry.cancel.wait() => End::Stop,
                    _ = tokio::time::sleep(budget) => End::Deadline,
                }
            };
            match end {
                End::Observation(observation) => {
                    let receipt = observation.receipt();
                    if observation.job_digest() == expected.grant().job_digest
                        && observation.binding() == &expected.grant().binding
                        && receipt.size == expected.job().bytes_total
                        && receipt.sha256 == expected.job().sha256
                    {
                        finish(
                            &entry,
                            TaskPhase::PeerReportedCompleted,
                            Some(*observation),
                            None,
                        );
                    } else {
                        finish(
                            &entry,
                            TaskPhase::Failed,
                            None,
                            Some(TaskFailure::ReceiptMismatch),
                        );
                    }
                }
                End::Failed => finish(
                    &entry,
                    TaskPhase::Failed,
                    None,
                    Some(TaskFailure::WorkerFailed),
                ),
                End::Stop => finish(
                    &entry,
                    TaskPhase::Interrupted,
                    None,
                    Some(TaskFailure::LocalStop),
                ),
                End::Deadline => finish(
                    &entry,
                    TaskPhase::Interrupted,
                    None,
                    Some(TaskFailure::TaskDeadline),
                ),
            }
        });
        Ok(id)
    }
    fn entry(&self, id: Uuid) -> Result<Arc<Entry>> {
        self.inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet task table poisoned"))?
            .entries
            .get(&id)
            .cloned()
            .context("unknown fleet task id")
    }
    pub fn get(&self, id: Uuid) -> Result<TaskSnapshot> {
        Ok(self
            .entry(id)?
            .snapshot
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet task snapshot poisoned"))?
            .clone())
    }
    /// Bounded read-only observations for the local GUI. The returned copies do
    /// not own workers, change admission, cancel tasks, or grant file authority.
    pub(crate) fn snapshots(&self) -> Result<Vec<TaskSnapshot>> {
        let entries: Vec<_> = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet task table poisoned"))?
            .entries
            .values()
            .cloned()
            .collect();
        entries
            .into_iter()
            .map(|entry| {
                entry
                    .snapshot
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fleet task snapshot poisoned"))
                    .map(|snapshot| snapshot.clone())
            })
            .collect()
    }
    /// Observe terminal task state without owning/cancelling its execution.
    /// Timing out/dropping this observer leaves the admitted worker running.
    pub async fn wait(&self, id: Uuid) -> Result<TaskSnapshot> {
        let entry = self.entry(id)?;
        loop {
            let notified = self.inner.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if entry.done.load(Ordering::Acquire) {
                return Ok(entry
                    .snapshot
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fleet task snapshot poisoned"))?
                    .clone());
            }
            notified.await;
        }
    }
    /// Returns true only for a new local request, never a remote cancel ACK.
    /// Terminal observations are immutable and are not withdrawn by cancellation.
    pub fn request_cancel(&self, id: Uuid) -> Result<bool> {
        let entry = self.entry(id)?;
        let mut s = entry
            .snapshot
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet task snapshot poisoned"))?;
        if s.phase.is_terminal() || entry.cancel.is_cancelled() {
            return Ok(false);
        }
        s.phase = TaskPhase::CancelRequested;
        entry.cancel.cancel();
        Ok(true)
    }
    /// Explicit forgetting only, after the owned future has dropped. Does not
    /// erase a target journal, delete files, release stage debt or permit resume.
    pub fn forget_finished(&self, id: Uuid) -> Result<()> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet task table poisoned"))?;
        let entry = state.entries.get(&id).context("unknown fleet task id")?;
        ensure!(
            entry.done.load(Ordering::Acquire),
            "fleet task still active"
        );
        state.entries.remove(&id);
        Ok(())
    }
    /// Close admission AND request cancellation without awaiting owned futures.
    /// Short bounded control operation; Runtime invokes it at its stop cut.
    pub(crate) fn stop_admission(&self) -> Result<()> {
        let entries = {
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fleet task table poisoned"))?;
            state.closed = true;
            state.entries.values().cloned().collect::<Vec<_>>()
        };
        for entry in entries {
            let mut s = entry
                .snapshot
                .lock()
                .map_err(|_| anyhow::anyhow!("fleet task snapshot poisoned"))?;
            if !s.phase.is_terminal() {
                s.phase = TaskPhase::CancelRequested;
                entry.cancel.cancel();
            }
        }
        Ok(())
    }
    /// Permanent stop; drain only the futures this registry owns, not unrelated
    /// externally held host owners. Never call from one of this table's workers.
    /// Blocking IO still bounds cancellation latency.
    pub async fn shutdown(&self) -> Result<()> {
        self.stop_admission()?;
        loop {
            let notified = self.inner.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                return Ok(());
            }
            notified.await;
        }
    }
}
fn finish(
    entry: &Entry,
    phase: TaskPhase,
    observation: Option<PeerCommitObservation>,
    failure: Option<TaskFailure>,
) {
    let mut s = entry.snapshot.lock().unwrap_or_else(|p| p.into_inner());
    if s.phase.is_terminal() {
        return;
    }
    s.phase = phase;
    s.peer_reported_committed_bytes = observation.as_ref().map(|v| v.receipt().size);
    s.peer_observation = observation;
    s.failure = failure;
}
// Field drop order is deliberate: a never-polled task may still own live
// resources in its factory closure. Release those BEFORE marking drained.
struct OwnedWork<W> {
    worker: Option<W>,
    _operation: Operation,
}
struct Operation {
    inner: Arc<Inner>,
    entry: Arc<Entry>,
}
impl Drop for Operation {
    fn drop(&mut self) {
        finish(
            &self.entry,
            TaskPhase::Failed,
            None,
            Some(TaskFailure::WorkerDropped),
        );
        self.entry.done.store(true, Ordering::Release);
        self.inner.active.fetch_sub(1, Ordering::AcqRel);
        self.inner.drained.notify_waiters();
    }
}
