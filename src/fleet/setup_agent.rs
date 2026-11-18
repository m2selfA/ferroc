//! Candidate LOCAL per-connection setup backend. No socket, TOFU, grant issuer,
//! time importer, file/stage IO or MCP tool. A configured transport must feed
//! only THIS connection's frames and report actual writes, then shutdown/drain
//! before replacing its scope. PreparedLocally is not peer/data readiness.
use super::{
    identity::{EndpointSlot, Fingerprint, IdentityStore},
    job::{LeaseProfile, ValidatedGrant},
    protocol::{Direction, device_digest},
    setup::{
        MAX_SETUP_MESSAGE, PreparedSetup, SetupConfirmation, SetupOffer, SetupPeer, SetupResponse,
    },
    sync_exec::CancelToken,
};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    time::{Instant, timeout},
};
use uuid::Uuid;
const HISTORY: usize = 64;
const OUTBOX: usize = 8;
const INBOX: usize = 2;
const ROUND_BUDGET: Duration = Duration::from_secs(30);
const WRITE_BUDGET: Duration = Duration::from_secs(5);
const MAX_ENVELOPE: usize = 2 * MAX_SETUP_MESSAGE + 4096;
/// Trusted LOCAL authority decision for signing time only. No input comes from
/// the wire; this does NOT create/refresh a TrustedTimeAnchor or live lease.
pub type ApprovedSetupNow = dyn Fn() -> Result<u64> + Send + Sync;
pub struct ConfiguredSetupPeer {
    pub device: String,
    pub fingerprint: Fingerprint,
    pub slot: EndpointSlot,
    pub profile: LeaseProfile,
}
pub struct LocalSetupApproval {
    pub identity: Arc<IdentityStore>,
    pub proposal: ValidatedGrant,
    pub peer: ConfiguredSetupPeer,
    pub now: Arc<ApprovedSetupNow>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SetupPhase {
    Queued,
    Running,
    CancelRequested,
    PreparedLocally,
    Interrupted,
    Failed,
}
impl SetupPhase {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::PreparedLocally | Self::Interrupted | Self::Failed
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SetupFailure {
    Cancelled,
    LocalStop,
    Deadline,
    Protocol,
    RoundFailed,
    WorkerDropped,
    ObserverDropped,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupSnapshot {
    pub id: Uuid,
    pub scope: Uuid,
    pub phase: SetupPhase,
    pub failure: Option<SetupFailure>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Stage {
    Offer,
    Response,
    Confirmation,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Incoming {
    #[serde(rename = "type")]
    kind: String,
    id: Uuid,
    from_device: String,
    stage: Stage,
    payload: String,
}
struct Entry {
    peer: String,
    role: Direction,
    next: Option<Stage>,
    inbound: mpsc::Sender<Incoming>,
    cancel: CancelToken,
    cause: Option<SetupFailure>,
    #[cfg(test)]
    error: Option<String>,
    until: Instant,
    snapshot: SetupSnapshot,
    active: bool,
    completing: bool,
}
#[derive(Default)]
struct State {
    closed: bool,
    entries: BTreeMap<Uuid, Entry>,
    jobs: HashSet<[u8; 32]>,
    bindings: HashSet<[u8; 32]>,
}
pub(crate) struct SetupControl {
    runtime: Weak<Runtime>,
    device: String,
    scope: Uuid,
    capacity: usize,
    budget: Duration,
    state: Mutex<State>,
    outbound: mpsc::Sender<SetupEmission>,
    stop: watch::Sender<bool>,
    drained: Notify,
}
#[derive(Clone)]
pub struct SetupBackend {
    inner: Arc<SetupControl>,
}
pub struct SetupOutbox {
    receiver: mpsc::Receiver<SetupEmission>,
    stop: watch::Receiver<bool>,
}
impl SetupOutbox {
    pub async fn recv(&mut self) -> Option<SetupEmission> {
        if *self.stop.borrow() {
            self.receiver.close();
            while self.receiver.try_recv().is_ok() {}
            return None;
        }
        tokio::select! {biased;
            _=self.stop.changed()=>{self.receiver.close();while self.receiver.try_recv().is_ok(){}None},
            item=self.receiver.recv()=>item,
        }
    }
}
/// One local handoff to the current socket's writer. Not Clone/Deserialize.
/// `wire_frame` checks before handoff, not an atomic revoke of accepted writes.
pub struct SetupEmission {
    inner: Weak<SetupControl>,
    id: Uuid,
    frame: Value,
    written: Option<oneshot::Sender<()>>,
}
impl SetupEmission {
    pub fn wire_frame(&self) -> Result<Value> {
        let inner = self.inner.upgrade().context("setup scope gone")?;
        let state = inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("setup table poisoned"))?;
        let e = state.entries.get(&self.id).context("setup absent")?;
        ensure!(
            !state.closed && e.active && !e.cancel.is_cancelled() && Instant::now() < e.until,
            "setup emission no longer admitted"
        );
        Ok(self.frame.clone())
    }
    /// A TRUSTED transport reports its completed write. Not peer read/consent.
    /// Drop without this report makes the round fail; no optimistic success.
    pub fn report_written(mut self) {
        if let Some(tx) = self.written.take() {
            let _ = tx.send(());
        }
    }
}
impl SetupBackend {
    pub(crate) fn create(
        runtime: Weak<Runtime>,
        device: &str,
        capacity: usize,
    ) -> Result<(Self, SetupOutbox)> {
        Self::create_budget(runtime, device, capacity, ROUND_BUDGET)
    }
    fn create_budget(
        runtime: Weak<Runtime>,
        device: &str,
        capacity: usize,
        budget: Duration,
    ) -> Result<(Self, SetupOutbox)> {
        device_digest(device)?;
        ensure!((1..=4).contains(&capacity), "setup capacity must be 1..4");
        ensure!(
            !budget.is_zero() && budget <= ROUND_BUDGET,
            "invalid setup round budget"
        );
        let (tx, rx) = mpsc::channel(OUTBOX);
        let (stop, stop_rx) = watch::channel(false);
        Ok((
            Self {
                inner: Arc::new(SetupControl {
                    runtime,
                    device: device.into(),
                    scope: Uuid::new_v4(),
                    capacity,
                    budget,
                    state: Mutex::new(State::default()),
                    outbound: tx,
                    stop,
                    drained: Notify::new(),
                }),
            },
            SetupOutbox {
                receiver: rx,
                stop: stop_rx,
            },
        ))
    }
    pub(crate) fn from_control(inner: Arc<SetupControl>) -> Self {
        Self { inner }
    }
    pub(crate) fn control(&self) -> Weak<SetupControl> {
        Arc::downgrade(&self.inner)
    }
    pub fn scope(&self) -> Uuid {
        self.inner.scope
    }
    pub fn start_source(
        &self,
        id: Uuid,
        local: LocalSetupApproval,
    ) -> Result<oneshot::Receiver<Result<PreparedSetup>>> {
        self.start(id, local, Direction::SourceToTarget)
    }
    pub fn arm_target(
        &self,
        id: Uuid,
        local: LocalSetupApproval,
    ) -> Result<oneshot::Receiver<Result<PreparedSetup>>> {
        self.start(id, local, Direction::TargetToSource)
    }
    fn start(
        &self,
        id: Uuid,
        local: LocalSetupApproval,
        role: Direction,
    ) -> Result<oneshot::Receiver<Result<PreparedSetup>>> {
        ensure!(!id.is_nil(), "nil setup round");
        let handle = tokio::runtime::Handle::try_current().context("setup needs Tokio runtime")?;
        let runtime = self.inner.runtime.upgrade().context("Runtime gone")?;
        // Same registry -> short control ordering as Runtime.shutdown.
        let admission = runtime.fleet_source_guard()?;
        let (fleet, device) = local.identity.issuance_scope();
        ensure!(
            device == self.inner.device,
            "setup identity differs from configured connection"
        );
        let job = local.proposal.job();
        let (mine, theirs) = match role {
            Direction::SourceToTarget => (job.source_device, job.target_device),
            Direction::TargetToSource => (job.target_device, job.source_device),
        };
        ensure!(
            fleet == job.fleet_id
                && mine == device_digest(device)?
                && theirs == device_digest(&local.peer.device)?,
            "setup configured role/device mismatch"
        );
        ensure!(
            local.peer.profile == local.proposal.lease_profile(),
            "setup configured profile mismatch"
        );
        let digest = job.digest()?;
        let binding: [u8; 32] = Sha256::digest(local.proposal.grant().binding.bytes()).into();
        let now = Instant::now();
        let until = now
            .checked_add(self.inner.budget)
            .context("setup deadline overflow")?;
        let (cancel, rx, result_tx, result_rx) = {
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("setup table poisoned"))?;
            ensure!(!state.closed, "setup scope stopped");
            ensure!(state.entries.len() < HISTORY, "setup history full");
            ensure!(
                state.entries.values().filter(|e| e.active).count() < self.inner.capacity,
                "setup active capacity full"
            );
            ensure!(
                !state.entries.contains_key(&id)
                    && !state.jobs.contains(&digest)
                    && !state.bindings.contains(&binding),
                "setup id/job/binding spent"
            );
            let (cancel, (tx, rx), (result_tx, result_rx)) =
                (CancelToken::new(), mpsc::channel(INBOX), oneshot::channel());
            state.jobs.insert(digest);
            state.bindings.insert(binding);
            state.entries.insert(
                id,
                Entry {
                    peer: local.peer.device.clone(),
                    role,
                    next: Some(if role == Direction::SourceToTarget {
                        Stage::Response
                    } else {
                        Stage::Offer
                    }),
                    inbound: tx,
                    cancel: cancel.clone(),
                    cause: None,
                    #[cfg(test)]
                    error: None,
                    until,
                    snapshot: SetupSnapshot {
                        id,
                        scope: self.inner.scope,
                        phase: SetupPhase::Queued,
                        failure: None,
                    },
                    active: true,
                    completing: false,
                },
            );
            (cancel, rx, result_tx, result_rx)
        };
        drop(admission);
        let inner = self.inner.clone();
        let drive = Box::pin(async move {
            tokio::select! {biased;
                _=cancel.wait()=>Err(anyhow::anyhow!("setup cancelled")),
                _=tokio::time::sleep_until(until)=>{inner.reason(id,SetupFailure::Deadline);Err(anyhow::anyhow!("setup deadline"))},
                result=drive_round(inner.clone(),id,role,runtime,local,rx)=>result,
            }
        });
        let owner = OwnedRound {
            future: Some(drive),
            completion: Completion {
                inner: self.inner.clone(),
                id,
                result: Some(result_tx),
                done: false,
            },
        };
        handle.spawn(owner.run());
        Ok(result_rx)
    }
    /// Feed this scope's exact relay envelope. Never infer an approval/clock
    /// from it. Unknown/foreign IDs cannot cancel another participant's round.
    /// Classify without retaining unknown payloads; native frames then pass
    /// the strict, bounded full envelope decoder. Never enabled by default.
    /// Adapter entry for a configured transport only. Returns false when the
    /// frame is not a setup envelope; a true result means it was consumed.
    pub fn receive_if_setup(&self, raw: &str) -> Result<bool> {
        #[derive(Deserialize)]
        struct Kind<'a> {
            #[serde(borrow, rename = "type")]
            kind: &'a str,
        }
        let kind: Kind<'_> = serde_json::from_str(raw)?;
        if kind.kind != "fleetSetup" {
            return Ok(false);
        }
        self.receive(raw)?;
        Ok(true)
    }
    pub fn receive(&self, raw: &str) -> Result<()> {
        ensure!(raw.len() <= MAX_ENVELOPE, "setup envelope too large");
        let frame: Incoming = serde_json::from_str(raw)?;
        ensure!(
            frame.kind == "fleetSetup"
                && !frame.id.is_nil()
                && frame.payload.len() <= MAX_SETUP_MESSAGE,
            "invalid setup envelope"
        );
        device_digest(&frame.from_device)?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("setup table poisoned"))?;
        ensure!(!state.closed, "setup scope stopped");
        let e = state
            .entries
            .get_mut(&frame.id)
            .context("setup id not locally armed")?;
        ensure!(e.peer == frame.from_device, "foreign setup sender");
        ensure!(
            e.active && !e.completing && !e.cancel.is_cancelled(),
            "setup round not receiving"
        );
        let failure = if Instant::now() >= e.until {
            Some(SetupFailure::Deadline)
        } else if e.next != Some(frame.stage) {
            Some(SetupFailure::Protocol)
        } else {
            None
        };
        if let Some(reason) = failure {
            e.cause.get_or_insert(reason);
            e.cancel.cancel();
            e.snapshot.phase = SetupPhase::CancelRequested;
            anyhow::bail!("setup phase/deadline rejected")
        }
        e.next = match (e.role, frame.stage) {
            (Direction::TargetToSource, Stage::Offer) => Some(Stage::Confirmation),
            _ => None,
        };
        if e.inbound.try_send(frame).is_err() {
            e.cause.get_or_insert(SetupFailure::Protocol);
            e.cancel.cancel();
            e.snapshot.phase = SetupPhase::CancelRequested;
            anyhow::bail!("setup inbox unavailable")
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn last_error(&self, id: Uuid) -> Option<String> {
        self.inner
            .state
            .lock()
            .ok()?
            .entries
            .get(&id)?
            .error
            .clone()
    }
    pub fn snapshot(&self, id: Uuid) -> Result<SetupSnapshot> {
        Ok(self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("setup table poisoned"))?
            .entries
            .get(&id)
            .context("unknown setup round")?
            .snapshot
            .clone())
    }
    pub fn request_cancel(&self, id: Uuid) -> Result<bool> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("setup table poisoned"))?;
        let e = state.entries.get_mut(&id).context("unknown setup round")?;
        if !e.active || e.completing || e.cancel.is_cancelled() {
            return Ok(false);
        }
        e.cause = Some(SetupFailure::Cancelled);
        e.cancel.cancel();
        e.snapshot.phase = SetupPhase::CancelRequested;
        Ok(true)
    }
    /// Stop is permanent. External PreparedSetup owners are not withdrawn.
    /// Never await shutdown from this backend's own clock/worker.
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.stop_admission()?;
        self.inner.drain().await
    }
}
impl SetupControl {
    fn reason(&self, id: Uuid, reason: SetupFailure) {
        if let Ok(mut state) = self.state.lock()
            && let Some(e) = state.entries.get_mut(&id)
        {
            e.cause.get_or_insert(reason);
        }
    }
    pub(crate) fn retired(&self) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("setup table poisoned"))?;
        Ok(state.closed && state.entries.values().all(|e| !e.active))
    }
    pub(crate) fn stop_admission(&self) -> Result<()> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("setup table poisoned"))?;
            state.closed = true;
            for e in state.entries.values_mut() {
                if e.active && !e.completing {
                    e.cause.get_or_insert(SetupFailure::LocalStop);
                    e.cancel.cancel();
                    e.snapshot.phase = SetupPhase::CancelRequested;
                }
            }
        }
        self.stop.send_replace(true);
        Ok(())
    }
    pub(crate) async fn drain(&self) -> Result<()> {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("setup table poisoned"))?
                .entries
                .values()
                .all(|e| !e.active)
            {
                return Ok(());
            }
            notified.await;
        }
    }
}
async fn emit(
    inner: &Arc<SetupControl>,
    id: Uuid,
    peer: &str,
    stage: Stage,
    payload: Vec<u8>,
) -> Result<()> {
    let payload = String::from_utf8(payload)?;
    let mut request = json!({"id":id,"stage":stage,"payload":payload});
    if stage == Stage::Offer {
        request["peerDevice"] = json!(peer)
    }
    let (tx, rx) = oneshot::channel();
    let item = SetupEmission {
        inner: Arc::downgrade(inner),
        id,
        frame: json!({"type":"fleetSetup","request":request}),
        written: Some(tx),
    };
    inner
        .outbound
        .try_send(item)
        .map_err(|_| anyhow::anyhow!("setup writer queue unavailable"))?;
    timeout(WRITE_BUDGET, rx)
        .await
        .context("setup write report deadline")?
        .context("setup write not reported")?;
    Ok(())
}
async fn drive_round(
    inner: Arc<SetupControl>,
    id: Uuid,
    role: Direction,
    runtime: Arc<Runtime>,
    local: LocalSetupApproval,
    mut inbound: mpsc::Receiver<Incoming>,
) -> Result<PreparedSetup> {
    let peer = SetupPeer {
        device: &local.peer.device,
        expected_fingerprint: &local.peer.fingerprint,
        endpoint_slot: local.peer.slot,
        profile: local.peer.profile,
    };
    match role {
        Direction::SourceToTarget => {
            let (pending, offer) = runtime.begin_fleet_setup(
                &local.identity,
                &local.proposal,
                peer,
                (local.now)()?,
            )?;
            emit(
                &inner,
                id,
                &local.peer.device,
                Stage::Offer,
                offer.encode()?,
            )
            .await?;
            let response = inbound
                .recv()
                .await
                .context("setup response mailbox closed")?;
            ensure!(
                response.stage == Stage::Response,
                "unexpected setup response"
            );
            let (prepared, confirmation) = pending.confirm(
                SetupResponse::decode(response.payload.as_bytes())?,
                (local.now)()?,
            )?;
            emit(
                &inner,
                id,
                &local.peer.device,
                Stage::Confirmation,
                confirmation.encode()?,
            )
            .await?;
            Ok(prepared)
        }
        Direction::TargetToSource => {
            let offer = inbound.recv().await.context("setup offer mailbox closed")?;
            ensure!(offer.stage == Stage::Offer, "unexpected setup offer");
            let (pending, response) = runtime.accept_fleet_setup(
                &local.identity,
                &local.proposal,
                peer,
                SetupOffer::decode(offer.payload.as_bytes())?,
                (local.now)()?,
            )?;
            emit(
                &inner,
                id,
                &local.peer.device,
                Stage::Response,
                response.encode()?,
            )
            .await?;
            let confirmation = inbound
                .recv()
                .await
                .context("setup confirmation mailbox closed")?;
            ensure!(
                confirmation.stage == Stage::Confirmation,
                "unexpected setup confirmation"
            );
            pending.finish(
                SetupConfirmation::decode(confirmation.payload.as_bytes())?,
                (local.now)()?,
            )
        }
    }
}
type Drive = Pin<Box<dyn Future<Output = Result<PreparedSetup>> + Send>>;
struct OwnedRound {
    future: Option<Drive>,
    completion: Completion,
}
impl OwnedRound {
    async fn run(mut self) {
        if let Ok(mut s) = self.completion.inner.state.lock()
            && let Some(e) = s.entries.get_mut(&self.completion.id)
            && !e.cancel.is_cancelled()
        {
            e.snapshot.phase = SetupPhase::Running;
        }
        let result = self.future.as_mut().expect("owned setup future").await;
        drop(self.future.take());
        self.completion.finish(result, None);
    }
}
impl Drop for OwnedRound {
    fn drop(&mut self) {
        drop(self.future.take());
        self.completion.finish(
            Err(anyhow::anyhow!("setup worker dropped")),
            Some(SetupFailure::WorkerDropped),
        );
    }
}
struct Completion {
    inner: Arc<SetupControl>,
    id: Uuid,
    result: Option<oneshot::Sender<Result<PreparedSetup>>>,
    done: bool,
}
impl Completion {
    fn finish(&mut self, mut result: Result<PreparedSetup>, forced: Option<SetupFailure>) {
        if self.done {
            return;
        }
        // Only cleanup recovers poison; normal admission never does. It grants no IO.
        let reason = {
            let mut state = self.inner.state.lock().unwrap_or_else(|p| p.into_inner());
            let e = state
                .entries
                .get_mut(&self.id)
                .expect("registered setup round");
            e.completing = true;
            if e.cause.is_none() && Instant::now() >= e.until {
                e.cause = Some(SetupFailure::Deadline)
            }
            e.cause.or(forced)
        };
        let mut failure = reason.or_else(|| {
            if result.is_err() {
                Some(SetupFailure::RoundFailed)
            } else {
                None
            }
        });
        #[cfg(test)]
        if let Err(error) = &result {
            let mut state = self.inner.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(e) = state.entries.get_mut(&self.id) {
                e.error = Some(format!("{error:#}"));
            }
        }
        if failure.is_some() {
            result = Err(anyhow::anyhow!("setup interrupted or failed"));
        }
        // Scope captures/Pending owners were dropped before this handoff. Claimed
        // completion is the cancel linearization point; no lock is held while waking.
        if let Some(tx) = self.result.take()
            && let Err(undelivered) = tx.send(result)
        {
            drop(undelivered);
            failure.get_or_insert(SetupFailure::ObserverDropped);
        }
        {
            let mut state = self.inner.state.lock().unwrap_or_else(|p| p.into_inner());
            let e = state
                .entries
                .get_mut(&self.id)
                .expect("registered setup round");
            e.active = false;
            e.snapshot.failure = failure;
            e.snapshot.phase = match failure {
                None => SetupPhase::PreparedLocally,
                Some(
                    SetupFailure::Cancelled
                    | SetupFailure::LocalStop
                    | SetupFailure::ObserverDropped,
                ) => SetupPhase::Interrupted,
                Some(_) => SetupPhase::Failed,
            };
        }
        self.done = true;
        self.inner.drained.notify_waiters();
    }
}
#[cfg(test)]
#[path = "setup_agent_tests.rs"]
mod tests;
