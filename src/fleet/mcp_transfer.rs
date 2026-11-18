//! Local MCP-facing task surface for PREAPPROVED fleet rounds only.
//!
//! The relay/peer cannot mint authority here: every job, path, size and SHA come
//! from the local setup file, and a round only starts after the normal setup
//! handshake and relay ticket. No new service, listener or wire message.
use super::{
    job::{LeaseProfile, ValidatedGrant},
    setup_config::{RoleFile, SetupProvision},
    setup_lease::SetupLease,
    transfer_tasks::{TaskSnapshot, TransferTasks},
    transport_driver::{TransferPlanSnapshot, run_leased_source},
};
use crate::{protocol::ToolDefinition, runtime::Runtime};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;

/// One locally approved source round ready to be started on demand.
pub(crate) struct ApprovedStart {
    pub(crate) round: Uuid,
    pub(crate) task: Uuid,
}

/// Handoff from the live session to the waiting task: the SAME authenticated
/// owner, its connection token and a plain copy of the local transfer plan.
pub(crate) struct SourceHandoff {
    pub(crate) owner: SetupLease,
    pub(crate) token: String,
    pub(crate) plan: TransferPlanSnapshot,
    pub(crate) stop: watch::Receiver<bool>,
}

struct RoundInfo {
    grant: ValidatedGrant,
}

/// Bounded local registry. Holds no raw records and never serializes a lease.
#[cfg(test)]
#[path = "mcp_transfer_tests.rs"]
mod tests;

pub(crate) struct McpTransfer {
    runtime: std::sync::Weak<Runtime>,
    tasks: TransferTasks,
    rounds: HashMap<Uuid, RoundInfo>,
    starts_tx: mpsc::UnboundedSender<ApprovedStart>,
    starts_rx: Mutex<Option<mpsc::UnboundedReceiver<ApprovedStart>>>,
    waiters: Mutex<HashMap<Uuid, oneshot::Sender<SourceHandoff>>>,
    active: Mutex<HashMap<Uuid, Uuid>>,
}

impl McpTransfer {
    pub(crate) fn open(
        runtime: &Arc<Runtime>,
        provision: Arc<SetupProvision>,
        capacity: usize,
    ) -> Result<Arc<Self>> {
        ensure!(capacity > 0, "invalid fleet MCP capacity");
        let plan = provision.transfer().context("no local transfer plan")?;
        ensure!(plan.mcp(), "MCP transfer not enabled locally");
        let mut rounds = HashMap::new();
        for (id, role, approval) in provision.rounds()? {
            if role != RoleFile::Source {
                continue;
            }
            let grant = approval.proposal.clone();
            ensure!(
                grant.lease_profile() == LeaseProfile::SingleOwner,
                "MCP transfer requires the single-owner profile"
            );
            rounds.insert(id, RoundInfo { grant });
        }
        ensure!(
            !rounds.is_empty(),
            "MCP transfer needs at least one source round"
        );
        let (starts_tx, starts_rx) = mpsc::unbounded_channel();
        Ok(Arc::new(Self {
            runtime: Arc::downgrade(runtime),
            tasks: TransferTasks::new(capacity.min(8))?,
            rounds,
            starts_tx,
            starts_rx: Mutex::new(Some(starts_rx)),
            waiters: Mutex::new(HashMap::new()),
            active: Mutex::new(HashMap::new()),
        }))
    }
    /// The Runtime installs this SAME table as its lifecycle attachment.
    pub(crate) fn task_table(&self) -> TransferTasks {
        self.tasks.clone()
    }
    /// Hand the single receiver to the live session; only the first caller gets it.
    pub(crate) fn take_starts(&self) -> Option<mpsc::UnboundedReceiver<ApprovedStart>> {
        self.starts_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
    /// Start a preapproved SOURCE round. Returns the local task id immediately;
    /// the task remains queued until the session delivers the authenticated owner.
    pub(crate) fn send_file(&self, round: Uuid, budget: Duration) -> Result<Uuid> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP transfer registry poisoned"))?;
        self.check_registration(&[round], budget, &active)?;
        let task = self.register(round, budget, &mut active)?;
        drop(active);
        if let Err(error) = self.queue(round, task) {
            let _ = self.tasks.request_cancel(task);
            self.abandon(round);
            return Err(error);
        }
        Ok(task)
    }
    /// Register a task without starting it. Used by the sequential batch so a
    /// second target host admission cannot race the first on one Runtime.
    fn register(
        &self,
        round: Uuid,
        budget: Duration,
        active: &mut HashMap<Uuid, Uuid>,
    ) -> Result<Uuid> {
        ensure!(
            !budget.is_zero() && budget <= Duration::from_secs(300),
            "invalid transfer budget"
        );
        let info = self
            .rounds
            .get(&round)
            .context("round is not a locally approved source round")?;
        ensure!(!active.contains_key(&round), "round already started");
        let (tx, rx) = oneshot::channel();
        let runtime = self.runtime.clone();
        let task = self
            .tasks
            .launch(info.grant.clone(), budget, move |_cancel| async move {
                let handoff: SourceHandoff =
                    rx.await.context("transfer owner was never delivered")?;
                let runtime = runtime.upgrade().context("Runtime gone")?;
                run_leased_source(
                    runtime,
                    handoff.owner,
                    handoff.token,
                    handoff.plan,
                    budget,
                    handoff.stop,
                )
                .await
            })?;
        ensure!(
            self.waiters
                .lock()
                .map_err(|_| anyhow::anyhow!("MCP transfer registry poisoned"))?
                .insert(round, tx)
                .is_none(),
            "round waiter already present"
        );
        active.insert(round, task);
        Ok(task)
    }
    fn check_registration(
        &self,
        rounds: &[Uuid],
        budget: Duration,
        active: &HashMap<Uuid, Uuid>,
    ) -> Result<()> {
        let mut grants = Vec::with_capacity(rounds.len());
        for round in rounds {
            ensure!(!active.contains_key(round), "round already started");
            grants.push(
                self.rounds
                    .get(round)
                    .context("round is not a locally approved source round")?
                    .grant
                    .clone(),
            );
        }
        self.tasks.check_batch(&grants, budget)
    }
    /// Recheck both before enqueue and immediately before the session consumes
    /// an enqueued command. Cancel still cannot roll back setup already begun.
    pub(crate) fn start_allowed(&self, round: Uuid, task: Uuid) -> bool {
        self.active
            .lock()
            .map(|active| active.get(&round) == Some(&task))
            .unwrap_or(false)
            && self.tasks.get(task).is_ok_and(|s| {
                matches!(
                    s.phase,
                    super::transfer_tasks::TaskPhase::Queued
                        | super::transfer_tasks::TaskPhase::Running
                )
            })
    }
    fn queue(&self, round: Uuid, task: Uuid) -> Result<()> {
        ensure!(
            self.start_allowed(round, task),
            "transfer task stopped before setup"
        );
        if self.starts_tx.send(ApprovedStart { round, task }).is_err() {
            self.abandon(round);
            anyhow::bail!("fleet session is not running");
        }
        Ok(())
    }
    /// Batch variant over preapproved rounds. It registers all ids immediately
    /// but starts them ONE AT A TIME, waiting for each terminal task before the
    /// next. This is NOT a directory diff: no manifest, scan, overwrite, delete
    /// or per-file field re-observation. A failure stops the remaining starts.
    pub(crate) fn sync_dir(
        self: &Arc<Self>,
        rounds: &[Uuid],
        budget: Duration,
    ) -> Result<Vec<Uuid>> {
        ensure!(
            (1..=8).contains(&rounds.len()),
            "sync_dir needs 1..=8 preapproved rounds"
        );
        let mut unique = std::collections::HashSet::new();
        ensure!(
            rounds.iter().all(|r| unique.insert(*r)),
            "sync_dir rounds must be unique"
        );
        let mut active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP transfer registry poisoned"))?;
        self.check_registration(rounds, budget, &active)?;
        let mut pairs = Vec::with_capacity(rounds.len());
        for round in rounds {
            match self.register(*round, budget, &mut active) {
                Ok(id) => pairs.push((*round, id)),
                Err(error) => {
                    drop(active);
                    for (registered, id) in pairs {
                        let _ = self.tasks.request_cancel(id);
                        self.abandon(registered);
                    }
                    return Err(error);
                }
            }
        }
        drop(active);
        let ids = pairs.iter().map(|(_, id)| *id).collect::<Vec<_>>();
        let this = Arc::clone(self);
        // A failing task leaves the rest registered but unstarted. Report the
        // failure locally and mark the remaining waiters as abandoned so they
        // fail instead of hanging; no remote cleanup or debt release is claimed.
        tokio::spawn(async move {
            let mut rest = pairs.into_iter();
            while let Some((round, task)) = rest.next() {
                if this.queue(round, task).is_err() {
                    this.abandon(round);
                    for (later, _) in rest {
                        this.abandon(later);
                    }
                    break;
                }
                // A cancel counts like a failure: later rounds must not start
                // after the operator stopped the batch. They are withdrawn so
                // their waiters fail instead of hanging until session end.
                let stop = match this.tasks.wait(task).await {
                    Ok(snapshot) => {
                        snapshot.failure.is_some()
                            || snapshot.phase
                                != super::transfer_tasks::TaskPhase::PeerReportedCompleted
                    }
                    Err(_) => true,
                };
                if stop {
                    this.abandon(round);
                    for (later, _) in rest {
                        this.abandon(later);
                    }
                    break;
                }
            }
        });
        Ok(ids)
    }
    /// Deliver the live owner to the waiting task. Returns false when the task is
    /// already gone (cancelled/failed); the caller then closes the owner.
    pub(crate) fn deliver(&self, round: Uuid, handoff: SourceHandoff) -> bool {
        let sender = self
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&round);
        match sender {
            Some(tx) => tx.send(handoff).is_ok(),
            None => false,
        }
    }
    /// Setup failed or the owner never became usable: drop the waiter so the
    /// task reports failure instead of hanging.
    pub(crate) fn abandon(&self, round: Uuid) {
        let _ = self
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&round);
        let _ = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&round);
    }
    pub(crate) fn get(&self, id: Uuid) -> Result<TaskSnapshot> {
        self.tasks.get(id)
    }
    pub(crate) fn cancel(&self, id: Uuid) -> Result<bool> {
        let cancelled = self.tasks.request_cancel(id)?;
        if cancelled {
            let round = self
                .active
                .lock()
                .map_err(|_| anyhow::anyhow!("MCP transfer registry poisoned"))?
                .iter()
                .find_map(|(round, task)| (*task == id).then_some(*round));
            if let Some(round) = round {
                self.waiters
                    .lock()
                    .map_err(|_| anyhow::anyhow!("MCP transfer registry poisoned"))?
                    .remove(&round);
            }
        }
        Ok(cancelled)
    }
    /// Cancel by preapproved round id. Also withdraws a not-yet-delivered
    /// waiter so a later owner delivery is refused and closed by the session
    /// instead of starting DATA after the operator cancelled. Returns false for
    /// an unstarted/already-terminal task or repeated request; unknown rounds error.
    pub(crate) fn cancel_round(&self, round: Uuid) -> Result<bool> {
        ensure!(
            self.rounds.contains_key(&round),
            "round is not a locally approved source round"
        );
        let task = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP transfer registry poisoned"))?
            .get(&round)
            .copied();
        let cancelled = match task {
            Some(id) => self.tasks.request_cancel(id)?,
            None => false,
        };
        let _withdrawn = self
            .waiters
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP transfer registry poisoned"))?
            .remove(&round)
            .is_some();
        Ok(cancelled)
    }
    /// Cancel every task of one sequential batch that has not settled. Later
    /// rounds in the batch are withdrawn so they cannot start after a cancel.
    pub(crate) fn cancel_batch(&self, rounds: &[Uuid]) -> Result<usize> {
        ensure!(
            (1..=8).contains(&rounds.len()),
            "cancel batch needs 1..=8 rounds"
        );
        let mut unique = std::collections::HashSet::new();
        for round in rounds {
            ensure!(unique.insert(*round), "cancel batch rounds must be unique");
            ensure!(
                self.rounds.contains_key(round),
                "round is not a locally approved source round"
            );
        }
        let mut n = 0;
        for round in rounds {
            if self.cancel_round(*round)? {
                n += 1;
            }
        }
        Ok(n)
    }
    /// Session end: drop every pending waiter so tasks fail instead of hanging.
    pub(crate) fn abandon_all(&self) {
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

pub(crate) fn tool_definitions() -> Vec<ToolDefinition> {
    let s = serde_json::json!({"type":"string"});
    let n = serde_json::json!({"type":"integer"});
    vec![
        ToolDefinition {
            name: "send_file".into(),
            description: "Start one PREAPPROVED local source round; returns a local task id. No remote grant or path authority.".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"roundId":s,"timeoutMs":n},"required":["roundId"]}),
        },
        ToolDefinition {
            name: "sync_dir".into(),
            description: "Start 1..=8 PREAPPROVED local source rounds; this is not a directory scan, diff, overwrite or delete.".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"rounds":{"type":"array","items":s,"minItems":1,"maxItems":8},"timeoutMs":n},"required":["rounds"]}),
        },
        ToolDefinition {
            name: "transfer_get".into(),
            description: "Read one local task snapshot. Peer observation is a peer statement, not remote disk proof.".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"taskId":s},"required":["taskId"]}),
        },
        ToolDefinition {
            name: "transfer_cancel".into(),
            description: "Request local cancellation by taskId, or by preapproved roundId/rounds; no remote cleanup, rollback or debt release is implied.".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"taskId":s,"roundId":s,"rounds":{"type":"array","items":s,"minItems":1,"maxItems":8,"uniqueItems":true}},"oneOf":[{"required":["taskId"]},{"required":["roundId"]},{"required":["rounds"]}]}),
        },
    ]
}
