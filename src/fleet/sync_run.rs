//! Bounded in-memory ledger for one additive sync run. Not a scheduler, sender,
//! persistence layer or completion proof: a receipt is only a peer statement.
//! No IO, network, retry, restart or concurrency capability.
use super::{
    control::Receipt,
    job::JobSpec,
    sync_plan::{PlannedFile, SyncPlan},
};
use anyhow::{Result, ensure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    Pending,
    InFlight,
    Settled,
    Failed,
    Cancelled,
}
/// Operator-visible run state. `Complete` is derived from every file settling;
/// it is not a durability or delivery claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Running,
    Blocked,
    Cancelled,
    Complete,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunStatus {
    pub state: RunState,
    pub planned: usize,
    pub settled: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub settled_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct RunEntry {
    path: String,
    bytes: u64,
    job: JobSpec,
    state: FileState,
    receipt: Option<Receipt>,
}
impl RunEntry {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn state(&self) -> FileState {
        self.state
    }
    /// Historical local observation of the peer's statement, not delivery proof.
    pub fn receipt(&self) -> Option<&Receipt> {
        self.receipt.as_ref()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunFailure {
    pub path: String,
    pub reason: String,
}

#[cfg(test)]
#[path = "sync_run_tests.rs"]
mod tests;

/// Files advance in plan order, one at a time. A failure blocks the whole run
/// permanently: no skip-ahead, no retry and no revival inside this ledger.
/// ```compile_fail
/// fn no_sender(l:ferroc::fleet::sync_run::RunLedger){l.send_next().unwrap();}
/// ```
/// ```compile_fail
/// fn no_persist(l:ferroc::fleet::sync_run::RunLedger){let _=l.journal;}
/// ```
#[derive(Clone, Debug)]
pub struct RunLedger {
    entries: Vec<RunEntry>,
    active: Option<usize>,
    failure: Option<RunFailure>,
    cancelled: Option<String>,
    settled_bytes: u64,
}
impl RunLedger {
    pub fn new(plan: &SyncPlan) -> Self {
        let entries = plan
            .files()
            .iter()
            .map(|f: &PlannedFile| RunEntry {
                path: f.path.clone(),
                bytes: f.bytes,
                job: f.job().clone(),
                state: FileState::Pending,
                receipt: None,
            })
            .collect();
        Self {
            entries,
            active: None,
            failure: None,
            cancelled: None,
            settled_bytes: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Bind the ordered file/job list, not just its length or total bytes.
    pub(super) fn validate_plan(&self, plan: &SyncPlan) -> Result<()> {
        ensure!(
            self.entries.len() == plan.files().len(),
            "sync ledger/plan mismatch"
        );
        ensure!(
            self.entries.iter().zip(plan.files()).all(|(entry, file)| {
                entry.path == file.path
                    && entry.bytes == file.bytes
                    && entry.job == *file.job()
                    && entry.job.sha256 == file.sha256
            }),
            "sync ledger/plan job mismatch"
        );
        Ok(())
    }
    /// Never adopt a caller's in-flight owner or revive a stopped ledger.
    pub(super) fn driver_next_index(&self) -> Result<Option<usize>> {
        ensure!(
            self.failure.is_none(),
            "sync run blocked by earlier failure"
        );
        ensure!(!self.is_cancelled(), "sync run cancelled");
        ensure!(
            self.active.is_none(),
            "sync run already has a file in flight"
        );
        Ok(self
            .entries
            .iter()
            .position(|entry| entry.state == FileState::Pending))
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn entries(&self) -> &[RunEntry] {
        &self.entries
    }
    pub fn active_path(&self) -> Option<&str> {
        self.active.map(|i| self.entries[i].path.as_str())
    }
    pub fn failure(&self) -> Option<&RunFailure> {
        self.failure.as_ref()
    }
    pub fn is_blocked(&self) -> bool {
        self.failure.is_some()
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.is_some()
    }
    pub fn cancelled_reason(&self) -> Option<&str> {
        self.cancelled.as_deref()
    }
    /// Aggregated operator view: local ledger facts plus accepted receipt sizes.
    /// Not remote progress and not a completion proof.
    pub fn status(&self) -> RunStatus {
        let settled = self.settled_count();
        let planned = self.entries.len();
        let state = if self.failure.is_some() {
            RunState::Blocked
        } else if self.cancelled.is_some() {
            RunState::Cancelled
        } else if settled == planned {
            RunState::Complete
        } else {
            RunState::Running
        };
        RunStatus {
            state,
            planned,
            settled,
            failed: self.failed_count(),
            cancelled: self.count(FileState::Cancelled),
            settled_bytes: self.settled_bytes,
        }
    }
    /// Stops new work permanently. Any in-flight file becomes Cancelled and the
    /// caller must drop its pumps: no rollback, no debt release, no completion.
    /// Refused after a failure or after the run already completed.
    pub fn cancel(&mut self, reason: &str) -> Result<()> {
        ensure!(!reason.is_empty(), "cancel reason required");
        ensure!(self.failure.is_none(), "sync run already failed");
        ensure!(!self.is_cancelled(), "sync run already cancelled");
        ensure!(
            self.settled_count() < self.entries.len(),
            "sync run already complete"
        );
        if let Some(index) = self.active.take() {
            self.entries[index].state = FileState::Cancelled;
        }
        self.cancelled = Some(reason.to_string());
        Ok(())
    }
    /// Receipt sizes only; NOT traffic, encoded bytes or durability.
    pub fn settled_bytes(&self) -> u64 {
        self.settled_bytes
    }
    pub fn settled_count(&self) -> usize {
        self.count(FileState::Settled)
    }
    pub fn failed_count(&self) -> usize {
        self.count(FileState::Failed)
    }
    fn count(&self, state: FileState) -> usize {
        self.entries.iter().filter(|e| e.state == state).count()
    }
    /// Next planned file, in plan order. Refuses while another file is in flight
    /// and after any failure. Returns None when every file is terminal.
    pub fn start_next(&mut self) -> Result<Option<&str>> {
        ensure!(
            self.failure.is_none(),
            "sync run blocked by earlier failure"
        );
        ensure!(!self.is_cancelled(), "sync run cancelled");
        ensure!(
            self.active.is_none(),
            "sync run already has a file in flight"
        );
        let Some(index) = self
            .entries
            .iter()
            .position(|e| e.state == FileState::Pending)
        else {
            return Ok(None);
        };
        self.entries[index].state = FileState::InFlight;
        self.active = Some(index);
        Ok(Some(self.entries[index].path.as_str()))
    }
    /// Accepts only the in-flight file's exact receipt size and SHA. A mismatch
    /// changes nothing, so the caller must resolve it rather than mask it.
    pub fn settle(&mut self, receipt: &Receipt) -> Result<()> {
        ensure!(
            self.failure.is_none(),
            "sync run blocked by earlier failure"
        );
        ensure!(!self.is_cancelled(), "sync run cancelled");
        let index = self
            .active
            .ok_or_else(|| anyhow::anyhow!("no file in flight to settle"))?;
        let entry = &self.entries[index];
        ensure!(
            receipt.size == entry.bytes
                && receipt.sha256 == entry.job.sha256
                && entry.receipt.is_none(),
            "receipt size/SHA mismatch or duplicate settlement for {}",
            entry.path
        );
        let settled_bytes = self
            .settled_bytes
            .checked_add(receipt.size)
            .ok_or_else(|| anyhow::anyhow!("settled byte overflow"))?;
        self.entries[index].state = FileState::Settled;
        self.entries[index].receipt = Some(receipt.clone());
        self.settled_bytes = settled_bytes;
        self.active = None;
        Ok(())
    }
    /// Terminal for this ledger. The in-flight file becomes Failed and the whole
    /// run stops: retained receipts and bytes are kept, nothing is retried.
    pub fn fail(&mut self, reason: &str) -> Result<()> {
        let index = self
            .active
            .ok_or_else(|| anyhow::anyhow!("no file in flight to fail"))?;
        ensure!(self.failure.is_none(), "sync run already failed");
        ensure!(!self.is_cancelled(), "sync run cancelled");
        ensure!(!reason.is_empty(), "failure reason required");
        let path = self.entries[index].path.clone();
        self.entries[index].state = FileState::Failed;
        self.active = None;
        self.failure = Some(RunFailure {
            path,
            reason: reason.to_string(),
        });
        Ok(())
    }
}
