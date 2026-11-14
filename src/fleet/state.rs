//! Deterministic single-file transaction model. No IO/durability/auth is implied.
use super::{
    protocol::{Binding, MAX_FILE_BYTES},
    ranges::ReceiveRanges,
};
use anyhow::{Result, ensure};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Queued,
    Preparing,
    Transferring,
    Verifying,
    Committing,
    Completed,
    CancelRequested,
    Cancelled,
    Failed,
    Expired,
    Interrupted,
    CommitUnknown,
}
impl Phase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::Failed | Self::Expired | Self::Interrupted
        )
    }
}
/// A validated transport envelope is not a durable receipt. P1 must persist the
/// receiver receipt BEFORE emitting COMMIT_ACK and prove it came from that peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub binding: Binding,
    pub size: u64,
    pub sha256: [u8; 32],
}
#[derive(Debug)]
pub struct TransferState {
    binding: Binding,
    total: u64,
    deadline_ms: u64,
    last_ms: u64,
    phase: Phase,
    digest: Option<[u8; 32]>,
    verified: bool,
    receipt: Option<CommitReceipt>,
}
impl TransferState {
    pub fn new(binding: Binding, total: u64, deadline_ms: u64, now_ms: u64) -> Result<Self> {
        binding.validate()?;
        ensure!(total <= MAX_FILE_BYTES, "fleet size quota exceeded");
        ensure!(deadline_ms > now_ms, "fleet deadline already expired");
        Ok(Self {
            binding,
            total,
            deadline_ms,
            last_ms: now_ms,
            phase: Phase::Queued,
            digest: None,
            verified: false,
            receipt: None,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn bytes_committed(&self) -> u64 {
        if self.receipt.is_some() {
            self.total
        } else {
            0
        }
    }
    pub fn receipt(&self) -> Option<&CommitReceipt> {
        self.receipt.as_ref()
    }
    fn observe_time(&mut self, now_ms: u64) -> Result<()> {
        ensure!(now_ms >= self.last_ms, "fleet clock moved backwards");
        self.last_ms = now_ms;
        if now_ms >= self.deadline_ms && !self.phase.terminal() {
            self.phase = if matches!(self.phase, Phase::Committing | Phase::CommitUnknown) {
                Phase::CommitUnknown
            } else {
                Phase::Expired
            };
        }
        Ok(())
    }
    fn live(&mut self, now_ms: u64) -> Result<()> {
        self.observe_time(now_ms)?;
        ensure!(now_ms < self.deadline_ms, "fleet deadline expired");
        Ok(())
    }
    pub fn prepare(&mut self, now_ms: u64) -> Result<()> {
        self.live(now_ms)?;
        ensure!(self.phase == Phase::Queued, "invalid prepare transition");
        self.phase = Phase::Preparing;
        Ok(())
    }
    pub fn ready(&mut self, now_ms: u64) -> Result<()> {
        self.live(now_ms)?;
        ensure!(self.phase == Phase::Preparing, "invalid ready transition");
        self.phase = Phase::Transferring;
        Ok(())
    }
    pub fn begin_verification(
        &mut self,
        ranges: &ReceiveRanges,
        digest: [u8; 32],
        now_ms: u64,
    ) -> Result<()> {
        self.live(now_ms)?;
        ensure!(
            self.phase == Phase::Transferring && ranges.total() == self.total && ranges.complete(),
            "file coverage incomplete or verification out of order"
        );
        self.digest = Some(digest);
        self.phase = Phase::Verifying;
        Ok(())
    }
    /// Supply the actually computed receiver readback, not the sender's value.
    pub fn verify_readback(&mut self, actual: [u8; 32], now_ms: u64) -> Result<()> {
        self.live(now_ms)?;
        ensure!(
            self.phase == Phase::Verifying,
            "invalid verification transition"
        );
        let expected = self.digest.expect("verification requires digest");
        if !bool::from(expected.ct_eq(&actual)) {
            self.phase = Phase::Failed;
            anyhow::bail!("fleet SHA256 mismatch");
        }
        self.verified = true;
        Ok(())
    }
    pub fn begin_commit(&mut self, now_ms: u64) -> Result<()> {
        self.live(now_ms)?;
        ensure!(
            self.phase == Phase::Verifying && self.verified,
            "unverified fleet commit"
        );
        self.phase = Phase::Committing;
        Ok(())
    }
    /// After the commit boundary, neither cancellation nor timeout proves that
    /// the destination was untouched. Only reconciliation can settle it.
    pub fn request_cancel(&mut self) -> Phase {
        match self.phase {
            Phase::Committing | Phase::CommitUnknown => self.phase = Phase::CommitUnknown,
            p if !p.terminal() => self.phase = Phase::CancelRequested,
            _ => {}
        }
        self.phase
    }
    /// Caller must have received authenticated receiver cleanup confirmation.
    pub fn confirm_cancelled(&mut self) -> Result<()> {
        ensure!(
            matches!(self.phase, Phase::CancelRequested | Phase::Cancelled),
            "cancellation needs receiver confirmation before commit"
        );
        self.phase = Phase::Cancelled;
        Ok(())
    }
    pub fn connection_lost(&mut self) {
        match self.phase {
            Phase::Committing | Phase::CommitUnknown => self.phase = Phase::CommitUnknown,
            p if !p.terminal() => self.phase = Phase::Interrupted,
            _ => {}
        }
    }
    pub fn expire(&mut self, now_ms: u64) -> Result<Phase> {
        self.observe_time(now_ms)?;
        Ok(self.phase)
    }
    /// Accept only a previously authenticated, durably persisted peer receipt.
    /// Late receipts may settle CommitUnknown even after the observation deadline.
    pub fn reconcile_commit(&mut self, receipt: CommitReceipt) -> Result<()> {
        if let Some(existing) = &self.receipt {
            ensure!(existing == &receipt, "conflicting fleet commit receipt");
            return Ok(());
        }
        ensure!(
            matches!(self.phase, Phase::Committing | Phase::CommitUnknown) && self.verified,
            "unexpected fleet commit receipt"
        );
        ensure!(
            receipt.binding == self.binding
                && receipt.size == self.total
                && self
                    .digest
                    .is_some_and(|expected| bool::from(expected.ct_eq(&receipt.sha256))),
            "fleet commit receipt mismatch"
        );
        self.receipt = Some(receipt);
        self.phase = Phase::Completed;
        Ok(())
    }
}
