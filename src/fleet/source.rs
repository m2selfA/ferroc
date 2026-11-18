//! Pure active source record bridge. No file IO, network, queue/backpressure,
//! source journal, receiver-private-state proof, or restart/resume capability.
use super::{
    auth::{EphemeralKey, PeerRecord, Transcript},
    control::{ControlBody, Finish, Receipt},
    job::{JobSpec, ValidatedGrant},
    lease::LeasedRecords,
    protocol::Binding,
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

/// Owns a NEW Source-role record session and the bytes this owner encoded.
/// bytes_encoded is NOT bytes sent/received/durable. Ordered chunks only; the
/// approved total/hash must match before FINISH. Caller supplies bytes, not a
/// checked source-file handle. There is no transport window or IO implication.
/// ```
/// fn source(r:ferroc::fleet::lease::LeasedRecords)->anyhow::Result<ferroc::fleet::source::SourceEncoder>{ferroc::fleet::source::SourceEncoder::new(r)}
/// ```
/// ```compile_fail
/// fn no_clone(s:ferroc::fleet::source::SourceEncoder){let _=s.clone();}
/// ```
/// ```compile_fail
/// fn no_unwrap(s:ferroc::fleet::source::SourceEncoder){let _=s.records;}
/// ```
/// ```compile_fail
/// fn no_restore(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::source::SourceEncoder::from(s);}
/// ```
/// ```compile_fail
/// fn no_bare_now(r:ferroc::fleet::lease::LeasedRecords){let _=ferroc::fleet::source::SourceEncoder::new(r,0);}
/// ```
/// ```compile_fail
/// fn no_early_ack(s:&mut ferroc::fleet::source::SourceEncoder,frame:&[u8]){s.observe_final(frame).unwrap();}
/// ```
pub struct SourceEncoder {
    records: LeasedRecords,
    hash: Sha256,
    bytes_encoded: u64,
    resume_prefix: Option<u64>,
    faulted: bool,
}
impl SourceEncoder {
    pub fn new(mut records: LeasedRecords) -> Result<Self> {
        records.enter_fresh_source()?;
        Ok(Self {
            records,
            hash: Sha256::new(),
            bytes_encoded: 0,
            resume_prefix: None,
            faulted: false,
        })
    }
    pub fn job(&self) -> &JobSpec {
        self.records.grant().job()
    }
    #[cfg(test)]
    pub(super) fn test_expire(&mut self) {
        self.records.test_expire();
    }
    pub(super) fn current_grant(&self) -> &ValidatedGrant {
        self.records.grant()
    }
    pub(super) fn io_chunk_bytes(&self) -> usize {
        self.records.grant().grant().chunk_bytes as usize
    }
    pub(super) fn check_source_io(&mut self) -> Result<()> {
        ensure!(!self.faulted, "source encoder faulted");
        if let Err(e) = self.records.check_commit_admission() {
            self.revoke();
            return Err(e);
        }
        Ok(())
    }
    pub(super) fn flow_faulted(&self) -> bool {
        self.faulted
    }
    pub(super) fn current_binding(&self) -> super::protocol::Binding {
        self.records.grant().grant().binding.clone()
    }
    pub(super) fn seal_flow_control(&mut self, body: ControlBody) -> Result<Vec<u8>> {
        ensure!(!self.faulted, "source encoder faulted");
        self.records.seal_control(body)
    }
    pub(super) fn open_flow_control(&mut self, bytes: &[u8]) -> Result<PeerRecord> {
        self.check_source_io()?;
        let result = self.records.open_record(bytes);
        if self.records.source_record_faulted() {
            self.revoke();
        }
        self.check_source_io()?;
        result
    }
    /// NEW suffix DATA bytes encoded by this owner; excludes any restored prefix.
    pub fn bytes_encoded(&self) -> u64 {
        self.bytes_encoded
    }
    pub fn resumed_prefix_bytes(&self) -> Option<u64> {
        self.resume_prefix
    }
    /// Logical next DATA offset, not a traffic/durability/current-file counter.
    pub fn next_data_offset(&self) -> u64 {
        self.resume_prefix.unwrap_or(0) + self.bytes_encoded
    }
    pub(super) fn restore_prefix(&mut self, hash: Sha256, bytes: u64) -> Result<()> {
        self.check_source_io()?;
        ensure!(
            self.resume_prefix.is_none()
                && self.bytes_encoded == 0
                && bytes <= self.job().bytes_total
                && self.records.grant().lease_profile() == super::job::LeaseProfile::SingleOwner,
            "source prefix seed requires fresh SingleOwner state"
        );
        self.hash = hash;
        self.resume_prefix = Some(bytes);
        Ok(())
    }
    /// Seal next ordered chunk; cache exact returned bytes for retransmission.
    /// A failed crypto/lease call closes this encoder; validation-only errors do
    /// not advance count/hash. The component retains no DATA queue.
    pub fn encode_next(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        ensure!(!self.faulted, "source encoder faulted");
        let offset = self.next_data_offset();
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("source byte count overflow"))?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= self.records.grant().grant().chunk_bytes as usize
                && end <= self.job().bytes_total,
            "source chunk empty/oversized/beyond approved total"
        );
        let frame = match self.records.seal_data(offset, bytes) {
            Ok(frame) => frame,
            Err(e) => {
                self.faulted = true;
                self.records.revoke();
                return Err(e);
            }
        };
        self.hash.update(bytes);
        self.bytes_encoded += bytes.len() as u64;
        Ok(frame)
    }
    pub fn revoke(&mut self) {
        self.records.revoke();
        self.faulted = true;
    }
    /// Renewal retains count/hash and original total deadline. Failed renewal
    /// preserves the old session per LeasedRecords. No renewal exists after FINISH.
    pub fn renew(
        &mut self,
        g: ValidatedGrant,
        k: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<()> {
        ensure!(!self.faulted, "source encoder faulted");
        self.records.renew(g, k, t, a, b)
    }
    /// Consume DATA capability. This only ENCODEs FINISH; not network delivery or
    /// target commit. Returned owner caches one immutable FINISH for retries.
    pub fn finish(self) -> Result<AwaitingCommit> {
        ensure!(
            !self.faulted && self.next_data_offset() == self.job().bytes_total,
            "source FINISH needs full encoded coverage"
        );
        let expected = self.job().sha256;
        let total = self.next_data_offset();
        let actual: [u8; 32] = self.hash.finalize().into();
        ensure!(
            actual == expected,
            "source encoded SHA256 differs from approved job"
        );
        let mut records = self.records;
        let finish = records.seal_control(ControlBody::Finish(Finish {
            size: total,
            sha256: actual,
        }))?;
        Ok(AwaitingCommit {
            records,
            finish,
            observation: None,
            accepted_frame_hash: None,
            unknown: false,
            faulted: false,
        })
    }
}
/// This status is only an in-memory authenticated peer statement, NOT local or
/// remote durability/current file truth. Even a valid peer can lie about IO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceCommitStatus {
    AwaitingAck,
    CommitUnknown,
    PeerReportedCompleted,
}
/// Descriptive authenticated observation. Clone/Serialize do not confer IO or
/// live session capabilities; there is deliberately NO Deserialize/constructor.
/// ```compile_fail
/// let _:ferroc::fleet::source::PeerCommitObservation=serde_json::from_str("null").unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PeerCommitObservation {
    job_digest: [u8; 32],
    binding: Binding,
    receipt: Receipt,
}
impl PeerCommitObservation {
    pub fn job_digest(&self) -> [u8; 32] {
        self.job_digest
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalAckOutcome {
    NotFinal,
    Accepted,
    Duplicate,
}
/// No DATA, renew, bare-time, key export, receiver state, persistence or network.
/// Only active FINISH owner can produce this type. A queued precomputed peer ACK
/// cannot prove private IO/causal timing; observation describes peer's claim only.
/// ```compile_fail
/// fn no_data(s: &mut ferroc::fleet::source::AwaitingCommit){s.encode_next(b"x").unwrap();}
/// ```
/// ```compile_fail
/// fn no_renew(s:&mut ferroc::fleet::source::AwaitingCommit,g:ferroc::fleet::job::ValidatedGrant,k:ferroc::fleet::auth::EphemeralKey,t:&ferroc::fleet::auth::Transcript,a:&[u8;64],b:&[u8;64]){s.renew(g,k,t,a,b).unwrap();}
/// ```
/// ```compile_fail
/// fn no_receipt_import(r:ferroc::fleet::control::Receipt){let _=ferroc::fleet::source::AwaitingCommit::from(r);}
/// ```
pub struct AwaitingCommit {
    records: LeasedRecords,
    finish: Vec<u8>,
    observation: Option<PeerCommitObservation>,
    accepted_frame_hash: Option<[u8; 32]>,
    unknown: bool,
    faulted: bool,
}
impl AwaitingCommit {
    pub fn finish_record(&self) -> &[u8] {
        &self.finish
    }
    pub fn job(&self) -> &JobSpec {
        self.records.grant().job()
    }
    pub fn status(&self) -> SourceCommitStatus {
        if self.observation.is_some() {
            SourceCommitStatus::PeerReportedCompleted
        } else if self.unknown || self.faulted {
            SourceCommitStatus::CommitUnknown
        } else {
            SourceCommitStatus::AwaitingAck
        }
    }
    pub fn peer_observation(&self) -> Option<&PeerCommitObservation> {
        self.observation.as_ref()
    }
    pub fn bytes_peer_reported_committed(&self) -> u64 {
        self.observation.as_ref().map_or(0, |o| o.receipt.size)
    }
    pub fn is_faulted(&self) -> bool {
        self.faulted
    }
    pub fn connection_lost(&mut self) {
        self.unknown = true;
    }
    /// Consume only authenticated active-epoch records. ACK/STATUS/READY and
    /// unrelated Duplicate never create completion. Only the EXACT accepted
    /// cached ciphertext is idempotent within the active replay window and
    /// clock continuity. Eviction/errors never erase an accepted observation.
    /// A fresh second final record (even equal
    /// receipt) violates the one-cached-ACK contract and closes this consumer;
    /// the earlier accepted historical observation is never erased/replaced.
    pub fn observe_final(&mut self, bytes: &[u8]) -> Result<FinalAckOutcome> {
        ensure!(!self.faulted, "source final ACK consumer faulted");
        let peer = match self.records.open_record(bytes) {
            Ok(p) => p,
            Err(e) => {
                self.faulted = self.records.source_record_faulted();
                return Err(e);
            }
        };
        let fingerprint: [u8; 32] = Sha256::digest(bytes).into();
        match peer {
            PeerRecord::Duplicate { .. } => Ok(
                if self.observation.is_some() && self.accepted_frame_hash == Some(fingerprint) {
                    FinalAckOutcome::Duplicate
                } else {
                    FinalAckOutcome::NotFinal
                },
            ),
            PeerRecord::Control { header, message } => match message.body {
                ControlBody::CommitAck(receipt) => {
                    if self.observation.is_some() {
                        self.faulted = true;
                        self.records.revoke();
                        anyhow::bail!("fresh second final ACK conflicts with cached receipt");
                    }
                    self.observation = Some(PeerCommitObservation {
                        job_digest: self.records.grant().grant().job_digest,
                        binding: header.binding,
                        receipt,
                    });
                    self.accepted_frame_hash = Some(fingerprint);
                    Ok(FinalAckOutcome::Accepted)
                }
                _ => Ok(FinalAckOutcome::NotFinal),
            },
            _ => Ok(FinalAckOutcome::NotFinal),
        }
    }
}
#[cfg(test)]
#[path = "source_tests.rs"]
mod tests;
