//! Strict, bounded control bodies. Decode only AFTER AEAD authentication.
//! Structural validation does not prove durable IO or a receiver journal.
use super::{
    job::ValidatedGrant,
    protocol::{Binding, Header, Kind, MAX_CONTROL},
    ranges::WINDOW,
    state::Phase,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ready {
    pub chunk_bytes: u32,
    pub window_chunks: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ack {
    pub contiguous: u64,
    pub received: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finish {
    pub size: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParentDurability {
    Synced,
    Unsupported,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub receipt_id: Uuid,
    pub size: u64,
    pub sha256: [u8; 32],
    pub parent_durability: ParentDurability,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CancelReason {
    Operator,
    SourceChanged,
    SourceIo,
    DeadlineExpired,
    GrantRevoked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cancel {
    pub reason: CancelReason,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Cleanup {
    NotRequired,
    Pending,
    Confirmed,
    Retained,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidInput,
    Unsupported,
    SourceChanged,
    Io,
    HashMismatch,
    DeadlineExpired,
    GrantRevoked,
    Interrupted,
    CleanupFailed,
    CommitUncertain,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub phase: Phase,
    pub bytes_received: u64,
    pub bytes_committed: u64,
    pub cleanup: Cleanup,
    pub receipt: Option<Receipt>,
    pub error: Option<ErrorCode>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum ControlBody {
    Prepare(Empty),
    Ready(Ready),
    Ack(Ack),
    Finish(Finish),
    CommitAck(Receipt),
    Cancel(Cancel),
    StatusRequest(Empty),
    Status(Status),
}
impl ControlBody {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Prepare(_) => Kind::Prepare,
            Self::Ready(_) => Kind::Ready,
            Self::Ack(_) => Kind::Ack,
            Self::Finish(_) => Kind::Finish,
            Self::CommitAck(_) => Kind::CommitAck,
            Self::Cancel(_) => Kind::Cancel,
            Self::StatusRequest(_) => Kind::StatusRequest,
            Self::Status(_) => Kind::Status,
        }
    }
    fn validate(&self, g: &ValidatedGrant) -> Result<()> {
        let job = g.job();
        let total = job.bytes_total;
        let check_digest = |size: u64, hash: &[u8; 32]| -> Result<()> {
            ensure!(
                size == total && hash == &job.sha256,
                "fleet final size/SHA differs from approved job"
            );
            Ok(())
        };
        let check_receipt = |r: &Receipt| -> Result<()> {
            ensure!(!r.receipt_id.is_nil(), "nil fleet receipt identifier");
            check_digest(r.size, &r.sha256)
        };
        match self {
            Self::Prepare(_) | Self::Cancel(_) | Self::StatusRequest(_) => {}
            Self::Ready(r) => ensure!(
                r.chunk_bytes == g.grant().chunk_bytes
                    && (1..=WINDOW as u8).contains(&r.window_chunks),
                "READY does not match negotiated grant/window"
            ),
            Self::Ack(a) => {
                ensure!(
                    a.contiguous <= a.received && a.received <= total,
                    "ACK counters outside file"
                );
                ensure!(
                    a.received - a.contiguous <= (g.grant().chunk_bytes as u64) * WINDOW as u64,
                    "ACK exceeds bounded receive window"
                );
            }
            Self::Finish(f) => check_digest(f.size, &f.sha256)?,
            Self::CommitAck(r) => check_receipt(r)?,
            Self::Status(s) => {
                ensure!(s.bytes_received <= total, "STATUS received outside file");
                if s.phase == Phase::Completed {
                    ensure!(
                        s.bytes_received == total
                            && s.bytes_committed == total
                            && s.error.is_none()
                            && matches!(s.cleanup, Cleanup::NotRequired | Cleanup::Confirmed),
                        "completed STATUS requires full receipt and no pending cleanup/error"
                    );
                    check_receipt(
                        s.receipt
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("completed STATUS missing receipt"))?,
                    )?;
                } else {
                    ensure!(
                        s.bytes_committed == 0 && s.receipt.is_none(),
                        "non-completed STATUS cannot claim committed bytes/receipt"
                    );
                }
                if matches!(s.phase, Phase::Queued | Phase::Preparing) {
                    ensure!(s.bytes_received == 0, "unstarted STATUS received bytes");
                }
                if matches!(
                    s.phase,
                    Phase::Verifying | Phase::Committing | Phase::CommitUnknown
                ) {
                    ensure!(
                        s.bytes_received == total,
                        "post-transfer STATUS needs full stage coverage"
                    );
                }
                if s.phase == Phase::Cancelled {
                    ensure!(
                        s.cleanup == Cleanup::Confirmed && s.error.is_none(),
                        "cancelled STATUS requires confirmed cleanup"
                    );
                }
                if s.phase == Phase::Failed {
                    ensure!(s.error.is_some(), "failed STATUS needs an error code");
                }
                if s.phase == Phase::Expired {
                    ensure!(
                        s.error == Some(ErrorCode::DeadlineExpired),
                        "expired STATUS needs deadline error"
                    );
                }
                if s.phase == Phase::Interrupted {
                    ensure!(
                        s.error == Some(ErrorCode::Interrupted),
                        "interrupted STATUS needs interruption error"
                    );
                }
                if matches!(
                    s.phase,
                    Phase::Queued
                        | Phase::Preparing
                        | Phase::Transferring
                        | Phase::Verifying
                        | Phase::Committing
                ) {
                    ensure!(s.error.is_none(), "active STATUS has terminal error");
                }
                if matches!(s.cleanup, Cleanup::Pending | Cleanup::Retained) {
                    ensure!(
                        !matches!(s.phase, Phase::Completed | Phase::Cancelled),
                        "unclean STATUS cannot claim success/cancelled"
                    );
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlMessage {
    version: u16,
    job_digest: [u8; 32],
    grant_digest: [u8; 32],
    pub body: ControlBody,
}
impl ControlMessage {
    pub fn new(g: &ValidatedGrant, body: ControlBody) -> Result<Self> {
        body.validate(g)?;
        Ok(Self {
            version: 1,
            job_digest: g.grant().job_digest,
            grant_digest: g.digest(),
            body,
        })
    }
    pub fn encode(&self, g: &ValidatedGrant) -> Result<Vec<u8>> {
        self.validate(g)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= MAX_CONTROL, "control payload too large");
        Ok(bytes)
    }
    fn validate(&self, g: &ValidatedGrant) -> Result<()> {
        ensure!(self.version == 1, "unsupported control body version");
        ensure!(
            self.job_digest == g.grant().job_digest && self.grant_digest == g.digest(),
            "control job/grant digest mismatch"
        );
        self.body.validate(g)
    }
    pub fn decode(h: &Header, bytes: &[u8], g: &ValidatedGrant) -> Result<Self> {
        h.validate()?;
        ensure!(
            h.kind != Kind::Data
                && bytes.len() <= MAX_CONTROL
                && h.plaintext_len as usize == bytes.len(),
            "invalid control envelope/length"
        );
        let expected: &Binding = &g.grant().binding;
        ensure!(&h.binding == expected, "control record binding mismatch");
        let msg: Self = serde_json::from_slice(bytes)?;
        msg.validate(g)?;
        ensure!(
            msg.body.kind() == h.kind,
            "control type differs from authenticated record kind"
        );
        Ok(msg)
    }
}
