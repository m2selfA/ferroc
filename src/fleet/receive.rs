//! Local lease-gated DATA writer only. No listener, publication or resume.
//! v4 receive intent precedes IO. Drop closes File then drains the host permit;
//! it NEVER deletes a stage or releases persistent reservations.
#[path = "commit_admission.rs"]
mod commit_admission;
pub use commit_admission::CommitCandidate;
#[path = "prefix_observation.rs"]
mod prefix_observation;
#[cfg(any(windows, target_os = "linux"))]
pub use commit_admission::{FinishedCandidate, ReceiptedCandidate, RenamedCandidate};
pub use prefix_observation::SyncedPrefixObservation;
#[path = "receive_resume.rs"]
mod receive_resume;
#[path = "retained_receiver.rs"]
mod retained_receiver;
#[cfg(test)]
#[path = "receive_tests.rs"]
mod tests;
use super::{FleetHost, Operation};
use crate::fleet::{
    auth::{EphemeralKey, PeerRecord, Transcript},
    fence::{FencedConnection, file_id},
    identity::open_stage,
    job::ValidatedGrant,
    journal::{JobKey, Snapshot},
    lease::LeasedRecords,
    protocol::Kind,
    ranges::{Admission, ReceiveRanges},
    state::Phase,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
/// No raw file/session escape; restarting cannot reconstruct coverage or adopt it.
/// close/shutdown waits until this accepted transfer is dropped, even while idle.
/// Async owners must arrange receiver shutdown/Drop before awaiting host close.
/// ```compile_fail
/// fn cannot_export_file(r:ferroc::fleet::host::receiver::HostReceiver<'_,'_>){let _=r.file;}
/// ```
/// ```compile_fail
/// fn cannot_clone(r:ferroc::fleet::host::receiver::HostReceiver<'_,'_>){let _=r.clone();}
/// ```
/// Journal checkpoint granularity for received bytes (not a resume token).
const PROGRESS_EVERY: u64 = 4 * 1024 * 1024;
/// Grouped durability for stage appends; see `write_record`.
const SYNC_EVERY: u64 = 4 * 1024 * 1024;
/// Target-side view of one renewal handshake: the successor it accepted and the
/// coverage it promised to install at.
#[derive(Clone, Debug)]
struct ReceiverRenewal {
    generation: u64,
    next_authorization_id: uuid::Uuid,
    next_key_epoch: uuid::Uuid,
    drained_at: u64,
}
pub struct HostReceiver<'h, 'r> {
    file: File,
    records: LeasedRecords,
    ranges: ReceiveRanges,
    /// Verified local recovery prefix, NOT negotiated by ordinary READY.
    resume_base: Option<Box<crate::fleet::control::ResumeBase>>,
    snapshot: Snapshot,
    faulted: bool,
    published: bool,
    flow_window: Option<u8>,
    flow_ready: Option<Vec<u8>>,
    flow_ack: Option<(u64, u64, Vec<u8>)>,
    /// Open renewal handshake. One at a time; cleared on install or revoke.
    renewal: Option<ReceiverRenewal>,
    /// Bytes appended since the last grouped durability point.
    unsynced: u64,
    /// Last received-byte count already committed to the journal. Persisting
    /// every 64 KiB chunk costs one SQLite commit per chunk, which dominates a
    /// large transfer; the in-memory ranges stay authoritative for ACKs and the
    /// seal still requires the complete stage, so a coarser checkpoint cannot
    /// produce a receipt. It is a checkpoint, never a resume token.
    persisted: u64,
    // File MUST drop before this operation releases the host's drain counter.
    operation: Operation<'h, 'r>,
}
fn check_stage(
    db: &FencedConnection,
    s: &Snapshot,
    file: &File,
    host: &FleetHost<'_>,
    published: bool,
) -> Result<File> {
    db.fence.check_connection(&db.connection)?;
    let r = s.stage().context("receive allocation missing")?;
    let a = r.allocation().context("receive binding missing")?;
    ensure!(
        !published || s.is_publication_attempt(),
        "unmarked publication location"
    );
    let (dest, parent, id) = if published {
        crate::fleet::allocation::published_parent(&host.attachment.runtime.policy, s)?
    } else {
        crate::fleet::allocation::parent(&host.attachment.runtime.policy, s)?
    };
    ensure!(
        s.owner() == db.fence.owner
            && a.original_owner() == db.fence.owner
            && a.database_id() == Some(db.fence.database_id())
            && a.database_parent_id() == Some(db.fence.database_parent_id()?.as_str())
            && a.parent_id() == id
            && r.path().parent() == dest.parent(),
        "receive parent/domain changed"
    );
    let observed = crate::fleet::allocation::stage_object_id(file, a.is_anonymous(), published)?;
    ensure!(
        a.file_id() == Some(observed.as_str())
            && if published {
                file_id(&open_stage(&dest)?)? == observed
            } else {
                crate::fleet::allocation::stage_path_matches(r.path(), &observed, a.is_anonymous())?
            }
            && file.metadata()?.len() <= s.job().bytes_total,
        "receive file object/size changed"
    );
    Ok(parent)
}
impl<'r> FleetHost<'r> {
    /// Explicit LOCAL slice. Job comes ONLY from authenticated Target records;
    /// never recreate/reopen on replay. Failure preserves any admitted obligation.
    pub fn admit_receiver<'h>(&'h self, records: LeasedRecords) -> Result<HostReceiver<'h, 'r>> {
        self.admit_receiver_inner(records, false)
    }
    /// Explicit Linux O_TMPFILE receive. Last-FD loss reclaims unnamed bytes;
    /// the journal reservation remains full, with no automatic reconciliation.
    /// A REPLACEMENT job must have arrived with its authorized pre-image; the
    /// publish step links once under a job-derived reserved name and then renames
    /// over the destination, so the destination is never partially visible.
    #[cfg(target_os = "linux")]
    pub fn admit_linux_anonymous_receiver<'h>(
        &'h self,
        records: LeasedRecords,
    ) -> Result<HostReceiver<'h, 'r>> {
        if records.grant().job().overwrite {
            ensure!(
                records.grant().job().pre_image_sha256.is_some(),
                "replacement job lost its authorized pre-image"
            );
        }
        self.admit_receiver_inner(records, true)
    }
    fn admit_receiver_inner<'h>(
        &'h self,
        mut records: LeasedRecords,
        anonymous: bool,
    ) -> Result<HostReceiver<'h, 'r>> {
        let operation = self.enter(true)?;
        let now = records.receive_admission()?;
        let job = records.grant().job().clone();
        let key = JobKey::from_job(&job);
        let ranges = ReceiveRanges::new(job.bytes_total)?;
        let mut guard = self
            .database
            .lock()
            .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
        let db = guard.as_mut().context("host database closed")?;
        let (new, s) = db.journal()?.admit(job, now)?;
        ensure!(new, "receive replay/resume forbidden");
        let reserved = if anonymous {
            #[cfg(target_os = "linux")]
            {
                db.reserve_anonymous_stage(
                    &key,
                    s.revision(),
                    &self.attachment.runtime.policy,
                    self.gate.clone(),
                    self.limits,
                )?
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("anonymous receive requires Linux");
            }
        } else {
            db.reserve_stage(
                &key,
                s.revision(),
                &self.attachment.runtime.policy,
                self.gate.clone(),
                self.limits,
            )?
        };
        records.receive_admission()?;
        let (bound, file) = db.create_receive_reserved(
            &key,
            reserved.revision(),
            &self.attachment.runtime.policy,
            self.gate.clone(),
        )?;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        let _parent = check_stage(db, &bound, &file, self, false)?;
        ensure!(file.metadata()?.len() == 0, "fresh receiver is not empty");
        records.receive_admission()?;
        let snapshot = db.journal()?.begin_receive(&key, bound.revision())?;
        records.receive_admission()?;
        Ok(HostReceiver {
            file,
            records,
            ranges,
            resume_base: None,
            snapshot,
            faulted: false,
            published: false,
            flow_window: None,
            flow_ready: None,
            flow_ack: None,
            renewal: None,
            unsynced: 0,
            persisted: 0,
            operation,
        })
    }
}
/// A LOCAL read-sequence hash observation, NOT a coherent snapshot, immutable content, a persisted
/// verified state, receipt, publish permit, or an assertion about later bytes.
/// DB/gate are released each64KiB to keep cancel/inventory observable. A later
/// publisher MUST revalidate content in its own final critical section.
/// ```compile_fail
/// fn cannot_publish_observation(r:ferroc::fleet::host::receiver::ReadbackObservation){r.publish_with(||Ok(())).unwrap();}
/// ```
pub struct ReadbackObservation {
    bytes: u64,
    sha256: [u8; 32],
    revision: u64,
}
impl ReadbackObservation {
    pub fn bytes_read(&self) -> u64 {
        self.bytes
    }
    pub fn observed_sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
}

/// Live local DATA-closed receiver, never recreated from disk metadata.
/// No write method, raw File or inner receiver escape. Drop keeps file/debt.
/// ```compile_fail
/// fn cannot_write(s:&mut ferroc::fleet::host::receiver::SealedReceiver<'_,'_>){s.write_record(&[]).unwrap();}
/// ```
/// ```compile_fail
/// fn cannot_unseal(s:ferroc::fleet::host::receiver::SealedReceiver<'_,'_>){let _=s.inner;}
/// ```
pub struct SealedReceiver<'h, 'r> {
    inner: HostReceiver<'h, 'r>,
}
impl SealedReceiver<'_, '_> {
    pub fn snapshot(&self) -> &Snapshot {
        self.inner.snapshot()
    }
    /// A fresh local read sequence under the LIVE lease, never durable verified.
    pub fn observe(&mut self) -> Result<ReadbackObservation> {
        self.inner.read_sequence_between(|_, _| Ok(()))
    }
    pub fn revoke(&mut self) {
        self.inner.revoke();
    }
    pub fn renew(
        &mut self,
        next: ValidatedGrant,
        key: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<()> {
        self.inner.renew(next, key, t, a, b)
    }
}

impl<'h, 'r> HostReceiver<'h, 'r> {
    /// Consume the DATA writer after fresh authenticated FINISH. v5 marks DATA
    /// closure only, not successful hashing/verification or a commit permit.
    /// ```compile_fail
    /// fn cannot_reuse(mut r:ferroc::fleet::host::receiver::HostReceiver<'_,'_>,f:&[u8]){let _=r.seal_finish(f);let _=r.write_record(&[]);}
    /// ```
    pub fn seal_finish(self, encrypted: &[u8]) -> Result<SealedReceiver<'h, 'r>> {
        self.seal_between(encrypted, |_| Ok(()))
    }
    fn seal_between(
        mut self,
        encrypted: &[u8],
        after: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<SealedReceiver<'h, 'r>> {
        let result = (|| {
            self.accept_finish(encrypted)?;
            let host = self.operation.host;
            {
                let mut guard = host
                    .database
                    .lock()
                    .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
                let db = guard.as_mut().context("host database closed")?;
                let _gate = host
                    .gate
                    .lock()
                    .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
                let _parent = self.current(db)?;
                self.records.receive_admission()?;
                ensure!(
                    self.file.metadata()?.len() == self.snapshot.job().bytes_total,
                    "sealed stage size changed"
                );
                self.snapshot = db.journal()?.seal_data(
                    &JobKey::from_job(self.snapshot.job()),
                    self.snapshot.revision(),
                    self.records.grant().grant().binding.clone(),
                )?;
                self.records.receive_admission()?;
            }
            // SQL may already have COMMITted even if this returns an error.
            // Never downgrade/unseal or release debt on error/cancel/expiry.
            after(&mut self)?;
            let mut guard = host
                .database
                .lock()
                .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
            let db = guard.as_mut().context("host database closed")?;
            let _gate = host
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            let _parent = self.current(db)?;
            self.records.receive_admission()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(SealedReceiver { inner: self }),
            Err(e) => {
                self.revoke();
                Err(e)
            }
        }
    }

    /// Authenticate a source FINISH and observe complete local stage coverage.
    /// No persisted transition from v4, no borrowed File/session or IO permit.
    pub fn observe_finish(&mut self, encrypted: &[u8]) -> Result<ReadbackObservation> {
        self.observe_between(encrypted, |_, _| Ok(()))
    }
    fn accept_finish(&mut self, encrypted: &[u8]) -> Result<()> {
        ensure!(
            !self.faulted && self.ranges.complete() && self.snapshot.data_seal().is_none(),
            "incomplete/faulted or already sealed receiver"
        );
        self.records.receive_admission()?;
        match self.records.open_record(encrypted)? {
            PeerRecord::Control { message, .. }
                if matches!(message.body, crate::fleet::control::ControlBody::Finish(_)) =>
            {
                Ok(())
            }
            _ => anyhow::bail!("readback requires fresh authenticated FINISH"),
        }
    }
    fn observe_between(
        &mut self,
        encrypted: &[u8],
        between: impl FnMut(u64, &mut Self) -> Result<()>,
    ) -> Result<ReadbackObservation> {
        if let Err(e) = self.accept_finish(encrypted) {
            self.revoke();
            return Err(e);
        }
        self.read_sequence_between(between)
    }
    fn read_sequence_between(
        &mut self,
        mut between: impl FnMut(u64, &mut Self) -> Result<()>,
    ) -> Result<ReadbackObservation> {
        let result = (|| {
            ensure!(
                !self.faulted && self.ranges.complete(),
                "incomplete/faulted receiver readback"
            );
            let host = self.operation.host;
            let total = self.snapshot.job().bytes_total;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                // Same DB->gate order as DATA/inventory; no held lock reaches
                // between(), so SQL cancellation can win at the next chunk.
                let n = {
                    let mut guard = host
                        .database
                        .lock()
                        .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
                    let db = guard.as_mut().context("host database closed")?;
                    let _gate = host
                        .gate
                        .lock()
                        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
                    let _parent = self.current(db)?;
                    self.records.receive_admission()?;
                    ensure!(
                        self.file.metadata()?.len() == total,
                        "readback stage size changed"
                    );
                    self.file.seek(SeekFrom::Start(offset))?;
                    let n = self.file.read(&mut buffer)?;
                    self.records.receive_admission()?;
                    n
                };
                if n == 0 {
                    break;
                }
                offset = offset
                    .checked_add(n as u64)
                    .context("readback size overflow")?;
                ensure!(offset <= total, "readback exceeds task");
                hash.update(&buffer[..n]);
                between(offset, self)?;
            }
            let sha256: [u8; 32] = hash.finalize().into();
            ensure!(
                offset == total && sha256 == self.snapshot.job().sha256,
                "local readback SHA256 mismatch"
            );
            self.records.receive_admission()?;
            Ok(ReadbackObservation {
                bytes: offset,
                sha256,
                revision: self.snapshot.revision(),
            })
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    /// Memory coverage only, NOT readback verification or durable commit.
    pub fn coverage_complete(&self) -> bool {
        !self.faulted && self.ranges.complete()
    }
    /// In-memory cumulative received bytes; not readback, commit or durability.
    pub fn observed_coverage(&self) -> u64 {
        self.ranges.received()
    }
    pub fn revoke(&mut self) {
        self.records.revoke();
        self.faulted = true;
    }
    pub fn renew(
        &mut self,
        next: ValidatedGrant,
        key: EphemeralKey,
        t: &Transcript,
        source_signature: &[u8; 64],
        target_signature: &[u8; 64],
    ) -> Result<()> {
        ensure!(
            self.resume_base.is_none(),
            "resume receiver does not rotate its approved base"
        );
        // Sealed receivers still renew their live epoch (receipts/ACKs), exactly as
        // before; DATA closure is enforced by the flow-control and DATA paths.
        ensure!(!self.faulted, "receiver faulted");
        let host = self.operation.host;
        let mut db = host
            .database
            .lock()
            .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
        let db = db.as_mut().context("host database closed")?;
        let _gate = host
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        let _parent = self.current(db)?;
        let renewed = self
            .records
            .renew(next, key, t, source_signature, target_signature);
        if renewed.is_ok() {
            // Cached READY/ACK ciphertext belongs to the superseded epoch. Drop
            // the bytes, keep the negotiated window and cumulative coverage, and
            // let the next control call re-seal under the current epoch.
            self.flow_ready = None;
            self.flow_ack = None;
        }
        renewed
    }
    fn current(&self, db: &mut FencedConnection) -> Result<File> {
        let s = db
            .journal()?
            .get(&JobKey::from_job(self.snapshot.job()))?
            .context("receive job missing")?;
        self.current_snapshot(db, &s)
    }
    fn current_snapshot(&self, db: &FencedConnection, s: &Snapshot) -> Result<File> {
        ensure!(
            (matches!(s.phase(), Phase::Transferring | Phase::Committing)
                || (s.is_publication_attempt() && s.phase() == Phase::CommitUnknown))
                && s.phase() == self.snapshot.phase()
                && s.job().digest()? == self.snapshot.job().digest()?
                && s.intent() == self.snapshot.intent()
                && s.intent_binding() == self.snapshot.intent_binding()
                && s.owner() == self.snapshot.owner()
                && s.revision() == self.snapshot.revision()
                && s.stage() == self.snapshot.stage()
                && s.data_seal() == self.snapshot.data_seal()
                && s.target_observation() == self.snapshot.target_observation()
                && s.retained_stage() == self.snapshot.retained_stage(),
            "receiver cancelled/stale"
        );
        check_stage(db, s, &self.file, self.operation.host, self.published)
    }
    /// P1 initial-epoch flow READY. Exact cached bytes, never a fresh nonce on
    /// retry. This is live admission, not a proof of final target completion.
    /// Renewal is allowed after READY only at an acknowledged boundary; cached
    /// control ciphertext is dropped and re-sealed under the current epoch.
    /// Accept a successor offer at the current coverage boundary and return the
    /// sealed RENEW_ACCEPT. Nothing is installed yet: the source still has to
    /// commit, so a peer that walks away here leaves the old epoch in force.
    pub fn accept_renewal(
        &mut self,
        offer_frame: &[u8],
    ) -> Result<(crate::fleet::control::RenewOffer, Vec<u8>)> {
        ensure!(
            self.resume_base.is_none(),
            "resume receiver does not rotate its approved base"
        );
        let opened = self.records.open_record(offer_frame)?;
        let offer = match opened {
            crate::fleet::auth::PeerRecord::Control { message, .. } => match message.body {
                crate::fleet::control::ControlBody::RenewOffer(o) => o,
                _ => anyhow::bail!("RENEW_ACCEPT expects a RENEW_OFFER frame"),
            },
            _ => anyhow::bail!("RENEW_ACCEPT expects a control frame"),
        };
        ensure!(
            !self.faulted && self.snapshot.data_seal().is_none(),
            "flow receiver faulted or sealed"
        );
        ensure!(self.flow_window.is_some(), "renewal requires READY");
        ensure!(offer.generation > 0, "renewal generation starts at 1");
        ensure!(self.renewal.is_none(), "renewal handshake already open");
        // No DATA is being written between frames, so this coverage is exactly
        // the boundary the source will be told to install at.
        let drained_at = self.ranges.contiguous();
        let frame = self
            .records
            .seal_control(crate::fleet::control::ControlBody::RenewAccept(
                crate::fleet::control::RenewAccept {
                    next_authorization_id: offer.next_authorization_id,
                    next_key_epoch: offer.next_key_epoch,
                    generation: offer.generation,
                    drained_at,
                },
            ))?;
        self.renewal = Some(ReceiverRenewal {
            generation: offer.generation,
            next_authorization_id: offer.next_authorization_id,
            next_key_epoch: offer.next_key_epoch,
            drained_at,
        });
        Ok((offer, frame))
    }
    /// Install the successor after the source's RENEW_COMMIT. The commit must
    /// name exactly the accepted successor and the boundary promised above; a
    /// mismatch keeps the old epoch and faults this receiver rather than
    /// installing over bytes that were never acknowledged.
    pub fn install_renewal(
        &mut self,
        commit_frame: &[u8],
        next: ValidatedGrant,
        key: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<()> {
        let state = self
            .renewal
            .clone()
            .context("no renewal handshake to install")?;
        let opened = self.records.open_record(commit_frame)?;
        let commit = match opened {
            crate::fleet::auth::PeerRecord::Control { message, .. } => match message.body {
                crate::fleet::control::ControlBody::RenewCommit(c) => c,
                _ => anyhow::bail!("RENEW_COMMIT expected"),
            },
            _ => anyhow::bail!("RENEW_COMMIT expects a control frame"),
        };
        let result = (|| {
            ensure!(
                commit.generation == state.generation
                    && commit.next_authorization_id == state.next_authorization_id
                    && commit.next_key_epoch == state.next_key_epoch,
                "RENEW_COMMIT names a different successor"
            );
            ensure!(
                commit.drained_at == state.drained_at,
                "RENEW_COMMIT agreed a different boundary"
            );
            ensure!(
                next.grant().binding.authorization_id == state.next_authorization_id
                    && next.grant().binding.key_epoch == state.next_key_epoch,
                "install grant is not the accepted successor"
            );
            ensure!(
                self.ranges.contiguous() == state.drained_at,
                "coverage moved since the accept"
            );
            self.renew(next, key, t, a, b)
        })();
        match result {
            Ok(()) => {
                self.renewal = None;
                Ok(())
            }
            Err(e) => {
                self.revoke();
                Err(e)
            }
        }
    }
    /// Test-only: seal an arbitrary confirmation under the CURRENT epoch, so a
    /// negative case can be authenticated but semantically wrong. Never exposed
    /// in production, and it does not bypass any check on the way out.
    #[cfg(all(test, windows))]
    pub(crate) fn seal_committed_for_test(
        &mut self,
        body: crate::fleet::control::RenewCommitted,
    ) -> Result<Vec<u8>> {
        self.records
            .seal_control(crate::fleet::control::ControlBody::RenewCommitted(body))
    }
    /// Confirm, sealed under the NEW epoch, that the receiver is installed and
    /// the relay adopted the successor. The source waits for this before it
    /// resumes DATA, so the two hosts cannot race the relay's adoption.
    pub fn renew_committed_record(
        &mut self,
        next: &ValidatedGrant,
        generation: u64,
    ) -> Result<Vec<u8>> {
        ensure!(
            self.resume_base.is_none(),
            "resume receiver does not rotate its approved base"
        );
        ensure!(
            !self.faulted && self.snapshot.data_seal().is_none(),
            "flow receiver faulted or sealed"
        );
        ensure!(self.renewal.is_none(), "renewal handshake still open");
        ensure!(
            next.grant().binding.authorization_id
                == self.records.grant().grant().binding.authorization_id
                && next.grant().binding.key_epoch == self.records.grant().grant().binding.key_epoch,
            "RENEW_COMMITTED must describe the installed successor"
        );
        self.records
            .seal_control(crate::fleet::control::ControlBody::RenewCommitted(
                crate::fleet::control::RenewCommitted {
                    next_authorization_id: next.grant().binding.authorization_id,
                    next_key_epoch: next.grant().binding.key_epoch,
                    generation,
                },
            ))
    }
    /// Historical prefix re-read at THIS local admission, not network bytes.
    pub fn resumed_prefix(&self) -> Option<u64> {
        self.resume_base.as_ref().map(|p| p.prefix_bytes)
    }
    #[cfg(test)]
    pub(crate) fn test_seal_flow_control(
        &mut self,
        body: crate::fleet::control::ControlBody,
    ) -> Result<Vec<u8>> {
        self.records.seal_control(body)
    }
    pub fn resume_ready_record(&mut self, window_chunks: u8) -> Result<&[u8]> {
        let result = self.prepare_flow_control(Some(window_chunks), true);
        if result.is_err() {
            self.revoke();
        }
        result?;
        Ok(self.flow_ready.as_ref().context("resume READY missing")?)
    }
    pub fn resume_ack_record(&mut self) -> Result<&[u8]> {
        let result = self.prepare_flow_control(None, true);
        if result.is_err() {
            self.revoke();
        }
        result?;
        Ok(&self.flow_ack.as_ref().context("resume ACK missing")?.2)
    }
    pub fn ready_record(&mut self, window_chunks: u8) -> Result<&[u8]> {
        let result = self.prepare_flow_control(Some(window_chunks), false);
        if result.is_err() {
            self.revoke();
        }
        result?;
        Ok(self.flow_ready.as_ref().context("READY missing")?)
    }
    /// Cumulative in-memory coverage only. Unchanged counters return the same
    /// exact ciphertext. Holes cannot release SourceWindow's retained prefix.
    pub fn ack_record(&mut self) -> Result<&[u8]> {
        let result = self.prepare_flow_control(None, false);
        if result.is_err() {
            self.revoke();
        }
        result?;
        Ok(&self.flow_ack.as_ref().context("ACK missing")?.2)
    }
    fn prepare_flow_control(&mut self, ready: Option<u8>, resumed: bool) -> Result<()> {
        ensure!(
            self.resume_base.is_some() == resumed,
            "resume-base negotiation required: flow mode mismatch; ordinary and resume READY/ACK cannot substitute"
        );
        use crate::fleet::{
            control::{Ack, ControlBody, Ready},
            ranges::WINDOW,
        };
        ensure!(
            !self.faulted && self.snapshot.data_seal().is_none(),
            "flow receiver faulted or sealed"
        );
        let host = self.operation.host;
        let _gate = host
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        // Same non-waiting gate -> DB seam as final admission. Do not call
        // db.journal(): that resets busy_timeout and may open a write transaction.
        commit_admission::no_wait(host, |db| {
            let snapshot =
                crate::fleet::journal::Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .get(&JobKey::from_job(self.snapshot.job()))?
                    .context("flow job missing")?;
            let _parent = self.current_snapshot(db, &snapshot)?;
            self.records.receive_admission()?;
            if let Some(window_chunks) = ready {
                ensure!(
                    (1..=WINDOW as u8).contains(&window_chunks),
                    "invalid READY window"
                );
                match self.flow_window {
                    Some(old) => ensure!(old == window_chunks, "READY retry changes window"),
                    None => {
                        ensure!(
                            self.ranges.received() == self.resumed_prefix().unwrap_or(0)
                                && self.ranges.contiguous() == self.resumed_prefix().unwrap_or(0),
                            "READY needs valid window before DATA"
                        );
                        self.flow_window = Some(window_chunks);
                    }
                }
                if self.flow_ready.is_none() {
                    let chunk_bytes = self.records.grant().grant().chunk_bytes;
                    let body = match &self.resume_base {
                        Some(base) => {
                            ControlBody::ResumeReady(crate::fleet::control::ResumeReady {
                                base: base.as_ref().clone(),
                                chunk_bytes,
                                window_chunks,
                            })
                        }
                        None => ControlBody::Ready(Ready {
                            chunk_bytes,
                            window_chunks,
                        }),
                    };
                    let frame = self.records.seal_control(body)?;
                    self.flow_ready = Some(frame);
                }
            } else {
                ensure!(self.flow_window.is_some(), "ACK requires prior READY");
                let contiguous = self.ranges.contiguous();
                let received = self.ranges.received();
                if !self
                    .flow_ack
                    .as_ref()
                    .is_some_and(|(c, r, _)| *c == contiguous && *r == received)
                {
                    let frame = self.records.seal_control(ControlBody::Ack(Ack {
                        contiguous,
                        received,
                    }))?;
                    self.flow_ack = Some((contiguous, received, frame));
                }
            }
            self.records.receive_admission()?;
            Ok(())
        })
    }
    /// Only encrypted Source DATA accepted. Failure permanently faults this
    /// instance: a burned AEAD sequence must never become a false duplicate ACK.
    pub fn write_record(&mut self, encrypted: &[u8]) -> Result<Admission> {
        let mut written = 0u64;
        let admission = self.write_between(encrypted, |f, o, b, _| {
            f.seek(SeekFrom::Start(o))?;
            f.write_all(b)?;
            written = b.len() as u64;
            Ok(())
        })?;
        // Durability point per chunk is what makes a 64 KiB chunk cost ~23 ms on
        // NTFS. Grouping them cannot manufacture a receipt: sealing re-reads and
        // re-hashes the whole stage, and a crash loses only unsynced stage tail,
        // which leaves the stage (and its debt) with no target file.
        self.unsynced += written;
        if self.unsynced >= SYNC_EVERY {
            self.file.sync_data()?;
            self.unsynced = 0;
        }
        Ok(admission)
    }
    fn write_between(
        &mut self,
        encrypted: &[u8],
        write: impl FnOnce(&mut File, u64, &[u8], &mut LeasedRecords) -> Result<()>,
    ) -> Result<Admission> {
        let result = (|| {
            ensure!(
                !self.faulted && self.snapshot.data_seal().is_none(),
                "receiver faulted or DATA sealed"
            );
            let host = self.operation.host;
            let mut db = host
                .database
                .lock()
                .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
            let db = db.as_mut().context("host database closed")?;
            let _gate = host
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            let _parent = self.current(db)?;
            self.records.receive_admission()?;
            let opened = self.records.open_record(encrypted)?;
            let (header, bytes) = match opened {
                PeerRecord::Data { header, bytes } => (header, bytes),
                PeerRecord::Duplicate { header } => {
                    ensure!(header.kind == Kind::Data, "not a DATA duplicate");
                    self.records.receive_admission()?;
                    return Ok(Admission::Duplicate);
                }
                _ => anyhow::bail!("local writer accepts DATA only"),
            };
            let digest = Sha256::digest(bytes.as_slice()).into();
            let admission = self
                .ranges
                .validate(header.offset, bytes.len() as u32, &digest)?;
            if admission == Admission::Duplicate {
                self.records.receive_admission()?;
                return Ok(admission);
            }
            self.records.receive_admission()?;
            write(&mut self.file, header.offset, &bytes, &mut self.records)?;
            // Cannot preempt an OS write. Expiry here may leave dirty bytes but
            // never returns ACK; retain debt and fault, even if progress commits.
            self.records.receive_admission()?;
            self.ranges
                .record_written(header.offset, bytes.len() as u32, digest)?;
            let received = self.ranges.received();
            // Small transfers keep the exact per-chunk journal so their tests and
            // operators can observe each step; only a large transfer groups the
            // checkpoints, where per-chunk commits would dominate the run.
            let total = self.snapshot.job().bytes_total;
            if received == total
                || total <= PROGRESS_EVERY
                || received.saturating_sub(self.persisted) >= PROGRESS_EVERY
            {
                self.snapshot = db.journal()?.progress(
                    &JobKey::from_job(self.snapshot.job()),
                    self.snapshot.revision(),
                    received,
                )?;
                self.persisted = received;
            }
            self.records.receive_admission()?;
            Ok(admission)
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
}
