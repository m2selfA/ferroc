//! Local lease-gated DATA writer only. No listener, publication or resume.
//! v4 receive intent precedes IO. Drop closes File then drains the host permit;
//! it NEVER deletes a stage or releases persistent reservations.
#[path = "commit_admission.rs"]
mod commit_admission;
pub use commit_admission::CommitCandidate;
#[cfg(windows)]
pub use commit_admission::{FinishedCandidate, ReceiptedCandidate, RenamedCandidate};
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
pub struct HostReceiver<'h, 'r> {
    file: File,
    records: LeasedRecords,
    ranges: ReceiveRanges,
    snapshot: Snapshot,
    faulted: bool,
    published: bool,
    flow_window: Option<u8>,
    flow_ready: Option<Vec<u8>>,
    flow_ack: Option<(u64, u64, Vec<u8>)>,
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
    let observed = file_id(file)?;
    ensure!(
        a.file_id() == Some(observed.as_str())
            && file_id(&open_stage(if published { &dest } else { r.path() })?)? == observed
            && file.metadata()?.len() <= s.job().bytes_total,
        "receive file object/size changed"
    );
    Ok(parent)
}
impl<'r> FleetHost<'r> {
    /// Explicit LOCAL slice. Job comes ONLY from authenticated Target records;
    /// never recreate/reopen on replay. Failure preserves any admitted obligation.
    pub fn admit_receiver<'h>(
        &'h self,
        mut records: LeasedRecords,
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
        let reserved = db.reserve_stage(
            &key,
            s.revision(),
            &self.attachment.runtime.policy,
            self.gate.clone(),
            self.limits,
        )?;
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
            snapshot,
            faulted: false,
            published: false,
            flow_window: None,
            flow_ready: None,
            flow_ack: None,
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
                && s.target_observation() == self.snapshot.target_observation(),
            "receiver cancelled/stale"
        );
        check_stage(db, s, &self.file, self.operation.host, self.published)
    }
    /// P1 initial-epoch flow READY. Exact cached bytes, never a fresh nonce on
    /// retry. This is live admission, not a proof of final target completion.
    /// Renewal is allowed after READY only at an acknowledged boundary; cached
    /// control ciphertext is dropped and re-sealed under the current epoch.
    pub fn ready_record(&mut self, window_chunks: u8) -> Result<&[u8]> {
        let result = self.prepare_flow_control(Some(window_chunks));
        if result.is_err() {
            self.revoke();
        }
        result?;
        Ok(self.flow_ready.as_ref().context("READY missing")?)
    }
    /// Cumulative in-memory coverage only. Unchanged counters return the same
    /// exact ciphertext. Holes cannot release SourceWindow's retained prefix.
    pub fn ack_record(&mut self) -> Result<&[u8]> {
        let result = self.prepare_flow_control(None);
        if result.is_err() {
            self.revoke();
        }
        result?;
        Ok(&self.flow_ack.as_ref().context("ACK missing")?.2)
    }
    fn prepare_flow_control(&mut self, ready: Option<u8>) -> Result<()> {
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
                            self.ranges.received() == 0,
                            "READY needs valid window before DATA"
                        );
                        self.flow_window = Some(window_chunks);
                    }
                }
                if self.flow_ready.is_none() {
                    let frame = self.records.seal_control(ControlBody::Ready(Ready {
                        chunk_bytes: self.records.grant().grant().chunk_bytes,
                        window_chunks,
                    }))?;
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
        self.write_between(encrypted, |f, o, b, _| {
            f.seek(SeekFrom::Start(o))?;
            f.write_all(b)?;
            f.sync_data()?;
            Ok(())
        })
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
            self.snapshot = db.journal()?.progress(
                &JobKey::from_job(self.snapshot.job()),
                self.snapshot.revision(),
                self.ranges.received(),
            )?;
            self.records.receive_admission()?;
            Ok(admission)
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
}
