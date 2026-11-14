//! Historical v8 observations; a separate child owns explicit v9 settlement.
use super::*;
use crate::fleet::fence::directory_id;
#[path = "settlement.rs"]
mod settlement;
pub use settlement::FinishedCandidate;

/// Live owner after a durable v8 target observation. Unknown and ALL stage debt
/// remain. This is NOT the final control::Receipt, COMMIT_ACK, or restart permit.
/// File/parent close before the same accepted host operation drains.
/// ```compile_fail
/// fn cannot_rebuild(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::host::receiver::ReceiptedCandidate::from(s);}
/// ```
/// ```compile_fail
/// fn cannot_clone(c:ferroc::fleet::host::receiver::ReceiptedCandidate<'_,'_>){let _=c.clone();}
/// ```
/// ```compile_fail
/// fn cannot_finalize(c:ferroc::fleet::host::receiver::ReceiptedCandidate<'_,'_>){c.publish().unwrap();}
/// ```
/// ```compile_fail
/// fn cannot_ack(c:ferroc::fleet::host::receiver::ReceiptedCandidate<'_,'_>){c.commit_ack().unwrap();}
/// ```
/// ```compile_fail
/// fn cannot_rebuild_receipt(r:ferroc::fleet::journal::TargetObservationReceipt){let _=ferroc::fleet::host::receiver::ReceiptedCandidate::from(r);}
/// ```
pub struct ReceiptedCandidate<'h, 'r> {
    inner: RenamedCandidate<'h, 'r>,
}
impl ReceiptedCandidate<'_, '_> {
    pub fn snapshot(&self) -> &Snapshot {
        self.inner.snapshot()
    }
    pub fn observation(&self) -> &crate::fleet::journal::TargetObservationReceipt {
        self.snapshot()
            .target_observation()
            .expect("private v8 owner invariant")
    }
    pub fn observe(&mut self) -> Result<ReadbackObservation> {
        self.inner.observe()
    }
    pub fn revoke(&mut self) {
        self.inner.revoke();
    }
    pub fn renew(
        &mut self,
        g: ValidatedGrant,
        k: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<()> {
        self.inner.renew(g, k, t, a, b)
    }
}
impl<'h, 'r> RenamedCandidate<'h, 'r> {
    /// Rehash the SAME live File under Runtime gate; persist a separate LOCAL
    /// observation in v8. No final Receipt, debt release, COMMIT_ACK or recovery.
    /// SQL errors/cancel/expiry can follow durable COMMIT: never retry/delete or
    /// pretend rollback. Parent directory durability is explicitly Unsupported.
    pub fn record_target_observation(self) -> Result<ReceiptedCandidate<'h, 'r>> {
        self.receipt_between(|_, _| Ok(()), |_| Ok(()), |_| Ok(()))
    }
    pub(in super::super::super) fn receipt_between(
        mut self,
        mut between: impl FnMut(u64, &mut Self) -> Result<()>,
        before_sql: impl FnOnce(&mut Self) -> Result<()>,
        after_sql: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<ReceiptedCandidate<'h, 'r>> {
        let result = (|| {
            let h = self.inner.inner.inner.operation.host;
            ensure!(
                !self.inner.inner.inner.faulted
                    && self.inner.inner.inner.published
                    && self.snapshot().target_observation().is_none(),
                "not a fresh live renamed owner"
            );
            let _gate = h
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            let key = JobKey::from_job(self.snapshot().job());
            let check = |this: &mut Self| {
                no_wait(h, |db| {
                    let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .get(&key)?
                        .context("target receipt job missing")?;
                    let p = this.inner.inner.inner.current_snapshot(db, &s)?;
                    ensure!(
                        directory_id(&p)? == directory_id(&this._parent)?,
                        "target receipt parent changed"
                    );
                    this.inner.inner.inner.records.receive_admission()?;
                    Ok(())
                })
            };
            check(&mut self)?;
            let total = self.snapshot().job().bytes_total;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = [0u8; 65536];
            self.inner.inner.inner.file.seek(SeekFrom::Start(0))?;
            loop {
                check(&mut self)?;
                ensure!(
                    self.inner.inner.inner.file.metadata()?.len() == total,
                    "target receipt size changed"
                );
                let n = self.inner.inner.inner.file.read(&mut buffer)?;
                self.inner.inner.inner.records.receive_admission()?;
                if n == 0 {
                    break;
                }
                offset = offset
                    .checked_add(n as u64)
                    .context("target receipt overflow")?;
                ensure!(offset <= total, "target receipt exceeds task");
                hash.update(&buffer[..n]);
                between(offset, &mut self)?;
            }
            let actual: [u8; 32] = hash.finalize().into();
            ensure!(
                offset == total && actual == self.snapshot().job().sha256,
                "target receipt Runtime-gate SHA256 mismatch"
            );
            self.inner.inner.inner.file.sync_all()?;
            before_sql(&mut self)?;
            no_wait(h, |db| {
                let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .get(&key)?
                    .context("target receipt job missing")?;
                let parent = self.inner.inner.inner.current_snapshot(db, &s)?;
                ensure!(
                    directory_id(&parent)? == directory_id(&self._parent)?
                        && self.inner.inner.inner.file.metadata()?.len() == total,
                    "target receipt final object/size changed"
                );
                self.inner.inner.inner.records.receive_admission()?;
                let binding = self
                    .inner
                    .inner
                    .inner
                    .records
                    .grant()
                    .grant()
                    .binding
                    .clone();
                let id = file_id(&self.inner.inner.inner.file)?;
                let parent_id = directory_id(&parent)?;
                self.inner.inner.inner.snapshot =
                    Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .record_target_observation(&key, s.revision(), binding, id, parent_id)?;
                self.inner.inner.inner.records.receive_admission()?;
                Ok(())
            })?;
            after_sql(&mut self)?;
            check(&mut self)?;
            ensure!(
                self.inner.inner.inner.file.metadata()?.len() == total,
                "target receipt final size changed"
            );
            Ok(())
        })();
        match result {
            Ok(()) => Ok(ReceiptedCandidate { inner: self }),
            Err(e) => {
                self.revoke();
                Err(e)
            }
        }
    }
}
