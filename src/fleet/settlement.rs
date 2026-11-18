//! LOCAL Windows settlement/encoded ACK component, not a network sender/P1.
use super::*;
use crate::fleet::{
    control::{ControlBody, Receipt},
    fence::directory_id,
};
/// Only created by successful live settlement. No write/rename/resume/rehydrate.
/// Receipt and encoded ACK describe a historical completion, not current bytes
/// or power-loss safety. Original File/parent stay held until this owner drops.
/// ```compile_fail
/// fn no_restore(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::host::receiver::FinishedCandidate::from(s);}
/// ```
/// ```compile_fail
/// fn no_restore_receipt(r:ferroc::fleet::control::Receipt){let _=ferroc::fleet::host::receiver::FinishedCandidate::from(r);}
/// ```
/// ```compile_fail
/// fn no_clone(c:ferroc::fleet::host::receiver::FinishedCandidate<'_,'_>){let _=c.clone();}
/// ```
/// ```compile_fail
/// fn no_file(c:ferroc::fleet::host::receiver::FinishedCandidate<'_,'_>){let _=c.inner;}
/// ```
/// ```compile_fail
/// fn no_write(c:ferroc::fleet::host::receiver::FinishedCandidate<'_,'_>){c.write_record(&[]).unwrap();}
/// ```
/// ```compile_fail
/// fn no_second_settlement(c:ferroc::fleet::host::receiver::FinishedCandidate<'_,'_>){c.settle_local().unwrap();}
/// ```
pub struct FinishedCandidate<'h, 'r> {
    inner: ReceiptedCandidate<'h, 'r>,
    ack: Vec<u8>,
}
impl FinishedCandidate<'_, '_> {
    pub fn snapshot(&self) -> &Snapshot {
        self.inner.snapshot()
    }
    pub fn receipt(&self) -> &Receipt {
        self.snapshot()
            .receipt()
            .expect("private settled owner invariant")
    }
    /// The ONE frame already encoded under the settlement gate. No socket,
    /// fresh encryption, current-byte assertion or restart reconstruction.
    /// Re-sending these exact bytes is an authenticated Duplicate, not a new ACK.
    pub fn local_commit_ack(&self) -> &[u8] {
        &self.ack
    }
}
impl<'h, 'r> ReceiptedCandidate<'h, 'r> {
    #[cfg(all(test, windows))]
    pub(in super::super::super::super) fn test_expire(&mut self) {
        self.inner.test_expire()
    }
    #[cfg(all(test, windows))]
    pub(in super::super::super::super) fn test_move(&self, p: &Path) -> Result<()> {
        self.inner.test_move(p)
    }
    /// Explicit LOCAL settlement: full fresh target hash/lease/object checks,
    /// atomically archive allocation origin + final receipt and remove LIVE stage
    /// debt. Unsupported directory durability remains explicit. SQL commit may
    /// precede error: an error is NOT proof that receipt/debt transition rolled
    /// back. Failed consuming owners revoke/close, never retry/delete/adopt.
    pub fn settle_local(self) -> Result<FinishedCandidate<'h, 'r>> {
        self.settle_between(|_, _| Ok(()), |_| Ok(()), |_| Ok(()))
    }
    pub(in super::super::super::super) fn settle_between(
        mut self,
        mut between: impl FnMut(u64, &mut Self) -> Result<()>,
        before_sql: impl FnOnce(&mut Self) -> Result<()>,
        after_sql: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<FinishedCandidate<'h, 'r>> {
        let result = (|| {
            ensure!(
                self.snapshot().target_observation().is_some()
                    && self.snapshot().receipt().is_none()
                    && !self.inner.inner.inner.inner.faulted,
                "not a fresh live observed target"
            );
            let h = self.inner.inner.inner.inner.operation.host;
            let original = self.snapshot().clone();
            let _gate = h
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            let key = JobKey::from_job(original.job());
            let check = |this: &mut Self, completed: bool| {
                no_wait(h, |db| {
                    let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .get(&key)?
                        .context("settlement job missing")?;
                    let parent = if completed {
                        ensure!(
                            s.phase() == Phase::Completed
                                && s.revision() == this.snapshot().revision()
                                && s.owner() == this.snapshot().owner()
                                && s.receipt() == this.snapshot().receipt()
                                && s.stage().is_none()
                                && s.settlement_origin() == original.stage()
                                && s.settlement_binding() == this.snapshot().settlement_binding()
                                && s.job().digest()? == original.job().digest()?
                                && s.target_observation() == original.target_observation(),
                            "settlement stale after SQL"
                        );
                        // Original descriptor is still LIVE; historical metadata is
                        // used only to check that descriptor, never to recover one.
                        crate::fleet::host::receiver::check_stage(
                            db,
                            &original,
                            &this.inner.inner.inner.inner.file,
                            h,
                            true,
                        )?
                    } else {
                        this.inner.inner.inner.inner.current_snapshot(db, &s)?
                    };
                    ensure!(
                        directory_id(&parent)? == directory_id(&this.inner._parent)?,
                        "settlement parent changed"
                    );
                    this.inner.inner.inner.inner.records.receive_admission()?;
                    Ok(())
                })
            };
            check(&mut self, false)?;
            let total = original.job().bytes_total;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = [0u8; 65536];
            self.inner.inner.inner.inner.file.seek(SeekFrom::Start(0))?;
            loop {
                check(&mut self, false)?;
                ensure!(
                    self.inner.inner.inner.inner.file.metadata()?.len() == total,
                    "settlement size changed"
                );
                let n = self.inner.inner.inner.inner.file.read(&mut buffer)?;
                self.inner.inner.inner.inner.records.receive_admission()?;
                if n == 0 {
                    break;
                }
                offset = offset
                    .checked_add(n as u64)
                    .context("settlement read overflow")?;
                ensure!(offset <= total, "settlement exceeds task");
                hash.update(&buffer[..n]);
                between(offset, &mut self)?;
            }
            let actual: [u8; 32] = hash.finalize().into();
            ensure!(
                offset == total && actual == original.job().sha256,
                "settlement Runtime-gate SHA256 mismatch"
            );
            self.inner.inner.inner.inner.file.sync_all()?;
            before_sql(&mut self)?;
            no_wait(h, |db| {
                let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .get(&key)?
                    .context("settlement job missing")?;
                let parent = self.inner.inner.inner.inner.current_snapshot(db, &s)?;
                ensure!(
                    directory_id(&parent)? == directory_id(&self.inner._parent)?
                        && self.inner.inner.inner.inner.file.metadata()?.len() == total,
                    "settlement final object/size changed"
                );
                self.inner.inner.inner.inner.records.receive_admission()?;
                let binding = self
                    .inner
                    .inner
                    .inner
                    .inner
                    .records
                    .grant()
                    .grant()
                    .binding
                    .clone();
                let file = file_id(&self.inner.inner.inner.inner.file)?;
                let parent = directory_id(&parent)?;
                self.inner.inner.inner.inner.snapshot = Journal::existing_fenced(
                    &mut db.connection,
                    &db.fence,
                )?
                .settle_live_target(&key, s.revision(), binding, file, parent)?;
                self.inner.inner.inner.inner.records.receive_admission()?;
                Ok(())
            })?;
            after_sql(&mut self)?;
            check(&mut self, true)?;
            ensure!(
                self.inner.inner.inner.inner.file.metadata()?.len() == total,
                "settlement final size changed"
            );
            let receipt = self
                .snapshot()
                .receipt()
                .context("settlement receipt missing")?
                .clone();
            let frame = self
                .inner
                .inner
                .inner
                .inner
                .records
                .seal_control(ControlBody::CommitAck(receipt))?;
            check(&mut self, true)?;
            ensure!(
                self.inner.inner.inner.inner.file.metadata()?.len() == total,
                "settlement ACK final size changed"
            );
            Ok(frame)
        })();
        match result {
            Ok(ack) => Ok(FinishedCandidate { inner: self, ack }),
            Err(e) => {
                self.revoke();
                Err(e)
            }
        }
    }
}
