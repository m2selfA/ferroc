//! LOCAL commit admission with retained live owner; no publication or raw File.
//! fs_gate covers fresh full hashing through SQL commit. Never block on DB
//! mutex/SQLite writer while owning gate: inventory takes DB -> gate.
use super::*;
use crate::fleet::journal::Journal;
use std::sync::TryLockError;
#[cfg(windows)]
#[path = "owned_publish.rs"]
mod owned_publish;
#[cfg(windows)]
pub use owned_publish::{FinishedCandidate, ReceiptedCandidate, RenamedCandidate};

pub(super) fn no_wait<T>(
    host: &FleetHost<'_>,
    action: impl FnOnce(&mut FencedConnection) -> Result<T>,
) -> Result<T> {
    let mut guard = match host.database.try_lock() {
        Ok(g) => g,
        Err(TryLockError::WouldBlock) => {
            anyhow::bail!("commit database busy; gate never waits for DB")
        }
        Err(TryLockError::Poisoned(_)) => anyhow::bail!("host database poisoned"),
    };
    let db = guard.as_mut().context("host database closed")?;
    let old: i64 = db
        .connection
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))?;
    ensure!((0..=i32::MAX as i64).contains(&old), "invalid busy timeout");
    db.connection.busy_timeout(std::time::Duration::ZERO)?;
    let result = action(db);
    let restore = db
        .connection
        .busy_timeout(std::time::Duration::from_millis(old as u64));
    match (result, restore) {
        (r, Ok(())) => r,
        (r, Err(e)) => anyhow::bail!(
            "busy timeout restoration failed: {e}; operation={r:?}",
            r = r.err()
        ),
    }
}
/// Live v6 owner retaining the SAME File, leased records and host operation.
/// Not an immutable SHA snapshot, a publish permit or a persisted capability.
/// Drop closes File BEFORE draining the accepted operation, retaining all debt.
/// No constructor from Snapshot and no hidden re-open/adoption on recovery.
/// ```compile_fail
/// fn cannot_rebuild(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::host::receiver::CommitCandidate::from(s);}
/// ```
/// ```compile_fail
/// fn cannot_unwrap(c:ferroc::fleet::host::receiver::CommitCandidate<'_,'_>){let _=c.inner;}
/// ```
/// ```compile_fail
/// fn cannot_write(c:&mut ferroc::fleet::host::receiver::CommitCandidate<'_,'_>){c.write_record(&[]).unwrap();}
/// ```
/// ```compile_fail
/// fn cannot_publish(c:ferroc::fleet::host::receiver::CommitCandidate<'_,'_>){c.publish().unwrap();}
/// ```
/// ```compile_fail
/// fn cannot_clone(c:ferroc::fleet::host::receiver::CommitCandidate<'_,'_>){let _=c.clone();}
/// ```
/// ```compile_fail
/// fn cannot_restore_json(){let _=serde_json::from_str::<ferroc::fleet::host::receiver::CommitCandidate<'_,'_>>("{}");}
/// ```
/// ```compile_fail
/// fn cannot_outlive_host<'r>(r:&'r ferroc::runtime::Runtime,p:&std::path::Path,records:ferroc::fleet::lease::LeasedRecords)->ferroc::fleet::host::receiver::CommitCandidate<'static,'r>{let h=r.open_fleet_host(p,ferroc::fleet::inventory::InventoryLimits::default()).unwrap();h.resume().unwrap();h.admit_receiver(records).unwrap().seal_finish(&[]).unwrap().prepare_commit().unwrap()}
/// ```
pub struct CommitCandidate<'h, 'r> {
    inner: SealedReceiver<'h, 'r>,
}
impl CommitCandidate<'_, '_> {
    #[cfg(test)]
    pub(super) fn test_expire(&mut self) {
        self.inner.inner.records.test_expire();
    }
    #[cfg(test)]
    pub(super) fn observe_between(
        &mut self,
        mut f: impl FnMut(u64) -> Result<()>,
    ) -> Result<ReadbackObservation> {
        self.inner.inner.read_sequence_between(|o, _| f(o))
    }

    pub fn snapshot(&self) -> &Snapshot {
        self.inner.snapshot()
    }
    /// Same non-coherent read-sequence observation as sealed receiver, under
    /// live lease/current Committing revision. Never a final publishing check.
    pub fn observe(&mut self) -> Result<ReadbackObservation> {
        self.inner.observe()
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

impl<'h, 'r> SealedReceiver<'h, 'r> {
    /// Keep the original live lease/File/host operation. No publication or resume.
    pub fn prepare_commit(self) -> Result<CommitCandidate<'h, 'r>> {
        self.prepare_between(|_, _| Ok(()), |_| Ok(()))
    }

    /// Consume a live sealed receiver, freshly hash under Runtime's actual gate,
    /// and durably reserve intent. Snapshot is DESCRIPTIVE only: bytes can change
    /// after return. Future publication must REHASH/revalidate in its own gate.
    /// No claim against mmap/external processes/shell or filesystem power loss.
    /// Errors may follow a successful SQL COMMIT; inspect, never auto-retry/resume.
    /// ```compile_fail
    /// fn intent_is_not_publishable(s:ferroc::fleet::journal::Snapshot){s.publish_with(||Ok(())).unwrap();}
    /// ```
    pub fn reserve_commit(self) -> Result<Snapshot> {
        self.reserve_between(|_, _| Ok(()), |_| Ok(()))
    }
    pub(super) fn reserve_between(
        self,
        between: impl FnMut(u64, &mut Self) -> Result<()>,
        after: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<Snapshot> {
        Ok(self.prepare_between(between, after)?.snapshot().clone())
    }
    pub(super) fn prepare_between(
        mut self,
        mut between: impl FnMut(u64, &mut Self) -> Result<()>,
        after: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<CommitCandidate<'h, 'r>> {
        let result = (|| {
            ensure!(
                !self.inner.faulted
                    && self.inner.ranges.complete()
                    && self.snapshot().data_seal().is_some()
                    && self.snapshot().intent().is_none(),
                "invalid sealed commit admission"
            );
            self.inner.records.receive_admission()?;
            let host = self.inner.operation.host;
            // No DB held while waiting for gate, hashing or running between().
            let _gate = host
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            let key = JobKey::from_job(self.snapshot().job());
            let check = |this: &mut Self| {
                no_wait(host, |db| {
                    let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .get(&key)?
                        .context("commit job missing")?;
                    this.inner.current_snapshot(db, &s)
                })
            };
            let total = self.snapshot().job().bytes_total;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = [0u8; 65536];
            self.inner.file.seek(SeekFrom::Start(0))?;
            loop {
                let _parent = check(&mut self)?;
                self.inner.records.receive_admission()?;
                ensure!(
                    self.inner.file.metadata()?.len() == total,
                    "commit stage size changed"
                );
                let n = self.inner.file.read(&mut buffer)?;
                self.inner.records.receive_admission()?;
                if n == 0 {
                    break;
                }
                offset = offset
                    .checked_add(n as u64)
                    .context("commit read size overflow")?;
                ensure!(offset <= total, "commit stage exceeds task");
                hash.update(&buffer[..n]);
                between(offset, &mut self)?;
            }
            let actual: [u8; 32] = hash.finalize().into();
            ensure!(
                offset == total && actual == self.snapshot().job().sha256,
                "stable Runtime-gate SHA256 mismatch"
            );
            self.inner.file.sync_data()?;
            self.inner.records.receive_admission()?;
            no_wait(host, |db| {
                let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .get(&key)?
                    .context("commit job missing")?;
                let _parent = self.inner.current_snapshot(db, &s)?;
                self.inner.records.receive_admission()?;
                ensure!(
                    self.inner.file.metadata()?.len() == total,
                    "commit final size changed"
                );
                let binding = self.inner.records.grant().grant().binding.clone();
                self.inner.snapshot = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .reserve_sealed_commit(&key, s.revision(), binding)?;
                self.inner.records.receive_admission()?;
                Ok(())
            })?;
            // Deliberately after DB release but before gate release: cancellation
            // may now settle as CommitUnknown, never erase durable intent.
            after(&mut self)?;
            let _parent = check(&mut self)?;
            self.inner.records.receive_admission()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(CommitCandidate { inner: self }),
            Err(error) => {
                self.inner.revoke();
                Err(error)
            }
        }
    }
}
