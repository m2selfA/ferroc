//! Explicit live-only retained format. Never constructs a receiver from metadata.
use super::*;
use crate::fleet::journal::{Journal, PrefixCheckpoint};
impl HostReceiver<'_, '_> {
    /// Opt into schema12 on the SAME freshly admitted named File, BEFORE DATA.
    /// No new file, remote approval, resume writer or checkpoint is created.
    /// Failure faults the live receiver; committed metadata/debt is never undone.
    pub fn enable_retained_checkpoints(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.faulted
                    && self.ranges.received() == 0
                    && self.snapshot.received() == 0
                    && self.snapshot.data_seal().is_none()
                    && self.snapshot.intent().is_none()
                    && self.snapshot.phase() == Phase::Transferring
                    && self.snapshot.retained_stage().is_none(),
                "retained opt-in must precede DATA"
            );
            let a = self
                .snapshot
                .stage()
                .and_then(|s| s.allocation())
                .context("retained allocation missing")?;
            ensure!(
                !a.is_anonymous(),
                "anonymous stage cannot enable retained checkpoints"
            );
            let host = self.operation.host;
            let _gate = host
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            self.records.receive_admission()?;
            let key = JobKey::from_job(self.snapshot.job());
            commit_admission::no_wait(host, |db| {
                let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .get(&key)?
                    .context("retained job missing")?;
                let _parent = self.current_snapshot(db, &s)?;
                self.records.receive_admission()?;
                ensure!(
                    self.file.metadata()?.len() == 0,
                    "retained opt-in needs empty original stage"
                );
                self.records.receive_admission()?;
                self.snapshot = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .enable_retained(
                        &key,
                        s.revision(),
                        self.records.grant().grant().binding.clone(),
                    )?;
                self.records.receive_admission()?;
                let _parent = self.current_snapshot(db, &self.snapshot)?;
                self.records.receive_admission()?;
                Ok(())
            })
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
    /// Persist descriptive prefix metadata in the SAME gate as fresh sync/hash.
    /// No cached SyncedPrefixObservation input is accepted. The metadata is not
    /// a stable-byte guarantee, restart IO authority or permission to release debt.
    /// An error after SQL COMMIT may leave a checkpoint; never blindly retry.
    pub fn capture_retained_checkpoint(&mut self) -> Result<PrefixCheckpoint> {
        self.checkpoint_after_commit(|_| Ok(()))
    }
    pub(super) fn checkpoint_after_commit(
        &mut self,
        after_commit: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<PrefixCheckpoint> {
        if self.snapshot.retained_stage().is_none() {
            self.revoke();
            anyhow::bail!("retained checkpoint opt-in missing");
        }
        self.prefix_action(
            |_, _| Ok(()),
            |this, observed| {
                this.records.receive_admission()?;
                this.file.sync_data()?;
                this.records.receive_admission()?;
                let host = this.operation.host;
                let key = JobKey::from_job(this.snapshot.job());
                commit_admission::no_wait(host, |db| {
                    let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .get(&key)?
                        .context("checkpoint job missing")?;
                    let _parent = this.current_snapshot(db, &s)?;
                    this.records.receive_admission()?;
                    ensure!(
                        this.file.metadata()?.len() == observed.stage_length(),
                        "checkpoint stage length changed after hash"
                    );
                    this.records.receive_admission()?;
                    this.snapshot = Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .record_prefix(
                            &key,
                            s.revision(),
                            observed.bytes(),
                            observed.sha256(),
                            observed.grant_digest(),
                            this.records.grant().grant().binding.clone(),
                        )?;
                    after_commit(this)?;
                    this.records.receive_admission()?;
                    let _parent = this.current_snapshot(db, &this.snapshot)?;
                    ensure!(
                        this.file.metadata()?.len() == observed.stage_length(),
                        "checkpoint stage length changed after SQL"
                    );
                    this.records.receive_admission()?;
                    Ok(this
                        .snapshot
                        .retained_stage()
                        .and_then(|s| s.checkpoint())
                        .context("committed checkpoint missing")?
                        .clone())
                })
            },
        )
    }
}
