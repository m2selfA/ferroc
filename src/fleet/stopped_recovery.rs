//! Explicit LOCAL single-row stopped-owner takeover. Metadata only: no file,
//! dual-proof lease, migration, coverage restoration, publication or debt relief.
use super::*;
impl Journal<'_> {
    pub(crate) fn recover_retained_job(
        &mut self,
        key: &JobKey,
        stopped: Uuid,
        revision: u64,
    ) -> Result<Snapshot> {
        self.check_owner()?;
        ensure!(
            !stopped.is_nil() && stopped != self.owner,
            "invalid stopped owner"
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut s = Self::load(&tx, key)?.context("selected recovery job missing")?;
        ensure!(
            s.owner == stopped
                && s.revision == revision
                && matches!(s.phase, Phase::Transferring | Phase::Interrupted)
                && s.data_seal().is_none()
                && s.intent().is_none()
                && s.receipt().is_none()
                && !s.is_migrated_origin()
                && s.migration_origin().is_none(),
            "selected recovery row changed or is not precommit"
        );
        let retained = s
            .retained_stage()
            .context("selected recovery needs retained opt-in")?;
        ensure!(
            retained.checkpoint().is_some(),
            "selected recovery needs persisted checkpoint"
        );
        let allocation = s
            .stage()
            .and_then(|r| r.allocation())
            .context("selected recovery stage missing")?;
        ensure!(
            !allocation.is_anonymous()
                && allocation.original_owner() != self.owner
                && retained.original_owner() == allocation.original_owner(),
            "selected recovery needs stopped retained allocation"
        );
        let fence = self
            .fence
            .context("selected recovery requires native fence")?;
        ensure!(
            allocation.database_id() == Some(fence.database_id())
                && allocation.database_parent_id() == Some(fence.database_parent_id()?.as_str()),
            "selected recovery database domain mismatch"
        );
        s.owner = self.owner;
        s.phase = Phase::Interrupted;
        s.revision = s
            .revision
            .checked_add(1)
            .context("recovery revision overflow")?;
        Self::save(&tx, key, revision, &s)?;
        tx.commit()?;
        Ok(s)
    }
}
