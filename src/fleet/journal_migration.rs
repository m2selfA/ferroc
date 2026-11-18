//! Schema13 atomic metadata handoff. No File, receiver, coverage or IO permission.
//! One explicit lineage only. The future live admission must consume a freshly
//! approved dual-signed session and recheck File/parent/prefix under the gate.
use super::*;
use crate::fleet::{
    job::{FileGrant, LeaseProfile, ValidatedGrant},
    resume_condition::ResumeProposal,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationLink {
    version: u16,
    transaction: Uuid,
    owner: Uuid,
    old_revision: u64,
    old_job: JobSpec,
    new_job: JobSpec,
    next: FileGrant,
    origin: StageReference,
    checkpoint: PrefixCheckpoint,
    condition_digest: [u8; 32],
}
impl MigrationLink {
    pub(super) fn origin(&self) -> &StageReference {
        &self.origin
    }
    pub(super) fn validate(&self, s: &Snapshot) -> Result<()> {
        self.origin.validate()?;
        let a = self
            .origin
            .allocation()
            .context("migration origin allocation missing")?;
        let next = self
            .next
            .clone()
            .validate_for_profile(self.new_job.clone(), LeaseProfile::SingleOwner)?;
        let condition = ResumeProposal::build(&self.old_job, &self.checkpoint, &next)?;
        ensure!(
            self.version == 1
                && !self.transaction.is_nil()
                && !self.owner.is_nil()
                && self.owner != a.original_owner()
                && !a.is_anonymous()
                && a.file_id().is_some()
                && a.database_id().is_some()
                && a.database_parent_id().is_some()
                && self.origin.reserved_bytes() == self.old_job.bytes_total
                && self.old_revision > self.checkpoint.revision()
                && self.old_revision < i64::MAX as u64
                && condition.digest() == self.condition_digest,
            "invalid migration origin/condition"
        );
        let state = s
            .retained_stage()
            .context("migration retained state missing")?;
        if s.version == 10 {
            ensure!(
                s.job().digest()? == self.old_job.digest()?
                    && s.owner() == self.owner
                    && s.revision() == self.old_revision + 1
                    && s.phase() == Phase::Interrupted
                    && s.stage().is_none()
                    && s.received() <= s.job().bytes_total
                    && !s.verified
                    && s.intent.is_none()
                    && s.receipt.is_none()
                    && s.absence_release.is_none()
                    && s.data_seal.is_none()
                    && s.intent_binding.is_none()
                    && s.target_observation.is_none()
                    && s.settlement_origin.is_none()
                    && s.settlement_binding.is_none()
                    && state.checkpoint() == Some(&self.checkpoint),
                "invalid migrated origin history"
            );
        } else {
            ensure!(
                matches!(s.version, 4..=9) && s.job().digest()? == self.new_job.digest()?,
                "invalid migration successor"
            );
            let live = s
                .provenance_stage()
                .context("migration successor obligation missing")?;
            let mut expected = self.origin.clone();
            expected
                .allocation
                .as_mut()
                .context("origin allocation missing")?
                .owner = self.owner;
            ensure!(
                *live == expected && state.original_owner() == self.owner,
                "migration successor differs from original allocation"
            );
        }
        Ok(())
    }
    pub(super) fn check_pair(c: &Connection, s: &Snapshot) -> Result<()> {
        let Some(link) = s.retained.as_ref().and_then(|r| r.migration.as_ref()) else {
            return Ok(());
        };
        let old = s.version == 10;
        let peer = Journal::load_one(
            c,
            &JobKey::from_job(if old { &link.new_job } else { &link.old_job }),
        )?
        .context("migration peer missing")?;
        ensure!((peer.version == 10) != old, "migration peer role mismatch");
        let other = peer
            .retained
            .as_ref()
            .and_then(|r| r.migration.as_ref())
            .context("migration backlink missing")?;
        ensure!(other == link, "migration reciprocal link mismatch");
        Ok(())
    }
}
impl Snapshot {
    /// Historical metadata only; not a live stage location, cleanup or IO right.
    pub fn migration_origin(&self) -> Option<&StageReference> {
        self.retained
            .as_ref()?
            .migration
            .as_ref()
            .map(|m| m.origin())
    }
    pub fn is_migrated_origin(&self) -> bool {
        self.version == 10
    }
}
impl Journal<'_> {
    /// Private metadata transition AFTER actual dual-proof/lease/File admission.
    /// Not a standalone IO permission or reconstructible coverage token.
    pub(in crate::fleet) fn begin_migrated_receive(
        &mut self,
        key: &JobKey,
        revision: u64,
        next: &ValidatedGrant,
        proposal: &ResumeProposal,
    ) -> Result<Snapshot> {
        let owner = self.owner;
        self.change(key, revision, |s, _| {
            ensure!(
                s.version == 4
                    && s.phase == Phase::Interrupted
                    && s.received == 0
                    && s.owner == owner
                    && !s.verified
                    && s.intent.is_none()
                    && s.receipt.is_none()
                    && s.data_seal.is_none(),
                "not an untouched migrated successor"
            );
            let link = s
                .retained
                .as_ref()
                .and_then(|r| r.migration.as_ref())
                .context("migration lineage missing")?;
            ensure!(
                link.owner == owner
                    && s.job() == next.job()
                    && link.next == *next.grant()
                    && link.condition_digest == proposal.digest()
                    && ResumeProposal::build(&link.old_job, &link.checkpoint, next)?
                        .canonical_bytes()
                        == proposal.canonical_bytes(),
                "migration live condition mismatch"
            );
            s.received = proposal.prefix_bytes();
            s.phase = Phase::Transferring;
            Ok(())
        })
    }

    /// Crate-internal METADATA primitive. It deliberately does not authenticate a
    /// peer, read the File or return an IO owner. No public/Runtime/tool caller.
    /// Failure after COMMIT is not rollback or automatic retry permission.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::fleet) fn migrate_retained_reference(
        &mut self,
        key: &JobKey,
        revision: u64,
        next: &ValidatedGrant,
        proposal: &ResumeProposal,
        now_ms: u64,
    ) -> Result<(Snapshot, Snapshot)> {
        self.check_owner()?;
        let fence = self.fence.context("migration requires native fence")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut old = Self::load(&tx, key)?.context("migration job missing")?;
        ensure!(
            old.version == 4
                && old.phase == Phase::Interrupted
                && old.owner == self.owner
                && old.revision == revision,
            "migration needs exact recovered precommit row"
        );
        let state = old.retained.as_ref().context("retained opt-in missing")?;
        ensure!(
            state.migration.is_none(),
            "repeated migration lineage unsupported"
        );
        let cp = state
            .checkpoint()
            .context("durable checkpoint missing")?
            .clone();
        let actual = ResumeProposal::build(old.job(), &cp, next)?;
        ensure!(
            actual.canonical_bytes() == proposal.canonical_bytes()
                && actual.digest() == proposal.digest(),
            "migration condition differs from current checkpoint"
        );
        ensure!(
            next.grant().issued_at_ms <= now_ms
                && now_ms < next.grant().expires_at_ms
                && now_ms < next.job().deadline_ms,
            "migration new grant time invalid"
        );
        let origin = old.stage.clone().context("migration stage debt missing")?;
        let a = origin
            .allocation()
            .context("migration allocation missing")?;
        ensure!(
            !a.is_anonymous()
                && a.original_owner() != self.owner
                && a.database_id() == Some(fence.database_id())
                && a.database_parent_id() == Some(fence.database_parent_id()?.as_str()),
            "migration stopped-origin/domain mismatch"
        );
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM ferroc_fleet_jobs_v1 LIMIT 129)",
            [],
            |r| r.get(0),
        )?;
        ensure!(count < MAX_JOBS as i64, "journal capacity exhausted");
        let link = MigrationLink {
            version: 1,
            transaction: Uuid::new_v4(),
            owner: self.owner,
            old_revision: revision,
            old_job: old.job.clone(),
            new_job: next.job().clone(),
            next: next.grant().clone(),
            origin: origin.clone(),
            checkpoint: cp,
            condition_digest: proposal.digest(),
        };
        let mut stage = origin;
        stage
            .allocation
            .as_mut()
            .context("allocation missing")?
            .owner = self.owner;
        let live = stage.allocation().context("allocation missing")?;
        let new = Snapshot {
            version: 4,
            job: next.job().clone(),
            owner: self.owner,
            revision: 1,
            phase: Phase::Interrupted,
            stage: Some(stage.clone()),
            received: 0,
            verified: false,
            intent: None,
            receipt: None,
            absence_release: None,
            data_seal: None,
            intent_binding: None,
            target_observation: None,
            settlement_origin: None,
            settlement_binding: None,
            retained: Some(Box::new(RetainedStageState {
                version: 1,
                owner: self.owner,
                allocation: live.id(),
                file_id: live.file_id().context("file id missing")?.into(),
                parent_id: live.parent_id().into(),
                binding: next.grant().binding.clone(),
                enabled_revision: 1,
                checkpoint: None,
                migration: Some(Box::new(link.clone())),
            })),
        };
        old.stage = None;
        old.version = 10;
        old.revision = revision
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .context("migration revision exhausted")?;
        old.retained
            .as_mut()
            .context("retained state missing")?
            .migration = Some(Box::new(link));
        old.validate()?;
        new.validate()?;
        ensure!(
            tx.execute(
                "UPDATE ferroc_fleet_meta SET version=13 WHERE version IN(12,13)",
                []
            )? == 1,
            "migration schema requires12/13"
        );
        Self::save(&tx, key, revision, &old)?;
        let body = serde_json::to_string(&new)?;
        ensure!(body.len() <= MAX_ROW, "migration row bound exceeded");
        tx.execute("INSERT INTO ferroc_fleet_jobs_v1(k,fleet,idem,parameters,digest,revision,body) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![JobKey::from_job(new.job()).id(),new.job.fleet_id.to_string(),new.job.idempotency_key,new.job.parameter_digest()?.as_slice(),new.job.digest()?.as_slice(),new.revision as i64,body])?;
        Self::load(&tx, key)?.context("old migration row missing")?;
        Self::load(&tx, &JobKey::from_job(new.job()))?.context("new migration row missing")?;
        fence.check_connection(&tx)?;
        tx.commit()?;
        self.check_owner()?;
        Ok((old, new))
    }
}
