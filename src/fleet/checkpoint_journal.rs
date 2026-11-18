//! Schema12 retained-stage metadata. No serialized value constructs a live IO owner.
use super::super::protocol::Binding;
use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixCheckpoint {
    version: u16,
    bytes: u64,
    sha256: [u8; 32],
    job_digest: [u8; 32],
    grant_digest: [u8; 32],
    binding: Binding,
    revision: u64,
}
impl PrefixCheckpoint {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn job_digest(&self) -> [u8; 32] {
        self.job_digest
    }
    pub fn grant_digest(&self) -> [u8; 32] {
        self.grant_digest
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedStageState {
    pub(super) version: u16,
    pub(super) owner: Uuid,
    pub(super) allocation: Uuid,
    pub(super) file_id: String,
    pub(super) parent_id: String,
    pub(super) binding: Binding,
    pub(super) enabled_revision: u64,
    pub(super) checkpoint: Option<PrefixCheckpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) migration: Option<Box<super::migration::MigrationLink>>,
}
fn same_session(a: &Binding, b: &Binding) -> bool {
    a.fleet_id == b.fleet_id
        && a.transfer_id == b.transfer_id
        && a.file_id == b.file_id
        && a.source_device == b.source_device
        && a.target_device == b.target_device
        && a.source_session == b.source_session
        && a.target_session == b.target_session
}
fn bound_to_job(b: &Binding, j: &JobSpec) -> Result<()> {
    b.validate()?;
    ensure!(
        b.fleet_id == j.fleet_id
            && b.transfer_id == j.transfer_id
            && b.file_id == j.file_id
            && b.source_device == j.source_device
            && b.target_device == j.target_device,
        "checkpoint binding/job mismatch"
    );
    Ok(())
}
impl RetainedStageState {
    pub fn original_owner(&self) -> Uuid {
        self.owner
    }
    pub fn file_id(&self) -> &str {
        &self.file_id
    }
    pub fn parent_id(&self) -> &str {
        &self.parent_id
    }
    pub fn checkpoint(&self) -> Option<&PrefixCheckpoint> {
        self.checkpoint.as_ref()
    }
    pub(super) fn validate(&self, s: &Snapshot, row_version: u16) -> Result<()> {
        let a = s
            .stage()
            .or_else(|| s.settlement_origin())
            .or_else(|| s.migration_origin().filter(|_| row_version == 10))
            .and_then(|r| r.allocation())
            .context("retained allocation missing")?;
        bound_to_job(&self.binding, s.job())?;
        ensure!(
            self.version == 1
                && row_version >= 4
                && !a.is_anonymous()
                && self.owner == a.original_owner()
                && self.allocation == a.id()
                && Some(self.file_id.as_str()) == a.file_id()
                && self.parent_id == a.parent_id()
                && self.enabled_revision > 0
                && self.enabled_revision <= s.revision()
                && a.database_id().is_some()
                && a.database_parent_id().is_some(),
            "invalid retained-stage metadata"
        );
        if let Some(c) = &self.checkpoint {
            bound_to_job(&c.binding, s.job())?;
            ensure!(
                c.version == 1
                    && c.revision > self.enabled_revision
                    && c.revision <= s.revision()
                    && c.bytes <= s.job().bytes_total
                    && c.job_digest == s.job().digest()?
                    && same_session(&c.binding, &self.binding)
                    && (c.bytes != 0 || c.sha256 == <[u8; 32]>::from(Sha256::digest([]))),
                "invalid prefix checkpoint"
            );
        }
        if let Some(link) = &self.migration {
            link.validate(s)?;
        }
        Ok(())
    }
}
impl Journal<'_> {
    pub(in crate::fleet) fn enable_retained(
        &mut self,
        key: &JobKey,
        revision: u64,
        binding: Binding,
    ) -> Result<Snapshot> {
        let fence = self.fence.context("retained stage requires native fence")?;
        self.change(key,revision,|s,c| {
            ensure!(s.version==4 && s.phase==Phase::Transferring && s.received==0 && s.retained.is_none(),"retained opt-in must precede DATA");
            let a=s.stage().and_then(|r|r.allocation()).context("retained allocation missing")?;
            ensure!(!a.is_anonymous() && s.owner()==fence.owner && a.original_owner()==fence.owner
                && a.database_id()==Some(fence.database_id()) && a.database_parent_id()==Some(fence.database_parent_id()?.as_str()),"retained owner/domain mismatch");
            bound_to_job(&binding,s.job())?;
            let state=RetainedStageState { version:1,owner:fence.owner,allocation:a.id(),file_id:a.file_id().context("retained file id missing")?.into(),parent_id:a.parent_id().into(),binding,enabled_revision:revision.checked_add(1).context("retained revision overflow")?,checkpoint:None,migration:None };
            ensure!(c.execute("UPDATE ferroc_fleet_meta SET version=CASE WHEN version=13 THEN 13 ELSE 12 END WHERE version IN(1,2,3,4,5,6,7,8,9,10,11,12,13)",[])?==1,"retained schema marker failed");
            s.retained=Some(Box::new(state));Ok(())
        })
    }
    pub(in crate::fleet) fn record_prefix(
        &mut self,
        key: &JobKey,
        revision: u64,
        bytes: u64,
        sha256: [u8; 32],
        grant_digest: [u8; 32],
        binding: Binding,
    ) -> Result<Snapshot> {
        let fence = self.fence.context("checkpoint requires native fence")?;
        self.change(key, revision, |s, c| {
            ensure!(
                s.version == 4
                    && s.phase == Phase::Transferring
                    && s.intent.is_none()
                    && s.data_seal.is_none()
                    && s.owner() == fence.owner,
                "checkpoint needs active DATA phase"
            );
            let job_digest = s.job().digest()?;
            bound_to_job(&binding, s.job())?;
            let state = s.retained.as_mut().context("checkpoint opt-in missing")?;
            ensure!(
                state.owner == fence.owner
                    && same_session(&binding, &state.binding)
                    && bytes <= s.job.bytes_total
                    && state
                        .checkpoint
                        .as_ref()
                        .is_none_or(|old| bytes >= old.bytes
                            && (bytes != old.bytes || sha256 == old.sha256)),
                "checkpoint regressed/changed prefix"
            );
            ensure!(
                c.execute(
                    "UPDATE ferroc_fleet_meta SET version=version WHERE version IN(12,13)",
                    []
                )? == 1,
                "checkpoint format requires schema12"
            );
            state.checkpoint = Some(PrefixCheckpoint {
                version: 1,
                bytes,
                sha256,
                job_digest,
                grant_digest,
                binding,
                revision: revision
                    .checked_add(1)
                    .context("checkpoint revision overflow")?,
            });
            Ok(())
        })
    }
}
