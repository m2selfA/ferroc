//! Live-owner sync/read sequence. The observation API writes no metadata.
//! Its private same-gate helper also drives explicit retained checkpoint capture.
//! Neither observation nor checkpoint creates restart IO, ACK, publish or release.
use super::*;
use crate::fleet::journal::Journal;

/// Historical description of bytes read AFTER sync_data completed on the same
/// named stage FD. The in-memory contiguous coverage defines the prefix, never
/// file length or journal received. Not a checkpoint, coherent snapshot, source
/// digest proof or resumable capability; external writers/mmap remain possible.
/// No File/lease/host is retained. Later DATA or external writes can change bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncedPrefixObservation {
    bytes: u64,
    sha256: [u8; 32],
    job_digest: [u8; 32],
    grant_digest: [u8; 32],
    revision: u64,
    file_id: String,
    parent_id: String,
    stage_length: u64,
}
impl SyncedPrefixObservation {
    pub(super) fn stage_length(&self) -> u64 {
        self.stage_length
    }
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
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn file_id(&self) -> &str {
        &self.file_id
    }
    pub fn parent_id(&self) -> &str {
        &self.parent_id
    }
}
impl HostReceiver<'_, '_> {
    /// Explicit local observation on a LIVE unsealed named-stage writer only.
    /// Sync then read the contiguous prefix under the actual Runtime gate, with
    /// per-64KiB lease/object/journal checks and nonwaiting SQL access. Success
    /// keeps this writer usable; failure faults it and preserves stage/debt.
    /// Does NOT persist checkpoint metadata, advance received/revision, seal DATA
    /// or reconstruct a writer after restart. Anonymous stages are rejected.
    pub fn observe_synced_prefix(&mut self) -> Result<SyncedPrefixObservation> {
        self.prefix_between(|_, _| Ok(()))
    }
    pub(super) fn prefix_between(
        &mut self,
        between: impl FnMut(u64, &mut Self) -> Result<()>,
    ) -> Result<SyncedPrefixObservation> {
        self.prefix_action(between, |_, observation| Ok(observation))
    }
    pub(super) fn prefix_action<T>(
        &mut self,
        mut between: impl FnMut(u64, &mut Self) -> Result<()>,
        finish: impl FnOnce(&mut Self, SyncedPrefixObservation) -> Result<T>,
    ) -> Result<T> {
        let result = (|| {
            ensure!(
                !self.faulted
                    && self.snapshot.phase() == Phase::Transferring
                    && self.snapshot.data_seal().is_none()
                    && self.snapshot.intent().is_none()
                    && !self.published,
                "prefix observation needs a live DATA writer"
            );
            let allocation = self
                .snapshot
                .stage()
                .and_then(|s| s.allocation())
                .context("prefix allocation missing")?;
            ensure!(
                !allocation.is_anonymous(),
                "anonymous stage cannot produce retained-prefix metadata"
            );
            let file_id = allocation
                .file_id()
                .context("prefix file identity missing")?
                .to_owned();
            let parent_id = allocation.parent_id().to_owned();
            let prefix = self.ranges.contiguous();
            let old_checkpoint = self
                .snapshot
                .retained_stage()
                .and_then(|s| s.checkpoint())
                .cloned();
            ensure!(
                old_checkpoint.as_ref().is_none_or(|c| c.bytes() <= prefix),
                "checkpoint exceeds live prefix"
            );
            let host = self.operation.host;
            let _gate = host
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            let key = JobKey::from_job(self.snapshot.job());
            let check = |this: &mut Self| {
                this.records.receive_admission()?;
                let parent = commit_admission::no_wait(host, |db| {
                    let current = Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .get(&key)?
                        .context("prefix job missing")?;
                    this.current_snapshot(db, &current)
                })?;
                this.records.receive_admission()?;
                Ok::<File, anyhow::Error>(parent)
            };
            let _parent = check(self)?;
            let length = self.file.metadata()?.len();
            ensure!(
                prefix <= length && length <= self.snapshot.job().bytes_total,
                "prefix exceeds current stage"
            );
            self.records.receive_admission()?;
            self.file.sync_data()?;
            self.records.receive_admission()?;
            self.unsynced = 0;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = [0u8; 65536];
            self.file.seek(SeekFrom::Start(0))?;
            while offset < prefix {
                let _current_parent = check(self)?;
                ensure!(
                    self.file.metadata()?.len() == length,
                    "prefix stage size changed"
                );
                let boundary = old_checkpoint
                    .as_ref()
                    .filter(|c| c.bytes() > offset)
                    .map_or(prefix, |c| c.bytes());
                let count = (prefix - offset)
                    .min(boundary - offset)
                    .min(buffer.len() as u64) as usize;
                self.file.read_exact(&mut buffer[..count])?;
                self.records.receive_admission()?;
                hash.update(&buffer[..count]);
                offset += count as u64;
                if let Some(old) = old_checkpoint.as_ref().filter(|c| c.bytes() == offset) {
                    ensure!(
                        <[u8; 32]>::from(hash.clone().finalize()) == old.sha256(),
                        "previous checkpoint prefix changed"
                    );
                }
                between(offset, self)?;
            }
            let _current_parent = check(self)?;
            ensure!(
                self.file.metadata()?.len() == length && self.ranges.contiguous() == prefix,
                "prefix stage or coverage changed"
            );
            self.records.receive_admission()?;
            let observation = SyncedPrefixObservation {
                bytes: prefix,
                sha256: hash.finalize().into(),
                job_digest: self.snapshot.job().digest()?,
                grant_digest: self.records.grant().digest(),
                revision: self.snapshot.revision(),
                file_id,
                parent_id,
                stage_length: length,
            };
            finish(self, observation)
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
}
