//! Explicit stopped-owner read-only checkpoint verification. Never a resumed writer.
use super::{
    allocation,
    fence::{FencedConnection, directory_id, file_id},
    identity::{open_private, open_stage},
    journal::{JobKey, Journal, PrefixCheckpoint, Snapshot},
    state::Phase,
};
use crate::config::Policy;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
};

/// Describes one fresh prefix read against historical metadata. No FD/lease/host,
/// resume/commit/release authority or guarantee against subsequent external writes.
#[derive(Debug, Serialize)]
pub struct CheckpointReadback {
    checkpoint: PrefixCheckpoint,
    observed_revision: u64,
    retained_length: u64,
}
impl CheckpointReadback {
    pub fn checkpoint(&self) -> &PrefixCheckpoint {
        &self.checkpoint
    }
    pub fn observed_revision(&self) -> u64 {
        self.observed_revision
    }
    pub fn retained_length(&self) -> u64 {
        self.retained_length
    }
}
fn current(
    db: &mut FencedConnection,
    s: &Snapshot,
    p: &Policy,
    file: &File,
    original: &File,
) -> Result<File> {
    let now = Journal::existing_fenced(&mut db.connection, &db.fence)?
        .get(&JobKey::from_job(s.job()))?
        .context("checkpoint row missing")?;
    ensure!(
        now.revision() == s.revision()
            && now.owner() == s.owner()
            && now.phase() == Phase::Interrupted
            && now.job().digest()? == s.job().digest()?
            && now.stage() == s.stage()
            && now.retained_stage() == s.retained_stage()
            && now.data_seal().is_none()
            && now.intent().is_none()
            && now.receipt().is_none(),
        "checkpoint observation became stale"
    );
    let r = s.stage().context("checkpoint stage missing")?;
    let a = r.allocation().context("checkpoint allocation missing")?;
    let (_, parent, id) = allocation::parent(p, s)?;
    ensure!(
        id == a.parent_id()
            && directory_id(original)? == id
            && Some(file_id(file)?.as_str()) == a.file_id()
            && allocation::stage_path_matches(
                r.path(),
                a.file_id().context("checkpoint file id missing")?,
                false
            )?,
        "checkpoint object or parent changed"
    );
    Ok(parent)
}
impl FencedConnection {
    /// Caller has explicitly recovered a different STOPPED owner under this same
    /// database fence. Read at most max_prefix_bytes (hard cap 1GiB), returning a
    /// fresh read sequence only. Tail bytes are not checkpoint coverage. No SQL
    /// writes, truncation, deletion, lease/key import, quota release or IO owner.
    pub fn inspect_retained_checkpoint(
        &mut self,
        key: &JobKey,
        p: &Policy,
        fs_gate: Arc<Mutex<()>>,
        max_prefix_bytes: u64,
    ) -> Result<CheckpointReadback> {
        ensure!(
            max_prefix_bytes <= 1024 * 1024 * 1024,
            "checkpoint readback budget exceeds 1GiB"
        );
        let _gate = fs_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        let previous: i64 = self
            .connection
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))?;
        ensure!(
            (0..=i32::MAX as i64).contains(&previous),
            "invalid busy timeout"
        );
        self.connection.busy_timeout(std::time::Duration::ZERO)?;
        let result = (|| {
            let s = Journal::existing_fenced(&mut self.connection, &self.fence)?
                .get(key)?
                .context("checkpoint job missing")?;
            let state = s
                .retained_stage()
                .context("retained format opt-in missing")?;
            let checkpoint = state
                .checkpoint()
                .context("no persisted checkpoint")?
                .clone();
            let r = s.stage().context("checkpoint stage missing")?;
            let a = r.allocation().context("checkpoint allocation missing")?;
            ensure!(
                s.phase() == Phase::Interrupted
                    && s.data_seal().is_none()
                    && s.intent().is_none()
                    && s.receipt().is_none()
                    && !a.is_anonymous()
                    && s.owner() == self.fence.owner
                    && a.original_owner() != self.fence.owner
                    && state.original_owner() == a.original_owner()
                    && a.database_id() == Some(self.fence.database_id())
                    && a.database_parent_id() == Some(self.fence.database_parent_id()?.as_str()),
                "checkpoint needs same-DB recovered stopped origin without commit/cancel history"
            );
            ensure!(
                checkpoint.bytes() <= max_prefix_bytes,
                "checkpoint exceeds readback budget"
            );
            let original = open_private(
                r.path().parent().context("checkpoint parent missing")?,
                true,
            )?;
            let mut file = open_stage(r.path())?;
            let _parent = current(self, &s, p, &file, &original)?;
            let length = file.metadata()?.len();
            ensure!(
                checkpoint.bytes() <= length && length <= s.job().bytes_total,
                "retained stage length invalid"
            );
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = [0u8; 65536];
            file.seek(SeekFrom::Start(0))?;
            while offset < checkpoint.bytes() {
                let _parent = current(self, &s, p, &file, &original)?;
                ensure!(
                    file.metadata()?.len() == length,
                    "retained stage length changed"
                );
                let n = (checkpoint.bytes() - offset).min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..n])?;
                hash.update(&buffer[..n]);
                offset += n as u64;
            }
            let _parent = current(self, &s, p, &file, &original)?;
            ensure!(
                file.metadata()?.len() == length
                    && <[u8; 32]>::from(hash.finalize()) == checkpoint.sha256(),
                "persisted checkpoint prefix mismatch"
            );
            self.fence.check_connection(&self.connection)?;
            Ok(CheckpointReadback {
                checkpoint,
                observed_revision: s.revision(),
                retained_length: length,
            })
        })();
        let restore = self
            .connection
            .busy_timeout(std::time::Duration::from_millis(previous as u64));
        match (result, restore) {
            (r, Ok(())) => r,
            (_, Err(_)) => anyhow::bail!("checkpoint readback busy timeout restoration failed"),
        }
    }
}
