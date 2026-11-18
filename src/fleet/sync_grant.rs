//! Local candidate grant issuance for one SyncPlan. NOT an authenticated issuer,
//! trusted clock, enrollment or approval: every grant is still structural only.
//! No network, IO, scheduling, signature or persistence capability.
use super::{
    job::{FileGrant, Permission, ValidatedGrant},
    sync_plan::SyncPlan,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const MAX_GRANT_CHUNK: u32 = 65536;

/// Per-run identifiers. Sessions stay stable for the whole sync run; per-file
/// authorization/epoch ids are derived from the seeds and the file index.
#[derive(Clone, Debug)]
pub struct GrantTemplate {
    pub source_session: Uuid,
    pub target_session: Uuid,
    pub authorization_seed: u128,
    pub epoch_seed: u128,
    pub issued_at_ms: u64,
    pub lease_ms: u64,
    pub chunk_bytes: u32,
}

/// One grant per planned file, in plan order. Still needs peer pins, signatures,
/// local policy and admission before any byte moves.
/// ```compile_fail
/// fn no_send(b:ferroc::fleet::sync_grant::GrantBatch){b.send_all().unwrap();}
/// ```
/// ```compile_fail
/// fn no_export(g:&ferroc::fleet::sync_grant::GrantBatch){let _=g.clock;}
/// ```
#[derive(Clone, Debug)]
pub struct GrantBatch {
    grants: Vec<ValidatedGrant>,
    chunk_bytes: u32,
    expires_at_ms: u64,
}
impl GrantBatch {
    pub fn len(&self) -> usize {
        self.grants.len()
    }
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
    pub fn grants(&self) -> &[ValidatedGrant] {
        &self.grants
    }
    /// Chunk ceiling shared by the batch, never above the plan/template limit.
    pub fn chunk_bytes(&self) -> u32 {
        self.chunk_bytes
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn job_digests(&self) -> Result<Vec<[u8; 32]>> {
        self.grants.iter().map(|g| g.job().digest()).collect()
    }
}
fn derive(seed: u128, index: usize, tag: u8) -> Uuid {
    let mut h = Sha256::new();
    h.update(b"ferroc-fleet-sync-grant\0");
    h.update(seed.to_be_bytes());
    h.update((index as u64).to_be_bytes());
    h.update([tag]);
    let d: [u8; 32] = h.finalize().into();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    Uuid::from_bytes(id)
}

#[cfg(test)]
#[path = "sync_grant_tests.rs"]
mod tests;

/// Structural issuance only: same plan plus same template gives identical grant
/// digests, which keeps replay auditable. An expired or replayed batch is still
/// rejected later by the lease/admission layer.
pub fn issue_for_plan(plan: &SyncPlan, template: &GrantTemplate) -> Result<GrantBatch> {
    // Two peers sharing one session id is a misconfiguration, not a transfer.
    ensure!(
        template.source_session != template.target_session,
        "grant sessions must differ"
    );
    ensure!(
        !template.source_session.is_nil() && !template.target_session.is_nil(),
        "grant sessions must be non-nil"
    );
    ensure!(
        template.authorization_seed != 0 && template.epoch_seed != 0,
        "grant seeds must be non-zero"
    );
    ensure!(
        template.authorization_seed != template.epoch_seed,
        "authorization and epoch seeds must differ"
    );
    ensure!(
        template.chunk_bytes > 0 && template.chunk_bytes <= MAX_GRANT_CHUNK,
        "grant chunk ceiling outside fleet bound"
    );
    ensure!(template.lease_ms > 0, "grant lease must be positive");
    let expires_at_ms = template
        .issued_at_ms
        .checked_add(template.lease_ms)
        .context("grant lease overflow")?;
    let chunk_bytes = template.chunk_bytes.min(MAX_GRANT_CHUNK);
    let mut grants = Vec::with_capacity(plan.files().len());
    let mut authorizations = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut transfer = None;
    for (index, planned) in plan.files().iter().enumerate() {
        let job = planned.job().clone();
        match transfer {
            Some(id) => ensure!(id == job.transfer_id, "plan mixes transfer ids"),
            None => transfer = Some(job.transfer_id),
        }
        ensure!(
            expires_at_ms <= job.deadline_ms,
            "grant lease exceeds the fixed job deadline for {}",
            planned.path
        );
        let authorization_id = derive(template.authorization_seed, index, 1);
        let key_epoch = derive(template.epoch_seed, index, 2);
        ensure!(
            !authorization_id.is_nil() && !key_epoch.is_nil(),
            "derived grant id is nil"
        );
        ensure!(authorization_id != key_epoch, "derived grant ids collide");
        ensure!(
            authorizations.insert(authorization_id),
            "authorization reused"
        );
        ensure!(epochs.insert(key_epoch), "key epoch reused");
        ensure!(files.insert(job.file_id), "file id reused");
        let grant = FileGrant {
            binding: super::protocol::Binding {
                fleet_id: job.fleet_id,
                source_device: job.source_device,
                target_device: job.target_device,
                source_session: template.source_session,
                target_session: template.target_session,
                transfer_id: job.transfer_id,
                file_id: job.file_id,
                authorization_id,
                key_epoch,
            },
            job_digest: job.digest()?,
            // The permission must mirror the job's clobber mode; validate_for
            // rejects a mismatch in either direction.
            permission: if job.overwrite {
                Permission::ReplaceExistingFile
            } else {
                Permission::SendFileNoClobber
            },
            chunk_bytes,
            issued_at_ms: template.issued_at_ms,
            expires_at_ms,
        };
        grants.push(
            grant
                .clone()
                .validate_for(job)
                .with_context(|| format!("grant rejected for {}", planned.path))?,
        );
    }
    Ok(GrantBatch {
        grants,
        chunk_bytes,
        expires_at_ms,
    })
}
