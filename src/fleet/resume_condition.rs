//! Explicit local restart proposal contract; no Runtime signer or transport hook.
//! A historical prefix/readback and plain grant cannot construct an IO owner.
use crate::fleet::{
    auth::Transcript,
    checkpoint_readback::CheckpointReadback,
    job::{JobSpec, LeaseProfile, ValidatedGrant},
    journal::PrefixCheckpoint,
    protocol::{Binding, Direction},
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

/// Immutable descriptive bytes to be separately approved by BOTH local roles.
/// This is not a lease, authenticated peer proof or permission to reopen a stage.
#[derive(Clone, Debug)]
pub struct ResumeProposal {
    canonical: Box<[u8]>,
    digest: [u8; 32],
    prefix_bytes: u64,
    prefix_sha256: [u8; 32],
    next_grant_digest: [u8; 32],
    job_digest_binding: [u8; 32],
}
fn old_binding_matches(b: &Binding, j: &JobSpec) -> bool {
    b.fleet_id == j.fleet_id
        && b.source_device == j.source_device
        && b.target_device == j.target_device
        && b.transfer_id == j.transfer_id
        && b.file_id == j.file_id
}
impl ResumeProposal {
    /// Target-side proposal from a native freshly verified read sequence. The
    /// readback remains historical: final target adoption must reread the File.
    pub fn from_readback(
        old: &JobSpec,
        readback: &CheckpointReadback,
        next: &ValidatedGrant,
    ) -> Result<Self> {
        Self::build(old, readback.checkpoint(), next)
    }
    pub(super) fn build(
        old: &JobSpec,
        cp: &PrefixCheckpoint,
        next: &ValidatedGrant,
    ) -> Result<Self> {
        old.validate()?;
        cp.binding().validate()?;
        let new = next.job();
        new.validate()?;
        ensure!(
            next.lease_profile() == LeaseProfile::SingleOwner,
            "restart proposal requires explicit SingleOwner approval"
        );
        ensure!(
            cp.job_digest() == old.digest()?
                && old_binding_matches(cp.binding(), old)
                && cp.bytes() <= old.bytes_total
                && cp.revision() > 0,
            "historical checkpoint/job mismatch"
        );
        ensure!(
            cp.bytes() != 0 || cp.sha256() == <[u8; 32]>::from(Sha256::digest([])),
            "invalid empty prefix"
        );
        ensure!(
            old.fleet_id == new.fleet_id
                && old.source_device == new.source_device
                && old.target_device == new.target_device
                && old.source_path == new.source_path
                && old.destination_path == new.destination_path
                && old.bytes_total == new.bytes_total
                && old.sha256 == new.sha256
                && old.overwrite == new.overwrite
                && old.pre_image_sha256 == new.pre_image_sha256
                && old.route == new.route,
            "restart cannot change immutable content intent"
        );
        // A new deadline is a NEW explicitly approved job, never renewal or
        // mutation of the old fixed deadline, task or authorization.
        ensure!(
            old.transfer_id != new.transfer_id
                && old.file_id != new.file_id
                && old.idempotency_key != new.idempotency_key,
            "restart needs fresh job identities"
        );
        let b = &next.grant().binding;
        let old_b = cp.binding();
        ensure!(
            b.authorization_id != old_b.authorization_id
                && b.key_epoch != old_b.key_epoch
                && b.source_session != b.target_session
                && ![old_b.source_session, old_b.target_session].contains(&b.source_session)
                && ![old_b.source_session, old_b.target_session].contains(&b.target_session),
            "restart needs fresh sessions/authorization/epoch"
        );
        let mut bytes = b"ferroc:fleet:resume-condition:v1\0".to_vec();
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.push(1); // local SingleOwner in NEW domain only
        bytes.extend_from_slice(&old.digest()?);
        bytes.extend_from_slice(&cp.grant_digest());
        bytes.extend_from_slice(&old_b.bytes());
        bytes.extend_from_slice(&cp.revision().to_be_bytes());
        bytes.extend_from_slice(&cp.bytes().to_be_bytes());
        bytes.extend_from_slice(&cp.sha256());
        bytes.extend_from_slice(&new.digest()?);
        bytes.extend_from_slice(&next.digest());
        bytes.extend_from_slice(&b.bytes());
        let digest = Sha256::digest(&bytes).into();
        Ok(Self {
            canonical: bytes.into_boxed_slice(),
            digest,
            prefix_bytes: cp.bytes(),
            prefix_sha256: cp.sha256(),
            next_grant_digest: next.digest(),
            job_digest_binding: old.digest()?,
        })
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn prefix_sha256(&self) -> [u8; 32] {
        self.prefix_sha256
    }
    pub(super) fn expected_grant_digest(&self) -> [u8; 32] {
        self.next_grant_digest
    }
    pub(super) fn old_job_binding_digest(&self) -> [u8; 32] {
        self.job_digest_binding
    }
    pub(super) fn checkpoint_length(&self) -> u64 {
        self.prefix_bytes
    }
    pub fn prefix_bytes(&self) -> u64 {
        self.prefix_bytes
    }
    /// NEW signing domain, bound to this condition and the actual fresh auth-v2
    /// transcript. Existing auth-v2 signatures alone never imply resume approval.
    /// This only generates bytes; it does not sign, verify pins or install leases.
    pub fn proof_bytes(
        &self,
        next: &ValidatedGrant,
        t: &Transcript,
        role: Direction,
    ) -> Result<Vec<u8>> {
        let g = next.grant();
        ensure!(
            next.lease_profile() == LeaseProfile::SingleOwner
                && next.digest() == self.next_grant_digest
                && t.binding == g.binding
                && t.job_digest == next.job().digest()?
                && t.grant_digest == next.digest()
                && t.max_file_bytes == next.job().bytes_total
                && t.chunk_bytes == g.chunk_bytes
                && t.issued_at_ms == g.issued_at_ms
                && t.expires_at_ms == g.expires_at_ms,
            "resume proof/transcript mismatch"
        );
        ensure!(
            t.source_ephemeral != [0; 32]
                && t.target_ephemeral != [0; 32]
                && t.source_ephemeral != t.target_ephemeral,
            "resume requires distinct fresh ephemeral keys"
        );
        let auth = t.bytes_with_profile(role, LeaseProfile::SingleOwner)?;
        let mut b = b"ferroc:fleet:resume-proof:v1\0".to_vec();
        b.push(role as u8);
        b.extend_from_slice(&self.digest);
        b.extend_from_slice(&Sha256::digest(auth));
        Ok(b)
    }
}
/// Closed signing request, never an arbitrary caller-provided byte buffer.
pub(super) struct SigningMessage<'a> {
    pub proposal: &'a ResumeProposal,
    pub grant: &'a ValidatedGrant,
    pub transcript: &'a Transcript,
    pub role: Direction,
}
impl SigningMessage<'_> {
    pub(super) fn identity_and_bytes(&self) -> Result<([u8; 32], Vec<u8>)> {
        let expected = match self.role {
            Direction::SourceToTarget => self.transcript.source_identity,
            Direction::TargetToSource => self.transcript.target_identity,
        };
        Ok((
            expected,
            self.proposal
                .proof_bytes(self.grant, self.transcript, self.role)?,
        ))
    }
}
#[cfg(test)]
#[path = "resume_condition_tests.rs"]
mod tests;
