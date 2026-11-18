//! Successor grant issuance for mid-transfer renewal.
//!
//! This mints the NEXT `FileGrant` for a job that is already running, and
//! nothing else: no signatures, no trusted-time import, no network, no
//! scheduling, no persistence. It exists because renewal had every other half
//! (peers can rotate, the relay can route a successor, the pumps have a
//! rotation seam) but no component produced the successor at all.
//!
//! Boundaries that must not be relaxed here:
//! - the job is carried over verbatim, so a renewal can never change path,
//!   size, SHA, permission or the fixed job deadline;
//! - a lease may never exceed `MAX_LEASE_MS`, and never outlive the job;
//! - identifiers derive from `seed + generation`, so replaying a generation
//!   reproduces the SAME identifiers and the relay's route rejects the reuse
//!   instead of silently accepting a fresh-looking binding;
//! - issuance is not approval: the caller still needs local policy, pins and
//!   both peers' end-to-end authentication before anything is written.
use super::{
    auth::MAX_LEASE_MS,
    job::{FileGrant, ValidatedGrant},
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use uuid::Uuid;
/// Bounded issuance history per job, so a renewal loop cannot run forever.
pub const MAX_GENERATIONS: u64 = 1024;
fn derived(seed: &[u8; 32], generation: u64, tag: &[u8]) -> Uuid {
    let mut h = Sha256::new();
    h.update(b"ferroc:fleet:renewal:v1\0");
    h.update(tag);
    h.update(seed);
    h.update(generation.to_be_bytes());
    let d: [u8; 32] = h.finalize().into();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    // Keep a well-formed v4-shaped identifier; the value is a digest, not entropy.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Uuid::from_bytes(b)
}
/// Mint the successor for `current` at `generation`.
///
/// `seed` is the caller's renewal seed for this job; it must be non-zero and is
/// what makes a replayed generation reproduce identical identifiers. `now_ms`
/// is the caller's trusted-time sample: this function reads no clock, so a wrong
/// `now_ms` is the caller's fault, not a hidden assumption.
pub fn successor(
    current: &ValidatedGrant,
    seed: &[u8; 32],
    generation: u64,
    now_ms: u64,
    lease_ms: u64,
) -> Result<ValidatedGrant> {
    ensure!(*seed != [0; 32], "empty renewal seed");
    ensure!(generation > 0, "renewal generation starts at 1");
    ensure!(generation <= MAX_GENERATIONS, "renewal history exhausted");
    ensure!(
        (1..=MAX_LEASE_MS).contains(&lease_ms),
        "renewal lease outside the product ceiling"
    );
    let old = current.grant();
    ensure!(
        now_ms < old.expires_at_ms,
        "current lease already expired; renewal is not resurrection"
    );
    let expires_at_ms = now_ms
        .checked_add(lease_ms)
        .ok_or_else(|| anyhow::anyhow!("renewal expiry overflow"))?;
    ensure!(
        expires_at_ms <= current.job().deadline_ms,
        "renewal would outlive the fixed job deadline"
    );
    let mut binding = old.binding.clone();
    binding.authorization_id = derived(seed, generation, b"auth");
    binding.key_epoch = derived(seed, generation, b"epoch");
    ensure!(
        binding.authorization_id != old.binding.authorization_id
            && binding.key_epoch != old.binding.key_epoch,
        "renewal must rotate authorization and key epoch"
    );
    FileGrant {
        binding,
        job_digest: old.job_digest,
        permission: old.permission,
        chunk_bytes: old.chunk_bytes,
        issued_at_ms: now_ms,
        expires_at_ms,
    }
    .validate_for(current.job().clone())
}
