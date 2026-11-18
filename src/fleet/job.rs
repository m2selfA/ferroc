//! Stable job/request digests and structurally validated short-lived grants.
//! Not device enrollment, an OS permission token, or a durable job journal.
use super::{
    auth::MAX_LEASE_MS,
    protocol::{Binding, MAX_DATA, MAX_FILE_BYTES},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Bumped when the canonical request bytes gained the replace pre-image
/// condition. Old implementations must reject v2 rather than hash a v1 job that
/// silently lacks the pre-image binding.
pub const JOB_VERSION: u16 = 2;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_IDEMPOTENCY_BYTES: usize = 128;
pub const MAX_JOBS: usize = 128;
/// Which lease ceiling applies to a grant.
///
/// `Rotating` is the multi-host profile: short leases, mandatory rotation, and a
/// bounded blast radius if a ticket leaks. `SingleOwner` is for one person
/// running both ends: one grant for the whole job, no rotation, and the accepted
/// cost that a leaked grant lives until the job deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseProfile {
    Rotating,
    SingleOwner,
}
impl LeaseProfile {
    pub const fn ceiling_ms(self) -> u64 {
        match self {
            Self::Rotating => MAX_LEASE_MS,
            // The validated grant separately requires expires <= job.deadline_ms.
            // No unrelated file-size-derived time limit in the single-owner path.
            Self::SingleOwner => u64::MAX,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoutePolicy {
    RelayOnly,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobSpec {
    pub version: u16,
    pub fleet_id: Uuid,
    pub source_device: [u8; 32],
    pub target_device: [u8; 32],
    pub transfer_id: Uuid,
    pub file_id: Uuid,
    pub source_path: String,
    pub destination_path: String,
    pub bytes_total: u64,
    pub sha256: [u8; 32],
    pub overwrite: bool,
    /// Required when `overwrite` is true: the exact content the target must
    /// still have at replace time. `None` for no-clobber jobs. This is a
    /// CALLER claim, not an observation; the receiver re-hashes the real target
    /// under its own gate and refuses on any difference.
    pub pre_image_sha256: Option<[u8; 32]>,
    pub route: RoutePolicy,
    pub deadline_ms: u64,
    pub idempotency_key: String,
}
fn checked_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES && !path.chars().any(char::is_control),
        "invalid fleet path length or control characters"
    );
    let b = path.as_bytes();
    let disk = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'/' || b[2] == b'\\');
    let unix = path.starts_with('/') && !path.starts_with("//");
    ensure!(
        disk || unix,
        "fleet path must be rooted Unix or Windows disk path; UNC/device namespaces unsupported"
    );
    let rest = if disk { &path[3..] } else { &path[1..] };
    ensure!(
        !rest.is_empty() && !rest.contains(':') && !path.ends_with(['/', '\\']),
        "fleet path must name a file; ADS unsupported"
    );
    ensure!(
        !rest
            .split(['/', '\\'])
            .any(|s| s.is_empty() || s == "." || s == ".."),
        "ambiguous fleet path components"
    );
    let filename = rest.rsplit(['/', '\\']).next().expect("nonempty path");
    ensure!(
        !filename.to_ascii_lowercase().starts_with(".ferroc-fleet-"),
        "reserved fleet stage namespace"
    );
    Ok(())
}
fn text(out: &mut Vec<u8>, value: &str) {
    // Every caller validates the <=4096/128 byte bound before this cast.
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}
impl JobSpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == JOB_VERSION, "unsupported fleet job version");
        for id in [self.fleet_id, self.transfer_id, self.file_id] {
            ensure!(!id.is_nil(), "nil stable fleet job identifier");
        }
        ensure!(
            self.source_device != [0; 32]
                && self.target_device != [0; 32]
                && self.source_device != self.target_device,
            "invalid fleet job devices"
        );
        checked_path(&self.source_path)?;
        checked_path(&self.destination_path)?;
        ensure!(
            self.bytes_total <= MAX_FILE_BYTES && self.deadline_ms > 0,
            "invalid fleet job size/deadline"
        );
        match (self.overwrite, self.pre_image_sha256) {
            (false, None) => {}
            (false, Some(_)) => {
                anyhow::bail!("no-clobber job must not carry a replace pre-image")
            }
            (true, None) => {
                anyhow::bail!("replace job requires the expected pre-image digest")
            }
            (true, Some(pre)) => {
                // Replacing a file with identical content is a no-op that would
                // still spend a full transfer; the planner must not emit it.
                ensure!(
                    pre != self.sha256,
                    "replace job pre-image equals the new content"
                );
            }
        }
        ensure!(
            !self.idempotency_key.is_empty()
                && self.idempotency_key.len() <= MAX_IDEMPOTENCY_BYTES
                && self
                    .idempotency_key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
            "invalid fleet idempotency key"
        );
        Ok(())
    }
    /// Exact UTF-8 bytes, no lossy path normalization or JSON field-order hash.
    /// Excludes coordinator-assigned transfer/file IDs and the lookup key so a
    /// retry cannot accidentally create another job merely by generating IDs.
    pub fn request_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut b = b"ferroc:fleet:request:v1\0".to_vec();
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(self.fleet_id.as_bytes());
        b.extend_from_slice(&self.source_device);
        b.extend_from_slice(&self.target_device);
        text(&mut b, &self.source_path);
        text(&mut b, &self.destination_path);
        b.extend_from_slice(&self.bytes_total.to_be_bytes());
        b.extend_from_slice(&self.sha256);
        b.push(u8::from(self.overwrite));
        // Bind the pre-image inside the same hashed bytes: a replace job cannot
        // be re-pointed at different existing content without changing the
        // request, job and grant digests.
        match self.pre_image_sha256 {
            Some(pre) => {
                b.push(1);
                b.extend_from_slice(&pre);
            }
            None => b.push(0),
        }
        b.push(match self.route {
            RoutePolicy::RelayOnly => 0,
        });
        b.extend_from_slice(&self.deadline_ms.to_be_bytes());
        Ok(b)
    }
    pub fn parameter_digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.request_bytes()?).into())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let request = self.request_bytes()?;
        let mut b = b"ferroc:fleet:job:v1\0".to_vec();
        b.extend_from_slice(self.transfer_id.as_bytes());
        b.extend_from_slice(self.file_id.as_bytes());
        text(&mut b, &self.idempotency_key);
        b.extend_from_slice(&request);
        Ok(b)
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
    fn matches_binding(&self, b: &Binding) -> bool {
        self.fleet_id == b.fleet_id
            && self.source_device == b.source_device
            && self.target_device == b.target_device
            && self.transfer_id == b.transfer_id
            && self.file_id == b.file_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    /// Create a file that must not exist. Destination is absent at commit.
    SendFileNoClobber,
    /// Replace a file that must still match the job's pre-image digest. A
    /// separate permission, not a flag on the create path: a receiver must
    /// distinguish "may create" from "may destroy existing bytes".
    ReplaceExistingFile,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileGrant {
    pub binding: Binding,
    pub job_digest: [u8; 32],
    pub permission: Permission,
    pub chunk_bytes: u32,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
impl FileGrant {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.canonical_bytes_with(LeaseProfile::Rotating)
    }
    /// Validate the selected local lease ceiling and encode identical wire bytes
    /// for either profile. The profile is not a signed field; peers independently
    /// choose it when validating their locally approved grant.
    pub fn canonical_bytes_with(&self, profile: LeaseProfile) -> Result<Vec<u8>> {
        self.binding.validate()?;
        ensure!(
            self.chunk_bytes > 0 && self.chunk_bytes as usize <= MAX_DATA,
            "invalid grant chunk limit"
        );
        ensure!(
            self.expires_at_ms > self.issued_at_ms
                && self.expires_at_ms - self.issued_at_ms <= profile.ceiling_ms(),
            "invalid grant lease"
        );
        let mut b = b"ferroc:fleet:grant:v1\0".to_vec();
        b.extend_from_slice(&self.binding.bytes());
        b.extend_from_slice(&self.job_digest);
        b.push(match self.permission {
            Permission::SendFileNoClobber => 1,
            Permission::ReplaceExistingFile => 2,
        });
        b.extend_from_slice(&self.chunk_bytes.to_be_bytes());
        b.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        b.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        // The profile deliberately does NOT enter the canonical bytes: those are
        // a cross-implementation golden contract. A long lease is refused by the
        // opposing profile's ceiling at validation time, which is where it has to
        // be refused anyway.
        Ok(b)
    }
    /// Structural validation only. The caller must independently approve local
    /// policy and authenticate the issuer; peer-offered grants are not trust.
    ///
    /// Uses the ROTATING profile, which caps a lease at `MAX_LEASE_MS`. A single
    /// owner running both ends has nobody to rotate against and should use
    /// `validate_for_profile(job, LeaseProfile::SingleOwner)` instead, so a long
    /// transfer is authorized once instead of being chopped into lease windows.
    pub fn validate_for(self, job: JobSpec) -> Result<ValidatedGrant> {
        self.validate_for_profile(job, LeaseProfile::Rotating)
    }
    /// Same checks with an explicit lease profile. `SingleOwner` raises the lease
    /// ceiling to the fixed job deadline; the job deadline bound is unchanged, so
    /// a grant still cannot outlive the job it authorizes.
    ///
    /// This is a POLICY switch, not a security claim: with rotation off, a stolen
    /// grant stays usable until the job deadline, and there is no epoch rotation
    /// to bound key exposure. That is the accepted trade-off of one owner.
    pub fn validate_for_profile(
        self,
        job: JobSpec,
        profile: LeaseProfile,
    ) -> Result<ValidatedGrant> {
        job.validate()?;
        ensure!(
            job.matches_binding(&self.binding),
            "grant does not match stable fleet job"
        );
        ensure!(
            job.digest()? == self.job_digest,
            "grant job digest mismatch"
        );
        ensure!(
            self.expires_at_ms <= job.deadline_ms,
            "grant exceeds fixed job deadline"
        );
        // The permission and the job's clobber mode must agree in both
        // directions, so a create grant can never authorize a replacement.
        ensure!(
            match self.permission {
                Permission::SendFileNoClobber => !job.overwrite,
                Permission::ReplaceExistingFile => job.overwrite,
            },
            "grant permission does not match the job's clobber mode"
        );
        let digest = Sha256::digest(self.canonical_bytes_with(profile)?).into();
        Ok(ValidatedGrant {
            job,
            grant: self,
            digest,
            profile,
        })
    }
}
/// No Deserialize or unchecked constructor. Still NOT an authenticated issuer.
#[derive(Clone, Debug)]
pub struct ValidatedGrant {
    job: JobSpec,
    grant: FileGrant,
    digest: [u8; 32],
    profile: LeaseProfile,
}
impl ValidatedGrant {
    /// Local policy retained across clone/authentication, never inferred from peer data.
    pub fn lease_profile(&self) -> LeaseProfile {
        self.profile
    }
    pub fn job(&self) -> &JobSpec {
        &self.job
    }
    pub fn grant(&self) -> &FileGrant {
        &self.grant
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionKind {
    Created,
    Existing,
}
#[derive(Clone, Debug)]
pub struct JobAdmission {
    pub kind: AdmissionKind,
    pub job: JobSpec,
}
struct Entry {
    request_digest: [u8; 32],
    job: JobSpec,
}
/// Finite IN-MEMORY admission ledger. No eviction of unresolved jobs, no TTL or
/// restart idempotency claim. Future coordinator must transact this in SQLite.
pub struct IdempotencyLedger {
    entries: HashMap<(Uuid, String), Entry>,
    capacity: usize,
}
impl IdempotencyLedger {
    pub fn new(capacity: usize) -> Result<Self> {
        ensure!(
            (1..=MAX_JOBS).contains(&capacity),
            "invalid fleet job capacity"
        );
        Ok(Self {
            entries: HashMap::new(),
            capacity,
        })
    }
    pub fn admit(&mut self, job: JobSpec, now_ms: u64) -> Result<JobAdmission> {
        let request_digest = job.parameter_digest()?;
        let key = (job.fleet_id, job.idempotency_key.clone());
        if let Some(existing) = self.entries.get(&key) {
            ensure!(
                request_digest == existing.request_digest,
                "idempotency key reused with different parameters"
            );
            return Ok(JobAdmission {
                kind: AdmissionKind::Existing,
                job: existing.job.clone(),
            });
        }
        ensure!(now_ms < job.deadline_ms, "fleet job deadline expired");
        ensure!(self.entries.len() < self.capacity, "fleet job ledger full");
        self.entries.insert(
            key,
            Entry {
                request_digest,
                job: job.clone(),
            },
        );
        Ok(JobAdmission {
            kind: AdmissionKind::Created,
            job,
        })
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
