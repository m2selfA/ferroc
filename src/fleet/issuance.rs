//! Explicit LOCAL role approval, not remote consent, a time service or IO authority.
//! A proposal is only structure. Each peer approves the SAME proposal locally.
use super::{
    auth::{DevicePin, Transcript},
    identity::{EndpointSlot, Fingerprint, IdentityStore, PeerEndpoint},
    job::{FileGrant, JobSpec, LeaseProfile, Permission, ValidatedGrant},
    protocol::{Binding, Direction, device_digest},
};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Explicit caller-selected sessions/profile/time; not imported from a peer.
pub struct ProposalOptions {
    pub source_session: Uuid,
    pub target_session: Uuid,
    pub profile: LeaseProfile,
    pub issued_at_ms: u64,
    pub lease_ms: u64,
    pub chunk_bytes: u32,
}
/// Pure proposal generation. Random authorization/epoch IDs are not approval,
/// durable idempotency or permission to retry. Share this exact grant with the
/// other host rather than generating a second proposal there.
pub fn propose(job: JobSpec, options: ProposalOptions) -> Result<ValidatedGrant> {
    job.validate()?;
    ensure!(
        options.source_session != options.target_session,
        "source and target sessions must differ"
    );
    let expires_at_ms = options
        .issued_at_ms
        .checked_add(options.lease_ms)
        .context("proposal lease overflow")?;
    let grant = FileGrant {
        binding: Binding {
            fleet_id: job.fleet_id,
            source_device: job.source_device,
            target_device: job.target_device,
            source_session: options.source_session,
            target_session: options.target_session,
            transfer_id: job.transfer_id,
            file_id: job.file_id,
            authorization_id: Uuid::new_v4(),
            key_epoch: Uuid::new_v4(),
        },
        job_digest: job.digest()?,
        permission: if job.overwrite {
            Permission::ReplaceExistingFile
        } else {
            Permission::SendFileNoClobber
        },
        chunk_bytes: options.chunk_bytes,
        issued_at_ms: options.issued_at_ms,
        expires_at_ms,
    };
    grant.validate_for_profile(job, options.profile)
}

/// Trusted caller input, NOT a deserialized remote approval. `now_ms` passed to
/// Runtime must come from the caller's local authority-time decision. It does
/// NOT install a TrustedTimeAnchor; leased authentication still requires one.
pub struct LocalApprovalRequest<'a> {
    pub proposal: &'a ValidatedGrant,
    pub role: Direction,
    pub peer_device: &'a str,
    pub expected_peer: &'a Fingerprint,
    pub endpoint_slot: EndpointSlot,
    pub source_ephemeral: [u8; 32],
    pub target_ephemeral: [u8; 32],
}
/// Historical local decision + one role signature. No clone/deserialize/restore
/// or private key. Not a live lease, peer signature, path reservation, content
/// observation, publication permit or automatic reauthorization after restart.
pub struct SignedLocalGrant {
    grant: ValidatedGrant,
    role: Direction,
    transcript: Transcript,
    signature: [u8; 64],
    source_pin: DevicePin,
    target_pin: DevicePin,
    endpoint: PeerEndpoint,
    peer_fingerprint: Fingerprint,
}
impl SignedLocalGrant {
    pub fn grant(&self) -> &ValidatedGrant {
        &self.grant
    }
    pub fn role(&self) -> Direction {
        self.role
    }
    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub fn source_pin(&self) -> &DevicePin {
        &self.source_pin
    }
    pub fn target_pin(&self) -> &DevicePin {
        &self.target_pin
    }
    pub fn endpoint(&self) -> &PeerEndpoint {
        &self.endpoint
    }
    pub fn peer_fingerprint(&self) -> &Fingerprint {
        &self.peer_fingerprint
    }
}

/// Historical local approval of a declared resume condition plus normal grant.
/// No lease, replay ledger, source observation, stage adoption or IO authority.
pub struct SignedLocalResume {
    approval: SignedLocalGrant,
    condition: super::resume_condition::ResumeProposal,
    signature: [u8; 64],
}
impl SignedLocalResume {
    pub fn approval(&self) -> &SignedLocalGrant {
        &self.approval
    }
    pub fn condition(&self) -> &super::resume_condition::ResumeProposal {
        &self.condition
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    /// Pure cryptographic check against this locally approved transcript/pin.
    /// Repeated checks are not fresh acceptance, time validation or IO permission.
    pub fn verify_peer_signature(&self, signature: &[u8; 64]) -> Result<()> {
        use ring::signature::{ED25519, UnparsedPublicKey};
        let a = &self.approval;
        let role = match a.role() {
            Direction::SourceToTarget => Direction::TargetToSource,
            Direction::TargetToSource => Direction::SourceToTarget,
        };
        let t = a.transcript();
        let key = match role {
            Direction::SourceToTarget => t.source_identity,
            Direction::TargetToSource => t.target_identity,
        };
        let bytes = self.condition.proof_bytes(a.grant(), t, role)?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&bytes, signature)
            .map_err(|_| anyhow::anyhow!("resume peer signature invalid"))
    }
}
pub(crate) fn approve_local(
    runtime: &Runtime,
    gate: Arc<Mutex<()>>,
    store: &IdentityStore,
    request: LocalApprovalRequest<'_>,
    now_ms: u64,
) -> Result<SignedLocalGrant> {
    Ok(approve_inner(runtime, gate, store, request, now_ms, None)?.0)
}
pub(crate) fn approve_resume_local(
    runtime: &Runtime,
    gate: Arc<Mutex<()>>,
    store: &IdentityStore,
    request: LocalApprovalRequest<'_>,
    condition: &super::resume_condition::ResumeProposal,
    now_ms: u64,
) -> Result<SignedLocalResume> {
    let (approval, signature) =
        approve_inner(runtime, gate, store, request, now_ms, Some(condition))?;
    Ok(SignedLocalResume {
        approval,
        condition: condition.clone(),
        signature: signature.context("resume proof missing")?,
    })
}
fn approve_inner(
    runtime: &Runtime,
    gate: Arc<Mutex<()>>,
    store: &IdentityStore,
    request: LocalApprovalRequest<'_>,
    now_ms: u64,
    resume: Option<&super::resume_condition::ResumeProposal>,
) -> Result<(SignedLocalGrant, Option<[u8; 64]>)> {
    // Same Runtime registry -> gate order as source/host. No SQLite or network.
    let _admission = runtime.fleet_source_guard()?;
    let _gate = gate
        .lock()
        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
    let grant = request.proposal;
    ensure!(
        grant.grant().binding.source_session != grant.grant().binding.target_session,
        "source and target sessions must differ"
    );
    let job = grant.job();
    let (fleet, local_device) = store.issuance_scope();
    ensure!(fleet == job.fleet_id, "approval fleet mismatch");
    ensure!(
        now_ms >= grant.grant().issued_at_ms && now_ms < grant.grant().expires_at_ms,
        "local approval outside grant lease"
    );
    let local_hash = device_digest(local_device)?;
    let peer_hash = device_digest(request.peer_device)?;
    let (mine, theirs, path) = match request.role {
        Direction::SourceToTarget => (job.source_device, job.target_device, &job.source_path),
        Direction::TargetToSource => (job.target_device, job.source_device, &job.destination_path),
    };
    ensure!(
        mine == local_hash && theirs == peer_hash,
        "approval role/device mismatch"
    );
    // The other path may use a different OS namespace. Never pretend a local
    // Policy check grants access to that remote filesystem.
    runtime.policy.resolve(path)?;
    let peers = store.peers()?;
    let peer = peers
        .iter()
        .find(|p| p.device() == request.peer_device)
        .context("peer is not enrolled")?;
    ensure!(
        peer.fingerprint(fleet)? == *request.expected_peer,
        "approval peer fingerprint mismatch"
    );
    let endpoint = store
        .endpoints_for(request.peer_device)?
        .into_iter()
        .find(|e| e.slot() == request.endpoint_slot)
        .context("approved peer endpoint slot missing")?;
    let local = store.load_identity()?;
    let public = local.public();
    let peer_public = peer.public_key();
    let (source_identity, target_identity, source_pin, target_pin) = match request.role {
        Direction::SourceToTarget => (
            public,
            peer_public,
            DevicePin::approved(local_device, public)?,
            DevicePin::approved(request.peer_device, peer_public)?,
        ),
        Direction::TargetToSource => (
            peer_public,
            public,
            DevicePin::approved(request.peer_device, peer_public)?,
            DevicePin::approved(local_device, public)?,
        ),
    };
    ensure!(
        request.source_ephemeral != [0; 32]
            && request.target_ephemeral != [0; 32]
            && request.source_ephemeral != request.target_ephemeral,
        "invalid/reflected approval ephemeral keys"
    );
    let transcript = Transcript::for_grant(
        grant,
        source_identity,
        target_identity,
        request.source_ephemeral,
        request.target_ephemeral,
    );
    let signature = local.sign_with_profile(&transcript, request.role, grant.lease_profile())?;
    let resume_signature = resume
        .map(|p| {
            local.sign_resume_message(&super::resume_condition::SigningMessage {
                proposal: p,
                grant,
                transcript: &transcript,
                role: request.role,
            })
        })
        .transpose()?;
    // Refresh local trust after signing too. A concurrent explicit revoke, key
    // change or endpoint rotation observed here refuses the output; no claim of
    // cross-process immutability after this final read is made.
    let current = store.peers()?;
    ensure!(
        current.iter().any(|p| p.device() == request.peer_device
            && p.public_key() == peer_public
            && p.fingerprint(fleet).ok().as_ref() == Some(request.expected_peer)),
        "peer approval changed during signing"
    );
    ensure!(
        store.load_identity()?.public() == public,
        "local identity changed during signing"
    );
    ensure!(
        store
            .endpoints_for(request.peer_device)?
            .iter()
            .any(|e| e == &endpoint),
        "endpoint changed during signing"
    );
    Ok((
        SignedLocalGrant {
            grant: grant.clone(),
            role: request.role,
            transcript,
            signature,
            source_pin,
            target_pin,
            endpoint,
            peer_fingerprint: request.expected_peer.clone(),
        },
        resume_signature,
    ))
}

#[cfg(test)]
#[path = "issuance_tests.rs"]
mod tests;
