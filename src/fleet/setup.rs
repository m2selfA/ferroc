//! One-shot LOCAL setup owners and bounded public messages. No ws route/MCP hook.
//! Each owner borrows its real Runtime/store and owns only its own ephemeral.
//! Offer data is never promoted to local policy, peer pins or trusted time.
use super::{
    auth::{EphemeralKey, IdentityKey, Transcript},
    identity::{EndpointSlot, Fingerprint, IdentityStore, PeerEndpoint},
    issuance::{LocalApprovalRequest, SignedLocalGrant},
    job::{FileGrant, JobSpec, LeaseProfile, ValidatedGrant},
    lease::{LeasedRecords, TrustedTimeAnchor},
    protocol::{Direction, device_digest},
};
use crate::runtime::Runtime;
use anyhow::{Context as _, Result, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

pub const SETUP_VERSION: u16 = 1;
/// Raw JSON cap BEFORE deserialization; not a global allocation/inflight bound.
pub const MAX_SETUP_MESSAGE: usize = 32 * 1024;
fn profile_tag(p: LeaseProfile) -> u8 {
    match p {
        LeaseProfile::Rotating => 0,
        LeaseProfile::SingleOwner => 1,
    }
}
fn verify(key: [u8; 32], bytes: &[u8], signature: &[u8]) -> Result<()> {
    ensure!(signature.len() == 64, "invalid setup signature length");
    UnparsedPublicKey::new(&ED25519, key)
        .verify(bytes, signature)
        .map_err(|_| anyhow::anyhow!("setup identity signature invalid"))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetupOffer {
    version: u16,
    profile: u8,
    job: JobSpec,
    grant: FileGrant,
    source_identity: [u8; 32],
    target_identity: [u8; 32],
    source_ephemeral: [u8; 32],
    signature: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetupResponse {
    version: u16,
    offer_digest: [u8; 32],
    target_ephemeral: [u8; 32],
    grant_signature: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetupConfirmation {
    version: u16,
    response_digest: [u8; 32],
    grant_signature: Vec<u8>,
    signature: Vec<u8>,
}
macro_rules! codec {
    ($ty:ty) => {
        impl $ty {
            pub fn encode(&self) -> Result<Vec<u8>> {
                self.shape()?;
                let raw = serde_json::to_vec(self)?;
                ensure!(raw.len() <= MAX_SETUP_MESSAGE, "setup message too large");
                Ok(raw)
            }
            pub fn decode(raw: &[u8]) -> Result<Self> {
                ensure!(
                    !raw.is_empty() && raw.len() <= MAX_SETUP_MESSAGE,
                    "invalid setup message size"
                );
                let value: Self = serde_json::from_slice(raw)?;
                value.shape()?;
                Ok(value)
            }
        }
    };
}
codec!(SetupOffer);
codec!(SetupResponse);
codec!(SetupConfirmation);
impl SetupOffer {
    fn shape(&self) -> Result<()> {
        ensure!(
            self.version == SETUP_VERSION && self.profile <= 1,
            "unsupported setup offer version/profile"
        );
        ensure!(self.signature.len() == 64, "invalid offer signature length");
        ensure!(
            self.source_identity != [0; 32]
                && self.target_identity != [0; 32]
                && self.source_identity != self.target_identity
                && self.source_ephemeral != [0; 32],
            "invalid setup offer keys"
        );
        Ok(())
    }
    fn matches(&self, expected: &ValidatedGrant, local_profile: LeaseProfile) -> Result<()> {
        self.shape()?;
        ensure!(
            self.profile == profile_tag(local_profile) && expected.lease_profile() == local_profile,
            "setup profile differs from local selection"
        );
        ensure!(
            &self.job == expected.job() && &self.grant == expected.grant(),
            "unexpected setup proposal"
        );
        Ok(())
    }
    fn bytes(&self, local_profile: LeaseProfile) -> Result<Vec<u8>> {
        self.shape()?;
        ensure!(
            self.profile == profile_tag(local_profile),
            "setup profile differs from local selection"
        );
        let p = self
            .grant
            .clone()
            .validate_for_profile(self.job.clone(), local_profile)?;
        ensure!(
            p.grant().binding.source_session != p.grant().binding.target_session,
            "setup sessions must differ"
        );
        let mut b = b"ferroc:fleet:setup-offer:v1\0".to_vec();
        b.extend_from_slice(&self.version.to_be_bytes());
        b.push(self.profile);
        b.extend_from_slice(&p.job().digest()?);
        b.extend_from_slice(&p.digest());
        b.extend_from_slice(&self.source_identity);
        b.extend_from_slice(&self.target_identity);
        b.extend_from_slice(&self.source_ephemeral);
        Ok(b)
    }
    fn digest(&self, profile: LeaseProfile) -> Result<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(self.bytes(profile)?);
        h.update(&self.signature);
        Ok(h.finalize().into())
    }
    /// Untrusted declared-profile structural correlation for the relay ONLY.
    pub(super) fn routing_context(&self) -> Result<(super::protocol::Binding, [u8; 32])> {
        self.shape()?;
        let profile = if self.profile == 0 {
            LeaseProfile::Rotating
        } else {
            LeaseProfile::SingleOwner
        };
        Ok((self.grant.binding.clone(), self.digest(profile)?))
    }
    /// UNTRUSTED metadata for a coordinator's independent local decision.
    pub fn offered_job(&self) -> &JobSpec {
        &self.job
    }
    /// UNTRUSTED structure, not a local grant approval.
    pub fn offered_grant(&self) -> &FileGrant {
        &self.grant
    }
}
impl SetupResponse {
    /// Structural hash only: caller must still verify enrolled-peer proofs.
    pub(super) fn routing_context(&self) -> Result<([u8; 32], [u8; 32])> {
        self.shape()?;
        let mut b = b"ferroc:fleet:setup-response:v1\0".to_vec();
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.offer_digest);
        b.extend_from_slice(&self.target_ephemeral);
        b.extend_from_slice(&self.grant_signature);
        b.extend_from_slice(&self.signature);
        Ok((self.offer_digest, Sha256::digest(b).into()))
    }
    fn shape(&self) -> Result<()> {
        ensure!(
            self.version == SETUP_VERSION,
            "unsupported setup response version"
        );
        ensure!(
            self.signature.len() == 64 && self.grant_signature.len() == 64,
            "invalid response signature length"
        );
        ensure!(
            self.offer_digest != [0; 32] && self.target_ephemeral != [0; 32],
            "invalid setup response context"
        );
        Ok(())
    }
    fn bytes(&self, offer: &SetupOffer, profile: LeaseProfile) -> Result<Vec<u8>> {
        self.shape()?;
        ensure!(
            self.offer_digest == offer.digest(profile)?,
            "setup response belongs to another offer"
        );
        ensure!(
            self.target_ephemeral != offer.source_ephemeral,
            "reflected setup ephemeral"
        );
        let mut b = b"ferroc:fleet:setup-response:v1\0".to_vec();
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.offer_digest);
        b.extend_from_slice(&self.target_ephemeral);
        b.extend_from_slice(&self.grant_signature);
        Ok(b)
    }
    fn digest(&self, offer: &SetupOffer, profile: LeaseProfile) -> Result<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(self.bytes(offer, profile)?);
        h.update(&self.signature);
        Ok(h.finalize().into())
    }
}
impl SetupConfirmation {
    pub(super) fn routing_response_digest(&self) -> Result<[u8; 32]> {
        self.shape()?;
        Ok(self.response_digest)
    }
    fn shape(&self) -> Result<()> {
        ensure!(
            self.version == SETUP_VERSION,
            "unsupported setup confirmation version"
        );
        ensure!(
            self.signature.len() == 64
                && self.grant_signature.len() == 64
                && self.response_digest != [0; 32],
            "invalid setup confirmation context"
        );
        Ok(())
    }
    fn bytes(
        &self,
        offer: &SetupOffer,
        response: &SetupResponse,
        profile: LeaseProfile,
    ) -> Result<Vec<u8>> {
        self.shape()?;
        ensure!(
            self.response_digest == response.digest(offer, profile)?,
            "confirmation belongs to another response"
        );
        let mut b = b"ferroc:fleet:setup-confirm:v1\0".to_vec();
        b.extend_from_slice(&self.version.to_be_bytes());
        b.extend_from_slice(&self.response_digest);
        b.extend_from_slice(&self.grant_signature);
        Ok(b)
    }
}
/// Closed, crate-private signing domains. No arbitrary sign-bytes entry point.
pub(super) enum SigningMessage<'a> {
    Offer(&'a SetupOffer, LeaseProfile),
    Response(&'a SetupOffer, &'a SetupResponse, LeaseProfile),
    Confirmation(
        &'a SetupOffer,
        &'a SetupResponse,
        &'a SetupConfirmation,
        LeaseProfile,
    ),
}
impl SigningMessage<'_> {
    fn offer(&self) -> &SetupOffer {
        match self {
            Self::Offer(o, _) | Self::Response(o, _, _) | Self::Confirmation(o, _, _, _) => o,
        }
    }
    fn role(&self) -> Direction {
        match self {
            Self::Response(..) => Direction::TargetToSource,
            _ => Direction::SourceToTarget,
        }
    }
    pub(super) fn identity_and_bytes(&self) -> Result<([u8; 32], Vec<u8>)> {
        Ok(match self {
            Self::Offer(o, p) => (o.source_identity, o.bytes(*p)?),
            Self::Response(o, r, p) => (o.target_identity, r.bytes(o, *p)?),
            Self::Confirmation(o, r, c, p) => (o.source_identity, c.bytes(o, r, *p)?),
        })
    }
}

/// Explicit LOCAL peer/profile decision. Never deserialized from message data.
#[derive(Clone, Copy)]
pub struct SetupPeer<'a> {
    pub device: &'a str,
    pub expected_fingerprint: &'a Fingerprint,
    pub endpoint_slot: EndpointSlot,
    pub profile: LeaseProfile,
}
struct LocalContext<'a> {
    runtime: &'a Runtime,
    store: &'a IdentityStore,
    peer: SetupPeer<'a>,
    gate: Arc<Mutex<()>>,
}
#[derive(PartialEq, Eq)]
struct Snapshot {
    source: [u8; 32],
    target: [u8; 32],
    endpoint: PeerEndpoint,
}
impl LocalContext<'_> {
    // Called only inside the actual Runtime registry -> fs_gate critical section.
    fn view(
        &self,
        p: &ValidatedGrant,
        role: Direction,
        now_ms: u64,
    ) -> Result<(IdentityKey, Snapshot)> {
        ensure!(
            p.lease_profile() == self.peer.profile,
            "setup profile differs from local selection"
        );
        let (fleet, local_device) = self.store.issuance_scope();
        ensure!(fleet == p.job().fleet_id, "setup fleet mismatch");
        ensure!(
            now_ms >= p.grant().issued_at_ms && now_ms < p.grant().expires_at_ms,
            "setup outside grant lease"
        );
        let (mine, theirs, path) = match role {
            Direction::SourceToTarget => (
                p.job().source_device,
                p.job().target_device,
                &p.job().source_path,
            ),
            Direction::TargetToSource => (
                p.job().target_device,
                p.job().source_device,
                &p.job().destination_path,
            ),
        };
        ensure!(
            mine == device_digest(local_device)? && theirs == device_digest(self.peer.device)?,
            "setup role/device mismatch"
        );
        self.runtime.policy.resolve(path)?;
        let peers = self.store.peers()?;
        let peer = peers
            .iter()
            .find(|v| v.device() == self.peer.device)
            .context("setup peer not enrolled")?;
        ensure!(
            peer.fingerprint(fleet)? == *self.peer.expected_fingerprint,
            "setup fingerprint mismatch"
        );
        let endpoint = self
            .store
            .endpoints_for(self.peer.device)?
            .into_iter()
            .find(|v| v.slot() == self.peer.endpoint_slot)
            .context("setup endpoint missing")?;
        let key = self.store.load_identity()?;
        let (source, target) = match role {
            Direction::SourceToTarget => (key.public(), peer.public_key()),
            Direction::TargetToSource => (peer.public_key(), key.public()),
        };
        Ok((
            key,
            Snapshot {
                source,
                target,
                endpoint,
            },
        ))
    }
    fn snapshot(&self, p: &ValidatedGrant, role: Direction, now: u64) -> Result<Snapshot> {
        let _admission = self.runtime.fleet_source_guard()?;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        Ok(self.view(p, role, now)?.1)
    }
    fn sign(
        &self,
        p: &ValidatedGrant,
        expected: &Snapshot,
        message: SigningMessage<'_>,
        now: u64,
    ) -> Result<Vec<u8>> {
        message.offer().matches(p, self.peer.profile)?;
        let role = message.role();
        let _admission = self.runtime.fleet_source_guard()?;
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        let (key, current) = self.view(p, role, now)?;
        ensure!(
            &current == expected
                && current.source == message.offer().source_identity
                && current.target == message.offer().target_identity,
            "setup local approval changed"
        );
        let signature = key.sign_setup_message(&message)?;
        ensure!(
            self.view(p, role, now)?.1 == current,
            "setup local approval changed during signing"
        );
        Ok(signature.to_vec())
    }
    fn approve(
        &self,
        p: &ValidatedGrant,
        role: Direction,
        source: [u8; 32],
        target: [u8; 32],
        now: u64,
    ) -> Result<SignedLocalGrant> {
        self.runtime.approve_fleet_grant(
            self.store,
            LocalApprovalRequest {
                proposal: p,
                role,
                peer_device: self.peer.device,
                expected_peer: self.peer.expected_fingerprint,
                endpoint_slot: self.peer.endpoint_slot,
                source_ephemeral: source,
                target_ephemeral: target,
            },
            now,
        )
    }
}
fn check_approval(
    a: &SignedLocalGrant,
    s: &Snapshot,
    o: &SetupOffer,
    r: &SetupResponse,
) -> Result<()> {
    ensure!(
        a.transcript().source_identity == s.source
            && a.transcript().target_identity == s.target
            && a.transcript().source_ephemeral == o.source_ephemeral
            && a.transcript().target_ephemeral == r.target_ephemeral
            && a.endpoint() == &s.endpoint,
        "setup approval changed"
    );
    Ok(())
}
/// Not Clone/Serialize; Drop discards only this ephemeral, never deletes files.
pub struct PendingSource<'a> {
    approved_at_ms: u64,
    context: LocalContext<'a>,
    proposal: ValidatedGrant,
    snapshot: Snapshot,
    ephemeral: EphemeralKey,
    offer: SetupOffer,
}
pub struct PendingTarget<'a> {
    approved_at_ms: u64,
    context: LocalContext<'a>,
    approval: SignedLocalGrant,
    snapshot: Snapshot,
    ephemeral: EphemeralKey,
    offer: SetupOffer,
    response: SetupResponse,
}
/// Both proofs checked. Still requires a separate trusted LOCAL time anchor.
pub struct PreparedSetup {
    ephemeral: EphemeralKey,
    approval: SignedLocalGrant,
    peer_signature: [u8; 64],
}
impl PreparedSetup {
    /// Core-only handoff of this exact setup's private ephemeral into BOTH-proof
    /// resume authentication. The condition/anchor are trusted LOCAL decisions;
    /// ordinary auth signatures cannot substitute for either new-domain proof.
    /// This installs no Runtime attachment, route ticket, File, DB or coverage,
    /// and does not re-check a live IdentityStore. Later Runtime/IO admission and
    /// current local peer approval remain independent requirements. Not a wire
    /// adapter or an unchecked LeasedRecords conversion; consumes self once.
    /// ```compile_fail
    /// use ferroc::fleet::{setup::PreparedSetup, resume_condition::ResumeProposal, lease::TrustedTimeAnchor};
    /// fn cannot_reuse(p: PreparedSetup, c: ResumeProposal, a: TrustedTimeAnchor, s: [u8;64], t: [u8;64]) {
    ///     let _ = p.authenticate_resume(c, &s, &t, a);
    ///     let _ = p.approval();
    /// }
    /// ```
    pub fn authenticate_resume(
        self,
        condition: super::resume_condition::ResumeProposal,
        source_resume_signature: &[u8; 64],
        target_resume_signature: &[u8; 64],
        anchor: TrustedTimeAnchor,
    ) -> Result<super::resume_lease::ResumeLease> {
        let a = &self.approval;
        let (source, target) = match a.role() {
            Direction::SourceToTarget => (a.signature(), &self.peer_signature),
            Direction::TargetToSource => (&self.peer_signature, a.signature()),
        };
        self.ephemeral.authenticate_resume_leased(
            condition,
            a.transcript(),
            a.role(),
            a.grant(),
            a.source_pin(),
            a.target_pin(),
            source,
            target,
            source_resume_signature,
            target_resume_signature,
            anchor,
        )
    }
    pub fn approval(&self) -> &SignedLocalGrant {
        &self.approval
    }
    pub fn authenticate(self, anchor: TrustedTimeAnchor) -> Result<LeasedRecords> {
        let a = &self.approval;
        let (source, target) = match a.role() {
            Direction::SourceToTarget => (a.signature(), &self.peer_signature),
            Direction::TargetToSource => (&self.peer_signature, a.signature()),
        };
        self.ephemeral.authenticate_leased(
            a.transcript(),
            a.role(),
            a.grant(),
            a.source_pin(),
            a.target_pin(),
            source,
            target,
            anchor,
        )
    }
}
pub(crate) fn begin_source<'a>(
    runtime: &'a Runtime,
    gate: Arc<Mutex<()>>,
    store: &'a IdentityStore,
    p: &ValidatedGrant,
    peer: SetupPeer<'a>,
    now: u64,
) -> Result<(PendingSource<'a>, SetupOffer)> {
    let context = LocalContext {
        runtime,
        gate,
        store,
        peer,
    };
    let snapshot = context.snapshot(p, Direction::SourceToTarget, now)?;
    let ephemeral = EphemeralKey::generate();
    let mut offer = SetupOffer {
        version: SETUP_VERSION,
        profile: profile_tag(peer.profile),
        job: p.job().clone(),
        grant: p.grant().clone(),
        source_identity: snapshot.source,
        target_identity: snapshot.target,
        source_ephemeral: ephemeral.public(),
        signature: vec![0; 64],
    };
    offer.signature = context.sign(
        p,
        &snapshot,
        SigningMessage::Offer(&offer, peer.profile),
        now,
    )?;
    Ok((
        PendingSource {
            approved_at_ms: now,
            context,
            proposal: p.clone(),
            snapshot,
            ephemeral,
            offer: offer.clone(),
        },
        offer,
    ))
}
pub(crate) fn accept_target<'a>(
    runtime: &'a Runtime,
    gate: Arc<Mutex<()>>,
    store: &'a IdentityStore,
    p: &ValidatedGrant,
    peer: SetupPeer<'a>,
    offer: SetupOffer,
    now: u64,
) -> Result<(PendingTarget<'a>, SetupResponse)> {
    let context = LocalContext {
        runtime,
        gate,
        store,
        peer,
    };
    offer.matches(p, peer.profile)?;
    let snapshot = context.snapshot(p, Direction::TargetToSource, now)?;
    ensure!(
        snapshot.source == offer.source_identity && snapshot.target == offer.target_identity,
        "unapproved setup identities"
    );
    verify(
        snapshot.source,
        &offer.bytes(peer.profile)?,
        &offer.signature,
    )?;
    let ephemeral = EphemeralKey::generate();
    let approval = context.approve(
        p,
        Direction::TargetToSource,
        offer.source_ephemeral,
        ephemeral.public(),
        now,
    )?;
    let mut response = SetupResponse {
        version: SETUP_VERSION,
        offer_digest: offer.digest(peer.profile)?,
        target_ephemeral: ephemeral.public(),
        grant_signature: approval.signature().to_vec(),
        signature: vec![0; 64],
    };
    check_approval(&approval, &snapshot, &offer, &response)?;
    response.signature = context.sign(
        p,
        &snapshot,
        SigningMessage::Response(&offer, &response, peer.profile),
        now,
    )?;
    Ok((
        PendingTarget {
            approved_at_ms: now,
            context,
            approval,
            snapshot,
            ephemeral,
            offer,
            response: response.clone(),
        },
        response,
    ))
}
impl PendingSource<'_> {
    /// Consumes even on error: no hidden retry or restored source capability.
    pub fn confirm(
        self,
        response: SetupResponse,
        now: u64,
    ) -> Result<(PreparedSetup, SetupConfirmation)> {
        ensure!(
            now >= self.approved_at_ms,
            "setup local authority time moved backwards"
        );
        let p = &self.proposal;
        let profile = self.context.peer.profile;
        verify(
            self.snapshot.target,
            &response.bytes(&self.offer, profile)?,
            &response.signature,
        )?;
        let t = Transcript::for_grant(
            p,
            self.snapshot.source,
            self.snapshot.target,
            self.offer.source_ephemeral,
            response.target_ephemeral,
        );
        verify(
            self.snapshot.target,
            &t.bytes_with_profile(Direction::TargetToSource, profile)?,
            &response.grant_signature,
        )?;
        let approval = self.context.approve(
            p,
            Direction::SourceToTarget,
            self.offer.source_ephemeral,
            response.target_ephemeral,
            now,
        )?;
        check_approval(&approval, &self.snapshot, &self.offer, &response)?;
        let mut confirmation = SetupConfirmation {
            version: SETUP_VERSION,
            response_digest: response.digest(&self.offer, profile)?,
            grant_signature: approval.signature().to_vec(),
            signature: vec![0; 64],
        };
        confirmation.signature = self.context.sign(
            p,
            &self.snapshot,
            SigningMessage::Confirmation(&self.offer, &response, &confirmation, profile),
            now,
        )?;
        let peer_signature = response
            .grant_signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid target signature"))?;
        Ok((
            PreparedSetup {
                ephemeral: self.ephemeral,
                approval,
                peer_signature,
            },
            confirmation,
        ))
    }
}
impl PendingTarget<'_> {
    pub fn finish(self, confirmation: SetupConfirmation, now: u64) -> Result<PreparedSetup> {
        ensure!(
            now >= self.approved_at_ms,
            "setup local authority time moved backwards"
        );
        let profile = self.context.peer.profile;
        verify(
            self.snapshot.source,
            &confirmation.bytes(&self.offer, &self.response, profile)?,
            &confirmation.signature,
        )?;
        verify(
            self.snapshot.source,
            &self
                .approval
                .transcript()
                .bytes_with_profile(Direction::SourceToTarget, profile)?,
            &confirmation.grant_signature,
        )?;
        let fresh = self.context.approve(
            self.approval.grant(),
            Direction::TargetToSource,
            self.offer.source_ephemeral,
            self.response.target_ephemeral,
            now,
        )?;
        check_approval(&fresh, &self.snapshot, &self.offer, &self.response)?;
        ensure!(
            fresh.signature() == self.approval.signature(),
            "target signing context changed"
        );
        let peer_signature = confirmation
            .grant_signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid source signature"))?;
        Ok(PreparedSetup {
            ephemeral: self.ephemeral,
            approval: fresh,
            peer_signature,
        })
    }
}
#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
