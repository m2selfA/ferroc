//! Public bounded proofs through the EXISTING double-present DATA route. The
//! relay correlates local approval only; endpoints verify BOTH signatures.
use super::{
    issuance::LocalApprovalRequest,
    lease::TrustedTimeAnchor,
    protocol::Direction,
    resume_condition::ResumeProposal,
    setup::PreparedSetup,
    setup_agent::LocalSetupApproval,
    setup_resume::{LocalResumeSetupApproval, ResumeSetupLease},
};
use crate::runtime::Runtime;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RoleResumeProof {
    pub condition_digest: [u8; 32],
    pub signature: Vec<u8>,
}
impl RoleResumeProof {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.signature.len() == 64, "invalid resume proof length");
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResumeRouteProofs {
    pub condition_digest: [u8; 32],
    pub source_signature: Vec<u8>,
    pub target_signature: Vec<u8>,
}
/// Owns the actual fresh setup ephemeral while awaiting the peer's recovery
/// proof. No installed lease/File/ticket/IO capability is constructed yet.
pub(crate) struct PendingResumeRoute {
    id: Uuid,
    prepared: PreparedSetup,
    local: LocalSetupApproval,
    role: Direction,
    condition: ResumeProposal,
    own_signature: [u8; 64],
}
impl PendingResumeRoute {
    pub(crate) fn begin(
        runtime: &Arc<Runtime>,
        id: Uuid,
        prepared: PreparedSetup,
        local: LocalSetupApproval,
        condition: ResumeProposal,
    ) -> Result<Self> {
        let a = prepared.approval();
        let role = a.role();
        let t = a.transcript();
        ensure!(
            !id.is_nil()
                && a.grant().digest() == local.proposal.digest()
                && a.grant().lease_profile() == local.proposal.lease_profile()
                && a.peer_fingerprint() == &local.peer.fingerprint
                && a.endpoint().device() == local.peer.device
                && a.endpoint().slot() == local.peer.slot,
            "resume route local approval differs from prepared setup"
        );
        let signed = runtime.approve_fleet_resume(
            &local.identity,
            LocalApprovalRequest {
                proposal: &local.proposal,
                role,
                peer_device: &local.peer.device,
                expected_peer: &local.peer.fingerprint,
                endpoint_slot: local.peer.slot,
                source_ephemeral: t.source_ephemeral,
                target_ephemeral: t.target_ephemeral,
            },
            &condition,
            (local.now)()?,
        )?;
        ensure!(
            signed
                .approval()
                .transcript()
                .bytes_with_profile(role, local.peer.profile)?
                == t.bytes_with_profile(role, local.peer.profile)?,
            "resume route transcript changed"
        );
        let own_signature = *signed.signature();
        Ok(Self {
            id,
            prepared,
            local,
            role,
            condition,
            own_signature,
        })
    }
    pub(crate) fn request(&self) -> serde_json::Value {
        serde_json::json!({"type":"fleetRoute","id":self.id,"grantDigest":self.local.proposal.digest(),
            "resume":RoleResumeProof{condition_digest:self.condition.digest(),signature:self.own_signature.to_vec()}})
    }
    pub(crate) fn finish(
        self,
        runtime: &Arc<Runtime>,
        digest: [u8; 32],
        proofs: ResumeRouteProofs,
        ticket: zeroize::Zeroizing<String>,
        anchor: TrustedTimeAnchor,
    ) -> Result<ResumeSetupLease> {
        ensure!(
            digest == self.local.proposal.digest()
                && proofs.condition_digest == self.condition.digest(),
            "resume route reply differs from local request"
        );
        let source: [u8; 64] = proofs
            .source_signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid source resume proof length"))?;
        let target: [u8; 64] = proofs
            .target_signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid target resume proof length"))?;
        ensure!(
            match self.role {
                Direction::SourceToTarget => source,
                Direction::TargetToSource => target,
            } == self.own_signature,
            "resume route substituted local proof"
        );
        let mut owner = runtime.authenticate_fleet_resume_setup(
            self.prepared,
            LocalResumeSetupApproval {
                local: self.local,
                role: self.role,
                condition: self.condition,
                source_resume_signature: source,
                target_resume_signature: target,
            },
            anchor,
        )?;
        owner.install_route_ticket(self.id, digest, ticket)?;
        Ok(owner)
    }
}
