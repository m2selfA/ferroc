//! Typed dual resume-proof binding to ONE fresh ordinary leased authentication.
//! No File/DB, host admission, cursor restoration, Runtime attachment or network.
//! Pins/grant/clock are trusted LOCAL caller inputs, never imported peer metadata.
use super::{
    auth::{DevicePin, EphemeralKey, Transcript},
    job::ValidatedGrant,
    lease::{LeasedRecords, TrustedTimeAnchor},
    protocol::Direction,
    resume_condition::ResumeProposal,
};
use anyhow::{Result, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};

/// Owns the exact NEW auth-v2 lease whose transcript BOTH resume proofs signed.
/// Descriptive getters confer no File/host/coverage or restart permission. It is
/// not Runtime-bound: later IO admission must enforce its own stop/policy cut,
/// actual stage/prefix verification, and consume this owner exactly once.
/// ```compile_fail
/// fn no_clone(r:ferroc::fleet::resume_lease::ResumeLease){let _=r.clone();}
/// ```
/// ```compile_fail
/// fn no_unwrap(r:ferroc::fleet::resume_lease::ResumeLease){let _=r.records;}
/// ```
/// ```compile_fail
/// let _:ferroc::fleet::resume_lease::ResumeLease=serde_json::from_str("{}").unwrap();
/// ```
pub struct ResumeLease {
    records: LeasedRecords,
    condition: ResumeProposal,
    role: Direction,
}
impl ResumeLease {
    // Borrow only, visible inside fleet; never export owned/untyped records.
    pub(in crate::fleet) fn records_mut(&mut self) -> &mut LeasedRecords {
        &mut self.records
    }
    #[cfg(test)]
    pub(in crate::fleet) fn test_expire(&mut self) {
        self.records.test_expire();
    }
    pub(in crate::fleet) fn into_target(mut self) -> Result<(ResumeProposal, LeasedRecords)> {
        self.records.receive_admission()?;
        Ok((self.condition, self.records))
    }
    pub(in crate::fleet) fn into_source(mut self) -> Result<(ResumeProposal, LeasedRecords)> {
        ensure!(
            self.role == Direction::SourceToTarget,
            "source continuation requires Source role"
        );
        self.records.check_commit_admission()?;
        Ok((self.condition, self.records))
    }
    pub fn grant(&self) -> &ValidatedGrant {
        self.records.grant()
    }
    pub fn condition(&self) -> &ResumeProposal {
        &self.condition
    }
    pub fn local_role(&self) -> Direction {
        self.role
    }
}
impl EphemeralKey {
    /// Consumes the actual fresh private ephemeral and caller-selected anchor.
    /// Validates BOTH new-domain proofs against the SAME transcript passed to
    /// ordinary leased auth (which also checks pins, role, private ephemeral,
    /// ordinary auth signatures and local clock). No unchecked LeasedRecords
    /// conversion exists; normal auth signatures cannot substitute resume proofs.
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate_resume_leased(
        self,
        condition: ResumeProposal,
        transcript: &Transcript,
        role: Direction,
        expected: &ValidatedGrant,
        source_pin: &DevicePin,
        target_pin: &DevicePin,
        source_auth_signature: &[u8; 64],
        target_auth_signature: &[u8; 64],
        source_resume_signature: &[u8; 64],
        target_resume_signature: &[u8; 64],
        anchor: TrustedTimeAnchor,
    ) -> Result<ResumeLease> {
        let source = condition.proof_bytes(expected, transcript, Direction::SourceToTarget)?;
        let target = condition.proof_bytes(expected, transcript, Direction::TargetToSource)?;
        ensure!(
            UnparsedPublicKey::new(&ED25519, transcript.source_identity)
                .verify(&source, source_resume_signature)
                .is_ok(),
            "resume source proof signature invalid"
        );
        ensure!(
            UnparsedPublicKey::new(&ED25519, transcript.target_identity)
                .verify(&target, target_resume_signature)
                .is_ok(),
            "resume target proof signature invalid"
        );
        let records = self.authenticate_leased(
            transcript,
            role,
            expected,
            source_pin,
            target_pin,
            source_auth_signature,
            target_auth_signature,
            anchor,
        )?;
        Ok(ResumeLease {
            records,
            condition,
            role,
        })
    }
}
#[cfg(test)]
#[path = "resume_lease_tests.rs"]
mod tests;
