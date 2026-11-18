//! Verified target adoption of a historical retained checkpoint. Same DB fence
//! only; the source NEVER learns the stage path, IDs or checkpoint from here.
use crate::config::Policy;
use crate::fleet::{
    checkpoint_readback::CheckpointReadback,
    fence::FencedConnection,
    journal::{JobKey, Journal},
    resume_condition::ResumeProposal,
};
use anyhow::{Context, Result, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};
use std::sync::{Arc, Mutex};
impl ResumeProposal {
    /// Target-side proposal from a real stopped-owner checkpoint readback.
    pub fn from_target_readback(
        old: &crate::fleet::job::JobSpec,
        readback: &CheckpointReadback,
        next: &crate::fleet::job::ValidatedGrant,
    ) -> Result<Self> {
        Self::build(old, readback.checkpoint(), next)
    }
}
/// Rebuild the exact proof bytes the SOURCE side signed. The caller supplies the
/// fresh grant and transcript from its own approved session; nothing signs here.
fn source_proof_bytes(
    proposal: &ResumeProposal,
    grant: &crate::fleet::job::ValidatedGrant,
    transcript: &crate::fleet::auth::Transcript,
) -> Result<Vec<u8>> {
    proposal.proof_bytes(
        grant,
        transcript,
        crate::fleet::protocol::Direction::SourceToTarget,
    )
}
/// Verify a source condition signature against the locally approved source
/// identity bound in the transcript, before any stage read.
pub fn verify_source_condition_signature(
    proposal: &ResumeProposal,
    grant: &crate::fleet::job::ValidatedGrant,
    transcript: &crate::fleet::auth::Transcript,
    signature: &[u8; 64],
) -> Result<()> {
    let bytes = source_proof_bytes(proposal, grant, transcript)?;
    UnparsedPublicKey::new(&ED25519, transcript.source_identity)
        .verify(&bytes, signature)
        .map_err(|_| anyhow::anyhow!("resume source condition signature invalid"))
}
/// Verify the declared condition against the ACTUAL recovered stage readback.
/// Not a live writer, settled file, publication permit or debt release.
#[allow(clippy::too_many_arguments)]
pub fn verify_target_resume_admission(
    db: &mut FencedConnection,
    p: &Policy,
    fs_gate: Arc<Mutex<()>>,
    job: &crate::fleet::job::JobSpec,
    proposal: &ResumeProposal,
    source_signature: &[u8; 64],
    grant: &crate::fleet::job::ValidatedGrant,
    transcript: &crate::fleet::auth::Transcript,
    max_prefix_bytes: u64,
) -> Result<CheckpointReadback> {
    ensure!(
        !job.transfer_id.is_nil() && job.validate().is_ok(),
        "invalid resume job"
    );
    verify_source_condition_signature(proposal, grant, transcript, source_signature)?;
    let _gate = fs_gate
        .lock()
        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
    let key = JobKey::from_job(job);
    let snapshot = Journal::existing_fenced(&mut db.connection, &db.fence)?
        .get(&key)?
        .context("resume job missing")?;
    ensure!(
        snapshot.job().digest()? == proposal.old_job_binding_digest()
            && snapshot.retained_stage().is_some(),
        "proposal does not match recovered stage"
    );
    // The condition signs ALL historical checkpoint fields, not just its
    // byte count/SHA. Rebuild from the row under this live fence so a genuine
    // signature for a different revision/grant/epoch cannot borrow this stage.
    let checkpoint = snapshot
        .retained_stage()
        .and_then(|r| r.checkpoint())
        .context("resume checkpoint missing")?;
    let expected = ResumeProposal::build(snapshot.job(), checkpoint, grant)?;
    ensure!(
        expected.canonical_bytes() == proposal.canonical_bytes()
            && expected.digest() == proposal.digest(),
        "signed resume checkpoint binding differs from recovered row"
    );
    let readback =
        db.inspect_retained_checkpoint(&key, p, Arc::new(Mutex::new(())), max_prefix_bytes)?;
    ensure!(
        readback.observed_revision() == snapshot.revision()
            && readback.checkpoint().bytes() == proposal.checkpoint_length()
            && readback.checkpoint().sha256() == proposal.prefix_sha256(),
        "condition no longer matches current stage readback"
    );
    Ok(readback)
}
