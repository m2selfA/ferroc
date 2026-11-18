use super::*;
use crate::fleet::{
    fence::{FencedConnection, OwnerFence},
    resume_admission::{verify_source_condition_signature, verify_target_resume_admission},
    resume_condition::ResumeProposal,
};
use std::sync::Arc;

struct Round {
    db: FencedConnection,
    key: JobKey,
    job: JobSpec,
    checkpoint: crate::fleet::journal::PrefixCheckpoint,
    grant: ValidatedGrant,
    transcript: Transcript,
    proposal: ResumeProposal,
    signature: [u8; 64],
    runtime: crate::runtime::Runtime,
    path: std::path::PathBuf,
    _temp: tempfile::TempDir,
}
fn sign(proposal: &ResumeProposal, grant: &ValidatedGrant, t: &Transcript) -> [u8; 64] {
    let bytes = proposal
        .proof_bytes(grant, t, Direction::SourceToTarget)
        .unwrap();
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x11; 32]).unwrap();
    kp.sign(&bytes).as_ref().try_into().unwrap()
}
fn round() -> Round {
    let (temp, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (mut source, mut receiver) = open(&host, &path, b"abc");
    let owner = receiver.snapshot().owner();
    let key = JobKey::from_job(receiver.snapshot().job());
    receiver.enable_retained_checkpoints().unwrap();
    receiver
        .write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let checkpoint = receiver.capture_retained_checkpoint().unwrap();
    drop(receiver);
    drop(source);
    host.close().unwrap();
    drop(host);
    let fence = OwnerFence::acquire(&path).unwrap();
    let mut db = fence.open_connection().unwrap();
    db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    let snapshot = db.journal().unwrap().get(&key).unwrap().unwrap();
    let job = snapshot.job().clone();
    let offer = Offer::new(&path, b"abc", 0);
    let mut new_job = job.clone();
    new_job.transfer_id = Uuid::new_v4();
    new_job.file_id = Uuid::new_v4();
    new_job.idempotency_key = "resume-fresh-attempt".into();
    let mut next = offer.g.grant().clone();
    next.binding.transfer_id = new_job.transfer_id;
    next.binding.file_id = new_job.file_id;
    next.binding.source_session = Uuid::new_v4();
    next.binding.target_session = Uuid::new_v4();
    next.binding.authorization_id = Uuid::new_v4();
    next.binding.key_epoch = Uuid::new_v4();
    next.job_digest = new_job.digest().unwrap();
    let grant = next
        .validate_for_profile(new_job, crate::fleet::job::LeaseProfile::SingleOwner)
        .unwrap();
    let transcript = Transcript::for_grant(
        &grant,
        IdentityKey::from_test_seed([0x11; 32]).public(),
        IdentityKey::from_test_seed([0x22; 32]).public(),
        offer.source.public(),
        offer.target.public(),
    );
    let readback = db
        .inspect_retained_checkpoint(&key, &runtime.policy, Arc::default(), 8)
        .unwrap();
    let proposal = ResumeProposal::from_target_readback(&job, &readback, &grant).unwrap();
    let signature = sign(&proposal, &grant, &transcript);
    Round {
        db,
        key,
        job,
        checkpoint,
        grant,
        transcript,
        proposal,
        signature,
        runtime,
        path,
        _temp: temp,
    }
}
impl Round {
    fn snapshot(&mut self) -> Vec<u8> {
        serde_json::to_vec(&self.db.journal().unwrap().get(&self.key).unwrap().unwrap()).unwrap()
    }
    fn verify(
        &mut self,
        max: u64,
    ) -> anyhow::Result<crate::fleet::checkpoint_readback::CheckpointReadback> {
        verify_target_resume_admission(
            &mut self.db,
            &self.runtime.policy,
            Arc::default(),
            &self.job,
            &self.proposal,
            &self.signature,
            &self.grant,
            &self.transcript,
            max,
        )
    }
}
#[test]
fn real_same_fence_readback_succeeds_without_metadata_writes() {
    let mut f = round();
    let before = f.snapshot();
    verify_source_condition_signature(&f.proposal, &f.grant, &f.transcript, &f.signature).unwrap();
    let observed = f.verify(8).unwrap();
    assert_eq!(observed.checkpoint(), &f.checkpoint);
    assert_eq!(f.snapshot(), before);
}
#[test]
fn zero_and_garbage_signatures_fail_before_stage_io() {
    let mut f = round();
    let before = f.snapshot();
    let path =
        f.db.journal()
            .unwrap()
            .get(&f.key)
            .unwrap()
            .unwrap()
            .stage()
            .unwrap()
            .path()
            .to_path_buf();
    std::fs::write(&path, b"xyz").unwrap();
    for signature in [[0; 64], [0x5a; 64]] {
        f.signature = signature;
        assert!(
            f.verify(8)
                .unwrap_err()
                .to_string()
                .contains("source condition signature invalid")
        );
        assert_eq!(f.snapshot(), before);
    }
}
#[test]
fn new_fence_without_explicit_recovery_is_rejected() {
    let mut f = round();
    let fence = OwnerFence::acquire(&f.path).err();
    assert!(fence.is_some()); // the original live fence is still exclusive
    let path = f.path.clone();
    // Moving into a new fence is not an authorization to recover its old owner.
    drop(f.db);
    f.db = OwnerFence::acquire(&path)
        .unwrap()
        .open_connection()
        .unwrap();
    assert!(
        f.verify(8)
            .unwrap_err()
            .to_string()
            .contains("same-DB recovered")
    );
}
fn mismatched_checkpoint(field: &str) {
    let mut f = round();
    let before = f.snapshot();
    let mut json = serde_json::to_value(&f.checkpoint).unwrap();
    match field {
        "revision" => json["revision"] = (f.checkpoint.revision() + 1).into(),
        "grant_digest" => json["grant_digest"] = serde_json::json!([0x41; 32].to_vec()),
        "authorization" => json["binding"]["authorizationId"] = Uuid::new_v4().to_string().into(),
        "epoch" => json["binding"]["keyEpoch"] = Uuid::new_v4().to_string().into(),
        _ => panic!("unknown checkpoint mutation"),
    }
    let changed = serde_json::from_value(json).unwrap();
    // The signature is genuine and the bytes/SHA still agree; ONLY the full
    // signed checkpoint binding can distinguish this from the live row.
    f.proposal = ResumeProposal::build(&f.job, &changed, &f.grant).unwrap();
    f.signature = sign(&f.proposal, &f.grant, &f.transcript);
    assert!(f.verify(8).is_err(), "accepted changed checkpoint {field}");
    assert_eq!(f.snapshot(), before);
}
#[test]
fn checkpoint_revision_is_bound() {
    mismatched_checkpoint("revision");
}
#[test]
fn checkpoint_grant_digest_is_bound() {
    mismatched_checkpoint("grant_digest");
}
#[test]
fn checkpoint_authorization_is_bound() {
    mismatched_checkpoint("authorization");
}
#[test]
fn checkpoint_epoch_is_bound() {
    mismatched_checkpoint("epoch");
}
#[test]
fn prefix_budget_refuses_without_metadata_writes() {
    let mut f = round();
    let before = f.snapshot();
    assert!(f.verify(2).unwrap_err().to_string().contains("budget"));
    assert_eq!(f.snapshot(), before);
}
#[test]
fn late_prefix_rewrite_is_rejected_without_metadata_writes() {
    let mut f = round();
    let before = f.snapshot();
    let path =
        f.db.journal()
            .unwrap()
            .get(&f.key)
            .unwrap()
            .unwrap()
            .stage()
            .unwrap()
            .path()
            .to_path_buf();
    std::fs::write(path, b"xyz").unwrap();
    assert!(
        f.verify(8)
            .unwrap_err()
            .to_string()
            .contains("prefix mismatch")
    );
    assert_eq!(f.snapshot(), before);
}
