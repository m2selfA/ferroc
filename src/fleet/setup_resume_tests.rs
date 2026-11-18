//! Actual three-phase setup ephemerals + separately approved resume signatures.
//! PUBLIC wrapping keys; historical checkpoint SYNTHETIC. Crypto-only, no IO resume.
use super::*;
#[path = "setup_resume_runtime_tests.rs"]
mod runtime_tests;
use crate::fleet::{
    issuance::{LocalApprovalRequest, SignedLocalResume},
    journal::PrefixCheckpoint,
    resume_condition::ResumeProposal,
};
fn prepared(f: &Fixture) -> (PreparedSetup, PreparedSetup) {
    let (a, offer) = f.begin();
    let offer = SetupOffer::decode(&offer.encode().unwrap()).unwrap();
    let (b, response) = f.accept(offer);
    let response = SetupResponse::decode(&response.encode().unwrap()).unwrap();
    let (a, confirmation) = a.confirm(response, 200).unwrap();
    let b = b
        .finish(
            SetupConfirmation::decode(&confirmation.encode().unwrap()).unwrap(),
            200,
        )
        .unwrap();
    (a, b)
}
fn condition(f: &Fixture, revision: u64) -> (ResumeProposal, JobSpec, PrefixCheckpoint) {
    let mut old = f.proposal.job().clone();
    old.transfer_id = Uuid::new_v4();
    old.file_id = Uuid::new_v4();
    old.idempotency_key = "old-prepared-resume".into();
    old.deadline_ms = 99;
    let mut binding = f.proposal.grant().binding.clone();
    binding.transfer_id = old.transfer_id;
    binding.file_id = old.file_id;
    binding.source_session = Uuid::new_v4();
    binding.target_session = Uuid::new_v4();
    binding.authorization_id = Uuid::new_v4();
    binding.key_epoch = Uuid::new_v4();
    let cp:PrefixCheckpoint=serde_json::from_value(serde_json::json!({"version":1,"bytes":1,"sha256":<[u8;32]>::from(Sha256::digest(b"a")),"job_digest":old.digest().unwrap(),"grant_digest":([9u8;32]),"binding":binding,"revision":revision})).unwrap();
    (
        ResumeProposal::build(&old, &cp, &f.proposal).unwrap(),
        old,
        cp,
    )
}
fn sign(
    f: &Fixture,
    a: &PreparedSetup,
    b: &PreparedSetup,
    p: &ResumeProposal,
) -> (SignedLocalResume, SignedLocalResume) {
    let t = a.approval().transcript();
    assert_eq!(
        t.source_ephemeral,
        b.approval().transcript().source_ephemeral
    );
    assert_eq!(
        t.target_ephemeral,
        b.approval().transcript().target_ephemeral
    );
    let ar =
        f.ra.approve_fleet_resume(
            &f.a,
            LocalApprovalRequest {
                proposal: &f.proposal,
                role: Direction::SourceToTarget,
                peer_device: "b",
                expected_peer: &f.bf,
                endpoint_slot: EndpointSlot::Primary,
                source_ephemeral: t.source_ephemeral,
                target_ephemeral: t.target_ephemeral,
            },
            p,
            200,
        )
        .unwrap();
    let br =
        f.rb.approve_fleet_resume(
            &f.b,
            LocalApprovalRequest {
                proposal: &f.proposal,
                role: Direction::TargetToSource,
                peer_device: "a",
                expected_peer: &f.af,
                endpoint_slot: EndpointSlot::Primary,
                source_ephemeral: t.source_ephemeral,
                target_ephemeral: t.target_ephemeral,
            },
            p,
            200,
        )
        .unwrap();
    assert_eq!(ar.approval().signature(), a.approval().signature());
    assert_eq!(br.approval().signature(), b.approval().signature());
    (ar, br)
}
#[test]
fn actual_prepared_ephemerals_authenticate_both_resume_roles_and_aead_without_io() {
    let f = Fixture::new();
    let (a, b) = prepared(&f);
    let (p, old, cp) = condition(&f, 3);
    let (ar, br) = sign(&f, &a, &b, &p);
    if let Some(path) = std::env::var_os("FERROC_SETUP_RESUME_EXPORT") {
        let t = a.approval().transcript();
        let v = serde_json::json!({"scope":"actual Runtime approvals over genuine three-phase PreparedSetup ephemeral keys; checkpoint PUBLIC synthetic, no target adoption/IO or stock restart","oldJob":old,"checkpoint":cp,"newJob":f.proposal.job(),"newGrant":f.proposal.grant(),"newGrantDigest":f.proposal.digest(),"transcript":{"binding":t.binding,"jobDigest":t.job_digest,"grantDigest":t.grant_digest,"sourceIdentity":t.source_identity,"targetIdentity":t.target_identity,"sourceEphemeral":t.source_ephemeral,"targetEphemeral":t.target_ephemeral,"maxFileBytes":t.max_file_bytes,"chunkBytes":t.chunk_bytes,"issuedAtMs":t.issued_at_ms,"expiresAtMs":t.expires_at_ms},"conditionBytes":p.canonical_bytes(),"conditionDigest":p.digest(),"sourceProof":p.proof_bytes(&f.proposal,t,Direction::SourceToTarget).unwrap(),"targetProof":p.proof_bytes(&f.proposal,t,Direction::TargetToSource).unwrap(),"sourceSignature":ar.signature().as_slice(),"targetSignature":br.signature().as_slice()});
        fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }
    let sa = a
        .authenticate_resume(p.clone(), ar.signature(), br.signature(), anchor(61_200))
        .unwrap();
    let tb = b
        .authenticate_resume(p, ar.signature(), br.signature(), anchor(61_200))
        .unwrap();
    assert_eq!(sa.local_role(), Direction::SourceToTarget);
    assert_eq!(tb.local_role(), Direction::TargetToSource);
    // In-crate crypto-only access; the public ResumeLease remains opaque.
    let mut sr = sa.into_source().unwrap().1;
    let mut tr = tb.into_target().unwrap().1;
    let frame = sr.seal_data(0, b"abc").unwrap();
    match tr.open_record(&frame).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("expected authenticated DATA"),
    }
    f.no_io();
}
#[test]
fn missing_either_resume_proof_cannot_borrow_prepared_authentication() {
    for bad_source in [true, false] {
        let f = Fixture::new();
        let (a, b) = prepared(&f);
        let (p, _, _) = condition(&f, 3);
        let (ar, br) = sign(&f, &a, &b, &p);
        let source = if bad_source { [0; 64] } else { *ar.signature() };
        let target = if bad_source { *br.signature() } else { [0; 64] };
        assert!(
            a.authenticate_resume(p, &source, &target, anchor(200))
                .is_err()
        );
        f.no_io();
    }
}
#[test]
fn swapped_resume_role_signatures_are_rejected() {
    let f = Fixture::new();
    let (a, b) = prepared(&f);
    let (p, _, _) = condition(&f, 3);
    let (ar, br) = sign(&f, &a, &b, &p);
    assert!(
        a.authenticate_resume(p, br.signature(), ar.signature(), anchor(200))
            .is_err()
    );
    f.no_io();
}
#[test]
fn ordinary_auth_signatures_never_substitute_for_new_resume_domain() {
    let f = Fixture::new();
    let (a, b) = prepared(&f);
    let (p, _, _) = condition(&f, 3);
    let source = *a.approval().signature();
    let target = *b.approval().signature();
    assert!(
        a.authenticate_resume(p, &source, &target, anchor(200))
            .is_err()
    );
    f.no_io();
}
#[test]
fn same_prepared_keys_and_grant_cannot_borrow_another_checkpoint_revision() {
    let f = Fixture::new();
    let (a, b) = prepared(&f);
    let (p, old, cp) = condition(&f, 3);
    let (ar, br) = sign(&f, &a, &b, &p);
    let mut changed = serde_json::to_value(&cp).unwrap();
    changed["revision"] = serde_json::json!(4);
    let changed: PrefixCheckpoint = serde_json::from_value(changed).unwrap();
    let other = ResumeProposal::build(&old, &changed, &f.proposal).unwrap();
    assert!(
        a.authenticate_resume(other, ar.signature(), br.signature(), anchor(200))
            .is_err()
    );
    f.no_io();
}
#[test]
fn proofs_for_other_actual_setup_ephemerals_are_rejected() {
    let f = Fixture::new();
    let (a, b) = prepared(&f);
    let (other_a, other_b) = prepared(&f);
    let (p, _, _) = condition(&f, 3);
    let (ar, br) = sign(&f, &a, &b, &p);
    assert_ne!(
        a.approval().transcript().source_ephemeral,
        other_a.approval().transcript().source_ephemeral
    );
    assert!(
        other_a
            .authenticate_resume(p, ar.signature(), br.signature(), anchor(200))
            .is_err()
    );
    drop(other_b);
    f.no_io();
}
#[test]
fn valid_resume_proofs_do_not_bypass_broken_original_auth_signature() {
    let f = Fixture::new();
    let (mut a, b) = prepared(&f);
    let (p, _, _) = condition(&f, 3);
    let (ar, br) = sign(&f, &a, &b, &p);
    a.peer_signature[0] ^= 1;
    assert!(
        a.authenticate_resume(p, ar.signature(), br.signature(), anchor(200))
            .is_err()
    );
    f.no_io();
}
#[test]
fn both_good_resume_proofs_do_not_import_peer_time_or_revive_expired_grant() {
    let f = Fixture::new();
    let (a, b) = prepared(&f);
    let (p, _, _) = condition(&f, 3);
    let (ar, br) = sign(&f, &a, &b, &p);
    assert!(
        a.authenticate_resume(p, ar.signature(), br.signature(), anchor(3_600_100))
            .is_err()
    );
    f.no_io();
}
