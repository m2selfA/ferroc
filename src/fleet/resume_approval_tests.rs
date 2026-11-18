use super::*;
use crate::fleet::{journal::PrefixCheckpoint, resume_condition::ResumeProposal};
use serde_json::json;
fn condition(f: &Fixture, g: &ValidatedGrant) -> ResumeProposal {
    condition_data(f, g).0
}
fn condition_data(f: &Fixture, g: &ValidatedGrant) -> (ResumeProposal, JobSpec, PrefixCheckpoint) {
    let mut old = f.job.clone();
    old.transfer_id = Uuid::new_v4();
    old.file_id = Uuid::new_v4();
    old.idempotency_key = "old-resume-attempt".into();
    old.deadline_ms = 99;
    let mut b = g.grant().binding.clone();
    b.transfer_id = old.transfer_id;
    b.file_id = old.file_id;
    b.source_session = Uuid::new_v4();
    b.target_session = Uuid::new_v4();
    b.authorization_id = Uuid::new_v4();
    b.key_epoch = Uuid::new_v4();
    let cp:PrefixCheckpoint=serde_json::from_value(json!({"version":1,"bytes":1,"sha256":<[u8;32]>::from(Sha256::digest(b"a")),"job_digest":old.digest().unwrap(),"grant_digest":([9u8;32]),"binding":b,"revision":3})).unwrap();
    (ResumeProposal::build(&old, &cp, g).unwrap(), old, cp)
}
#[test]
fn independent_stores_sign_both_resume_roles_under_real_runtime_approval() {
    let f = fixture();
    let g = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 3600000)).unwrap();
    let (p, old, cp) = condition_data(&f, &g);
    let a =
        f.ra.approve_fleet_resume(&f.a, req(&g, Direction::SourceToTarget, &f.bf), &p, 200)
            .unwrap();
    let b =
        f.rb.approve_fleet_resume(&f.b, req(&g, Direction::TargetToSource, &f.af), &p, 200)
            .unwrap();
    a.verify_peer_signature(b.signature()).unwrap();
    b.verify_peer_signature(a.signature()).unwrap();
    assert_eq!(a.condition().digest(), b.condition().digest());
    assert!(a.verify_peer_signature(a.signature()).is_err());
    assert!(a.verify_peer_signature(b.approval().signature()).is_err());
    let mut bad = *b.signature();
    bad[0] ^= 1;
    assert!(a.verify_peer_signature(&bad).is_err());
    let normal =
        f.ra.approve_fleet_grant(&f.a, req(&g, Direction::SourceToTarget, &f.bf), 200)
            .unwrap();
    assert_eq!(normal.signature(), a.approval().signature());
    assert_ne!(normal.signature(), a.signature());
    if let Some(path) = std::env::var_os("FERROC_RESUME_SIGNER_EXPORT") {
        let t = a.approval().transcript();
        let v = json!({"scope":"actual local Runtime approval using two separately encrypted IdentityStores; old checkpoint is PUBLIC synthetic fixture, no target adoption or IO resume","oldJob":old,"checkpoint":cp,"newJob":g.job(),"newGrant":g.grant(),"newGrantDigest":g.digest(),"transcript":{"binding":t.binding,"jobDigest":t.job_digest,"grantDigest":t.grant_digest,"sourceIdentity":t.source_identity,"targetIdentity":t.target_identity,"sourceEphemeral":t.source_ephemeral,"targetEphemeral":t.target_ephemeral,"maxFileBytes":t.max_file_bytes,"chunkBytes":t.chunk_bytes,"issuedAtMs":t.issued_at_ms,"expiresAtMs":t.expires_at_ms},"conditionBytes":p.canonical_bytes(),"conditionDigest":p.digest(),"sourceProof":p.proof_bytes(&g,t,Direction::SourceToTarget).unwrap(),"targetProof":p.proof_bytes(&g,t,Direction::TargetToSource).unwrap(),"sourceSignature":a.signature().as_slice(),"targetSignature":b.signature().as_slice()});
        std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    }
}
#[test]
fn other_grant_or_ordinary_profile_cannot_borrow_resume_condition() {
    let f = fixture();
    let g = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    let p = condition(&f, &g);
    let other = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    assert!(
        f.ra.approve_fleet_resume(&f.a, req(&other, Direction::SourceToTarget, &f.bf), &p, 200)
            .is_err()
    );
    let rotating = g.grant().clone().validate_for(g.job().clone()).unwrap();
    assert!(
        f.ra.approve_fleet_resume(
            &f.a,
            req(&rotating, Direction::SourceToTarget, &f.bf),
            &p,
            200
        )
        .is_err()
    );
}
#[test]
fn wrong_pin_role_endpoint_and_time_refuse_resume_signing() {
    let f = fixture();
    let g = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    let p = condition(&f, &g);
    assert!(
        f.ra.approve_fleet_resume(&f.a, req(&g, Direction::SourceToTarget, &f.af), &p, 200)
            .is_err()
    );
    assert!(
        f.ra.approve_fleet_resume(&f.a, req(&g, Direction::TargetToSource, &f.af), &p, 200)
            .is_err()
    );
    assert!(
        f.ra.approve_fleet_resume(&f.a, req(&g, Direction::SourceToTarget, &f.bf), &p, 99)
            .is_err()
    );
    assert!(
        f.ra.approve_fleet_resume(&f.a, req(&g, Direction::SourceToTarget, &f.bf), &p, 1100)
            .is_err()
    );
    f.a.clear_peer_endpoint("b", EndpointSlot::Primary, &f.bf)
        .unwrap();
    assert!(
        f.ra.approve_fleet_resume(&f.a, req(&g, Direction::SourceToTarget, &f.bf), &p, 200)
            .is_err()
    );
}
#[test]
fn revoked_peer_and_shutdown_refuse_resume_signing() {
    let f = fixture();
    let g = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    let p = condition(&f, &g);
    f.a.clear_peer_endpoint("b", EndpointSlot::Primary, &f.bf)
        .unwrap();
    f.a.revoke_peer("b", &f.bf).unwrap();
    assert!(
        f.ra.approve_fleet_resume(&f.a, req(&g, Direction::SourceToTarget, &f.bf), &p, 200)
            .is_err()
    );
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(f.rb.shutdown());
    assert!(
        f.rb.approve_fleet_resume(&f.b, req(&g, Direction::TargetToSource, &f.af), &p, 200)
            .is_err()
    );
}
