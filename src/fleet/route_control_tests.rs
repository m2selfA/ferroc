use super::*;
use crate::fleet::job::{FileGrant, JobSpec};
use serde_json::{Value, json};
fn fixture(n: u128) -> (Value, ValidatedGrant) {
    // INVALID signatures from existing routing-only fixture. Never an AEAD or
    // file/lease approval proof. The relay here approves only a local route.
    let v: Value = serde_json::from_str(&crate::fleet::setup_broker::tests::public_offer(
        "route-a", "route-b", n,
    ))
    .unwrap();
    let job: JobSpec = serde_json::from_value(v["job"].clone()).unwrap();
    let grant: FileGrant = serde_json::from_value(v["grant"].clone()).unwrap();
    let grant = grant
        .validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap();
    (
        json!({"version":1,"approvals":[{"sourceDeviceId":"route-a","targetDeviceId":"route-b","round":{"id":Uuid::from_u128(n+1000),"role":"source","job":grant.job(),"sourceSession":grant.grant().binding.source_session,"targetSession":grant.grant().binding.target_session,"authorizationId":grant.grant().binding.authorization_id,"keyEpoch":grant.grant().binding.key_epoch,"chunkBytes":grant.grant().chunk_bytes,"issuedAtMs":grant.grant().issued_at_ms,"leaseMs":grant.grant().expires_at_ms-grant.grant().issued_at_ms},"profile":"singleOwner","ttlMs":10000}]}),
        grant,
    )
}
fn load(v: &Value) -> Result<ApprovedDataRoutes> {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("local.json");
    std::fs::write(&p, serde_json::to_vec(v).unwrap()).unwrap();
    ApprovedDataRoutes::load(&p)
}
fn control() -> (RouteControl, Uuid, ValidatedGrant) {
    let (v, g) = fixture(1);
    let id = serde_json::from_value(v["approvals"][0]["round"]["id"].clone()).unwrap();
    (
        RouteControl::new(
            Uuid::new_v4(),
            Arc::new(FleetRelay::new()),
            load(&v).unwrap(),
        ),
        id,
        g,
    )
}
#[test]
fn disconnect_closes_original_approval_even_after_route_rotation() {
    let (c, id, g) = control();
    let now = Instant::now();
    c.present(id, g.digest(), peer("route-a"), now).unwrap();
    c.present(id, g.digest(), peer("route-b"), now).unwrap();
    assert_eq!(c.fleet.test_pair_count(), 1);
    let mut next = g.grant().clone();
    next.binding.authorization_id = Uuid::new_v4();
    next.binding.key_epoch = Uuid::new_v4();
    let next = next
        .validate_for_profile(g.job().clone(), LeaseProfile::SingleOwner)
        .unwrap();
    c.fleet.advance_local(&g, &next).unwrap();
    assert_eq!(c.fleet.test_pair_count(), 1);
    c.disconnected(&peer("route-a"));
    assert_eq!(
        c.fleet.test_pair_count(),
        0,
        "initial approval must still close its live rotated route"
    );
}
fn resume_control() -> (RouteControl, Uuid, ValidatedGrant) {
    let (mut v, g) = fixture(9);
    v["approvals"][0]["resumeConditionDigest"] = json!(vec![9; 32]);
    let id = serde_json::from_value(v["approvals"][0]["round"]["id"].clone()).unwrap();
    (
        RouteControl::new(
            Uuid::new_v4(),
            Arc::new(FleetRelay::new()),
            load(&v).unwrap(),
        ),
        id,
        g,
    )
}
fn public_resume(marker: u8) -> super::super::resume_route::RoleResumeProof {
    // PUBLIC deliberately invalid signatures: correlation-only relay evidence.
    super::super::resume_route::RoleResumeProof {
        condition_digest: [9; 32],
        signature: vec![marker; 64],
    }
}
#[test]
fn resume_route_needs_exact_local_mode_both_roles_and_binds_public_proofs() {
    let (c, id, g) = resume_control();
    let now = Instant::now();
    assert!(c.present(id, g.digest(), peer("route-a"), now).is_err());
    assert!(
        c.present_resume(id, g.digest(), peer("route-a"), now, Some(public_resume(1)))
            .unwrap()
            .is_none()
    );
    assert_eq!(c.fleet.test_pair_count(), 0);
    let [a, b] = c
        .present_resume(id, g.digest(), peer("route-b"), now, Some(public_resume(2)))
        .unwrap()
        .unwrap();
    for d in [a, b] {
        let f = d.frame();
        assert_eq!(f["resume"]["conditionDigest"], json!(vec![9; 32]));
        assert_eq!(f["resume"]["sourceSignature"], json!(vec![1; 64]));
        assert_eq!(f["resume"]["targetSignature"], json!(vec![2; 64]));
    }
    assert!(
        c.present_resume(id, g.digest(), peer("route-a"), now, Some(public_resume(1)))
            .is_err()
    );
}
#[test]
fn resume_route_rejects_wrong_condition_shape_and_foreign_without_minting() {
    let (c, id, g) = resume_control();
    let now = Instant::now();
    let mut wrong = public_resume(1);
    wrong.condition_digest = [8; 32];
    assert!(
        c.present_resume(id, g.digest(), peer("route-a"), now, Some(wrong))
            .is_err()
    );
    let mut short = public_resume(1);
    short.signature.pop();
    assert!(
        c.present_resume(id, g.digest(), peer("route-a"), now, Some(short))
            .is_err()
    );
    assert!(
        c.present_resume(id, g.digest(), peer("foreign"), now, Some(public_resume(1)))
            .is_err()
    );
    assert_eq!(c.fleet.test_pair_count(), 0);
    assert!(
        c.present_resume(id, g.digest(), peer("route-a"), now, Some(public_resume(1)))
            .unwrap()
            .is_none()
    );
    assert!(
        c.present_resume(id, g.digest(), peer("route-b"), now, Some(public_resume(2)))
            .unwrap()
            .is_some()
    );
}
#[test]
fn fresh_route_refuses_resume_proofs_and_fresh_delivery_omits_extension() {
    let (c, id, g) = control();
    let now = Instant::now();
    assert!(
        c.present_resume(id, g.digest(), peer("route-a"), now, Some(public_resume(1)))
            .is_err()
    );
    c.present(id, g.digest(), peer("route-a"), now).unwrap();
    let pair = c
        .present(id, g.digest(), peer("route-b"), now)
        .unwrap()
        .unwrap();
    assert!(pair.iter().all(|d| d.frame().get("resume").is_none()));
}
fn peer(s: &str) -> Peer {
    Peer::new(s, "gen-1").unwrap()
}
#[test]
fn one_role_never_mints_tickets_and_both_roles_use_exact_local_grant() {
    let (c, id, g) = control();
    let now = Instant::now();
    assert!(
        c.present(id, g.digest(), peer("route-a"), now)
            .unwrap()
            .is_none()
    );
    let [a, b] = c
        .present(id, g.digest(), peer("route-b"), now)
        .unwrap()
        .unwrap();
    assert_eq!(a.recipient(), &peer("route-a"));
    assert_eq!(b.recipient(), &peer("route-b"));
    assert_ne!(a.secret, b.secret);
    assert_eq!(a.secret.len(), 64);
    c.may_deliver(&a, now).unwrap();
    c.sent(&a);
    assert!(c.may_deliver(&a, now).is_err());
    assert!(c.present(id, g.digest(), peer("route-a"), now).is_err());
}
#[test]
fn foreign_wrong_grant_and_unknown_id_do_not_destroy_healthy_round() {
    let (c, id, g) = control();
    let now = Instant::now();
    assert!(c.present(id, g.digest(), peer("foreign"), now).is_err());
    assert!(
        c.present(Uuid::new_v4(), g.digest(), peer("route-a"), now)
            .is_err()
    );
    assert!(c.present(id, [0; 32], peer("route-a"), now).is_err());
    assert!(
        c.present(id, g.digest(), peer("route-a"), now)
            .unwrap()
            .is_none()
    );
    assert!(c.present(id, g.digest(), peer("route-a"), now).is_err());
    assert!(
        c.present(id, g.digest(), peer("route-b"), now)
            .unwrap()
            .is_some()
    );
}
#[test]
fn disconnect_is_exact_generation_and_tickets_cannot_be_reissued() {
    let (c, id, g) = control();
    let now = Instant::now();
    c.present(id, g.digest(), peer("route-a"), now).unwrap();
    c.disconnected(&Peer::new("route-a", "older").unwrap());
    let [a, b] = c
        .present(id, g.digest(), peer("route-b"), now)
        .unwrap()
        .unwrap();
    c.disconnected(&peer("foreign"));
    c.may_deliver(&a, now).unwrap();
    c.disconnected(&peer("route-a"));
    assert!(c.may_deliver(&a, now).is_err());
    assert!(c.may_deliver(&b, now).is_err());
    assert!(
        c.present(id, g.digest(), Peer::new("route-a", "new").unwrap(), now)
            .is_err()
    );
}
#[test]
fn write_failure_and_expiration_keep_spent_approval() {
    let (c, id, g) = control();
    let now = Instant::now();
    c.present(id, g.digest(), peer("route-a"), now).unwrap();
    assert!(
        c.present(id, g.digest(), peer("route-b"), now + PRESENT_TTL)
            .is_err()
    );
    assert!(c.present(id, g.digest(), peer("route-b"), now).is_err());
    let (c, id, g) = control();
    c.present(id, g.digest(), peer("route-a"), now).unwrap();
    let [a, _] = c
        .present(id, g.digest(), peer("route-b"), now)
        .unwrap()
        .unwrap();
    assert!(c.may_deliver(&a, now + Duration::from_secs(10)).is_err());
    c.failed(id);
    assert!(c.may_deliver(&a, now).is_err());
    assert!(c.present(id, g.digest(), peer("route-b"), now).is_err());
}
#[test]
fn config_is_strict_local_bounded_unique_single_owner() {
    let (v, _) = fixture(1);
    assert!(load(&v).is_ok());
    for field in ["version", "extra"] {
        let mut x = v.clone();
        x[field] = json!(77);
        assert!(load(&x).is_err());
    }
    for (f, value) in [
        ("ttlMs", json!(0)),
        ("ttlMs", json!(300001)),
        ("sourceDeviceId", json!("foreign")),
        ("profile", json!("rotating")),
    ] {
        let mut x = v.clone();
        x["approvals"][0][f] = value;
        assert!(load(&x).is_err());
    }
    let mut nil = v.clone();
    nil["approvals"][0]["round"]["id"] = json!(Uuid::nil());
    assert!(load(&nil).is_err());
    let mut nil = v.clone();
    nil["approvals"][0]["round"]["role"] = json!("target");
    assert!(load(&nil).is_err());
    let mut x = v.clone();
    let a = x["approvals"][0].clone();
    x["approvals"].as_array_mut().unwrap().push(a);
    assert!(load(&x).is_err());
    x["approvals"] = json!([]);
    assert!(load(&x).is_err());
    let entries: Vec<Value> = (1..=17)
        .map(|n| fixture(n).0["approvals"][0].clone())
        .collect();
    assert!(load(&json!({"version":1,"approvals":entries})).is_err());
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("oversized");
    std::fs::write(&p, vec![b' '; 65537]).unwrap();
    assert!(ApprovedDataRoutes::load(&p).is_err());
}
