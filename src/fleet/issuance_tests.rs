use super::*;
use crate::{
    config::Policy,
    fleet::{
        auth::{EphemeralKey, PeerRecord},
        identity::{PeerApproval, Protection},
        job::{JOB_VERSION, RoutePolicy},
        lease::{ClockSample, TrustedTimeAnchor},
    },
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use zeroize::Zeroizing;

#[path = "resume_approval_tests.rs"]
mod resume_approval_tests;

struct Fixture {
    _tmp: tempfile::TempDir,
    a: IdentityStore,
    b: IdentityStore,
    ra: Runtime,
    rb: Runtime,
    af: Fingerprint,
    bf: Fingerprint,
    job: JobSpec,
    outside: PathBuf,
}
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let fleet = Uuid::new_v4();
    let a = IdentityStore::create(
        &tmp.path().join("id-a"),
        Protection::supplied_key(Zeroizing::new([0x61; 32])).unwrap(),
        fleet,
        "a",
    )
    .unwrap();
    let b = IdentityStore::create(
        &tmp.path().join("id-b"),
        Protection::supplied_key(Zeroizing::new([0x62; 32])).unwrap(),
        fleet,
        "b",
    )
    .unwrap();
    let ka = a.create_identity().unwrap();
    let kb = b.create_identity().unwrap();
    let af = a.local_fingerprint().unwrap();
    let bf = b.local_fingerprint().unwrap();
    a.enroll_peer(
        PeerApproval::verify(fleet, "b", kb.public(), &bf).unwrap(),
        "peer-b",
        1,
    )
    .unwrap();
    b.enroll_peer(
        PeerApproval::verify(fleet, "a", ka.public(), &af).unwrap(),
        "peer-a",
        1,
    )
    .unwrap();
    a.set_peer_endpoint(
        "b",
        EndpointSlot::Primary,
        "https://relay.example/ferroc",
        &bf,
    )
    .unwrap();
    b.set_peer_endpoint(
        "a",
        EndpointSlot::Primary,
        "https://relay.example/ferroc",
        &af,
    )
    .unwrap();
    for dir in ["work-a", "work-b", "outside"] {
        fs::create_dir(tmp.path().join(dir)).unwrap();
    }
    let source = tmp.path().join("work-a/in.bin");
    fs::write(&source, b"abc").unwrap();
    let dest = tmp.path().join("work-b/out.bin");
    let ra = Runtime::new(Policy::new(vec![tmp.path().join("work-a")], false).unwrap());
    let rb = Runtime::new(Policy::new(vec![tmp.path().join("work-b")], false).unwrap());
    let job = JobSpec {
        version: JOB_VERSION,
        fleet_id: fleet,
        source_device: device_digest("a").unwrap(),
        target_device: device_digest("b").unwrap(),
        transfer_id: Uuid::new_v4(),
        file_id: Uuid::new_v4(),
        source_path: source.to_str().unwrap().into(),
        destination_path: dest.to_str().unwrap().into(),
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 3_600_100,
        idempotency_key: "local-approval-test".into(),
    };
    let outside = tmp.path().join("outside/file");
    Fixture {
        _tmp: tmp,
        a,
        b,
        ra,
        rb,
        af,
        bf,
        job,
        outside,
    }
}
fn options(profile: LeaseProfile, lease_ms: u64) -> ProposalOptions {
    ProposalOptions {
        source_session: Uuid::new_v4(),
        target_session: Uuid::new_v4(),
        profile,
        issued_at_ms: 100,
        lease_ms,
        chunk_bytes: 65536,
    }
}
fn req<'a>(
    p: &'a ValidatedGrant,
    role: Direction,
    fp: &'a Fingerprint,
) -> LocalApprovalRequest<'a> {
    LocalApprovalRequest {
        proposal: p,
        role,
        peer_device: if role == Direction::SourceToTarget {
            "b"
        } else {
            "a"
        },
        expected_peer: fp,
        endpoint_slot: EndpointSlot::Primary,
        source_ephemeral: EphemeralKey::from_test_bytes([0x31; 32]).public(),
        target_ephemeral: EphemeralKey::from_test_bytes([0x32; 32]).public(),
    }
}
#[test]
fn both_hosts_approve_same_proposal_and_dual_sign_leased_aead() {
    let f = fixture();
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 3_600_000)).unwrap();
    let sa =
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .unwrap();
    let sb =
        f.rb.approve_fleet_grant(&f.b, req(&p, Direction::TargetToSource, &f.af), 200)
            .unwrap();
    assert_eq!(
        sa.transcript()
            .bytes_with_profile(sa.role(), LeaseProfile::SingleOwner)
            .unwrap(),
        sb.transcript()
            .bytes_with_profile(sa.role(), LeaseProfile::SingleOwner)
            .unwrap()
    );
    assert_eq!(sa.grant().digest(), sb.grant().digest());
    assert_eq!(sa.peer_fingerprint(), &f.bf);
    assert_eq!(sa.endpoint().url(), "https://relay.example/ferroc");
    let t = sa.transcript();
    let anchor = || TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 201).unwrap();
    let mut a = EphemeralKey::from_test_bytes([0x31; 32])
        .authenticate_leased(
            t,
            sa.role(),
            &p,
            sa.source_pin(),
            sa.target_pin(),
            sa.signature(),
            sb.signature(),
            anchor(),
        )
        .unwrap();
    let mut b = EphemeralKey::from_test_bytes([0x32; 32])
        .authenticate_leased(
            t,
            sb.role(),
            &p,
            sb.source_pin(),
            sb.target_pin(),
            sa.signature(),
            sb.signature(),
            anchor(),
        )
        .unwrap();
    let frame = a.seal_data(0, b"abc").unwrap();
    match b.open_record(&frame).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("expected DATA"),
    }
    // A local signature is NOT the peer's signature and cannot authenticate both roles.
    assert!(
        EphemeralKey::from_test_bytes([0x31; 32])
            .authenticate_leased(
                t,
                sa.role(),
                &p,
                sa.source_pin(),
                sa.target_pin(),
                sa.signature(),
                sa.signature(),
                anchor()
            )
            .is_err()
    );
    assert!(!std::path::Path::new(&f.job.destination_path).exists());
}
#[test]
fn proposal_preserves_profile_permission_and_fixed_deadline() {
    let f = fixture();
    assert!(propose(f.job.clone(), options(LeaseProfile::Rotating, 60_001)).is_err());
    assert!(propose(f.job.clone(), options(LeaseProfile::SingleOwner, 0)).is_err());
    assert!(propose(f.job.clone(), options(LeaseProfile::SingleOwner, 3_600_001)).is_err());
    let mut o = options(LeaseProfile::SingleOwner, u64::MAX);
    o.issued_at_ms = 1;
    assert!(propose(f.job.clone(), o).is_err());
    let mut o = options(LeaseProfile::SingleOwner, 100);
    o.target_session = o.source_session;
    assert!(propose(f.job.clone(), o).is_err());
    let mut o = options(LeaseProfile::SingleOwner, 100);
    o.source_session = Uuid::nil();
    assert!(propose(f.job.clone(), o).is_err());
    let mut o = options(LeaseProfile::SingleOwner, 100);
    o.chunk_bytes = 0;
    assert!(propose(f.job.clone(), o).is_err());
    // A caller can structurally validate grants without using propose().
    // The Runtime approval must still reject reflected session IDs.
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    let mut raw = p.grant().clone();
    raw.binding.target_session = raw.binding.source_session;
    let bypass = raw
        .validate_for_profile(f.job.clone(), LeaseProfile::SingleOwner)
        .unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&bypass, Direction::SourceToTarget, &f.bf), 200)
            .is_err()
    );
    let mut j = f.job.clone();
    j.overwrite = true;
    j.pre_image_sha256 = Some([0x44; 32]);
    let p = propose(j.clone(), options(LeaseProfile::Rotating, 60_000)).unwrap();
    assert_eq!(p.grant().permission, Permission::ReplaceExistingFile);
    let mut jbad = j.clone();
    jbad.pre_image_sha256 = None;
    assert!(propose(jbad, options(LeaseProfile::SingleOwner, 100)).is_err());
    let mut jbad = j;
    jbad.version = 1;
    assert!(propose(jbad, options(LeaseProfile::SingleOwner, 100)).is_err());
}
#[test]
fn remote_path_not_locally_resolved_but_local_path_must_be_allowed() {
    let f = fixture();
    let mut j = f.job.clone();
    j.destination_path = "/other-host/not-local/output".into();
    let p = propose(j, options(LeaseProfile::SingleOwner, 1000)).unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .is_ok()
    );
    let mut j = f.job.clone();
    j.source_path = f.outside.to_str().unwrap().into();
    let p = propose(j, options(LeaseProfile::SingleOwner, 1000)).unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .err()
            .unwrap()
            .to_string()
            .contains("outside allowed")
    );
    let mut j = f.job.clone();
    j.destination_path = f.outside.to_str().unwrap().into();
    let p = propose(j, options(LeaseProfile::SingleOwner, 1000)).unwrap();
    assert!(
        f.rb.approve_fleet_grant(&f.b, req(&p, Direction::TargetToSource, &f.af), 200)
            .is_err()
    );
}
#[test]
fn role_device_fleet_and_peer_key_mismatches_refuse_signing() {
    let f = fixture();
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::TargetToSource, &f.af), 200)
            .is_err()
    );
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.af), 200)
            .is_err()
    );
    let mut r = req(&p, Direction::SourceToTarget, &f.bf);
    r.peer_device = "unknown";
    assert!(f.ra.approve_fleet_grant(&f.a, r, 200).is_err());
    let mut j = f.job.clone();
    j.fleet_id = Uuid::new_v4();
    let p = propose(j, options(LeaseProfile::SingleOwner, 1000)).unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .is_err()
    );
    let mut j = f.job.clone();
    j.target_device = device_digest("other").unwrap();
    let p = propose(j, options(LeaseProfile::SingleOwner, 1000)).unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .is_err()
    );
}
#[test]
fn reapproved_new_key_cannot_be_signed_with_the_old_keys_endpoint() {
    let f = fixture();
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    f.a.revoke_peer("b", &f.bf).unwrap();
    let (key, _) = crate::fleet::auth::IdentityKey::generate().unwrap();
    let fp = crate::fleet::identity::fingerprint(f.job.fleet_id, "b", key.public()).unwrap();
    f.a.enroll_peer(
        PeerApproval::verify(f.job.fleet_id, "b", key.public(), &fp).unwrap(),
        "peer-b",
        2,
    )
    .unwrap();
    let error =
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &fp), 200)
            .err()
            .unwrap();
    assert!(error.to_string().contains("different peer key"), "{error}");
}

#[test]
fn missing_endpoint_and_revoked_peer_fail_closed() {
    let f = fixture();
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    let mut r = req(&p, Direction::SourceToTarget, &f.bf);
    r.endpoint_slot = EndpointSlot::Fallback;
    assert!(f.ra.approve_fleet_grant(&f.a, r, 200).is_err());
    f.a.clear_peer_endpoint("b", EndpointSlot::Primary, &f.bf)
        .unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .is_err()
    );
    f.a.revoke_peer("b", &f.bf).unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .is_err()
    );
}
#[test]
fn signature_is_bound_to_job_ephemerals_and_current_endpoint() {
    use ring::signature::{ED25519, UnparsedPublicKey};
    let f = fixture();
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    let s =
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .unwrap();
    let public = f.a.load_identity().unwrap().public();
    let verify = |t: &Transcript| {
        UnparsedPublicKey::new(&ED25519, public).verify(
            &t.bytes_with_profile(s.role(), LeaseProfile::SingleOwner)
                .unwrap(),
            s.signature(),
        )
    };
    assert!(verify(s.transcript()).is_ok());
    let mut changed = s.transcript().clone();
    changed.job_digest[0] ^= 1;
    assert!(verify(&changed).is_err());
    let mut changed = s.transcript().clone();
    changed.target_ephemeral[0] ^= 1;
    assert!(verify(&changed).is_err());
    f.a.set_peer_endpoint("b", EndpointSlot::Primary, "https://new.example", &f.bf)
        .unwrap();
    let fresh =
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .unwrap();
    assert_ne!(s.endpoint().url(), fresh.endpoint().url());
    // Endpoint is descriptive LOCAL metadata, not part of canonical signature bytes.
    assert_eq!(s.signature(), fresh.signature());
}
#[test]
fn signing_rejects_invalid_time_and_reflected_ephemeral_keys() {
    let f = fixture();
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    for now in [0, 99, 1100, u64::MAX] {
        assert!(
            f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), now)
                .is_err()
        );
    }
    let mut r = req(&p, Direction::SourceToTarget, &f.bf);
    r.target_ephemeral = r.source_ephemeral;
    assert!(f.ra.approve_fleet_grant(&f.a, r, 200).is_err());
    let mut r = req(&p, Direction::SourceToTarget, &f.bf);
    r.source_ephemeral = [0; 32];
    assert!(f.ra.approve_fleet_grant(&f.a, r, 200).is_err());
}
#[tokio::test]
async fn stopped_runtime_or_disabled_transfers_never_sign() {
    let mut f = fixture();
    let p = propose(f.job.clone(), options(LeaseProfile::SingleOwner, 1000)).unwrap();
    f.ra.policy.allow_transfers = false;
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .is_err()
    );
    f.ra.policy.allow_transfers = true;
    f.ra.shutdown_fleet_host().await.unwrap();
    assert!(
        f.ra.approve_fleet_grant(&f.a, req(&p, Direction::SourceToTarget, &f.bf), 200)
            .is_err()
    );
    // Lifecycle is per Runtime, not a global stop.
    assert!(
        f.rb.approve_fleet_grant(&f.b, req(&p, Direction::TargetToSource, &f.af), 200)
            .is_ok()
    );
}
