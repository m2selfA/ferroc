use super::*;
#[path = "setup_resume_tests.rs"]
mod resume_tests;
#[test]
fn setup_clock_source_cannot_confirm_with_earlier_local_authority_time() {
    let f = Fixture::new();
    let (a, offer) = f.begin();
    let (_b, response) = f.accept(offer);
    assert!(
        a.confirm(response, 199).is_err(),
        "source setup must not move local authority time backward from 200 to199"
    );
    f.no_io();
}
#[test]
fn setup_clock_target_cannot_finish_with_earlier_local_authority_time() {
    let f = Fixture::new();
    let (a, offer) = f.begin();
    let (b, response) = f.accept(offer);
    let (_a, confirmation) = a.confirm(response, 200).unwrap();
    assert!(
        b.finish(confirmation, 199).is_err(),
        "target setup must not move local authority time backward from 200 to199"
    );
    f.no_io();
}

#[test]
fn correctly_signed_confirmation_still_needs_auth_v2_source_signature() {
    let f = Fixture::new();
    let (a, offer) = f.begin();
    let (b, response) = f.accept(offer);
    let (_ready, mut confirmation) = a.confirm(response, 200).unwrap();
    confirmation.grant_signature[0] ^= 1;
    confirmation.signature =
        f.a.load_identity()
            .unwrap()
            .sign_setup_message(&SigningMessage::Confirmation(
                &b.offer,
                &b.response,
                &confirmation,
                LeaseProfile::SingleOwner,
            ))
            .unwrap()
            .to_vec();
    assert!(b.finish(confirmation, 200).is_err());
    f.no_io();
}
#[test]
fn deterministic_setup_fixture_preserves_old_auth_and_exports_for_node_oracle() {
    use crate::fleet::protocol::Binding;
    let uid = |b| Uuid::from_bytes([b; 16]);
    let source = IdentityKey::from_test_seed([0x11; 32]);
    let target = IdentityKey::from_test_seed([0x22; 32]);
    let source_x = EphemeralKey::from_test_bytes([0x33; 32]);
    let target_x = EphemeralKey::from_test_bytes([0x44; 32]);
    let job = JobSpec {
        version: JOB_VERSION,
        fleet_id: uid(1),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: uid(5),
        file_id: uid(6),
        source_path: "/source/α.bin".into(),
        destination_path: "/target/β.bin".into(),
        bytes_total: 1048576,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: "request-1".into(),
    };
    let grant = FileGrant {
        binding: Binding {
            fleet_id: uid(1),
            source_device: job.source_device,
            target_device: job.target_device,
            source_session: uid(3),
            target_session: uid(4),
            transfer_id: uid(5),
            file_id: uid(6),
            authorization_id: uid(7),
            key_epoch: uid(8),
        },
        job_digest: job.digest().unwrap(),
        permission: super::super::job::Permission::SendFileNoClobber,
        chunk_bytes: 262144,
        issued_at_ms: 100,
        expires_at_ms: 1000,
    };
    let p = grant.validate_for(job).unwrap();
    let profile = LeaseProfile::Rotating;
    let t = Transcript::for_grant(
        &p,
        source.public(),
        target.public(),
        source_x.public(),
        target_x.public(),
    );
    let source_sig = source.sign(&t, Direction::SourceToTarget).unwrap();
    let target_sig = target.sign(&t, Direction::TargetToSource).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let old: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/fleet-p0-control-vectors.json"
    ))
    .unwrap();
    assert_eq!(hex(&p.digest()), old["grant_digest_hex"].as_str().unwrap());
    assert_eq!(
        hex(&source_sig),
        old["source_signature_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&target_sig),
        old["target_signature_hex"].as_str().unwrap()
    );
    let mut offer = SetupOffer {
        version: SETUP_VERSION,
        profile: 0,
        job: p.job().clone(),
        grant: p.grant().clone(),
        source_identity: source.public(),
        target_identity: target.public(),
        source_ephemeral: source_x.public(),
        signature: vec![0; 64],
    };
    offer.signature = source
        .sign_setup_message(&SigningMessage::Offer(&offer, profile))
        .unwrap()
        .to_vec();
    let mut response = SetupResponse {
        version: SETUP_VERSION,
        offer_digest: offer.digest(profile).unwrap(),
        target_ephemeral: target_x.public(),
        grant_signature: target_sig.to_vec(),
        signature: vec![0; 64],
    };
    response.signature = target
        .sign_setup_message(&SigningMessage::Response(&offer, &response, profile))
        .unwrap()
        .to_vec();
    let mut confirmation = SetupConfirmation {
        version: SETUP_VERSION,
        response_digest: response.digest(&offer, profile).unwrap(),
        grant_signature: source_sig.to_vec(),
        signature: vec![0; 64],
    };
    confirmation.signature = source
        .sign_setup_message(&SigningMessage::Confirmation(
            &offer,
            &response,
            &confirmation,
            profile,
        ))
        .unwrap()
        .to_vec();
    verify(
        source.public(),
        &offer.bytes(profile).unwrap(),
        &offer.signature,
    )
    .unwrap();
    verify(
        target.public(),
        &response.bytes(&offer, profile).unwrap(),
        &response.signature,
    )
    .unwrap();
    verify(
        source.public(),
        &confirmation.bytes(&offer, &response, profile).unwrap(),
        &confirmation.signature,
    )
    .unwrap();
    if let Some(path) = std::env::var_os("FERROC_FLEET_SETUP_ORACLE_OUTPUT") {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let data = serde_json::json!({"warning":"PUBLIC cfg(test) identities, never operational keys","offerBytes":offer.bytes(profile).unwrap(),"responseBytes":response.bytes(&offer,profile).unwrap(),"confirmationBytes":confirmation.bytes(&offer,&response,profile).unwrap(),"offer":offer,"response":response,"confirmation":confirmation});
        serde_json::to_writer_pretty(file, &data).unwrap();
    }
}

use crate::{
    config::Policy,
    fleet::{
        auth::PeerRecord,
        identity::{PeerApproval, Protection},
        issuance::{ProposalOptions, propose},
        job::{JOB_VERSION, RoutePolicy},
        lease::ClockSample,
    },
};
use std::{fs, path::PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

struct Fixture {
    _tmp: tempfile::TempDir,
    a: IdentityStore,
    b: IdentityStore,
    ra: Runtime,
    rb: Runtime,
    af: Fingerprint,
    bf: Fingerprint,
    proposal: ValidatedGrant,
    outside: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let fleet = Uuid::new_v4();
        let a = IdentityStore::create(
            &tmp.path().join("id-a"),
            Protection::supplied_key(Zeroizing::new([0x71; 32])).unwrap(),
            fleet,
            "a",
        )
        .unwrap();
        let b = IdentityStore::create(
            &tmp.path().join("id-b"),
            Protection::supplied_key(Zeroizing::new([0x72; 32])).unwrap(),
            fleet,
            "b",
        )
        .unwrap();
        let ak = a.create_identity().unwrap();
        let bk = b.create_identity().unwrap();
        let af = a.local_fingerprint().unwrap();
        let bf = b.local_fingerprint().unwrap();
        a.enroll_peer(
            PeerApproval::verify(fleet, "b", bk.public(), &bf).unwrap(),
            "peer-b",
            1,
        )
        .unwrap();
        b.enroll_peer(
            PeerApproval::verify(fleet, "a", ak.public(), &af).unwrap(),
            "peer-a",
            1,
        )
        .unwrap();
        a.set_peer_endpoint("b", EndpointSlot::Primary, "https://relay.example", &bf)
            .unwrap();
        b.set_peer_endpoint("a", EndpointSlot::Primary, "https://relay.example", &af)
            .unwrap();
        for d in ["work-a", "work-b", "outside"] {
            fs::create_dir(tmp.path().join(d)).unwrap();
        }
        let source = tmp.path().join("work-a/in.bin");
        fs::write(&source, b"abc").unwrap();
        let dest = tmp.path().join("work-b/out.bin");
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
            idempotency_key: "setup-test".into(),
        };
        let proposal = propose(
            job,
            ProposalOptions {
                source_session: Uuid::new_v4(),
                target_session: Uuid::new_v4(),
                profile: LeaseProfile::SingleOwner,
                issued_at_ms: 100,
                lease_ms: 3_600_000,
                chunk_bytes: 65536,
            },
        )
        .unwrap();
        let ra = Runtime::new(Policy::new(vec![tmp.path().join("work-a")], false).unwrap());
        let rb = Runtime::new(Policy::new(vec![tmp.path().join("work-b")], false).unwrap());
        let outside = tmp.path().join("outside/x.bin");
        Self {
            _tmp: tmp,
            a,
            b,
            ra,
            rb,
            af,
            bf,
            proposal,
            outside,
        }
    }
    fn peer_a(&self) -> SetupPeer<'_> {
        SetupPeer {
            device: "b",
            expected_fingerprint: &self.bf,
            endpoint_slot: EndpointSlot::Primary,
            profile: LeaseProfile::SingleOwner,
        }
    }
    fn peer_b(&self) -> SetupPeer<'_> {
        SetupPeer {
            device: "a",
            expected_fingerprint: &self.af,
            endpoint_slot: EndpointSlot::Primary,
            profile: LeaseProfile::SingleOwner,
        }
    }
    fn begin(&self) -> (PendingSource<'_>, SetupOffer) {
        self.ra
            .begin_fleet_setup(&self.a, &self.proposal, self.peer_a(), 200)
            .unwrap()
    }
    fn accept(&self, o: SetupOffer) -> (PendingTarget<'_>, SetupResponse) {
        self.rb
            .accept_fleet_setup(&self.b, &self.proposal, self.peer_b(), o, 200)
            .unwrap()
    }
    fn no_io(&self) {
        assert!(!std::path::Path::new(&self.proposal.job().destination_path).exists());
        assert_eq!(
            fs::read_dir(self._tmp.path().join("work-b"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read(self.proposal.job().source_path.clone()).unwrap(),
            b"abc"
        );
    }
}
fn anchor(now: u64) -> TrustedTimeAnchor {
    TrustedTimeAnchor::approved_window(ClockSample::now(), now, now + 1).unwrap()
}
#[test]
fn three_public_messages_produce_two_independently_owned_leased_sessions() {
    let f = Fixture::new();
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
    assert_eq!(a.approval().grant().digest(), b.approval().grant().digest());
    assert_eq!(a.approval().role(), Direction::SourceToTarget);
    assert_eq!(b.approval().role(), Direction::TargetToSource);
    let mut ar = a.authenticate(anchor(61_200)).unwrap();
    let mut br = b.authenticate(anchor(61_200)).unwrap();
    let frame = ar.seal_data(0, b"abc").unwrap();
    match br.open_record(&frame).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("expected DATA"),
    };
    f.no_io();
}
#[test]
fn target_requires_exact_locally_selected_proposal_not_just_offered_structure() {
    let f = Fixture::new();
    let (_a, offer) = f.begin();
    for field in 0..6 {
        let mut o = offer.clone();
        match field {
            0 => o.job.idempotency_key = "changed".into(),
            1 => o.job.source_path = f.outside.to_str().unwrap().into(),
            2 => o.job.bytes_total += 1,
            3 => {
                o.job.overwrite = true;
                o.job.pre_image_sha256 = Some([7; 32]);
                o.grant.permission = super::super::job::Permission::ReplaceExistingFile;
            }
            4 => o.grant.binding.authorization_id = Uuid::new_v4(),
            _ => o.grant.binding.key_epoch = Uuid::new_v4(),
        }
        o.grant.job_digest = o.job.digest().unwrap();
        let local = o
            .grant
            .clone()
            .validate_for_profile(o.job.clone(), LeaseProfile::SingleOwner)
            .unwrap();
        // Even independently accepting altered structure cannot forge source's offer signature.
        assert!(
            f.rb.accept_fleet_setup(&f.b, &local, f.peer_b(), o, 200)
                .is_err()
        );
    }
    let mut wrong = f.proposal.job().clone();
    wrong.idempotency_key = "wrong-local".into();
    let mut g = f.proposal.grant().clone();
    g.job_digest = wrong.digest().unwrap();
    let expected = g
        .validate_for_profile(wrong, LeaseProfile::SingleOwner)
        .unwrap();
    assert!(
        f.rb.accept_fleet_setup(&f.b, &expected, f.peer_b(), offer, 200)
            .is_err()
    );
    f.no_io();
}
#[test]
fn offer_signature_keys_and_recipient_cannot_be_replaced() {
    let f = Fixture::new();
    let (_a, offer) = f.begin();
    for field in 0..4 {
        let mut o = offer.clone();
        match field {
            0 => o.signature[0] ^= 1,
            1 => o.source_identity = [9; 32],
            2 => o.target_identity = [8; 32],
            _ => o.source_ephemeral = [7; 32],
        };
        assert!(
            f.rb.accept_fleet_setup(&f.b, &f.proposal, f.peer_b(), o, 200)
                .is_err()
        );
    }
    f.no_io();
}
#[test]
fn profile_is_explicit_locally_and_bound_in_new_offer_domain() {
    let f = Fixture::new();
    let mut grant = f.proposal.grant().clone();
    grant.expires_at_ms = 60_100;
    let single = grant
        .clone()
        .validate_for_profile(f.proposal.job().clone(), LeaseProfile::SingleOwner)
        .unwrap();
    let rotating = grant
        .validate_for_profile(f.proposal.job().clone(), LeaseProfile::Rotating)
        .unwrap();
    let (_a, mut offer) =
        f.ra.begin_fleet_setup(&f.a, &single, f.peer_a(), 200)
            .unwrap();
    let mut target = f.peer_b();
    target.profile = LeaseProfile::Rotating;
    assert!(
        f.rb.accept_fleet_setup(&f.b, &rotating, target, offer.clone(), 200)
            .is_err()
    );
    offer.profile = 0;
    assert!(
        f.rb.accept_fleet_setup(&f.b, &rotating, target, offer, 200)
            .is_err()
    );
    let mut source = f.peer_a();
    source.profile = LeaseProfile::Rotating;
    assert!(f.ra.begin_fleet_setup(&f.a, &single, source, 200).is_err());
}
#[test]
fn wrong_pin_missing_endpoint_and_wrong_role_are_rejected() {
    let f = Fixture::new();
    let mut peer = f.peer_a();
    peer.expected_fingerprint = &f.af;
    assert!(
        f.ra.begin_fleet_setup(&f.a, &f.proposal, peer, 200)
            .is_err()
    );
    assert!(
        f.rb.begin_fleet_setup(&f.b, &f.proposal, f.peer_b(), 200)
            .is_err()
    );
    f.a.clear_peer_endpoint("b", EndpointSlot::Primary, &f.bf)
        .unwrap();
    assert!(
        f.ra.begin_fleet_setup(&f.a, &f.proposal, f.peer_a(), 200)
            .is_err()
    );
    f.no_io();
}
#[test]
fn source_rejects_corrupt_response_proof_and_grant_signature() {
    for field in 0..4 {
        let f = Fixture::new();
        let (a, offer) = f.begin();
        let (_b, mut r) = f.accept(offer);
        match field {
            0 => r.signature[0] ^= 1,
            1 => r.grant_signature[0] ^= 1,
            2 => r.offer_digest[0] ^= 1,
            _ => r.target_ephemeral = [4; 32],
        };
        assert!(a.confirm(r, 200).is_err());
        f.no_io();
    }
}
#[test]
fn correctly_signed_response_still_needs_valid_auth_v2_role_signature() {
    let f = Fixture::new();
    let (a, offer) = f.begin();
    let (_b, mut r) = f.accept(offer.clone());
    r.grant_signature[0] ^= 1;
    r.signature =
        f.b.load_identity()
            .unwrap()
            .sign_setup_message(&SigningMessage::Response(
                &offer,
                &r,
                LeaseProfile::SingleOwner,
            ))
            .unwrap()
            .to_vec();
    assert!(a.confirm(r, 200).is_err());
    f.no_io();
}
#[test]
fn target_rejects_corrupt_confirmation_proof_and_grant_signature() {
    for field in 0..3 {
        let f = Fixture::new();
        let (a, offer) = f.begin();
        let (b, r) = f.accept(offer);
        let (_ready, mut c) = a.confirm(r, 200).unwrap();
        match field {
            0 => c.signature[0] ^= 1,
            1 => c.grant_signature[0] ^= 1,
            _ => c.response_digest[0] ^= 1,
        };
        assert!(b.finish(c, 200).is_err());
        f.no_io();
    }
}
#[test]
fn replayed_offer_has_no_global_spent_ledger_but_cannot_cross_finish_instances() {
    let f = Fixture::new();
    let (a, offer) = f.begin();
    let (b1, r1) = f.accept(offer.clone());
    let (b2, r2) = f.accept(offer);
    assert_ne!(r1.target_ephemeral, r2.target_ephemeral);
    let (_ready, c) = a.confirm(r1, 200).unwrap();
    assert!(b2.finish(c.clone(), 200).is_err());
    assert!(b1.finish(c, 200).is_ok());
    f.no_io();
}
#[test]
fn new_domains_do_not_accept_an_old_transcript_signature_or_wrong_role_signer() {
    let f = Fixture::new();
    let (_a, mut offer) = f.begin();
    let (b, r) = f.accept(offer.clone());
    assert!(
        f.b.load_identity()
            .unwrap()
            .sign_setup_message(&SigningMessage::Offer(&offer, LeaseProfile::SingleOwner))
            .is_err()
    );
    offer.signature = b.approval.signature().to_vec();
    assert!(
        f.rb.accept_fleet_setup(&f.b, &f.proposal, f.peer_b(), offer.clone(), 200)
            .is_err()
    );
    let a_bytes = offer.bytes(LeaseProfile::SingleOwner).unwrap();
    let b_bytes = r.bytes(&b.offer, LeaseProfile::SingleOwner).unwrap();
    assert!(a_bytes.starts_with(b"ferroc:fleet:setup-offer:v1\0"));
    assert!(b_bytes.starts_with(b"ferroc:fleet:setup-response:v1\0"));
    assert_ne!(a_bytes, b_bytes);
}
#[test]
fn local_source_path_escape_and_target_path_escape_are_role_checked() {
    let f = Fixture::new();
    let mut job = f.proposal.job().clone();
    job.source_path = f.outside.to_str().unwrap().into();
    let mut grant = f.proposal.grant().clone();
    grant.job_digest = job.digest().unwrap();
    let bad = grant
        .validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap();
    assert!(f.ra.begin_fleet_setup(&f.a, &bad, f.peer_a(), 200).is_err());
    let mut job = f.proposal.job().clone();
    job.destination_path = "/other-os/root/out.bin".into();
    let mut grant = f.proposal.grant().clone();
    grant.job_digest = job.digest().unwrap();
    let remote = grant
        .validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap();
    let (_a, offer) =
        f.ra.begin_fleet_setup(&f.a, &remote, f.peer_a(), 200)
            .unwrap();
    assert!(
        f.rb.accept_fleet_setup(&f.b, &remote, f.peer_b(), offer, 200)
            .is_err()
    );
    f.no_io();
}
#[test]
fn endpoint_changes_and_peer_revoke_invalidate_pending_owners() {
    let f = Fixture::new();
    let (a, o) = f.begin();
    let (_b, r) = f.accept(o);
    f.a.set_peer_endpoint("b", EndpointSlot::Primary, "https://changed.example", &f.bf)
        .unwrap();
    assert!(a.confirm(r, 200).is_err());
    let f = Fixture::new();
    let (a, o) = f.begin();
    let (b, r) = f.accept(o);
    let (_a, c) = a.confirm(r, 200).unwrap();
    f.b.revoke_peer("a", &f.af).unwrap();
    assert!(b.finish(c, 200).is_err());
    f.no_io();
}
#[tokio::test]
async fn shutdown_does_not_wait_for_idle_setup_but_prevents_its_next_transition() {
    let f = Fixture::new();
    let (a, o) = f.begin();
    let (_b, r) = f.accept(o);
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        f.ra.shutdown_fleet_host(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(a.confirm(r, 200).is_err());
    let f = Fixture::new();
    let (a, o) = f.begin();
    let (b, r) = f.accept(o);
    let (_a, c) = a.confirm(r, 200).unwrap();
    f.rb.shutdown_fleet_host().await.unwrap();
    assert!(b.finish(c, 200).is_err());
    f.no_io();
}
#[test]
fn expired_or_not_yet_live_setup_fails_and_time_anchor_is_separate() {
    let f = Fixture::new();
    for now in [99, 3_600_100] {
        assert!(
            f.ra.begin_fleet_setup(&f.a, &f.proposal, f.peer_a(), now)
                .is_err()
        );
    }
    let (a, o) = f.begin();
    let (b, r) = f.accept(o);
    let (a, c) = a.confirm(r, 200).unwrap();
    let _b = b.finish(c, 200).unwrap();
    assert!(a.authenticate(anchor(3_600_100)).is_err());
    f.no_io();
}
#[test]
fn codecs_reject_oversize_truncated_unknown_duplicate_nested_and_wrong_phase() {
    let f = Fixture::new();
    let (_a, o) = f.begin();
    let raw = o.encode().unwrap();
    assert!(SetupOffer::decode(&vec![b' '; MAX_SETUP_MESSAGE + 1]).is_err());
    assert!(SetupOffer::decode(&raw[..raw.len() - 1]).is_err());
    let mut v = serde_json::to_value(&o).unwrap();
    v["unknown"] = serde_json::json!(1);
    assert!(SetupOffer::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut v = serde_json::to_value(&o).unwrap();
    v["grant"]["binding"]["extra"] = serde_json::json!(1);
    assert!(SetupOffer::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    let duplicate = format!(
        "{{\"version\":1,{}",
        std::str::from_utf8(&raw[1..]).unwrap()
    );
    assert!(SetupOffer::decode(duplicate.as_bytes()).is_err());
    assert!(SetupResponse::decode(&raw).is_err());
    assert!(SetupConfirmation::decode(&raw).is_err());
    let mut v = serde_json::to_value(&o).unwrap();
    v["signature"] = serde_json::json!([0, 1]);
    assert!(SetupOffer::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut v = serde_json::to_value(&o).unwrap();
    v["version"] = serde_json::json!(2);
    assert!(SetupOffer::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    f.no_io();
}
