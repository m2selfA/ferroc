use super::*;
use crate::{
    config::Policy,
    fleet::{
        auth::PeerRecord,
        identity::{IdentityStore, PeerApproval, Protection},
        issuance::{ProposalOptions, propose},
        job::{JOB_VERSION, JobSpec, RoutePolicy},
        lease::{ClockSample, TrustedTimeAnchor},
        protocol::device_digest,
    },
    runtime::Runtime,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
const A: &str = "source-A";
const B: &str = "target-B";
struct Two {
    root: tempfile::TempDir,
    a: Arc<IdentityStore>,
    b: Arc<IdentityStore>,
    ra: Arc<Runtime>,
    rb: Arc<Runtime>,
    proposal: ValidatedGrant,
    fa: Fingerprint,
    fb: Fingerprint,
}
fn two() -> Two {
    let root = tempfile::tempdir().unwrap();
    let fleet = Uuid::new_v4();
    let wrap = || {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        Protection::supplied_key(key).unwrap()
    };
    let a = Arc::new(IdentityStore::create(&root.path().join("id-a"), wrap(), fleet, A).unwrap());
    let b = Arc::new(IdentityStore::create(&root.path().join("id-b"), wrap(), fleet, B).unwrap());
    let (fa, fb) = {
        let ka = a.create_identity().unwrap();
        let kb = b.create_identity().unwrap();
        let fa = a.local_fingerprint().unwrap();
        let fb = b.local_fingerprint().unwrap();
        a.enroll_peer(
            PeerApproval::verify(fleet, B, kb.public(), &fb).unwrap(),
            "peer-b",
            1,
        )
        .unwrap();
        b.enroll_peer(
            PeerApproval::verify(fleet, A, ka.public(), &fa).unwrap(),
            "peer-a",
            1,
        )
        .unwrap();
        (fa, fb)
    };
    a.set_peer_endpoint(B, EndpointSlot::Primary, "https://relay.invalid", &fb)
        .unwrap();
    b.set_peer_endpoint(A, EndpointSlot::Primary, "https://relay.invalid", &fa)
        .unwrap();
    std::fs::create_dir(root.path().join("work-a")).unwrap();
    crate::fleet::identity::make_directory(&root.path().join("work-b")).unwrap();
    std::fs::write(root.path().join("work-a/input.bin"), b"abc").unwrap();
    let ra = Arc::new(Runtime::new(
        Policy::new(vec![root.path().join("work-a")], false).unwrap(),
    ));
    let rb = Arc::new(Runtime::new(
        Policy::new(vec![root.path().join("work-b")], false).unwrap(),
    ));
    let job = JobSpec {
        version: JOB_VERSION,
        fleet_id: fleet,
        source_device: device_digest(A).unwrap(),
        target_device: device_digest(B).unwrap(),
        transfer_id: Uuid::new_v4(),
        file_id: Uuid::new_v4(),
        source_path: root
            .path()
            .join("work-a/input.bin")
            .to_str()
            .unwrap()
            .into(),
        destination_path: root
            .path()
            .join("work-b/output.bin")
            .to_str()
            .unwrap()
            .into(),
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 60_100,
        idempotency_key: "setup-agent-unit".into(),
    };
    let proposal = propose(
        job,
        ProposalOptions {
            source_session: Uuid::new_v4(),
            target_session: Uuid::new_v4(),
            profile: LeaseProfile::SingleOwner,
            issued_at_ms: 100,
            lease_ms: 60_000,
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    Two {
        root,
        a,
        b,
        ra,
        rb,
        proposal,
        fa,
        fb,
    }
}
fn now() -> Arc<ApprovedSetupNow> {
    Arc::new(|| Ok(200))
}
fn local(t: &Two, side: char) -> LocalSetupApproval {
    match side {
        'a' => LocalSetupApproval {
            identity: t.a.clone(),
            proposal: t.proposal.clone(),
            peer: ConfiguredSetupPeer {
                device: B.into(),
                fingerprint: t.fb.clone(),
                slot: EndpointSlot::Primary,
                profile: LeaseProfile::SingleOwner,
            },
            now: now(),
        },
        _ => LocalSetupApproval {
            identity: t.b.clone(),
            proposal: t.proposal.clone(),
            peer: ConfiguredSetupPeer {
                device: A.into(),
                fingerprint: t.fa.clone(),
                slot: EndpointSlot::Primary,
                profile: LeaseProfile::SingleOwner,
            },
            now: now(),
        },
    }
}
async fn pump(mut out: SetupOutbox, to: SetupBackend, from: &'static str) {
    while let Some(item) = out.recv().await {
        let frame = item.wire_frame().unwrap();
        let req = &frame["request"];
        let flat = json!({"type":"fleetSetup","id":req["id"],"fromDevice":from,"stage":req["stage"],"payload":req["payload"]});
        to.receive_if_setup(&flat.to_string()).unwrap();
        item.report_written();
    }
}
#[tokio::test]
async fn three_phase_round_runs_through_two_bounded_backends_and_keeps_target_empty() {
    let t = two();
    let (a, _oa) = t.ra.open_fleet_setup(A, 2).unwrap();
    let (b, ob) = t.rb.open_fleet_setup(B, 2).unwrap();
    let id = Uuid::new_v4();
    let arm = b.arm_target(id, local(&t, 'b')).unwrap();
    let (pump_a, pump_b) = (
        tokio::spawn(pump(_oa, b.clone(), A)),
        tokio::spawn(pump(ob, a.clone(), B)),
    );
    let run = a.start_source(id, local(&t, 'a')).unwrap();
    let source = match run.await.unwrap() {
        Ok(v) => v,
        Err(e) => panic!(
            "source {e}: {:?} / {:?} / {:?}",
            a.snapshot(id),
            b.snapshot(id),
            a.last_error(id)
        ),
    };
    let target = match arm.await.unwrap() {
        Ok(v) => v,
        Err(e) => panic!("target {e}: {:?} / {:?}", a.snapshot(id), b.snapshot(id)),
    };
    assert_eq!(a.snapshot(id).unwrap().phase, SetupPhase::PreparedLocally);
    assert_eq!(b.snapshot(id).unwrap().phase, SetupPhase::PreparedLocally);
    let anchor = || TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 201).unwrap();
    let mut sa = source.authenticate(anchor()).unwrap();
    let mut sb = target.authenticate(anchor()).unwrap();
    let rec = sa.seal_data(0, b"abc").unwrap();
    match sb.open_record(&rec).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("expected local readback"),
    }
    assert!(!t.root.path().join("work-b/output.bin").exists());
    assert_eq!(
        std::fs::read_dir(t.root.path().join("work-b"))
            .unwrap()
            .count(),
        0
    );
    pump_a.abort();
    pump_b.abort();
}
#[tokio::test]
async fn foreign_or_unknown_id_cannot_cancel_and_repeat_phase_faults_only_its_round() {
    let t = two();
    let (a, _oa) = t.ra.open_fleet_setup(A, 2).unwrap();
    let (b, _ob) = t.rb.open_fleet_setup(B, 2).unwrap();
    let id = Uuid::new_v4();
    let _arm = b.arm_target(id, local(&t, 'b')).unwrap();
    let _run = a.start_source(id, local(&t, 'a')).unwrap();
    let foreign=json!({"type":"fleetSetup","id":id,"fromDevice":"intruder-C","stage":"response","payload":"x"}).to_string();
    assert!(b.receive_if_setup(&foreign).is_err());
    assert_eq!(b.snapshot(id).unwrap().phase, SetupPhase::Queued);
    let unknown=json!({"type":"fleetSetup","id":Uuid::new_v4(),"fromDevice":A,"stage":"offer","payload":"x"}).to_string();
    assert!(b.receive_if_setup(&unknown).is_err());
    assert!(b.request_cancel(id).unwrap());
    assert!(!b.request_cancel(id).unwrap());
    assert_eq!(b.snapshot(id).unwrap().phase, SetupPhase::CancelRequested);
}
#[tokio::test]
async fn duplicate_id_job_or_binding_spent_and_capacity_history_refuse() {
    let t = two();
    let (a, _o) = t.ra.open_fleet_setup(A, 2).unwrap();
    let id = Uuid::new_v4();
    let _r = a.start_source(id, local(&t, 'a')).unwrap();
    assert!(a.start_source(id, local(&t, 'a')).is_err());
    assert!(a.start_source(Uuid::new_v4(), local(&t, 'a')).is_err());
    let mut other = local(&t, 'a');
    other.proposal = propose(
        t.proposal.job().clone(),
        ProposalOptions {
            source_session: Uuid::new_v4(),
            target_session: Uuid::new_v4(),
            profile: LeaseProfile::SingleOwner,
            issued_at_ms: 100,
            lease_ms: 60_000,
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    assert!(a.start_source(Uuid::new_v4(), other).is_err());
    let mut wrong = local(&t, 'a');
    wrong.peer.device = A.into();
    assert!(a.start_source(Uuid::new_v4(), wrong).is_err());
}
#[tokio::test]
async fn writer_queue_unavailable_and_dropped_emission_fail_the_round_without_fake_success() {
    let t = two();
    let (a, mut oa) = t.ra.open_fleet_setup(A, 1).unwrap();
    let id = Uuid::new_v4();
    let mut run = a.start_source(id, local(&t, 'a')).unwrap();
    let item = oa.recv().await.unwrap();
    assert!(item.wire_frame().is_ok());
    drop(item);
    assert!(run.try_recv().is_err());
    let result = timeout(Duration::from_secs(8), &mut run)
        .await
        .expect("round settles after write report deadline");
    assert!(result.expect("worker reports a terminal result").is_err());
    let snap = a.snapshot(id).unwrap();
    assert_eq!(snap.phase, SetupPhase::Failed);
    assert_eq!(snap.failure, Some(SetupFailure::RoundFailed));
}
#[tokio::test]
async fn observer_drop_and_shutdown_interrupt_without_restoring_admission() {
    let t = two();
    let (a, o) = t.ra.open_fleet_setup(A, 1).unwrap();
    let id = Uuid::new_v4();
    let run = a.start_source(id, local(&t, 'a')).unwrap();
    drop(run);
    drop(o);
    let mut state = SetupPhase::Queued;
    for _ in 0..200 {
        if a.snapshot(id).unwrap().phase != SetupPhase::Queued {
            state = a.snapshot(id).unwrap().phase;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await
    }
    assert!(matches!(
        state,
        SetupPhase::Interrupted | SetupPhase::Failed
    ));
    a.shutdown().await.unwrap();
    assert!(a.start_source(Uuid::new_v4(), local(&t, 'a')).is_err());
    let raw = json!({"type":"fleetSetup","id":id,"fromDevice":B,"stage":"response","payload":"x"})
        .to_string();
    assert!(a.receive_if_setup(&raw).is_err());
}
#[tokio::test]
async fn expired_round_is_interrupted_and_cannot_advance_later() {
    let t = two();
    let root = tempfile::tempdir().unwrap();
    let rt = Arc::new(Runtime::new(
        Policy::new(vec![t.root.path().join("work-a")], false).unwrap(),
    ));
    let (backend, outbox) =
        SetupBackend::create_budget(Arc::downgrade(&rt), A, 1, Duration::from_millis(30)).unwrap();
    drop(outbox);
    let id = Uuid::new_v4();
    let run = backend.start_source(id, local(&t, 'a')).unwrap();
    let result = timeout(Duration::from_secs(3), run)
        .await
        .expect("bounded deadline");
    assert!(result.expect("worker reports a terminal result").is_err());
    let snap = backend.snapshot(id).unwrap();
    assert!(matches!(
        snap.phase,
        SetupPhase::Failed | SetupPhase::Interrupted
    ));
    let raw = json!({"type":"fleetSetup","id":id,"fromDevice":B,"stage":"response","payload":"x"})
        .to_string();
    assert!(backend.receive_if_setup(&raw).is_err());
    drop(root);
}

fn prepared_pair(
    t: &Two,
) -> (
    crate::fleet::setup::PreparedSetup,
    crate::fleet::setup::PreparedSetup,
) {
    use crate::fleet::setup::SetupPeer;
    let (a, offer) =
        t.ra.begin_fleet_setup(
            &t.a,
            &t.proposal,
            SetupPeer {
                device: B,
                expected_fingerprint: &t.fb,
                endpoint_slot: EndpointSlot::Primary,
                profile: LeaseProfile::SingleOwner,
            },
            200,
        )
        .unwrap();
    let (b, response) =
        t.rb.accept_fleet_setup(
            &t.b,
            &t.proposal,
            SetupPeer {
                device: A,
                expected_fingerprint: &t.fa,
                endpoint_slot: EndpointSlot::Primary,
                profile: LeaseProfile::SingleOwner,
            },
            offer,
            200,
        )
        .unwrap();
    let (a, confirmation) = a.confirm(response, 200).unwrap();
    (a, b.finish(confirmation, 200).unwrap())
}
fn synthetic_anchor() -> TrustedTimeAnchor {
    TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 201).unwrap()
}
fn leased_a(t: &Two) -> crate::fleet::setup_lease::SetupLease {
    let (a, _b) = prepared_pair(t);
    t.ra.authenticate_fleet_setup(
        a,
        local(t, 'a'),
        Direction::SourceToTarget,
        synthetic_anchor(),
    )
    .unwrap()
}
fn leased_b(t: &Two) -> crate::fleet::setup_lease::SetupLease {
    let (_a, b) = prepared_pair(t);
    t.rb.authenticate_fleet_setup(
        b,
        local(t, 'b'),
        Direction::TargetToSource,
        synthetic_anchor(),
    )
    .unwrap()
}
#[tokio::test]
async fn leased_route_ticket_is_bound_to_original_owner_and_consumed_once() {
    let t = two();
    let mut a = leased_a(&t);
    let id = Uuid::new_v4();
    assert!(
        a.accept_data_route(
            id,
            t.proposal.digest(),
            zeroize::Zeroizing::new("a".repeat(64))
        )
        .is_err()
    );
    let frame = a.request_data_route(id).unwrap();
    assert_eq!(frame["type"], "fleetRoute");
    assert_eq!(frame["grantDigest"], serde_json::json!(t.proposal.digest()));
    assert!(a.request_data_route(id).is_err());
    assert!(
        a.accept_data_route(
            Uuid::new_v4(),
            t.proposal.digest(),
            zeroize::Zeroizing::new("a".repeat(64))
        )
        .is_err()
    );
    assert!(
        a.accept_data_route(id, [0; 32], zeroize::Zeroizing::new("a".repeat(64)))
            .is_err()
    );
    assert!(
        a.accept_data_route(
            id,
            t.proposal.digest(),
            zeroize::Zeroizing::new("bad".into())
        )
        .is_err()
    );
    a.accept_data_route(
        id,
        t.proposal.digest(),
        zeroize::Zeroizing::new("a".repeat(64)),
    )
    .unwrap();
    assert!(a.test_route_ticket_held());
    assert!(
        a.accept_data_route(
            id,
            t.proposal.digest(),
            zeroize::Zeroizing::new("b".repeat(64))
        )
        .is_err()
    );
    a.close();
    assert!(!a.test_route_ticket_held());
    assert!(a.is_closed());
}
#[tokio::test]
async fn leased_owner_hands_only_its_consumed_ticket_records_to_source() {
    // No ticket: no file IO capability may be opened.
    let t = two();
    let a = leased_a(&t);
    assert!(a.into_source_window(&t.ra, 8).is_err());
    assert!(
        std::fs::read_dir(t.root.path().join("work-b"))
            .unwrap()
            .count()
            == 0
    );
    // A held but NOT consumed ticket is still routing, not file authority.
    let t = two();
    let mut a = leased_a(&t);
    a.test_set_route_ticket(&"a".repeat(64));
    assert!(a.into_source_window(&t.ra, 8).is_err());
    // Consumed by THIS owner: existing SourceWindow opens the exact job file.
    let t = two();
    let mut a = leased_a(&t);
    a.test_set_route_ticket(&"a".repeat(64));
    a.test_claim_route().unwrap();
    let window = a.into_source_window(&t.ra, 8).unwrap();
    assert_eq!(window.bytes_encoded(), 0);
    drop(window);
    assert_eq!(
        std::fs::read_dir(t.root.path().join("work-b"))
            .unwrap()
            .count(),
        0
    );
    // Role separation is not inferred from a valid ticket.
    let t = two();
    let mut b = leased_b(&t);
    b.test_set_route_ticket(&"b".repeat(64));
    b.test_claim_route().unwrap();
    assert!(b.into_source_window(&t.rb, 8).is_err());
    // Closed/replayed owner cannot resurrect a moved record owner.
    let t = two();
    let mut a = leased_a(&t);
    a.test_set_route_ticket(&"c".repeat(64));
    a.test_claim_route().unwrap();
    a.close();
    assert!(a.into_source_window(&t.ra, 8).is_err());
}
#[cfg(windows)]
#[tokio::test]
async fn leased_target_hands_only_claimed_records_to_the_same_runtime_host() {
    use crate::fleet::inventory::InventoryLimits;
    let t = two();
    let b = leased_b(&t);
    let db = t.root.path().join("work-b/host.db");
    drop(crate::fleet::identity::new_private(&db).unwrap());
    let host =
        t.rb.open_fleet_host(&db, InventoryLimits::default())
            .unwrap();
    host.resume().unwrap();
    // No ticket: cannot turn identity/setup success into a receiver.
    assert!(b.into_receiver(&host).is_err());
    drop(host);
    let t = two();
    let mut b = leased_b(&t);
    b.test_set_route_ticket(&"d".repeat(64));
    b.test_claim_route().unwrap();
    let db = t.root.path().join("work-b/host.db");
    drop(crate::fleet::identity::new_private(&db).unwrap());
    let host =
        t.rb.open_fleet_host(&db, InventoryLimits::default())
            .unwrap();
    host.resume().unwrap();
    let receiver = b.into_receiver(&host).unwrap();
    // Admission necessarily creates a private STAGE and journal rows. It must
    // not publish the requested destination or a completed target.
    assert!(
        !std::path::Path::new(&t.proposal.job().destination_path).exists(),
        "admission must not publish the target file"
    );
    drop(receiver);
    host.close().unwrap();
}
#[tokio::test]
async fn failed_link_connect_consumes_the_ticket_and_closes_the_owner() {
    use crate::network::Network;
    let t = two();
    let mut a = leased_a(&t);
    a.test_set_route_ticket(&"e".repeat(64));
    assert!(
        a.connect_link(
            &Network::direct(),
            "PUBLIC_TEST_TOKEN",
            std::time::Duration::from_millis(200)
        )
        .await
        .is_err()
    );
    assert!(a.is_closed());
    assert!(!a.test_route_ticket_held());
    assert!(
        a.into_source_window(&t.ra, 8).is_err(),
        "a failed dial cannot leave a reopened source owner"
    );
}
#[tokio::test]
async fn leased_route_request_and_ticket_revalidate_expiry_and_peer() {
    let t = two();
    let mut a = leased_a(&t);
    a.test_expire();
    assert!(a.request_data_route(Uuid::new_v4()).is_err());
    let t = two();
    let mut a = leased_a(&t);
    let id = Uuid::new_v4();
    a.request_data_route(id).unwrap();
    a.test_expire();
    assert!(
        a.accept_data_route(
            id,
            t.proposal.digest(),
            zeroize::Zeroizing::new("a".repeat(64))
        )
        .is_err()
    );
    assert!(!a.test_route_ticket_held());
    let t = two();
    let mut a = leased_a(&t);
    let id = Uuid::new_v4();
    a.request_data_route(id).unwrap();
    t.a.revoke_peer(B, &t.fb).unwrap();
    assert!(
        a.accept_data_route(
            id,
            t.proposal.digest(),
            zeroize::Zeroizing::new("a".repeat(64))
        )
        .is_err()
    );
    assert!(a.is_closed());
}
#[tokio::test]
async fn leased_owner_roundtrip_and_bad_ciphertext_do_not_create_files() {
    use crate::fleet::control::{Ack, ControlBody};
    let t = two();
    let (a, b) = prepared_pair(&t);
    let mut a =
        t.ra.authenticate_fleet_setup(
            a,
            local(&t, 'a'),
            Direction::SourceToTarget,
            synthetic_anchor(),
        )
        .unwrap();
    let mut b =
        t.rb.authenticate_fleet_setup(
            b,
            local(&t, 'b'),
            Direction::TargetToSource,
            synthetic_anchor(),
        )
        .unwrap();
    let data = a.seal_data(0, b"abc").unwrap();
    let mut corrupt = data.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(b.open_record(&corrupt).is_err());
    assert!(!b.is_closed());
    match b.open_record(&data).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("DATA"),
    }
    let ack = b
        .seal_control(ControlBody::Ack(Ack {
            contiguous: 3,
            received: 3,
        }))
        .unwrap();
    match a.open_record(&ack).unwrap() {
        PeerRecord::Control { message, .. } => assert!(matches!(message.body, ControlBody::Ack(_))),
        _ => panic!("ACK"),
    }
    assert_eq!(
        std::fs::read_dir(t.root.path().join("work-b"))
            .unwrap()
            .count(),
        0
    );
}
#[tokio::test]
async fn leased_owner_expiry_preserves_readonly_ack_but_never_allows_new_data() {
    use crate::fleet::control::{Ack, ControlBody};
    let t = two();
    let (a, b) = prepared_pair(&t);
    let mut a =
        t.ra.authenticate_fleet_setup(
            a,
            local(&t, 'a'),
            Direction::SourceToTarget,
            synthetic_anchor(),
        )
        .unwrap();
    let mut b =
        t.rb.authenticate_fleet_setup(
            b,
            local(&t, 'b'),
            Direction::TargetToSource,
            synthetic_anchor(),
        )
        .unwrap();
    let ack = b
        .seal_control(ControlBody::Ack(Ack {
            contiguous: 0,
            received: 0,
        }))
        .unwrap();
    a.test_expire();
    assert!(
        a.open_record(&ack).is_ok(),
        "read-only ACK must survive mutation expiry"
    );
    assert!(a.seal_data(0, b"abc").is_err());
    let ack = b
        .seal_control(ControlBody::Ack(Ack {
            contiguous: 0,
            received: 0,
        }))
        .unwrap();
    assert!(
        a.open_record(&ack).is_ok(),
        "a rejected late DATA attempt cannot erase read-only observation"
    );
}

#[tokio::test]
async fn leased_owner_refuses_shutdown_before_and_after_admission() {
    let t = two();
    let (a, _b) = prepared_pair(&t);
    t.ra.shutdown().await;
    assert!(
        t.ra.authenticate_fleet_setup(
            a,
            local(&t, 'a'),
            Direction::SourceToTarget,
            synthetic_anchor()
        )
        .is_err()
    );
    let t = two();
    let mut a = leased_a(&t);
    t.ra.shutdown().await;
    assert!(a.seal_data(0, b"abc").is_err());
    assert!(a.is_closed());
}
#[tokio::test]
async fn leased_owner_rechecks_peer_and_endpoint_before_installation() {
    let t = two();
    let (a, _b) = prepared_pair(&t);
    t.a.set_peer_endpoint(B, EndpointSlot::Primary, "https://rotated.invalid", &t.fb)
        .unwrap();
    assert!(
        t.ra.authenticate_fleet_setup(
            a,
            local(&t, 'a'),
            Direction::SourceToTarget,
            synthetic_anchor()
        )
        .is_err()
    );
    let t = two();
    let (a, _b) = prepared_pair(&t);
    t.a.revoke_peer(B, &t.fb).unwrap();
    assert!(
        t.ra.authenticate_fleet_setup(
            a,
            local(&t, 'a'),
            Direction::SourceToTarget,
            synthetic_anchor()
        )
        .is_err()
    );
}
#[tokio::test]
async fn leased_owner_revocation_or_endpoint_drift_is_terminal() {
    let t = two();
    let mut a = leased_a(&t);
    t.a.set_peer_endpoint(B, EndpointSlot::Primary, "https://rotated.invalid", &t.fb)
        .unwrap();
    assert!(a.check_active().is_err());
    assert!(a.is_closed());
    t.a.set_peer_endpoint(B, EndpointSlot::Primary, "https://relay.invalid", &t.fb)
        .unwrap();
    assert!(
        a.check_active().is_err(),
        "restoring metadata must not resurrect crypto owner"
    );
    let t = two();
    let mut a = leased_a(&t);
    t.a.revoke_peer(B, &t.fb).unwrap();
    assert!(a.seal_data(0, b"abc").is_err());
    assert!(a.is_closed());
}
#[tokio::test]
async fn leased_owner_refuses_wrong_expected_grant_role_pin_and_anchor() {
    for variant in 0..4 {
        let t = two();
        let (a, _b) = prepared_pair(&t);
        let mut local = local(&t, 'a');
        let mut role = Direction::SourceToTarget;
        let mut anchor = synthetic_anchor();
        match variant {
            0 => {
                local.proposal = two().proposal;
            }
            1 => {
                role = Direction::TargetToSource;
            }
            2 => {
                local.peer.fingerprint = t.fa.clone();
            }
            _ => {
                anchor =
                    TrustedTimeAnchor::approved_window(ClockSample::now(), 60_100, 60_101).unwrap();
            }
        }
        assert!(
            t.ra.authenticate_fleet_setup(a, local, role, anchor)
                .is_err()
        );
    }
}
#[tokio::test]
async fn leased_owner_effect_expiry_and_terminal_clock_close_runtime_drop() {
    let t = two();
    let mut a = leased_a(&t);
    a.test_expire();
    assert!(a.check_active().is_err());
    assert!(
        !a.is_closed(),
        "expiry preserves readonly observation, not mutation"
    );
    assert!(a.seal_data(0, b"abc").is_err());
    a.close();
    let mut a = leased_a(&t);
    a.test_discontinuous();
    assert!(a.check_active().is_err());
    assert!(a.is_closed());
    let mut a = leased_a(&t);
    a.close();
    assert!(a.seal_data(0, b"abc").is_err());
    let t = two();
    let mut a = leased_a(&t);
    drop(t);
    assert!(a.check_active().is_err());
    assert!(a.is_closed());
}

#[cfg(any(windows, target_os = "linux"))]
#[tokio::test]
async fn target_mkdir_requires_original_live_claimed_owner_and_runtime() {
    for mode in 0..5 {
        let mut t = two();
        let root = t.root.path().join("work-b");
        let destination = root.join("new/deep/output.bin");
        let mut job = t.proposal.job().clone();
        job.destination_path = destination.to_str().unwrap().into();
        let mut grant = t.proposal.grant().clone();
        grant.job_digest = job.digest().unwrap();
        t.proposal = grant
            .validate_for_profile(job, LeaseProfile::SingleOwner)
            .unwrap();
        let mut owner = if mode == 1 {
            leased_a(&t)
        } else {
            leased_b(&t)
        };
        if mode != 0 {
            owner.test_set_route_ticket(&"e".repeat(64));
            owner.test_claim_route().unwrap();
        }
        if mode == 2 {
            owner.test_expire();
        }
        if mode == 3 {
            t.rb.shutdown().await;
        }
        let result = owner.prepare_target_parents(&root);
        if mode == 4 {
            let pinned = result.unwrap();
            assert_eq!(pinned.created, 2);
            assert!(root.join("new/deep").is_dir());
            assert!(!destination.exists());
        } else {
            assert!(result.is_err(), "mode {mode}");
            assert!(!root.join("new").exists(), "mode {mode} created dirs");
        }
    }
}
