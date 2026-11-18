use super::*;
use crate::fleet::{
    auth::{AuthenticatedRecords, DevicePin, IdentityKey},
    control::{Ack, Cleanup, ControlMessage, Empty, ParentDurability, Status},
    job::{FileGrant, Permission, RoutePolicy},
    lease::{ClockSample, TrustedTimeAnchor},
    protocol::{Direction, Kind, device_digest},
    state::Phase,
};
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;
use uuid::Uuid;
#[path = "source_resume_tests.rs"]
mod cursor_tests;
#[path = "source_window_tests.rs"]
mod flow_tests;
#[path = "source_prefix_tests.rs"]
mod prefix_tests;
struct Offer {
    g: ValidatedGrant,
    t: Transcript,
    s: EphemeralKey,
    r: EphemeralKey,
    a: [u8; 64],
    b: [u8; 64],
    sp: DevicePin,
    tp: DevicePin,
}
impl Offer {
    fn new(data: &[u8], generation: u64) -> Self {
        Self::paths(
            data,
            generation,
            "/source/file.bin".into(),
            "/target/file.bin".into(),
        )
    }
    fn paths(data: &[u8], generation: u64, source_path: String, destination_path: String) -> Self {
        Self::paths_with_chunk(data, generation, source_path, destination_path, 65536)
    }
    fn paths_with_chunk(
        data: &[u8],
        generation: u64,
        source_path: String,
        destination_path: String,
        chunk_bytes: u32,
    ) -> Self {
        let j = JobSpec {
            version: crate::fleet::job::JOB_VERSION,
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("source-A").unwrap(),
            target_device: device_digest("target-B").unwrap(),
            transfer_id: Uuid::from_bytes([5; 16]),
            file_id: Uuid::from_bytes([6; 16]),
            source_path,
            destination_path,
            bytes_total: data.len() as u64,
            sha256: Sha256::digest(data).into(),
            overwrite: false,
            pre_image_sha256: None,
            route: RoutePolicy::RelayOnly,
            deadline_ms: 60100,
            idempotency_key: "source-ack-local".into(),
        };
        let g = FileGrant {
            binding: Binding {
                fleet_id: j.fleet_id,
                source_device: j.source_device,
                target_device: j.target_device,
                source_session: Uuid::from_bytes([3; 16]),
                target_session: Uuid::from_bytes([4; 16]),
                transfer_id: j.transfer_id,
                file_id: j.file_id,
                authorization_id: Uuid::from_u128(1000 + generation as u128),
                key_epoch: Uuid::from_u128(2000 + generation as u128),
            },
            job_digest: j.digest().unwrap(),
            permission: Permission::SendFileNoClobber,
            chunk_bytes,
            issued_at_ms: if generation == 0 { 100 } else { 201 },
            expires_at_ms: 50100 + generation,
        }
        .validate_for(j)
        .unwrap();
        let s = EphemeralKey::generate();
        let r = EphemeralKey::generate();
        let sk = IdentityKey::from_test_seed([0x11; 32]);
        let tk = IdentityKey::from_test_seed([0x22; 32]);
        let t = Transcript::for_grant(&g, sk.public(), tk.public(), s.public(), r.public());
        let a = sk.sign(&t, Direction::SourceToTarget).unwrap();
        let b = tk.sign(&t, Direction::TargetToSource).unwrap();
        Self {
            g,
            t,
            s,
            r,
            a,
            b,
            sp: DevicePin::approved("source-A", sk.public()).unwrap(),
            tp: DevicePin::approved("target-B", tk.public()).unwrap(),
        }
    }
    fn pair(self) -> (LeasedRecords, LeasedRecords) {
        let sample = ClockSample::now();
        let s = self
            .s
            .authenticate_leased(
                &self.t,
                Direction::SourceToTarget,
                &self.g,
                &self.sp,
                &self.tp,
                &self.a,
                &self.b,
                TrustedTimeAnchor::approved_window(sample, 200, 200).unwrap(),
            )
            .unwrap();
        let r = self
            .r
            .authenticate_leased(
                &self.t,
                Direction::TargetToSource,
                &self.g,
                &self.sp,
                &self.tp,
                &self.a,
                &self.b,
                TrustedTimeAnchor::approved_window(sample, 200, 200).unwrap(),
            )
            .unwrap();
        (s, r)
    }
    fn raw_peer(self) -> (LeasedRecords, AuthenticatedRecords, ValidatedGrant) {
        let sample = ClockSample::now();
        let s = self
            .s
            .authenticate_leased(
                &self.t,
                Direction::SourceToTarget,
                &self.g,
                &self.sp,
                &self.tp,
                &self.a,
                &self.b,
                TrustedTimeAnchor::approved_window(sample, 200, 200).unwrap(),
            )
            .unwrap();
        let r = self
            .r
            .authenticate(
                &self.t,
                Direction::TargetToSource,
                &self.g,
                &self.sp,
                &self.tp,
                &self.a,
                &self.b,
                200,
            )
            .unwrap();
        (s, r, self.g)
    }
}
fn receipt(data: &[u8]) -> Receipt {
    Receipt {
        receipt_id: Uuid::from_bytes([9; 16]),
        size: data.len() as u64,
        sha256: Sha256::digest(data).into(),
        parent_durability: ParentDurability::Unsupported,
    }
}
fn waiting(data: &[u8]) -> (AwaitingCommit, LeasedRecords) {
    let (s, r) = Offer::new(data, 0).pair();
    let mut s = SourceEncoder::new(s).unwrap();
    for c in data.chunks(65536) {
        s.encode_next(c).unwrap();
    }
    let s = s.finish().unwrap();
    (s, r)
}
#[test]
fn fresh_source_only_rejects_target_role_used_attempts_and_renewed_history() {
    let (_, r) = Offer::new(b"abc", 0).pair();
    assert!(SourceEncoder::new(r).is_err());
    for mode in 0..4 {
        let (mut s, _) = Offer::new(b"abc", 0).pair();
        match mode {
            0 => {
                s.seal_data(0, b"a").unwrap();
            }
            1 => {
                s.seal_control(ControlBody::Prepare(Empty {})).unwrap();
            }
            2 => {
                assert!(s.open_record(b"malformed").is_err());
            }
            _ => {
                assert!(s.seal_data(99, b"a").is_err());
            }
        }
        let e = SourceEncoder::new(s).err().unwrap();
        assert!(format!("{e:#}").contains("used/renewed"));
    }
    let (mut s, _) = Offer::new(b"abc", 0).pair();
    std::thread::sleep(Duration::from_millis(3));
    let n = Offer::new(b"abc", 1);
    s.renew(n.g, n.s, &n.t, &n.a, &n.b).unwrap();
    assert!(SourceEncoder::new(s).is_err());
}
#[test]
fn ordered_bytes_count_is_encoding_not_delivery_or_completion() {
    let (s, _never_receives) = Offer::new(b"abc", 0).pair();
    let mut s = SourceEncoder::new(s).unwrap();
    assert_eq!(s.bytes_encoded(), 0);
    s.encode_next(b"a").unwrap();
    assert_eq!(s.bytes_encoded(), 1);
    s.encode_next(b"bc").unwrap();
    assert_eq!(s.bytes_encoded(), 3);
    let s = s.finish().unwrap();
    assert_eq!(s.status(), SourceCommitStatus::AwaitingAck);
    assert_eq!(s.bytes_peer_reported_committed(), 0);
    assert!(s.peer_observation().is_none());
}
#[test]
fn empty_overrun_and_chunk_limit_errors_never_advance_hash_or_count() {
    for mode in 0..2 {
        let (s, _) = Offer::new(b"abc", 0).pair();
        let mut s = SourceEncoder::new(s).unwrap();
        assert!(
            s.encode_next(if mode == 0 { b"" } else { b"abcd" })
                .is_err()
        );
        assert_eq!(s.bytes_encoded(), 0);
        s.encode_next(b"abc").unwrap();
        s.finish().unwrap();
    }
    let data = vec![0x23; 65537];
    let (s, _) = Offer::new(&data, 0).pair();
    let mut s = SourceEncoder::new(s).unwrap();
    assert!(s.encode_next(&data).is_err());
    assert_eq!(s.bytes_encoded(), 0);
    s.encode_next(&data[..65536]).unwrap();
    s.encode_next(&data[65536..]).unwrap();
    s.finish().unwrap();
}
#[test]
fn incomplete_encoding_or_wrong_actual_sha_cannot_create_finish_owner() {
    let (s, _) = Offer::new(b"abc", 0).pair();
    let mut s = SourceEncoder::new(s).unwrap();
    s.encode_next(b"a").unwrap();
    assert!(s.finish().is_err());
    let (s, _) = Offer::new(b"abc", 0).pair();
    let mut s = SourceEncoder::new(s).unwrap();
    s.encode_next(b"xyz").unwrap();
    let e = s.finish().err().unwrap();
    assert!(format!("{e:#}").contains("SHA256"));
}
#[test]
fn finish_is_cached_ciphertext_and_repeat_is_not_fresh_finish() {
    let (mut s, mut r) = waiting(b"abc");
    let first = s.finish_record().to_vec();
    assert!(
        matches!(r.open_record(&first).unwrap(),PeerRecord::Control{message,..}if message.body==ControlBody::Finish(Finish{size:3,sha256:Sha256::digest(b"abc").into()}))
    );
    assert_eq!(first, s.finish_record());
    assert!(matches!(
        r.open_record(s.finish_record()).unwrap(),
        PeerRecord::Duplicate { .. }
    ));
    s.connection_lost();
    assert_eq!(s.status(), SourceCommitStatus::CommitUnknown);
    assert_eq!(s.bytes_peer_reported_committed(), 0);
}
#[test]
fn full_progress_and_completed_status_do_not_replace_final_ack() {
    let (mut s, mut r) = waiting(b"abc");
    for body in [
        ControlBody::Ack(Ack {
            contiguous: 3,
            received: 3,
        }),
        ControlBody::Status(Status {
            phase: Phase::Completed,
            bytes_received: 3,
            bytes_committed: 3,
            cleanup: Cleanup::NotRequired,
            receipt: Some(receipt(b"abc")),
            error: None,
        }),
    ] {
        let f = r.seal_control(body).unwrap();
        assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::NotFinal);
        assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::NotFinal);
        assert_eq!(s.status(), SourceCommitStatus::AwaitingAck);
        assert_eq!(s.bytes_peer_reported_committed(), 0);
    }
    let f = r
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::Accepted);
}
#[test]
fn exact_accepted_ack_is_idempotent_but_unrelated_duplicate_is_not_final() {
    let (mut s, mut r) = waiting(b"abc");
    let old = r
        .seal_control(ControlBody::Ack(Ack {
            contiguous: 3,
            received: 3,
        }))
        .unwrap();
    assert_eq!(s.observe_final(&old).unwrap(), FinalAckOutcome::NotFinal);
    let f = r
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::Accepted);
    let observed = s.peer_observation().unwrap().clone();
    assert_eq!(s.status(), SourceCommitStatus::PeerReportedCompleted);
    assert_eq!(s.bytes_peer_reported_committed(), 3);
    assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::Duplicate);
    assert_eq!(s.observe_final(&old).unwrap(), FinalAckOutcome::NotFinal);
    s.connection_lost();
    assert_eq!(s.status(), SourceCommitStatus::PeerReportedCompleted);
    assert_eq!(s.peer_observation(), Some(&observed));
}
#[test]
fn fresh_second_ack_equal_or_conflicting_closes_without_erasing_history() {
    for equal in [false, true] {
        let (mut s, mut r) = waiting(b"abc");
        let f = r
            .seal_control(ControlBody::CommitAck(receipt(b"abc")))
            .unwrap();
        s.observe_final(&f).unwrap();
        let old = s.peer_observation().unwrap().clone();
        let mut next = receipt(b"abc");
        if !equal {
            next.receipt_id = Uuid::new_v4();
        }
        let fresh = r.seal_control(ControlBody::CommitAck(next)).unwrap();
        assert!(s.observe_final(&fresh).is_err());
        assert!(s.is_faulted());
        assert!(s.observe_final(&f).is_err());
        assert_eq!(s.peer_observation(), Some(&old));
        assert_eq!(s.status(), SourceCommitStatus::PeerReportedCompleted);
    }
}
#[test]
fn malformed_aead_and_foreign_session_do_not_complete_or_poison_valid_ack() {
    let (mut s, mut r) = waiting(b"abc");
    let f = r
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    let mut corrupted = f.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(s.observe_final(&corrupted).is_err());
    assert!(s.observe_final(b"malformed").is_err());
    let (_, mut other) = Offer::new(b"abc", 0).pair();
    let other = other
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    assert!(s.observe_final(&other).is_err());
    assert!(!s.is_faulted());
    assert!(s.peer_observation().is_none());
    assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::Accepted);
}
#[test]
fn valid_json_authenticated_bad_size_sha_id_or_binding_digest_cannot_become_duplicate_success() {
    for mode in 0..5 {
        let (source, mut raw, g) = Offer::new(b"abc", 0).raw_peer();
        let mut source = SourceEncoder::new(source).unwrap();
        source.encode_next(b"abc").unwrap();
        let mut s = source.finish().unwrap();
        let good = ControlMessage::new(&g, ControlBody::CommitAck(receipt(b"abc"))).unwrap();
        let mut json = serde_json::to_value(good).unwrap();
        match mode {
            0 => json["body"]["payload"]["size"] = serde_json::json!(4),
            1 => json["body"]["payload"]["sha256"] = serde_json::to_value([0u8; 32]).unwrap(),
            2 => json["body"]["payload"]["receiptId"] = serde_json::json!(Uuid::nil()),
            3 => json["jobDigest"] = serde_json::to_value([0u8; 32]).unwrap(),
            _ => json["grantDigest"] = serde_json::to_value([0u8; 32]).unwrap(),
        };
        assert!(
            serde_json::from_value::<ControlMessage>(json.clone()).is_ok(),
            "valid JSON semantic case{mode}"
        );
        let f = raw
            .seal(Kind::CommitAck, 0, &serde_json::to_vec(&json).unwrap(), 200)
            .unwrap();
        assert!(s.observe_final(&f).is_err());
        assert!(s.is_faulted());
        assert_eq!(s.status(), SourceCommitStatus::CommitUnknown);
        assert_eq!(s.bytes_peer_reported_committed(), 0);
        assert!(s.observe_final(&f).is_err());
    }
}
#[test]
fn source_expiry_before_encoding_or_finish_never_reopens_data() {
    for after_data in [false, true] {
        let (records, _) = Offer::new(b"abc", 0).pair();
        let mut s = SourceEncoder::new(records).unwrap();
        if after_data {
            s.encode_next(b"abc").unwrap();
        }
        s.records.test_expire();
        if after_data {
            assert!(s.finish().is_err())
        } else {
            assert!(s.encode_next(b"abc").is_err());
            assert_eq!(s.bytes_encoded(), 0);
            assert!(s.finish().is_err());
        }
    }
}
#[test]
fn late_ack_after_expiry_or_disconnect_can_settle_same_live_session() {
    let (mut s, mut r) = waiting(b"abc");
    s.connection_lost();
    s.records.test_expire();
    let f = r
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    assert_eq!(s.status(), SourceCommitStatus::CommitUnknown);
    assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::Accepted);
    assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::Duplicate);
    assert_eq!(s.bytes_peer_reported_committed(), 3);
}
#[test]
fn clock_discontinuity_prevents_ack_even_when_crypto_would_match() {
    let (mut s, mut r) = waiting(b"abc");
    let f = r
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    s.records.test_discontinuous();
    assert!(s.observe_final(&f).is_err());
    assert!(s.is_faulted());
    assert_eq!(s.status(), SourceCommitStatus::CommitUnknown);
    assert!(s.peer_observation().is_none());
}
#[test]
fn partial_encoder_renewal_keeps_count_sha_and_uses_current_epoch_ack() {
    let (records, mut target) = Offer::new(b"abc", 0).pair();
    let mut s = SourceEncoder::new(records).unwrap();
    let f = s.encode_next(b"a").unwrap();
    target.open_record(&f).unwrap();
    std::thread::sleep(Duration::from_millis(3));
    let n = Offer::new(b"abc", 1);
    let binding = n.g.grant().binding.clone();
    let stale_epoch_ack = target
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    s.renew(n.g.clone(), n.s, &n.t, &n.a, &n.b).unwrap();
    target.renew(n.g, n.r, &n.t, &n.a, &n.b).unwrap();
    assert_eq!(s.bytes_encoded(), 1);
    target.open_record(&s.encode_next(b"bc").unwrap()).unwrap();
    let mut s = s.finish().unwrap();
    target.open_record(s.finish_record()).unwrap();
    assert!(s.observe_final(&stale_epoch_ack).is_err());
    assert!(s.peer_observation().is_none());
    let ack = target
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    s.observe_final(&ack).unwrap();
    assert_eq!(s.peer_observation().unwrap().binding(), &binding);
}
#[test]
fn failed_renewal_preserves_original_hash_and_session_without_fresh_import() {
    let (records, mut target) = Offer::new(b"abc", 0).pair();
    let mut s = SourceEncoder::new(records).unwrap();
    target.open_record(&s.encode_next(b"a").unwrap()).unwrap();
    std::thread::sleep(Duration::from_millis(3));
    let n = Offer::new(b"abc", 1);
    let mut bad = n.b;
    bad[0] ^= 1;
    assert!(s.renew(n.g, n.s, &n.t, &n.a, &bad).is_err());
    assert_eq!(s.bytes_encoded(), 1);
    target.open_record(&s.encode_next(b"bc").unwrap()).unwrap();
    let mut s = s.finish().unwrap();
    target.open_record(s.finish_record()).unwrap();
    let ack = target
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    s.observe_final(&ack).unwrap();
    assert_eq!(
        s.peer_observation().unwrap().binding().authorization_id,
        Uuid::from_u128(1000)
    );
}
#[test]
fn empty_file_still_requires_final_authenticated_receipt() {
    let (mut s, mut target) = waiting(b"");
    assert_eq!(s.status(), SourceCommitStatus::AwaitingAck);
    assert_eq!(s.bytes_peer_reported_committed(), 0);
    let f = target
        .seal_control(ControlBody::CommitAck(receipt(b"")))
        .unwrap();
    assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::Accepted);
    assert_eq!(s.status(), SourceCommitStatus::PeerReportedCompleted);
    assert_eq!(s.peer_observation().unwrap().receipt().size, 0);
}
#[test]
fn precomputed_authenticated_ack_is_only_peer_claim_not_private_io_proof() {
    let (records, mut peer) = Offer::new(b"abc", 0).pair();
    // Deliberately dishonest peer: knows approved SHA and claims receipt BEFORE
    // seeing any DATA/FINISH. Wire authentication cannot prove its private IO.
    let precomputed = peer
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    let mut source = SourceEncoder::new(records).unwrap();
    source.encode_next(b"abc").unwrap();
    let mut pending = source.finish().unwrap();
    assert_eq!(pending.status(), SourceCommitStatus::AwaitingAck);
    assert_eq!(
        pending.observe_final(&precomputed).unwrap(),
        FinalAckOutcome::Accepted
    );
    assert_eq!(pending.status(), SourceCommitStatus::PeerReportedCompleted);
    assert_eq!(
        pending.peer_observation().unwrap().receipt(),
        &receipt(b"abc")
    );
    // No Runtime, target file or journal exists in this test. Never report this
    // typed observation as independently verified filesystem completion.
}

#[test]
fn replay_window_eviction_does_not_erase_historical_peer_receipt() {
    let (mut s, mut peer) = waiting(b"abc");
    let first = peer
        .seal_control(ControlBody::CommitAck(receipt(b"abc")))
        .unwrap();
    s.observe_final(&first).unwrap();
    let observation = s.peer_observation().unwrap().clone();
    for _ in 0..129 {
        let f = peer
            .seal_control(ControlBody::Ack(Ack {
                contiguous: 3,
                received: 3,
            }))
            .unwrap();
        assert_eq!(s.observe_final(&f).unwrap(), FinalAckOutcome::NotFinal);
    }
    assert!(s.observe_final(&first).is_err());
    assert_eq!(s.peer_observation(), Some(&observation));
    assert_eq!(s.status(), SourceCommitStatus::PeerReportedCompleted);
}

#[test]
fn explicit_revoke_prevents_finish_or_further_encoding() {
    let (records, _) = Offer::new(b"abc", 0).pair();
    let mut s = SourceEncoder::new(records).unwrap();
    s.encode_next(b"a").unwrap();
    s.revoke();
    assert!(s.encode_next(b"bc").is_err());
    assert!(s.finish().is_err());
}
#[cfg(windows)]
fn native_roundtrip(data: &[u8]) {
    use crate::{
        config::Policy,
        fleet::{
            identity::{make_directory, new_private},
            inventory::InventoryLimits,
        },
        runtime::Runtime,
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    make_directory(&root).unwrap();
    let db = root.join("relay.db");
    drop(new_private(&db).unwrap());
    let runtime = Runtime::new(Policy::new(vec![root.clone()], false).unwrap());
    let host = runtime
        .open_fleet_host(&db, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let offer = Offer::paths(
        data,
        0,
        root.join("source.bin").to_str().unwrap().into(),
        root.join("target.bin").to_str().unwrap().into(),
    );
    let (records, target) = offer.pair();
    let mut s = SourceEncoder::new(records).unwrap();
    let mut recv = host.admit_receiver(target).unwrap();
    let start = Instant::now();
    for c in data.chunks(65536) {
        recv.write_record(&s.encode_next(c).unwrap()).unwrap();
    }
    let mut s = s.finish().unwrap();
    assert_eq!(s.status(), SourceCommitStatus::AwaitingAck);
    let target = recv
        .seal_finish(s.finish_record())
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    assert_eq!(s.bytes_peer_reported_committed(), 0);
    assert_eq!(s.status(), SourceCommitStatus::AwaitingAck);
    assert_eq!(
        s.observe_final(target.local_commit_ack()).unwrap(),
        FinalAckOutcome::Accepted
    );
    assert_eq!(s.status(), SourceCommitStatus::PeerReportedCompleted);
    assert_eq!(s.peer_observation().unwrap().receipt(), target.receipt());
    assert_eq!(
        s.observe_final(target.local_commit_ack()).unwrap(),
        FinalAckOutcome::Duplicate
    );
    assert_eq!(
        std::fs::read(&target.snapshot().job().destination_path).unwrap(),
        data
    );
    assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
    let db = rusqlite::Connection::open(&db).unwrap();
    assert_eq!(
        db.query_row("SELECT version FROM ferroc_fleet_meta", [], |r| r
            .get::<_, u16>(0))
            .unwrap(),
        9
    );
    assert_eq!(host.status().unwrap().in_flight, 1);
    drop(target);
    assert_eq!(host.status().unwrap().in_flight, 0);
    println!(
        "SOURCE_ACK_NATIVE: bytes={} elapsed_ms={} encodedNotSent/sourceWaitsUntilAck/current9Receipt+SHA/peerReportedOnly/noSourceJournal/noNetwork",
        data.len(),
        start.elapsed().as_millis()
    );
}
#[cfg(windows)]
#[test]
fn native_v9_zero_and_cross_chunk_source_complete_only_after_real_final_ack() {
    for data in [vec![], vec![0x62; 65537]] {
        native_roundtrip(&data);
    }
}
#[cfg(windows)]
#[test]
fn native_eight_mib_source_to_v9_target_and_back_is_local_not_network() {
    native_roundtrip(&vec![0x78; 8 * 1024 * 1024]);
}

fn file_source_fixture(
    data: &[u8],
) -> (
    tempfile::TempDir,
    crate::runtime::Runtime,
    LeasedRecords,
    LeasedRecords,
) {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("source.bin");
    std::fs::write(&path, data).unwrap();
    let offer = Offer::paths(
        data,
        0,
        path.to_str().unwrap().into(),
        t.path().join("target.bin").to_str().unwrap().into(),
    );
    let (s, r) = offer.pair();
    let runtime = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![t.path().to_path_buf()], false).unwrap(),
    );
    (t, runtime, s, r)
}
#[test]
fn file_source_zero_one_and_cross_chunk_real_file_decode() {
    for data in [vec![], vec![0x23], vec![0x71; 65537]] {
        let (_t, r, s, mut target) = file_source_fixture(&data);
        let mut source = r.open_fleet_source(s).unwrap();
        let mut decoded = Vec::new();
        let mut sizes = Vec::new();
        while let Some(frame) = source.next_record().unwrap() {
            match target.open_record(&frame).unwrap() {
                PeerRecord::Data {
                    header,
                    bytes: plaintext,
                } => {
                    assert_eq!(header.offset, decoded.len() as u64);
                    sizes.push(plaintext.len());
                    decoded.extend_from_slice(&plaintext);
                }
                _ => panic!("DATA expected"),
            }
        }
        assert_eq!(source.bytes_encoded(), data.len() as u64);
        assert_eq!(decoded, data);
        assert!(sizes.iter().all(|n| *n <= 65536));
        let pending = source.finish().unwrap();
        assert!(matches!(
            target.open_record(pending.finish_record()).unwrap(),
            PeerRecord::Control {
                message: ControlMessage {
                    body: ControlBody::Finish(_),
                    ..
                },
                ..
            }
        ));
    }
}
#[test]
fn file_source_rejects_wrong_role_before_io() {
    let (_t, r, _s, target) = file_source_fixture(b"abc");
    assert!(r.open_fleet_source(target).is_err());
}
#[test]
fn file_source_rejects_previously_used_session() {
    let (_t, r, mut s, _target) = file_source_fixture(b"abc");
    s.seal_data(0, b"a").unwrap();
    assert!(r.open_fleet_source(s).is_err());
}
#[test]
fn file_source_policy_escape_is_denied() {
    let (_t, _r, s, _target) = file_source_fixture(b"abc");
    let other = tempfile::tempdir().unwrap();
    let r = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![other.path().to_path_buf()], false).unwrap(),
    );
    assert!(r.open_fleet_source(s).is_err());
}
#[test]
fn file_source_transfers_disabled_rejects_open() {
    let (_t, mut r, s, _target) = file_source_fixture(b"abc");
    r.policy.allow_transfers = false;
    assert!(r.open_fleet_source(s).is_err());
}
#[test]
fn file_source_missing_directory_and_wrong_size_are_denied() {
    for mode in 0..3 {
        let (t, r, s, _target) = file_source_fixture(b"abc");
        let p = t.path().join("source.bin");
        std::fs::rename(&p, t.path().join("saved.bin")).unwrap();
        match mode {
            0 => {}
            1 => std::fs::create_dir(&p).unwrap(),
            _ => std::fs::write(&p, b"ab").unwrap(),
        };
        assert!(r.open_fleet_source(s).is_err());
    }
}
#[test]
fn file_source_hardlink_rejected_without_deleting_either_name() {
    let (t, r, s, _target) = file_source_fixture(b"abc");
    let p = t.path().join("source.bin");
    let link = t.path().join("alias.bin");
    std::fs::hard_link(&p, &link).unwrap();
    assert!(r.open_fleet_source(s).is_err());
    assert_eq!(std::fs::read(p).unwrap(), b"abc");
    assert_eq!(std::fs::read(link).unwrap(), b"abc");
}
#[test]
fn file_source_growth_or_truncation_faults_reader_and_releases_handle() {
    for data in [b"ab".as_slice(), b"abcd".as_slice()] {
        let (t, r, s, _target) = file_source_fixture(b"abc");
        let mut source = r.open_fleet_source(s).unwrap();
        let p = t.path().join("source.bin");
        std::fs::write(&p, data).unwrap();
        assert!(source.next_record().is_err());
        assert!(source.next_record().is_err());
        // Verify release BEFORE consuming/dropping the failed owner.
        std::fs::rename(&p, t.path().join("after-error.bin")).unwrap();
        assert!(source.finish().is_err());
    }
}
#[test]
fn file_source_same_size_change_cannot_emit_finish() {
    let (t, r, s, _target) = file_source_fixture(b"abc");
    let mut source = r.open_fleet_source(s).unwrap();
    std::fs::write(t.path().join("source.bin"), b"xyz").unwrap();
    source.next_record().unwrap().unwrap();
    assert!(source.finish().is_err());
    assert_eq!(std::fs::read(t.path().join("source.bin")).unwrap(), b"xyz");
}
#[test]
fn file_source_finish_binds_encoded_stream_not_later_source_snapshot() {
    let (t, r, s, mut peer) = file_source_fixture(b"abc");
    let mut source = r.open_fleet_source(s).unwrap();
    let frame = source.next_record().unwrap().unwrap();
    std::fs::write(t.path().join("source.bin"), b"xyz").unwrap();
    let pending = source.finish().unwrap();
    match peer.open_record(&frame).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("DATA expected"),
    };
    assert!(matches!(
        peer.open_record(pending.finish_record()).unwrap(),
        PeerRecord::Control {
            message: ControlMessage {
                body: ControlBody::Finish(_),
                ..
            },
            ..
        }
    ));
    assert_eq!(std::fs::read(t.path().join("source.bin")).unwrap(), b"xyz");
}
#[test]
fn file_source_respects_smaller_granted_chunk() {
    let (t, r, _s, _peer) = file_source_fixture(b"abcdefghij");
    let mut o = Offer::paths(
        b"abcdefghij",
        0,
        t.path().join("source.bin").to_str().unwrap().into(),
        t.path().join("target.bin").to_str().unwrap().into(),
    );
    let mut g = o.g.grant().clone();
    g.chunk_bytes = 3;
    o.g = g.validate_for(o.g.job().clone()).unwrap();
    o.t = Transcript::for_grant(
        &o.g,
        IdentityKey::from_test_seed([0x11; 32]).public(),
        IdentityKey::from_test_seed([0x22; 32]).public(),
        o.s.public(),
        o.r.public(),
    );
    o.a = IdentityKey::from_test_seed([0x11; 32])
        .sign(&o.t, Direction::SourceToTarget)
        .unwrap();
    o.b = IdentityKey::from_test_seed([0x22; 32])
        .sign(&o.t, Direction::TargetToSource)
        .unwrap();
    let (s, mut peer) = o.pair();
    let mut source = r.open_fleet_source(s).unwrap();
    let mut lengths = Vec::new();
    while let Some(frame) = source.next_record().unwrap() {
        match peer.open_record(&frame).unwrap() {
            PeerRecord::Data { bytes, .. } => lengths.push(bytes.len()),
            _ => panic!("DATA expected"),
        }
    }
    assert_eq!(lengths, vec![3, 3, 3, 1]);
    source.finish().unwrap();
}
#[test]
fn file_source_partial_coverage_cannot_finish() {
    let (_t, r, s, _target) = file_source_fixture(&vec![1; 65537]);
    let mut source = r.open_fleet_source(s).unwrap();
    source.next_record().unwrap().unwrap();
    assert_eq!(source.bytes_encoded(), 65536);
    assert!(source.finish().is_err());
}
#[test]
fn file_source_revoke_and_expiry_before_read_are_permanent() {
    for expire in [false, true] {
        let (t, r, s, _target) = file_source_fixture(b"abc");
        let mut source = r.open_fleet_source(s).unwrap();
        if expire {
            source.test_expire();
        } else {
            source.revoke();
        }
        assert!(source.next_record().is_err());
        assert!(source.finish().is_err());
        assert_eq!(std::fs::read(t.path().join("source.bin")).unwrap(), b"abc");
    }
}
#[test]
fn file_source_expiry_after_data_prevents_finish() {
    let (_t, r, s, _target) = file_source_fixture(b"abc");
    let mut source = r.open_fleet_source(s).unwrap();
    source.next_record().unwrap().unwrap();
    source.test_expire();
    assert!(source.finish().is_err());
}
#[test]
fn file_source_idle_owner_does_not_block_shutdown_but_cannot_continue() {
    let (_t, r, s, _target) = file_source_fixture(b"abc");
    let mut source = r.open_fleet_source(s).unwrap();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(r.shutdown());
    assert!(source.next_record().is_err());
    assert!(source.finish().is_err());
}
#[test]
fn file_source_shutdown_rejects_new_owner() {
    let (_t, r, s, _target) = file_source_fixture(b"abc");
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(r.shutdown());
    assert!(r.open_fleet_source(s).is_err());
}
#[cfg(windows)]
#[test]
fn file_source_windows_original_handle_denies_path_replacement() {
    let (t, r, s, _target) = file_source_fixture(b"abc");
    let source = r.open_fleet_source(s).unwrap();
    let p = t.path().join("source.bin");
    assert!(std::fs::rename(&p, t.path().join("moved.bin")).is_err());
    drop(source);
    std::fs::rename(&p, t.path().join("moved.bin")).unwrap();
}
#[cfg(unix)]
#[test]
fn file_source_symlink_is_rejected() {
    use std::os::unix::fs::symlink;
    let (t, r, s, _target) = file_source_fixture(b"abc");
    let p = t.path().join("source.bin");
    std::fs::rename(&p, t.path().join("saved.bin")).unwrap();
    symlink(t.path().join("saved.bin"), &p).unwrap();
    assert!(r.open_fleet_source(s).is_err());
}
#[cfg(windows)]
fn file_source_native(data: &[u8]) {
    use crate::{
        config::Policy,
        fleet::{
            identity::{make_directory, new_private},
            inventory::InventoryLimits,
        },
        runtime::Runtime,
    };
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let db = root.join("relay.db");
    drop(new_private(&db).unwrap());
    let path = root.join("source.bin");
    std::fs::write(&path, data).unwrap();
    let runtime = Runtime::new(Policy::new(vec![root.clone()], false).unwrap());
    let host = runtime
        .open_fleet_host(&db, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let (s, target) = Offer::paths(
        data,
        0,
        path.to_str().unwrap().into(),
        root.join("target.bin").to_str().unwrap().into(),
    )
    .pair();
    let mut source = runtime.open_fleet_source(s).unwrap();
    let mut receiver = host.admit_receiver(target).unwrap();
    let start = Instant::now();
    let mut frames = 0;
    while let Some(frame) = source.next_record().unwrap() {
        receiver.write_record(&frame).unwrap();
        frames += 1;
    }
    let mut pending = source.finish().unwrap();
    let done = receiver
        .seal_finish(pending.finish_record())
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    assert_eq!(pending.status(), SourceCommitStatus::AwaitingAck);
    assert_eq!(
        pending.observe_final(done.local_commit_ack()).unwrap(),
        FinalAckOutcome::Accepted
    );
    assert_eq!(std::fs::read(root.join("target.bin")).unwrap(), data);
    assert_eq!(std::fs::read(path).unwrap(), data);
    assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
    drop(done);
    assert_eq!(host.status().unwrap().in_flight, 0);
    println!(
        "FILE_SOURCE_NATIVE bytes={} frames={} elapsed_ms={} realSourceFile+v9+ACK/localOnly/noNetwork",
        data.len(),
        frames,
        start.elapsed().as_millis()
    );
}
#[cfg(windows)]
#[test]
fn file_source_real_file_to_v9_zero_one_and_cross_chunk() {
    for data in [vec![], vec![9], vec![0x63; 65537]] {
        file_source_native(&data);
    }
}
#[cfg(windows)]
#[test]
fn file_source_eight_mib_real_source_to_v9_and_ack() {
    file_source_native(&vec![0x78; 8 * 1024 * 1024]);
}
#[test]
#[ignore = "release-only 128MiB real source IO and authenticated stream component, not network"]
fn file_source_128_mib_bounded_stream_component() {
    use std::io::Write;
    let (t, r, _old_s, _old_target) = file_source_fixture(b"");
    let path = t.path().join("source.bin");
    let chunk = vec![0x5a; 65536];
    let size = 128 * 1024 * 1024u64;
    let mut f = std::fs::File::create(&path).unwrap();
    let mut expected = Sha256::new();
    for _ in 0..size / 65536 {
        f.write_all(&chunk).unwrap();
        expected.update(&chunk);
    }
    f.sync_all().unwrap();
    drop(f);
    let expected: [u8; 32] = expected.finalize().into();
    let mut o = Offer::paths(
        b"",
        0,
        path.to_str().unwrap().into(),
        t.path().join("target.bin").to_str().unwrap().into(),
    );
    let mut job = o.g.job().clone();
    job.bytes_total = size;
    job.sha256 = expected;
    let mut grant = o.g.grant().clone();
    grant.job_digest = job.digest().unwrap();
    o.g = grant.validate_for(job).unwrap();
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    o.t = Transcript::for_grant(&o.g, sk.public(), tk.public(), o.s.public(), o.r.public());
    o.a = sk.sign(&o.t, Direction::SourceToTarget).unwrap();
    o.b = tk.sign(&o.t, Direction::TargetToSource).unwrap();
    let (s, mut target) = o.pair();
    let mut source = r.open_fleet_source(s).unwrap();
    let mut received = 0u64;
    let mut actual = Sha256::new();
    let start = std::time::Instant::now();
    let mut records = 0;
    while let Some(frame) = source.next_record().unwrap() {
        assert!(frame.len() <= 65536 + 232);
        match target.open_record(&frame).unwrap() {
            PeerRecord::Data { header, bytes } => {
                assert_eq!(header.offset, received);
                received += bytes.len() as u64;
                actual.update(&bytes);
            }
            _ => panic!("DATA expected"),
        };
        records += 1;
    }
    let source = source.finish().unwrap();
    assert_eq!(received, size);
    assert_eq!(<[u8; 32]>::from(actual.finalize()), expected);
    assert!(matches!(
        target.open_record(source.finish_record()).unwrap(),
        PeerRecord::Control {
            message: ControlMessage {
                body: ControlBody::Finish(_),
                ..
            },
            ..
        }
    ));
    println!(
        "FILE_SOURCE_SCALE bytes={} records={} max_plaintext=65536 elapsed_ms={} realFile+authenticatedStream/notNetwork/notHostCommit",
        size,
        records,
        start.elapsed().as_millis()
    );
}
