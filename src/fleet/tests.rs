use super::{
    auth::{AuthenticatedRecords, DevicePin, EphemeralKey, IdentityKey, MAX_LEASE_MS, Transcript},
    crypto::{Opened, REPLAY_WINDOW, RecordOpener, RecordSealer},
    job::{FileGrant, JobSpec, Permission, RoutePolicy, ValidatedGrant},
    protocol::{
        Binding, Direction, Frame, HEADER_LEN, Header, Kind, MAX_CONTROL, MAX_DATA, MAX_FILE_BYTES,
        MAX_RECORDS, device_digest,
    },
    ranges::{Admission, ReceiveRanges, WINDOW},
    stage::{ParentSync, Publication, PublishMode, StageBudget, StageFile},
    state::{CommitReceipt, Phase, TransferState},
};
use crate::config::Policy;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn binding() -> Binding {
    Binding {
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        source_session: Uuid::from_bytes([3; 16]),
        target_session: Uuid::from_bytes([4; 16]),
        transfer_id: Uuid::from_bytes([5; 16]),
        file_id: Uuid::from_bytes([6; 16]),
        authorization_id: Uuid::from_bytes([7; 16]),
        key_epoch: Uuid::from_bytes([8; 16]),
    }
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn vector() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/fleet-p0-vectors.json")).unwrap()
}
fn seal() -> RecordSealer {
    RecordSealer::new(&[0x42; 32], binding(), Direction::SourceToTarget).unwrap()
}
fn open() -> RecordOpener {
    RecordOpener::new(&[0x42; 32], binding(), Direction::SourceToTarget).unwrap()
}
fn plaintext(opened: Opened) -> Vec<u8> {
    match opened {
        Opened::Fresh { plaintext, .. } => plaintext.to_vec(),
        _ => panic!("expected fresh record"),
    }
}

fn job() -> JobSpec {
    let b = binding();
    JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: b.fleet_id,
        source_device: b.source_device,
        target_device: b.target_device,
        transfer_id: b.transfer_id,
        file_id: b.file_id,
        source_path: "/source/α.bin".into(),
        destination_path: "/target/β.bin".into(),
        bytes_total: 1048576,
        sha256: sha(b"abc"),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: "request-1".into(),
    }
}
fn grant(job: JobSpec) -> ValidatedGrant {
    FileGrant {
        binding: binding(),
        job_digest: job.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: MAX_DATA as u32,
        issued_at_ms: 100,
        expires_at_ms: 1000,
    }
    .validate_for(job)
    .unwrap()
}
struct Offer {
    t: Transcript,
    grant: ValidatedGrant,
    source_pin: DevicePin,
    target_pin: DevicePin,
    source: EphemeralKey,
    target: EphemeralKey,
    a: [u8; 64],
    b: [u8; 64],
}
impl Offer {
    fn new() -> Self {
        // PUBLIC fixture seeds only. Test-only constructors are absent in release.
        let a = IdentityKey::from_test_seed([0x11; 32]);
        let b = IdentityKey::from_test_seed([0x22; 32]);
        let source = EphemeralKey::from_test_bytes([0x33; 32]);
        let target = EphemeralKey::from_test_bytes([0x44; 32]);
        let grant = grant(job());
        let t = Transcript::for_grant(
            &grant,
            a.public(),
            b.public(),
            source.public(),
            target.public(),
        );
        Self {
            source_pin: DevicePin::approved("source-A", a.public()).unwrap(),
            target_pin: DevicePin::approved("target-B", b.public()).unwrap(),
            a: a.sign(&t, Direction::SourceToTarget).unwrap(),
            b: b.sign(&t, Direction::TargetToSource).unwrap(),
            t,
            grant,
            source,
            target,
        }
    }
    fn resign(&mut self) {
        // A test's explicit local re-approval is not a production TOFU path.
        let mut job = self.grant.job().clone();
        job.bytes_total = self.t.max_file_bytes;
        self.grant = FileGrant {
            binding: self.t.binding.clone(),
            job_digest: job.digest().unwrap(),
            permission: Permission::SendFileNoClobber,
            chunk_bytes: self.t.chunk_bytes,
            issued_at_ms: self.t.issued_at_ms,
            expires_at_ms: self.t.expires_at_ms,
        }
        .validate_for(job)
        .unwrap();
        self.t.job_digest = self.grant.grant().job_digest;
        self.t.grant_digest = self.grant.digest();
        self.a = IdentityKey::from_test_seed([0x11; 32])
            .sign(&self.t, Direction::SourceToTarget)
            .unwrap();
        self.b = IdentityKey::from_test_seed([0x22; 32])
            .sign(&self.t, Direction::TargetToSource)
            .unwrap();
    }
    fn source_session(self, now: u64) -> anyhow::Result<AuthenticatedRecords> {
        self.source.authenticate(
            &self.t,
            Direction::SourceToTarget,
            &self.grant,
            &self.source_pin,
            &self.target_pin,
            &self.a,
            &self.b,
            now,
        )
    }
    fn sessions(self) -> (AuthenticatedRecords, AuthenticatedRecords) {
        let a = self
            .source
            .authenticate(
                &self.t,
                Direction::SourceToTarget,
                &self.grant,
                &self.source_pin,
                &self.target_pin,
                &self.a,
                &self.b,
                200,
            )
            .unwrap();
        let b = self
            .target
            .authenticate(
                &self.t,
                Direction::TargetToSource,
                &self.grant,
                &self.source_pin,
                &self.target_pin,
                &self.a,
                &self.b,
                200,
            )
            .unwrap();
        (a, b)
    }
}

#[path = "control_tests.rs"]
mod control_contract;
#[path = "lease_profile_tests.rs"]
mod lease_profile;

#[test]
fn independent_node_record_golden_vector() {
    let vector = vector();
    let bytes = seal().seal(Kind::Data, 0, b"abc").unwrap();
    assert_eq!(hex(&binding().bytes()), vector["binding_hex"]);
    assert_eq!(hex(&bytes[..HEADER_LEN]), vector["header_hex"]);
    assert_eq!(hex(&bytes), vector["record_hex"]);
    assert_eq!(hex(&sha(&bytes)), vector["record_sha256"]);
    assert_eq!(plaintext(open().open(&bytes).unwrap()), b"abc");
}
#[test]
fn independent_node_signature_key_agreement_and_record_vector() {
    let v: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/fleet-p0-control-vectors.json"
    ))
    .unwrap();
    let o = Offer::new();
    assert_eq!(hex(&o.t.source_identity), v["source_identity_public_hex"]);
    assert_eq!(hex(&o.t.target_identity), v["target_identity_public_hex"]);
    assert_eq!(hex(&o.t.source_ephemeral), v["source_x25519_public_hex"]);
    assert_eq!(hex(&o.t.target_ephemeral), v["target_x25519_public_hex"]);
    assert_eq!(
        hex(&o.t.bytes(Direction::SourceToTarget).unwrap()),
        v["source_auth_hex"]
    );
    assert_eq!(
        hex(&o.t.bytes(Direction::TargetToSource).unwrap()),
        v["target_auth_hex"]
    );
    assert_eq!(hex(&o.a), v["source_signature_hex"]);
    assert_eq!(hex(&o.b), v["target_signature_hex"]);
    let (mut a, mut b) = o.sessions();
    let bytes = a.seal(Kind::Data, 0, b"abc", 201).unwrap();
    assert_eq!(hex(&bytes), v["authenticated_record_hex"]);
    assert_eq!(plaintext(b.open(&bytes, 201).unwrap()), b"abc");
    let ack = b.seal(Kind::Ack, 0, b"staged", 202).unwrap();
    assert_eq!(plaintext(a.open(&ack, 202).unwrap()), b"staged");
}
#[test]
fn identity_pkcs8_roundtrip_rejects_corruption() {
    let (a, encoded) = IdentityKey::generate().unwrap();
    assert_eq!(
        a.public(),
        IdentityKey::from_pkcs8(&encoded).unwrap().public()
    );
    let mut invalid = encoded.to_vec();
    *invalid.last_mut().unwrap() ^= 1;
    assert!(IdentityKey::from_pkcs8(&invalid).is_err());
    assert!(IdentityKey::from_pkcs8(&[0; 32]).is_err());
}
#[test]
fn every_frame_byte_is_authenticated_or_structurally_rejected() {
    let bytes = seal().seal(Kind::Data, 0, b"abc").unwrap();
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 1;
        assert!(open().open(&bad).is_err(), "tampered byte {i}");
    }
}
#[test]
fn truncated_oversized_trailing_and_unknown_frames_rejected() {
    let bytes = seal().seal(Kind::Data, 0, b"abc").unwrap();
    for len in 0..bytes.len() {
        assert!(Frame::decode(&bytes[..len]).is_err(), "prefix {len}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Frame::decode(&extra).is_err());
    for (i, value) in [
        (8, 1),
        (10, 255),
        (11, 3),
        (12, 1),
        (15, 215),
        (16, 255),
        (212, 255),
    ] {
        let mut bad = bytes.clone();
        bad[i] = value;
        assert!(Frame::decode(&bad).is_err(), "field {i}");
    }
    assert!(Frame::decode(&vec![0; super::protocol::MAX_FRAME + 1]).is_err());
}
#[test]
fn record_caps_direction_sequence_and_overflow() {
    assert!(seal().seal(Kind::Data, 0, b"").is_err());
    assert!(seal().seal(Kind::Data, u64::MAX, b"a").is_err());
    assert!(seal().seal(Kind::Data, MAX_FILE_BYTES, b"a").is_err());
    assert!(seal().seal(Kind::Data, 0, &vec![0; MAX_DATA + 1]).is_err());
    assert!(
        seal()
            .seal(Kind::Prepare, 0, &vec![0; MAX_CONTROL + 1])
            .is_err()
    );
    assert!(seal().seal(Kind::Ack, 0, b"").is_err());
    assert!(seal().seal(Kind::Finish, 1, b"").is_err());
    let mut h = Header {
        kind: Kind::Data,
        direction: Direction::SourceToTarget,
        binding: binding(),
        sequence: MAX_RECORDS,
        offset: 0,
        plaintext_len: 1,
    };
    assert!(h.encode().is_err());
    h.sequence = MAX_RECORDS - 1;
    assert!(h.encode().is_ok());
    assert_eq!(seal().remaining_records(), MAX_RECORDS);
}
#[test]
fn exact_ciphertext_duplicate_is_not_counted_twice() {
    let bytes = seal().seal(Kind::Data, 0, b"abc").unwrap();
    let mut r = open();
    assert!(matches!(r.open(&bytes).unwrap(), Opened::Fresh { .. }));
    assert!(matches!(r.open(&bytes).unwrap(), Opened::Duplicate { .. }));
    // A malicious authenticated sender reuses its nonce. Reject conflicting
    // records; production API only constructs sealers from fresh ephemeral keys.
    let conflict = seal().seal(Kind::Data, 0, b"xyz").unwrap();
    assert!(r.open(&conflict).is_err());
    assert!(matches!(r.open(&bytes).unwrap(), Opened::Duplicate { .. }));
}
#[test]
fn stale_sequences_and_forged_high_sequence_do_not_reset_window() {
    let mut s = seal();
    let mut frames = Vec::new();
    for i in 0..=REPLAY_WINDOW {
        frames.push(s.seal(Kind::Data, i as u64, b"x").unwrap());
    }
    let mut r = open();
    assert!(r.open(&frames[REPLAY_WINDOW]).is_ok());
    assert!(r.open(&frames[0]).is_err());
    assert!(r.open(&frames[1]).is_ok());
    let mut forged = frames[0].clone();
    forged[196..204].copy_from_slice(&(MAX_RECORDS - 1).to_be_bytes());
    let mut fresh = open();
    assert!(fresh.open(&forged).is_err());
    assert!(fresh.open(&frames[0]).is_ok());
}
#[test]
fn every_context_dimension_is_bound() {
    let frame = seal().seal(Kind::Data, 0, b"x").unwrap();
    for i in 0..9 {
        let mut b = binding();
        match i {
            0 => b.fleet_id = Uuid::new_v4(),
            1 => b.source_device[0] ^= 1,
            2 => b.target_device[0] ^= 1,
            3 => b.source_session = Uuid::new_v4(),
            4 => b.target_session = Uuid::new_v4(),
            5 => b.transfer_id = Uuid::new_v4(),
            6 => b.file_id = Uuid::new_v4(),
            7 => b.authorization_id = Uuid::new_v4(),
            _ => b.key_epoch = Uuid::new_v4(),
        };
        assert!(
            RecordOpener::new(&[0x42; 32], b, Direction::SourceToTarget)
                .unwrap()
                .open(&frame)
                .is_err()
        );
    }
    let mut b = binding();
    b.target_device = b.source_device;
    assert!(b.validate().is_err());
    let mut b = binding();
    b.transfer_id = Uuid::nil();
    assert!(b.validate().is_err());
    assert!(device_digest("").is_err());
    assert!(device_digest("bad\nidentity").is_err());
    assert!(RecordSealer::new(&[0; 32], binding(), Direction::SourceToTarget).is_err());
}
#[test]
fn handshake_tamper_replay_and_unapproved_pins_rejected() {
    for i in 0..8 {
        let mut o = Offer::new();
        match i {
            0 => o.t.source_ephemeral[0] ^= 1,
            1 => o.t.target_ephemeral[0] ^= 1,
            2 => o.t.max_file_bytes -= 1,
            3 => o.t.chunk_bytes -= 1,
            4 => o.t.expires_at_ms += 1,
            5 => o.t.binding.key_epoch = Uuid::new_v4(),
            6 => o.a[0] ^= 1,
            _ => o.b[0] ^= 1,
        };
        assert!(o.source_session(200).is_err(), "handshake tamper {i}");
    }
    let mut o = Offer::new();
    o.source_pin = DevicePin::approved("other-device", o.t.source_identity).unwrap();
    assert!(o.source_session(200).is_err());
    let mut o = Offer::new();
    o.source_pin = DevicePin::approved("source-A", o.t.target_identity).unwrap();
    assert!(o.source_session(200).is_err());
    let mut o = Offer::new();
    std::mem::swap(&mut o.a, &mut o.b);
    assert!(o.source_session(200).is_err());
}
#[test]
fn handshake_rejects_low_order_keys_oversized_leases_and_wrong_role() {
    let mut o = Offer::new();
    o.t.target_ephemeral = [0; 32];
    o.resign();
    assert!(o.source_session(200).is_err());
    let mut o = Offer::new();
    o.t.source_ephemeral = [0; 32];
    o.resign();
    assert!(o.source_session(200).is_err());
    let mut o = Offer::new();
    o.t.expires_at_ms = o.t.issued_at_ms + MAX_LEASE_MS + 1;
    assert!(o.t.bytes(Direction::SourceToTarget).is_err());
    o.t.expires_at_ms = o.t.issued_at_ms;
    assert!(o.t.bytes(Direction::SourceToTarget).is_err());
    assert!(Offer::new().source_session(99).is_err());
    assert!(Offer::new().source_session(1000).is_err());
    let o = Offer::new();
    assert!(
        IdentityKey::from_test_seed([0x11; 32])
            .sign(&o.t, Direction::TargetToSource)
            .is_err()
    );
}
#[test]
fn authenticated_quotas_and_expiry_do_not_allow_clock_rollback() {
    let mut o = Offer::new();
    o.t.max_file_bytes = 3;
    o.t.chunk_bytes = 2;
    o.resign();
    let (mut a, mut b) = o.sessions();
    assert!(a.seal(Kind::Data, 0, b"abc", 201).is_err());
    assert!(a.seal(Kind::Data, 2, b"ab", 202).is_err());
    let frame = a.seal(Kind::Data, 1, b"ab", 203).unwrap();
    assert!(b.open(&frame, 1000).is_err());
    assert!(b.open(&frame, 999).is_err());
    assert!(a.seal(Kind::Finish, 0, b"", 1000).is_err());
    assert!(a.seal(Kind::Data, 0, b"a", 999).is_err());
    let cancel = a.seal(Kind::Cancel, 0, b"", 1001).unwrap();
    assert!(b.open(&cancel, 1001).is_ok());
    let receipt = b.seal(Kind::CommitAck, 0, b"receipt-only", 1002).unwrap();
    assert!(a.open(&receipt, 1002).is_ok());
}
#[test]
fn authenticated_receiver_enforces_negotiated_not_only_global_caps() {
    let mut small = Offer::new();
    small.t.chunk_bytes = 1;
    small.resign();
    let (mut small_source, mut small_target) = small.sessions();
    let valid = small_source.seal(Kind::Data, 0, b"a", 200).unwrap();
    assert_eq!(plaintext(small_target.open(&valid, 200).unwrap()), b"a");
    let (mut full_source, _) = Offer::new().sessions();
    let frame = full_source.seal(Kind::Data, 0, b"ab", 201).unwrap();
    // The other offer also has a different transcript-derived key. is_err
    // alone would falsely pass on an AEAD failure if quota checking vanished.
    assert_eq!(
        small_target.open(&frame, 201).err().unwrap().to_string(),
        "DATA exceeds authenticated quota"
    );
}
#[test]
fn coverage_all_four_chunk_permutations_match_scalar_oracle() {
    let mut cases = 0;
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let mut order = [a, b, c, d];
                    order.sort();
                    if order != [0, 1, 2, 3] {
                        continue;
                    }
                    let mut r = ReceiveRanges::new(12).unwrap();
                    let mut bitmap = [false; 12];
                    for i in [a, b, c, d] {
                        r.record_written((i * 3) as u64, 3, [i as u8; 32]).unwrap();
                        bitmap[i * 3..i * 3 + 3].fill(true);
                        assert_eq!(r.received(), bitmap.iter().filter(|&&v| v).count() as u64);
                        assert_eq!(
                            r.contiguous(),
                            bitmap.iter().position(|&v| !v).unwrap_or(12) as u64
                        );
                        assert!(r.pending_ranges() <= WINDOW);
                    }
                    assert!(r.complete());
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 24);
}
#[test]
fn coverage_overlap_conflicting_duplicate_and_holes_rejected() {
    let mut r = ReceiveRanges::new(10).unwrap();
    assert!(r.record_written(3, 4, [1; 32]).is_ok());
    assert_eq!(
        r.record_written(3, 4, [1; 32]).unwrap(),
        Admission::Duplicate
    );
    assert_eq!(r.received(), 4);
    for (offset, len, digest) in [
        (3, 4, [2; 32]),
        (4, 1, [1; 32]),
        (1, 3, [1; 32]),
        (9, 2, [1; 32]),
        (u64::MAX, 1, [1; 32]),
        (0, 0, [1; 32]),
    ] {
        assert!(r.record_written(offset, len, digest).is_err());
    }
    assert!(!r.complete());
    assert_eq!(r.received(), 4);
    r.record_written(0, 3, [0; 32]).unwrap();
    assert_eq!(r.contiguous(), 7);
    assert!(r.record_written(0, 3, [0; 32]).is_err());
}
#[test]
fn coverage_full_window_can_always_fill_the_missing_prefix() {
    let mut r = ReceiveRanges::new(10).unwrap();
    for offset in 1..=8 {
        r.record_written(offset, 1, [1; 32]).unwrap();
    }
    assert_eq!(r.pending_ranges(), WINDOW);
    assert!(r.record_written(9, 1, [1; 32]).is_err());
    r.record_written(0, 1, [1; 32]).unwrap();
    assert_eq!(r.pending_ranges(), 0);
    assert_eq!(r.contiguous(), 9);
    r.record_written(9, 1, [1; 32]).unwrap();
    assert!(r.complete());
    let mut r = ReceiveRanges::new(MAX_FILE_BYTES).unwrap();
    assert!(
        r.record_written((MAX_DATA * WINDOW + 1) as u64, 1, [1; 32])
            .is_err()
    );
    assert!(ReceiveRanges::new(MAX_FILE_BYTES + 1).is_err());
    assert!(ReceiveRanges::new(0).unwrap().complete());
}

fn verified_state() -> TransferState {
    let mut s = TransferState::new(binding(), 3, 1000, 100).unwrap();
    s.prepare(101).unwrap();
    s.ready(102).unwrap();
    let mut r = ReceiveRanges::new(3).unwrap();
    r.record_written(0, 3, sha(b"abc")).unwrap();
    s.begin_verification(&r, sha(b"abc"), 103).unwrap();
    s.verify_readback(sha(b"abc"), 104).unwrap();
    s
}
fn receipt() -> CommitReceipt {
    CommitReceipt {
        binding: binding(),
        size: 3,
        sha256: sha(b"abc"),
    }
}
#[test]
fn state_rejects_early_finish_wrong_coverage_and_unverified_commit() {
    let mut s = TransferState::new(binding(), 3, 1000, 100).unwrap();
    assert!(s.ready(101).is_err());
    s.prepare(102).unwrap();
    s.ready(103).unwrap();
    assert!(
        s.begin_verification(&ReceiveRanges::new(3).unwrap(), sha(b"abc"), 104)
            .is_err()
    );
    assert!(
        s.begin_verification(&ReceiveRanges::new(0).unwrap(), sha(b"abc"), 105)
            .is_err()
    );
    assert!(s.begin_commit(106).is_err());
    assert_eq!(s.bytes_committed(), 0);
    let mut r = ReceiveRanges::new(3).unwrap();
    r.record_written(0, 3, sha(b"abc")).unwrap();
    s.begin_verification(&r, sha(b"abc"), 107).unwrap();
    assert!(s.begin_commit(108).is_err());
    assert!(s.verify_readback(sha(b"bad"), 109).is_err());
    assert_eq!(s.phase(), Phase::Failed);
    assert!(s.begin_commit(110).is_err());
}
#[test]
fn state_only_matching_receipt_completes_and_is_idempotent() {
    let mut s = verified_state();
    assert!(s.reconcile_commit(receipt()).is_err());
    s.begin_commit(105).unwrap();
    let mut bad = receipt();
    bad.size = 4;
    assert!(s.reconcile_commit(bad).is_err());
    let mut bad = receipt();
    bad.binding.source_session = Uuid::new_v4();
    assert!(s.reconcile_commit(bad).is_err());
    let mut bad = receipt();
    bad.sha256[0] ^= 1;
    assert!(s.reconcile_commit(bad).is_err());
    assert_eq!(s.bytes_committed(), 0);
    s.reconcile_commit(receipt()).unwrap();
    s.reconcile_commit(receipt()).unwrap();
    assert_eq!(s.phase(), Phase::Completed);
    assert_eq!(s.bytes_committed(), 3);
    let mut bad = receipt();
    bad.size = 4;
    assert!(s.reconcile_commit(bad).is_err());
    assert_eq!(s.bytes_committed(), 3);
    assert_eq!(s.expire(1001).unwrap(), Phase::Completed);
    assert_eq!(s.request_cancel(), Phase::Completed);
}
#[test]
fn cancellation_before_commit_needs_cleanup_confirmation() {
    for phase in 0..4 {
        let mut s = TransferState::new(binding(), 3, 1000, 100).unwrap();
        if phase >= 1 {
            s.prepare(101).unwrap();
        }
        if phase >= 2 {
            s.ready(102).unwrap();
        }
        if phase >= 3 {
            s = verified_state();
        }
        assert!(s.confirm_cancelled().is_err());
        assert_eq!(s.request_cancel(), Phase::CancelRequested);
        assert!(s.begin_commit(200).is_err());
        s.confirm_cancelled().unwrap();
        assert_eq!(s.phase(), Phase::Cancelled);
        assert_eq!(s.request_cancel(), Phase::Cancelled);
        assert!(s.reconcile_commit(receipt()).is_err());
    }
}
#[test]
fn lost_ack_cancel_disconnect_and_expiry_never_falsely_undo_commit() {
    for event in 0..3 {
        let mut s = verified_state();
        s.begin_commit(105).unwrap();
        match event {
            0 => {
                s.request_cancel();
            }
            1 => s.connection_lost(),
            _ => {
                s.expire(1000).unwrap();
            }
        }
        assert_eq!(s.phase(), Phase::CommitUnknown);
        assert_eq!(s.bytes_committed(), 0);
        assert!(s.confirm_cancelled().is_err());
        s.reconcile_commit(receipt()).unwrap();
        assert_eq!(s.phase(), Phase::Completed);
    }
    let mut s = verified_state();
    s.connection_lost();
    assert_eq!(s.phase(), Phase::Interrupted);
    assert!(s.begin_commit(106).is_err());
}
#[test]
fn total_deadline_and_monotonic_time_are_not_reset_by_failures() {
    let mut s = TransferState::new(binding(), 0, 1000, 100).unwrap();
    s.prepare(200).unwrap();
    assert!(s.ready(199).is_err());
    assert_eq!(s.expire(1000).unwrap(), Phase::Expired);
    assert!(s.ready(999).is_err());
    assert_eq!(s.phase(), Phase::Expired);
    assert!(TransferState::new(binding(), 0, 100, 100).is_err());
    assert!(TransferState::new(binding(), MAX_FILE_BYTES + 1, 1000, 100).is_err());
}

fn policy(root: &tempfile::TempDir) -> Policy {
    Policy::new(vec![root.path().into()], false).unwrap()
}
fn stage(root: &tempfile::TempDir, total: u64, budget: &StageBudget) -> StageFile {
    StageFile::prepare(
        policy(root),
        root.path().join("target.bin").to_str().unwrap(),
        total,
        budget,
        Arc::new(Mutex::new(())),
    )
    .unwrap()
}
fn stage_links(root: &tempfile::TempDir) -> usize {
    fs::read_dir(root.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|f| {
            f.file_name()
                .to_string_lossy()
                .starts_with(".ferroc-fleet-")
        })
        .count()
}
#[test]
fn local_stage_empty_one_byte_and_cross_chunk_roundtrip() {
    for size in [0, 1, MAX_DATA + 1] {
        let root = tempfile::tempdir().unwrap();
        let budget = StageBudget::new((MAX_DATA + 1) as u64, 2).unwrap();
        let mut s = stage(&root, size as u64, &budget);
        let bytes = vec![0x5a; size];
        for (i, data) in bytes.chunks(MAX_DATA).enumerate() {
            s.write_chunk((i * MAX_DATA) as u64, data).unwrap();
        }
        assert_eq!(s.bytes_received(), size as u64);
        assert_eq!(
            s.publish(sha(&bytes)).unwrap(),
            Publication::Published {
                size: size as u64,
                sha256: sha(&bytes),
                parent_sync: if cfg!(unix) {
                    ParentSync::Synced
                } else {
                    ParentSync::Unsupported
                },
                mode: PublishMode::CreateNoClobber,
            }
        );
        assert_eq!(fs::read(root.path().join("target.bin")).unwrap(), bytes);
        assert_eq!(stage_links(&root), 0);
        assert_eq!(budget.usage().unwrap(), (0, 0));
    }
}
#[test]
fn local_stage_hash_mismatch_leaves_prior_destination_untouched() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(100, 2).unwrap();
    let mut s = stage(&root, 3, &budget);
    s.write_chunk(0, b"abc").unwrap();
    fs::write(root.path().join("target.bin"), b"prior").unwrap();
    // Existing target would also reject publication. Prove the earlier hash
    // guard caused this failure instead of accepting that unrelated error.
    assert_eq!(
        s.publish(sha(b"bad")).err().unwrap().to_string(),
        "fleet readback SHA256 or size mismatch"
    );
    assert_eq!(fs::read(root.path().join("target.bin")).unwrap(), b"prior");
    assert_eq!(stage_links(&root), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[test]
fn local_stage_concurrent_target_no_clobber_and_incomplete_rejected() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(100, 2).unwrap();
    let mut s = stage(&root, 3, &budget);
    s.write_chunk(0, b"abc").unwrap();
    fs::write(root.path().join("target.bin"), b"prior").unwrap();
    assert!(s.publish(sha(b"abc")).is_err());
    assert_eq!(fs::read(root.path().join("target.bin")).unwrap(), b"prior");
    assert!(
        StageFile::prepare(
            policy(&root),
            root.path().join("target.bin").to_str().unwrap(),
            3,
            &budget,
            Arc::new(Mutex::new(()))
        )
        .is_err()
    );
    let other = root.path().join("other.bin");
    let mut s = StageFile::prepare(
        policy(&root),
        other.to_str().unwrap(),
        10,
        &budget,
        Arc::new(Mutex::new(())),
    )
    .unwrap();
    s.write_chunk(9, b"x").unwrap();
    assert!(s.publish(sha(b"x")).is_err());
    assert!(!other.exists());
    assert_eq!(stage_links(&root), 0);
}
#[test]
fn local_stage_cancel_and_faulted_write_cleanup_are_explicit() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(100, 2).unwrap();
    let mut s = stage(&root, 3, &budget);
    s.write_chunk(0, b"a").unwrap();
    assert_eq!(stage_links(&root), 1);
    s.cancel().unwrap();
    assert_eq!(stage_links(&root), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert!(!root.path().join("target.bin").exists());
    let mut s = stage(&root, 3, &budget);
    assert!(s.write_chunk(3, b"x").is_err());
    assert!(s.write_chunk(0, b"abc").is_err());
    assert!(s.publish(sha(b"abc")).is_err());
    assert_eq!(stage_links(&root), 0);
}
#[test]
fn local_stage_byte_active_quota_and_drop_release_reservations() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(2, 1).unwrap();
    let s = stage(&root, 2, &budget);
    assert_eq!(budget.usage().unwrap(), (2, 1));
    assert!(
        StageFile::prepare(
            policy(&root),
            root.path().join("second").to_str().unwrap(),
            0,
            &budget,
            Arc::new(Mutex::new(()))
        )
        .is_err()
    );
    drop(s);
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert_eq!(stage_links(&root), 0);
    assert!(
        StageFile::prepare(
            policy(&root),
            root.path().join("second").to_str().unwrap(),
            3,
            &budget,
            Arc::new(Mutex::new(()))
        )
        .is_err()
    );
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert!(StageBudget::new(1, 5).is_err());
}
#[test]
fn local_stage_denies_disabled_policy_outside_traversal_and_missing_parent() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(10, 2).unwrap();
    let prepare = |p: Policy, path: &std::path::Path| {
        StageFile::prepare(
            p,
            path.to_str().unwrap(),
            1,
            &budget,
            Arc::new(Mutex::new(())),
        )
    };
    let mut disabled = policy(&root);
    disabled.allow_transfers = false;
    assert!(prepare(disabled, &root.path().join("target")).is_err());
    assert!(prepare(policy(&root), &outside.path().join("target")).is_err());
    assert!(prepare(policy(&root), &root.path().join("../escape")).is_err());
    assert!(prepare(policy(&root), &root.path().join("missing/target")).is_err());
    assert!(!root.path().join("missing").exists());
    assert_eq!(stage_links(&root), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[cfg(windows)]
#[test]
fn local_stage_windows_ads_and_device_namespaces_rejected() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(10, 2).unwrap();
    for path in [
        format!("{}:stream", root.path().join("target").display()),
        r"\\.\NUL".to_string(),
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\file".to_string(),
    ] {
        assert!(
            StageFile::prepare(policy(&root), &path, 1, &budget, Arc::new(Mutex::new(()))).is_err()
        );
    }
    assert_eq!(stage_links(&root), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[cfg(unix)]
#[test]
fn local_stage_unix_symlink_escape_rejected() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(10, 2).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
    assert!(
        StageFile::prepare(
            policy(&root),
            root.path().join("link/target").to_str().unwrap(),
            1,
            &budget,
            Arc::new(Mutex::new(()))
        )
        .is_err()
    );
    assert!(!outside.path().join("target").exists());
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[test]
fn native_partial_write_storage_full_injection_does_not_ack_or_publish() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(10, 1).unwrap();
    let mut s = stage(&root, 6, &budget);
    let err = s.inject_partial_storage_full(0, b"abcdef").err().unwrap();
    assert_eq!(
        err.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::StorageFull
    );
    assert_eq!(fs::metadata(s.stage_path()).unwrap().len(), 3);
    assert_eq!(s.bytes_received(), 0);
    fs::write(root.path().join("target.bin"), b"prior").unwrap();
    assert!(s.write_chunk(0, b"abcdef").is_err());
    assert!(s.publish(sha(b"abcdef")).is_err());
    assert_eq!(fs::read(root.path().join("target.bin")).unwrap(), b"prior");
    assert_eq!(stage_links(&root), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[test]
fn native_stage_readback_detects_modified_stage_and_releases_quota() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(10, 1).unwrap();
    let mut s = stage(&root, 3, &budget);
    s.write_chunk(0, b"abc").unwrap();
    fs::write(s.stage_path(), b"xyz").unwrap();
    assert!(s.publish(sha(b"abc")).is_err());
    assert!(!root.path().join("target.bin").exists());
    assert_eq!(stage_links(&root), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[test]
fn reserved_stage_namespace_is_not_a_destination() {
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(10, 1).unwrap();
    for name in [".ferroc-fleet-owned", ".FERROC-FLEET-owned"] {
        assert!(
            StageFile::prepare(
                policy(&root),
                root.path().join(name).to_str().unwrap(),
                1,
                &budget,
                Arc::new(Mutex::new(()))
            )
            .is_err()
        );
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[test]
fn repeated_cleanup_confirmation_is_idempotent() {
    let mut s = verified_state();
    s.request_cancel();
    s.confirm_cancelled().unwrap();
    s.confirm_cancelled().unwrap();
    assert_eq!(s.phase(), Phase::Cancelled);
}

#[cfg(windows)]
#[test]
fn native_failed_cancel_retains_bytes_slot_and_reconciles_only_after_removal() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(6, 1).unwrap();
    let mut s = stage(&root, 6, &budget);
    s.write_chunk(0, b"abcdef").unwrap();
    let owned = s.stage_path().to_path_buf();
    let blocker = fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&owned)
        .unwrap();
    // tempfile wraps the original IO error in a private PathError and its
    // outer raw_os_error is None. Establish literal OS=32 using the same
    // owned path/handle, then verify close preserved that error kind.
    let denied = fs::remove_file(&owned).expect_err("native control must deny deletion");
    assert_eq!(denied.raw_os_error(), Some(32));
    let error = s.cancel().expect_err("native handle must deny deletion");
    assert!(error.to_string().contains(&owned.display().to_string()));
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        denied.kind()
    );
    assert!(owned.exists());
    assert_eq!(budget.usage().unwrap(), (6, 1));
    let debt = budget.retained().unwrap();
    assert_eq!(debt.len(), 1);
    assert_eq!(debt[0].path, owned);
    assert_eq!(debt[0].bytes, 6);
    assert_eq!(budget.reconcile_removed().unwrap(), 0);
    assert_eq!(budget.usage().unwrap(), (6, 1));
    assert!(
        StageFile::prepare(
            policy(&root),
            root.path().join("replacement").to_str().unwrap(),
            0,
            &budget,
            Arc::new(Mutex::new(()))
        )
        .is_err()
    );
    drop(blocker);
    // Merely unblocking deletion is not proof the owned stage disappeared.
    assert_eq!(budget.reconcile_removed().unwrap(), 0);
    assert_eq!(budget.usage().unwrap(), (6, 1));
    fs::remove_file(&owned).unwrap();
    assert_eq!(budget.reconcile_removed().unwrap(), 1);
    assert_eq!(budget.reconcile_removed().unwrap(), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert!(budget.retained().unwrap().is_empty());
    stage(&root, 6, &budget).cancel().unwrap();
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[cfg(windows)]
#[test]
fn native_failed_drop_retains_even_zero_byte_active_slot() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let budget = StageBudget::new(0, 1).unwrap();
    let s = stage(&root, 0, &budget);
    let owned = s.stage_path().to_path_buf();
    let blocker = fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&owned)
        .unwrap();
    drop(s);
    assert!(owned.exists());
    assert_eq!(budget.usage().unwrap(), (0, 1));
    assert_eq!(budget.retained().unwrap().len(), 1);
    assert!(
        StageFile::prepare(
            policy(&root),
            root.path().join("replacement").to_str().unwrap(),
            0,
            &budget,
            Arc::new(Mutex::new(()))
        )
        .is_err()
    );
    drop(blocker);
    fs::remove_file(&owned).unwrap();
    assert_eq!(budget.reconcile_removed().unwrap(), 1);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[cfg(windows)]
#[test]
fn native_failed_publication_and_readback_failure_retain_unclean_stage_quota() {
    use std::os::windows::fs::OpenOptionsExt;
    for correct_hash in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let budget = StageBudget::new(6, 1).unwrap();
        let mut s = stage(&root, 6, &budget);
        s.write_chunk(0, b"abcdef").unwrap();
        let owned = s.stage_path().to_path_buf();
        let blocker = fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&owned)
            .unwrap();
        if correct_hash {
            // Native Windows sharing denial prevents no-clobber rename. A
            // publication attempt is uncertain, never a safe-to-retry failure.
            assert!(matches!(
                s.publish(sha(b"abcdef")).unwrap(),
                Publication::Uncertain {
                    reason: "no-clobber publication error; reconcile destination",
                    ..
                }
            ));
        } else {
            assert_eq!(
                s.publish(sha(b"bad")).err().unwrap().to_string(),
                "fleet readback SHA256 or size mismatch"
            );
        }
        assert!(owned.exists());
        assert!(!root.path().join("target.bin").exists());
        assert_eq!(budget.usage().unwrap(), (6, 1));
        assert_eq!(budget.retained().unwrap().len(), 1);
        assert_eq!(budget.reconcile_removed().unwrap(), 0);
        drop(blocker);
        fs::remove_file(&owned).unwrap();
        assert_eq!(budget.reconcile_removed().unwrap(), 1);
        assert_eq!(budget.usage().unwrap(), (0, 0));
    }
}

#[test]
#[ignore = "explicit local-stage scale probe; not a network transfer"]
fn local_stage_streaming_scale_probe() {
    let bytes = std::env::var("FERROC_P0_PROBE_BYTES")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(1024 * 1024 * 1024);
    assert!((1..=1024 * 1024 * 1024).contains(&bytes));
    let start = std::time::Instant::now();
    let root = match std::env::var("FERROC_P0_PROBE_PARENT") {
        Ok(parent) => tempfile::tempdir_in(parent).unwrap(),
        Err(std::env::VarError::NotPresent) => tempfile::tempdir().unwrap(),
        Err(e) => panic!("invalid probe workspace: {e}"),
    };
    let budget = StageBudget::new(bytes, 1).unwrap();
    let mut s = stage(&root, bytes, &budget);
    let chunk = vec![0x5a; MAX_DATA];
    let mut expected = Sha256::new();
    let mut offset = 0;
    while offset < bytes {
        let n = (bytes - offset).min(MAX_DATA as u64) as usize;
        s.write_chunk(offset, &chunk[..n]).unwrap();
        expected.update(&chunk[..n]);
        offset += n as u64;
    }
    let expected: [u8; 32] = expected.finalize().into();
    assert!(matches!(
        s.publish(expected).unwrap(),
        Publication::Published { .. }
    ));
    let mut file = fs::File::open(root.path().join("target.bin")).unwrap();
    let mut actual = Sha256::new();
    let mut buf = [0; 64 * 1024];
    let mut read = 0;
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        actual.update(&buf[..n]);
        read += n as u64;
    }
    assert_eq!(read, bytes);
    assert_eq!(actual.finalize().as_slice(), expected);
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert_eq!(stage_links(&root), 0);
    println!(
        "FLEET_STAGE_PROBE {}",
        json!({"scope":"local-stage-only/not-network","bytes":bytes,"sha256":hex(&expected),"elapsedMs":start.elapsed().as_millis()})
    );
}
