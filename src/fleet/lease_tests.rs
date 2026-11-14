use super::*;
use crate::{
    config::Policy,
    fleet::{
        auth::IdentityKey,
        control::{Empty, ParentDurability, Receipt},
        job::{FileGrant, JobSpec, Permission, RoutePolicy},
        protocol::{Binding, device_digest},
        stage::{Publication, StageBudget, StageFile},
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    sync::{Arc, Mutex},
};
fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn spec() -> JobSpec {
    JobSpec {
        version: 1,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::from_bytes([5; 16]),
        file_id: Uuid::from_bytes([6; 16]),
        source_path: "/source/file.bin".into(),
        destination_path: "/target/file.bin".into(),
        bytes_total: 3,
        sha256: sha(b"abc"),
        overwrite: false,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: "lease-test".into(),
    }
}
struct Offer {
    g: ValidatedGrant,
    t: Transcript,
    source: EphemeralKey,
    target: EphemeralKey,
    a: [u8; 64],
    b: [u8; 64],
    source_pin: DevicePin,
    target_pin: DevicePin,
}
impl Offer {
    fn new(generation: u64) -> Self {
        let j = spec();
        let raw = FileGrant {
            binding: Binding {
                fleet_id: j.fleet_id,
                source_device: j.source_device,
                target_device: j.target_device,
                source_session: Uuid::from_bytes([3; 16]),
                target_session: Uuid::from_bytes([4; 16]),
                transfer_id: j.transfer_id,
                file_id: j.file_id,
                authorization_id: Uuid::from_u128(10000 + generation as u128),
                key_epoch: Uuid::from_u128(20000 + generation as u128),
            },
            job_digest: j.digest().unwrap(),
            permission: Permission::SendFileNoClobber,
            chunk_bytes: 3,
            issued_at_ms: if generation == 0 {
                100
            } else {
                200 + generation
            },
            expires_at_ms: 1000 + 500 * generation,
        };
        let g = raw.validate_for(j).unwrap();
        let source = EphemeralKey::from_test_bytes(sha(format!(
            "PUBLIC TEST source ephemeral {generation}"
        )
        .as_bytes()));
        let target = EphemeralKey::from_test_bytes(sha(format!(
            "PUBLIC TEST target ephemeral {generation}"
        )
        .as_bytes()));
        let a = IdentityKey::from_test_seed([0x11; 32]);
        let b = IdentityKey::from_test_seed([0x22; 32]);
        let t = Transcript::for_grant(&g, a.public(), b.public(), source.public(), target.public());
        let mut o = Self {
            g,
            t,
            source,
            target,
            a: [0; 64],
            b: [0; 64],
            source_pin: DevicePin::approved("source-A", a.public()).unwrap(),
            target_pin: DevicePin::approved("target-B", b.public()).unwrap(),
        };
        o.resign();
        o
    }
    fn resign(&mut self) {
        self.t = Transcript::for_grant(
            &self.g,
            self.t.source_identity,
            self.t.target_identity,
            self.t.source_ephemeral,
            self.t.target_ephemeral,
        );
        self.a = IdentityKey::from_test_seed([0x11; 32])
            .sign(&self.t, Direction::SourceToTarget)
            .unwrap();
        self.b = IdentityKey::from_test_seed([0x22; 32])
            .sign(&self.t, Direction::TargetToSource)
            .unwrap();
    }
    fn modify(&mut self, change: impl FnOnce(&mut JobSpec, &mut FileGrant)) {
        let mut j = self.g.job().clone();
        let mut g = self.g.grant().clone();
        change(&mut j, &mut g);
        g.job_digest = j.digest().unwrap();
        self.g = g.validate_for(j).unwrap();
        self.resign();
    }
    fn pair(self, s: ClockSample) -> (LeasedRecords, LeasedRecords) {
        let a = self
            .source
            .authenticate_leased_between(
                &self.t,
                Direction::SourceToTarget,
                &self.g,
                &self.source_pin,
                &self.target_pin,
                &self.a,
                &self.b,
                TrustedTimeAnchor::approved_window(s, 200, 200).unwrap(),
                || s,
            )
            .unwrap();
        let b = self
            .target
            .authenticate_leased_between(
                &self.t,
                Direction::TargetToSource,
                &self.g,
                &self.source_pin,
                &self.target_pin,
                &self.a,
                &self.b,
                TrustedTimeAnchor::approved_window(s, 200, 200).unwrap(),
                || s,
            )
            .unwrap();
        (a, b)
    }
}
fn initial() -> (LeasedRecords, LeasedRecords, ClockSample) {
    let s = ClockSample::now();
    let (a, b) = Offer::new(0).pair(s);
    (a, b, s)
}
fn at(s: ClockSample, ms: u64) -> ClockSample {
    s.shifted(Duration::from_millis(ms), Duration::from_millis(ms))
}
fn renew(a: &mut LeasedRecords, o: Offer, s: ClockSample) -> Result<()> {
    a.renew_between(o.g, o.source, &o.t, &o.a, &o.b, s, || s)
}
fn both(a: &mut LeasedRecords, b: &mut LeasedRecords, o: Offer, s: ClockSample) {
    a.renew_between(o.g.clone(), o.source, &o.t, &o.a, &o.b, s, || s)
        .unwrap();
    b.renew_between(o.g, o.target, &o.t, &o.a, &o.b, s, || s)
        .unwrap();
}
fn receipt() -> ControlBody {
    ControlBody::CommitAck(Receipt {
        receipt_id: Uuid::from_bytes([9; 16]),
        size: 3,
        sha256: sha(b"abc"),
        parent_durability: ParentDurability::Unsupported,
    })
}
fn data(p: PeerRecord) -> Vec<u8> {
    match p {
        PeerRecord::Data { bytes, .. } => bytes.to_vec(),
        _ => panic!("expected DATA"),
    }
}

#[test]
fn clock_window_import_requires_certainly_live_grant() {
    assert!(TrustedTimeAnchor::approved_window(ClockSample::now(), 201, 200).is_err());
    for (low, high) in [(99, 200), (200, 1000), (1000, 1000)] {
        let o = Offer::new(0);
        let s = ClockSample::now();
        let anchor = TrustedTimeAnchor::approved_window(s, low, high).unwrap();
        assert!(
            o.source
                .authenticate_leased_between(
                    &o.t,
                    Direction::SourceToTarget,
                    &o.g,
                    &o.source_pin,
                    &o.target_pin,
                    &o.a,
                    &o.b,
                    anchor,
                    || s
                )
                .is_err()
        );
    }
}
#[test]
fn data_encryption_cannot_deliver_after_expiry_and_burned_sequence_is_not_reset() {
    let (mut a, _, s) = initial();
    assert!(
        a.seal_data_between(0, b"a", at(s, 799), || at(s, 800))
            .is_err()
    );
    let query = a
        .seal_control_at(ControlBody::StatusRequest(Empty {}), at(s, 801))
        .unwrap();
    assert_eq!(Frame::decode(&query).unwrap().header.sequence, 1);
}
#[test]
fn decrypted_data_and_finish_are_not_exposed_when_processing_crosses_expiry() {
    for finish in [false, true] {
        let (mut a, mut b, s) = initial();
        let frame = if finish {
            a.seal_control_at(
                ControlBody::Finish(crate::fleet::control::Finish {
                    size: 3,
                    sha256: sha(b"abc"),
                }),
                at(s, 700),
            )
            .unwrap()
        } else {
            a.seal_data_at(0, b"abc", at(s, 700)).unwrap()
        };
        assert!(
            b.open_record_between(&frame, at(s, 799), || at(s, 800))
                .is_err()
        );
        assert!(b.open_record_at(&frame, at(s, 801)).is_err());
    }
}
#[test]
fn finish_sealing_requires_postcrypto_lease_but_readonly_settlement_does_not() {
    let (mut a, mut b, s) = initial();
    let finish = ControlBody::Finish(crate::fleet::control::Finish {
        size: 3,
        sha256: sha(b"abc"),
    });
    assert!(
        a.seal_control_between(finish, at(s, 799), || at(s, 800))
            .is_err()
    );
    let r = b
        .seal_control_between(receipt(), at(s, 799), || at(s, 801))
        .unwrap();
    assert!(matches!(
        a.open_record_between(&r, at(s, 801), || at(s, 802))
            .unwrap(),
        PeerRecord::Control { .. }
    ));
}

#[test]
fn initial_crypto_completion_must_still_precede_imported_expiry() {
    let o = Offer::new(0);
    let s = ClockSample::now();
    let result = o.source.authenticate_leased_between(
        &o.t,
        Direction::SourceToTarget,
        &o.g,
        &o.source_pin,
        &o.target_pin,
        &o.a,
        &o.b,
        TrustedTimeAnchor::approved_window(s, 200, 200).unwrap(),
        || at(s, 800),
    );
    assert!(result.is_err());
}
#[test]
fn renewal_must_advance_both_issuance_and_expiry_without_reanchoring() {
    for kind in 0..3 {
        let (mut a, _, s) = initial();
        let original = a.clock.anchor.sample;
        let mut o = Offer::new(1);
        o.modify(|_, g| match kind {
            0 => g.issued_at_ms = 100,
            1 => g.expires_at_ms = 1000,
            _ => g.expires_at_ms = 999,
        });
        assert!(renew(&mut a, o, at(s, 100)).is_err());
        assert_eq!(a.epoch_count(), 1);
        assert_eq!(a.clock.anchor.sample.mono, original.mono);
        assert_eq!(a.clock.anchor.sample.wall, original.wall);
        a.seal_data_at(0, b"a", at(s, 200)).unwrap();
    }
}

#[test]
fn public_live_api_uses_real_clock_without_peer_supplied_now() {
    let mut o = Offer::new(0);
    o.modify(|j, g| {
        j.deadline_ms = 120000;
        g.expires_at_ms = 60000;
    });
    let s = ClockSample::now();
    let mut a = o
        .source
        .authenticate_leased(
            &o.t,
            Direction::SourceToTarget,
            &o.g,
            &o.source_pin,
            &o.target_pin,
            &o.a,
            &o.b,
            TrustedTimeAnchor::approved_window(s, 200, 201).unwrap(),
        )
        .unwrap();
    assert!(a.seal_control(ControlBody::Prepare(Empty {})).is_ok());
    a.check_commit_admission().unwrap();
}
#[test]
fn lease_boundary_rounds_up_and_never_lends_submillisecond_time() {
    let (mut a, _, s) = initial();
    assert!(a.seal_data_at(0, b"a", at(s, 799)).is_ok());
    let fraction = s.shifted(
        Duration::from_millis(799) + Duration::from_nanos(1),
        Duration::from_millis(799) + Duration::from_nanos(1),
    );
    assert!(a.seal_data_at(1, b"b", fraction).is_err());
    assert!(
        a.seal_control_at(ControlBody::StatusRequest(Empty {}), at(s, 800))
            .is_ok()
    );
}
#[test]
fn local_monotonic_and_wall_rollbacks_permanently_poison_continuity() {
    for wall_only in [false, true] {
        let (mut a, _, s) = initial();
        a.seal_data_at(0, b"a", at(s, 50)).unwrap();
        let bad = if wall_only {
            s.shifted(Duration::from_millis(60), Duration::from_millis(49))
        } else {
            at(s, 49)
        };
        assert!(a.seal_data_at(1, b"b", bad).is_err());
        assert!(a.seal_data_at(1, b"b", at(s, 70)).is_err());
        assert!(
            a.seal_control_at(ControlBody::StatusRequest(Empty {}), at(s, 80))
                .is_err()
        );
    }
    let (mut a, _, s) = initial();
    assert!(
        a.seal_data_at(
            0,
            b"a",
            s.rollback(Duration::from_millis(1), Duration::from_millis(1))
        )
        .is_err()
    );
}
#[test]
fn excessive_suspend_or_clock_step_is_not_reinterpreted_as_fresh_time() {
    for delta in [(0, 3000), (3000, 0)] {
        let (mut a, _, s) = initial();
        let bad = s.shifted(
            Duration::from_millis(delta.0),
            Duration::from_millis(delta.1),
        );
        assert!(
            a.seal_control_at(ControlBody::StatusRequest(Empty {}), bad)
                .is_err()
        );
        assert!(renew(&mut a, Offer::new(1), at(s, 4000)).is_err());
    }
}
#[test]
fn small_clock_divergence_uses_conservative_upper_not_faster_renewal() {
    let (mut a, _, s) = initial();
    let early = s.shifted(Duration::from_millis(100), Duration::from_millis(500));
    a.seal_data_at(0, b"a", early).unwrap();
    let expiry = s.shifted(Duration::from_millis(200), Duration::from_millis(800));
    assert!(a.seal_data_at(1, b"b", expiry).is_err());
    assert!(
        a.seal_control_at(ControlBody::StatusRequest(Empty {}), expiry)
            .is_ok()
    );
}
#[test]
fn uncertainty_lower_bound_rejects_not_certainly_issued_renewal() {
    let o = Offer::new(0);
    let s = ClockSample::now();
    let mut a = o
        .source
        .authenticate_leased_between(
            &o.t,
            Direction::SourceToTarget,
            &o.g,
            &o.source_pin,
            &o.target_pin,
            &o.a,
            &o.b,
            TrustedTimeAnchor::approved_window(s, 200, 210).unwrap(),
            || s,
        )
        .unwrap();
    assert!(renew(&mut a, Offer::new(1), s).is_err());
    assert_eq!(a.epoch_count(), 1);
    renew(&mut a, Offer::new(1), at(s, 2)).unwrap();
    assert_eq!(a.epoch_count(), 2);
}
#[test]
fn trusted_time_arithmetic_overflow_fails_closed() {
    let mut o = Offer::new(0);
    o.modify(|j, g| {
        j.deadline_ms = u64::MAX;
        g.issued_at_ms = u64::MAX - 2000;
        g.expires_at_ms = u64::MAX - 1;
    });
    let s = ClockSample::now();
    let mut a = o
        .source
        .authenticate_leased_between(
            &o.t,
            Direction::SourceToTarget,
            &o.g,
            &o.source_pin,
            &o.target_pin,
            &o.a,
            &o.b,
            TrustedTimeAnchor::approved_window(s, u64::MAX - 1000, u64::MAX - 1000).unwrap(),
            || s,
        )
        .unwrap();
    assert!(
        a.seal_control_at(ControlBody::StatusRequest(Empty {}), at(s, 2000))
            .is_err()
    );
    assert!(a.clock.poisoned);
}
#[test]
fn renewal_rotates_keys_preserves_deadline_and_rejects_old_epochs() {
    let (mut a, mut b, s) = initial();
    let until = a.clock.job_until;
    let old = a.seal_data_at(0, b"a", at(s, 50)).unwrap();
    assert_eq!(data(b.open_record_at(&old, at(s, 50)).unwrap()), b"a");
    both(&mut a, &mut b, Offer::new(1), at(s, 100));
    assert_eq!(a.clock.job_until, until);
    assert_eq!(a.epoch_count(), 2);
    assert!(b.open_record_at(&old, at(s, 110)).is_err());
    let fresh = a.seal_data_at(1, b"bc", at(s, 120)).unwrap();
    assert_eq!(Frame::decode(&fresh).unwrap().header.sequence, 0);
    assert_eq!(data(b.open_record_at(&fresh, at(s, 120)).unwrap()), b"bc");
    assert!(matches!(
        b.open_record_at(&fresh, at(s, 130)).unwrap(),
        PeerRecord::Duplicate { .. }
    ));
}
#[test]
fn failed_dual_signature_or_private_key_match_preserves_active_epoch_sequence() {
    for failure in 0..3 {
        let (mut a, mut b, s) = initial();
        let old = a.grant().digest();
        let first = a.seal_data_at(0, b"a", at(s, 10)).unwrap();
        b.open_record_at(&first, at(s, 10)).unwrap();
        let mut o = Offer::new(1);
        match failure {
            0 => o.a[0] ^= 1,
            1 => o.b[0] ^= 1,
            _ => o.source = EphemeralKey::from_test_bytes([0x99; 32]),
        };
        assert!(renew(&mut a, o, at(s, 100)).is_err());
        assert_eq!(a.epoch_count(), 1);
        assert_eq!(a.grant().digest(), old);
        let second = a.seal_data_at(1, b"b", at(s, 200)).unwrap();
        assert_eq!(Frame::decode(&second).unwrap().header.sequence, 1);
        assert_eq!(data(b.open_record_at(&second, at(s, 200)).unwrap()), b"b");
    }
}
#[test]
fn expiry_during_renewal_crypto_does_not_backdate_installation() {
    let (mut a, _, s) = initial();
    let old = a.grant().digest();
    let o = Offer::new(1);
    assert!(
        a.renew_between(o.g, o.source, &o.t, &o.a, &o.b, at(s, 799), || at(s, 800))
            .is_err()
    );
    assert_eq!(a.grant().digest(), old);
    assert_eq!(a.epoch_count(), 1);
    assert!(a.seal_data_at(0, b"a", at(s, 801)).is_err());
    assert!(
        a.seal_control_at(ControlBody::StatusRequest(Empty {}), at(s, 801))
            .is_ok()
    );
}
#[test]
fn expired_or_revoked_job_cannot_be_revived_but_receipts_may_settle() {
    for revoked in [false, true] {
        let (mut a, mut b, s) = initial();
        let time = if revoked {
            a.revoke();
            at(s, 100)
        } else {
            at(s, 800)
        };
        assert!(renew(&mut a, Offer::new(1), time).is_err());
        assert!(a.seal_data_at(0, b"a", time).is_err());
        let commit = b.seal_control_at(receipt(), time).unwrap();
        assert!(matches!(
            a.open_record_at(&commit, time).unwrap(),
            PeerRecord::Control { .. }
        ));
    }
}
#[test]
fn changed_task_paths_size_hash_deadline_and_live_sessions_are_rejected() {
    let (mut a, _, s) = initial();
    for i in 0..6 {
        let mut o = Offer::new(1);
        o.modify(|j, g| match i {
            0 => j.source_path.push('x'),
            1 => j.destination_path.push('x'),
            2 => j.bytes_total += 1,
            3 => j.sha256[0] ^= 1,
            4 => j.deadline_ms += 1000,
            _ => g.binding.source_session = Uuid::new_v4(),
        });
        assert!(renew(&mut a, o, at(s, 100 + i)).is_err());
        assert_eq!(a.epoch_count(), 1);
    }
}
#[test]
fn narrowed_chunk_ceiling_cannot_be_expanded_by_later_renewal() {
    let (mut a, _, s) = initial();
    let mut o = Offer::new(1);
    o.modify(|_, g| g.chunk_bytes = 2);
    renew(&mut a, o, at(s, 100)).unwrap();
    assert!(renew(&mut a, Offer::new(2), at(s, 200)).is_err());
    assert_eq!(a.grant().grant().chunk_bytes, 2);
    assert!(a.seal_data_at(0, b"abc", at(s, 300)).is_err());
}
#[test]
fn reused_epochs_authorizations_and_any_previous_ephemeral_are_rejected() {
    for reused in 0..4 {
        let (mut a, _, s) = initial();
        let oldest = Offer::new(0);
        both_unused_target_renew(&mut a, at(s, 100));
        let mut o = Offer::new(2);
        match reused {
            0 => o.modify(|_, g| {
                g.binding.authorization_id = oldest.g.grant().binding.authorization_id
            }),
            1 => o.modify(|_, g| g.binding.key_epoch = oldest.g.grant().binding.key_epoch),
            2 => {
                o.t.source_ephemeral = oldest.t.source_ephemeral;
                o.resign();
            }
            _ => {
                o.t.target_ephemeral = oldest.t.source_ephemeral;
                o.resign();
            }
        }
        assert!(renew(&mut a, o, at(s, 200)).is_err());
        assert_eq!(a.epoch_count(), 2);
    }
}
fn both_unused_target_renew(a: &mut LeasedRecords, s: ClockSample) {
    renew(a, Offer::new(1), s).unwrap();
}
#[test]
fn epoch_history_is_bounded_without_eviction_or_replay_reacceptance() {
    let (mut a, _, s) = initial();
    for i in 0..MAX_LEASE_EPOCHS - 1 {
        a.clock
            .authorizations
            .insert(Uuid::from_u128(50000 + i as u128));
    }
    assert_eq!(a.epoch_count(), MAX_LEASE_EPOCHS);
    assert!(renew(&mut a, Offer::new(1), at(s, 100)).is_err());
    assert_eq!(a.epoch_count(), MAX_LEASE_EPOCHS);
    a.seal_data_at(0, b"a", at(s, 200)).unwrap();
}
#[test]
fn renewal_cannot_reset_fixed_total_deadline() {
    let (mut a, _, s) = initial();
    let fixed = a.clock.job_until;
    let mut o = Offer::new(1);
    o.modify(|_, g| g.expires_at_ms = 5000);
    renew(&mut a, o, at(s, 100)).unwrap();
    assert_eq!(a.clock.job_until, fixed);
    assert!(a.seal_data_at(0, b"a", at(s, 4800)).is_err());
    assert!(
        a.seal_control_at(ControlBody::StatusRequest(Empty {}), at(s, 4800))
            .is_ok()
    );
}
#[test]
fn authenticated_semantic_fault_cannot_be_erased_with_renewed_keys() {
    let (mut a, mut b, s) = initial();
    let bad = a.records.seal(Kind::Prepare, 0, b"{}", 300).unwrap();
    assert!(b.open_record_at(&bad, at(s, 100)).is_err());
    let o = Offer::new(1);
    assert!(
        b.renew_between(o.g, o.target, &o.t, &o.a, &o.b, at(s, 200), || at(s, 200))
            .is_err()
    );
    assert_eq!(b.epoch_count(), 1);
}
#[test]
fn old_receipt_can_be_reconciled_in_current_context_without_old_key_retention() {
    let (mut a, mut b, s) = initial();
    let stale = b.seal_control_at(receipt(), at(s, 50)).unwrap();
    both(&mut a, &mut b, Offer::new(1), at(s, 100));
    assert!(a.open_record_at(&stale, at(s, 110)).is_err());
    let current = b.seal_control_at(receipt(), at(s, 120)).unwrap();
    assert!(matches!(
        a.open_record_at(&current, at(s, 120)).unwrap(),
        PeerRecord::Control { .. }
    ));
    // Receipt here is test metadata, not proof of a persistent receiver journal.
}
#[test]
fn real_revocation_after_readback_refuses_native_publication_and_retains_owned_stage() {
    let root = tempfile::tempdir().unwrap();
    let mut offer = Offer::new(0);
    offer.modify(|j, _| {
        j.source_path = root.path().join("source.bin").to_str().unwrap().into();
        j.destination_path = root.path().join("target.bin").to_str().unwrap().into();
    });
    let job = offer.g.job().clone();
    let budget = StageBudget::new(3, 1).unwrap();
    let mut stage = StageFile::prepare(
        Policy::new(vec![root.path().into()], false).unwrap(),
        &job.destination_path,
        3,
        &budget,
        Arc::default(),
    )
    .unwrap();
    stage.write_chunk(0, b"abc").unwrap();
    let path = stage.stage_path().to_path_buf();
    // Start the real 800ms grant after pure fixture filesystem preparation.
    // This tests revocation, not whether unrelated parallel IO expired setup.
    let (_, mut receiver) = offer.pair(ClockSample::now());
    let verified = stage
        .verify_with(job.sha256, || receiver.check_commit_admission())
        .unwrap();
    receiver.revoke();
    let rejected = verified
        .publish_with(|| receiver.check_commit_admission())
        .unwrap_err();
    assert!(
        rejected
            .reason()
            .to_string()
            .contains("authorization revoked"),
        "{}",
        rejected.reason()
    );
    assert!(!std::path::Path::new(&job.destination_path).exists());
    assert_eq!(fs::read(path).unwrap(), b"abc");
    assert_eq!(budget.usage().unwrap(), (3, 1));
    rejected.into_parts().0.into_stage().cancel().unwrap();
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[test]
fn synthetic_grant_deadline_at_admission_blocks_real_file_publication() {
    let root = tempfile::tempdir().unwrap();
    let mut offer = Offer::new(0);
    offer.modify(|j, _| {
        j.source_path = root.path().join("source.bin").to_str().unwrap().into();
        j.destination_path = root.path().join("target.bin").to_str().unwrap().into();
    });
    let job = offer.g.job().clone();
    let sample = ClockSample::now();
    let (_, mut receiver) = offer.pair(sample);
    let budget = StageBudget::new(3, 1).unwrap();
    let mut stage = StageFile::prepare(
        Policy::new(vec![root.path().into()], false).unwrap(),
        &job.destination_path,
        3,
        &budget,
        Arc::default(),
    )
    .unwrap();
    stage.write_chunk(0, b"abc").unwrap();
    let verified = stage.verify_with(job.sha256, || Ok(())).unwrap();
    let rejected = verified
        .publish_with(|| {
            receiver.clock.check(Kind::Finish, at(sample, 800))?;
            receiver.check_commit_admission()
        })
        .unwrap_err();
    assert!(!std::path::Path::new(&job.destination_path).exists());
    assert_eq!(budget.usage().unwrap(), (3, 1));
    rejected.into_parts().0.into_stage().cancel().unwrap();
}

#[test]
fn renewed_authenticated_records_continue_real_stage_without_quota_or_coverage_reset() {
    let root = tempfile::tempdir().unwrap();
    let mut initial_offer = Offer::new(0);
    initial_offer.modify(|j, _| {
        j.source_path = root.path().join("source.bin").to_str().unwrap().into();
        j.destination_path = root.path().join("target.bin").to_str().unwrap().into();
    });
    let job = initial_offer.g.job().clone();
    let s = ClockSample::now();
    let (mut a, mut b) = initial_offer.pair(s);
    let budget = StageBudget::new(3, 1).unwrap();
    let mut stage = StageFile::prepare(
        Policy::new(vec![root.path().into()], false).unwrap(),
        &job.destination_path,
        3,
        &budget,
        Arc::new(Mutex::new(())),
    )
    .unwrap();
    let first = a.seal_data_at(0, b"a", at(s, 50)).unwrap();
    match b.open_record_at(&first, at(s, 50)).unwrap() {
        PeerRecord::Data { header, bytes } => {
            stage.write_chunk(header.offset, &bytes).unwrap();
        }
        _ => panic!("DATA"),
    };
    let mut next = Offer::new(1);
    next.modify(|j, _| *j = job.clone());
    both(&mut a, &mut b, next, at(s, 100));
    assert_eq!(stage.bytes_received(), 1);
    assert_eq!(budget.usage().unwrap(), (3, 1));
    let rest = a.seal_data_at(1, b"bc", at(s, 200)).unwrap();
    match b.open_record_at(&rest, at(s, 200)).unwrap() {
        PeerRecord::Data { header, bytes } => {
            stage.write_chunk(header.offset, &bytes).unwrap();
        }
        _ => panic!("DATA"),
    };
    assert!(!root.path().join("target.bin").exists());
    assert!(matches!(
        stage.publish(job.sha256).unwrap(),
        Publication::Published { .. }
    ));
    assert_eq!(fs::read(root.path().join("target.bin")).unwrap(), b"abc");
    assert_eq!(budget.usage().unwrap(), (0, 0));
    // Synthetic clock/real file IO component; not cancellable service commit.
}
