use super::*;
use crate::fleet::{
    auth::{DevicePin, EphemeralKey, IdentityKey, MAX_LEASE_MS, Transcript},
    job::FileGrant,
    lease::{ClockSample, TrustedTimeAnchor},
    protocol::Direction,
    renewal::{MAX_GENERATIONS, successor},
};
fn fixture() -> (tempfile::TempDir, ValidatedGrant) {
    let t = tempfile::tempdir().unwrap();
    let data = b"renewal";
    let g = grant(t.path(), data);
    (t, g)
}
/// Same job, later window, rotated identifiers: the happy path.
#[test]
fn successor_rotates_identifiers_and_keeps_the_job() {
    let (_t, g) = fixture();
    let seed = [0x11; 32];
    let next = successor(&g, &seed, 1, g.grant().issued_at_ms + 1000, 5_000).unwrap();
    assert_eq!(next.job().digest().unwrap(), g.job().digest().unwrap());
    assert_eq!(next.grant().chunk_bytes, g.grant().chunk_bytes);
    assert_eq!(next.grant().permission, g.grant().permission);
    assert_ne!(
        next.grant().binding.authorization_id,
        g.grant().binding.authorization_id
    );
    assert_ne!(next.grant().binding.key_epoch, g.grant().binding.key_epoch);
    // Stable routing identity survives the rotation.
    assert_eq!(
        next.grant().binding.source_session,
        g.grant().binding.source_session
    );
    assert_eq!(
        next.grant().binding.transfer_id,
        g.grant().binding.transfer_id
    );
    assert_eq!(
        next.grant().expires_at_ms,
        g.grant().issued_at_ms + 1000 + 5_000
    );
}
/// Replaying a generation reproduces the same identifiers, so the route's
/// reuse rejection is what stops a double-spend, not fresh randomness.
#[test]
fn replaying_a_generation_reproduces_the_same_identifiers() {
    let (_t, g) = fixture();
    let seed = [0x22; 32];
    let a = successor(&g, &seed, 3, g.grant().issued_at_ms + 10, 1_000).unwrap();
    let b = successor(&g, &seed, 3, g.grant().issued_at_ms + 10, 1_000).unwrap();
    assert_eq!(a.digest(), b.digest());
    let other_seed = successor(&g, &[0x23; 32], 3, g.grant().issued_at_ms + 10, 1_000).unwrap();
    assert_ne!(a.digest(), other_seed.digest());
}
/// Every structural boundary is refused here rather than at the relay.
#[test]
fn successor_refuses_empty_seed_bad_generation_and_out_of_window_leases() {
    let (_t, g) = fixture();
    let now = g.grant().issued_at_ms + 10;
    assert!(
        successor(&g, &[0; 32], 1, now, 1_000).is_err(),
        "empty seed"
    );
    assert!(
        successor(&g, &[1; 32], 0, now, 1_000).is_err(),
        "generation 0"
    );
    assert!(
        successor(&g, &[1; 32], MAX_GENERATIONS + 1, now, 1_000).is_err(),
        "generation past history"
    );
    assert!(
        successor(&g, &[1; 32], 1, now, MAX_LEASE_MS + 1).is_err(),
        "lease above the product ceiling"
    );
    assert!(successor(&g, &[1; 32], 1, now, 0).is_err(), "zero lease");
    // Already expired: renewal is not resurrection.
    assert!(
        successor(&g, &[1; 32], 1, g.grant().expires_at_ms, 1_000).is_err(),
        "expired current lease"
    );
    // Would outlive the fixed job deadline.
    let job_deadline = g.job().deadline_ms;
    assert!(
        successor(&g, &[1; 32], 1, job_deadline - 10, 1_000).is_err(),
        "renewal past the job deadline"
    );
}
/// A real signature round-trip on the successor: the issued grant is usable by
/// both peers, and the old epoch's records do not authenticate against it.
#[test]
fn issued_successor_authenticates_for_both_roles() {
    let (_t, g) = fixture();
    let next = successor(&g, &[0x33; 32], 1, g.grant().issued_at_ms + 10, 5_000).unwrap();
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let s = EphemeralKey::from_test_bytes([0x91; 32]);
    let t = EphemeralKey::from_test_bytes([0x92; 32]);
    let tr = Transcript::for_grant(&next, sk.public(), tk.public(), s.public(), t.public());
    let a = sk.sign(&tr, Direction::SourceToTarget).unwrap();
    let b = tk.sign(&tr, Direction::TargetToSource).unwrap();
    for (seed, role) in [
        ([0x91u8; 32], Direction::SourceToTarget),
        ([0x92u8; 32], Direction::TargetToSource),
    ] {
        let key = EphemeralKey::from_test_bytes(seed);
        key.authenticate_leased(
            &tr,
            role,
            &next,
            &DevicePin::approved("source-A", sk.public()).unwrap(),
            &DevicePin::approved("target-B", tk.public()).unwrap(),
            &a,
            &b,
            TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 200).unwrap(),
        )
        .unwrap();
    }
    // The OLD grant cannot be authenticated against the new transcript.
    let stale = Transcript::for_grant(&g, sk.public(), tk.public(), s.public(), t.public());
    assert!(
        EphemeralKey::from_test_bytes([0x91; 32])
            .authenticate_leased(
                &stale,
                Direction::SourceToTarget,
                &next,
                &DevicePin::approved("source-A", sk.public()).unwrap(),
                &DevicePin::approved("target-B", tk.public()).unwrap(),
                &sk.sign(&stale, Direction::SourceToTarget).unwrap(),
                &tk.sign(&stale, Direction::TargetToSource).unwrap(),
                TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 200).unwrap(),
            )
            .is_err(),
        "mismatched grant/transcript must not authenticate"
    );
}
/// The registry accepts the issued successor and then refuses its reuse.
#[test]
fn registry_offers_the_issued_successor_and_refuses_replay() {
    let (_t, g) = fixture();
    let f = FleetRelay::new();
    let _tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(60))
        .unwrap();
    let next = successor(&g, &[0x44; 32], 1, g.grant().issued_at_ms + 10, 5_000).unwrap();
    f.offer_renewal(&g, &next).unwrap();
    // A second offer of the same successor is a duplicate, not a second chance.
    assert!(f.offer_renewal(&g, &next).is_err());
    // After adoption the successor is the live binding.
    let offer = RenewOffer {
        current_authorization_id: g.grant().binding.authorization_id,
        current_key_epoch: g.grant().binding.key_epoch,
        next_authorization_id: next.grant().binding.authorization_id,
        next_key_epoch: next.grant().binding.key_epoch,
    };
    assert_eq!(f.present("source-A", &offer).unwrap(), (false, 0));
    assert_eq!(f.present("target-B", &offer).unwrap(), (true, 1));
    assert!(f.offer_renewal(&g, &next).is_err(), "old binding is gone");
    // Reissuing the SAME generation yields the same binding, which is refused.
    let replay = successor(&g, &[0x44; 32], 1, g.grant().issued_at_ms + 10, 5_000).unwrap();
    assert_eq!(replay.digest(), next.digest());
    assert!(
        f.offer_renewal(&next, &replay).is_err(),
        "replayed generation cannot become a new live binding"
    );
}
/// A grant that keeps its identifiers is not a rotation, so issuance refuses it
/// even when the caller asks for a valid generation.
#[test]
fn non_rotating_grant_is_refused() {
    let (_t, g) = fixture();
    let old = g.grant();
    let same = FileGrant {
        binding: old.binding.clone(),
        job_digest: old.job_digest,
        permission: old.permission,
        chunk_bytes: old.chunk_bytes,
        issued_at_ms: old.issued_at_ms + 1,
        expires_at_ms: old.expires_at_ms + 1,
    }
    .validate_for(g.job().clone())
    .unwrap();
    let f = FleetRelay::new();
    let _tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(60))
        .unwrap();
    assert!(f.offer_renewal(&g, &same).is_err());
}
