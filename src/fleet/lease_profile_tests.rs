use super::*;
use crate::fleet::{
    auth::MAX_LEASE_MS,
    job::{FileGrant, JobSpec, LeaseProfile},
    protocol::Binding,
};
/// The shared fixture job, with a chosen deadline and a lease that fits it.
fn job_with_deadline(deadline_ms: u64) -> JobSpec {
    let mut job = job();
    job.deadline_ms = deadline_ms;
    job
}
fn grant_with_lease(job: &JobSpec, lease: u64) -> FileGrant {
    let binding = Binding {
        fleet_id: job.fleet_id,
        source_device: job.source_device,
        target_device: job.target_device,
        source_session: Uuid::from_bytes([3; 16]),
        target_session: Uuid::from_bytes([4; 16]),
        transfer_id: job.transfer_id,
        file_id: job.file_id,
        authorization_id: Uuid::from_bytes([7; 16]),
        key_epoch: Uuid::from_bytes([8; 16]),
    };
    FileGrant {
        binding,
        job_digest: job.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 65536,
        issued_at_ms: 100,
        expires_at_ms: 100 + lease,
    }
}
/// One long grant for the whole job: accepted for a single owner, refused by the
/// rotating profile that multi-host work depends on.
#[test]
fn single_owner_allows_a_job_length_lease_that_rotating_refuses() {
    let job = job_with_deadline(86_400_000);
    let long = grant_with_lease(&job, 3_600_000);
    assert!(long.clone().validate_for(job.clone()).is_err());
    let ok = long
        .clone()
        .validate_for_profile(job.clone(), LeaseProfile::SingleOwner);
    assert!(ok.is_ok());
    // The job deadline is still the hard bound, whatever the profile.
    assert!(
        long.validate_for_profile(job_with_deadline(1000), LeaseProfile::SingleOwner)
            .is_err()
    );
}
/// The profile is NOT part of the canonical bytes: those are a cross-implementation
/// golden contract. A long lease is refused by the opposing profile's ceiling at
/// validation time instead, which is where it must be refused anyway.
#[test]
fn the_lease_profile_does_not_change_the_golden_canonical_bytes() {
    let job = job_with_deadline(86_400_000);
    // A lease both profiles accept, so this test is about the digest only.
    let long = grant_with_lease(&job, MAX_LEASE_MS);
    let rotating = long
        .clone()
        .canonical_bytes_with(LeaseProfile::Rotating)
        .unwrap();
    let single = long
        .canonical_bytes_with(LeaseProfile::SingleOwner)
        .unwrap();
    assert_eq!(rotating, single);
    assert_eq!(long.canonical_bytes().unwrap(), rotating);
}
/// The rotating ceiling itself is untouched.
#[test]
fn rotating_profile_still_caps_at_the_short_lease() {
    let job = job_with_deadline(86_400_000);
    assert!(
        grant_with_lease(&job, MAX_LEASE_MS)
            .validate_for(job.clone())
            .is_ok()
    );
    assert!(
        grant_with_lease(&job, MAX_LEASE_MS + 1)
            .validate_for(job)
            .is_err()
    );
}

/// A long SingleOwner grant must reach the real dual-signature/AEAD path, not
/// merely pass structural validation. Each side owns its own private ephemeral.
#[test]
fn single_owner_long_lease_authenticates_and_roundtrips() {
    use crate::fleet::{
        auth::{DevicePin, EphemeralKey, IdentityKey, PeerRecord, Transcript},
        lease::{ClockSample, TrustedTimeAnchor},
    };
    let mut j = job_with_deadline(3_600_100);
    j.bytes_total = 3;
    j.sha256 = sha(b"abc");
    let raw = grant_with_lease(&j, 3_600_000);
    let g = raw
        .clone()
        .validate_for_profile(j.clone(), LeaseProfile::SingleOwner)
        .unwrap();
    assert!(raw.clone().validate_for(j.clone()).is_err());
    // Same job and valid digest, but truly outside its deadline (not a digest error).
    let mut over = raw.clone();
    over.expires_at_ms = j.deadline_ms + 1;
    assert!(
        over.validate_for_profile(j, LeaseProfile::SingleOwner)
            .unwrap_err()
            .to_string()
            .contains("fixed job deadline")
    );
    let a = IdentityKey::from_test_seed([0x11; 32]);
    let b = IdentityKey::from_test_seed([0x22; 32]);
    let x = EphemeralKey::from_test_bytes([0x33; 32]);
    let y = EphemeralKey::from_test_bytes([0x44; 32]);
    let t = Transcript::for_grant(&g, a.public(), b.public(), x.public(), y.public());
    assert!(t.bytes(Direction::SourceToTarget).is_err());
    assert!(a.sign(&t, Direction::SourceToTarget).is_err());
    let sig_a = a
        .sign_with_profile(&t, Direction::SourceToTarget, LeaseProfile::SingleOwner)
        .unwrap();
    let sig_b = b
        .sign_with_profile(&t, Direction::TargetToSource, LeaseProfile::SingleOwner)
        .unwrap();
    let sp = DevicePin::approved("source-A", a.public()).unwrap();
    let tp = DevicePin::approved("target-B", b.public()).unwrap();
    let sample = ClockSample::now();
    let anchor = || TrustedTimeAnchor::approved_window(sample, 200, 201).unwrap();
    let mut source = x
        .authenticate_leased(
            &t,
            Direction::SourceToTarget,
            &g,
            &sp,
            &tp,
            &sig_a,
            &sig_b,
            anchor(),
        )
        .expect("long source handshake");
    let mut target = y
        .authenticate_leased(
            &t,
            Direction::TargetToSource,
            &g,
            &sp,
            &tp,
            &sig_a,
            &sig_b,
            anchor(),
        )
        .expect("long target handshake");
    let frame = source.seal_data(0, b"abc").unwrap();
    match target.open_record(&frame).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(bytes.as_slice(), b"abc"),
        _ => panic!("expected DATA"),
    }
    source.revoke();
    assert!(source.seal_data(0, b"abc").is_err());
    let expired = TrustedTimeAnchor::approved_window(
        ClockSample::now(),
        raw.expires_at_ms,
        raw.expires_at_ms,
    )
    .unwrap();
    let fresh = EphemeralKey::from_test_bytes([0x33; 32]);
    assert!(
        fresh
            .authenticate_leased(
                &t,
                Direction::SourceToTarget,
                &g,
                &sp,
                &tp,
                &sig_a,
                &sig_b,
                expired
            )
            .is_err()
    );
}
#[test]
fn single_owner_deadline_is_not_a_file_size_derived_time_limit() {
    let j = job_with_deadline(2_000_000_100);
    assert!(
        grant_with_lease(&j, 2_000_000_000)
            .validate_for_profile(j, LeaseProfile::SingleOwner)
            .is_ok()
    );
}
