//! LOCAL original-File cursor only. PUBLIC fixture keys/checkpoint, NOT process/network resume.
use super::*;
use crate::fleet::{resume_lease::ResumeLease, source_file::SourceFile};
fn owners(
    data: &[u8],
    prefix: u64,
) -> (
    tempfile::TempDir,
    crate::runtime::Runtime,
    ResumeLease,
    ResumeLease,
) {
    let (t, runtime, s, peer, p) = super::prefix_tests::fixture(data, prefix);
    let g = s.grant().clone();
    drop(s);
    drop(peer);
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let source = EphemeralKey::generate();
    let target = EphemeralKey::generate();
    let transcript = Transcript::for_grant(
        &g,
        sk.public(),
        tk.public(),
        source.public(),
        target.public(),
    );
    let sp = DevicePin::approved("source-A", sk.public()).unwrap();
    let tp = DevicePin::approved("target-B", tk.public()).unwrap();
    let sa = sk
        .sign_with_profile(&transcript, Direction::SourceToTarget, g.lease_profile())
        .unwrap();
    let ta = tk
        .sign_with_profile(&transcript, Direction::TargetToSource, g.lease_profile())
        .unwrap();
    let proof = |seed, role| -> [u8; 64] {
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
            .unwrap()
            .sign(&p.proof_bytes(&g, &transcript, role).unwrap())
            .as_ref()
            .try_into()
            .unwrap()
    };
    let sr = proof(0x11, Direction::SourceToTarget);
    let tr = proof(0x22, Direction::TargetToSource);
    let anchor = || TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 200).unwrap();
    let s = source
        .authenticate_resume_leased(
            p.clone(),
            &transcript,
            Direction::SourceToTarget,
            &g,
            &sp,
            &tp,
            &sa,
            &ta,
            &sr,
            &tr,
            anchor(),
        )
        .unwrap();
    let r = target
        .authenticate_resume_leased(
            p,
            &transcript,
            Direction::TargetToSource,
            &g,
            &sp,
            &tp,
            &sa,
            &ta,
            &sr,
            &tr,
            anchor(),
        )
        .unwrap();
    (t, runtime, s, r)
}
fn finish(source: SourceFile<'_>, mut peer: LeasedRecords, data: &[u8]) {
    let pending = source.finish().unwrap();
    match peer.open_record(pending.finish_record()).unwrap() {
        PeerRecord::Control { message, .. } => match message.body {
            ControlBody::Finish(f) => {
                assert_eq!(f.size, data.len() as u64);
                assert_eq!(f.sha256, <[u8; 32]>::from(Sha256::digest(data)));
            }
            _ => panic!("FINISH expected"),
        },
        _ => panic!("FINISH expected"),
    }
}
#[test]
fn actual_prefix_state_encodes_only_suffix_but_finishes_complete_sha() {
    let (t, r, s, peer) = owners(b"abcdefgh", 3);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            t.path().join("source.bin"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let mut source = r.open_fleet_resume_source(s, 8).unwrap();
    let (_, mut peer) = peer.into_target().unwrap();
    assert_eq!(source.resumed_prefix_bytes(), Some(3));
    assert_eq!(source.bytes_encoded(), 0);
    assert_eq!(source.next_data_offset(), 3);
    match peer
        .open_record(&source.next_record().unwrap().unwrap())
        .unwrap()
    {
        PeerRecord::Data { header, bytes } => {
            assert_eq!(header.offset, 3);
            assert_eq!(bytes.as_slice(), b"defgh");
        }
        _ => panic!("suffix DATA expected"),
    }
    assert_eq!(source.bytes_encoded(), 5);
    assert_eq!(source.next_data_offset(), 8);
    assert!(source.next_record().unwrap().is_none());
    assert_eq!(
        std::fs::read(t.path().join("source.bin")).unwrap(),
        b"abcdefgh"
    );
    finish(source, peer, b"abcdefgh");
}
#[test]
fn complete_prefix_finishes_without_encoding_or_rereading_suffix() {
    let (_t, r, s, peer) = owners(b"abcdefgh", 8);
    let mut source = r.open_fleet_resume_source(s, 8).unwrap();
    assert_eq!(source.bytes_encoded(), 0);
    assert_eq!(source.next_data_offset(), 8);
    assert!(source.next_record().unwrap().is_none());
    finish(source, peer.into_target().unwrap().1, b"abcdefgh");
}
#[test]
fn empty_recovery_preserves_explicit_mode_without_encoded_bytes() {
    let (_t, r, s, peer) = owners(b"", 0);
    let mut source = r.open_fleet_resume_source(s, 0).unwrap();
    assert_eq!(source.resumed_prefix_bytes(), Some(0));
    assert_eq!(source.bytes_encoded(), 0);
    assert!(source.next_record().unwrap().is_none());
    finish(source, peer.into_target().unwrap().1, b"");
}
#[test]
fn ordinary_window_refuses_even_zero_prefix_recovery() {
    for prefix in [0, 3] {
        let (_t, r, s, _peer) = owners(b"abcdefgh", prefix);
        let source = r.open_fleet_resume_source(s, 8).unwrap();
        assert_eq!(source.bytes_encoded(), 0);
        assert!(crate::fleet::source_window::SourceWindow::new(source, 8).is_err());
    }
}
#[test]
fn ordinary_observer_cannot_rewind_or_reseed_recovery_even_prefix_zero() {
    for prefix in [0, 3] {
        let (_t, r, s, _peer) = owners(b"abcdefgh", prefix);
        let p = s.condition().clone();
        let mut source = r.open_fleet_resume_source(s, 8).unwrap();
        assert!(source.observe_resume_prefix(&p, 8).is_err());
        assert!(source.next_record().is_err());
    }
}
#[test]
fn changed_prefix_refuses_owner_and_does_not_modify_source() {
    let (t, r, s, _peer) = owners(b"abcdefgh", 3);
    std::fs::write(t.path().join("source.bin"), b"xyzdefgh").unwrap();
    assert!(r.open_fleet_resume_source(s, 8).is_err());
    assert_eq!(
        std::fs::read(t.path().join("source.bin")).unwrap(),
        b"xyzdefgh"
    );
}
#[test]
fn prefix_read_budget_is_hard_bounded() {
    for max in [2, 1024 * 1024 * 1024 + 1] {
        let (t, r, s, _peer) = owners(b"abcdefgh", 3);
        assert!(r.open_fleet_resume_source(s, max).is_err());
        assert_eq!(
            std::fs::read(t.path().join("source.bin")).unwrap(),
            b"abcdefgh"
        );
    }
}
#[test]
fn target_role_cannot_become_source_file() {
    let (_t, r, _s, target) = owners(b"abcdefgh", 3);
    assert!(
        r.open_fleet_resume_source(target, 8)
            .err()
            .unwrap()
            .to_string()
            .contains("Source role")
    );
}
#[test]
fn expired_source_owner_cannot_open_continuation() {
    let (_t, r, mut s, _peer) = owners(b"abcdefgh", 3);
    s.test_expire();
    assert!(r.open_fleet_resume_source(s, 8).is_err());
}
#[tokio::test]
async fn runtime_stop_rejects_idle_source_resume_owner() {
    let (_t, r, s, _peer) = owners(b"abcdefgh", 3);
    r.shutdown().await;
    assert!(r.open_fleet_resume_source(s, 8).is_err());
}
#[test]
fn changed_suffix_cannot_finish_approved_whole_stream_sha() {
    let (t, r, s, _peer) = owners(b"abcdefgh", 3);
    let mut source = r.open_fleet_resume_source(s, 8).unwrap();
    std::fs::write(t.path().join("source.bin"), b"abcXXXXX").unwrap();
    assert!(source.next_record().unwrap().is_some());
    assert_eq!(source.bytes_encoded(), 5);
    assert!(source.finish().is_err());
}
#[test]
fn same_size_prefix_rewrite_after_read_is_not_current_file_proof() {
    let (t, r, s, peer) = owners(b"abcdefgh", 3);
    let mut source = r.open_fleet_resume_source(s, 8).unwrap();
    std::fs::write(t.path().join("source.bin"), b"xyzdefgh").unwrap();
    assert!(source.next_record().unwrap().is_some());
    assert_eq!(source.bytes_encoded(), 5);
    // FINISH hashes the historical actual prefix plus newly encoded suffix,
    // never promises the source's already-read prefix is still unchanged.
    finish(source, peer.into_target().unwrap().1, b"abcdefgh");
    assert_eq!(
        std::fs::read(t.path().join("source.bin")).unwrap(),
        b"xyzdefgh"
    );
}
#[test]
fn policy_of_io_runtime_must_allow_exact_source_path() {
    let (t, _r, s, _peer) = owners(b"abcdefgh", 3);
    let other = t.path().join("other");
    std::fs::create_dir(&other).unwrap();
    let r = crate::runtime::Runtime::new(crate::config::Policy::new(vec![other], false).unwrap());
    assert!(r.open_fleet_resume_source(s, 8).is_err());
}
