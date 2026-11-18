use super::*;
use crate::fleet::{
    auth::IdentityKey,
    control::{ControlBody, RenewCommit, RenewCommitted},
    host::receiver::HostReceiver,
    renewal::successor,
    source_window::{ProgressOutcome, WindowRecord},
};
/// Both sides build the same successor from the same seed/generation, exactly as
/// a real control plane would hand each host its own copy.
fn successor_for(g: &ValidatedGrant) -> ValidatedGrant {
    // A renewal must ADVANCE the lease window, so start inside the current one
    // and end past it while staying under the job deadline.
    // Start inside the current window (so it is "certainly live") and end after
    // it, while staying under the job deadline.
    // A renewal must ADVANCE expiry, so the new window has to end after the
    // current one while staying inside the fixed job deadline.
    successor(g, &[0x5d; 32], 1, g.grant().issued_at_ms + 10, 50_000).unwrap()
}
fn material(next: &ValidatedGrant) -> (EphemeralKey, EphemeralKey, Transcript, [u8; 64], [u8; 64]) {
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let s = EphemeralKey::from_test_bytes([0xa1; 32]);
    let t = EphemeralKey::from_test_bytes([0xa2; 32]);
    let tr = Transcript::for_grant(next, sk.public(), tk.public(), s.public(), t.public());
    let a = sk.sign(&tr, Direction::SourceToTarget).unwrap();
    let b = tk.sign(&tr, Direction::TargetToSource).unwrap();
    (s, t, tr, a, b)
}
/// Drive source + receiver to a drained boundary of `chunks` acknowledged DATA.
fn drained(
    window: &mut SourceWindow<'_>,
    receiver: &mut HostReceiver<'_, '_>,
    chunks: usize,
) -> Result<()> {
    let ready = receiver.ready_record(4)?.to_vec();
    window.observe_control(&ready)?;
    for _ in 0..chunks {
        let frame = match window.next_record()? {
            WindowRecord::Data { ciphertext, .. } => ciphertext.to_vec(),
            other => panic!("DATA expected: {other:?}"),
        };
        receiver.write_record(&frame)?;
        let ack = receiver.ack_record()?.to_vec();
        window.observe_control(&ack)?;
    }
    assert_eq!(window.pending_records(), 0);
    Ok(())
}
/// Full handshake: offer → accept → commit, both sides installed, coverage and
/// encoded counters preserved across the rotation, transfer continues.
#[cfg(windows)]
#[tokio::test]
async fn renewal_handshake_rotates_both_sides_at_the_same_boundary() {
    const CHUNK: usize = 65536;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x4b; 4 * CHUNK];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let mut receiver = host
        .admit_receiver(records(&g, Direction::TargetToSource))
        .unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut window = SourceWindow::new(
        srt.open_fleet_source(records(&g, Direction::SourceToTarget))
            .unwrap(),
        2,
    )
    .unwrap();
    drained(&mut window, &mut receiver, 2).unwrap();
    assert!(window.at_renewal_boundary());
    let next = successor_for(&g);
    let (ks, kt, tr, a, b) = material(&next);
    // Offer travels under the OLD epoch and installs nothing.
    let offer_frame = window
        .begin_renewal(
            next.grant().binding.authorization_id,
            next.grant().binding.key_epoch,
            1,
        )
        .unwrap();
    assert_eq!(window.renewal_accepted(), None);
    // Accept names the target's coverage boundary; nothing installed yet.
    let (_offer, accept_frame) = receiver.accept_renewal(&offer_frame).unwrap();
    let outcome = window.observe_control(&accept_frame).unwrap();
    assert_eq!(outcome, ProgressOutcome::RenewAccepted);
    assert_eq!(window.renewal_accepted(), Some((2 * CHUNK) as u64));
    assert_eq!(window.bytes_encoded(), (2 * CHUNK) as u64);
    // Commit is sealed under the OLD epoch, then both sides install.
    let commit_frame = window
        .commit_renewal(next.clone(), ks, &tr, &a, &b)
        .unwrap();
    receiver
        .install_renewal(&commit_frame, next.clone(), kt, &tr, &a, &b)
        .unwrap();
    // Counters survive the rotation: nothing re-encoded, nothing re-acknowledged.
    assert_eq!(window.bytes_encoded(), (2 * CHUNK) as u64);
    assert_eq!(window.bytes_peer_reported_contiguous(), (2 * CHUNK) as u64);
    assert_eq!(receiver.observed_coverage(), (2 * CHUNK) as u64);
    // And the transfer continues under the new epoch to completion.
    let frame = match window.next_record().unwrap() {
        WindowRecord::Data { ciphertext, .. } => ciphertext.to_vec(),
        other => panic!("DATA expected after rotation: {other:?}"),
    };
    receiver.write_record(&frame).unwrap();
    let ack = receiver.ack_record().unwrap().to_vec();
    window.observe_control(&ack).unwrap();
    assert_eq!(window.bytes_encoded(), (3 * CHUNK) as u64);
}
/// A peer that names a different boundary must not be installed over.
#[cfg(windows)]
#[tokio::test]
async fn renewal_handshake_refuses_a_foreign_successor_and_a_second_offer() {
    const CHUNK: usize = 65536;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x4c; 4 * CHUNK];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let mut receiver = host
        .admit_receiver(records(&g, Direction::TargetToSource))
        .unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut window = SourceWindow::new(
        srt.open_fleet_source(records(&g, Direction::SourceToTarget))
            .unwrap(),
        2,
    )
    .unwrap();
    drained(&mut window, &mut receiver, 2).unwrap();
    let next = successor_for(&g);
    let (_ks, kt, _tr, _a, _b) = material(&next);
    let offer_frame = window
        .begin_renewal(
            next.grant().binding.authorization_id,
            next.grant().binding.key_epoch,
            1,
        )
        .unwrap();
    // The accept must name exactly the boundary the source offered.
    let (_offer, accept_frame) = receiver.accept_renewal(&offer_frame).unwrap();
    window.observe_control(&accept_frame).unwrap();
    assert_eq!(window.renewal_accepted(), Some((2 * CHUNK) as u64));
    // A second accept for the same offer is refused, not silently re-applied.
    assert!(
        receiver.accept_renewal(&offer_frame).is_err(),
        "one handshake at a time"
    );
    // A commit for a successor the receiver never accepted must be refused.
    let other = successor(
        &next,
        &[0x77; 32],
        2,
        next.grant().issued_at_ms + 10,
        50_000,
    )
    .unwrap();
    let (_, _, other_tr, other_a, other_b) = material(&other);
    let mut foreign_records = records(&g, Direction::SourceToTarget);
    let foreign_commit = foreign_records
        .seal_control(ControlBody::RenewCommit(RenewCommit {
            next_authorization_id: other.grant().binding.authorization_id,
            next_key_epoch: other.grant().binding.key_epoch,
            generation: 2,
            drained_at: (2 * CHUNK) as u64,
        }))
        .unwrap();
    assert!(
        receiver
            .install_renewal(&foreign_commit, other, kt, &other_tr, &other_a, &other_b)
            .is_err(),
        "install for an unaccepted successor must fail"
    );
}

/// The target's confirmation is sealed under the NEW epoch and must name the
/// successor the source actually installed. This is what tells the source it may
/// resume DATA, so a mismatch has to be refused rather than ignored.
#[cfg(windows)]
#[tokio::test]
async fn renewal_committed_names_the_installed_successor() {
    const CHUNK: usize = 65536;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x4d; 4 * CHUNK];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let mut receiver = host
        .admit_receiver(records(&g, Direction::TargetToSource))
        .unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut window = SourceWindow::new(
        srt.open_fleet_source(records(&g, Direction::SourceToTarget))
            .unwrap(),
        2,
    )
    .unwrap();
    drained(&mut window, &mut receiver, 2).unwrap();
    let next = successor_for(&g);
    let (ks, kt, tr, a, b) = material(&next);
    let offer_frame = window
        .begin_renewal(
            next.grant().binding.authorization_id,
            next.grant().binding.key_epoch,
            1,
        )
        .unwrap();
    let (_offer, accept_frame) = receiver.accept_renewal(&offer_frame).unwrap();
    window.observe_control(&accept_frame).unwrap();
    let commit_frame = window
        .commit_renewal(next.clone(), ks, &tr, &a, &b)
        .unwrap();
    receiver
        .install_renewal(&commit_frame, next.clone(), kt, &tr, &a, &b)
        .unwrap();
    // The receiver now confirms under the new epoch.
    let confirmed = receiver.renew_committed_record(&next, 1).unwrap();
    assert_eq!(
        window.observe_control(&confirmed).unwrap(),
        ProgressOutcome::RenewCommitted
    );
    // A confirmation naming a different successor is refused.
    let other = successor(
        &next,
        &[0x7a; 32],
        2,
        next.grant().issued_at_ms + 10,
        50_000,
    )
    .unwrap();
    let wrong = receiver
        .seal_committed_for_test(RenewCommitted {
            next_authorization_id: other.grant().binding.authorization_id,
            next_key_epoch: other.grant().binding.key_epoch,
            generation: 2,
        })
        .unwrap();
    assert!(
        window.observe_control(&wrong).is_err(),
        "a confirmation for an uninstalled successor must not be accepted"
    );
}
