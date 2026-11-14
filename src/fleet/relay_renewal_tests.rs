use super::*;
/// Same job, rotated authorization/epoch; other fields are caller-chosen so a
/// negative case can violate exactly one routing rule.
fn variant(
    g: &ValidatedGrant,
    auth: u128,
    epoch: u128,
    session: u128,
    chunk: u32,
) -> ValidatedGrant {
    let old = g.grant();
    let mut binding = old.binding.clone();
    binding.authorization_id = Uuid::from_u128(auth);
    binding.key_epoch = Uuid::from_u128(epoch);
    binding.source_session = Uuid::from_u128(session);
    FileGrant {
        binding,
        job_digest: old.job_digest,
        permission: old.permission,
        chunk_bytes: chunk,
        issued_at_ms: old.issued_at_ms + 1,
        expires_at_ms: old.expires_at_ms + 1,
    }
    .validate_for(g.job().clone())
    .unwrap()
}
#[test]
fn advance_local_requires_stable_identity_rotation_and_no_reuse() {
    let t = tempfile::tempdir().unwrap();
    let data = b"xyz";
    let g = grant(t.path(), data);
    let registry = FleetRelay::new();
    registry
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let session = g.grant().binding.source_session.as_u128();
    let auth = g.grant().binding.authorization_id.as_u128();
    let epoch = g.grant().binding.key_epoch.as_u128();

    // Never approved here (different job), so there is no live route to advance.
    let other = grant(t.path(), b"xyz2");
    assert!(
        registry
            .advance_local(&other, &variant(&other, 9001, 9501, session, 65536))
            .is_err()
    );
    // Not a rotation: same authorization and epoch.
    assert!(
        registry
            .advance_local(&g, &variant(&g, auth, epoch, session, 65536))
            .is_err()
    );
    // Rotation cannot move the live session identity.
    assert!(
        registry
            .advance_local(&g, &variant(&g, 9001, 9501, session + 1, 65536))
            .is_err()
    );

    let next = variant(&g, 9001, 9501, session, 65536);
    registry.advance_local(&g, &next).unwrap();
    // The superseded binding can no longer be advanced or replayed.
    assert!(registry.advance_local(&g, &next).is_err());
    assert!(
        registry
            .advance_local(&next, &variant(&next, 9002, 9502, session, 65536))
            .is_ok()
    );
    // Binding reuse is refused even after a later legitimate successor.
    assert!(
        registry
            .advance_local(&variant(&next, 9002, 9502, session, 65536), &next)
            .is_err()
    );
    let pair = registry
        .table
        .lock()
        .unwrap()
        .pairs
        .values()
        .next()
        .unwrap()
        .clone();
    let mut old_records = records(&g, Direction::SourceToTarget);
    let stale = old_records.seal_data(0, data).unwrap();
    let mut new_records = records(&next, Direction::SourceToTarget);
    let fresh = new_records.seal_data(0, data).unwrap();
    let route = pair.route.lock().unwrap();
    assert!(
        route.validate(&stale, Direction::SourceToTarget).is_err(),
        "superseded epoch must not route"
    );
    assert!(
        route.validate(&fresh, Direction::SourceToTarget).is_err(),
        "only the latest approved successor routes"
    );
    drop(route);
    let newest = variant(&next, 9002, 9502, session, 65536);
    let mut newest_records = records(&newest, Direction::SourceToTarget);
    let latest = newest_records.seal_data(0, data).unwrap();
    assert!(
        pair.route
            .lock()
            .unwrap()
            .validate(&latest, Direction::SourceToTarget)
            .is_ok()
    );
    // Stale frames stay rejected once the newest binding is live.
    assert!(
        pair.route
            .lock()
            .unwrap()
            .validate(&stale, Direction::SourceToTarget)
            .is_err()
    );
}
/// Real relay + real file, one mid-transfer epoch rotation at a drained ACK
/// boundary, then continue to v9. PUBLIC TEST issuance and loopback only.
#[cfg(windows)]
fn renewal_offer(
    g: &ValidatedGrant,
    generation: u128,
) -> (
    ValidatedGrant,
    Transcript,
    EphemeralKey,
    EphemeralKey,
    [u8; 64],
    [u8; 64],
) {
    let old = g.grant();
    let mut binding = old.binding.clone();
    binding.authorization_id = Uuid::from_u128(9000 + generation);
    binding.key_epoch = Uuid::from_u128(9500 + generation);
    let next = FileGrant {
        binding,
        job_digest: old.job_digest,
        permission: old.permission,
        chunk_bytes: old.chunk_bytes,
        issued_at_ms: old.issued_at_ms + generation as u64,
        expires_at_ms: old.expires_at_ms + generation as u64,
    }
    .validate_for(g.job().clone())
    .unwrap();
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let s = EphemeralKey::from_test_bytes([0x55; 32]);
    let t = EphemeralKey::from_test_bytes([0x66; 32]);
    let tr = Transcript::for_grant(&next, sk.public(), tk.public(), s.public(), t.public());
    let a = sk.sign(&tr, Direction::SourceToTarget).unwrap();
    let b = tk.sign(&tr, Direction::TargetToSource).unwrap();
    (next, tr, s, t, a, b)
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_relay_renewal_mid_transfer_keeps_coverage_and_settles() {
    use crate::fleet::source::FinalAckOutcome;
    use crate::fleet::source_window::WindowRecord;
    const CHUNK: usize = 65536;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x62; 3 * CHUNK];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let registry = Arc::new(FleetRelay::new());
    let (url, _relay, server) = server(&root, Some(registry.clone())).await;
    let tickets = registry
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let mut source = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    let mut target = link(
        &url,
        tickets.target.expose_secret(),
        &g,
        Direction::TargetToSource,
    )
    .await
    .unwrap();
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
    let ready = receiver.ready_record(2).unwrap().to_vec();
    target.send(ready).await.unwrap();
    window
        .observe_control(&source.receive().await.unwrap())
        .unwrap();
    for index in 0..3 {
        if index == 1 {
            // Drain first: the only safe rotation point.
            assert_eq!(window.pending_records(), 0);
            assert_eq!(window.bytes_encoded(), CHUNK as u64);
            assert_eq!(receiver.observed_coverage(), CHUNK as u64);
            let (next, tr, ks, kt, a, b) = renewal_offer(&g, 1);
            registry.advance_local(&g, &next).unwrap();
            source.advance(&next).unwrap();
            target.advance(&next).unwrap();
            receiver.renew(next.clone(), kt, &tr, &a, &b).unwrap();
            window.renew(next, ks, &tr, &a, &b).unwrap();
            assert_eq!(window.bytes_encoded(), CHUNK as u64);
            assert_eq!(receiver.observed_coverage(), CHUNK as u64);
        }
        let frame = match window.next_record().unwrap() {
            WindowRecord::Data { ciphertext, .. } => ciphertext.to_vec(),
            other => panic!("DATA expected: {other:?}"),
        };
        source.send(frame).await.unwrap();
        let incoming = target.receive().await.unwrap();
        receiver.write_record(&incoming).unwrap();
        let ack = receiver.ack_record().unwrap().to_vec();
        target.send(ack).await.unwrap();
        window
            .observe_control(&source.receive().await.unwrap())
            .unwrap();
    }
    let mut pending = window.finish().unwrap();
    source.send(pending.finish_record().to_vec()).await.unwrap();
    let finish = target.receive().await.unwrap();
    let done = receiver
        .seal_finish(&finish)
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    let receipt = done.receipt().clone();
    target.send(done.local_commit_ack().to_vec()).await.unwrap();
    let final_frame = source.receive().await.unwrap();
    assert_eq!(
        pending.observe_final(&final_frame).unwrap(),
        FinalAckOutcome::Accepted
    );
    assert_eq!(pending.peer_observation().unwrap().receipt(), &receipt);
    drop(done);
    assert_eq!(std::fs::read(root.join("target/output.bin")).unwrap(), data);
    // `receiver` was consumed by seal_finish; FinishedCandidate is dropped above.
    host.close().unwrap();
    registry.close();
    server.abort();
    let _ = server.await;
}

#[test]
fn advance_local_after_registry_close_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"xyz");
    let registry = FleetRelay::new();
    registry
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    registry.close();
    let session = g.grant().binding.source_session.as_u128();
    assert!(
        registry
            .advance_local(&g, &variant(&g, 9001, 9501, session, 65536))
            .is_err()
    );
}
