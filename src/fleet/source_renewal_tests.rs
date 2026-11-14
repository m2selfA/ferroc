use super::*;
#[test]
fn renewal_requires_drained_acked_window_and_preserves_session() {
    let data = vec![0x58; 3 * 65536];
    let (_t, r, s, mut p, source, destination) = renewable_fixture(&data);
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 2).unwrap();
    // A renewal before READY is refused: no flow window is negotiated yet.
    let early = Offer::paths(&data, 1, source.clone(), destination.clone());
    assert!(
        w.renew(early.g, early.s, &early.t, &early.a, &early.b)
            .is_err()
    );
    assert!(!w.is_faulted());
    assert_eq!(w.next_record().unwrap(), WindowRecord::WaitingForReady);
    w.observe_control(&ready(&mut p, 2)).unwrap();

    let (_, first) = take(&mut w);
    p.open_record(&first).unwrap();
    assert_eq!(w.pending_records(), 1);
    // Unacknowledged ciphertext would be undecryptable under a new epoch.
    let refused = Offer::paths(&data, 1, source.clone(), destination.clone());
    assert!(
        w.renew(refused.g, refused.s, &refused.t, &refused.a, &refused.b)
            .is_err()
    );
    assert!(!w.is_faulted());
    assert_eq!(w.pending_records(), 1);
    assert_eq!(w.retry_record(0).unwrap(), first);

    let old_ack = ack(&mut p, 65536, 65536);
    w.observe_control(&old_ack).unwrap();
    assert_eq!(w.pending_records(), 0);
    assert_eq!(w.bytes_peer_reported_contiguous(), 65536);

    let next = Offer::paths(&data, 1, source.clone(), destination.clone());
    w.renew(next.g.clone(), next.s, &next.t, &next.a, &next.b)
        .unwrap();
    p.renew(next.g, next.r, &next.t, &next.a, &next.b).unwrap();
    // Counters, hash and the original total deadline survive the rotation.
    assert_eq!(w.bytes_encoded(), 65536);
    assert_eq!(w.bytes_peer_reported_contiguous(), 65536);
    assert_eq!(w.pending_records(), 0);

    let (offset, second) = take(&mut w);
    assert_eq!(offset, 65536);
    p.open_record(&second).unwrap();
    w.observe_control(&ack(&mut p, 131072, 131072)).unwrap();
    assert_eq!(w.bytes_peer_reported_contiguous(), 131072);
    let (_, third) = take(&mut w);
    p.open_record(&third).unwrap();
    w.observe_control(&ack(&mut p, data.len() as u64, data.len() as u64))
        .unwrap();
    assert_eq!(w.next_record().unwrap(), WindowRecord::Exhausted);

    // A superseded-epoch ACK cannot authenticate under the renewed binding. It is
    // rejected WITHOUT poisoning the live window, exactly like any foreign frame:
    // only authenticated-but-wrong traffic faults. New-epoch progress is unaffected.
    assert!(w.observe_control(&old_ack).is_err());
    assert!(!w.is_faulted());
    assert_eq!(w.bytes_peer_reported_contiguous(), data.len() as u64);
    let _end = w.finish().unwrap();
}
#[test]
fn renewal_rejection_keeps_old_epoch_writable_and_finish_gated() {
    let data = vec![0x31; 65536];
    let (_t, r, s, mut p, source, destination) = renewable_fixture(&data);
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    w.observe_control(&ready(&mut p, 1)).unwrap();
    let (_, only) = take(&mut w);
    p.open_record(&only).unwrap();
    w.observe_control(&ack(&mut p, 65536, 65536)).unwrap();

    // A successor that changes the approved job byte total cannot be installed.
    let wider = Offer::paths(&vec![0x31; 65537], 1, source, destination);
    assert!(
        w.renew(wider.g, wider.s, &wider.t, &wider.a, &wider.b)
            .is_err()
    );
    assert!(!w.is_faulted());
    assert_eq!(w.bytes_encoded(), 65536);
    assert_eq!(w.bytes_peer_reported_contiguous(), 65536);
    let end = w.finish().unwrap();
    p.open_record(end.finish_record()).unwrap();
    assert_eq!(end.status(), SourceCommitStatus::AwaitingAck);
}
