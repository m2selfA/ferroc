use super::*;
#[test]
fn flow_ready_and_ack_are_cached_exactly_and_duplicate_data_never_rewrites() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.resume().unwrap();
    let (mut s, mut receiver) = open(&h, &path, b"abc");
    let a = receiver.ready_record(2).unwrap().to_vec();
    assert_eq!(receiver.ready_record(2).unwrap(), a);
    s.open_record(&a).unwrap();
    let zero = receiver.ack_record().unwrap().to_vec();
    assert_eq!(receiver.ack_record().unwrap(), zero);
    s.open_record(&zero).unwrap();
    let data = s.seal_data(0, b"abc").unwrap();
    receiver.write_record(&data).unwrap();
    let ack = receiver.ack_record().unwrap().to_vec();
    assert_ne!(ack, zero);
    assert_eq!(receiver.write_record(&data).unwrap(), Admission::Duplicate);
    assert_eq!(receiver.ack_record().unwrap(), ack);
    s.open_record(&ack).unwrap();
    assert_eq!(
        std::fs::read(receiver.snapshot.stage().unwrap().path()).unwrap(),
        b"abc"
    );
    drop(receiver);
    h.close().unwrap();
}
#[test]
fn flow_invalid_window_and_ack_without_ready_fault_without_debt_release() {
    for mode in [0, 9, 255] {
        let (_t, path, r) = fixture();
        let h = r
            .open_fleet_host(&path, InventoryLimits::default())
            .unwrap();
        h.resume().unwrap();
        let (_s, mut receiver) = open(&h, &path, b"abc");
        let stage = receiver.snapshot.stage().unwrap().path().to_path_buf();
        if mode == 255 {
            assert!(receiver.ack_record().is_err());
        } else {
            assert!(receiver.ready_record(mode).is_err());
        }
        assert!(receiver.faulted);
        assert!(stage.exists());
        assert!(receiver.snapshot.stage().is_some());
        assert!(receiver.ready_record(1).is_err());
        drop(receiver);
        h.close().unwrap();
    }
}
#[test]
fn flow_ready_after_data_and_changed_ready_window_fail() {
    for after_data in [false, true] {
        let (_t, path, r) = fixture();
        let h = r
            .open_fleet_host(&path, InventoryLimits::default())
            .unwrap();
        h.resume().unwrap();
        let (mut s, mut receiver) = open(&h, &path, b"abc");
        if after_data {
            receiver
                .write_record(&s.seal_data(0, b"abc").unwrap())
                .unwrap();
        } else {
            receiver.ready_record(2).unwrap();
        }
        assert!(receiver.ready_record(1).is_err());
        assert!(receiver.faulted);
        assert!(receiver.snapshot.stage().unwrap().path().exists());
        drop(receiver);
        h.close().unwrap();
    }
}
#[test]
fn flow_database_mutex_competition_fails_fast_and_keeps_original_stage() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.resume().unwrap();
    let (_s, mut receiver) = open(&h, &path, b"abc");
    let hold = h.database.lock().unwrap();
    let start = Instant::now();
    assert!(receiver.ready_record(2).is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(receiver.faulted);
    assert!(receiver.snapshot.stage().unwrap().path().exists());
    drop(hold);
    drop(receiver);
    h.close().unwrap();
}
#[test]
fn flow_sql_writer_does_not_block_readonly_ready_and_restores_busy_timeout() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.resume().unwrap();
    let (_s, mut receiver) = open(&h, &path, b"abc");
    let writer = rusqlite::Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let start = Instant::now();
    receiver.ready_record(2).unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    writer.execute_batch("ROLLBACK").unwrap();
    let hold = h.database.lock().unwrap();
    let timeout: i64 = hold
        .as_ref()
        .unwrap()
        .connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert_eq!(timeout, 5000);
    drop(hold);
    drop(receiver);
    h.close().unwrap();
}
#[test]
fn flow_expired_cached_ack_and_changed_stage_are_not_exported() {
    for expired in [false, true] {
        let (_t, path, r) = fixture();
        let h = r
            .open_fleet_host(&path, InventoryLimits::default())
            .unwrap();
        h.resume().unwrap();
        let (mut s, mut receiver) = open(&h, &path, b"abc");
        receiver.ready_record(2).unwrap();
        receiver
            .write_record(&s.seal_data(0, b"abc").unwrap())
            .unwrap();
        receiver.ack_record().unwrap();
        if expired {
            receiver.records.test_expire();
        } else {
            receiver.file.set_len(4).unwrap();
        }
        assert!(receiver.ack_record().is_err());
        assert!(receiver.faulted);
        assert!(receiver.snapshot.stage().is_some());
        drop(receiver);
        h.close().unwrap();
    }
}
// Fixture leases need a wider skew window so a later public renew(now) can
// certainly-live the successor grant. PUBLIC TEST issuance only.
fn leased_pair(o: Offer) -> (LeasedRecords, LeasedRecords) {
    let sample = ClockSample::now();
    let one = o
        .source
        .authenticate_leased(
            &o.t,
            Direction::SourceToTarget,
            &o.g,
            &o.sp,
            &o.tp,
            &o.a,
            &o.b,
            TrustedTimeAnchor::approved_window(sample, 300, 300).unwrap(),
        )
        .unwrap();
    let two = o
        .target
        .authenticate_leased(
            &o.t,
            Direction::TargetToSource,
            &o.g,
            &o.sp,
            &o.tp,
            &o.a,
            &o.b,
            TrustedTimeAnchor::approved_window(sample, 300, 300).unwrap(),
        )
        .unwrap();
    (one, two)
}
fn open_renewable<'h, 'r>(
    h: &'h FleetHost<'r>,
    path: &Path,
    data: &[u8],
) -> (LeasedRecords, HostReceiver<'h, 'r>) {
    h.resume().unwrap();
    let (source, target) = leased_pair(Offer::new(path, data, 0));
    (source, h.admit_receiver(target).unwrap())
}
const CHUNK: usize = 65536;
#[test]
fn flow_renewal_after_acked_prefix_keeps_coverage_and_rotates_epoch() {
    let data = vec![0x4a; 3 * CHUNK];
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (mut s, mut receiver) = open_renewable(&h, &path, &data);
    let ready = receiver.ready_record(2).unwrap().to_vec();
    s.open_record(&ready).unwrap();
    receiver
        .write_record(&s.seal_data(0, &data[..CHUNK]).unwrap())
        .unwrap();
    let first_ack = receiver.ack_record().unwrap().to_vec();
    s.open_record(&first_ack).unwrap();
    assert_eq!(receiver.observed_coverage(), CHUNK as u64);

    let next = Offer::new(&path, &data, 1);
    receiver
        .renew(next.g.clone(), next.target, &next.t, &next.a, &next.b)
        .unwrap();
    s.renew(next.g, next.source, &next.t, &next.a, &next.b)
        .unwrap();
    // Coverage survives rotation; no byte is re-requested or rewritten.
    assert_eq!(receiver.observed_coverage(), CHUNK as u64);
    assert!(!receiver.coverage_complete());
    assert!(
        s.open_record(&first_ack).is_err(),
        "superseded epoch ACK must not reopen"
    );

    // Continue under the rotated epoch and keep cumulative coverage monotonic.
    for index in 1..3 {
        let offset = index * CHUNK;
        receiver
            .write_record(
                &s.seal_data(offset as u64, &data[offset..offset + CHUNK])
                    .unwrap(),
            )
            .unwrap();
        let ack = receiver.ack_record().unwrap().to_vec();
        s.open_record(&ack).unwrap();
    }
    assert!(receiver.coverage_complete());
    assert_eq!(
        std::fs::read(receiver.snapshot.stage().unwrap().path()).unwrap(),
        data
    );
    drop(receiver);
    h.close().unwrap();
}

#[test]
fn flow_sql_exclusive_blocks_ready_or_cached_ack_without_wait_and_restores_timeout() {
    for cached_ack in [false, true] {
        let (_t, path, r) = fixture();
        let h = r
            .open_fleet_host(&path, InventoryLimits::default())
            .unwrap();
        h.resume().unwrap();
        let (mut s, mut receiver) = open(&h, &path, b"abc");
        if cached_ack {
            receiver.ready_record(2).unwrap();
            receiver
                .write_record(&s.seal_data(0, b"abc").unwrap())
                .unwrap();
            receiver.ack_record().unwrap();
        }
        {
            let g = h.database.lock().unwrap();
            g.as_ref()
                .unwrap()
                .connection
                .pragma_update(None, "journal_mode", "DELETE")
                .unwrap();
        }
        let writer = rusqlite::Connection::open(&path).unwrap();
        writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let start = Instant::now();
        let result = if cached_ack {
            receiver.ack_record()
        } else {
            receiver.ready_record(2)
        };
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(receiver.faulted);
        writer.execute_batch("ROLLBACK").unwrap();
        let g = h.database.lock().unwrap();
        let timeout: i64 = g
            .as_ref()
            .unwrap()
            .connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);
        drop(g);
        assert!(receiver.snapshot.stage().unwrap().path().exists());
        drop(receiver);
        h.close().unwrap();
    }
}
