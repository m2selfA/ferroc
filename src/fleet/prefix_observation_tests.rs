use super::*;

#[test]
fn expiry_during_prefix_read_fails_and_retains_full_obligation() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let data = vec![3u8; 65537];
    let (mut source, mut recv) = open(&h, &p, &data);
    for (offset, chunk) in data.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((offset * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    assert!(
        recv.prefix_between(|_, this| {
            this.records.test_expire();
            Ok(())
        })
        .is_err()
    );
    assert!(recv.faulted);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (65537, 1));
    assert_eq!(schema(&p), 4);
}
#[test]
fn truncation_during_prefix_read_returns_no_observation_and_retains_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let data = vec![3u8; 65537];
    let (mut source, mut recv) = open(&h, &p, &data);
    for (offset, chunk) in data.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((offset * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    assert!(
        recv.prefix_between(|_, this| {
            this.file.set_len(1)?;
            Ok(())
        })
        .is_err()
    );
    assert!(recv.faulted);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (65537, 1));
}
#[cfg(target_os = "linux")]
#[test]
fn anonymous_receiver_cannot_create_retained_prefix_metadata() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.resume().unwrap();
    let (_, target) = Offer::new(&p, b"abc", 0).pair();
    let mut recv = h.admit_linux_anonymous_receiver(target).unwrap();
    let error = recv.observe_synced_prefix().unwrap_err().to_string();
    assert!(error.contains("anonymous stage"), "{error}");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    assert_eq!(schema(&p), 11);
}

#[test]
fn partial_prefix_is_synced_and_hashed_without_seal_or_metadata_transition() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdefgh");
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let before = serde_json::to_value(recv.snapshot()).unwrap();
    let observed = recv.observe_synced_prefix().unwrap();
    assert_eq!(observed.bytes(), 3);
    assert_eq!(observed.sha256(), <[u8; 32]>::from(Sha256::digest(b"abc")));
    assert_eq!(
        observed.job_digest(),
        recv.snapshot().job().digest().unwrap()
    );
    assert_eq!(observed.revision(), recv.snapshot().revision());
    assert_eq!(serde_json::to_value(recv.snapshot()).unwrap(), before);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert_eq!(schema(&p), 4);
    recv.write_record(&source.seal_data(3, b"defgh").unwrap())
        .unwrap();
    let full = recv.observe_synced_prefix().unwrap();
    assert_eq!(full.bytes(), 8);
    assert_eq!(full.sha256(), recv.snapshot().job().sha256);
    assert_eq!(observed.bytes(), 3);
    assert!(recv.snapshot().data_seal().is_none());
}
#[test]
fn out_of_order_tail_is_never_counted_as_a_contiguous_prefix() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdefgh");
    recv.write_record(&source.seal_data(4, b"efgh").unwrap())
        .unwrap();
    let observed = recv.observe_synced_prefix().unwrap();
    assert_eq!(observed.bytes(), 0);
    assert_eq!(observed.sha256(), <[u8; 32]>::from(Sha256::digest(b"")));
    recv.write_record(&source.seal_data(0, b"abcd").unwrap())
        .unwrap();
    assert_eq!(
        recv.observe_synced_prefix().unwrap().sha256(),
        recv.snapshot().job().sha256
    );
}
#[test]
fn cancellation_faults_observation_without_clearing_stage_or_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"a").unwrap())
        .unwrap();
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    h.cancel(
        &JobKey::from_job(recv.snapshot().job()),
        recv.snapshot().revision(),
    )
    .unwrap();
    assert!(recv.observe_synced_prefix().is_err());
    assert!(recv.faulted);
    assert!(path.exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn database_mutex_contention_fails_without_waiting_under_gate() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, mut recv) = open(&h, &p, b"abc");
    let guard = h.database.lock().unwrap();
    let error = recv.observe_synced_prefix().unwrap_err().to_string();
    assert!(error.contains("gate never waits for DB"), "{error}");
    drop(guard);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn sqlite_writer_does_not_make_read_only_observation_wait_or_write_metadata() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"ab").unwrap())
        .unwrap();
    let db = rusqlite::Connection::open(&p).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let observed = recv.observe_synced_prefix().unwrap();
    assert_eq!(observed.bytes(), 2);
    db.execute_batch("ROLLBACK").unwrap();
    let mut guard = h.database.lock().unwrap();
    let db = guard.as_mut().unwrap();
    let timeout: i64 = db
        .connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert_eq!(timeout, 5000);
}
#[test]
fn read_sequence_is_historical_not_a_guarantee_against_external_same_size_writes() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let data = vec![7u8; 131073];
    let (mut source, mut recv) = open(&h, &p, &data);
    for (offset, chunk) in data.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((offset * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    let observed = recv
        .prefix_between(|offset, this| {
            if offset == 65536 {
                this.file.seek(SeekFrom::Start(0))?;
                this.file.write_all(&[9])?;
                this.file.seek(SeekFrom::Start(offset))?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(observed.sha256(), <[u8; 32]>::from(Sha256::digest(&data)));
    assert_ne!(
        recv.observe_synced_prefix().unwrap().sha256(),
        observed.sha256()
    );
    assert_eq!(
        h.inventory().unwrap().recorded_usage(),
        (data.len() as u64, 1)
    );
}
