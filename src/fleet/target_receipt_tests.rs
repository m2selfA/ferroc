use super::*;
#[path = "settlement_tests.rs"]
mod settlement_tests;
use crate::fleet::control::ParentDurability;
#[test]
#[ignore = "explicit real archived 1a5c binary only"]
fn actual_1a5c_refuses_schema8_at_entry() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_OBSERVATION_LEGACY_TEST").expect("explicit actual1a5c required"),
    );
    let mut f = std::fs::File::open(&exe).unwrap();
    let mut hash = Sha256::new();
    let mut b = [0u8; 65536];
    loop {
        let n = f.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&b[..n]);
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "1a5c09131d2655c2f86ac17942394421d53bae3e8ac4c18bb66b6c38931cc2d1"
    );
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc").record_target_observation().unwrap();
    let key = JobKey::from_job(c.snapshot().job());
    let raw = serde_json::to_string(c.snapshot()).unwrap();
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    drop(c);
    h.close().unwrap();
    drop(h);
    let mut child = process(
        &exe,
        &p,
        "old",
        "fleet::inventory::tests::inventory_process_child",
    );
    assert!(!child.wait().success());
    let log = child.logs();
    assert!(
        log.contains("unsupported/ambiguous fleet journal schema version"),
        "{log}"
    );
    assert!(!p.with_file_name("old-must-not-ready").exists());
    assert_eq!(schema(&p), 8);
    assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let restored = h.get(&key).unwrap().unwrap();
    assert_eq!(serde_json::to_string(&restored).unwrap(), raw);
    let conn = rusqlite::Connection::open(&p).unwrap();
    conn.execute("UPDATE ferroc_fleet_meta SET version=7", [])
        .unwrap();
    let e = h.get(&key).unwrap_err();
    assert!(
        format!("{e:#}").contains("row exceeds schema gate"),
        "{e:#}"
    );
    conn.execute("UPDATE ferroc_fleet_meta SET version=8", [])
        .unwrap();
    assert_eq!(
        serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
        raw
    );
    retained(&restored, &h, 3, true);
    assert_eq!(std::fs::read(dest).unwrap(), b"abc");
    println!(
        "ACTUAL1A5C_SCHEMA8_REFUSED: exactoldSHA/entryRefusal/rowBytesUnchanged/newReaderReject7row8/restore8/debtRetained/noFinalReceipt"
    );
}

#[test]
fn multi_chunk_hash_checks_lease_between_every_chunk() {
    let data = vec![0x45; 131073];
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, &data);
    let key = JobKey::from_job(c.snapshot().job());
    let mut calls = 0;
    assert!(
        c.receipt_between(
            |offset, c| {
                calls += 1;
                assert_eq!(offset, 65536);
                c.test_expire();
                Ok(())
            },
            |_| Ok(()),
            |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(calls, 1);
    retained(&h.get(&key).unwrap().unwrap(), &h, data.len() as u64, false);
}
#[test]
fn expired_before_sql_cannot_record_observation() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    assert!(
        c.receipt_between(
            |_, _| Ok(()),
            |c| {
                c.test_expire();
                Ok(())
            },
            |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(schema(&p), 7);
    retained(&h.get(&key).unwrap().unwrap(), &h, 3, false);
}
#[test]
fn cancellation_after_observation_commit_is_historical_not_final() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    assert!(
        c.receipt_between(
            |_, _| Ok(()),
            |_| Ok(()),
            |_| {
                let s = h.get(&key)?.unwrap();
                h.cancel(&key, s.revision())?;
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(schema(&p), 8);
    retained(&h.get(&key).unwrap().unwrap(), &h, 3, true);
}
#[test]
fn schema8_is_not_downgraded_by_older_stage_or_receive_entrypoints() {
    for receive in [false, true] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        rusqlite::Connection::open(&p)
            .unwrap()
            .execute("UPDATE ferroc_fleet_meta SET version=8", [])
            .unwrap();
        if receive {
            let c = renamed(&h, &p, b"abc");
            assert_eq!(schema(&p), 8);
            drop(c.record_target_observation().unwrap());
        } else {
            h.resume().unwrap();
            let offer = Offer::new(&p, b"abc", 0);
            h.admit(offer.g.job().clone(), 0).unwrap();
            assert_eq!(schema(&p), 8);
        }
    }
}
#[test]
fn malformed_observation_is_valid_json_but_semantically_rejected() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc").record_target_observation().unwrap();
    let key = JobKey::from_job(c.snapshot().job());
    let original = serde_json::to_value(c.snapshot()).unwrap();
    let raw = serde_json::to_string(c.snapshot()).unwrap();
    drop(c);
    let wrong = Offer::tagged(&p, b"abc", 0, 77).g.grant().binding.clone();
    for (field, bad) in [
        ("observation_id", serde_json::json!(Uuid::nil())),
        ("commit_intent", serde_json::json!(Uuid::nil())),
        ("size", serde_json::json!(99)),
        ("sha256", serde_json::to_value([0u8; 32]).unwrap()),
        ("target_file_id", serde_json::json!("different")),
        ("parent_id", serde_json::json!("different")),
        ("parent_durability", serde_json::json!("synced")),
        ("binding", serde_json::to_value(&wrong).unwrap()),
    ] {
        let mut v = original.clone();
        v["target_observation"][field] = bad;
        assert!(
            serde_json::from_value::<Snapshot>(v.clone()).is_ok(),
            "semantic control must parse {field}"
        );
        let conn = rusqlite::Connection::open(&p).unwrap();
        conn.execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1",
            [serde_json::to_string(&v).unwrap()],
        )
        .unwrap();
        let e = h.get(&key).unwrap_err();
        assert!(
            format!("{e:#}").contains("target observation"),
            "{field}: {e:#}"
        );
        conn.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [&raw])
            .unwrap();
        assert!(h.get(&key).unwrap().unwrap().target_observation().is_some());
    }
}
#[test]
fn legacy_publication_cannot_manufacture_final_receipt_or_clear_stage_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc").record_target_observation().unwrap();
    let s = c.snapshot().clone();
    drop(c);
    let key = JobKey::from_job(s.job());
    let mut guard = h.database.lock().unwrap();
    let mut j = guard.as_mut().unwrap().journal().unwrap();
    assert!(
        j.publication(
            &key,
            s.revision(),
            crate::fleet::stage::Publication::Published {
                size: 3,
                sha256: s.job().sha256,
                parent_sync: crate::fleet::stage::ParentSync::Unsupported
            }
        )
        .is_err()
    );
    assert!(j.confirm_removed(&key, s.revision()).is_err());
    assert_eq!(j.get(&key).unwrap().unwrap().revision(), s.revision());
    drop(guard);
    retained(&s, &h, 3, true);
}
#[test]
fn observation_owner_keeps_close_draining_and_never_deletes_substitute_on_drop() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = renamed(&h, &p, b"abc").record_target_observation().unwrap();
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let t = scope.spawn(|| tx.send(h.close()).unwrap());
        wait_closing(&h);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(c.observe().unwrap().bytes_read(), 3);
        drop(c);
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        t.join().unwrap();
    });
    let saved = p.with_file_name("receipt-saved");
    std::fs::rename(&dest, &saved).unwrap();
    std::fs::write(&dest, b"substitute").unwrap();
    drop(h);
    assert_eq!(std::fs::read(dest).unwrap(), b"substitute");
    assert_eq!(std::fs::read(saved).unwrap(), b"abc");
}
#[test]
fn renewed_receipt_binding_stays_historical_and_revoke_prevents_revival() {
    // The inherited Offer fixture intentionally supports ONE advancing renewal:
    // generations >0 all have issued_at_ms=201. Never weaken that contract.
    for before in [false, true] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let mut c = renamed(&h, &p, b"abc");
        let old = c.snapshot().intent_binding().unwrap().clone();
        let next = Offer::new(&p, b"abc", 1);
        let binding = next.g.grant().binding.clone();
        std::thread::sleep(Duration::from_millis(3));
        let mut c = if before {
            c.renew(next.g, next.target, &next.t, &next.a, &next.b)
                .unwrap();
            let c = c.record_target_observation().unwrap();
            assert_eq!(c.observation().binding(), &binding);
            assert_ne!(c.observation().binding(), &old);
            c
        } else {
            let mut c = c.record_target_observation().unwrap();
            let receipt = c.observation().clone();
            c.renew(next.g, next.target, &next.t, &next.a, &next.b)
                .unwrap();
            assert_eq!(c.observation(), &receipt);
            assert_eq!(c.observation().binding(), &old);
            c
        };
        assert_eq!(c.observe().unwrap().bytes_read(), 3);
        c.revoke();
        assert!(c.observe().is_err());
        let next = Offer::new(&p, b"abc", 2);
        let e = c
            .renew(next.g, next.target, &next.t, &next.a, &next.b)
            .unwrap_err();
        assert!(format!("{e:#}").contains("receiver faulted"), "{e:#}");
    }
}
#[test]
fn actual_process_exit_before_and_after_observation_sql_never_restores_live_owner() {
    for after in [false, true] {
        let (_t, p, r) = fixture();
        let mut child = process(
            &std::env::current_exe().unwrap(),
            &p,
            if after {
                "receipt-after"
            } else {
                "receipt-before"
            },
            "fleet::host::receiver::tests::intent_tests::candidate_tests::owned_publish_tests::target_receipt_tests::receipt_process_child",
        );
        assert_eq!(
            child.wait().code(),
            Some(if after { 57 } else { 56 }),
            "{}",
            child.logs()
        );
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let key = JobKey::from_job(Offer::new(&p, b"abc", 0).g.job());
        let s = h.get(&key).unwrap().unwrap();
        assert_eq!(schema(&p), if after { 8 } else { 7 });
        retained(&s, &h, 3, after);
        let dest = PathBuf::from(&s.job().destination_path);
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
        h.recover_stopped_owner(s.owner()).unwrap();
        let e = h.resume().unwrap_err();
        assert!(
            format!("{e:#}").contains("unresolved inventory/debt"),
            "{e:#}"
        );
        assert!(
            !h.inspect_allocation(&key)
                .unwrap()
                .eligible_for_absence_release()
        );
        let (_, records) = Offer::new(&p, b"abc", 0).pair();
        assert!(h.admit_receiver(records).is_err());
        retained(&h.get(&key).unwrap().unwrap(), &h, 3, after);
        assert_eq!(std::fs::read(dest).unwrap(), b"abc");
    }
}
#[test]
#[ignore = "real no-Drop subprocess only"]
fn receipt_process_child() {
    let p = PathBuf::from(std::env::var_os("FERROC_RECEIVE_DB").unwrap());
    let mode = std::env::var("FERROC_RECEIVE_MODE").unwrap();
    let r = crate::runtime::Runtime::new(
        Policy::new(vec![p.parent().unwrap().to_owned()], false).unwrap(),
    );
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let _ = c.receipt_between(
        |_, _| Ok(()),
        |_| {
            if mode == "receipt-before" {
                std::process::exit(56)
            }
            Ok(())
        },
        |_| std::process::exit(57),
    );
    panic!("unreachable crash control");
}
#[test]
fn native_eight_mib_target_observation_roundtrip_not_network_or_settlement() {
    let data = vec![0x58; 8 * 1024 * 1024];
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let start = Instant::now();
    let mut c = renamed(&h, &p, &data).record_target_observation().unwrap();
    assert_eq!(c.observe().unwrap().bytes_read(), data.len() as u64);
    assert_eq!(c.observation().sha256(), Sha256::digest(&data).as_slice());
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    let s = c.snapshot().clone();
    drop(c);
    assert_eq!(std::fs::read(dest).unwrap(), data);
    retained(&s, &h, 8 * 1024 * 1024, true);
    println!(
        "LOCAL_TARGET_RECEIPT8MIB: bytes={} elapsed_ms={} v8Unknown/originalLease/noFinalReceipt/noDebtRelease/noNetwork",
        data.len(),
        start.elapsed().as_millis()
    );
}

fn renamed<'h, 'r>(h: &'h FleetHost<'r>, p: &Path, data: &[u8]) -> RenamedCandidate<'h, 'r> {
    candidate(h, p, data).attempt_local_publication().unwrap()
}
fn retained(s: &Snapshot, h: &FleetHost<'_>, bytes: u64, observed: bool) {
    assert_eq!(s.phase(), Phase::CommitUnknown);
    assert!(s.receipt().is_none());
    assert_eq!(s.target_observation().is_some(), observed);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (bytes, 1));
}
#[test]
fn success_retains_original_file_lease_operation_and_all_debt() {
    for data in [b"abc".as_slice(), b"".as_slice()] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let c = renamed(&h, &p, data);
        let before = c.snapshot().clone();
        let dest = PathBuf::from(&before.job().destination_path);
        let mut c = c.record_target_observation().unwrap();
        assert_eq!(schema(&p), 8);
        assert_eq!(c.snapshot().revision(), before.revision() + 1);
        assert_eq!(c.snapshot().stage(), before.stage());
        assert_eq!(c.snapshot().intent(), before.intent());
        assert_eq!(c.observation().size(), data.len() as u64);
        assert_eq!(c.observation().sha256(), before.job().sha256);
        assert_eq!(
            c.observation().parent_durability(),
            ParentDurability::Unsupported
        );
        assert_eq!(c.observe().unwrap().bytes_read(), data.len() as u64);
        assert_eq!(h.status().unwrap().in_flight, 1);
        assert_eq!(
            std::fs::remove_file(&dest).unwrap_err().raw_os_error(),
            Some(32)
        );
        let raw = serde_json::to_string(c.snapshot()).unwrap();
        let key = JobKey::from_job(c.snapshot().job());
        drop(c);
        assert_eq!(h.status().unwrap().in_flight, 0);
        let s = h.get(&key).unwrap().unwrap();
        assert_eq!(serde_json::to_string(&s).unwrap(), raw);
        retained(&s, &h, data.len() as u64, true);
        assert_eq!(std::fs::read(dest).unwrap(), data);
    }
}
#[test]
fn same_size_target_mutation_is_rehashed_not_trusted_from_v7() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    std::fs::write(&dest, b"xyz").unwrap();
    let e = c.record_target_observation().err().unwrap();
    assert!(format!("{e:#}").contains("SHA256 mismatch"), "{e:#}");
    retained(&h.get(&key).unwrap().unwrap(), &h, 3, false);
    assert_eq!(schema(&p), 7);
    assert_eq!(std::fs::read(dest).unwrap(), b"xyz");
}
#[test]
fn original_handle_move_and_same_size_substitute_is_rejected_not_deleted() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    let moved = p.with_file_name("saved-target");
    c.test_move(&moved).unwrap();
    std::fs::write(&dest, b"xyz").unwrap();
    assert!(c.record_target_observation().is_err());
    retained(&h.get(&key).unwrap().unwrap(), &h, 3, false);
    assert_eq!(std::fs::read(dest).unwrap(), b"xyz");
    assert_eq!(std::fs::read(moved).unwrap(), b"abc");
}
#[test]
fn cancelled_or_expired_owner_cannot_issue_observation() {
    for expire in [false, true] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let mut c = renamed(&h, &p, b"abc");
        let key = JobKey::from_job(c.snapshot().job());
        if expire {
            c.test_expire()
        } else {
            let s = h.get(&key).unwrap().unwrap();
            h.cancel(&key, s.revision()).unwrap();
        }
        assert!(c.record_target_observation().is_err());
        retained(&h.get(&key).unwrap().unwrap(), &h, 3, false);
        assert_eq!(schema(&p), 7);
    }
}
#[test]
fn real_sql_failure_after_native_rename_retains_target_unknown_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    let db = rusqlite::Connection::open(&p).unwrap();
    db.execute_batch("CREATE TRIGGER fail_observation BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'observation SQL failure'); END").unwrap();
    let e = c.record_target_observation().err().unwrap();
    assert!(
        format!("{e:#}").contains("observation SQL failure"),
        "{e:#}"
    );
    assert_eq!(schema(&p), 7);
    retained(&h.get(&key).unwrap().unwrap(), &h, 3, false);
    assert_eq!(std::fs::read(dest).unwrap(), b"abc");
}
#[test]
fn writer_at_receipt_commit_fails_without_waiting_and_restores_timeout() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let db = rusqlite::Connection::open(&p).unwrap();
    let lock_wait = std::cell::Cell::new(Duration::ZERO);
    let start = Instant::now();
    let e = c
        .receipt_between(
            |_, _| Ok(()),
            |_| {
                let t = Instant::now();
                db.execute_batch("BEGIN IMMEDIATE")?;
                lock_wait.set(t.elapsed());
                Ok(())
            },
            |_| Ok(()),
        )
        .err()
        .unwrap();
    let elapsed = start.elapsed();
    // The fixture's own BEGIN IMMEDIATE can block on SQLite's 5 s busy timeout.
    // Only our no-wait behaviour is gated; its wait is reported separately.
    let own = elapsed.saturating_sub(lock_wait.get());
    db.execute_batch("ROLLBACK").unwrap();
    assert!(format!("{e:#}").contains("database is locked"), "{e:#}");
    assert!(
        own < Duration::from_secs(2),
        "{own:?} (elapsed {elapsed:?}, fixture lock {lock_wait:?})"
    );
    assert_eq!(timeout(&h), 5000);
    assert_eq!(schema(&p), 7);
    retained(&h.get(&key).unwrap().unwrap(), &h, 3, false);
    println!(
        "TARGET_RECEIPT_NOWAIT: own_ms={} lock_ms={} restored5000 noReceipt",
        own.as_millis(),
        lock_wait.get().as_millis()
    );
}
#[test]
fn post_sql_expiry_size_or_identity_change_returns_no_live_owner() {
    for kind in 0..3 {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let c = renamed(&h, &p, b"abc");
        let key = JobKey::from_job(c.snapshot().job());
        let dest = PathBuf::from(&c.snapshot().job().destination_path);
        let moved = p.with_file_name("post-sql-original");
        assert!(
            c.receipt_between(
                |_, _| Ok(()),
                |_| Ok(()),
                |c| {
                    match kind {
                        0 => c.test_expire(),
                        1 => std::fs::OpenOptions::new()
                            .write(true)
                            .open(&dest)?
                            .set_len(2)?,
                        _ => {
                            c.test_move(&moved)?;
                            std::fs::write(&dest, b"xyz")?;
                        }
                    }
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(schema(&p), 8);
        retained(&h.get(&key).unwrap().unwrap(), &h, 3, true);
        if kind == 2 {
            assert_eq!(std::fs::read(dest).unwrap(), b"xyz");
            assert_eq!(std::fs::read(moved).unwrap(), b"abc");
        }
    }
}
#[test]
fn eof_size_change_is_rejected_before_observation_sql() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = renamed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    assert!(
        c.receipt_between(
            |_, _| Ok(()),
            |_| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&dest)?
                    .set_len(2)?;
                Ok(())
            },
            |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(schema(&p), 7);
    retained(&h.get(&key).unwrap().unwrap(), &h, 3, false);
}
