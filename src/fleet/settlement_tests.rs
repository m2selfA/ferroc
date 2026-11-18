use super::*;
use crate::fleet::control::{ControlBody, Finish};
#[test]
#[ignore = "explicit real b9fc v8 binary only"]
fn actual_b9fc_refuses_schema9_at_entry() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_SETTLEMENT_LEGACY_TEST").expect("explicit actual b9fc required"),
    );
    let mut f = std::fs::File::open(&exe).unwrap();
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "b9fc75ac63724400db7f65eeb3204154df65aab23e65973a9688cd7723f36c41"
    );
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc").settle_local().unwrap();
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
    assert_eq!(schema(&p), 9);
    assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    assert_eq!(
        serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
        raw
    );
    let db = rusqlite::Connection::open(&p).unwrap();
    db.execute("UPDATE ferroc_fleet_meta SET version=8", [])
        .unwrap();
    let e = h.get(&key).unwrap_err();
    assert!(
        format!("{e:#}").contains("row exceeds schema gate"),
        "{e:#}"
    );
    db.execute("UPDATE ferroc_fleet_meta SET version=9", [])
        .unwrap();
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(serde_json::to_string(&s).unwrap(), raw);
    done(&h, &s, 3);
    println!(
        "ACTUALB9FC_SCHEMA9_REFUSED: exactOldSHA/entryRefusal/row+targetUnchanged/newReaderReject8row9/restore9/historyOrigin+finalReceipt/zeroStageDebt"
    );
}

#[test]
fn final_settlement_allows_separate_new_job_without_downgrading_metadata9() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let first = observed(&h, &p, b"abc").settle_local().unwrap();
    let (mut source, records) = Offer::tagged(&p, b"def", 0, 1).pair();
    let mut recv = h.admit_receiver(records).unwrap();
    assert_eq!(schema(&p), 9);
    recv.write_record(&source.seal_data(0, b"def").unwrap())
        .unwrap();
    let finish = source
        .seal_control(ControlBody::Finish(Finish {
            size: 3,
            sha256: Sha256::digest(b"def").into(),
        }))
        .unwrap();
    let c = recv
        .seal_finish(&finish)
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap();
    assert_eq!(schema(&p), 9);
    let second = c.settle_local().unwrap();
    done(&h, first.snapshot(), 3);
    done(&h, second.snapshot(), 3);
    assert_eq!(h.status().unwrap().in_flight, 2);
    assert_eq!(
        std::fs::read(&first.snapshot().job().destination_path).unwrap(),
        b"abc"
    );
    assert_eq!(
        std::fs::read(&second.snapshot().job().destination_path).unwrap(),
        b"def"
    );
}
#[test]
fn renewed_binding_settles_without_rewriting_historical_observation() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = observed(&h, &p, b"abc");
    let observed = c.observation().clone();
    let offer = Offer::new(&p, b"abc", 1);
    let binding = offer.g.grant().binding.clone();
    std::thread::sleep(Duration::from_millis(3));
    c.renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
        .unwrap();
    let c = c.settle_local().unwrap();
    assert_eq!(c.snapshot().settlement_binding(), Some(&binding));
    assert_eq!(c.snapshot().target_observation(), Some(&observed));
    assert_ne!(c.snapshot().settlement_binding(), Some(observed.binding()));
    done(&h, c.snapshot(), 3);
}
#[test]
fn legacy_publication_cannot_restore_completed_from_recovered_history() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc").settle_local().unwrap();
    let s = c.snapshot().clone();
    let key = JobKey::from_job(s.job());
    drop(c);
    h.close().unwrap();
    drop(h);
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.recover_stopped_owner(s.owner()).unwrap();
    let archived = h.get(&key).unwrap().unwrap();
    assert_eq!(archived.phase(), Phase::CommitUnknown);
    assert_eq!(archived.receipt(), s.receipt());
    assert_eq!(archived.settlement_origin(), s.settlement_origin());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
    let mut guard = h.database.lock().unwrap();
    let mut j = guard.as_mut().unwrap().journal().unwrap();
    let e = j
        .publication(
            &key,
            archived.revision(),
            crate::fleet::stage::Publication::Published {
                size: 3,
                sha256: s.job().sha256,
                parent_sync: crate::fleet::stage::ParentSync::Unsupported,
                mode: crate::fleet::stage::PublishMode::CreateNoClobber,
            },
        )
        .unwrap_err();
    assert!(format!("{e:#}").contains("no metadata replay"), "{e:#}");
    assert_eq!(j.get(&key).unwrap().unwrap().phase(), Phase::CommitUnknown);
    drop(guard);
    h.resume().unwrap();
    let (_, records) = Offer::new(&p, b"abc", 0).pair();
    assert!(h.admit_receiver(records).is_err());
    assert_eq!(std::fs::read(&s.job().destination_path).unwrap(), b"abc");
}
#[test]
fn settlement_semantic_corruptions_are_valid_json_but_rejected() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc").settle_local().unwrap();
    let key = JobKey::from_job(c.snapshot().job());
    let original = serde_json::to_value(c.snapshot()).unwrap();
    let raw = serde_json::to_string(c.snapshot()).unwrap();
    drop(c);
    for case in 0..8 {
        let mut v = original.clone();
        match case {
            0 => v["settlement_origin"] = serde_json::Value::Null,
            1 => v["settlement_origin"]["reserved"] = serde_json::json!(99),
            2 => v["receipt"]["receiptId"] = serde_json::json!(Uuid::nil()),
            3 => v["receipt"]["parentDurability"] = serde_json::json!("synced"),
            4 => {
                v["settlement_binding"] =
                    serde_json::to_value(Offer::tagged(&p, b"abc", 0, 66).g.grant().binding.clone())
                        .unwrap()
            }
            5 => v["stage"] = v["settlement_origin"].clone(),
            6 => v["phase"] = serde_json::to_value(Phase::Committing).unwrap(),
            _ => v["target_observation"] = serde_json::Value::Null,
        };
        assert!(
            serde_json::from_value::<Snapshot>(v.clone()).is_ok(),
            "must be semantic control {case}"
        );
        let db = rusqlite::Connection::open(&p).unwrap();
        db.execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1",
            [serde_json::to_string(&v).unwrap()],
        )
        .unwrap();
        assert!(h.get(&key).is_err(), "semantic corruption {case}");
        db.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [&raw])
            .unwrap();
        assert_eq!(h.get(&key).unwrap().unwrap().phase(), Phase::Completed);
    }
}
#[test]
fn eof_expiry_size_and_multichunk_revoke_before_sql_preserve_debt() {
    for case in 0..3 {
        let data = vec![0x34; 131073];
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let c = observed(&h, &p, &data);
        let key = JobKey::from_job(c.snapshot().job());
        let dest = PathBuf::from(&c.snapshot().job().destination_path);
        assert!(
            c.settle_between(
                |offset, c| {
                    if case == 2 {
                        assert_eq!(offset, 65536);
                        c.revoke();
                    }
                    Ok(())
                },
                |c| {
                    if case == 0 {
                        c.test_expire()
                    } else if case == 1 {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&dest)?
                            .set_len(2)?;
                    }
                    Ok(())
                },
                |_| Ok(())
            )
            .is_err()
        );
        assert_eq!(schema(&p), 8);
        unchanged(&h, &key, data.len() as u64);
    }
}
#[test]
fn finished_owner_keeps_drain_and_original_handle_until_drop() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc").settle_local().unwrap();
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let t = scope.spawn(|| tx.send(h.close()).unwrap());
        wait_closing(&h);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert!(!c.local_commit_ack().to_vec().is_empty());
        assert_eq!(
            std::fs::remove_file(&dest).unwrap_err().raw_os_error(),
            Some(32)
        );
        drop(c);
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        t.join().unwrap();
    });
    let saved = p.with_file_name("finished-original");
    std::fs::rename(&dest, &saved).unwrap();
    std::fs::write(&dest, b"substitute").unwrap();
    drop(h);
    assert_eq!(std::fs::read(dest).unwrap(), b"substitute");
    assert_eq!(std::fs::read(saved).unwrap(), b"abc");
}
#[test]
fn late_cancel_keeps_completion_and_historical_ack_usable() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc").settle_local().unwrap();
    let key = JobKey::from_job(c.snapshot().job());
    let receipt = c.receipt().clone();
    let cancelled = h.cancel(&key, c.snapshot().revision()).unwrap();
    assert_eq!(cancelled.phase(), Phase::Completed);
    assert_eq!(cancelled.receipt(), Some(&receipt));
    assert!(!c.local_commit_ack().to_vec().is_empty());
    done(&h, &cancelled, 3);
}
#[test]
fn held_host_database_fails_fast_without_lock_order_inversion() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let guard = h.database.lock().unwrap();
    let now = Instant::now();
    let e = c.settle_local().err().unwrap();
    assert!(format!("{e:#}").contains("gate never waits"), "{e:#}");
    assert!(now.elapsed() < Duration::from_secs(2));
    drop(guard);
    unchanged(&h, &key, 3);
}
#[test]
fn actual_exit_before_after_settlement_sql_has_distinct_debt_and_history() {
    for after in [false, true] {
        let (_t, p, r) = fixture();
        let mut child = process(
            &std::env::current_exe().unwrap(),
            &p,
            if after {
                "settle-after"
            } else {
                "settle-before"
            },
            "fleet::host::receiver::tests::intent_tests::candidate_tests::owned_publish_tests::target_receipt_tests::settlement_tests::settlement_process_child",
        );
        assert_eq!(
            child.wait().code(),
            Some(if after { 59 } else { 58 }),
            "{}",
            child.logs()
        );
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let key = JobKey::from_job(Offer::new(&p, b"abc", 0).g.job());
        let s = h.get(&key).unwrap().unwrap();
        if after {
            done(&h, &s, 3)
        } else {
            unchanged(&h, &key, 3)
        }
        assert_eq!(schema(&p), if after { 9 } else { 8 });
        h.recover_stopped_owner(s.owner()).unwrap();
        let history = h.get(&key).unwrap().unwrap();
        assert_eq!(history.phase(), Phase::CommitUnknown);
        assert_eq!(history.receipt().is_some(), after);
        assert_eq!(history.settlement_origin().is_some(), after);
        assert_eq!(
            h.inventory().unwrap().recorded_usage(),
            if after { (0, 0) } else { (3, 1) }
        );
        assert_eq!(std::fs::read(&s.job().destination_path).unwrap(), b"abc");
    }
}
#[test]
#[ignore = "real no-Drop settlement subprocess only"]
fn settlement_process_child() {
    let p = PathBuf::from(std::env::var_os("FERROC_RECEIVE_DB").unwrap());
    let mode = std::env::var("FERROC_RECEIVE_MODE").unwrap();
    let r = crate::runtime::Runtime::new(
        Policy::new(vec![p.parent().unwrap().to_owned()], false).unwrap(),
    );
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc");
    let _ = c.settle_between(
        |_, _| Ok(()),
        |_| {
            if mode == "settle-before" {
                std::process::exit(58)
            }
            Ok(())
        },
        |_| std::process::exit(59),
    );
    panic!("unreachable crash control");
}
#[test]
fn native_eight_mib_data_to_final_ack_is_local_component_not_network() {
    let data = vec![0x59; 8 * 1024 * 1024];
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let start = Instant::now();
    let (mut source, mut recv) = open(&h, &p, &data);
    for (off, chunk) in data.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((off * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    let finish = source
        .seal_control(ControlBody::Finish(Finish {
            size: data.len() as u64,
            sha256: Sha256::digest(&data).into(),
        }))
        .unwrap();
    let c = recv
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
    let frame = c.local_commit_ack().to_vec();
    let msg = match source.open_record(&frame).unwrap() {
        PeerRecord::Control { message, .. } => message,
        _ => panic!("expected local encrypted ack"),
    };
    assert_eq!(msg.body, ControlBody::CommitAck(c.receipt().clone()));
    assert_eq!(
        std::fs::read(&c.snapshot().job().destination_path).unwrap(),
        data
    );
    done(&h, c.snapshot(), data.len() as u64);
    println!(
        "LOCAL_SETTLEMENT_ACK8MIB: bytes={} elapsed_ms={} originalLease/v9Completed/receipt+zeroStageDebt/realEncryptedAck/noNetwork/parentUnsupported",
        data.len(),
        start.elapsed().as_millis()
    );
}

fn observed<'h, 'r>(h: &'h FleetHost<'r>, p: &Path, data: &[u8]) -> ReceiptedCandidate<'h, 'r> {
    renamed(h, p, data).record_target_observation().unwrap()
}
fn unchanged(h: &FleetHost<'_>, key: &JobKey, bytes: u64) {
    let s = h.get(key).unwrap().unwrap();
    assert_eq!(s.phase(), Phase::CommitUnknown);
    assert!(
        s.stage().is_some()
            && s.target_observation().is_some()
            && s.receipt().is_none()
            && s.settlement_origin().is_none()
    );
    assert_eq!(h.inventory().unwrap().recorded_usage(), (bytes, 1));
}
fn done(h: &FleetHost<'_>, s: &Snapshot, bytes: u64) {
    assert_eq!(s.phase(), Phase::Completed);
    assert!(s.stage().is_none() && s.target_observation().is_some());
    assert_eq!(s.settlement_origin().unwrap().reserved_bytes(), bytes);
    let r = s.receipt().unwrap();
    assert_eq!(r.receipt_id, s.intent().unwrap());
    assert_eq!(r.sha256, s.job().sha256);
    assert_eq!(r.size, bytes);
    assert_eq!(r.parent_durability, ParentDurability::Unsupported);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
}
#[test]
fn explicit_completion_archives_source_and_releases_bytes_and_zero_slot() {
    for data in [b"abc".as_slice(), b"".as_slice()] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let c = observed(&h, &p, data);
        let before = c.snapshot().clone();
        let dest = PathBuf::from(&before.job().destination_path);
        let c = c.settle_local().unwrap();
        assert_eq!(schema(&p), 9);
        assert_eq!(c.snapshot().revision(), before.revision() + 1);
        assert_eq!(c.snapshot().settlement_origin(), before.stage());
        assert_eq!(c.snapshot().data_seal(), before.data_seal());
        assert_eq!(
            c.snapshot().target_observation(),
            before.target_observation()
        );
        done(&h, c.snapshot(), data.len() as u64);
        assert_eq!(h.status().unwrap().in_flight, 1);
        assert_eq!(
            std::fs::remove_file(&dest).unwrap_err().raw_os_error(),
            Some(32)
        );
        let key = JobKey::from_job(c.snapshot().job());
        let raw = serde_json::to_string(c.snapshot()).unwrap();
        drop(c);
        assert_eq!(h.status().unwrap().in_flight, 0);
        assert_eq!(
            serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
            raw
        );
        assert_eq!(std::fs::read(dest).unwrap(), data);
    }
}
#[test]
fn same_size_change_after_observation_cannot_settle_cached_sha() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    std::fs::write(&dest, b"xyz").unwrap();
    let e = c.settle_local().err().unwrap();
    assert!(format!("{e:#}").contains("SHA256 mismatch"), "{e:#}");
    assert_eq!(schema(&p), 8);
    unchanged(&h, &key, 3);
    assert_eq!(std::fs::read(dest).unwrap(), b"xyz");
}
#[test]
fn substitute_target_cannot_settle_or_be_deleted_by_error_drop() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = PathBuf::from(&c.snapshot().job().destination_path);
    let saved = p.with_file_name("settle-original");
    c.test_move(&saved).unwrap();
    std::fs::write(&dest, b"xyz").unwrap();
    assert!(c.settle_local().is_err());
    unchanged(&h, &key, 3);
    assert_eq!(std::fs::read(dest).unwrap(), b"xyz");
    assert_eq!(std::fs::read(saved).unwrap(), b"abc");
}
#[test]
fn expiry_or_cancel_before_commit_preserves_entire_debt() {
    for expire in [false, true] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let mut c = observed(&h, &p, b"abc");
        let key = JobKey::from_job(c.snapshot().job());
        if expire {
            c.test_expire()
        } else {
            h.cancel(&key, c.snapshot().revision()).unwrap();
        }
        assert!(c.settle_local().is_err());
        assert_eq!(schema(&p), 8);
        unchanged(&h, &key, 3);
    }
}
#[test]
fn sql_abort_after_rename_does_not_release_debt_or_issue_receipt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let db = rusqlite::Connection::open(&p).unwrap();
    db.execute_batch("CREATE TRIGGER abort_settle BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'settlement SQL abort'); END").unwrap();
    let e = c.settle_local().err().unwrap();
    assert!(format!("{e:#}").contains("settlement SQL abort"), "{e:#}");
    assert_eq!(schema(&p), 8);
    unchanged(&h, &key, 3);
}
#[test]
fn sqlite_writer_at_final_settlement_is_zero_wait_and_restored() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = observed(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let db = rusqlite::Connection::open(&p).unwrap();
    let lock_wait = std::cell::Cell::new(Duration::ZERO);
    let start = Instant::now();
    let e = c
        .settle_between(
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
    assert_eq!(schema(&p), 8);
    unchanged(&h, &key, 3);
    println!(
        "SETTLEMENT_NOWAIT: own_ms={} lock_ms={} original2s/restore5000/noReceipt/noRelease",
        own.as_millis(),
        lock_wait.get().as_millis()
    );
}
#[test]
fn after_commit_errors_do_not_erase_historical_completion_or_claim_rollback() {
    for kind in 0..3 {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let c = observed(&h, &p, b"abc");
        let key = JobKey::from_job(c.snapshot().job());
        let dest = PathBuf::from(&c.snapshot().job().destination_path);
        let saved = p.with_file_name("post-settle-original");
        assert!(
            c.settle_between(
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
                            c.test_move(&saved)?;
                            std::fs::write(&dest, b"xyz")?;
                        }
                    }
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(schema(&p), 9);
        let s = h.get(&key).unwrap().unwrap();
        done(&h, &s, 3);
        if kind == 2 {
            assert_eq!(std::fs::read(dest).unwrap(), b"xyz");
            assert_eq!(std::fs::read(saved).unwrap(), b"abc");
        }
    }
}
#[test]
fn encrypted_commit_ack_roundtrip_is_local_only_and_binds_persisted_receipt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let f = source
        .seal_control(ControlBody::Finish(Finish {
            size: 3,
            sha256: Sha256::digest(b"abc").into(),
        }))
        .unwrap();
    let c = recv
        .seal_finish(&f)
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    let receipt = c.receipt().clone();
    let frame = c.local_commit_ack().to_vec();
    source.test_expire(); // Stored ACK settles the completed event, no new IO.
    let message = match source.open_record(&frame).unwrap() {
        PeerRecord::Control { message, .. } => message,
        _ => panic!("expected encrypted COMMIT_ACK"),
    };
    assert_eq!(message.body, ControlBody::CommitAck(receipt));
    assert_eq!(c.local_commit_ack(), frame.as_slice());
    assert!(matches!(
        source.open_record(c.local_commit_ack()).unwrap(),
        PeerRecord::Duplicate { .. }
    ));
    assert!(source.seal_data(0, b"abc").is_err());
    done(&h, c.snapshot(), 3);
}
