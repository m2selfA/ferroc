use super::*;
#[path = "commit_candidate_tests.rs"]
mod candidate_tests;
fn sealed<'h, 'r>(h: &'h FleetHost<'r>, p: &Path, data: &[u8]) -> SealedReceiver<'h, 'r> {
    let (_, r, f) = fill(h, p, data);
    r.seal_finish(&f).unwrap()
}
fn timeout(h: &FleetHost<'_>) -> i64 {
    h.database
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .connection
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .unwrap()
}
#[test]
fn v6_intent_is_atomic_historical_runtime_event_not_publication_and_restores_timeout() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let old = recv.snapshot().clone();
    h.database
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .connection
        .busy_timeout(Duration::from_millis(1234))
        .unwrap();
    let s = recv.reserve_commit().unwrap();
    assert_eq!(timeout(&h), 1234);
    assert_eq!(schema(&p), 6);
    assert_eq!(s.revision(), old.revision() + 1);
    assert_eq!(s.phase(), Phase::Committing);
    assert!(s.intent().is_some_and(|id| !id.is_nil()) && s.receipt().is_none());
    assert_eq!(s.intent_binding(), Some(s.data_seal().unwrap().binding()));
    assert_eq!(serde_json::to_value(&s).unwrap()["verified"], true);
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"abc");
    assert!(!Path::new(&s.job().destination_path).exists());
    let key = JobKey::from_job(s.job());
    {
        let mut db = h.database.lock().unwrap();
        let mut j = db.as_mut().unwrap().journal().unwrap();
        assert!(j.progress(&key, s.revision(), 3).is_err());
        assert!(j.readback(&key, s.revision(), s.job().sha256).is_err());
        assert!(j.begin_commit(&key, s.revision()).is_err());
        assert!(j.confirm_removed(&key, s.revision()).is_err());
    }
    assert!(
        !h.inspect_allocation(&key)
            .unwrap()
            .eligible_for_absence_release()
    );
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn runtime_write_queues_until_gate_release_and_intent_is_not_later_file_truth() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, &vec![b'a'; 131073]);
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let gate = r.test_fs_gate();
    let (start_tx, start_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let runtime = &r;
        let worker_path = &path;
        let worker = scope.spawn(move || {
            start_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            ready_tx.send(()).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = rt.block_on(runtime.call(
                "write_file",
                serde_json::json!({"path":worker_path,"content":"x".repeat(131073)}),
            ));
            done_tx.send(result).unwrap();
        });
        let mut sent = false;
        let s = recv
            .reserve_between(
                |offset, _| {
                    assert!(matches!(
                        gate.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ));
                    if !sent {
                        assert_eq!(offset, 65536);
                        start_tx.send(()).unwrap();
                        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
                        sent = true;
                    }
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
        let response = done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        assert_ne!(response.is_error, Some(true));
        assert_eq!(std::fs::read(&path).unwrap(), vec![b'x'; 131073]);
        assert_eq!(s.phase(), Phase::Committing);
        assert!(s.receipt().is_none());
        assert!(!Path::new(&s.job().destination_path).exists());
        let key = JobKey::from_job(s.job());
        assert_eq!(
            h.cancel(&key, s.revision()).unwrap().phase(),
            Phase::CommitUnknown
        );
    });
}
#[test]
fn cancel_before_hash_cannot_create_intent() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    h.cancel(&key, recv.snapshot().revision()).unwrap();
    assert!(recv.reserve_commit().is_err());
    assert_eq!(schema(&p), 5);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(s.phase(), Phase::CancelRequested);
    assert!(s.intent().is_none());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn real_cancel_runs_at64k_without_db_held_across_full_hash() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, &vec![42; 131073]);
    let key = JobKey::from_job(recv.snapshot().job());
    let rev = recv.snapshot().revision();
    let mut calls = 0;
    let error = recv
        .reserve_between(
            |offset, _| {
                assert_eq!(offset, 65536);
                h.cancel(&key, rev).unwrap();
                calls += 1;
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();
    assert_eq!(calls, 1);
    assert!(error.to_string().contains("cancelled/stale"));
    assert_eq!(schema(&p), 5);
    assert!(h.get(&key).unwrap().unwrap().intent().is_none());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
}
#[test]
fn expiry_before_hash_preserves_seal_and_bytes() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut recv = sealed(&h, &p, b"abc");
    recv.inner.records.test_expire();
    assert!(recv.reserve_commit().is_err());
    assert_eq!(schema(&p), 5);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn expiry_at64k_cannot_retroactively_admit() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, &vec![42; 131073]);
    let mut n = 0;
    assert!(
        recv.reserve_between(
            |offset, r| {
                assert_eq!(offset, 65536);
                r.inner.records.test_expire();
                n += 1;
                Ok(())
            },
            |_| Ok(())
        )
        .is_err()
    );
    assert_eq!(n, 1);
    assert_eq!(schema(&p), 5);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
}
#[test]
fn cancel_after_sql_commit_settles_unknown_and_preserves_intent() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    assert!(
        recv.reserve_between(
            |_, _| Ok(()),
            |r| {
                h.cancel(&key, r.snapshot().revision())?;
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(schema(&p), 6);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(s.phase(), Phase::CommitUnknown);
    assert!(s.intent().is_some() && s.receipt().is_none());
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"abc");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn expiry_after_sql_commit_returns_error_without_erasing_possible_intent() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    assert!(
        recv.reserve_between(
            |_, _| Ok(()),
            |r| {
                r.inner.records.test_expire();
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(schema(&p), 6);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(s.phase(), Phase::Committing);
    assert!(s.intent().is_some());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn sql_failure_rolls_back_intent_and_metadata_without_cleanup() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let raw = serde_json::to_string(recv.snapshot()).unwrap();
    let key = JobKey::from_job(recv.snapshot().job());
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("CREATE TRIGGER reject_v6 BEFORE UPDATE ON ferroc_fleet_jobs_v1 WHEN json_extract(NEW.body,'$.version')=6 BEGIN SELECT RAISE(ABORT,'intent fault');END;").unwrap();
    assert!(recv.reserve_commit().is_err());
    assert_eq!(timeout(&h), 5000);
    assert_eq!(schema(&p), 5);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(serde_json::to_string(&s).unwrap(), raw);
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"abc");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[tokio::test]
async fn same_size_runtime_mutation_before_final_hash_never_mints_intent() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let key = JobKey::from_job(recv.snapshot().job());
    let result = r
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(result.is_error, Some(true));
    assert!(
        recv.reserve_commit()
            .unwrap_err()
            .to_string()
            .contains("SHA256 mismatch")
    );
    assert_eq!(schema(&p), 5);
    assert!(h.get(&key).unwrap().unwrap().intent().is_none());
    assert_eq!(std::fs::read(path).unwrap(), b"xyz");
}
#[tokio::test]
async fn runtime_move_denied_on_windows_or_substitute_rejected_without_cleanup() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let moved = p.with_file_name("moved-stage");
    let result = r
        .call(
            "move_file",
            serde_json::json!({"source":path,"destination":moved}),
        )
        .await;
    #[cfg(windows)]
    {
        assert_eq!(result.is_error, Some(true), "{result:?}");
        assert!(
            format!("{result:?}").contains("os error 32"),
            "not a share violation: {result:?}"
        );
        assert!(!moved.exists());
    }
    #[cfg(not(windows))]
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let result = r
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(result.is_error, Some(true));
    assert!(recv.reserve_commit().is_err());
    assert_eq!(schema(&p), 5);
    assert_eq!(std::fs::read(&path).unwrap(), b"xyz");
    #[cfg(not(windows))]
    assert_eq!(std::fs::read(&moved).unwrap(), b"abc");
    #[cfg(windows)]
    assert!(!moved.exists());
}
#[test]
fn typed_v6_negative_snapshots_fail_validation_and_restore_exact_original() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let s = sealed(&h, &p, b"abc").reserve_commit().unwrap();
    let key = JobKey::from_job(s.job());
    let raw = serde_json::to_string(&s).unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    for mode in 0..9 {
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        match mode {
            0 => v["intent_binding"] = serde_json::Value::Null,
            1 => v["intent_binding"]["sourceSession"] = serde_json::json!(Uuid::new_v4()),
            2 => v["intent"] = serde_json::json!(Uuid::nil()),
            3 => v["verified"] = serde_json::json!(false),
            4 => v["phase"] = serde_json::to_value(Phase::Verifying).unwrap(),
            5 => v["version"] = serde_json::json!(5),
            6 => v["data_seal"] = serde_json::Value::Null,
            7 => v["received"] = serde_json::json!(2),
            8 => v["intent_binding"]["keyEpoch"] = serde_json::json!(Uuid::nil()),
            _ => unreachable!(),
        };
        let changed = serde_json::to_string(&v).unwrap();
        let _: Snapshot =
            serde_json::from_str(&changed).expect("negative must reach typed validation");
        c.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [changed])
            .unwrap();
        let error = h.get(&key).unwrap_err();
        c.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [&raw])
            .unwrap();
        if mode == 8 {
            assert_eq!(error.to_string(), "nil fleet identifier");
        } else {
            assert!(
                error.to_string().contains("intent")
                    || error.to_string().contains("invalid")
                    || error.to_string().contains("seal"),
                "case {mode}: {error}"
            );
        }
        assert_eq!(
            serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
            raw
        );
    }
    c.execute("UPDATE ferroc_fleet_meta SET version=5", [])
        .unwrap();
    let rejected = h.get(&key).unwrap_err();
    c.execute("UPDATE ferroc_fleet_meta SET version=6", [])
        .unwrap();
    assert!(rejected.to_string().contains("row exceeds schema gate"));
    assert!(h.get(&key).unwrap().is_some());
}
#[test]
fn zero_byte_intent_keeps_slot_and_cannot_release_or_resume() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let s = sealed(&h, &p, b"").reserve_commit().unwrap();
    let key = JobKey::from_job(s.job());
    assert_eq!(schema(&p), 6);
    assert!(s.intent().is_some() && s.receipt().is_none());
    assert!(
        !h.inspect_allocation(&key)
            .unwrap()
            .eligible_for_absence_release()
    );
    let (_, target) = Offer::new(&p, b"", 0).pair();
    assert!(h.admit_receiver(target).is_err());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
}
#[test]
fn renewed_current_binding_not_old_seal_epoch_is_persisted_at_admission() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut recv = sealed(&h, &p, b"abc");
    let old = recv.snapshot().data_seal().unwrap().binding().clone();
    let offer = Offer::new(&p, b"abc", 1);
    let expected = offer.g.grant().binding.clone();
    std::thread::sleep(Duration::from_millis(3));
    recv.renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
        .unwrap();
    let s = recv.reserve_commit().unwrap();
    assert_eq!(s.intent_binding(), Some(&expected));
    assert_eq!(s.data_seal().unwrap().binding(), &old);
    assert_ne!(expected.key_epoch, old.key_epoch);
}
#[test]
fn v3_v4_v5_under_independent_empty_schema6_domains_never_downgrade() {
    for mode in 0..3 {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        rusqlite::Connection::open(&p)
            .unwrap()
            .execute("UPDATE ferroc_fleet_meta SET version=6", [])
            .unwrap();
        h.resume().unwrap();
        if mode == 0 {
            h.admit(Offer::new(&p, b"", 0).g.job().clone(), 100)
                .unwrap();
        } else if mode == 1 {
            let (_, target) = Offer::new(&p, b"", 0).pair();
            drop(h.admit_receiver(target).unwrap());
        } else {
            drop(sealed(&h, &p, b""));
        }
        assert_eq!(schema(&p), 6);
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
    }
}
#[test]
fn native_no_drop_intent_before_and_after_return_recovers_unknown_not_published() {
    for mode in ["admission-intent", "admission-unreturned"] {
        let (_t, p, r) = fixture();
        let mut child = process(
            &std::env::current_exe().unwrap(),
            &p,
            mode,
            "fleet::host::receiver::tests::receiving_process_child",
        );
        assert_eq!(
            child.wait().code(),
            Some(if mode == "admission-intent" { 51 } else { 52 }),
            "{}",
            child.logs()
        );
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let key = JobKey::from_job(Offer::new(&p, b"abc", 0).g.job());
        let before = h.get(&key).unwrap().unwrap();
        assert_eq!(schema(&p), 6);
        let recovered = h.recover_stopped_owner(before.owner()).unwrap();
        let s = &recovered[0];
        assert_eq!(s.phase(), Phase::CommitUnknown);
        assert_eq!(s.intent(), before.intent());
        assert_eq!(s.intent_binding(), before.intent_binding());
        assert!(s.receipt().is_none());
        assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"abc");
        assert!(!Path::new(&s.job().destination_path).exists());
        assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
        assert!(h.resume().is_err());
    }
}
#[test]
fn native_eight_mib_local_data_seal_and_final_hash_intent_readback() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let bytes = vec![37u8; 8 * 1024 * 1024];
    let started = Instant::now();
    let recv = sealed(&h, &p, &bytes);
    let s = recv.reserve_commit().unwrap();
    let elapsed = started.elapsed();
    assert_eq!(schema(&p), 6);
    assert_eq!(s.phase(), Phase::Committing);
    assert_eq!(s.received(), bytes.len() as u64);
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), bytes);
    assert_eq!(
        h.inventory().unwrap().recorded_usage(),
        (bytes.len() as u64, 1)
    );
    assert!(!Path::new(&s.job().destination_path).exists());
    assert!(s.receipt().is_none());
    println!(
        "LOCAL_INTENT8MIB: bytes={} elapsed_ms={} SHA/data-readback matched, original fixture lease unchanged; no publish/network",
        bytes.len(),
        elapsed.as_millis()
    );
}

#[test]
fn native_db_to_gate_inventory_competition_does_not_deadlock_hash() {
    let (_t, p, _r) = fixture();
    let mut child = process(
        &std::env::current_exe().unwrap(),
        &p,
        "admission-inversion",
        "fleet::host::receiver::tests::receiving_process_child",
    );
    assert!(child.wait().success(), "{}", child.logs());
    assert!(child.logs().contains("ACTUAL_INVERSION_AVOIDED"));
}
#[test]
fn native_external_sql_writer_fails_without_five_second_wait_and_restores_timeout() {
    let (_t, p, _r) = fixture();
    let mut child = process(
        &std::env::current_exe().unwrap(),
        &p,
        "admission-sql-busy",
        "fleet::host::receiver::tests::receiving_process_child",
    );
    assert!(child.wait().success(), "{}", child.logs());
    assert!(child.logs().contains("ACTUAL_SQL_BUSY_NOWAIT_RESTORED"));
}
// Runs ONLY via the existing bounded parent/child controller. All expected
// contention must terminate; parent kills stuck child instead of hanging suite.
pub(super) fn process_case(h: &FleetHost<'_>, p: &Path, mode: &str) {
    if mode == "admission-inversion" {
        let recv = sealed(h, p, &vec![42; 131073]);
        let (start_tx, start_rx) = mpsc::channel();
        let (held_tx, held_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                start_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let mut db = h.database.lock().unwrap();
                held_tx.send(()).unwrap();
                let report = db
                    .as_mut()
                    .unwrap()
                    .inventory(
                        &h.attachment.runtime.policy,
                        &h.attachment.runtime.policy.roots,
                        h.gate.clone(),
                        InventoryLimits::default(),
                    )
                    .unwrap();
                done_tx.send(report.recorded_usage()).unwrap();
            });
            let mut sent = false;
            let error = recv
                .reserve_between(
                    |offset, _| {
                        assert_eq!(offset, 65536);
                        if !sent {
                            start_tx.send(()).unwrap();
                            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                            sent = true;
                        }
                        Ok(())
                    },
                    |_| Ok(()),
                )
                .unwrap_err();
            assert!(error.to_string().contains("commit database busy"));
            assert_eq!(
                done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                (131073, 1)
            );
            worker.join().unwrap();
        });
        assert_eq!(schema(p), 5);
        println!(
            "ACTUAL_INVERSION_AVOIDED: DB held before gate inventory; hash failed fast retaining v5/debt"
        );
        return;
    }
    let recv = sealed(h, p, b"abc");
    if mode == "admission-sql-busy" {
        let c = rusqlite::Connection::open(p).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let error = recv.reserve_commit().unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(timeout(h), 5000);
        c.execute_batch("ROLLBACK").unwrap();
        assert!(
            error.to_string().contains("database is locked"),
            "wrong failure: {error:#}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "SQL busy waited: {elapsed:?}"
        );
        assert_eq!(schema(p), 5);
        assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
        println!(
            "ACTUAL_SQL_BUSY_NOWAIT_RESTORED: {elapsed:?}, old timeout5000 restored, v5/debt retained"
        );
        return;
    }
    #[cfg(windows)]
    if mode == "admission-publish-marker" || mode == "admission-publish-renamed" {
        let c = recv.prepare_commit().unwrap();
        let _r = c
            .rename_between(
                |_| {
                    if mode == "admission-publish-marker" {
                        std::process::exit(54)
                    }
                    Ok(())
                },
                |_| std::process::exit(55),
                |_, _| Ok(()),
            )
            .unwrap();
        unreachable!();
    }
    if mode == "admission-candidate" {
        let mut c = recv.prepare_commit().unwrap();
        assert_eq!(c.observe().unwrap().bytes_read(), 3);
        std::process::exit(53);
    }
    if mode == "admission-unreturned" {
        let _ = recv.reserve_between(|_, _| Ok(()), |_| std::process::exit(52));
        unreachable!();
    }
    assert_eq!(mode, "admission-intent");
    let s = recv.reserve_commit().unwrap();
    assert_eq!(s.phase(), Phase::Committing);
    std::process::exit(51);
}
#[test]
#[ignore = "actual archived0cd6 schema5 reader required"]
fn actual0cd6_refuses_schema6_before_any_row_or_stage_effect() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_INTENT_LEGACY_TEST").expect("explicit actual0cd6 required"),
    );
    let mut f = File::open(&exe).unwrap();
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
        "0cd6aba8e150d85f8ed23d0964b8ceddd3cb3aa6c33289adcf8d333d3f562447"
    );
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let s = sealed(&h, &p, b"abc").reserve_commit().unwrap();
    let raw = serde_json::to_string(&s).unwrap();
    let path = s.stage().unwrap().path().to_owned();
    let key = JobKey::from_job(s.job());
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
    assert_eq!(schema(&p), 6);
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    assert_eq!(
        serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
        raw
    );
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    println!("ACTUAL0CD6_SCHEMA6_REFUSED: fullSHA checked, row/stage unchanged; fixture reclaimed");
}
