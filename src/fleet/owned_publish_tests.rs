use super::*;
#[path = "target_receipt_tests.rs"]
mod target_receipt_tests;
#[test]
fn size_change_after_marker_or_rename_faults_without_debt_release() {
    for after in [false, true] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let c = candidate(&h, &p, b"abc");
        let key = JobKey::from_job(c.snapshot().job());
        let stage = c.snapshot().stage().unwrap().path().to_owned();
        let dest = destination(&c);
        let e = c
            .rename_between(
                |_| {
                    if !after {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&stage)?
                            .set_len(2)?;
                    }
                    Ok(())
                },
                |_| {
                    if after {
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(&dest)?
                            .set_len(2)?;
                    }
                    Ok(())
                },
                |_, _| Ok(()),
            )
            .err()
            .unwrap();
        assert!(format!("{e:#}").contains("final size changed"), "{e:#}");
        let s = h.get(&key).unwrap().unwrap();
        retain(&s, &h, 3);
        assert_eq!(schema(&p), 7);
        assert_eq!(dest.exists(), after);
        assert_eq!(
            std::fs::metadata(if after { &dest } else { &stage })
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn version7_wrong_phase_is_valid_json_but_semantically_rejected() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let moved = c.attempt_local_publication().unwrap();
    let s = moved.snapshot().clone();
    drop(moved);
    let key = JobKey::from_job(s.job());
    let raw = serde_json::to_string(&s).unwrap();
    let mut value = serde_json::to_value(&s).unwrap();
    assert_eq!(
        value["phase"],
        serde_json::to_value(Phase::CommitUnknown).unwrap()
    );
    value["phase"] = serde_json::to_value(Phase::Committing).unwrap();
    assert!(
        serde_json::from_value::<Snapshot>(value.clone()).is_ok(),
        "must reject semantic state, NOT JSON spelling"
    );
    h.database
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .connection
        .execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1",
            [serde_json::to_string(&value).unwrap()],
        )
        .unwrap();
    let e = h.get(&key).unwrap_err();
    assert!(
        format!("{e:#}").contains("invalid journal version/owner/revision"),
        "{e:#}"
    );
    h.database
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .connection
        .execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [raw])
        .unwrap();
    assert!(h.get(&key).unwrap().unwrap().is_publication_attempt());
}
#[test]
fn stage_verifier_shares_delete_but_identity_and_fence_opens_do_not() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let path = c.snapshot().stage().unwrap().path().to_owned();
    let e = crate::fleet::identity::open_private(&path, false).unwrap_err();
    assert!(format!("{e:#}").contains("os error 32"));
    let stage = crate::fleet::identity::open_stage(&path).unwrap();
    assert_eq!(
        c.snapshot()
            .stage()
            .unwrap()
            .allocation()
            .unwrap()
            .file_id(),
        Some(file_id(&stage).unwrap().as_str())
    );
    assert_eq!(
        std::fs::remove_file(&path).unwrap_err().raw_os_error(),
        Some(32)
    );
    drop(stage);
    drop(c);
    assert!(crate::fleet::identity::open_private(&path, false).is_ok());
}
#[test]
fn native_writer_after_v7_marker_never_reinitializes_journal() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = destination(&c);
    let db = rusqlite::Connection::open(&p).unwrap();
    let lock_wait = std::cell::Cell::new(Duration::ZERO);
    let start = Instant::now();
    let moved = c
        .rename_between(
            |_| {
                let t = Instant::now();
                db.execute_batch("BEGIN IMMEDIATE")?;
                lock_wait.set(t.elapsed());
                Ok(())
            },
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    let elapsed = start.elapsed();
    // The fixture's own BEGIN IMMEDIATE can block on SQLite's 5 s busy timeout.
    // Only our no-wait behaviour is gated; its wait is reported separately.
    let own = elapsed.saturating_sub(lock_wait.get());
    db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
    drop(moved);
    assert_eq!(timeout(&h), 5000);
    assert_eq!(schema(&p), 7);
    retain(&h.get(&key).unwrap().unwrap(), &h, 3);
    println!(
        "NATIVE_POST_MARKER_SQL: own_ms={} lock_ms={} schema7/renamed/noReceipt timeout5000",
        own.as_millis(),
        lock_wait.get().as_millis()
    );
    assert!(
        own < Duration::from_secs(2),
        "{own:?} (elapsed {elapsed:?}, fixture lock {lock_wait:?})"
    );
}
#[test]
fn native_attempt_sql_writer_fails_fast_and_restores_original_timeout() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let dest = destination(&c);
    let db = rusqlite::Connection::open(&p).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    let e = c.attempt_local_publication().err().unwrap();
    let elapsed = started.elapsed();
    db.execute_batch("ROLLBACK").unwrap();
    assert!(format!("{e:#}").contains("database is locked"), "{e:#}");
    assert_eq!(timeout(&h), 5000);
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    println!(
        "NATIVE_SQL_BUSY_NOWAIT: elapsed_ms={} restored_timeout=5000 schema6/noRename",
        elapsed.as_millis()
    );
    assert_eq!(schema(&p), 6);
    assert!(!dest.exists());
}
#[test]
fn paused_host_allows_accepted_native_attempt_but_no_new_admissions() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    h.pause().unwrap();
    let moved = c.attempt_local_publication().unwrap();
    assert_eq!(h.status().unwrap().mode, HostMode::Paused);
    let (_, records) = Offer::tagged(&p, b"abc", 0, 1).pair();
    assert!(h.admit_receiver(records).is_err());
    drop(moved);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
#[ignore = "explicit actual f5d3 binary hash/provenance gate"]
fn actual_f5d3_refuses_schema7_before_native_publication_or_row_effect() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_PUBLISH_LEGACY_TEST").expect("actual f5d3 explicit only"),
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
        "f5d3d18fe1c803ac615926047d6f012bfca3d859189e3d0d471c77418b56c80c"
    );
    for renamed in [false, true] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let c = candidate(&h, &p, b"abc");
        let key = JobKey::from_job(c.snapshot().job());
        if renamed {
            drop(c.attempt_local_publication().unwrap());
        } else {
            assert!(
                c.rename_between(
                    |_| anyhow::bail!("stop after durable marker"),
                    |_| panic!("never rename"),
                    |_, _| Ok(())
                )
                .is_err()
            );
        }
        let s = h.get(&key).unwrap().unwrap();
        let raw = serde_json::to_string(&s).unwrap();
        let data_path = if renamed {
            PathBuf::from(&s.job().destination_path)
        } else {
            s.stage().unwrap().path().to_owned()
        };
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
        assert_eq!(schema(&p), 7);
        assert_eq!(std::fs::read(&data_path).unwrap(), b"abc");
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
            raw
        );
        let conn = rusqlite::Connection::open(&p).unwrap();
        conn.execute("UPDATE ferroc_fleet_meta SET version=6", [])
            .unwrap();
        let e = h.get(&key).unwrap_err();
        assert!(
            format!("{e:#}").contains("row exceeds schema gate"),
            "{e:#}"
        );
        conn.execute("UPDATE ferroc_fleet_meta SET version=7", [])
            .unwrap();
        assert_eq!(
            serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
            raw
        );
        assert_eq!(std::fs::read(&data_path).unwrap(), b"abc");
        assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    }
    println!(
        "ACTUALF5D3_SCHEMA7_REFUSED: exact old SHA checked before/after rename; row+bytes unchanged; current reader rejects metadata6/row7; restored7; no resume/receipt"
    );
}

fn destination(c: &CommitCandidate<'_, '_>) -> PathBuf {
    PathBuf::from(&c.snapshot().job().destination_path)
}
fn retain(s: &Snapshot, h: &FleetHost<'_>, bytes: u64) {
    assert_eq!(s.phase(), Phase::CommitUnknown);
    assert!(s.is_publication_attempt() && s.receipt().is_none());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (bytes, 1));
}
#[test]
fn same_handle_native_publication_retains_live_lease_and_debt_not_receipt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let before = c.snapshot().clone();
    let dest = destination(&c);
    let mut moved = c.attempt_local_publication().unwrap();
    assert_eq!(schema(&p), 7);
    assert_eq!(moved.snapshot().revision(), before.revision() + 1);
    assert_eq!(moved.snapshot().stage(), before.stage());
    assert_eq!(moved.snapshot().intent(), before.intent());
    assert_eq!(moved.observe().unwrap().bytes_read(), 3);
    let id = file_id(&crate::fleet::identity::open_stage(&dest).unwrap()).unwrap();
    assert_eq!(
        before.stage().unwrap().allocation().unwrap().file_id(),
        Some(id.as_str())
    );
    assert_eq!(h.status().unwrap().in_flight, 1);
    assert!(!before.stage().unwrap().path().exists());
    assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
    let s = moved.snapshot().clone();
    drop(moved);
    retain(&s, &h, 3);
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert_eq!(std::fs::read(dest).unwrap(), b"abc");
}
#[test]
fn preexisting_target_denies_without_marker_or_overwrite() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let s = c.snapshot().clone();
    let dest = destination(&c);
    std::fs::write(&dest, b"keep").unwrap();
    assert!(c.attempt_local_publication().is_err());
    assert_eq!(schema(&p), 6);
    assert_eq!(std::fs::read(dest).unwrap(), b"keep");
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"abc");
}
#[test]
fn target_appears_after_marker_never_overwrites_or_releases_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let path = c.snapshot().stage().unwrap().path().to_owned();
    let dest = destination(&c);
    assert!(
        c.rename_between(
            |_| {
                std::fs::write(&dest, b"keep")?;
                Ok(())
            },
            |_| panic!("must not rename"),
            |_, _| Ok(())
        )
        .is_err()
    );
    assert_eq!(schema(&p), 7);
    let s = h.get(&key).unwrap().unwrap();
    retain(&s, &h, 3);
    assert_eq!(std::fs::read(dest).unwrap(), b"keep");
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
}
#[test]
fn owned_stage_name_replaced_before_attempt_never_publishes_substitute() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let s = c.snapshot().clone();
    let original = s.stage().unwrap().path().to_owned();
    let held = p.with_file_name("moved-owned-stage");
    c.test_move_owned(&held).unwrap();
    let mut substitute = crate::fleet::identity::new_private(&original).unwrap();
    substitute.write_all(b"xyz").unwrap();
    drop(substitute);
    let dest = destination(&c);
    let e = c.attempt_local_publication().err().unwrap();
    assert!(e.to_string().contains("file object/size changed"), "{e:#}");
    assert_eq!(schema(&p), 6);
    assert!(!dest.exists());
    assert_eq!(std::fs::read(original).unwrap(), b"xyz");
    assert_eq!(std::fs::read(held).unwrap(), b"abc");
}
#[tokio::test]
async fn same_size_runtime_mutation_rehash_denies_before_marker() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let path = c.snapshot().stage().unwrap().path().to_owned();
    let out = r
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(out.is_error, Some(true));
    let dest = destination(&c);
    let e = c.attempt_local_publication().err().unwrap();
    assert!(e.to_string().contains("SHA256 mismatch"));
    assert_eq!(schema(&p), 6);
    assert!(!dest.exists());
    assert_eq!(std::fs::read(path).unwrap(), b"xyz");
}
#[test]
fn cancel_between_final_hash_and_syscall_keeps_v7_unknown_without_rename() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let path = c.snapshot().stage().unwrap().path().to_owned();
    let dest = destination(&c);
    assert!(
        c.rename_between(
            |c| {
                h.cancel(&key, c.snapshot().revision())?;
                Ok(())
            },
            |_| panic!("must not rename"),
            |_, _| Ok(())
        )
        .is_err()
    );
    let s = h.get(&key).unwrap().unwrap();
    retain(&s, &h, 3);
    assert_eq!(schema(&p), 7);
    assert!(!dest.exists());
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
}
#[test]
fn expiry_after_sql_marker_keeps_stage_without_rename() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = destination(&c);
    assert!(
        c.rename_between(
            |c| {
                c.test_expire();
                Ok(())
            },
            |_| panic!("must not rename"),
            |_, _| Ok(())
        )
        .is_err()
    );
    let s = h.get(&key).unwrap().unwrap();
    retain(&s, &h, 3);
    assert!(s.stage().unwrap().path().exists());
    assert!(!dest.exists());
    assert_eq!(schema(&p), 7);
}
#[test]
fn cancel_after_actual_rename_returns_error_but_preserves_target_and_unknown() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = destination(&c);
    assert!(
        c.rename_between(
            |_| Ok(()),
            |c| {
                h.cancel(&key, c.snapshot().revision())?;
                Ok(())
            },
            |_, _| Ok(())
        )
        .is_err()
    );
    let s = h.get(&key).unwrap().unwrap();
    retain(&s, &h, 3);
    assert_eq!(std::fs::read(dest).unwrap(), b"abc");
    assert!(!s.stage().unwrap().path().exists());
}
#[test]
fn expiry_after_actual_rename_never_erases_target_or_mints_ack() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let dest = destination(&c);
    assert!(
        c.rename_between(
            |_| Ok(()),
            |c| {
                c.test_expire();
                Ok(())
            },
            |_, _| Ok(())
        )
        .is_err()
    );
    retain(&h.get(&key).unwrap().unwrap(), &h, 3);
    assert_eq!(std::fs::read(dest).unwrap(), b"abc");
}
#[test]
fn sql_failure_does_not_enter_v7_or_rename() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let dest = destination(&c);
    h.database.lock().unwrap().as_mut().unwrap().connection.execute_batch("CREATE TRIGGER reject_native BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'native-denied'); END;").unwrap();
    let e = c.attempt_local_publication().err().unwrap();
    assert!(e.to_string().contains("native-denied"), "{e:#}");
    assert_eq!(schema(&p), 6);
    assert!(!dest.exists());
}
#[test]
fn unsupported_future_receipt_cannot_clear_v7_stage_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let moved = c.attempt_local_publication().unwrap();
    let s = moved.snapshot().clone();
    let key = JobKey::from_job(s.job());
    drop(moved);
    let mut db = h.database.lock().unwrap();
    let mut j = db.as_mut().unwrap().journal().unwrap();
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
    drop(db);
    retain(&s, &h, 3);
}
#[test]
fn renamed_owner_retains_close_drain_and_original_handle_until_drop() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let dest = destination(&c);
    let mut moved = c.attempt_local_publication().unwrap();
    assert_eq!(
        std::fs::remove_file(&dest).unwrap_err().raw_os_error(),
        Some(32)
    );
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let t = scope.spawn(|| tx.send(h.close()).unwrap());
        wait_closing(&h);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(moved.observe().unwrap().bytes_read(), 3);
        drop(moved);
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        t.join().unwrap();
    });
    let to = p.with_file_name("moved-after-drain");
    std::fs::rename(&dest, &to).unwrap();
    std::fs::write(&dest, b"keep-substitute").unwrap();
    drop(h);
    assert_eq!(std::fs::read(dest).unwrap(), b"keep-substitute");
    assert_eq!(std::fs::read(to).unwrap(), b"abc");
}
#[test]
fn renamed_epoch_renewal_keeps_historical_binding_and_revocation_is_final() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let mut moved = c.attempt_local_publication().unwrap();
    let raw = serde_json::to_string(moved.snapshot()).unwrap();
    let offer = Offer::new(&p, b"abc", 1);
    std::thread::sleep(Duration::from_millis(3));
    moved
        .renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
        .unwrap();
    assert_eq!(moved.observe().unwrap().bytes_read(), 3);
    assert_eq!(serde_json::to_string(moved.snapshot()).unwrap(), raw);
    moved.revoke();
    assert!(moved.observe().is_err());
    let offer = Offer::new(&p, b"abc", 2);
    assert!(
        moved
            .renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
            .is_err()
    );
    drop(moved);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn actual_no_drop_marker_and_rename_crashes_keep_one_debt_no_resume() {
    for mode in ["admission-publish-marker", "admission-publish-renamed"] {
        let (_t, p, r) = fixture();
        let mut child = process(
            &std::env::current_exe().unwrap(),
            &p,
            mode,
            "fleet::host::receiver::tests::receiving_process_child",
        );
        assert_eq!(
            child.wait().code(),
            Some(if mode.ends_with("marker") { 54 } else { 55 }),
            "{}",
            child.logs()
        );
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let key = JobKey::from_job(Offer::new(&p, b"abc", 0).g.job());
        let before = h.get(&key).unwrap().unwrap();
        assert_eq!(schema(&p), 7);
        let rows = h.recover_stopped_owner(before.owner()).unwrap();
        let s = &rows[0];
        retain(s, &h, 3);
        assert_eq!(s.intent(), before.intent());
        let original = s.stage().unwrap().path();
        let target = Path::new(&s.job().destination_path);
        assert_eq!(original.exists(), mode.ends_with("marker"));
        assert_eq!(target.exists(), mode.ends_with("renamed"));
        assert_eq!(
            std::fs::read(if original.exists() { original } else { target }).unwrap(),
            b"abc"
        );
        assert!(h.resume().is_err());
    }
}
#[test]
fn empty_native_rename_keeps_slot_no_receipt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"");
    let mut moved = c.attempt_local_publication().unwrap();
    assert_eq!(moved.observe().unwrap().bytes_read(), 0);
    let s = moved.snapshot().clone();
    drop(moved);
    retain(&s, &h, 0);
}
#[test]
fn final_hash_cancel_at64k_does_not_mark_or_rename() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, &vec![9; 131073]);
    let key = JobKey::from_job(c.snapshot().job());
    let dest = destination(&c);
    let mut calls = 0;
    assert!(
        c.rename_between(
            |_| panic!("must not mark"),
            |_| panic!("must not rename"),
            |offset, c| {
                assert_eq!(offset, 65536);
                h.cancel(&key, c.snapshot().revision())?;
                calls += 1;
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(calls, 1);
    assert_eq!(schema(&p), 6);
    assert!(!dest.exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
}
#[test]
fn schema7_never_downgrades_for_empty_new_allocators_or_receivers() {
    for mode in 0..3 {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        rusqlite::Connection::open(&p)
            .unwrap()
            .execute("UPDATE ferroc_fleet_meta SET version=7", [])
            .unwrap();
        h.resume().unwrap();
        if mode == 0 {
            h.admit(Offer::new(&p, b"", 0).g.job().clone(), 100)
                .unwrap();
        } else if mode == 1 {
            let (_, records) = Offer::new(&p, b"", 0).pair();
            drop(h.admit_receiver(records).unwrap());
        } else {
            let c = candidate(&h, &p, b"");
            drop(c);
        }
        assert_eq!(schema(&p), 7);
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
    }
}
#[test]
fn native_eight_mib_end_to_local_rename_observation_not_network() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let data = vec![71; 8 * 1024 * 1024];
    let started = Instant::now();
    let c = candidate(&h, &p, &data);
    let dest = destination(&c);
    let mut moved = c.attempt_local_publication().unwrap();
    assert_eq!(moved.observe().unwrap().bytes_read(), data.len() as u64);
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    let s = moved.snapshot().clone();
    drop(moved);
    retain(&s, &h, 8388608);
    println!(
        "LOCAL_SAME_HANDLE_RENAME8MIB: bytes=8388608 elapsed_ms={} DATA+v6+v7+nativeRename+observe/readback originalLease; NO receipt/network",
        started.elapsed().as_millis()
    );
}
