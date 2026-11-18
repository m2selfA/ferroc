use super::*;
#[path = "checkpoint_extra_tests.rs"]
mod extra;
use crate::fleet::fence::OwnerFence;
use std::sync::Arc;

#[test]
fn explicit_pre_data_mode_persists_partial_prefix_and_survives_owner_stop_read_only() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdefgh");
    let owner = recv.snapshot().owner();
    let key = JobKey::from_job(recv.snapshot().job());
    recv.enable_retained_checkpoints().unwrap();
    assert_eq!(schema(&p), 12);
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let cp = recv.capture_retained_checkpoint().unwrap();
    assert_eq!(cp.bytes(), 3);
    assert_eq!(cp.sha256(), <[u8; 32]>::from(Sha256::digest(b"abc")));
    recv.write_record(&source.seal_data(3, b"de").unwrap())
        .unwrap();
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    drop(recv);
    h.close().unwrap();
    let fence = OwnerFence::acquire(&p).unwrap();
    let mut db = fence.open_connection().unwrap();
    assert!(
        db.inspect_retained_checkpoint(&key, &r.policy, Arc::default(), 8)
            .is_err()
    );
    db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    let before = db.journal().unwrap().get(&key).unwrap().unwrap();
    db.connection
        .busy_timeout(Duration::from_millis(1357))
        .unwrap();
    let writer = rusqlite::Connection::open(&p).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let observed = db
        .inspect_retained_checkpoint(&key, &r.policy, Arc::default(), 8)
        .unwrap();
    assert_eq!(observed.checkpoint(), &cp);
    assert_eq!(observed.retained_length(), 5);
    writer.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        db.connection
            .query_row("PRAGMA busy_timeout", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1357
    );
    let after = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert_eq!(before.revision(), after.revision());
    assert_eq!(schema(&p), 12);
    assert!(after.stage().is_some() && after.receipt().is_none());
}
#[test]
fn default_writer_stays_schema4_and_late_opt_in_is_refused() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"a").unwrap())
        .unwrap();
    assert_eq!(schema(&p), 4);
    assert!(recv.enable_retained_checkpoints().is_err());
    assert_eq!(schema(&p), 4);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn sql_failure_after_sync_keeps_prior_checkpoint_and_full_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"a").unwrap())
        .unwrap();
    let cp = recv.capture_retained_checkpoint().unwrap();
    recv.write_record(&source.seal_data(1, b"b").unwrap())
        .unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("CREATE TRIGGER reject_cp BEFORE UPDATE OF body ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'checkpoint test fault');END;").unwrap();
    assert!(recv.capture_retained_checkpoint().is_err());
    assert!(recv.faulted);
    let key = JobKey::from_job(recv.snapshot().job());
    assert_eq!(
        h.get(&key)
            .unwrap()
            .unwrap()
            .retained_stage()
            .unwrap()
            .checkpoint()
            .unwrap(),
        &cp
    );
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn writer_contention_fast_fails_and_restores_timeout_without_checkpoint() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"a").unwrap())
        .unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(recv.capture_retained_checkpoint().is_err());
    c.execute_batch("ROLLBACK").unwrap();
    assert!(
        recv.snapshot()
            .retained_stage()
            .unwrap()
            .checkpoint()
            .is_none()
    );
    let guard = h.database.lock().unwrap();
    let timeout: i64 = guard
        .as_ref()
        .unwrap()
        .connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    assert_eq!(timeout, 5000);
}
#[test]
fn previous_prefix_rewrite_cannot_be_hidden_by_advancing_checkpoint() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdefgh");
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let cp = recv.capture_retained_checkpoint().unwrap();
    recv.write_record(&source.seal_data(3, b"de").unwrap())
        .unwrap();
    recv.file.seek(SeekFrom::Start(0)).unwrap();
    recv.file.write_all(b"z").unwrap();
    assert!(recv.capture_retained_checkpoint().is_err());
    let key = JobKey::from_job(recv.snapshot().job());
    assert_eq!(
        h.get(&key)
            .unwrap()
            .unwrap()
            .retained_stage()
            .unwrap()
            .checkpoint()
            .unwrap(),
        &cp
    );
}
#[test]
fn stopped_owner_same_size_prefix_mutation_is_rejected_without_releasing_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let owner = recv.snapshot().owner();
    let key = JobKey::from_job(recv.snapshot().job());
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"ab").unwrap())
        .unwrap();
    recv.capture_retained_checkpoint().unwrap();
    let stage = recv.snapshot().stage().unwrap().path().to_owned();
    drop(recv);
    h.close().unwrap();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&stage)
        .unwrap();
    f.write_all(b"zz").unwrap();
    drop(f);
    let fence = OwnerFence::acquire(&p).unwrap();
    let mut db = fence.open_connection().unwrap();
    db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    assert!(
        db.inspect_retained_checkpoint(&key, &r.policy, Arc::default(), 3)
            .is_err()
    );
    let s = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert_eq!(s.stage().unwrap().reserved_bytes(), 3);
}
#[test]
fn schema_downgrade_cannot_load_retained_metadata() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, mut recv) = open(&h, &p, b"abc");
    recv.enable_retained_checkpoints().unwrap();
    let key = JobKey::from_job(recv.snapshot().job());
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute("UPDATE ferroc_fleet_meta SET version=11", [])
        .unwrap();
    assert!(h.get(&key).is_err());
    assert!(h.inventory().is_err());
}

#[test]
fn post_sql_expiry_reports_failure_but_retains_committed_checkpoint_and_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"a").unwrap())
        .unwrap();
    let key = JobKey::from_job(recv.snapshot().job());
    assert!(
        recv.checkpoint_after_commit(|this| {
            this.records.test_expire();
            Ok(())
        })
        .is_err()
    );
    assert!(recv.faulted);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(s.retained_stage().unwrap().checkpoint().unwrap().bytes(), 1);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn cancellation_or_expiry_before_capture_never_creates_checkpoint() {
    for expire in [false, true] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let (mut source, mut recv) = open(&h, &p, b"abc");
        recv.enable_retained_checkpoints().unwrap();
        recv.write_record(&source.seal_data(0, b"a").unwrap())
            .unwrap();
        let key = JobKey::from_job(recv.snapshot().job());
        if expire {
            recv.records.test_expire();
        } else {
            h.cancel(&key, recv.snapshot().revision()).unwrap();
        }
        assert!(recv.capture_retained_checkpoint().is_err());
        assert!(
            h.get(&key)
                .unwrap()
                .unwrap()
                .retained_stage()
                .unwrap()
                .checkpoint()
                .is_none()
        );
        assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    }
}
#[test]
fn out_of_order_tail_is_zero_checkpoint_not_coverage_and_later_prefix_advances() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(2, b"c").unwrap())
        .unwrap();
    let cp = recv.capture_retained_checkpoint().unwrap();
    assert_eq!(cp.bytes(), 0);
    recv.write_record(&source.seal_data(0, b"ab").unwrap())
        .unwrap();
    let next = recv.capture_retained_checkpoint().unwrap();
    assert_eq!(next.bytes(), 3);
    assert!(next.revision() > cp.revision());
    assert_eq!(schema(&p), 12);
}
#[test]
fn schema_twelve_survives_seal_intent_and_windows_settlement() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let cp = recv.capture_retained_checkpoint().unwrap();
    let finish = source
        .seal_control(crate::fleet::control::ControlBody::Finish(
            crate::fleet::control::Finish {
                size: 3,
                sha256: Sha256::digest(b"abc").into(),
            },
        ))
        .unwrap();
    let sealed = recv.seal_finish(&finish).unwrap();
    assert_eq!(schema(&p), 12);
    let candidate = sealed.prepare_commit().unwrap();
    assert_eq!(schema(&p), 12);
    assert_eq!(
        candidate.snapshot().retained_stage().unwrap().checkpoint(),
        Some(&cp)
    );
    #[cfg(windows)]
    {
        let renamed = candidate.attempt_local_publication().unwrap();
        assert_eq!(schema(&p), 12);
        let observed = renamed.record_target_observation().unwrap();
        assert_eq!(schema(&p), 12);
        let finished = observed.settle_local().unwrap();
        assert_eq!(schema(&p), 12);
        assert_eq!(finished.snapshot().phase(), Phase::Completed);
        assert_eq!(
            finished.snapshot().retained_stage().unwrap().checkpoint(),
            Some(&cp)
        );
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
    }
}
#[test]
fn stopped_checkpoint_budget_and_stage_replacement_fail_read_only() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let owner = recv.snapshot().owner();
    let key = JobKey::from_job(recv.snapshot().job());
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"ab").unwrap())
        .unwrap();
    recv.capture_retained_checkpoint().unwrap();
    let stage = recv.snapshot().stage().unwrap().path().to_owned();
    drop(recv);
    h.close().unwrap();
    let fence = OwnerFence::acquire(&p).unwrap();
    let mut db = fence.open_connection().unwrap();
    db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    assert!(
        db.inspect_retained_checkpoint(&key, &r.policy, Arc::default(), 1)
            .is_err()
    );
    assert!(
        db.inspect_retained_checkpoint(&key, &r.policy, Arc::default(), 1024 * 1024 * 1024 + 1)
            .is_err()
    );
    std::fs::rename(&stage, stage.with_extension("held-original")).unwrap();
    let mut f = crate::fleet::identity::new_stage_private(&stage).unwrap();
    f.write_all(b"ab").unwrap();
    drop(f);
    assert!(
        db.inspect_retained_checkpoint(&key, &r.policy, Arc::default(), 3)
            .is_err()
    );
    let s = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert_eq!(s.stage().unwrap().reserved_bytes(), 3);
    assert!(s.receipt().is_none());
}
#[cfg(target_os = "linux")]
#[test]
fn anonymous_receiver_never_enables_retained_schema_or_checkpoint() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.resume().unwrap();
    let (_, target) = Offer::new(&p, b"abc", 0).pair();
    let mut recv = h.admit_linux_anonymous_receiver(target).unwrap();
    assert!(recv.enable_retained_checkpoints().is_err());
    assert_eq!(schema(&p), 11);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[cfg(windows)]
#[test]
#[ignore = "explicit actual archived schema11 CLI; FERROC_CHECKPOINT_OLD_READER"]
fn actual_schema11_cli_refuses_twelve_without_changing_stage_or_row() {
    use std::process::Command;
    let exe = PathBuf::from(
        std::env::var_os("FERROC_CHECKPOINT_OLD_READER").expect("explicit old reader required"),
    );
    let old = std::fs::read(&exe).unwrap();
    let image_hash = Sha256::digest(&old);
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"ab").unwrap())
        .unwrap();
    recv.capture_retained_checkpoint().unwrap();
    let before = serde_json::to_value(recv.snapshot()).unwrap();
    let stage = recv.snapshot().stage().unwrap().path().to_owned();
    drop(recv);
    h.close().unwrap();
    let output = Command::new(&exe)
        .arg("--allow-dir")
        .arg(p.parent().unwrap())
        .args(["fleet-inventory", "--db"])
        .arg(&p)
        .arg("--root")
        .arg(p.parent().unwrap())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("schema"), "{stderr}");
    assert_eq!(schema(&p), 12);
    assert_eq!(std::fs::read(&stage).unwrap(), b"ab");
    let f = OwnerFence::acquire(&p).unwrap();
    let mut db = f.open_connection().unwrap();
    assert_eq!(
        serde_json::to_value(db.journal().unwrap().get(&key).unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(Sha256::digest(std::fs::read(exe).unwrap()), image_hash);
    println!(
        "OLD_READER_SCHEMA12_REJECTED image_sha256={image_hash:x} row_stage_and_debt_unchanged"
    );
}
