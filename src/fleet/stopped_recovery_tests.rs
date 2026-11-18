//! Single-row explicit recovery admission tests. Not stock restart evidence.
use super::*;
#[test]
fn selected_takeover_sql_refusal_rolls_back_owner_revision_and_debt() {
    let f = stopped(b"abcdefgh", 3);
    let h = selected(&f);
    let old = h.get(&f.key).unwrap().unwrap();
    h.resume_retained_recovery().unwrap();
    let before = bytes(&h, &f.key);
    {
        let mut guard = h.database.lock().unwrap();
        let db = guard.as_mut().unwrap();
        db.connection.execute_batch("CREATE TEMP TRIGGER reject_selected_recovery BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'forced recovery failure'); END;").unwrap();
    }
    assert!(
        h.recover_retained_job(&f.key, old.owner(), old.revision())
            .is_err()
    );
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn selected_takeover_does_not_recover_another_job_of_same_stopped_owner() {
    let (_temp, path, runtime) = fixture();
    let h = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (source, mut a) = open(&h, &path, b"abc");
    a.enable_retained_checkpoints().unwrap();
    a.capture_retained_checkpoint().unwrap();
    let first = a.snapshot().clone();
    drop(a);
    drop(source);
    // A second pending metadata job of the SAME owner, without bypassing the
    // normal unresolved-stage prohibition on another allocation.
    let mut other = first.job().clone();
    other.transfer_id = Uuid::new_v4();
    other.file_id = Uuid::new_v4();
    other.idempotency_key = "other-pending-old-owner".into();
    let second = {
        let mut guard = h.database.lock().unwrap();
        guard
            .as_mut()
            .unwrap()
            .journal()
            .unwrap()
            .admit(other, 200)
            .unwrap()
            .1
    };
    let proof = h.stop_creators().unwrap();
    drop(proof);
    drop(h);
    let h = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.resume_retained_recovery().unwrap();
    let key = JobKey::from_job(first.job());
    let untouched_key = JobKey::from_job(second.job());
    let before = bytes(&h, &untouched_key);
    h.recover_retained_job(&key, first.owner(), first.revision())
        .unwrap();
    assert_eq!(bytes(&h, &untouched_key), before);
    assert_eq!(
        h.get(&untouched_key).unwrap().unwrap().owner(),
        first.owner()
    );
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}
fn selected(f: &Recovery) -> FleetHost<'_> {
    f.runtime
        .open_fleet_host(&f.path, InventoryLimits::default())
        .unwrap()
}
#[test]
fn selection_requires_recovery_only_and_exact_owner_revision() {
    let f = stopped(b"abcdefgh", 3);
    let h = selected(&f);
    let old = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    assert!(
        h.recover_retained_job(&f.key, old.owner(), old.revision())
            .is_err()
    );
    h.resume_retained_recovery().unwrap();
    for (who, rev) in [
        (Uuid::nil(), old.revision()),
        (Uuid::new_v4(), old.revision()),
        (old.owner(), old.revision() + 1),
    ] {
        assert!(h.recover_retained_job(&f.key, who, rev).is_err());
        assert_eq!(bytes(&h, &f.key), before);
    }
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn selected_takeover_preserves_checkpoint_stage_and_full_debt_and_refuses_replay() {
    let f = stopped(b"abcdefgh", 3);
    let h = selected(&f);
    let old = h.get(&f.key).unwrap().unwrap();
    h.resume_retained_recovery().unwrap();
    let new = h
        .recover_retained_job(&f.key, old.owner(), old.revision())
        .unwrap();
    assert_ne!(new.owner(), old.owner());
    assert_eq!(new.phase(), Phase::Interrupted);
    assert_eq!(new.revision(), old.revision() + 1);
    assert_eq!(new.stage(), old.stage());
    assert_eq!(new.retained_stage(), old.retained_stage());
    assert_eq!(new.received(), old.received());
    assert_eq!(schema(&f.path), 12);
    assert_eq!(
        h.inspect_retained_checkpoint(&f.key, 8)
            .unwrap()
            .checkpoint(),
        &f.cp
    );
    assert!(
        h.recover_retained_job(&f.key, old.owner(), old.revision())
            .is_err()
    );
    assert!(h.resume().is_err());
    let (_, ordinary) = Offer::tagged(&f.path, b"other", 0, 9).pair();
    assert!(h.admit_receiver(ordinary).is_err());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn selected_takeover_does_not_restore_tail_or_bypass_dual_proof_migration() {
    let f = stopped(b"abcdefgh", 3);
    let h = selected(&f);
    let old = h.get(&f.key).unwrap().unwrap();
    h.resume_retained_recovery().unwrap();
    let row = h
        .recover_retained_job(&f.key, old.owner(), old.revision())
        .unwrap();
    assert_eq!(row.received(), 5);
    let (source, target) = owner(&f, &f.cp, false);
    let mut source = source.unwrap();
    let new_key = JobKey::from_job(target.grant().job());
    let mut recv = h
        .admit_retained_receiver(&f.key, row.revision(), target, 8)
        .unwrap();
    assert_eq!(recv.resumed_prefix(), Some(3));
    assert_eq!(recv.snapshot().received(), 3);
    recv.write_record(&source.seal_data(3, b"defgh").unwrap())
        .unwrap();
    assert_eq!(std::fs::read(&f.stage).unwrap(), b"abcdefgh");
    drop(recv);
    assert_eq!(schema(&f.path), 13);
    assert!(h.get(&f.key).unwrap().unwrap().is_migrated_origin());
    assert_eq!(h.get(&new_key).unwrap().unwrap().received(), 8);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn selected_takeover_rechecks_prefix_and_keeps_metadata_debt_on_refusal() {
    let f = stopped(b"abcdefgh", 3);
    let h = selected(&f);
    let old = h.get(&f.key).unwrap().unwrap();
    h.resume_retained_recovery().unwrap();
    let row = h
        .recover_retained_job(&f.key, old.owner(), old.revision())
        .unwrap();
    std::fs::write(&f.stage, b"BADde").unwrap();
    assert!(h.inspect_retained_checkpoint(&f.key, 8).is_err());
    let (_, target) = owner(&f, &f.cp, false);
    assert!(
        h.admit_retained_receiver(&f.key, row.revision(), target, 8)
            .is_err()
    );
    assert_eq!(h.get(&f.key).unwrap().unwrap().phase(), Phase::Interrupted);
    assert_eq!(schema(&f.path), 12);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn selected_takeover_is_closed_after_pause_and_close() {
    let f = stopped(b"abcdefgh", 3);
    let h = selected(&f);
    let old = h.get(&f.key).unwrap().unwrap();
    h.resume_retained_recovery().unwrap();
    h.pause().unwrap();
    assert!(
        h.recover_retained_job(&f.key, old.owner(), old.revision())
            .is_err()
    );
    h.close().unwrap();
    assert!(h.resume_retained_recovery().is_err());
}
