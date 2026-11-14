use super::*;
use crate::fleet::{
    fence::OwnerFence,
    identity::{make_directory, new_private},
    inventory::InventoryLimits,
    job::{JobSpec, RoutePolicy},
    protocol::device_digest,
};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
fn fixture() -> (tempfile::TempDir, PathBuf, Policy) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let path = root.join("relay.db");
    drop(new_private(&path).unwrap());
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TABLE sentinel(v TEXT);INSERT INTO sentinel VALUES('keep');")
        .unwrap();
    drop(c);
    let p = Policy::new(vec![root], false).unwrap();
    (t, path, p)
}
fn spec(path: &Path, n: u8, bytes: u64) -> JobSpec {
    let root = path.parent().unwrap();
    JobSpec {
        version: 1,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::from_bytes([n; 16]),
        file_id: Uuid::from_bytes([n + 1; 16]),
        source_path: root.join(format!("source{n}")).to_str().unwrap().into(),
        destination_path: root.join(format!("target{n}")).to_str().unwrap().into(),
        bytes_total: bytes,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: format!("reconcile-{n}"),
    }
}
fn reserve(
    db: &mut FencedConnection,
    path: &Path,
    p: &Policy,
    n: u8,
    bytes: u64,
) -> (JobKey, Snapshot) {
    let job = spec(path, n, bytes);
    let k = JobKey::from_job(&job);
    let (_, s) = db.journal().unwrap().admit(job, 200).unwrap();
    let s = db
        .reserve_stage(
            &k,
            s.revision(),
            p,
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    (k, s)
}
fn stopped(path: &Path, p: &Policy) -> (JobKey, Snapshot, FencedConnection) {
    let f = OwnerFence::acquire(path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = reserve(&mut db, path, p, 5, 3);
    let old = f.owner();
    drop(db);
    drop(f);
    let f = OwnerFence::acquire(path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s2 = db
        .journal()
        .unwrap()
        .recover_stopped_owner(old)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(s.stage().unwrap(), s2.stage().unwrap());
    (k, s2, db)
}
fn inspect(db: &mut FencedConnection, k: &JobKey, p: &Policy) -> Reconciliation {
    db.inspect_allocation(k, p, Arc::default()).unwrap()
}
fn approval(report: &Reconciliation) -> AbsenceApproval {
    AbsenceApproval::approve_expected_fingerprint(report.fingerprint())
}
#[test]
fn origin_fenced_but_not_recovered_is_not_eligible() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, _s) = reserve(&mut db, &path, &p, 5, 3);
    drop(db);
    drop(f);
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let report = inspect(&mut db, &k, &p);
    assert!(report.origin_stopped());
    assert!(!report.owner_recovered());
    let s = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_err()
    );
}
#[test]
fn present_bound_and_unbound_objects_are_never_adopted_or_deleted() {
    for bound in [false, true] {
        let (_t, path, p) = fixture();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let (k, s) = reserve(&mut db, &path, &p, 5, 3);
        let s = if bound {
            db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
                .unwrap()
        } else {
            s
        };
        let candidate = s.stage().unwrap().path().to_owned();
        if !bound {
            drop(new_private(&candidate).unwrap());
        }
        fs::write(&candidate, b"abc").unwrap();
        let old = f.owner();
        drop(db);
        drop(f);
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let s = db
            .journal()
            .unwrap()
            .recover_stopped_owner(old)
            .unwrap()
            .pop()
            .unwrap();
        let before = serde_json::to_string(&s).unwrap();
        let report = inspect(&mut db, &k, &p);
        assert_eq!(
            report.state(),
            if bound {
                ObjectState::PresentBoundIdsMatch
            } else {
                ObjectState::PresentUnbound
            }
        );
        assert!(
            db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
                .is_err()
        );
        assert_eq!(fs::read(&candidate).unwrap(), b"abc");
        assert_eq!(
            serde_json::to_string(&db.journal().unwrap().get(&k).unwrap().unwrap()).unwrap(),
            before
        );
        let alias = candidate.with_extension("hardlink");
        fs::hard_link(&candidate, &alias).unwrap();
        assert_eq!(
            inspect(&mut db, &k, &p).state(),
            ObjectState::UnsafeOrUnreadable
        );
        assert_eq!(fs::read(&alias).unwrap(), b"abc");
    }
}
#[test]
fn file_appearing_after_inspection_invalidates_approval_without_metadata_change() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    let candidate = s.stage().unwrap().path();
    drop(new_private(candidate).unwrap());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_err()
    );
    assert!(candidate.exists());
    assert_eq!(
        db.journal().unwrap().get(&k).unwrap().unwrap().revision(),
        s.revision()
    );
}
#[test]
fn revision_change_requires_fresh_approval_even_when_path_remains_absent() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    let canceled = db.journal().unwrap().cancel(&k, s.revision()).unwrap();
    assert!(
        db.release_absent_allocation(
            &k,
            canceled.revision(),
            &p,
            approval(&report),
            Arc::default()
        )
        .is_err()
    );
    let fresh = inspect(&mut db, &k, &p);
    assert!(
        db.release_absent_allocation(
            &k,
            canceled.revision(),
            &p,
            approval(&fresh),
            Arc::default()
        )
        .is_ok()
    );
}
#[test]
fn wrong_approved_fingerprint_never_retires_obligation() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    assert!(
        db.release_absent_allocation(
            &k,
            s.revision(),
            &p,
            AbsenceApproval::approve_expected_fingerprint([0; 32]),
            Arc::default()
        )
        .is_err()
    );
    assert!(
        db.journal()
            .unwrap()
            .get(&k)
            .unwrap()
            .unwrap()
            .stage()
            .is_some()
    );
}
#[test]
fn reacquiring_fence_invalidates_previous_owner_approval() {
    let (_t, path, p) = fixture();
    let (k, _s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    let old = db.journal().unwrap().get(&k).unwrap().unwrap().owner();
    drop(db);
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = db
        .journal()
        .unwrap()
        .recover_stopped_owner(old)
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_err()
    );
    let fresh = inspect(&mut db, &k, &p);
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&fresh), Arc::default())
            .is_ok()
    );
}
#[test]
fn sql_abort_retains_debt_and_no_release_record_then_explicit_reinspection_succeeds() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TRIGGER reject_release BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'release fault');END;").unwrap();
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_err()
    );
    let observed = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert_eq!(observed.stage(), s.stage());
    assert!(observed.absence_release().is_none());
    assert_eq!(observed.revision(), s.revision());
    c.execute_batch("DROP TRIGGER reject_release;").unwrap();
    let fresh = inspect(&mut db, &k, &p);
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&fresh), Arc::default())
            .is_ok()
    );
}
#[test]
fn durable_release_survives_owner_recovery_and_idempotent_job_replay() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    let released = db
        .release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
        .unwrap();
    let id = released.absence_release().unwrap().id();
    let actor = released.absence_release().unwrap().by();
    let job = released.job().clone();
    let old = released.owner();
    assert!(
        db.release_absent_allocation(
            &k,
            released.revision(),
            &p,
            approval(&report),
            Arc::default()
        )
        .is_err()
    );
    drop(db);
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let recovered = db
        .journal()
        .unwrap()
        .recover_stopped_owner(old)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(recovered.phase(), Phase::Cancelled);
    assert_eq!(recovered.absence_release().unwrap().id(), id);
    assert_eq!(recovered.absence_release().unwrap().by(), actor);
    let (new, replayed) = db.journal().unwrap().admit(job, 999999).unwrap();
    assert!(!new);
    assert_eq!(replayed.absence_release().unwrap().id(), id);
    assert!(replayed.stage().is_none());
}
#[test]
fn transfer_pause_does_not_block_readonly_reconciliation_or_explicit_settlement() {
    let (_t, path, mut p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    p.allow_transfers = false;
    let report = inspect(&mut db, &k, &p);
    assert!(report.eligible_for_absence_release());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_ok()
    );
}
#[test]
fn denied_directory_policy_never_probes_into_release() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let other = path.parent().unwrap().join("other");
    make_directory(&other).unwrap();
    let narrow = Policy::new(vec![other], false).unwrap();
    let report = inspect(&mut db, &k, &narrow);
    assert_eq!(report.state(), ObjectState::ScopeUnavailable);
    assert!(!report.eligible_for_absence_release());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &narrow, approval(&report), Arc::default())
            .is_err()
    );
}
fn child_parent_fixture() -> (
    tempfile::TempDir,
    PathBuf,
    Policy,
    JobKey,
    Snapshot,
    FencedConnection,
    PathBuf,
) {
    let (t, path, p) = fixture();
    let child = path.parent().unwrap().join("destination");
    make_directory(&child).unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let mut job = spec(&path, 5, 3);
    job.destination_path = child.join("target").to_str().unwrap().into();
    let k = JobKey::from_job(&job);
    let (_, s) = db.journal().unwrap().admit(job, 200).unwrap();
    let s = db
        .reserve_stage(
            &k,
            s.revision(),
            &p,
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let old = f.owner();
    drop(db);
    drop(f);
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let r = db
        .journal()
        .unwrap()
        .recover_stopped_owner(old)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(r.stage(), s.stage());
    (t, path, p, k, r, db, child)
}
#[test]
fn replacement_parent_denied_then_original_directory_is_restored_before_release() {
    let (_t, path, p, k, s, mut db, child) = child_parent_fixture();
    let before = inspect(&mut db, &k, &p);
    let saved = child.with_extension("saved");
    fs::rename(&child, &saved).unwrap();
    make_directory(&child).unwrap();
    let report = inspect(&mut db, &k, &p);
    assert_eq!(report.state(), ObjectState::ParentMismatch);
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&before), Arc::default())
            .is_err()
    );
    fs::remove_dir(&child).unwrap();
    fs::rename(&saved, &child).unwrap();
    let fresh = inspect(&mut db, &k, &p);
    assert_eq!(before.fingerprint(), fresh.fingerprint());
    assert_eq!(
        directory_id(&open_private(&child, true).unwrap()).unwrap(),
        s.stage().unwrap().allocation().unwrap().parent_id()
    );
    assert!(path.exists());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&fresh), Arc::default())
            .is_ok()
    );
}
#[cfg(windows)]
#[test]
fn native_parent_acl_widening_denies_release_and_restores_exact_descriptor() {
    let (_t, _path, p, k, s, mut db, child) = child_parent_fixture();
    let before = inspect(&mut db, &k, &p);
    let dir = open_private(&child, true).unwrap();
    crate::fleet::identity_windows::test_world_read_then_restore(&child, &dir, || {
        let denied = inspect(&mut db, &k, &p);
        assert!(!denied.eligible_for_absence_release());
        assert!(
            db.release_absent_allocation(&k, s.revision(), &p, approval(&before), Arc::default())
                .is_err()
        );
    })
    .unwrap();
    assert!(open_private(&child, true).is_ok());
    let fresh = inspect(&mut db, &k, &p);
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&fresh), Arc::default())
            .is_ok()
    );
}
#[test]
fn legacy_schema2_without_persisted_db_domain_cannot_be_backfilled_or_released() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let c = rusqlite::Connection::open(&path).unwrap();
    let mut body = serde_json::to_value(&s).unwrap();
    body["version"] = serde_json::json!(2);
    body["stage"]["allocation"]
        .as_object_mut()
        .unwrap()
        .remove("database_id");
    body["stage"]["allocation"]
        .as_object_mut()
        .unwrap()
        .remove("database_parent_id");
    c.execute(
        "UPDATE ferroc_fleet_jobs_v1 SET body=?1 WHERE k=?2",
        rusqlite::params![serde_json::to_string(&body).unwrap(), k.id()],
    )
    .unwrap();
    c.execute("UPDATE ferroc_fleet_meta SET version=2", [])
        .unwrap();
    let report = inspect(&mut db, &k, &p);
    assert!(!report.database_matches());
    assert!(!report.origin_stopped());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_err()
    );
    let raw: String = c
        .query_row(
            "SELECT body FROM ferroc_fleet_jobs_v1 WHERE k=?1",
            [k.id()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
        body
    );
    let inv = db
        .inventory(
            &p,
            &[path.parent().unwrap().into()],
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    assert!(
        inv.findings()
            .iter()
            .any(|f| f.kind == crate::fleet::inventory::FindingKind::AllocationDatabaseUnproven)
    );
}
#[test]
fn concurrent_release_connections_have_exactly_one_durable_winner() {
    let (_t, path, p) = fixture();
    let (k, s, db) = stopped(&path, &p);
    drop(db);
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = db
        .journal()
        .unwrap()
        .recover_stopped_owner(s.owner())
        .unwrap()
        .pop()
        .unwrap();
    let report = inspect(&mut db, &k, &p);
    let fingerprint = report.fingerprint();
    let wins = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..2 {
            let f = &f;
            let p = &p;
            let k = &k;
            let revision = s.revision();
            threads.push(scope.spawn(move || {
                let mut db = f.open_connection().unwrap();
                db.release_absent_allocation(
                    k,
                    revision,
                    p,
                    AbsenceApproval::approve_expected_fingerprint(fingerprint),
                    Arc::default(),
                )
                .is_ok()
            }));
        }
        threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(wins, 1);
    let row = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert_eq!(row.revision(), s.revision() + 1);
    assert_eq!(row.phase(), Phase::Cancelled);
    assert!(row.stage().is_none());
    assert!(row.absence_release().is_some());
}
#[test]
fn poisoned_actual_gate_does_not_retire_or_touch_obligation() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    let gate = Arc::new(Mutex::new(()));
    let held = gate.clone();
    let _ = std::thread::spawn(move || {
        let _g = held.lock().unwrap();
        panic!("intentional release gate poison");
    })
    .join();
    assert!(db.inspect_allocation(&k, &p, gate.clone()).is_err());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), gate)
            .is_err()
    );
    assert_eq!(
        db.journal().unwrap().get(&k).unwrap().unwrap().revision(),
        s.revision()
    );
}
#[test]
fn zero_byte_obligation_is_a_slot_until_explicit_stopped_origin_release() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = reserve(&mut db, &path, &p, 5, 0);
    let old = f.owner();
    drop(db);
    drop(f);
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let recovered = db
        .journal()
        .unwrap()
        .recover_stopped_owner(old)
        .unwrap()
        .pop()
        .unwrap();
    let inv = db
        .inventory(
            &p,
            &[path.parent().unwrap().into()],
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    assert_eq!(inv.recorded_usage(), (0, 1));
    assert!(inv.quarantined_budget().is_none());
    let report = inspect(&mut db, &k, &p);
    db.release_absent_allocation(
        &k,
        recovered.revision(),
        &p,
        approval(&report),
        Arc::default(),
    )
    .unwrap();
    let inv = db
        .inventory(
            &p,
            &[path.parent().unwrap().into()],
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    assert_eq!(inv.recorded_usage(), (0, 0));
    assert_eq!(inv.quarantined_budget().unwrap().usage().unwrap(), (0, 0));
    assert!(inv.quarantined_budget().unwrap().is_quarantined().unwrap());
    assert!(!s.stage().unwrap().path().exists());
}
#[test]
fn same_database_object_moved_to_different_parent_is_not_same_lock_domain() {
    let (_t, path, p) = fixture();
    let (k, s, db) = stopped(&path, &p);
    drop(db);
    let other = path.parent().unwrap().join("other-db-parent");
    make_directory(&other).unwrap();
    let moved = other.join("moved.db");
    fs::rename(&path, &moved).unwrap();
    let f = OwnerFence::acquire(&moved).unwrap();
    let mut db = f.open_connection().unwrap();
    let recovered = db
        .journal()
        .unwrap()
        .recover_stopped_owner(s.owner())
        .unwrap()
        .pop()
        .unwrap();
    let a = recovered.stage().unwrap().allocation().unwrap();
    assert_eq!(a.database_id(), Some(db.fence.database_id()));
    assert_ne!(
        a.database_parent_id(),
        Some(db.fence.database_parent_id().unwrap().as_str())
    );
    let report = inspect(&mut db, &k, &p);
    assert!(!report.database_matches());
    assert!(!report.origin_stopped());
    assert!(
        db.release_absent_allocation(
            &k,
            recovered.revision(),
            &p,
            approval(&report),
            Arc::default()
        )
        .is_err()
    );
    let old = recovered.owner();
    drop(db);
    drop(f);
    fs::rename(&moved, &path).unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = db
        .journal()
        .unwrap()
        .recover_stopped_owner(old)
        .unwrap()
        .pop()
        .unwrap();
    let restored = inspect(&mut db, &k, &p);
    assert!(restored.eligible_for_absence_release());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&restored), Arc::default())
            .is_ok()
    );
}
#[test]
fn dropping_factory_with_live_connection_never_proves_origin_stopped() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = reserve(&mut db, &path, &p, 5, 3);
    drop(f);
    assert!(OwnerFence::acquire(&path).is_err());
    let report = inspect(&mut db, &k, &p);
    assert!(!report.origin_stopped());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_err()
    );
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_ok()
    );
}
#[test]
fn corrupt_release_record_cannot_be_read_as_success_or_zero_debt() {
    for field in ["id", "by", "previous_revision", "allocation"] {
        let (_t, path, p) = fixture();
        let (k, s, mut db) = stopped(&path, &p);
        let r = inspect(&mut db, &k, &p);
        let done = db
            .release_absent_allocation(&k, s.revision(), &p, approval(&r), Arc::default())
            .unwrap();
        let mut body = serde_json::to_value(&done).unwrap();
        body["absence_release"][field] = match field {
            "id" | "by" => serde_json::json!(Uuid::nil()),
            "previous_revision" => serde_json::json!(done.revision()),
            _ => serde_json::Value::Null,
        };
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1 WHERE k=?2",
            rusqlite::params![serde_json::to_string(&body).unwrap(), k.id()],
        )
        .unwrap();
        assert!(db.journal().unwrap().get(&k).is_err());
        assert!(
            db.inventory(
                &p,
                &[path.parent().unwrap().into()],
                Arc::default(),
                InventoryLimits::default()
            )
            .is_err()
        );
    }
}
#[test]
#[ignore = "bounded no-drop release helper invoked only by owning parent"]
fn release_process_child() {
    let path = PathBuf::from(std::env::var_os("FERROC_RELEASE_DB").unwrap());
    let p = Policy::new(vec![path.parent().unwrap().into()], false).unwrap();
    let (k, s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    let result = db
        .release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
        .unwrap();
    fs::write(
        path.with_file_name("release-observed"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    std::process::exit(31);
}
#[test]
fn actual_no_drop_exit_after_release_commit_preserves_archived_allocation_and_settlement() {
    let (_t, path, p) = fixture();
    let log = tempfile::tempfile().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fleet::reconcile::tests::release_process_child",
            "--ignored",
            "--nocapture",
        ])
        .env("FERROC_RELEASE_DB", &path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let mut child = Process { child, log };
    assert_eq!(child.wait().code(), Some(31), "{}", child.output());
    let observed: Snapshot =
        serde_json::from_slice(&fs::read(path.with_file_name("release-observed")).unwrap())
            .unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let k = JobKey::from_job(observed.job());
    let persisted = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert_eq!(
        serde_json::to_string(&persisted).unwrap(),
        serde_json::to_string(&observed).unwrap()
    );
    assert_eq!(persisted.phase(), Phase::Cancelled);
    assert!(
        !persisted
            .absence_release()
            .unwrap()
            .original_allocation()
            .path()
            .exists()
    );
    let inv = db
        .inventory(
            &p,
            &[path.parent().unwrap().into()],
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    assert_eq!(inv.recorded_usage(), (0, 0));
    assert!(inv.complete());
}

struct Process {
    child: Child,
    log: File,
}
impl Process {
    fn wait(&mut self) -> std::process::ExitStatus {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > end {
                self.child.kill().unwrap();
                self.child.wait().unwrap();
                panic!("child timed out and reaped");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn output(&mut self) -> String {
        self.log.seek(SeekFrom::Start(0)).unwrap();
        let mut s = String::new();
        Read::by_ref(&mut self.log)
            .take(65537)
            .read_to_string(&mut s)
            .unwrap();
        assert!(s.len() <= 65536);
        s
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn spawn(exe: &Path, path: &Path, mode: &str) -> Process {
    let log = tempfile::tempfile().unwrap();
    let ready = path.with_file_name("ready-origin");
    let child = Command::new(exe)
        .args([
            "--exact",
            "fleet::allocation::tests::allocation_process_child",
            "--ignored",
            "--nocapture",
        ])
        .env("FERROC_ALLOCATION_DB", path)
        .env("FERROC_ALLOCATION_MODE", mode)
        .env("FERROC_ALLOCATION_READY", &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .spawn()
        .unwrap();
    Process { child, log }
}
fn wait_ready(child: &mut Process, path: &Path) -> Uuid {
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(text) = fs::read_to_string(path.with_file_name("ready-origin"))
            && let Ok(id) = Uuid::parse_str(&text)
        {
            return id;
        }
        assert!(
            child.child.try_wait().unwrap().is_none(),
            "child failed: {}",
            child.output()
        );
        assert!(Instant::now() < end, "readiness timed out; Drop reaps");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn real_crash_boundaries_require_native_takeover_and_never_release_present_files() {
    for mode in ["reserved", "created", "bound"] {
        let (_t, path, p) = fixture();
        let mut process = spawn(&std::env::current_exe().unwrap(), &path, mode);
        let old = wait_ready(&mut process, &path);
        assert!(OwnerFence::acquire(&path).is_err());
        process.child.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert_eq!(process.wait().code(), Some(23), "{}", process.output());
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let k = JobKey::from_job(&spec(&path, 5, 3));
        let before = inspect(&mut db, &k, &p);
        assert!(before.origin_stopped());
        assert!(!before.owner_recovered());
        let s = db
            .journal()
            .unwrap()
            .recover_stopped_owner(old)
            .unwrap()
            .pop()
            .unwrap();
        let report = inspect(&mut db, &k, &p);
        assert_eq!(report.eligible_for_absence_release(), mode == "reserved");
        let result =
            db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default());
        assert_eq!(result.is_ok(), mode == "reserved");
        if mode != "reserved" {
            assert_eq!(fs::read(s.stage().unwrap().path()).unwrap(), b"");
            assert!(
                db.journal()
                    .unwrap()
                    .get(&k)
                    .unwrap()
                    .unwrap()
                    .stage()
                    .is_some()
            );
        }
    }
}
#[test]
#[ignore = "explicit historical executable probe; no normal CI artifact dependency"]
fn actual49a8_refuses_schema3_and_actual_legacy2_never_gets_automatic_domain_binding() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_RECONCILIATION_LEGACY_TEST")
            .expect("explicit historical49a8 exe required"),
    );
    let mut file = File::open(&exe).unwrap();
    let mut hash = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = file.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&b[..n]);
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "49a8c238f737727f92010561c47ec45fbb06acd986365871a8214fe3c7cc6e65"
    );
    {
        let (_t, path, p) = fixture();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let (k, s) = reserve(&mut db, &path, &p, 5, 3);
        let before = serde_json::to_string(&s).unwrap();
        drop(db);
        drop(f);
        let mut child = spawn(&exe, &path, "reserved");
        drop(child.child.stdin.take());
        assert!(!child.wait().success());
        let output = child.output();
        assert!(
            output.contains("unsupported/ambiguous fleet journal schema version"),
            "{output}"
        );
        assert!(!path.with_file_name("ready-origin").exists());
        assert!(!s.stage().unwrap().path().exists());
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        assert_eq!(
            serde_json::to_string(&db.journal().unwrap().get(&k).unwrap().unwrap()).unwrap(),
            before
        );
    }
    {
        let (_t, path, p) = fixture();
        let mut child = spawn(&exe, &path, "reserved");
        let old = wait_ready(&mut child, &path);
        child.child.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert_eq!(child.wait().code(), Some(23), "{}", child.output());
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let s = db
            .journal()
            .unwrap()
            .recover_stopped_owner(old)
            .unwrap()
            .pop()
            .unwrap();
        let k = JobKey::from_job(s.job());
        let report = inspect(&mut db, &k, &p);
        assert_eq!(report.state(), ObjectState::Absent);
        assert!(!report.database_matches());
        assert!(!report.eligible_for_absence_release());
        assert!(
            s.stage()
                .unwrap()
                .allocation()
                .unwrap()
                .database_id()
                .is_none()
        );
        assert!(
            db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
                .is_err()
        );
        assert_eq!(
            db.connection
                .query_row("SELECT version FROM ferroc_fleet_meta", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    println!(
        "ACTUAL49A8_SCHEMA3_REFUSED_AND_ACTUAL_SCHEMA2_UNPROVEN: oldSHA fully checked; no adoption/release; fixtures reclaimed"
    );
}

#[test]
fn current_origin_absence_is_diagnostic_not_permission_to_release() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = reserve(&mut db, &path, &p, 5, 3);
    let report = inspect(&mut db, &k, &p);
    assert_eq!(report.state(), ObjectState::Absent);
    assert!(report.database_matches());
    assert!(!report.origin_stopped());
    assert!(!report.eligible_for_absence_release());
    assert!(
        db.release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
            .is_err()
    );
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_ok()
    );
}
#[test]
fn stopped_origin_explicit_absence_release_retains_original_record_and_opens_next_reservation() {
    let (_t, path, p) = fixture();
    let (k, s, mut db) = stopped(&path, &p);
    let report = inspect(&mut db, &k, &p);
    assert!(report.eligible_for_absence_release());
    let released = db
        .release_absent_allocation(&k, s.revision(), &p, approval(&report), Arc::default())
        .unwrap();
    assert_eq!(released.phase(), Phase::Cancelled);
    assert!(released.stage().is_none());
    let r = released.absence_release().unwrap();
    assert_eq!(r.original_allocation(), s.stage().unwrap());
    assert_eq!(r.previous_revision(), s.revision());
    assert_eq!(r.fingerprint(), report.fingerprint());
    assert!(!s.stage().unwrap().path().exists());
    let (_, new) = reserve(&mut db, &path, &p, 7, 0);
    assert_eq!(new.stage().unwrap().reserved_bytes(), 0);
}
#[test]
fn sqlite_copy_is_not_proof_origin_stopped_even_after_metadata_owner_recovery() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut original = f.open_connection().unwrap();
    let (k, s) = reserve(&mut original, &path, &p, 5, 3);
    let copy = path.with_file_name("copy.db");
    drop(new_private(&copy).unwrap());
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("VACUUM main INTO ?1", [copy.to_str().unwrap()])
        .unwrap();
    let second = OwnerFence::acquire(&copy).unwrap();
    let mut db = second.open_connection().unwrap();
    let recovered = db
        .journal()
        .unwrap()
        .recover_stopped_owner(f.owner())
        .unwrap()
        .pop()
        .unwrap();
    let report = inspect(&mut db, &k, &p);
    assert!(!report.database_matches());
    assert!(!report.origin_stopped());
    assert!(!report.eligible_for_absence_release());
    assert!(
        db.release_absent_allocation(
            &k,
            recovered.revision(),
            &p,
            approval(&report),
            Arc::default()
        )
        .is_err()
    );
    let inv = db
        .inventory(
            &p,
            &[path.parent().unwrap().into()],
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    assert!(
        inv.findings()
            .iter()
            .any(|f| f.kind == crate::fleet::inventory::FindingKind::AllocationDatabaseMismatch)
    );
    assert!(
        original
            .create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_ok()
    );
}
