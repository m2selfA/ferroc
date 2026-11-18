use super::*;
use crate::fleet::identity::new_private;
use crate::fleet::{
    fence::OwnerFence,
    identity::make_directory,
    job::{JobSpec, RoutePolicy},
    protocol::device_digest,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
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
        version: crate::fleet::job::JOB_VERSION,
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
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: format!("allocation-{n}"),
    }
}
fn admit(db: &mut FencedConnection, path: &Path, n: u8, bytes: u64) -> (JobKey, Snapshot) {
    let j = spec(path, n, bytes);
    let k = JobKey::from_job(&j);
    let (_, s) = db.journal().unwrap().admit(j, 200).unwrap();
    (k, s)
}
fn reserve(db: &mut FencedConnection, key: &JobKey, s: &Snapshot, p: &Policy) -> Snapshot {
    db.reserve_stage(
        key,
        s.revision(),
        p,
        Arc::default(),
        InventoryLimits::default(),
    )
    .unwrap()
}
fn scan(db: &mut FencedConnection, p: &Policy, path: &Path) -> inventory::RecoveryInventory {
    db.inventory(
        p,
        &[path.parent().unwrap().into()],
        Arc::default(),
        InventoryLimits::default(),
    )
    .unwrap()
}
fn schema(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT version FROM ferroc_fleet_meta", [], |r| r.get(0))
        .unwrap()
}
#[test]
fn reservation_is_durable_before_any_file_exists_and_quota_cannot_be_released() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let n = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
    let s = reserve(&mut db, &k, &s, &p);
    let r = s.stage().unwrap();
    assert_eq!(schema(&path), 3);
    assert_eq!(s.phase(), Phase::Interrupted);
    assert!(!r.path().exists());
    assert_eq!(r.reserved_bytes(), 3);
    assert!(r.allocation().unwrap().file_id().is_none());
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        n
    );
    assert!(
        db.journal()
            .unwrap()
            .confirm_removed(&k, s.revision())
            .is_err()
    );
    let loaded = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert_eq!(s.revision(), loaded.revision());
    assert_eq!(loaded.stage().unwrap().path(), r.path());
    let report = scan(&mut db, &p, &path);
    assert_eq!(report.recorded_usage(), (3, 1));
    assert!(!report.complete());
    assert!(report.quarantined_budget().is_none());
}
#[test]
fn empty_file_binding_keeps_job_interrupted_and_returns_no_receive_capability() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let bound = db
        .create_reserved_stage(&k, s.revision(), &p, Arc::default())
        .unwrap();
    let reference = bound.stage().unwrap();
    let a = reference.allocation().unwrap();
    assert_eq!(bound.phase(), Phase::Interrupted);
    assert_eq!(bound.received(), 0);
    assert_eq!(fs::read(reference.path()).unwrap(), b"");
    assert_eq!(
        a.file_id(),
        Some(
            file_id(&open_stage(reference.path()).unwrap())
                .unwrap()
                .as_str()
        )
    );
    assert!(a.parent_durability().is_some());
    let report = scan(&mut db, &p, &path);
    assert!(report.complete());
    assert!(report.stages()[0].recorded_identity_matches);
    assert_eq!(
        report.quarantined_budget().unwrap().usage().unwrap(),
        (3, 1)
    );
    assert!(
        report
            .quarantined_budget()
            .unwrap()
            .is_quarantined()
            .unwrap()
    );
    assert!(
        db.journal()
            .unwrap()
            .progress(&k, bound.revision(), 3)
            .is_err()
    );
    assert!(
        db.journal()
            .unwrap()
            .readback(&k, bound.revision(), [0; 32])
            .is_err()
    );
    assert!(
        db.journal()
            .unwrap()
            .begin_commit(&k, bound.revision())
            .is_err()
    );
}
#[test]
fn zero_byte_reservation_still_blocks_a_second_slot_even_with_fresh_limits() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 0);
    let s = reserve(&mut db, &k, &s, &p);
    db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
        .unwrap();
    let (k2, s2) = admit(&mut db, &path, 7, 0);
    assert!(
        db.reserve_stage(
            &k2,
            s2.revision(),
            &p,
            Arc::default(),
            InventoryLimits::default()
        )
        .is_err()
    );
    assert_eq!(scan(&mut db, &p, &path).recorded_usage(), (0, 1));
}
#[test]
fn sql_reservation_failure_rolls_back_schema_and_never_creates_a_file() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TRIGGER reject_reservation BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'reservation fault');END;").unwrap();
    assert!(
        db.reserve_stage(
            &k,
            s.revision(),
            &p,
            Arc::default(),
            InventoryLimits::default()
        )
        .is_err()
    );
    assert_eq!(schema(&path), 1);
    let s2 = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert_eq!(s2.revision(), s.revision());
    assert!(s2.stage().is_none());
    assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|r| {
        r.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".ferroc-fleet-alloc-")
    }));
}
#[test]
fn sql_binding_failure_retains_empty_file_and_full_unbound_obligation() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TRIGGER reject_binding BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'binding fault');END;").unwrap();
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_err()
    );
    assert_eq!(fs::read(s.stage().unwrap().path()).unwrap(), b"");
    let after = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert_eq!(after.revision(), s.revision());
    assert!(
        after
            .stage()
            .unwrap()
            .allocation()
            .unwrap()
            .file_id()
            .is_none()
    );
    let r = scan(&mut db, &p, &path);
    assert_eq!(r.recorded_usage(), (3, 1));
    assert!(r.quarantined_budget().is_none());
}
#[test]
fn preexisting_candidate_is_never_adopted_or_overwritten_or_deleted() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let candidate = s.stage().unwrap().path();
    let mut file = new_private(candidate).unwrap();
    file.write_all(b"keep").unwrap();
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_err()
    );
    assert_eq!(fs::read(candidate).unwrap(), b"keep");
    assert_eq!(
        db.journal().unwrap().get(&k).unwrap().unwrap().revision(),
        s.revision()
    );
}
#[test]
fn second_create_cannot_rebind_an_existing_file() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let bound = db
        .create_reserved_stage(&k, s.revision(), &p, Arc::default())
        .unwrap();
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_err()
    );
    assert!(
        db.create_reserved_stage(&k, bound.revision(), &p, Arc::default())
            .is_err()
    );
    assert_eq!(fs::read(bound.stage().unwrap().path()).unwrap(), b"");
}
#[test]
fn cancel_during_creation_wins_cas_without_releasing_unbound_object() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let mut competing = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let r = db.create_reserved_inner(&k, s.revision(), &p, Arc::default(), |_, _| {
        let canceled = competing.journal()?.cancel(&k, s.revision())?;
        assert!(
            competing
                .journal()?
                .confirm_removed(&k, canceled.revision())
                .is_err()
        );
        Ok(())
    });
    assert!(r.is_err());
    let after = db.journal().unwrap().get(&k).unwrap().unwrap();
    assert_eq!(after.phase(), Phase::CancelRequested);
    assert!(
        after
            .stage()
            .unwrap()
            .allocation()
            .unwrap()
            .file_id()
            .is_none()
    );
    assert_eq!(fs::read(after.stage().unwrap().path()).unwrap(), b"");
    assert_eq!(scan(&mut db, &p, &path).recorded_usage(), (3, 1));
}
#[test]
fn unknown_local_candidate_blocks_reservation_without_schema_upgrade() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let candidate = path.with_file_name(".ferroc-fleet-unknown");
    drop(new_private(&candidate).unwrap());
    assert!(
        db.reserve_stage(
            &k,
            s.revision(),
            &p,
            Arc::default(),
            InventoryLimits::default()
        )
        .is_err()
    );
    assert_eq!(schema(&path), 1);
    assert!(
        db.journal()
            .unwrap()
            .get(&k)
            .unwrap()
            .unwrap()
            .stage()
            .is_none()
    );
    assert!(candidate.exists());
}
#[test]
fn policy_and_quota_failure_precede_any_reservation_or_file_creation() {
    for disabled in [false, true] {
        let (_t, path, mut p) = fixture();
        if disabled {
            p.allow_transfers = false;
        }
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let (k, s) = admit(&mut db, &path, 5, 3);
        assert!(
            db.reserve_stage(
                &k,
                s.revision(),
                &p,
                Arc::default(),
                InventoryLimits {
                    byte_limit: 2,
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert_eq!(schema(&path), 1);
        assert!(
            db.journal()
                .unwrap()
                .get(&k)
                .unwrap()
                .unwrap()
                .stage()
                .is_none()
        );
    }
}
#[test]
fn canceled_reservation_cannot_create_and_absence_cannot_clear_it() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let s = db.journal().unwrap().cancel(&k, s.revision()).unwrap();
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_err()
    );
    assert!(
        db.journal()
            .unwrap()
            .confirm_removed(&k, s.revision())
            .is_err()
    );
    assert_eq!(scan(&mut db, &p, &path).recorded_usage(), (3, 1));
}
#[test]
fn parent_rename_replacement_is_rejected_and_baseline_is_restored() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let destination = root.join("destination");
    make_directory(&destination).unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let mut job = spec(&path, 5, 3);
    job.destination_path = destination.join("target").to_str().unwrap().into();
    let k = JobKey::from_job(&job);
    let (_, s) = db.journal().unwrap().admit(job, 200).unwrap();
    let s = reserve(&mut db, &k, &s, &p);
    let saved = root.join("saved-directory");
    fs::rename(&destination, &saved).unwrap();
    make_directory(&destination).unwrap();
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_err()
    );
    assert!(!s.stage().unwrap().path().exists());
    fs::remove_dir(&destination).unwrap();
    fs::rename(&saved, &destination).unwrap();
    assert_eq!(
        directory_id(&open_private(&destination, true).unwrap()).unwrap(),
        s.stage().unwrap().allocation().unwrap().parent_id()
    );
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_ok()
    );
}
#[test]
fn replacing_bound_file_is_reported_without_trusting_length_or_deleting_either() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let b = db
        .create_reserved_stage(&k, s.revision(), &p, Arc::default())
        .unwrap();
    let candidate = b.stage().unwrap().path();
    let saved = candidate.with_extension("saved");
    fs::rename(candidate, &saved).unwrap();
    drop(new_private(candidate).unwrap());
    let report = scan(&mut db, &p, &path);
    assert!(!report.complete());
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind == inventory::FindingKind::RecordedIdentityMismatch)
    );
    assert!(report.quarantined_budget().is_none());
    assert!(saved.exists() && candidate.exists());
}
#[cfg(windows)]
#[test]
fn native_stage_acl_is_rejected_then_restored_before_binding() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    let result = db.create_reserved_inner(&k, s.revision(), &p, Arc::default(), |file, r| {
        crate::fleet::identity_windows::test_world_read_then_restore(r.path(), file, || {
            assert!(open_stage(r.path()).is_err());
        })
        .unwrap();
        Ok(())
    });
    assert!(result.is_ok());
    assert!(scan(&mut db, &p, &path).complete());
}

#[test]
fn concurrent_fenced_connections_have_one_reservation_winner_without_fs_gate_trust() {
    for distinct_jobs in [false, true] {
        let (_t, path, p) = fixture();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let (k, s) = admit(&mut db, &path, 5, 3);
        let mut keys = vec![k.clone()];
        let second = if distinct_jobs {
            let (k2, s2) = admit(&mut db, &path, 7, 3);
            keys.push(k2.clone());
            (k2, s2.revision())
        } else {
            (k.clone(), s.revision())
        };
        let attempts = [(k, s.revision()), second];
        let wins = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for (key, revision) in attempts {
                let f = &f;
                let p = &p;
                handles.push(scope.spawn(move || {
                    let mut db = f.open_connection().unwrap();
                    db.reserve_stage(
                        &key,
                        revision,
                        p,
                        Arc::default(),
                        InventoryLimits::default(),
                    )
                    .is_ok()
                }));
            }
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(wins, 1);
        let mut staged = 0;
        for key in keys {
            let row = db.journal().unwrap().get(&key).unwrap().unwrap();
            if let Some(r) = row.stage() {
                staged += 1;
                assert!(!r.path().exists());
            }
        }
        assert_eq!(staged, 1);
        assert_eq!(scan(&mut db, &p, &path).recorded_usage(), (3, 1));
    }
}

#[test]
fn policy_revocation_and_existing_destination_after_reservation_leave_debt_without_stage() {
    for disabled in [false, true] {
        let (_t, path, mut p) = fixture();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let (k, s) = admit(&mut db, &path, 5, 3);
        let s = reserve(&mut db, &k, &s, &p);
        if disabled {
            p.allow_transfers = false;
        } else {
            let mut file = new_private(Path::new(&s.job().destination_path)).unwrap();
            file.write_all(b"keep").unwrap();
        }
        assert!(
            db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
                .is_err()
        );
        assert!(!s.stage().unwrap().path().exists());
        assert_eq!(
            db.journal().unwrap().get(&k).unwrap().unwrap().revision(),
            s.revision()
        );
        if !disabled {
            assert_eq!(fs::read(&s.job().destination_path).unwrap(), b"keep");
        }
    }
}
#[cfg(windows)]
#[test]
fn actual_parent_acl_widening_refuses_creation_then_restores_exact_original_descriptor() {
    let (_t, path, p) = fixture();
    let target = path.parent().unwrap().join("private-parent");
    make_directory(&target).unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let mut job = spec(&path, 5, 3);
    job.destination_path = target.join("target").to_str().unwrap().into();
    let k = JobKey::from_job(&job);
    let (_, s) = db.journal().unwrap().admit(job, 200).unwrap();
    let s = reserve(&mut db, &k, &s, &p);
    let directory = open_private(&target, true).unwrap();
    crate::fleet::identity_windows::test_world_read_then_restore(&target, &directory, || {
        assert!(
            db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
                .is_err()
        );
        assert!(!s.stage().unwrap().path().exists());
    })
    .unwrap();
    assert_eq!(
        directory_id(&open_private(&target, true).unwrap()).unwrap(),
        s.stage().unwrap().allocation().unwrap().parent_id()
    );
    assert!(
        db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
            .is_ok()
    );
}
#[test]
fn fabricated_allocation_cannot_enter_legacy_attach_path() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let allocated = reserve(&mut db, &k, &s, &p);
    let fake = allocated.stage().unwrap().clone();
    let (k2, s2) = admit(&mut db, &path, 7, 3);
    assert!(
        db.journal()
            .unwrap()
            .attach_stage(&k2, s2.revision(), fake)
            .is_err()
    );
    assert!(
        db.journal()
            .unwrap()
            .get(&k2)
            .unwrap()
            .unwrap()
            .stage()
            .is_none()
    );
}
#[test]
fn corrupt_binding_name_or_ids_never_look_like_a_valid_zero_debt_row() {
    for field in ["id", "owner", "parent_id", "file_id"] {
        let (_t, path, p) = fixture();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let (k, s) = admit(&mut db, &path, 5, 3);
        reserve(&mut db, &k, &s, &p);
        let c = rusqlite::Connection::open(&path).unwrap();
        let raw: String = c
            .query_row(
                "SELECT body FROM ferroc_fleet_jobs_v1 WHERE k=?1",
                [k.id()],
                |r| r.get(0),
            )
            .unwrap();
        let mut body: serde_json::Value = serde_json::from_str(&raw).unwrap();
        body["stage"]["allocation"][field] = serde_json::json!("not-a-valid-observation");
        c.execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1 WHERE k=?2",
            rusqlite::params![serde_json::to_string(&body).unwrap(), k.id()],
        )
        .unwrap();
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
#[ignore = "explicit provenance probe requires provided actual archived e630 testexe"]
fn actual_archived_e630_binary_refuses_schema3_before_any_stage_creation() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_ALLOCATION_LEGACY_TEST").expect("explicit old exe required"),
    );
    let mut old = File::open(&exe).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = old.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "e630a76f3f6146bc58f947112a65cd43667b6650e83dbdba4a1dcbfc034d15d7"
    );
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let (k, s) = admit(&mut db, &path, 5, 3);
    let reserved = reserve(&mut db, &k, &s, &p);
    let before = serde_json::to_string(&reserved).unwrap();
    drop(db);
    drop(f);
    let log = tempfile::tempfile().unwrap();
    let mut child = Process {
        child: Command::new(exe)
            .args([
                "--exact",
                "fleet::inventory::tests::inventory_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env("FERROC_INVENTORY_DB", &path)
            .env("FERROC_INVENTORY_MODE", "before_attach")
            .env(
                "FERROC_INVENTORY_READY",
                path.with_file_name("old-must-not-ready"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log.try_clone().unwrap()))
            .spawn()
            .unwrap(),
        log,
    };
    let status = child.wait();
    let output = child.logs();
    assert!(!status.success());
    assert!(
        output.contains("unsupported/ambiguous fleet journal schema version"),
        "{output}"
    );
    assert_eq!(schema(&path), 3);
    assert!(!reserved.stage().unwrap().path().exists());
    assert!(!path.with_file_name("old-must-not-ready").exists());
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    assert_eq!(
        serde_json::to_string(&db.journal().unwrap().get(&k).unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(scan(&mut db, &p, &path).recorded_usage(), (3, 1));
    println!(
        "ACTUAL_E630_SCHEMA3_REJECTED: oldSHA=e630a76f...,no stage/no row change;fixture reclaimed on return"
    );
}

struct Process {
    child: Child,
    log: File,
}
impl Process {
    fn wait(&mut self) -> std::process::ExitStatus {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            if Instant::now() >= end {
                self.child.kill().unwrap();
                self.child.wait().unwrap();
                panic!("allocation child timeout; killed/reaped");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn logs(&mut self) -> String {
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
fn ready(owner: Uuid) -> ! {
    fs::write(
        std::env::var_os("FERROC_ALLOCATION_READY").unwrap(),
        owner.to_string(),
    )
    .unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
    std::process::exit(23);
}
#[test]
#[ignore = "bounded crash helper invoked only by parent"]
fn allocation_process_child() {
    let path = std::env::var_os("FERROC_ALLOCATION_DB").unwrap();
    let path = Path::new(&path);
    let mode = std::env::var("FERROC_ALLOCATION_MODE").unwrap();
    let f = OwnerFence::acquire(path).unwrap();
    let mut db = f.open_connection().unwrap();
    let p = Policy::new(vec![path.parent().unwrap().into()], false).unwrap();
    let (k, s) = admit(&mut db, path, 5, 3);
    let s = reserve(&mut db, &k, &s, &p);
    match mode.as_str() {
        "reserved" => ready(f.owner()),
        "created" => {
            db.create_reserved_inner(&k, s.revision(), &p, Arc::default(), |_, _| {
                ready(f.owner())
            })
            .unwrap();
        }
        "bound" => {
            db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
                .unwrap();
            ready(f.owner());
        }
        _ => panic!("invalid allocation child mode"),
    }
}
fn spawn(path: &Path, mode: &str) -> (Process, Uuid) {
    let log = tempfile::tempfile().unwrap();
    let ready = path.with_file_name("allocation-ready");
    let child = Command::new(std::env::current_exe().unwrap())
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
    let mut child = Process { child, log };
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(s) = fs::read_to_string(&ready)
            && let Ok(id) = Uuid::parse_str(&s)
        {
            return (child, id);
        }
        if child.child.try_wait().unwrap().is_some() {
            panic!("child failed: {}", child.logs());
        }
        assert!(Instant::now() < end, "readiness timeout; Drop reaps");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn crashes_at_all_three_boundaries_retain_debt_and_never_resume_old_owner() {
    for mode in ["reserved", "created", "bound"] {
        let (_t, path, p) = fixture();
        let (mut child, old) = spawn(&path, mode);
        child.child.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert_eq!(child.wait().code(), Some(23), "{}", child.logs());
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let k = JobKey::from_job(&spec(&path, 5, 3));
        let before = db.journal().unwrap().get(&k).unwrap().unwrap();
        assert_eq!(before.owner(), old);
        let report = scan(&mut db, &p, &path);
        assert_eq!(report.recorded_usage(), (3, 1));
        assert_eq!(report.complete(), mode == "bound");
        assert!(
            db.create_reserved_stage(&k, before.revision(), &p, Arc::default())
                .is_err()
        );
        let recovered = db.journal().unwrap().recover_stopped_owner(old).unwrap();
        assert_eq!(recovered.len(), 1);
        let s = &recovered[0];
        assert_eq!(s.phase(), Phase::Interrupted);
        assert!(
            db.create_reserved_stage(&k, s.revision(), &p, Arc::default())
                .is_err()
        );
        assert!(
            db.journal()
                .unwrap()
                .confirm_removed(&k, s.revision())
                .is_err()
        );
        assert_eq!(
            s.stage().unwrap().allocation().unwrap().original_owner(),
            old
        );
    }
}
