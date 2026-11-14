use super::*;
use crate::{
    config::Policy,
    fleet::{
        job::RoutePolicy,
        protocol::device_digest,
        stage::{StageBudget, StageFile},
    },
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
fn owner() -> Uuid {
    Uuid::from_bytes([9; 16])
}
fn other() -> Uuid {
    Uuid::from_bytes([10; 16])
}
fn db(path: &Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;")
        .unwrap();
    c
}
fn job(root: &Path) -> JobSpec {
    JobSpec {
        version: 1,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::from_bytes([5; 16]),
        file_id: Uuid::from_bytes([6; 16]),
        source_path: root.join("source.bin").to_str().unwrap().into(),
        destination_path: root.join("target.bin").to_str().unwrap().into(),
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: "journal-case".into(),
    }
}
fn stage(root: &Path) -> StageReference {
    let p = root.join(".ferroc-fleet-journal-test");
    fs::write(&p, b"abc").unwrap();
    StageReference::observed_local(p, 3).unwrap()
}
fn ready(j: &mut Journal<'_>, root: &Path) -> (JobKey, Snapshot) {
    let job = job(root);
    let k = JobKey::from_job(&job);
    let (_, s) = j.admit(job.clone(), 200).unwrap();
    let s = j.attach_stage(&k, s.revision(), stage(root)).unwrap();
    let s = j.progress(&k, s.revision(), 3).unwrap();
    let s = j.readback(&k, s.revision(), job.sha256).unwrap();
    (k, s)
}
fn published() -> Publication {
    Publication::Published {
        size: 3,
        sha256: Sha256::digest(b"abc").into(),
        parent_sync: ParentSync::Unsupported,
    }
}
#[test]
fn real_file_reopen_preserves_stable_job_ids_and_conflicting_parameters_fail() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("relay.db");
    let mut c = db(&p);
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let original = job(t.path());
    let (created, s) = j.admit(original.clone(), 200).unwrap();
    assert!(created);
    j.into_connection();
    drop(c);
    let mut c = db(&p);
    let mut j = Journal::attach(&mut c, other()).unwrap();
    let mut retry = original.clone();
    retry.transfer_id = Uuid::new_v4();
    retry.file_id = Uuid::new_v4();
    let (created, existing) = j.admit(retry, 99999).unwrap();
    assert!(!created);
    assert_eq!(existing.job(), &original);
    assert_eq!(existing.owner(), s.owner());
    let mut wrong = original;
    wrong.sha256[0] ^= 1;
    assert!(j.admit(wrong, 200).is_err());
}
#[test]
fn rejected_configurations_do_not_create_a_weak_or_memory_journal() {
    let mut c = Connection::open_in_memory().unwrap();
    assert!(Journal::attach(&mut c, owner()).is_err());
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    c.execute_batch("PRAGMA synchronous=NORMAL").unwrap();
    assert!(Journal::attach(&mut c, owner()).is_err());
    c.execute_batch("PRAGMA synchronous=FULL;PRAGMA journal_mode=OFF")
        .unwrap();
    assert!(Journal::attach(&mut c, owner()).is_err());
    c.execute_batch("PRAGMA journal_mode=WAL;BEGIN").unwrap();
    assert!(Journal::attach(&mut c, owner()).is_err());
    c.execute_batch("ROLLBACK").unwrap();
    assert!(Journal::attach(&mut c, Uuid::nil()).is_err());
}
#[test]
fn same_database_keeps_existing_relay_tables_and_future_versions_fail() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    c.execute_batch(
        "CREATE TABLE kv(k TEXT PRIMARY KEY,v TEXT);INSERT INTO kv VALUES('sentinel','keep');",
    )
    .unwrap();
    Journal::attach(&mut c, owner()).unwrap().into_connection();
    assert_eq!(
        c.query_row("SELECT v FROM kv", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "keep"
    );
    c.execute("UPDATE ferroc_fleet_meta SET version=99", [])
        .unwrap();
    assert!(Journal::attach(&mut c, owner()).is_err());
    assert_eq!(
        c.query_row("SELECT version FROM ferroc_fleet_meta", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        99
    );
}
#[test]
fn revisions_and_owner_are_checked_before_any_transition() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("db");
    let mut c = db(&path);
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (_, s) = j.admit(job(t.path()), 200).unwrap();
    let k = JobKey::from_job(s.job());
    assert!(j.attach_stage(&k, 8, stage(t.path())).is_err());
    let s = j.attach_stage(&k, 0, stage(t.path())).unwrap();
    assert!(j.progress(&k, 0, 1).is_err());
    assert_eq!(j.get(&k).unwrap().unwrap().revision(), s.revision());
    j.into_connection();
    let mut second = db(&path);
    let mut other = Journal::attach(&mut second, other()).unwrap();
    assert!(other.cancel(&k, s.revision()).is_err());
    assert_eq!(other.get(&k).unwrap().unwrap().phase(), Phase::Transferring);
}
#[test]
fn coverage_counter_is_monotonic_bounded_and_never_substitutes_for_readback() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (_, s) = j.admit(job(t.path()), 200).unwrap();
    let k = JobKey::from_job(s.job());
    let s = j.attach_stage(&k, 0, stage(t.path())).unwrap();
    let s = j.progress(&k, s.revision(), 2).unwrap();
    assert!(j.progress(&k, s.revision(), 1).is_err());
    assert!(j.progress(&k, s.revision(), 4).is_err());
    assert!(j.readback(&k, s.revision(), job(t.path()).sha256).is_err());
    assert!(j.begin_commit(&k, s.revision()).is_err());
    let s = j.progress(&k, s.revision(), 3).unwrap();
    assert!(j.readback(&k, s.revision(), [0; 32]).is_err());
    assert!(j.publication(&k, s.revision(), published()).is_err());
}
#[test]
fn cancellation_requires_observed_path_absence_and_retains_reservation() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (k, s) = ready(&mut j, t.path());
    let s = j.cancel(&k, s.revision()).unwrap();
    assert_eq!(s.phase(), Phase::CancelRequested);
    assert!(j.confirm_removed(&k, s.revision()).is_err());
    assert_eq!(
        j.get(&k)
            .unwrap()
            .unwrap()
            .stage()
            .unwrap()
            .reserved_bytes(),
        3
    );
    fs::remove_file(s.stage().unwrap().path()).unwrap();
    let s = j.confirm_removed(&k, s.revision()).unwrap();
    assert_eq!(s.phase(), Phase::Cancelled);
    assert!(s.stage().is_none());
    assert_eq!(
        j.cancel(&k, s.revision()).unwrap().phase(),
        Phase::Cancelled
    );
}
#[test]
fn independent_sqlite_connections_serialize_commit_cancel_with_one_revision_winner() {
    for _ in 0..4 {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("db");
        let mut c = db(&path);
        let mut j = Journal::attach(&mut c, owner()).unwrap();
        let (k, s) = ready(&mut j, t.path());
        let revision = s.revision();
        j.into_connection();
        drop(c);
        let mut a = db(&path);
        let mut b = db(&path);
        let key_a = k.clone();
        let key_b = k.clone();
        let (signal, ready_rx) = std::sync::mpsc::channel();
        let signal_b = signal.clone();
        let (start_a, wait_a) = std::sync::mpsc::channel();
        let (start_b, wait_b) = std::sync::mpsc::channel();
        let (committed, cancelled) = std::thread::scope(|scope| {
            let left = scope.spawn(move || {
                signal.send(()).unwrap();
                wait_a.recv_timeout(Duration::from_secs(5)).unwrap();
                let mut j = Journal::attach(&mut a, owner()).unwrap();
                j.begin_commit(&key_a, revision)
            });
            let right = scope.spawn(move || {
                signal_b.send(()).unwrap();
                wait_b.recv_timeout(Duration::from_secs(5)).unwrap();
                let mut j = Journal::attach(&mut b, owner()).unwrap();
                j.cancel(&key_b, revision)
            });
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            start_a.send(()).unwrap();
            start_b.send(()).unwrap();
            (left.join().unwrap(), right.join().unwrap())
        });
        assert_ne!(
            committed.is_ok(),
            cancelled.is_ok(),
            "exactly one old revision may win"
        );
        let mut c = db(&path);
        let mut j = Journal::attach(&mut c, owner()).unwrap();
        let s = j.get(&k).unwrap().unwrap();
        assert_eq!(s.revision(), revision + 1);
        assert!(s.receipt().is_none());
        assert!(s.stage().unwrap().path().exists());
        if committed.is_ok() {
            assert_eq!(s.phase(), Phase::Committing);
            let s = j.cancel(&k, s.revision()).unwrap();
            assert_eq!(s.phase(), Phase::CommitUnknown);
            assert!(j.confirm_removed(&k, s.revision()).is_err());
        } else {
            assert_eq!(s.phase(), Phase::CancelRequested);
            assert!(j.begin_commit(&k, s.revision()).is_err());
        }
    }
}

#[test]
fn commit_intent_is_persistent_and_cancel_never_becomes_a_false_rollback() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("db");
    let mut c = db(&p);
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (k, s) = ready(&mut j, t.path());
    let s = j.begin_commit(&k, s.revision()).unwrap();
    let id = s.intent();
    let s = j.cancel(&k, s.revision()).unwrap();
    assert_eq!(s.phase(), Phase::CommitUnknown);
    assert!(j.confirm_removed(&k, s.revision()).is_err());
    j.into_connection();
    drop(c);
    let mut c = db(&p);
    let mut j = Journal::attach(&mut c, other()).unwrap();
    let r = j.recover_stopped_owner(owner()).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].intent(), id);
    assert_eq!(r[0].phase(), Phase::CommitUnknown);
    assert!(r[0].stage().is_some());
}
#[test]
fn receipt_is_stable_on_replay_and_restart_does_not_infer_file_survival() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("db");
    let mut c = db(&p);
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (k, s) = ready(&mut j, t.path());
    let s = j.begin_commit(&k, s.revision()).unwrap();
    let s = j.publication(&k, s.revision(), published()).unwrap();
    let receipt = s.receipt().unwrap().clone();
    assert_eq!(receipt.receipt_id, s.intent().unwrap());
    let s = j.publication(&k, s.revision(), published()).unwrap();
    assert_eq!(s.receipt(), Some(&receipt));
    let s = j.cancel(&k, s.revision()).unwrap();
    assert_eq!(s.phase(), Phase::Completed);
    j.into_connection();
    drop(c);
    let mut c = db(&p);
    let mut j = Journal::attach(&mut c, other()).unwrap();
    let r = j.recover_stopped_owner(owner()).unwrap();
    assert_eq!(r[0].phase(), Phase::CommitUnknown);
    assert_eq!(r[0].receipt(), Some(&receipt));
    assert!(j.confirm_removed(&k, r[0].revision()).is_err());
    // This scalar metadata case is not a physical publication/IO claim.
}
#[test]
fn uncertain_publication_and_mismatched_receipt_never_complete() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (k, s) = ready(&mut j, t.path());
    let s = j.begin_commit(&k, s.revision()).unwrap();
    assert!(
        j.publication(
            &k,
            s.revision(),
            Publication::Published {
                size: 4,
                sha256: job(t.path()).sha256,
                parent_sync: ParentSync::Unsupported
            }
        )
        .is_err()
    );
    let s = j
        .publication(
            &k,
            s.revision(),
            Publication::Uncertain {
                size: 3,
                sha256: job(t.path()).sha256,
                reason: "injected uncertainty",
            },
        )
        .unwrap();
    assert_eq!(s.phase(), Phase::CommitUnknown);
    assert!(s.receipt().is_none());
    assert!(s.stage().is_some());
}
#[test]
fn sqlite_abort_rolls_back_progress_and_returns_no_receipt() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (k, s) = ready(&mut j, t.path());
    let s = j.begin_commit(&k, s.revision()).unwrap();
    j.into_connection();
    c.execute_batch("CREATE TEMP TRIGGER fault BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'injected durable-write failure');END;").unwrap();
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    assert!(j.publication(&k, s.revision(), published()).is_err());
    let unchanged = j.get(&k).unwrap().unwrap();
    assert_eq!(unchanged.phase(), Phase::Committing);
    assert_eq!(unchanged.revision(), s.revision());
    assert!(unchanged.receipt().is_none());
    j.into_connection();
    c.execute_batch("DROP TRIGGER fault").unwrap();
}
#[test]
fn corrupted_payload_digest_revision_and_unknown_fields_are_refused() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (_, s) = j.admit(job(t.path()), 200).unwrap();
    let k = JobKey::from_job(s.job());
    let original = serde_json::to_value(&s).unwrap();
    j.into_connection();
    for field in ["version", "phase", "owner", "extra"] {
        let mut bad = original.clone();
        bad[field] = match field {
            "version" => serde_json::json!(99),
            "phase" => serde_json::json!("completed"),
            "owner" => serde_json::json!(Uuid::nil()),
            _ => serde_json::json!(true),
        };
        c.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [bad.to_string()])
            .unwrap();
        let j = Journal::attach(&mut c, owner()).unwrap();
        assert!(j.get(&k).is_err());
    }
    c.execute(
        "UPDATE ferroc_fleet_jobs_v1 SET body=?1",
        [original.to_string()],
    )
    .unwrap();
    c.execute("UPDATE ferroc_fleet_jobs_v1 SET digest=zeroblob(32)", [])
        .unwrap();
    let j = Journal::attach(&mut c, owner()).unwrap();
    assert!(j.get(&k).is_err());
}
#[test]
fn interrupted_recovery_quarantines_reference_without_deleting_or_resuming() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (k, s) = ready(&mut j, t.path());
    let path = s.stage().unwrap().path().to_path_buf();
    j.into_connection();
    let mut j = Journal::attach(&mut c, other()).unwrap();
    let rows = j.recover_stopped_owner(owner()).unwrap();
    assert_eq!(rows[0].phase(), Phase::Interrupted);
    assert!(path.exists());
    assert!(j.progress(&k, rows[0].revision(), 3).is_err());
    assert!(j.confirm_removed(&k, rows[0].revision()).is_err());
    assert!(j.recover_stopped_owner(other()).is_err());
    assert!(j.recover_stopped_owner(owner()).unwrap().is_empty());
}
#[test]
fn capacity_preserves_existing_ids_and_receipts_without_eviction() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    for i in 0..MAX_JOBS {
        let mut v = job(t.path());
        v.transfer_id = Uuid::new_v4();
        v.file_id = Uuid::new_v4();
        v.idempotency_key = format!("key-{i}");
        j.admit(v, 200).unwrap();
    }
    assert!(j.admit(job(t.path()), 200).is_err());
    let mut retry = job(t.path());
    retry.idempotency_key = "key-0".into();
    assert!(!j.admit(retry, 200).unwrap().0);
}
#[test]
fn unresolved_old_owner_and_cleanup_reservation_block_new_stage_admission() {
    let t = tempfile::tempdir().unwrap();
    let mut c = db(&t.path().join("db"));
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (old_key, old) = ready(&mut j, t.path());
    let old_path = old.stage().unwrap().path().to_path_buf();
    j.into_connection();
    let mut j = Journal::attach(&mut c, other()).unwrap();
    let mut fresh = job(t.path());
    fresh.transfer_id = Uuid::new_v4();
    fresh.file_id = Uuid::new_v4();
    fresh.idempotency_key = "another-job".into();
    let key = JobKey::from_job(&fresh);
    let (_, new) = j.admit(fresh, 200).unwrap();
    let path = t.path().join(".ferroc-fleet-next");
    fs::write(&path, b"abc").unwrap();
    let candidate = StageReference::observed_local(path, 3).unwrap();
    assert!(
        j.attach_stage(&key, new.revision(), candidate.clone())
            .is_err()
    );
    assert_eq!(j.get(&key).unwrap().unwrap().phase(), Phase::Queued);
    let recovered = j.recover_stopped_owner(owner()).unwrap();
    assert_eq!(recovered[0].phase(), Phase::Interrupted);
    assert!(
        j.attach_stage(&key, new.revision(), candidate.clone())
            .is_err()
    );
    assert!(
        j.confirm_removed(&old_key, recovered[0].revision())
            .is_err()
    );
    fs::remove_file(old_path).unwrap();
    j.confirm_removed(&old_key, recovered[0].revision())
        .unwrap();
    assert_eq!(
        j.attach_stage(&key, new.revision(), candidate)
            .unwrap()
            .phase(),
        Phase::Transferring
    );
}

#[test]
fn sql_cancel_ordering_guards_real_verified_stage_publication_not_just_metadata() {
    for cancel_first in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db");
        let mut c = db(&path);
        let mut j = Journal::attach(&mut c, owner()).unwrap();
        let spec = job(root.path());
        let key = JobKey::from_job(&spec);
        let (_, s) = j.admit(spec.clone(), 200).unwrap();
        let budget = StageBudget::new(3, 1).unwrap();
        let mut stage = StageFile::prepare(
            Policy::new(vec![root.path().into()], false).unwrap(),
            &spec.destination_path,
            3,
            &budget,
            Arc::default(),
        )
        .unwrap();
        let stage_path = stage.stage_path().to_path_buf();
        let s = j
            .attach_stage(
                &key,
                s.revision(),
                StageReference::observed_local(stage_path.clone(), 3).unwrap(),
            )
            .unwrap();
        stage.write_chunk(0, b"abc").unwrap();
        let verified = stage.verify_with(spec.sha256, || Ok(())).unwrap();
        let s = j.progress(&key, s.revision(), 3).unwrap();
        let s = j.readback(&key, s.revision(), verified.sha256()).unwrap();
        let revision = s.revision();
        if cancel_first {
            let cancelled = j.cancel(&key, revision).unwrap();
            let rejected = verified
                .publish_with(|| {
                    j.begin_commit(&key, revision)?;
                    Ok(())
                })
                .unwrap_err();
            assert!(!Path::new(&spec.destination_path).exists());
            assert!(stage_path.exists());
            assert_eq!(budget.usage().unwrap(), (3, 1));
            rejected.into_parts().0.into_stage().cancel().unwrap();
            let settled = j.confirm_removed(&key, cancelled.revision()).unwrap();
            assert_eq!(settled.phase(), Phase::Cancelled);
            assert!(settled.receipt().is_none());
        } else {
            let mut peer = db(&path);
            let peer_key = key.clone();
            let (start, wait) = std::sync::mpsc::channel();
            let (done, ack) = std::sync::mpsc::channel();
            let result = std::thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    wait.recv_timeout(Duration::from_secs(5)).unwrap();
                    let mut p = Journal::attach(&mut peer, owner()).unwrap();
                    let s = p.get(&peer_key).unwrap().unwrap();
                    let s = p.cancel(&peer_key, s.revision()).unwrap();
                    assert_eq!(s.phase(), Phase::CommitUnknown);
                    done.send(()).unwrap();
                });
                let result = verified.publish_with(|| {
                    j.begin_commit(&key, revision)?;
                    start.send(())?;
                    ack.recv_timeout(Duration::from_secs(5))?;
                    ensure!(
                        !Path::new(&spec.destination_path).exists(),
                        "publication not yet attempted"
                    );
                    Ok(())
                });
                worker.join().unwrap();
                result
            })
            .unwrap();
            assert!(matches!(result, Publication::Published { .. }));
            let current = j.get(&key).unwrap().unwrap();
            assert_eq!(current.phase(), Phase::CommitUnknown);
            let settled = j.publication(&key, current.revision(), result).unwrap();
            assert_eq!(settled.phase(), Phase::Completed);
            assert!(settled.receipt().is_some());
            assert_eq!(fs::read(&spec.destination_path).unwrap(), b"abc");
            assert_eq!(budget.usage().unwrap(), (0, 0));
        }
    }
}

#[test]
fn real_stage_publication_is_followed_by_committed_receipt_and_file_readback() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("db");
    let mut c = db(&p);
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let v = job(t.path());
    let k = JobKey::from_job(&v);
    let (_, s) = j.admit(v.clone(), 200).unwrap();
    let budget = StageBudget::new(3, 1).unwrap();
    let mut file = StageFile::prepare(
        Policy::new(vec![t.path().into()], false).unwrap(),
        &v.destination_path,
        3,
        &budget,
        Arc::new(Mutex::new(())),
    )
    .unwrap();
    let s = j
        .attach_stage(
            &k,
            s.revision(),
            StageReference::observed_local(file.stage_path().into(), 3).unwrap(),
        )
        .unwrap();
    file.write_chunk(0, b"abc").unwrap();
    let actual = Sha256::digest(fs::read(file.stage_path()).unwrap()).into();
    let s = j.progress(&k, s.revision(), file.bytes_received()).unwrap();
    let s = j.readback(&k, s.revision(), actual).unwrap();
    let s = j.begin_commit(&k, s.revision()).unwrap();
    assert!(!Path::new(&v.destination_path).exists());
    let publication = file.publish(v.sha256).unwrap();
    let s = j.publication(&k, s.revision(), publication).unwrap();
    assert_eq!(s.phase(), Phase::Completed);
    assert_eq!(s.receipt().unwrap().sha256, v.sha256);
    assert_eq!(fs::read(&v.destination_path).unwrap(), b"abc");
    assert_eq!(budget.usage().unwrap(), (0, 0));
}
#[test]
#[ignore = "unclean-exit helper; invoked only by parent with explicit file DB"]
fn journal_crash_child() {
    let path = std::env::var_os("FERROC_JOURNAL_PROBE_DB").expect("parent-owned DB");
    let action = std::env::var("FERROC_JOURNAL_PROBE_ACTION").unwrap();
    let root = Path::new(&path).parent().unwrap();
    let mut c = db(Path::new(&path));
    if action == "uncommitted" {
        c.execute_batch("BEGIN IMMEDIATE;UPDATE ferroc_fleet_jobs_v1 SET revision=revision+99;")
            .unwrap();
        std::process::exit(23);
    }
    let mut j = Journal::attach(&mut c, owner()).unwrap();
    let (k, s) = ready(&mut j, root);
    j.begin_commit(&k, s.revision()).unwrap();
    std::process::exit(0);
}
#[test]
fn independent_unclean_exit_recovers_intent_and_rolls_back_uncommitted_tx() {
    for action in ["intent", "uncommitted"] {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("db");
        let mut c = db(&path);
        let mut j = Journal::attach(&mut c, owner()).unwrap();
        let v = job(t.path());
        let k = JobKey::from_job(&v);
        j.admit(v, 200).unwrap();
        j.into_connection();
        drop(c);
        let mut log = tempfile::tempfile().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fleet::journal::tests::journal_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("FERROC_JOURNAL_PROBE_DB", &path)
            .env("FERROC_JOURNAL_PROBE_ACTION", action)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("journal child timeout; reaped");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        log.seek(SeekFrom::Start(0)).unwrap();
        let mut output = String::new();
        Read::by_ref(&mut log)
            .take(65537)
            .read_to_string(&mut output)
            .unwrap();
        assert!(output.len() <= 65536);
        assert_eq!(
            status.code(),
            Some(if action == "intent" { 0 } else { 23 }),
            "{output}"
        );
        let mut c = db(&path);
        let mut j = Journal::attach(&mut c, other()).unwrap();
        let s = j.get(&k).unwrap().unwrap();
        if action == "intent" {
            assert_eq!(s.phase(), Phase::Committing);
            let rows = j.recover_stopped_owner(owner()).unwrap();
            assert_eq!(rows[0].phase(), Phase::CommitUnknown);
            assert!(rows[0].stage().unwrap().path().exists());
        } else {
            assert_eq!(s.revision(), 0);
            assert_eq!(s.phase(), Phase::Queued);
        }
    }
}
