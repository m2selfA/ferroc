use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::{make_directory, new_private},
        job::{JobSpec, RoutePolicy},
        protocol::device_digest,
        state::Phase,
    },
};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};
fn fixture() -> (tempfile::TempDir, PathBuf, Runtime) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let path = root.join("relay.db");
    drop(new_private(&path).unwrap());
    let r = Runtime::new(Policy::new(vec![root], false).unwrap());
    (t, path, r)
}
fn job(path: &Path, n: u8) -> JobSpec {
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
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: format!("creator-{n}"),
    }
}
fn wait(host: &FleetHost<'_>, predicate: impl Fn(HostStatus) -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if predicate(host.status().unwrap()) {
            return;
        }
        assert!(Instant::now() < end, "bounded creator status wait");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn reserve(host: &FleetHost<'_>, path: &Path) -> Snapshot {
    host.resume().unwrap();
    assert!(
        host.admit_inner(job(path, 5), 200, |_| anyhow::bail!("precreate failure"))
            .is_err()
    );
    host.get(&JobKey::from_job(&job(path, 5))).unwrap().unwrap()
}
struct RestoreDb {
    original: PathBuf,
    parked: PathBuf,
}
impl RestoreDb {
    fn restore(&self) {
        if self.parked.exists() {
            if self.original.exists() {
                std::fs::rename(
                    &self.original,
                    self.original.with_extension("replacement-kept"),
                )
                .unwrap();
            }
            std::fs::rename(&self.parked, &self.original).unwrap();
        }
    }
}
impl Drop for RestoreDb {
    fn drop(&mut self) {
        self.restore();
    }
}
fn db_id(p: &Path) -> String {
    crate::fleet::fence::file_id(&crate::fleet::identity::open_private(p, false).unwrap()).unwrap()
}
#[test]
fn moved_database_parent_rejected_then_original_native_object_is_restored() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let id = db_id(&path);
    let proof = h.stop_creators().unwrap();
    drop(h);
    let other = path.parent().unwrap().join("moved");
    make_directory(&other).unwrap();
    let moved = other.join("relay.db");
    std::fs::rename(&path, &moved).unwrap();
    let rollback = RestoreDb {
        original: path.clone(),
        parked: moved.clone(),
    };
    assert_eq!(db_id(&moved), id);
    let next = r
        .open_fleet_host(&moved, InventoryLimits::default())
        .unwrap();
    let k = JobKey::from_job(s.job());
    assert!(next.recover_creators(proof).is_err());
    assert_eq!(next.get(&k).unwrap().unwrap().owner(), s.owner());
    next.close().unwrap();
    drop(next);
    rollback.restore();
    assert_eq!(db_id(&path), id);
    let restored = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(restored.get(&k).unwrap().unwrap().owner(), s.owner());
    assert_eq!(restored.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn replacement_at_original_path_rejected_then_original_database_restored() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let id = db_id(&path);
    let proof = h.stop_creators().unwrap();
    drop(h);
    let parked = path.with_file_name("original-parked.db");
    std::fs::rename(&path, &parked).unwrap();
    let rollback = RestoreDb {
        original: path.clone(),
        parked: parked.clone(),
    };
    let c = rusqlite::Connection::open(&parked).unwrap();
    c.execute("VACUUM INTO ?1", [path.to_str().unwrap()])
        .unwrap();
    drop(c);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // VACUUM creates a new file with SQLite's default mode, not the source mode.
        // Make this owned fixture admissible before testing database identity.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_ne!(db_id(&path), id);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let key = JobKey::from_job(s.job());
    assert!(next.recover_creators(proof).is_err());
    assert_eq!(next.get(&key).unwrap().unwrap().owner(), s.owner());
    next.close().unwrap();
    drop(next);
    rollback.restore();
    assert_eq!(db_id(&path), id);
    let restored = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(restored.get(&key).unwrap().unwrap().owner(), s.owner());
    assert_eq!(restored.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn database_poison_never_mints_a_stop_proof_or_releases_native_lock() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.resume().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = h.admit_inner(job(&path, 5), 200, |_| {
            panic!("intentional creator DB poison")
        });
    }));
    assert!(result.is_err());
    assert!(h.stop_creators().is_err());
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert!(OwnerFence::acquire(&path).is_err());
    drop(h);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
    assert!(next.resume().is_err());
}
#[test]
fn proof_counts_creators_already_queued_behind_the_database_mutex() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.resume().unwrap();
    let (tx, rx) = mpsc::channel();
    let (go, ready) = mpsc::channel();
    let proof = std::thread::scope(|scope| {
        let old = &h;
        let p = &path;
        let first = scope.spawn(move || {
            old.admit_inner(job(p, 5), 200, |_| {
                tx.send(())?;
                ready.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            })
        });
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let old = &h;
        let p = &path;
        let queued = scope.spawn(move || old.admit(job(p, 7), 200));
        wait(&h, |s| s.in_flight == 2);
        let old = &h;
        let stopped = scope.spawn(move || old.stop_creators());
        wait(&h, |s| s.mode == HostMode::Closing);
        assert!(h.admit(job(&path, 9), 200).is_err());
        go.send(()).unwrap();
        assert!(first.join().unwrap().is_ok());
        assert!(queued.join().unwrap().is_err());
        stopped.join().unwrap().unwrap()
    });
    assert_eq!(h.status().unwrap().in_flight, 0);
    drop(h);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let rows = next.recover_creators(proof).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn proof_recovery_waits_actual_gate_and_runtime_shutdown_drains_it() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let _s = reserve(&h, &path);
    let proof = h.stop_creators().unwrap();
    drop(h);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let gate = r.test_fs_gate();
    let held = gate.lock().unwrap();
    std::thread::scope(|scope| {
        let host = &next;
        let recovery = scope.spawn(move || host.recover_creators(proof));
        wait(&next, |s| s.in_flight == 1);
        let (tx, rx) = mpsc::channel();
        let runtime = &r;
        let stopping = scope.spawn(move || {
            let engine = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            engine.block_on(runtime.shutdown_fleet_host()).unwrap();
            tx.send(()).unwrap();
        });
        wait(&next, |s| s.mode == HostMode::Closing);
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(held);
        assert_eq!(recovery.join().unwrap().unwrap().len(), 1);
        stopping.join().unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    assert_eq!(next.status().unwrap().in_flight, 0);
    assert!(OwnerFence::acquire(&path).is_err());
    next.close().unwrap();
}
#[test]
fn disabled_transfers_allow_proved_metadata_recovery_not_resume() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let _s = reserve(&h, &path);
    let proof = h.stop_creators().unwrap();
    drop(h);
    let mut p = r.policy.clone();
    p.allow_transfers = false;
    let disabled = Runtime::new(p);
    let next = disabled
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let rows = next.recover_creators(proof).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(next.status().unwrap().mode, HostMode::Paused);
    assert!(next.resume().is_err());
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn runtime_shutdown_drain_still_requires_fresh_terminal_close_to_issue_proof() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    engine.block_on(r.shutdown_fleet_host()).unwrap();
    assert_eq!(h.status().unwrap().mode, HostMode::Closing);
    assert!(OwnerFence::acquire(&path).is_err());
    let proof = h.stop_creators().unwrap();
    assert_eq!(proof.origin_owner(), s.owner());
    assert_eq!(h.status().unwrap().mode, HostMode::Closed);
    assert!(h.stop_creators().is_err());
    drop(h);
    assert!(
        r.open_fleet_host(&path, InventoryLimits::default())
            .is_err()
    );
    let other = Runtime::new(r.policy.clone());
    let next = other
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(next.recover_creators(proof).unwrap().len(), 1);
    assert!(next.resume().is_err());
}

#[test]
fn concurrent_terminal_proof_issuance_has_exactly_one_winner() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let proofs = std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let host = &h;
                scope.spawn(move || host.stop_creators())
            })
            .collect();
        tasks
            .into_iter()
            .filter_map(|t| t.join().unwrap().ok())
            .collect::<Vec<_>>()
    });
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].origin_owner(), s.owner());
    assert_eq!(h.status().unwrap().mode, HostMode::Closed);
    assert!(h.stop_creators().is_err());
    drop(h);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(
        next.recover_creators(proofs.into_iter().next().unwrap())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
}

#[test]
fn terminal_proof_new_fence_metadata_recovery_and_separate_absence_approval() {
    let (_t, path, r) = fixture();
    let old = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&old, &path);
    let key = JobKey::from_job(s.job());
    let prior = old.inspect_allocation(&key).unwrap().fingerprint();
    let proof = old.stop_creators().unwrap();
    assert_eq!(proof.origin_owner(), s.owner());
    assert_eq!(old.status().unwrap().mode, HostMode::Closed);
    assert!(old.stop_creators().is_err());
    assert!(old.resume().is_err());
    assert!(
        r.open_fleet_host(&path, InventoryLimits::default())
            .is_err()
    );
    drop(old);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let rows = next.recover_creators(proof).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_ne!(row.owner(), s.owner());
    assert_eq!(row.stage(), s.stage());
    assert_eq!(next.status().unwrap().mode, HostMode::Paused);
    assert!(next.resume().is_err());
    assert!(
        next.release_absent_allocation(
            &key,
            row.revision(),
            AbsenceApproval::approve_expected_fingerprint(prior)
        )
        .is_err()
    );
    let report = next.inspect_allocation(&key).unwrap();
    assert!(report.eligible_for_absence_release());
    let done = next
        .release_absent_allocation(
            &key,
            row.revision(),
            AbsenceApproval::approve_expected_fingerprint(report.fingerprint()),
        )
        .unwrap();
    assert_eq!(done.phase(), Phase::Cancelled);
    assert!(done.absence_release().is_some());
    next.resume().unwrap();
    assert!(next.admit(job(&path, 7), 200).is_ok());
}
#[test]
fn proof_waits_for_accepted_creator_and_never_retires_its_present_file() {
    let (_t, path, r) = fixture();
    let old = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    old.resume().unwrap();
    let (tx, rx) = mpsc::channel();
    let (go, ready) = mpsc::channel();
    let (proof_tx, proof_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let h = &old;
        let p = &path;
        let work = scope.spawn(move || {
            h.admit_inner(job(p, 5), 200, |_| {
                tx.send(())?;
                ready.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            })
        });
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let h = &old;
        let stopping = scope.spawn(move || proof_tx.send(h.stop_creators().unwrap()).unwrap());
        wait(&old, |s| s.mode == HostMode::Closing);
        assert!(proof_rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(OwnerFence::acquire(&path).is_err());
        go.send(()).unwrap();
        let s = work.join().unwrap().unwrap().snapshot;
        stopping.join().unwrap();
        let proof = proof_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(s.stage().unwrap().path().exists());
        let other = Runtime::new(r.policy.clone());
        let next = other
            .open_fleet_host(&path, InventoryLimits::default())
            .unwrap();
        let row = next.recover_creators(proof).unwrap().pop().unwrap();
        let key = JobKey::from_job(row.job());
        let report = next.inspect_allocation(&key).unwrap();
        assert!(!report.eligible_for_absence_release());
        assert!(
            next.release_absent_allocation(
                &key,
                row.revision(),
                AbsenceApproval::approve_expected_fingerprint(report.fingerprint())
            )
            .is_err()
        );
        assert!(row.stage().unwrap().path().exists());
        assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
    });
}
#[test]
fn previously_plain_closed_host_cannot_reconstruct_creator_proof() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.close().unwrap();
    assert!(h.stop_creators().is_err());
    assert!(h.close().is_ok());
    assert!(OwnerFence::acquire(&path).is_ok());
}
#[test]
fn gate_poison_mints_no_proof_and_keeps_fence_until_plain_close() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let gate = r.test_fs_gate();
    let _ = std::thread::spawn(move || {
        let _g = gate.lock().unwrap();
        panic!("intentional gate poison for stop");
    })
    .join();
    assert!(h.stop_creators().is_err());
    assert_eq!(h.status().unwrap().mode, HostMode::Closing);
    assert!(OwnerFence::acquire(&path).is_err());
    h.close().unwrap();
    assert!(h.stop_creators().is_err());
    assert!(!s.stage().unwrap().path().exists());
    assert!(OwnerFence::acquire(&path).is_ok());
}
#[test]
fn copied_database_rejects_proof_before_any_metadata_recovery() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let copy = path.with_file_name("copy.db");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("VACUUM INTO ?1", [copy.to_str().unwrap()])
        .unwrap();
    drop(c);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The copied database must pass file admission before recovery can be tested.
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let proof = h.stop_creators().unwrap();
    drop(h);
    let next = r
        .open_fleet_host(&copy, InventoryLimits::default())
        .unwrap();
    let key = JobKey::from_job(s.job());
    let before = serde_json::to_value(next.get(&key).unwrap().unwrap()).unwrap();
    assert!(next.recover_creators(proof).is_err());
    assert_eq!(
        serde_json::to_value(next.get(&key).unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn reappeared_file_after_proof_and_inspection_keeps_original_reservation() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let key = JobKey::from_job(s.job());
    let proof = h.stop_creators().unwrap();
    drop(h);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let row = next.recover_creators(proof).unwrap().pop().unwrap();
    let report = next.inspect_allocation(&key).unwrap();
    let mut file = new_private(row.stage().unwrap().path()).unwrap();
    file.write_all(b"xyz").unwrap();
    drop(file);
    assert!(
        next.release_absent_allocation(
            &key,
            row.revision(),
            AbsenceApproval::approve_expected_fingerprint(report.fingerprint())
        )
        .is_err()
    );
    assert_eq!(
        serde_json::to_value(next.get(&key).unwrap().unwrap()).unwrap(),
        serde_json::to_value(&row).unwrap()
    );
    assert_eq!(std::fs::read(row.stage().unwrap().path()).unwrap(), b"xyz");
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn sql_recovery_failure_consumes_proof_but_preserves_all_rows_and_debt() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let s = reserve(&h, &path);
    let key = JobKey::from_job(s.job());
    let proof = h.stop_creators().unwrap();
    drop(h);
    let next = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TRIGGER reject_creator_recovery BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'creator recovery failure');END;").unwrap();
    assert!(next.recover_creators(proof).is_err());
    assert_eq!(
        serde_json::to_value(next.get(&key).unwrap().unwrap()).unwrap(),
        serde_json::to_value(&s).unwrap()
    );
    assert_eq!(next.status().unwrap().in_flight, 0);
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
}
