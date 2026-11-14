use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::{make_directory, new_private},
        inventory::InventoryLimits,
        job::{JobSpec, RoutePolicy},
        journal::JobKey,
        protocol::device_digest,
        state::Phase,
    },
    runtime::Runtime,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::{Child, Command, Stdio};
use std::time::Instant;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    time::Duration,
};
fn fixture() -> (tempfile::TempDir, PathBuf, Runtime) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let db = root.join("relay.db");
    drop(new_private(&db).unwrap());
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("CREATE TABLE sentinel(v TEXT);INSERT INTO sentinel VALUES('keep');")
        .unwrap();
    drop(c);
    let runtime = Runtime::new(Policy::new(vec![root], false).unwrap());
    (t, db, runtime)
}
fn job(path: &Path, n: u8, bytes: u64) -> JobSpec {
    let root = path.parent().unwrap();
    JobSpec {
        version: 1,
        fleet_id: uuid::Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: uuid::Uuid::from_bytes([n; 16]),
        file_id: uuid::Uuid::from_bytes([n + 1; 16]),
        source_path: root.join(format!("source{n}")).to_str().unwrap().into(),
        destination_path: root.join(format!("target{n}")).to_str().unwrap().into(),
        bytes_total: bytes,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: format!("host-{n}"),
    }
}
fn wait_status(host: &FleetHost<'_>, predicate: impl Fn(HostStatus) -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let state = host.status().unwrap();
        if predicate(state) {
            break;
        }
        assert!(Instant::now() < until, "host status wait bounded");
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
fn failed_open_and_bad_limits_release_runtime_attachment_before_retry() {
    let (_t, path, runtime) = fixture();
    assert!(
        runtime
            .open_fleet_host(
                &path.with_file_name("missing.db"),
                InventoryLimits::default()
            )
            .is_err()
    );
    assert!(
        runtime
            .open_fleet_host(
                &path,
                InventoryLimits {
                    max_active: 0,
                    ..Default::default()
                }
            )
            .is_err()
    );
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(host.status().unwrap().mode, HostMode::Paused);
}
#[test]
fn second_runtime_same_database_cannot_bypass_native_fence() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let other = Runtime::new(runtime.policy.clone());
    assert!(
        other
            .open_fleet_host(&path, InventoryLimits::default())
            .is_err()
    );
    host.close().unwrap();
    let next = other
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(next.status().unwrap().mode, HostMode::Paused);
}
#[test]
fn host_and_actual_runtime_write_both_wait_for_the_same_real_fs_gate() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let gate = runtime.test_fs_gate();
    assert!(Arc::ptr_eq(&host.gate, &gate));
    let held = gate.lock().unwrap();
    let output = path.with_file_name("runtime-write.txt");
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        let h = &host;
        let p = &path;
        let admitted = scope.spawn(move || {
            let result = h.admit(job(p, 5, 3), 200);
            tx.send(result.is_ok()).unwrap();
            result
        });
        wait_status(&host, |s| s.in_flight == 1);
        let (done, written) = mpsc::channel();
        let r = &runtime;
        let output1 = &output;
        let writer = scope.spawn(move || {
            let engine = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = engine.block_on(r.call(
                "write_file",
                serde_json::json!({"path":output1,"content":"actual-runtime"}),
            ));
            done.send(result.is_error != Some(true)).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(written.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(!output.exists());
        drop(held);
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
        assert!(written.recv_timeout(Duration::from_secs(10)).unwrap());
        assert!(admitted.join().unwrap().is_ok());
        writer.join().unwrap();
    });
    assert_eq!(std::fs::read(&output).unwrap(), b"actual-runtime");
}
#[test]
fn same_job_concurrent_admissions_replay_without_creating_another_file() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let host = &host;
                let path = &path;
                scope.spawn(move || host.admit(job(path, 5, 3), 200).unwrap())
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.new_job).count(), 1);
    assert_eq!(results[0].snapshot.stage(), results[1].snapshot.stage());
    assert_eq!(host.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn distinct_jobs_concurrent_admissions_cannot_reset_persistent_budget() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let wins = std::thread::scope(|scope| {
        let handles: Vec<_> = [5, 7]
            .into_iter()
            .map(|n| {
                let host = &host;
                let path = &path;
                scope.spawn(move || host.admit(job(path, n, 3), 200).is_ok())
            })
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(wins, 1);
    assert_eq!(host.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn fixed_byte_limit_rejects_and_queued_replay_never_retries_creation() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(
            &path,
            InventoryLimits {
                byte_limit: 2,
                ..Default::default()
            },
        )
        .unwrap();
    host.resume().unwrap();
    assert!(host.admit(job(&path, 5, 3), 200).is_err());
    let k = JobKey::from_job(&job(&path, 5, 3));
    let queued = host.get(&k).unwrap().unwrap();
    assert_eq!(queued.phase(), Phase::Queued);
    assert!(queued.stage().is_none());
    let replay = host.admit(job(&path, 5, 3), 200).unwrap();
    assert!(!replay.new_job);
    assert!(replay.snapshot.stage().is_none());
    assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
    assert!(host.admit(job(&path, 7, 2), 200).is_ok());
}
#[test]
fn failed_creation_retains_absent_debt_until_close_takeover_and_explicit_release() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    assert!(
        host.admit_inner(job(&path, 5, 3), 200, |_| anyhow::bail!(
            "injected precreate failure"
        ))
        .is_err()
    );
    let key = JobKey::from_job(&job(&path, 5, 3));
    let reserved = host.get(&key).unwrap().unwrap();
    assert!(!reserved.stage().unwrap().path().exists());
    let report = host.inspect_allocation(&key).unwrap();
    assert!(!report.origin_stopped());
    assert!(
        host.release_absent_allocation(
            &key,
            reserved.revision(),
            AbsenceApproval::approve_expected_fingerprint(report.fingerprint())
        )
        .is_err()
    );
    host.pause().unwrap();
    assert!(host.resume().is_err());
    let old = reserved.owner();
    host.close().unwrap();
    drop(host);
    let next = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert!(next.resume().is_err());
    let s = next.recover_stopped_owner(old).unwrap().pop().unwrap();
    let report = next.inspect_allocation(&key).unwrap();
    assert!(report.eligible_for_absence_release());
    let released = next
        .release_absent_allocation(
            &key,
            s.revision(),
            AbsenceApproval::approve_expected_fingerprint(report.fingerprint()),
        )
        .unwrap();
    assert_eq!(released.phase(), Phase::Cancelled);
    assert!(released.absence_release().is_some());
    next.resume().unwrap();
    assert!(next.admit(job(&path, 7, 0), 200).is_ok());
}
#[test]
fn sql_binding_failure_retains_empty_object_and_full_debt_without_poison() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let result=host.admit_inner(job(&path,5,3),200,|_|{let c=rusqlite::Connection::open(&path)?;c.execute_batch("CREATE TRIGGER reject_host_binding BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'host bind fault');END;")?;Ok(())});
    assert!(result.is_err());
    let s = host
        .get(&JobKey::from_job(&job(&path, 5, 3)))
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"");
    assert!(s.stage().unwrap().allocation().unwrap().file_id().is_none());
    assert_eq!(host.inventory().unwrap().recorded_usage(), (3, 1));
    assert_eq!(host.status().unwrap().in_flight, 0);
}
#[test]
fn actual_runtime_destination_mutation_between_phases_denies_create_retaining_obligation() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let result = host.admit_inner(job(&path, 5, 3), 200, |s| {
        let engine = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let r = engine.block_on(runtime.call(
            "write_file",
            serde_json::json!({"path":s.job().destination_path,"content":"keep"}),
        ));
        anyhow::ensure!(r.is_error != Some(true), "actual runtime write failed");
        Ok(())
    });
    assert!(result.is_err());
    let s = host
        .get(&JobKey::from_job(&job(&path, 5, 3)))
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(&s.job().destination_path).unwrap(), b"keep");
    assert!(!s.stage().unwrap().path().exists());
    assert_eq!(host.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn pause_allows_cancel_but_never_deletes_or_releases_same_origin_empty_stage() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let admitted = host.admit(job(&path, 5, 3), 200).unwrap();
    let key = JobKey::from_job(admitted.snapshot.job());
    host.pause().unwrap();
    let canceled = host.cancel(&key, admitted.snapshot.revision()).unwrap();
    assert_eq!(canceled.phase(), Phase::CancelRequested);
    assert!(canceled.stage().unwrap().path().exists());
    assert!(host.resume().is_err());
    let report = host.inspect_allocation(&key).unwrap();
    assert!(
        host.release_absent_allocation(
            &key,
            canceled.revision(),
            AbsenceApproval::approve_expected_fingerprint(report.fingerprint())
        )
        .is_err()
    );
    assert_eq!(host.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn unknown_stage_blocks_resume_without_touching_foreign_bytes() {
    let (_t, path, runtime) = fixture();
    let foreign = path.with_file_name(".ferroc-fleet-unknown-host");
    let mut f = new_private(&foreign).unwrap();
    f.write_all(b"keep").unwrap();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert!(host.resume().is_err());
    assert!(!host.inventory().unwrap().complete());
    assert_eq!(std::fs::read(&foreign).unwrap(), b"keep");
    assert_eq!(host.status().unwrap().mode, HostMode::Paused);
}
#[test]
fn actual_gate_poison_refuses_admission_without_silent_replacement_and_close_still_drains() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let gate = runtime.test_fs_gate();
    let _ = std::thread::spawn(move || {
        let _held = gate.lock().unwrap();
        panic!("intentional real runtime gate poison");
    })
    .join();
    assert!(host.admit(job(&path, 5, 3), 200).is_err());
    let s = host
        .get(&JobKey::from_job(&job(&path, 5, 3)))
        .unwrap()
        .unwrap();
    assert!(s.stage().is_none());
    assert!(host.inventory().is_err());
    assert_eq!(host.status().unwrap().in_flight, 0);
    host.close().unwrap();
    assert!(crate::fleet::fence::OwnerFence::acquire(&path).is_ok());
}
#[test]
fn panic_after_reservation_poison_keeps_fence_until_drop_and_does_not_zero_debt() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = host.admit_inner(job(&path, 5, 3), 200, |_| {
            panic!("intentional precreate panic")
        });
    }));
    assert!(panicked.is_err());
    assert_eq!(host.status().unwrap().in_flight, 0);
    assert!(host.get(&JobKey::from_job(&job(&path, 5, 3))).is_err());
    assert!(host.close().is_err());
    assert!(crate::fleet::fence::OwnerFence::acquire(&path).is_err());
    drop(host);
    let fence = crate::fleet::fence::OwnerFence::acquire(&path).unwrap();
    let mut db = fence.open_connection().unwrap();
    let s = db
        .journal()
        .unwrap()
        .get(&JobKey::from_job(&job(&path, 5, 3)))
        .unwrap()
        .unwrap();
    assert_eq!(s.stage().unwrap().reserved_bytes(), 3);
    assert!(!s.stage().unwrap().path().exists());
}
#[test]
fn close_drains_operations_already_queued_behind_database_then_rejects_new_work() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let (entered, ready) = mpsc::channel();
    let (go, proceed) = mpsc::channel();
    std::thread::scope(|scope| {
        let h = &host;
        let p = &path;
        let first = scope.spawn(move || {
            h.admit_inner(job(p, 5, 3), 200, |_| {
                entered.send(())?;
                proceed.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            })
        });
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
        let h = &host;
        let p = &path;
        let queued = scope.spawn(move || h.admit(job(p, 7, 0), 200));
        wait_status(&host, |s| s.in_flight == 2);
        let h = &host;
        let closing = scope.spawn(move || h.close());
        wait_status(&host, |s| s.mode == HostMode::Closing);
        assert!(host.admit(job(&path, 9, 0), 200).is_err());
        go.send(()).unwrap();
        assert!(first.join().unwrap().is_ok());
        assert!(queued.join().unwrap().is_err());
        closing.join().unwrap().unwrap();
    });
    assert_eq!(host.status().unwrap().mode, HostMode::Closed);
    assert_eq!(host.status().unwrap().in_flight, 0);
}
#[test]
fn drop_without_close_preserves_stage_and_next_host_cannot_auto_resume() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let admitted = host.admit(job(&path, 5, 3), 200).unwrap();
    let stage = admitted.snapshot.stage().unwrap().path().to_owned();
    drop(host);
    assert!(stage.exists());
    let next = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert!(next.resume().is_err());
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
    assert_eq!(std::fs::read(stage).unwrap(), b"");
}
#[test]
fn disabled_transfers_can_open_readonly_host_but_never_resume_admission() {
    let (_t, path, mut runtime) = fixture();
    runtime.policy.allow_transfers = false;
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert!(host.inventory().unwrap().complete());
    assert!(host.resume().is_err());
    assert!(host.admit(job(&path, 5, 0), 200).is_err());
    host.close().unwrap();
}
#[test]
#[ignore = "bounded Runtime-host no-drop subprocess helper invoked by parent"]
fn host_process_child() {
    let path = PathBuf::from(std::env::var_os("FERROC_HOST_DB").unwrap());
    let mode = std::env::var("FERROC_HOST_MODE").unwrap();
    let runtime = Runtime::new(Policy::new(vec![path.parent().unwrap().into()], false).unwrap());
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    if mode == "reserved" {
        let _ = host.admit_inner(job(&path, 5, 3), 200, |_| std::process::exit(37));
    } else {
        host.admit(job(&path, 5, 3), 200).unwrap();
        std::process::exit(38);
    }
}
struct Process {
    child: Child,
    log: std::fs::File,
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
                panic!("host child timeout/reaped");
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
#[test]
fn actual_host_process_crash_preserves_debt_and_only_absent_case_can_settle_after_takeover() {
    for mode in ["reserved", "bound"] {
        let (_t, path, runtime) = fixture();
        let log = tempfile::tempfile().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fleet::host::tests::host_process_child",
                "--ignored",
                "--nocapture",
            ])
            .env("FERROC_HOST_DB", &path)
            .env("FERROC_HOST_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let mut child = Process { child, log };
        assert_eq!(
            child.wait().code(),
            Some(if mode == "reserved" { 37 } else { 38 }),
            "{}",
            child.output()
        );
        let host = runtime
            .open_fleet_host(&path, InventoryLimits::default())
            .unwrap();
        assert!(host.resume().is_err());
        let key = JobKey::from_job(&job(&path, 5, 3));
        let old = host.get(&key).unwrap().unwrap();
        let s = host
            .recover_stopped_owner(old.owner())
            .unwrap()
            .pop()
            .unwrap();
        let report = host.inspect_allocation(&key).unwrap();
        assert_eq!(report.eligible_for_absence_release(), mode == "reserved");
        let outcome = host.release_absent_allocation(
            &key,
            s.revision(),
            AbsenceApproval::approve_expected_fingerprint(report.fingerprint()),
        );
        assert_eq!(outcome.is_ok(), mode == "reserved");
        if mode == "reserved" {
            host.resume().unwrap();
        } else {
            assert!(s.stage().unwrap().path().exists());
            assert_eq!(host.inventory().unwrap().recorded_usage(), (3, 1));
        }
    }
}

#[test]
fn actual_runtime_shutdown_stops_and_drains_host_without_forgiving_debt_or_unfencing() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let (entered, ready) = mpsc::channel();
    let (go, proceed) = mpsc::channel();
    std::thread::scope(|scope| {
        let h = &host;
        let p = &path;
        let accepted = scope.spawn(move || {
            h.admit_inner(job(p, 5, 3), 200, |_| {
                entered.send(())?;
                proceed.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            })
        });
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
        let (done, stopped) = mpsc::channel();
        let r = &runtime;
        let shutdown = scope.spawn(move || {
            let engine = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            engine.block_on(r.shutdown());
            done.send(()).unwrap();
        });
        wait_status(&host, |s| s.mode == HostMode::Closing);
        assert!(stopped.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(host.admit(job(&path, 7, 0), 200).is_err());
        go.send(()).unwrap();
        let admitted = accepted.join().unwrap().unwrap();
        shutdown.join().unwrap();
        stopped.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(admitted.snapshot.stage().unwrap().path().exists());
    });
    assert_eq!(host.status().unwrap().in_flight, 0);
    assert_eq!(host.status().unwrap().mode, HostMode::Closing);
    assert!(crate::fleet::fence::OwnerFence::acquire(&path).is_err());
    host.close().unwrap();
    drop(host);
    assert!(
        runtime
            .open_fleet_host(&path, InventoryLimits::default())
            .is_err()
    );
    let next_runtime = Runtime::new(runtime.policy.clone());
    let next = next_runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert!(next.resume().is_err());
    assert_eq!(next.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn runtime_shutdown_before_attachment_is_terminal_and_does_not_create_fleet_schema() {
    let (_t, path, runtime) = fixture();
    let c = rusqlite::Connection::open(&path).unwrap();
    let before = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    engine.block_on(runtime.shutdown_fleet_host()).unwrap();
    engine.block_on(runtime.shutdown_fleet_host()).unwrap();
    assert!(
        runtime
            .open_fleet_host(&path, InventoryLimits::default())
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        before
    );
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='ferroc_fleet_meta'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn runtime_shutdown_waits_for_already_accepted_host_construction() {
    let (_t, path, runtime) = fixture();
    let gate = runtime.test_fs_gate();
    let held = gate.lock().unwrap();
    let registration = runtime.test_fleet_registration();
    std::thread::scope(|scope| {
        let r = &runtime;
        let p = &path;
        let opening =
            scope.spawn(move || r.open_fleet_host(p, InventoryLimits::default()).unwrap());
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if matches!(
                registration.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ) {
                break;
            }
            assert!(
                Instant::now() < until,
                "constructor did not claim lifecycle registration"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let (done, completed) = mpsc::channel();
        let r = &runtime;
        let shutdown = scope.spawn(move || {
            let engine = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            engine.block_on(r.shutdown_fleet_host()).unwrap();
            done.send(()).unwrap();
        });
        assert!(completed.recv_timeout(Duration::from_millis(50)).is_err());
        drop(held);
        let host = opening.join().unwrap();
        shutdown.join().unwrap();
        completed.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(host.status().unwrap().mode, HostMode::Closing);
        assert_eq!(host.status().unwrap().in_flight, 0);
        assert!(host.admit(job(&path, 5, 0), 200).is_err());
        assert!(crate::fleet::fence::OwnerFence::acquire(&path).is_err());
        host.close().unwrap();
    });
    assert!(
        runtime
            .open_fleet_host(&path, InventoryLimits::default())
            .is_err()
    );
}

#[test]
fn default_pause_blocks_new_jobs_until_explicit_clean_resume() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert_eq!(host.status().unwrap().mode, HostMode::Paused);
    let j = job(&path, 5, 3);
    let k = JobKey::from_job(&j);
    assert!(host.admit(j.clone(), 200).is_err());
    assert!(host.get(&k).unwrap().is_none());
    host.resume().unwrap();
    let result = host.admit(j, 200).unwrap();
    assert!(result.new_job);
    assert_eq!(result.snapshot.phase(), Phase::Interrupted);
    assert_eq!(result.snapshot.received(), 0);
    assert_eq!(
        std::fs::read(result.snapshot.stage().unwrap().path()).unwrap(),
        b""
    );
}
#[test]
fn one_runtime_cannot_open_second_host_even_for_another_database() {
    let (_t, path, runtime) = fixture();
    let second = path.with_file_name("second.db");
    drop(new_private(&second).unwrap());
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    assert!(
        runtime
            .open_fleet_host(&second, InventoryLimits::default())
            .is_err()
    );
    host.close().unwrap();
    assert!(
        runtime
            .open_fleet_host(&second, InventoryLimits::default())
            .is_err()
    );
    drop(host);
    let host = runtime
        .open_fleet_host(&second, InventoryLimits::default())
        .unwrap();
    assert_eq!(host.status().unwrap().mode, HostMode::Paused);
}
#[test]
fn pause_rejects_new_admission_but_accepted_creation_finishes() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let (entered, ready) = mpsc::channel();
    let (go, proceed) = mpsc::channel();
    std::thread::scope(|scope| {
        let h = &host;
        let p = &path;
        let accepted = scope.spawn(move || {
            h.admit_inner(job(p, 5, 3), 200, |_| {
                entered.send(())?;
                proceed.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            })
        });
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
        host.pause().unwrap();
        assert_eq!(host.status().unwrap().in_flight, 1);
        assert!(host.admit(job(&path, 7, 0), 200).is_err());
        go.send(()).unwrap();
        assert!(accepted.join().unwrap().is_ok());
    });
    assert_eq!(host.status().unwrap().mode, HostMode::Paused);
    assert_eq!(host.status().unwrap().in_flight, 0);
}
#[test]
fn close_waits_for_creation_then_releases_native_lock_not_debt() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let (entered, ready) = mpsc::channel();
    let (go, proceed) = mpsc::channel();
    std::thread::scope(|scope| {
        let h = &host;
        let p = &path;
        let accepted = scope.spawn(move || {
            h.admit_inner(job(p, 5, 3), 200, |_| {
                entered.send(())?;
                proceed.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            })
        });
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
        let (tx, rx) = mpsc::channel();
        let h = &host;
        let closing = scope.spawn(move || {
            h.close().unwrap();
            tx.send(()).unwrap();
        });
        wait_status(&host, |s| s.mode == HostMode::Closing);
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(crate::fleet::fence::OwnerFence::acquire(&path).is_err());
        go.send(()).unwrap();
        let admitted = accepted.join().unwrap().unwrap();
        closing.join().unwrap();
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(admitted.snapshot.stage().unwrap().path().exists());
    });
    assert_eq!(host.status().unwrap().mode, HostMode::Closed);
    assert!(host.resume().is_err());
    assert!(host.inventory().is_err());
    let fence = crate::fleet::fence::OwnerFence::acquire(&path).unwrap();
    let mut db = fence.open_connection().unwrap();
    let k = JobKey::from_job(&job(&path, 5, 3));
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
