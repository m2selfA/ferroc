use super::*;
#[cfg(windows)]
#[path = "owned_publish_tests.rs"]
mod owned_publish_tests;
use crate::fleet::host::HostMode;
fn candidate<'h, 'r>(h: &'h FleetHost<'r>, p: &Path, data: &[u8]) -> CommitCandidate<'h, 'r> {
    sealed(h, p, data).prepare_commit().unwrap()
}
fn wait_closing(h: &FleetHost<'_>) {
    let start = Instant::now();
    while h.status().unwrap().mode != HostMode::Closing {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::yield_now();
    }
}
#[test]
fn retains_original_object_and_single_operation_without_schema_change() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let recv = sealed(&h, &p, b"abc");
    let id = file_id(&recv.inner.file).unwrap();
    let before = recv.snapshot().clone();
    let mut c = recv.prepare_commit().unwrap();
    assert_eq!(schema(&p), 6);
    assert_eq!(c.snapshot().revision(), before.revision() + 1);
    assert_eq!(c.snapshot().stage(), before.stage());
    assert_eq!(
        c.snapshot()
            .stage()
            .unwrap()
            .allocation()
            .unwrap()
            .file_id(),
        Some(id.as_str())
    );
    assert_eq!(h.status().unwrap().in_flight, 1);
    let raw = serde_json::to_string(c.snapshot()).unwrap();
    assert_eq!(c.observe().unwrap().bytes_read(), 3);
    assert_eq!(
        c.observe().unwrap().observed_sha256().as_slice(),
        Sha256::digest(b"abc").as_slice()
    );
    let s = c.snapshot().clone();
    drop(c);
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert_eq!(
        serde_json::to_string(&h.get(&JobKey::from_job(s.job())).unwrap().unwrap()).unwrap(),
        raw
    );
    assert!(!Path::new(&s.job().destination_path).exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[cfg(windows)]
#[tokio::test]
async fn native_handle_denies_move_until_drop_and_never_removes_substitute() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let s = c.snapshot().clone();
    let path = s.stage().unwrap().path().to_owned();
    let moved = p.with_file_name("candidate-moved");
    let out = r
        .call(
            "move_file",
            serde_json::json!({"source":path,"destination":moved}),
        )
        .await;
    assert_eq!(out.is_error, Some(true), "{out:?}");
    assert!(format!("{out:?}").contains("os error 32"));
    drop(c);
    let out = r
        .call(
            "move_file",
            serde_json::json!({"source":path,"destination":moved}),
        )
        .await;
    assert_ne!(out.is_error, Some(true), "{out:?}");
    let out = r
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(out.is_error, Some(true));
    drop(s);
    assert_eq!(std::fs::read(path).unwrap(), b"xyz");
    assert_eq!(std::fs::read(moved).unwrap(), b"abc");
}
#[test]
fn idle_candidate_holds_close_until_file_drop() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            tx.send(h.close()).unwrap();
        });
        wait_closing(&h);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(c.observe().unwrap().bytes_read(), 3);
        drop(c);
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        worker.join().unwrap();
        assert_eq!(h.status().unwrap().mode, HostMode::Closed);
    });
}
#[test]
fn creator_stop_waits_then_new_owner_recovers_unknown() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let c = candidate(&h, &p, b"abc");
    let s = c.snapshot().clone();
    let (tx, rx) = mpsc::channel();
    let stopped = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            tx.send(h.stop_creators()).unwrap();
        });
        wait_closing(&h);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(c);
        let proof = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        worker.join().unwrap();
        proof
    });
    drop(h);
    let new = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let rows = new.recover_creators(stopped).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].phase(), Phase::CommitUnknown);
    assert_eq!(rows[0].intent(), s.intent());
    assert_ne!(rows[0].owner(), s.owner());
    assert_eq!(new.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn pause_denies_new_work_not_accepted_candidate() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    h.pause().unwrap();
    assert_eq!(h.status().unwrap().mode, HostMode::Paused);
    assert_eq!(c.observe().unwrap().bytes_read(), 3);
    let (_, other) = Offer::tagged(&p, b"abc", 0, 1).pair();
    assert!(h.admit_receiver(other).is_err());
    assert_eq!(c.snapshot().phase(), Phase::Committing);
    drop(c);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn cancellation_keeps_unknown_and_denies_observe_renew() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    let key = JobKey::from_job(c.snapshot().job());
    let s = h.cancel(&key, c.snapshot().revision()).unwrap();
    assert_eq!(s.phase(), Phase::CommitUnknown);
    assert_eq!(s.intent(), c.snapshot().intent());
    assert!(c.observe().is_err());
    let offer = Offer::new(&p, b"abc", 1);
    assert!(
        c.renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
            .is_err()
    );
    drop(c);
    assert_eq!(h.get(&key).unwrap().unwrap().phase(), Phase::CommitUnknown);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn bad_renewal_preserves_old_candidate_and_row() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    let raw = serde_json::to_string(c.snapshot()).unwrap();
    let offer = Offer::new(&p, b"abc", 1);
    let mut bad = offer.a;
    bad[0] ^= 1;
    std::thread::sleep(Duration::from_millis(3));
    assert!(
        c.renew(offer.g, offer.target, &offer.t, &bad, &offer.b)
            .is_err()
    );
    assert_eq!(c.observe().unwrap().bytes_read(), 3);
    assert_eq!(serde_json::to_string(c.snapshot()).unwrap(), raw);
}
#[test]
fn renewal_rotates_live_epoch_not_historical_binding() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    let raw = serde_json::to_string(c.snapshot()).unwrap();
    let offer = Offer::new(&p, b"abc", 1);
    std::thread::sleep(Duration::from_millis(3));
    c.renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
        .unwrap();
    let reused = Offer::new(&p, b"abc", 1);
    assert!(
        c.renew(reused.g, reused.target, &reused.t, &reused.a, &reused.b)
            .is_err()
    );
    assert_eq!(c.observe().unwrap().bytes_read(), 3);
    assert_eq!(serde_json::to_string(c.snapshot()).unwrap(), raw);
    assert_eq!(schema(&p), 6);
}
#[test]
fn expiry_cannot_be_revived_by_new_grant() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    c.test_expire();
    let offer = Offer::new(&p, b"abc", 1);
    std::thread::sleep(Duration::from_millis(3));
    assert!(
        c.renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
            .is_err()
    );
    assert!(c.observe().is_err());
    drop(c);
    assert_eq!(schema(&p), 6);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn revoked_candidate_never_revives_or_deletes_file() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    let path = c.snapshot().stage().unwrap().path().to_owned();
    c.revoke();
    let offer = Offer::new(&p, b"abc", 1);
    assert!(
        c.renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
            .is_err()
    );
    assert!(c.observe().is_err());
    drop(c);
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[tokio::test]
async fn runtime_mutation_invalidates_observation_not_historical_event() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    let path = c.snapshot().stage().unwrap().path().to_owned();
    let raw = serde_json::to_string(c.snapshot()).unwrap();
    let key = JobKey::from_job(c.snapshot().job());
    let out = r
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(out.is_error, Some(true));
    assert!(c.observe().is_err());
    drop(c);
    assert_eq!(
        serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
        raw
    );
    assert_eq!(std::fs::read(path).unwrap(), b"xyz");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn inventory_cancel_between64k_reads_never_deadlock() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, &vec![42; 131073]);
    let key = JobKey::from_job(c.snapshot().job());
    let rev = c.snapshot().revision();
    let intent = c.snapshot().intent();
    let mut calls = 0;
    assert!(
        c.observe_between(|offset| {
            assert_eq!(offset, 65536);
            std::thread::scope(|scope| {
                let inv = scope.spawn(|| h.inventory().unwrap());
                let cancel = scope.spawn(|| h.cancel(&key, rev).unwrap());
                assert_eq!(inv.join().unwrap().recorded_usage(), (131073, 1));
                assert_eq!(cancel.join().unwrap().phase(), Phase::CommitUnknown);
            });
            calls += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(calls, 1);
    drop(c);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(s.intent(), intent);
    assert_eq!(s.phase(), Phase::CommitUnknown);
}
#[test]
fn actual_no_drop_exit_never_reconstructs_candidate() {
    let (_t, p, r) = fixture();
    let mut child = process(
        &std::env::current_exe().unwrap(),
        &p,
        "admission-candidate",
        "fleet::host::receiver::tests::receiving_process_child",
    );
    assert_eq!(child.wait().code(), Some(53), "{}", child.logs());
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let key = JobKey::from_job(Offer::new(&p, b"abc", 0).g.job());
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(s.phase(), Phase::Committing);
    let rows = h.recover_stopped_owner(s.owner()).unwrap();
    assert_eq!(rows[0].phase(), Phase::CommitUnknown);
    assert_eq!(rows[0].intent(), s.intent());
    assert!(!Path::new(&s.job().destination_path).exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    assert!(h.resume().is_err());
    let (_, records) = Offer::new(&p, b"abc", 0).pair();
    assert!(h.admit_receiver(records).is_err());
}
#[test]
fn empty_candidate_holds_slot_before_and_after_drop() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"");
    assert_eq!(h.status().unwrap().in_flight, 1);
    assert_eq!(c.observe().unwrap().bytes_read(), 0);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
    drop(c);
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
}
#[test]
fn native_eight_mib_live_candidate_roundtrip() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let data = vec![47; 8 * 1024 * 1024];
    let started = Instant::now();
    let mut c = candidate(&h, &p, &data);
    let s = c.snapshot().clone();
    assert_eq!(c.observe().unwrap().bytes_read(), data.len() as u64);
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), data);
    drop(c);
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8388608, 1));
    assert!(s.receipt().is_none());
    println!(
        "LOCAL_LIVE_CANDIDATE8MIB: bytes=8388608 elapsed_ms={} original lease unchanged; DATA+prepare+observe+readback+Drop not network/publish",
        started.elapsed().as_millis()
    );
}
#[test]
fn appearing_destination_never_overwritten() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let mut c = candidate(&h, &p, b"abc");
    let path = PathBuf::from(&c.snapshot().job().destination_path);
    std::fs::write(&path, b"keep-target").unwrap();
    assert!(c.observe().is_err());
    drop(c);
    assert_eq!(std::fs::read(path).unwrap(), b"keep-target");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
