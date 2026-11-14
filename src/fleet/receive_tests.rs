use super::*;
#[path = "flow_control_tests.rs"]
mod flow_control_tests;
#[path = "commit_admission_tests.rs"]
mod intent_tests;
use crate::{
    config::Policy,
    fleet::{
        auth::{DevicePin, IdentityKey},
        identity::{make_directory, new_private},
        inventory::InventoryLimits,
        job::{FileGrant, JobSpec, Permission, RoutePolicy},
        lease::{ClockSample, TrustedTimeAnchor},
        protocol::{Binding, Direction, device_digest},
    },
};
use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};
use uuid::Uuid;
fn fixture() -> (tempfile::TempDir, PathBuf, crate::runtime::Runtime) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let path = root.join("relay.db");
    drop(new_private(&path).unwrap());
    let r = crate::runtime::Runtime::new(Policy::new(vec![root], false).unwrap());
    (t, path, r)
}
struct Offer {
    g: ValidatedGrant,
    t: Transcript,
    source: EphemeralKey,
    target: EphemeralKey,
    a: [u8; 64],
    b: [u8; 64],
    sp: DevicePin,
    tp: DevicePin,
}
impl Offer {
    fn new(path: &Path, data: &[u8], generation: u64) -> Self {
        Self::tagged(path, data, generation, 0)
    }
    fn tagged(path: &Path, data: &[u8], generation: u64, tag: u8) -> Self {
        let job = JobSpec {
            version: 1,
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("source-A").unwrap(),
            target_device: device_digest("target-B").unwrap(),
            transfer_id: Uuid::from_bytes([5 + tag; 16]),
            file_id: Uuid::from_bytes([6 + tag; 16]),
            source_path: path.with_file_name("source.bin").to_str().unwrap().into(),
            destination_path: path
                .with_file_name(if tag == 0 {
                    "target.bin".into()
                } else {
                    format!("target-{tag}.bin")
                })
                .to_str()
                .unwrap()
                .into(),
            bytes_total: data.len() as u64,
            sha256: Sha256::digest(data).into(),
            overwrite: false,
            route: RoutePolicy::RelayOnly,
            deadline_ms: 60100,
            idempotency_key: if tag == 0 {
                "receive-local".into()
            } else {
                format!("receive-local-{tag}")
            },
        };
        let g = FileGrant {
            binding: Binding {
                fleet_id: job.fleet_id,
                source_device: job.source_device,
                target_device: job.target_device,
                source_session: Uuid::from_bytes([3; 16]),
                target_session: Uuid::from_bytes([4; 16]),
                transfer_id: job.transfer_id,
                file_id: job.file_id,
                authorization_id: Uuid::from_u128(1000 + generation as u128),
                key_epoch: Uuid::from_u128(2000 + generation as u128),
            },
            job_digest: job.digest().unwrap(),
            permission: Permission::SendFileNoClobber,
            chunk_bytes: 65536,
            issued_at_ms: if generation == 0 { 100 } else { 201 },
            expires_at_ms: 50100 + generation,
        }
        .validate_for(job)
        .unwrap();
        let source = EphemeralKey::generate();
        let target = EphemeralKey::generate();
        let sk = IdentityKey::from_test_seed([0x11; 32]);
        let tk = IdentityKey::from_test_seed([0x22; 32]);
        let t = Transcript::for_grant(
            &g,
            sk.public(),
            tk.public(),
            source.public(),
            target.public(),
        );
        let a = sk.sign(&t, Direction::SourceToTarget).unwrap();
        let b = tk.sign(&t, Direction::TargetToSource).unwrap();
        Self {
            g,
            t,
            source,
            target,
            a,
            b,
            sp: DevicePin::approved("source-A", sk.public()).unwrap(),
            tp: DevicePin::approved("target-B", tk.public()).unwrap(),
        }
    }
    fn pair(self) -> (LeasedRecords, LeasedRecords) {
        let sample = ClockSample::now();
        let one = self
            .source
            .authenticate_leased(
                &self.t,
                Direction::SourceToTarget,
                &self.g,
                &self.sp,
                &self.tp,
                &self.a,
                &self.b,
                TrustedTimeAnchor::approved_window(sample, 200, 200).unwrap(),
            )
            .unwrap();
        let two = self
            .target
            .authenticate_leased(
                &self.t,
                Direction::TargetToSource,
                &self.g,
                &self.sp,
                &self.tp,
                &self.a,
                &self.b,
                TrustedTimeAnchor::approved_window(sample, 200, 200).unwrap(),
            )
            .unwrap();
        (one, two)
    }
}
fn open<'h, 'r>(
    h: &'h FleetHost<'r>,
    path: &Path,
    data: &[u8],
) -> (LeasedRecords, HostReceiver<'h, 'r>) {
    h.resume().unwrap();
    let (source, target) = Offer::new(path, data, 0).pair();
    (source, h.admit_receiver(target).unwrap())
}
fn schema(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT version FROM ferroc_fleet_meta", [], |r| r.get(0))
        .unwrap()
}
#[test]
fn crypto_tamper_and_non_data_control_cannot_write_or_become_false_ack() {
    for mode in [0, 1] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let (mut source, mut recv) = open(&h, &p, b"abc");
        let path = recv.snapshot().stage().unwrap().path().to_owned();
        let data = source.seal_data(0, b"abc").unwrap();
        let invalid = if mode == 0 {
            let mut b = data.clone();
            *b.last_mut().unwrap() ^= 1;
            b
        } else {
            source
                .seal_control(crate::fleet::control::ControlBody::StatusRequest(
                    crate::fleet::control::Empty {},
                ))
                .unwrap()
        };
        assert!(recv.write_record(&invalid).is_err());
        assert!(recv.write_record(&data).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"");
        assert_eq!(recv.snapshot().received(), 0);
    }
}
#[test]
fn overlapping_fresh_sequence_is_rejected_without_rewriting_written_bytes() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdef");
    recv.write_record(&source.seal_data(1, b"bcd").unwrap())
        .unwrap();
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let before = std::fs::read(&path).unwrap();
    assert!(
        recv.write_record(&source.seal_data(0, b"abc").unwrap())
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(recv.snapshot().received(), 3);
}
#[test]
fn schema4_begin_sql_failure_rolls_back_marker_without_exposing_writer() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.resume().unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("CREATE TRIGGER reject_v4 BEFORE UPDATE OF version ON ferroc_fleet_meta WHEN NEW.version=4 BEGIN SELECT RAISE(ABORT,'receive intent fault');END;").unwrap();
    let (_, target) = Offer::new(&p, b"abc", 0).pair();
    let key = JobKey::from_job(target.grant().job());
    assert!(h.admit_receiver(target).is_err());
    assert_eq!(schema(&p), 3);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(s.phase(), Phase::Interrupted);
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    assert_eq!(h.status().unwrap().in_flight, 0);
}
#[test]
fn clock_discontinuity_prevents_write_without_mutating_system_clock() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.records.test_discontinuous();
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    assert!(
        recv.write_record(&source.seal_data(0, b"abc").unwrap())
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), b"");
}
#[test]
fn actual_gate_blocks_receiver_io_and_positive_release_completes() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let data = source.seal_data(0, b"abc").unwrap();
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let gate = r.test_fs_gate();
    let held = gate.lock().unwrap();
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        let (started, start) = mpsc::channel();
        let writer = scope.spawn(move || {
            started.send(()).unwrap();
            let result = recv.write_record(&data);
            tx.send(result.is_ok()).unwrap();
            recv
        });
        start.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        drop(held);
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap());
        let recv = writer.join().unwrap();
        assert_eq!(recv.snapshot().received(), 3);
        drop(recv);
    });
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
    assert_eq!(h.status().unwrap().in_flight, 0);
}
#[test]
fn empty_file_is_only_memory_coverage_and_still_occupies_persistent_slot() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv) = open(&h, &p, b"");
    assert!(recv.coverage_complete());
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    drop(recv);
    assert!(path.exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
    assert_eq!(schema(&p), 4);
}
#[test]
fn invalid_v4_snapshot_is_rejected_and_original_body_is_restored() {
    for field in ["verified", "phase", "fileId"] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let (_, recv) = open(&h, &p, b"abc");
        let k = JobKey::from_job(recv.snapshot().job());
        drop(recv);
        let c = rusqlite::Connection::open(&p).unwrap();
        let raw: String = c
            .query_row("SELECT body FROM ferroc_fleet_jobs_v1", [], |r| r.get(0))
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        match field {
            "verified" => value["verified"] = true.into(),
            "phase" => {
                value["phase"] = serde_json::to_value(Phase::Verifying).unwrap();
                value["verified"] = true.into();
                value["received"] = 3.into();
            }
            _ => {
                value["stage"]["allocation"]["file_id"] = serde_json::Value::Null;
            }
        };
        let _: Snapshot = serde_json::from_value(value.clone())
            .expect("negative fixture must be valid typed JSON");
        c.execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1",
            [value.to_string()],
        )
        .unwrap();
        let error = h.get(&k).unwrap_err().to_string();
        assert!(
            error.contains("invalid journal version/owner/revision"),
            "field={field},wrong rejection layer: {error}"
        );
        c.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [&raw])
            .unwrap();
        assert!(h.get(&k).unwrap().is_some());
        assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    }
}

fn fill<'h, 'r>(
    h: &'h FleetHost<'r>,
    p: &Path,
    bytes: &[u8],
) -> (LeasedRecords, HostReceiver<'h, 'r>, Vec<u8>) {
    let (mut source, mut recv) = open(h, p, bytes);
    for (n, chunk) in bytes.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((n * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    let finish = source
        .seal_control(crate::fleet::control::ControlBody::Finish(
            crate::fleet::control::Finish {
                size: bytes.len() as u64,
                sha256: Sha256::digest(bytes).into(),
            },
        ))
        .unwrap();
    (source, recv, finish)
}
#[test]
fn finish_observes_three_chunks_without_persisting_verified_or_releasing_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let bytes = vec![42; 131073];
    let (_, mut recv, finish) = fill(&h, &p, &bytes);
    let rev = recv.snapshot().revision();
    let observed = recv.observe_finish(&finish).unwrap();
    assert_eq!(observed.bytes_read(), 131073);
    assert_eq!(
        observed.observed_sha256(),
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_eq!(observed.revision(), rev);
    assert_eq!(recv.snapshot().phase(), Phase::Transferring);
    assert_eq!(recv.snapshot().revision(), rev);
    assert_eq!(schema(&p), 4);
    let body: String = rusqlite::Connection::open(&p)
        .unwrap()
        .query_row("SELECT body FROM ferroc_fleet_jobs_v1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["verified"],
        false
    );
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
}
#[test]
fn cancel_and_inventory_can_run_between64k_reads_with_no_lock_inversion() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, mut recv, finish) = fill(&h, &p, &vec![42; 131073]);
    let key = JobKey::from_job(recv.snapshot().job());
    let revision = recv.snapshot().revision();
    let mut calls = 0;
    assert!(
        recv.observe_between(&finish, |offset, _| {
            calls += 1;
            assert_eq!(offset, 65536);
            {
                let _db = h.database.try_lock().expect("DB held across chunks");
                let _gate = r.test_fs_gate();
                let _guard = _gate.try_lock().expect("gate held across chunks");
            }
            std::thread::scope(|scope| {
                let scan = scope.spawn(|| h.inventory().unwrap());
                let cancel = scope.spawn(|| h.cancel(&key, revision).unwrap());
                assert_eq!(scan.join().unwrap().recorded_usage(), (131073, 1));
                assert_eq!(cancel.join().unwrap().phase(), Phase::CancelRequested);
            });
            Ok(())
        })
        .is_err()
    );
    assert_eq!(calls, 1);
    assert_eq!(recv.file.stream_position().unwrap(), 65536);
    assert!(recv.snapshot().stage().unwrap().path().exists());
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
}
#[test]
fn expiry_between_chunks_stops_read_at64k_and_retains_full_reservation() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, mut recv, finish) = fill(&h, &p, &vec![42; 131073]);
    assert!(
        recv.observe_between(&finish, |offset, recv| {
            assert_eq!(offset, 65536);
            recv.records.test_expire();
            Ok(())
        })
        .is_err()
    );
    assert_eq!(recv.file.stream_position().unwrap(), 65536);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
}
#[tokio::test]
async fn runtime_same_size_mutation_before_finish_is_sha_rejected_without_cleanup() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, mut recv, finish) = fill(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let changed = r
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(changed.is_error, Some(true));
    assert!(
        recv.observe_finish(&finish)
            .err()
            .expect("same-size mutation must fail local SHA")
            .to_string()
            .contains("local readback SHA256 mismatch")
    );
    assert_eq!(std::fs::read(path).unwrap(), b"xyz");
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn observation_is_read_sequence_not_immutable_snapshot_after_runtime_mutation() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let bytes = vec![b'a'; 131073];
    let (_, mut recv, finish) = fill(&h, &p, &bytes);
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let mut changed = false;
    let observed = recv
        .observe_between(&finish, |offset, _| {
            if !changed {
                assert_eq!(offset, 65536);
                let mut rewrite = bytes.clone();
                rewrite[..65536].fill(b'b');
                let engine = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let result = engine.block_on(r.call(
                    "write_file",
                    serde_json::json!({"path":path,"content":String::from_utf8(rewrite).unwrap()}),
                ));
                assert_ne!(result.is_error, Some(true));
                changed = true;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        observed.observed_sha256(),
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_ne!(
        observed.observed_sha256(),
        <[u8; 32]>::from(Sha256::digest(std::fs::read(path).unwrap()))
    );
    assert_eq!(recv.snapshot().phase(), Phase::Transferring);
    assert!(recv.snapshot().intent().is_none());
}
#[test]
fn incomplete_coverage_cannot_observe_finish() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"a").unwrap())
        .unwrap();
    let finish = source
        .seal_control(crate::fleet::control::ControlBody::Finish(
            crate::fleet::control::Finish {
                size: 3,
                sha256: Sha256::digest(b"abc").into(),
            },
        ))
        .unwrap();
    assert!(recv.observe_finish(&finish).is_err());
    assert_eq!(recv.snapshot().received(), 1);
}
#[test]
fn finish_replay_never_becomes_a_second_readback_permission() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, mut recv, finish) = fill(&h, &p, b"abc");
    recv.observe_finish(&finish).unwrap();
    assert!(recv.observe_finish(&finish).is_err());
    assert_eq!(recv.snapshot().phase(), Phase::Transferring);
    assert_eq!(schema(&p), 4);
}
#[test]
fn empty_finish_observation_keeps_zero_byte_slot_and_unverified_state() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, mut recv, finish) = fill(&h, &p, b"");
    assert_eq!(recv.observe_finish(&finish).unwrap().bytes_read(), 0);
    assert_eq!(recv.snapshot().phase(), Phase::Transferring);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
}

#[test]
fn sealed_finish_persists_descriptive_marker_not_verified_and_cannot_write() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, recv, finish) = fill(&h, &p, b"abc");
    let rev = recv.snapshot().revision();
    let mut sealed = recv.seal_finish(&finish).unwrap();
    let s = sealed.snapshot();
    assert_eq!(schema(&p), 5);
    assert_eq!(s.revision(), rev + 1);
    assert!(!s.data_seal().unwrap().id().is_nil());
    assert_eq!(
        s.data_seal().unwrap().binding(),
        &source.grant().grant().binding
    );
    assert_eq!(s.phase(), Phase::Transferring);
    assert!(s.intent().is_none() && s.receipt().is_none());
    assert_eq!(sealed.observe().unwrap().bytes_read(), 3);
    assert_eq!(sealed.observe().unwrap().bytes_read(), 3);
    let raw = serde_json::to_value(sealed.snapshot()).unwrap();
    assert_eq!(raw["verified"], false);
    assert!(
        sealed
            .inner
            .write_record(&source.seal_data(0, b"abc").unwrap())
            .is_err()
    );
    let key = JobKey::from_job(sealed.snapshot().job());
    let rev = sealed.snapshot().revision();
    {
        let mut db = h.database.lock().unwrap();
        let mut j = db.as_mut().unwrap().journal().unwrap();
        assert!(j.progress(&key, rev, 3).is_err());
        assert!(
            j.readback(&key, rev, Sha256::digest(b"abc").into())
                .is_err()
        );
        assert!(j.begin_commit(&key, rev).is_err());
        assert!(j.confirm_removed(&key, rev).is_err());
    }
    drop(sealed);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn cancel_before_seal_keeps_v4_and_never_returns_sealed_capability() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    h.cancel(&key, recv.snapshot().revision()).unwrap();
    assert!(recv.seal_finish(&finish).is_err());
    assert_eq!(schema(&p), 4);
    assert!(h.get(&key).unwrap().unwrap().data_seal().is_none());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn cancel_after_seal_sql_commit_preserves_v5_marker_without_returning_capability() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    assert!(
        recv.seal_between(&finish, |r| {
            h.cancel(&key, r.snapshot().revision())?;
            Ok(())
        })
        .is_err()
    );
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(schema(&p), 5);
    assert_eq!(s.phase(), Phase::CancelRequested);
    assert!(s.data_seal().is_some() && s.intent().is_none());
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"abc");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn expired_after_seal_commit_cannot_unseal_or_ack_and_keeps_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    assert!(
        recv.seal_between(&finish, |r| {
            r.records.test_expire();
            Ok(())
        })
        .is_err()
    );
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(schema(&p), 5);
    assert!(s.data_seal().is_some());
    assert_eq!(s.phase(), Phase::Transferring);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn seal_sql_failure_rolls_back_version_and_body_but_preserves_bytes() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let key = JobKey::from_job(recv.snapshot().job());
    let raw = serde_json::to_string(recv.snapshot()).unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("CREATE TRIGGER reject_seal BEFORE UPDATE ON ferroc_fleet_jobs_v1 WHEN json_extract(NEW.body,'$.version')=5 BEGIN SELECT RAISE(ABORT,'seal fault');END;").unwrap();
    assert!(recv.seal_finish(&finish).is_err());
    assert_eq!(schema(&p), 4);
    let s = h.get(&key).unwrap().unwrap();
    assert_eq!(serde_json::to_string(&s).unwrap(), raw);
    assert_eq!(std::fs::read(s.stage().unwrap().path()).unwrap(), b"abc");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn invalid_schema5_snapshot_cases_are_typed_then_rejected_and_original_restored() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let sealed = recv.seal_finish(&finish).unwrap();
    let key = JobKey::from_job(sealed.snapshot().job());
    let raw = serde_json::to_string(sealed.snapshot()).unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    for mode in 0..10 {
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        match mode {
            0 => v["data_seal"]["id"] = serde_json::json!(Uuid::nil()),
            1 => v["data_seal"]["file_id"] = serde_json::json!("wrong-file"),
            2 => v["data_seal"]["original_owner"] = serde_json::json!(Uuid::new_v4()),
            3 => {
                let b = v["data_seal"]["job_digest"][0].as_u64().unwrap();
                v["data_seal"]["job_digest"][0] = serde_json::json!((b + 1) % 256);
            }
            4 => v["data_seal"]["binding"]["authorizationId"] = serde_json::json!(Uuid::nil()),
            5 => v["version"] = serde_json::json!(4),
            6 => v["verified"] = serde_json::json!(true),
            7 => v["phase"] = serde_json::to_value(Phase::Verifying).unwrap(),
            8 => v["received"] = serde_json::json!(2),
            9 => v["data_seal"] = serde_json::Value::Null,
            _ => unreachable!(),
        };
        let changed = serde_json::to_string(&v).unwrap();
        let _: Snapshot = serde_json::from_str(&changed)
            .expect("negative must reach typed Snapshot validation, not JSON parse failure");
        c.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [changed])
            .unwrap();
        let denied = h.get(&key).is_err();
        c.execute("UPDATE ferroc_fleet_jobs_v1 SET body=?1", [&raw])
            .unwrap();
        assert!(denied, "case {mode} accepted");
        assert_eq!(
            serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
            raw
        );
    }
}
#[test]
fn schema5_row_under_downgraded_metadata_is_denied_and_restored() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let sealed = recv.seal_finish(&finish).unwrap();
    let key = JobKey::from_job(sealed.snapshot().job());
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute("UPDATE ferroc_fleet_meta SET version=4", [])
        .unwrap();
    let error = h.get(&key).expect_err("v5 row needs metadata5");
    c.execute("UPDATE ferroc_fleet_meta SET version=5", [])
        .unwrap();
    assert!(error.to_string().contains("row exceeds schema gate"));
    assert!(h.get(&key).unwrap().unwrap().data_seal().is_some());
}
#[test]
fn v3_and_v4_fresh_admission_under_empty_schema5_never_downgrades_or_bypasses_debt() {
    // Explicit schema-monotonicity fixtures, NOT a released/completed v5 job.
    // Two independent domains: existing debt intentionally blocks any second stage.
    for raw in [true, false] {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        rusqlite::Connection::open(&p)
            .unwrap()
            .execute("UPDATE ferroc_fleet_meta SET version=5", [])
            .unwrap();
        h.resume().unwrap();
        if raw {
            let a = h
                .admit(Offer::new(&p, b"", 0).g.job().clone(), 100)
                .unwrap();
            assert_eq!(a.snapshot.phase(), Phase::Interrupted);
        } else {
            let (_, target) = Offer::new(&p, b"", 0).pair();
            let recv = h.admit_receiver(target).unwrap();
            assert!(recv.snapshot().data_seal().is_none());
            drop(recv);
        }
        assert_eq!(schema(&p), 5);
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
        let (_, target) = Offer::tagged(&p, b"", 0, 1).pair();
        assert!(h.admit_receiver(target).is_err());
        assert_eq!(schema(&p), 5);
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
    }
}
#[test]
fn sealed_renewal_changes_live_epoch_without_rewriting_historical_seal_binding() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, recv, finish) = fill(&h, &p, b"abc");
    let mut sealed = recv.seal_finish(&finish).unwrap();
    let marker = sealed.snapshot().data_seal().unwrap().clone();
    let offer = Offer::new(&p, b"abc", 1);
    std::thread::sleep(Duration::from_millis(3));
    source
        .renew(offer.g.clone(), offer.source, &offer.t, &offer.a, &offer.b)
        .unwrap();
    sealed
        .renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
        .unwrap();
    assert_ne!(
        sealed.inner.records.grant().grant().binding,
        marker.binding().clone()
    );
    assert_eq!(sealed.snapshot().data_seal().unwrap(), &marker);
    assert_eq!(sealed.observe().unwrap().bytes_read(), 3);
}
#[tokio::test]
async fn sealed_marker_does_not_assert_hash_of_runtime_modified_data() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let result = r
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(result.is_error, Some(true));
    let mut sealed = recv.seal_finish(&finish).unwrap();
    assert!(sealed.observe().is_err());
    let key = JobKey::from_job(sealed.snapshot().job());
    drop(sealed);
    let s = h.get(&key).unwrap().unwrap();
    assert!(s.data_seal().is_some() && s.intent().is_none() && s.receipt().is_none());
    assert_eq!(serde_json::to_value(s).unwrap()["verified"], false);
    assert_eq!(std::fs::read(path).unwrap(), b"xyz");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn sealed_cancel_and_inventory_between64k_reads_keep_marker_and_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, &vec![42; 131073]);
    let mut sealed = recv.seal_finish(&finish).unwrap();
    let key = JobKey::from_job(sealed.snapshot().job());
    let rev = sealed.snapshot().revision();
    assert!(
        sealed
            .inner
            .read_sequence_between(|offset, _| {
                assert_eq!(offset, 65536);
                std::thread::scope(|scope| {
                    let scan = scope.spawn(|| h.inventory().unwrap());
                    let cancel = scope.spawn(|| h.cancel(&key, rev).unwrap());
                    assert_eq!(scan.join().unwrap().recorded_usage(), (131073, 1));
                    assert_eq!(cancel.join().unwrap().phase(), Phase::CancelRequested);
                });
                Ok(())
            })
            .is_err()
    );
    assert_eq!(sealed.inner.file.stream_position().unwrap(), 65536);
    drop(sealed);
    assert!(h.get(&key).unwrap().unwrap().data_seal().is_some());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
}
#[test]
fn sealed_zero_byte_file_still_occupies_slot_and_does_not_resume() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"");
    let mut sealed = recv.seal_finish(&finish).unwrap();
    assert_eq!(sealed.observe().unwrap().bytes_read(), 0);
    drop(sealed);
    let (_, target) = Offer::new(&p, b"", 0).pair();
    assert!(h.admit_receiver(target).is_err());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
}
#[test]
fn seal_crash_before_or_after_observation_is_interrupted_not_verified_or_resumable() {
    for mode in ["seal", "seal-observed"] {
        let (_t, p, r) = fixture();
        let mut child = process(
            &std::env::current_exe().unwrap(),
            &p,
            mode,
            "fleet::host::receiver::tests::receiving_process_child",
        );
        assert_eq!(
            child.wait().code(),
            Some(if mode == "seal" { 49 } else { 50 }),
            "{}",
            child.logs()
        );
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let offer = Offer::new(&p, b"abc", 0);
        let key = JobKey::from_job(offer.g.job());
        let before = h.get(&key).unwrap().unwrap();
        let marker = before.data_seal().unwrap().clone();
        let recovered = h.recover_stopped_owner(before.owner()).unwrap();
        assert_eq!(schema(&p), 5);
        assert_eq!(recovered[0].phase(), Phase::Interrupted);
        assert_eq!(recovered[0].data_seal().unwrap(), &marker);
        assert!(recovered[0].intent().is_none() && recovered[0].receipt().is_none());
        assert_eq!(
            std::fs::read(recovered[0].stage().unwrap().path()).unwrap(),
            b"abc"
        );
        assert!(
            !h.inspect_allocation(&key)
                .unwrap()
                .eligible_for_absence_release()
        );
        assert!(h.resume().is_err());
        assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    }
}
#[test]
fn sealed_close_waits_for_live_file_and_accepted_operation() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let mut sealed = recv.seal_finish(&finish).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            tx.send(h.close()).unwrap();
        });
        let blocked = rx.recv_timeout(Duration::from_millis(50)).is_err();
        let observed = sealed.observe();
        drop(sealed);
        let closed = rx.recv_timeout(Duration::from_secs(5));
        worker.join().unwrap();
        assert!(blocked);
        assert_eq!(observed.unwrap().bytes_read(), 3);
        closed.unwrap().unwrap();
    });
}
#[test]
#[ignore = "actual archived308323 schema4 reader required"]
fn actual308323_refuses_schema5_before_any_stage_or_row_effect() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_SEAL_LEGACY_TEST").expect("explicit actual308323 required"),
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
        "308323eb2ea929e78545ae43152724c9e012342057ef7f73ea53cf766c82e95c"
    );
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, finish) = fill(&h, &p, b"abc");
    let sealed = recv.seal_finish(&finish).unwrap();
    let key = JobKey::from_job(sealed.snapshot().job());
    let raw = serde_json::to_string(sealed.snapshot()).unwrap();
    let path = sealed.snapshot().stage().unwrap().path().to_owned();
    drop(sealed);
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
    assert_eq!(schema(&p), 5);
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    assert_eq!(
        serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
        raw
    );
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    println!(
        "ACTUAL308323_SCHEMA5_REFUSED: fullSHA checked, stage and row unchanged; fixture reclaimed"
    );
}

struct Process {
    child: std::process::Child,
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
                panic!("receiver child timeout; reaped");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn logs(&mut self) -> String {
        use std::io::Read;
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
fn process(exe: &Path, path: &Path, mode: &str, test: &str) -> Process {
    use std::process::{Command, Stdio};
    let log = tempfile::tempfile().unwrap();
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", test, "--ignored", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()));
    if mode == "old" {
        cmd.env("FERROC_INVENTORY_DB", path)
            .env("FERROC_INVENTORY_MODE", "before_attach")
            .env(
                "FERROC_INVENTORY_READY",
                path.with_file_name("old-must-not-ready"),
            );
    } else {
        cmd.env("FERROC_RECEIVE_DB", path)
            .env("FERROC_RECEIVE_MODE", mode);
    }
    Process {
        child: cmd.spawn().unwrap(),
        log,
    }
}
#[test]
#[ignore = "bounded no-drop receiving child invoked by parent"]
fn receiving_process_child() {
    let p = PathBuf::from(std::env::var_os("FERROC_RECEIVE_DB").unwrap());
    let mode = std::env::var("FERROC_RECEIVE_MODE").unwrap();
    let runtime =
        crate::runtime::Runtime::new(Policy::new(vec![p.parent().unwrap().into()], false).unwrap());
    let h = runtime
        .open_fleet_host(&p, InventoryLimits::default())
        .unwrap();
    if mode.starts_with("admission-") {
        intent_tests::process_case(&h, &p, &mode);
        return;
    }
    let (mut source, mut recv) = open(&h, &p, b"abc");
    if mode == "seal" || mode == "seal-observed" {
        recv.write_record(&source.seal_data(0, b"abc").unwrap())
            .unwrap();
        let finish = source
            .seal_control(crate::fleet::control::ControlBody::Finish(
                crate::fleet::control::Finish {
                    size: 3,
                    sha256: Sha256::digest(b"abc").into(),
                },
            ))
            .unwrap();
        let mut sealed = recv.seal_finish(&finish).unwrap();
        if mode == "seal-observed" {
            sealed.observe().unwrap();
        }
        std::process::exit(if mode == "seal" { 49 } else { 50 });
    }
    if mode == "data" {
        recv.write_record(&source.seal_data(0, b"abc").unwrap())
            .unwrap();
        std::process::exit(48);
    }
    assert_eq!(mode, "intent");
    std::process::exit(47);
}
#[test]
fn actual_crash_after_v4_intent_and_data_retains_debt_without_resume() {
    for mode in ["intent", "data"] {
        let (_t, p, r) = fixture();
        let mut child = process(
            &std::env::current_exe().unwrap(),
            &p,
            mode,
            "fleet::host::receiver::tests::receiving_process_child",
        );
        assert_eq!(
            child.wait().code(),
            Some(if mode == "intent" { 47 } else { 48 }),
            "{}",
            child.logs()
        );
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let offer = Offer::new(&p, b"abc", 0);
        let key = JobKey::from_job(offer.g.job());
        let before = h.get(&key).unwrap().unwrap();
        assert_eq!(schema(&p), 4);
        let rows = h.recover_stopped_owner(before.owner()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].phase(), Phase::Interrupted);
        assert_eq!(rows[0].received(), if mode == "intent" { 0 } else { 3 });
        assert_eq!(
            std::fs::read(rows[0].stage().unwrap().path()).unwrap(),
            if mode == "intent" {
                b"".as_slice()
            } else {
                b"abc".as_slice()
            }
        );
        assert!(
            !h.inspect_allocation(&key)
                .unwrap()
                .eligible_for_absence_release()
        );
        assert!(h.resume().is_err());
        assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    }
}
#[test]
#[ignore = "actual archived eafd schema3 reader required"]
fn actual_eafd_binary_refuses_schema4_before_receiving() {
    use std::io::Read;
    let exe = PathBuf::from(
        std::env::var_os("FERROC_RECEIVE_LEGACY_TEST").expect("explicit actual eafd exe required"),
    );
    let mut f = File::open(&exe).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = f.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        "eafdbfb96a7e3ddf93f6d8e39a1deb5b4b3557f536e9a6244c2ac893ad7dc106"
    );
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let s = recv.snapshot().clone();
    let key = JobKey::from_job(s.job());
    let path = s.stage().unwrap().path().to_owned();
    let raw = serde_json::to_string(&s).unwrap();
    drop(recv);
    h.close().unwrap();
    drop(h);
    let mut child = process(
        &exe,
        &p,
        "old",
        "fleet::inventory::tests::inventory_process_child",
    );
    assert!(!child.wait().success());
    let output = child.logs();
    assert!(
        output.contains("unsupported/ambiguous fleet journal schema version"),
        "{output}"
    );
    assert!(!p.with_file_name("old-must-not-ready").exists());
    assert_eq!(schema(&p), 4);
    assert_eq!(std::fs::read(&path).unwrap(), b"abc");
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    assert_eq!(
        serde_json::to_string(&h.get(&key).unwrap().unwrap()).unwrap(),
        raw
    );
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    println!(
        "ACTUAL_EAFD_SCHEMA4_REJECTED: exact archived SHA checked; receiver row/data unchanged; fixture reclaimed"
    );
}

#[test]
fn actual_authenticated_data_persists_with_schema4_and_not_destination() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdef");
    assert_eq!(schema(&p), 4);
    assert_eq!(recv.snapshot().phase(), Phase::Transferring);
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let b = source.seal_data(3, b"def").unwrap();
    let a = source.seal_data(0, b"abc").unwrap();
    assert_eq!(recv.write_record(&b).unwrap(), Admission::New);
    assert!(!recv.coverage_complete());
    assert_eq!(recv.write_record(&a).unwrap(), Admission::New);
    assert!(recv.coverage_complete());
    assert_eq!(recv.snapshot().received(), 6);
    assert_eq!(recv.write_record(&a).unwrap(), Admission::Duplicate);
    assert_eq!(std::fs::read(&path).unwrap(), b"abcdef");
    assert!(!Path::new(&recv.snapshot().job().destination_path).exists());
    drop(recv);
    assert!(path.exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (6, 1));
}
#[test]
fn source_role_and_revoked_or_expired_target_cannot_create_any_job() {
    for mode in 0..3 {
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        h.resume().unwrap();
        let (source, mut target) = Offer::new(&p, b"abc", 0).pair();
        if mode == 1 {
            target.revoke();
        }
        if mode == 2 {
            target.test_expire();
        }
        assert!(
            h.admit_receiver(if mode == 0 { source } else { target })
                .is_err()
        );
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
        assert_eq!(schema(&p), 1);
    }
}
#[test]
fn expired_active_receiver_denies_io_keeps_empty_file_and_full_reservation() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    recv.records.test_expire();
    assert!(
        recv.write_record(&source.seal_data(0, b"abc").unwrap())
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn cancel_wins_before_data_and_replay_never_turns_into_ack() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let k = JobKey::from_job(recv.snapshot().job());
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let row = h.cancel(&k, recv.snapshot().revision()).unwrap();
    assert_eq!(row.phase(), Phase::CancelRequested);
    let data = source.seal_data(0, b"abc").unwrap();
    assert!(recv.write_record(&data).is_err());
    assert!(recv.write_record(&data).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
}
#[test]
fn partial_storage_failure_faults_and_preserves_dirty_bytes_without_progress() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdef");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let data = source.seal_data(0, b"abcdef").unwrap();
    assert!(
        recv.write_between(&data, |f, _, b, _| {
            f.write_all(&b[..3])?;
            Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "injected partial storage failure",
            )
            .into())
        })
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"abc");
    assert_eq!(recv.snapshot().received(), 0);
    assert!(!recv.coverage_complete());
    assert!(recv.write_record(&data).is_err());
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (6, 1));
}
#[test]
fn post_write_revocation_retains_bytes_but_never_reports_progress_or_ack() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let data = source.seal_data(0, b"abc").unwrap();
    assert!(
        recv.write_between(&data, |f, _, b, lease| {
            f.write_all(b)?;
            f.sync_data()?;
            lease.revoke();
            Ok(())
        })
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"abc");
    assert_eq!(recv.snapshot().received(), 0);
    assert!(recv.write_record(&data).is_err());
}
#[test]
fn sql_progress_failure_preserves_file_and_zero_progress_and_no_replay_ack() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("CREATE TRIGGER reject_receive_progress BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'receive progress fault');END;").unwrap();
    let data = source.seal_data(0, b"abc").unwrap();
    assert!(recv.write_record(&data).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"abc");
    assert_eq!(recv.snapshot().received(), 0);
    assert!(recv.write_record(&data).is_err());
}
#[test]
fn renewal_rotates_records_without_reopening_or_losing_received_coverage() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdef");
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let offer = Offer::new(&p, b"abcdef", 1);
    std::thread::sleep(Duration::from_millis(3));
    source
        .renew(offer.g.clone(), offer.source, &offer.t, &offer.a, &offer.b)
        .unwrap();
    recv.renew(offer.g, offer.target, &offer.t, &offer.a, &offer.b)
        .unwrap();
    recv.write_record(&source.seal_data(3, b"def").unwrap())
        .unwrap();
    assert!(recv.coverage_complete());
    assert_eq!(
        std::fs::read(recv.snapshot().stage().unwrap().path()).unwrap(),
        b"abcdef"
    );
}
#[test]
fn failed_renewal_keeps_old_epoch_live_but_local_revoke_is_final() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abcdef");
    let offer = Offer::new(&p, b"abcdef", 1);
    let mut bad = offer.a;
    bad[0] ^= 1;
    std::thread::sleep(Duration::from_millis(3));
    assert!(
        recv.renew(offer.g, offer.target, &offer.t, &bad, &offer.b)
            .is_err()
    );
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    recv.revoke();
    assert!(
        recv.write_record(&source.seal_data(3, b"def").unwrap())
            .is_err()
    );
    assert_eq!(recv.snapshot().received(), 3);
}
#[test]
fn same_job_cannot_resume_or_adopt_after_drop_and_recovery() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    drop(recv);
    let proof = h.stop_creators().unwrap();
    drop(h);
    let next = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let row = next.recover_creators(proof).unwrap().pop().unwrap();
    assert_eq!(row.phase(), Phase::Interrupted);
    assert_eq!(row.received(), 3);
    assert!(
        !next
            .inspect_allocation(&JobKey::from_job(row.job()))
            .unwrap()
            .eligible_for_absence_release()
    );
    assert!(next.resume().is_err());
    let (_, target) = Offer::new(&p, b"abc", 0).pair();
    assert!(next.admit_receiver(target).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
}
#[test]
fn shutdown_waits_for_idle_receiver_drop_before_unlocking_database() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_source, recv) = open(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    std::thread::scope(|scope| {
        let host = &h;
        let (tx, rx) = mpsc::channel();
        let closing = scope.spawn(move || {
            host.close().unwrap();
            tx.send(()).unwrap();
        });
        let end = Instant::now() + Duration::from_secs(10);
        while h.status().unwrap().mode != crate::fleet::host::HostMode::Closing {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
        assert!(crate::fleet::fence::OwnerFence::acquire(&p).is_err());
        drop(recv);
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
        closing.join().unwrap();
    });
    assert!(path.exists());
    assert!(crate::fleet::fence::OwnerFence::acquire(&p).is_ok());
}
#[test]
fn existing_destination_prevents_data_and_retains_both_target_and_empty_stage() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let path = recv.snapshot().stage().unwrap().path().to_owned();
    let dest = recv.snapshot().job().destination_path.clone();
    let mut f = new_private(Path::new(&dest)).unwrap();
    f.write_all(b"keep").unwrap();
    drop(f);
    assert!(
        recv.write_record(&source.seal_data(0, b"abc").unwrap())
            .is_err()
    );
    assert_eq!(std::fs::read(dest).unwrap(), b"keep");
    assert_eq!(std::fs::read(path).unwrap(), b"");
}
#[test]
fn schema4_row_cannot_skip_verification_enter_commit_or_clear_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let s = recv.snapshot().clone();
    drop(recv);
    let mut guard = h.database.lock().unwrap();
    let db = guard.as_mut().unwrap();
    let k = JobKey::from_job(s.job());
    assert!(
        db.journal()
            .unwrap()
            .readback(&k, s.revision(), s.job().sha256)
            .is_err()
    );
    assert!(
        db.journal()
            .unwrap()
            .begin_commit(&k, s.revision())
            .is_err()
    );
    assert!(
        db.journal()
            .unwrap()
            .confirm_removed(&k, s.revision())
            .is_err()
    );
    assert_eq!(
        db.journal().unwrap().get(&k).unwrap().unwrap().revision(),
        s.revision()
    );
    assert_eq!(schema(&p), 4);
}
