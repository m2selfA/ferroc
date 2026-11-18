//! Actual Linux O_TMPFILE receiver/SQL/AEAD, not a network or deployment probe.
use super::*;
use crate::fleet::{
    control::{ControlBody, Finish},
    inventory::FindingKind,
};
fn fill_anonymous<'h, 'r>(
    h: &'h FleetHost<'r>,
    p: &Path,
    bytes: &[u8],
) -> (LeasedRecords, HostReceiver<'h, 'r>, Vec<u8>) {
    h.resume().unwrap();
    let (mut source, target) = Offer::new(p, bytes, 0).pair();
    let mut recv = h.admit_linux_anonymous_receiver(target).unwrap();
    assert!(
        recv.snapshot()
            .stage()
            .unwrap()
            .allocation()
            .unwrap()
            .is_anonymous()
    );
    assert!(!recv.snapshot().stage().unwrap().path().exists());
    for (i, chunk) in bytes.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((i * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    let fin = source
        .seal_control(ControlBody::Finish(Finish {
            size: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }))
        .unwrap();
    (source, recv, fin)
}
#[test]
fn linux_anonymous_zero_one_cross_chunk_and_eight_mib_settle_and_ack() {
    for size in [0, 1, 131073, 8 * 1024 * 1024] {
        let bytes = vec![0x35; size];
        let (_t, p, r) = fixture();
        let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
        let (mut source, recv, fin) = fill_anonymous(&h, &p, &bytes);
        assert_eq!(schema(&p), 11);
        let logical = recv.snapshot().stage().unwrap().path().to_owned();
        let sealed = recv.seal_finish(&fin).unwrap();
        assert_eq!(schema(&p), 11);
        let candidate = sealed.prepare_commit().unwrap();
        assert_eq!(schema(&p), 11);
        let published = candidate.attempt_local_publication().unwrap();
        assert_eq!(schema(&p), 11);
        let receipt = published.record_target_observation().unwrap();
        assert_eq!(schema(&p), 11);
        let done = receipt.settle_local().unwrap();
        assert_eq!(schema(&p), 11);
        assert_eq!(done.snapshot().phase(), Phase::Completed);
        assert!(done.snapshot().stage().is_none());
        assert!(
            done.snapshot()
                .settlement_origin()
                .unwrap()
                .allocation()
                .unwrap()
                .is_anonymous()
        );
        match source.open_record(done.local_commit_ack()).unwrap() {
            PeerRecord::Control { message, .. } => {
                assert_eq!(message.body, ControlBody::CommitAck(done.receipt().clone()))
            }
            _ => panic!("expected authenticated ACK"),
        }
        assert_eq!(
            std::fs::read(p.with_file_name("target.bin")).unwrap(),
            bytes
        );
        assert!(!logical.exists());
        drop(done);
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
        h.close().unwrap();
        let restart = crate::runtime::Runtime::new(
            Policy::new(vec![p.parent().unwrap().to_path_buf()], false).unwrap(),
        );
        let reopened = restart
            .open_fleet_host(&p, InventoryLimits::default())
            .unwrap();
        let rows = reopened.inventory().unwrap();
        assert_eq!(rows.recorded_usage(), (0, 0));
        reopened.close().unwrap();
    }
}
#[test]
fn linux_anonymous_drop_keeps_full_debt_and_never_reports_missing_stage() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, _) = fill_anonymous(&h, &p, b"abc");
    drop(recv);
    let report = h.inventory().unwrap();
    assert_eq!(report.recorded_usage(), (3, 1));
    assert!(!report.complete());
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind == FindingKind::AnonymousStageUnobservable)
    );
    assert!(
        !report
            .findings()
            .iter()
            .any(|f| f.kind == FindingKind::MissingStage)
    );
    assert!(!p.with_file_name("target.bin").exists());
    h.close().unwrap();
    let restart = crate::runtime::Runtime::new(
        Policy::new(vec![p.parent().unwrap().to_path_buf()], false).unwrap(),
    );
    let reopened = restart
        .open_fleet_host(&p, InventoryLimits::default())
        .unwrap();
    assert_eq!(reopened.inventory().unwrap().recorded_usage(), (3, 1));
    assert!(reopened.resume().is_err());
    reopened.close().unwrap();
}
#[test]
fn linux_existing_target_before_native_link_preserves_bytes_and_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, fin) = fill_anonymous(&h, &p, b"abc");
    let c = recv.seal_finish(&fin).unwrap().prepare_commit().unwrap();
    let target = p.with_file_name("target.bin");
    let result = c.rename_between(
        |_| {
            std::fs::write(&target, b"xyz")?;
            Ok(())
        },
        |_| Ok(()),
        |_, _| Ok(()),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"xyz");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}
#[test]
fn linux_parent_replacement_is_refused_before_publication() {
    let (_t, p, r) = fixture();
    let sink = p.parent().unwrap().join("sink");
    crate::fleet::identity::make_directory(&sink).unwrap();
    let alias = sink.join("fake.db");
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, fin) = fill_anonymous(&h, &alias, b"abc");
    let c = recv.seal_finish(&fin).unwrap().prepare_commit().unwrap();
    let moved = sink.with_file_name("moved");
    let result = c.rename_between(
        |_| {
            std::fs::rename(&sink, &moved)?;
            crate::fleet::identity::make_directory(&sink)?;
            Ok(())
        },
        |_| Ok(()),
        |_, _| Ok(()),
    );
    assert!(result.is_err());
    assert!(!sink.join("target.bin").exists());
    assert!(!moved.join("target.bin").exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}
#[test]
fn linux_external_post_link_change_cannot_get_receipt_or_release_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, fin) = fill_anonymous(&h, &p, b"abc");
    let published = recv
        .seal_finish(&fin)
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap();
    std::fs::write(p.with_file_name("target.bin"), b"xyz").unwrap();
    assert!(published.record_target_observation().is_err());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}
#[test]
fn linux_anonymous_db_contention_fails_without_wait_and_keeps_v6_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, fin) = fill_anonymous(&h, &p, b"abc");
    let c = recv.seal_finish(&fin).unwrap().prepare_commit().unwrap();
    let writer = rusqlite::Connection::open(&p).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    assert!(c.attempt_local_publication().is_err());
    let own = started.elapsed();
    writer.execute_batch("ROLLBACK").unwrap();
    assert!(own < Duration::from_secs(2), "own={own:?}");
    assert_eq!(schema(&p), 11);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}
#[test]
fn linux_anonymous_placeholder_collision_faults_without_writing_or_forgiving() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.resume().unwrap();
    let (mut s, t) = Offer::new(&p, b"abc", 0).pair();
    let mut recv = h.admit_linux_anonymous_receiver(t).unwrap();
    let logical = recv.snapshot().stage().unwrap().path().to_owned();
    std::fs::write(&logical, b"xyz").unwrap();
    assert!(recv.write_record(&s.seal_data(0, b"abc").unwrap()).is_err());
    drop(recv);
    assert_eq!(std::fs::read(logical).unwrap(), b"xyz");
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}
#[test]
fn linux_parent_move_after_link_keeps_unknown_target_and_full_debt() {
    let (_t, p, r) = fixture();
    let sink = p.parent().unwrap().join("sink");
    crate::fleet::identity::make_directory(&sink).unwrap();
    let alias = sink.join("fake.db");
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, fin) = fill_anonymous(&h, &alias, b"abc");
    let c = recv.seal_finish(&fin).unwrap().prepare_commit().unwrap();
    let moved = sink.with_file_name("moved");
    assert!(
        c.rename_between(
            |_| Ok(()),
            |_| {
                std::fs::rename(&sink, &moved)?;
                Ok(())
            },
            |_, _| Ok(())
        )
        .is_err()
    );
    assert_eq!(std::fs::read(moved.join("target.bin")).unwrap(), b"abc");
    assert!(!sink.join("target.bin").exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}
#[test]
fn linux_anonymous_schema_downgrade_is_rejected_without_exempting_debt() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, _) = fill_anonymous(&h, &p, b"abc");
    assert!(
        crate::fleet::fence::file_id(&recv.file).is_err(),
        "ordinary DB/identity single-link rules must not accept zero links"
    );
    drop(recv);
    let sql = rusqlite::Connection::open(&p).unwrap();
    sql.execute("UPDATE ferroc_fleet_meta SET version=10", [])
        .unwrap();
    assert!(h.inventory().is_err());
    sql.execute("UPDATE ferroc_fleet_meta SET version=11", [])
        .unwrap();
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    h.close().unwrap();
}

#[test]
fn linux_legacy_named_receiver_cannot_enter_anonymous_publication_path() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_, recv, fin) = super::fill(&h, &p, b"abc");
    let c = recv.seal_finish(&fin).unwrap().prepare_commit().unwrap();
    assert!(c.attempt_local_publication().is_err());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (3, 1));
    assert_ne!(schema(&p), 11);
    h.close().unwrap();
}
/// Replacement offer whose pre-image is the bytes actually on disk.
fn replacing_pair(destination: &Path, new: &[u8], old: &[u8]) -> (LeasedRecords, LeasedRecords) {
    let job = JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::from_bytes([65; 16]),
        file_id: Uuid::from_bytes([66; 16]),
        source_path: destination
            .with_file_name("source.bin")
            .to_str()
            .unwrap()
            .into(),
        destination_path: destination.to_str().unwrap().into(),
        bytes_total: new.len() as u64,
        sha256: Sha256::digest(new).into(),
        overwrite: true,
        pre_image_sha256: Some(Sha256::digest(old).into()),
        route: RoutePolicy::RelayOnly,
        deadline_ms: 60100,
        idempotency_key: "replace-linux".into(),
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
            authorization_id: Uuid::from_u128(9001),
            key_epoch: Uuid::from_u128(9002),
        },
        job_digest: job.digest().unwrap(),
        permission: Permission::ReplaceExistingFile,
        chunk_bytes: 65536,
        issued_at_ms: 100,
        expires_at_ms: 50100,
    }
    .validate_for(job)
    .unwrap();
    let source = EphemeralKey::generate();
    let target = EphemeralKey::generate();
    let sk = IdentityKey::from_test_seed([0x81; 32]);
    let tk = IdentityKey::from_test_seed([0x82; 32]);
    let t = Transcript::for_grant(
        &g,
        sk.public(),
        tk.public(),
        source.public(),
        target.public(),
    );
    let a = sk.sign(&t, Direction::SourceToTarget).unwrap();
    let b = tk.sign(&t, Direction::TargetToSource).unwrap();
    let sp = DevicePin::approved("source-A", sk.public()).unwrap();
    let tp = DevicePin::approved("target-B", tk.public()).unwrap();
    let sample = ClockSample::now();
    let one = source
        .authenticate_leased(
            &t,
            Direction::SourceToTarget,
            &g,
            &sp,
            &tp,
            &a,
            &b,
            TrustedTimeAnchor::approved_window(sample, 200, 200).unwrap(),
        )
        .unwrap();
    let two = target
        .authenticate_leased(
            &t,
            Direction::TargetToSource,
            &g,
            &sp,
            &tp,
            &a,
            &b,
            TrustedTimeAnchor::approved_window(sample, 200, 200).unwrap(),
        )
        .unwrap();
    (one, two)
}

#[test]
fn linux_anonymous_replace_publishes_over_the_authorized_pre_image() {
    let bytes = vec![0x47; 200_000];
    let old = vec![0x11; 4096];
    let (_t, p, r) = fixture();
    let destination = p.with_file_name("target.bin");
    std::fs::write(&destination, &old).unwrap();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.resume().unwrap();
    let (mut source, target) = replacing_pair(&destination, &bytes, &old);
    let mut recv = h.admit_linux_anonymous_receiver(target).unwrap();
    for (i, chunk) in bytes.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((i * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    let fin = source
        .seal_control(ControlBody::Finish(Finish {
            size: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
        }))
        .unwrap();
    let sealed = recv.seal_finish(&fin).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    let published = candidate.attempt_local_publication().unwrap();
    // Anonymous owners use the v11 schema; a replacement job is expressed by its
    // pre-image binding and settlement must not downgrade the recorded version.
    assert_eq!(schema(&p), 11);
    let receipt = published.record_target_observation().unwrap();
    let done = receipt.settle_local().unwrap();
    assert_eq!(schema(&p), 11);
    assert_eq!(done.snapshot().phase(), Phase::Completed);
    assert!(done.snapshot().stage().is_none());
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    // No reserved replacement name survives a successful rename.
    let leftovers: Vec<_> = std::fs::read_dir(destination.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with(".ferroc-fleet-repl-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    drop(done);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
    h.close().unwrap();
}

#[test]
fn linux_anonymous_replace_refuses_changed_pre_image_and_keeps_debt() {
    let bytes = vec![0x48; 70_000];
    let old = vec![0x12; 4096];
    let (_t, p, r) = fixture();
    let destination = p.with_file_name("target.bin");
    std::fs::write(&destination, &old).unwrap();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.resume().unwrap();
    let (mut source, target) = replacing_pair(&destination, &bytes, &old);
    let mut recv = h.admit_linux_anonymous_receiver(target).unwrap();
    for (i, chunk) in bytes.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((i * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    let fin = source
        .seal_control(ControlBody::Finish(Finish {
            size: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
        }))
        .unwrap();
    // Same size, different bytes: the authorized pre-image no longer matches.
    std::fs::write(&destination, vec![0x13; 4096]).unwrap();
    let candidate = recv.seal_finish(&fin).unwrap().prepare_commit().unwrap();
    let error = match candidate.attempt_local_publication() {
        Ok(_) => panic!("changed pre-image must not publish"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("no longer matches the authorized pre-image"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(&destination).unwrap(), vec![0x13; 4096]);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (70_000, 1));
    h.close().unwrap();
}
