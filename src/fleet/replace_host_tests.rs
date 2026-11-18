//! Host receiver wiring for REPLACEMENT jobs. LOCAL only: real Windows
//! filesystem, real v7/v8/v9 stages, one process and one machine. No two-host,
//! restart-resume, Linux or production claim.
use super::*;
use std::fs;

/// Offer whose job replaces `old` with `new`, with the pre-image digest taken
/// from the bytes actually present on disk.
fn replacing_offer(path: &Path, new: &[u8], old: &[u8], tag: u8) -> (LeasedRecords, LeasedRecords) {
    let destination = path.with_file_name(if tag == 0 {
        "target.bin".to_string()
    } else {
        format!("target-{tag}.bin")
    });
    fs::write(&destination, old).unwrap();
    let job = JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::from_bytes([5 + tag; 16]),
        file_id: Uuid::from_bytes([6 + tag; 16]),
        source_path: path.with_file_name("source.bin").to_str().unwrap().into(),
        destination_path: destination.to_str().unwrap().into(),
        bytes_total: new.len() as u64,
        sha256: Sha256::digest(new).into(),
        overwrite: true,
        pre_image_sha256: Some(Sha256::digest(old).into()),
        route: RoutePolicy::RelayOnly,
        deadline_ms: 60100,
        idempotency_key: if tag == 0 {
            "replace-local".into()
        } else {
            format!("replace-local-{tag}")
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
            authorization_id: Uuid::from_u128(3000 + tag as u128),
            key_epoch: Uuid::from_u128(4000 + tag as u128),
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

fn fill_replacing<'h, 'r>(
    h: &'h FleetHost<'r>,
    path: &Path,
    new: &[u8],
    old: &[u8],
    tag: u8,
) -> (LeasedRecords, HostReceiver<'h, 'r>, Vec<u8>) {
    h.resume().unwrap();
    let (mut source, target) = replacing_offer(path, new, old, tag);
    let mut recv = h.admit_receiver(target).unwrap();
    for (n, chunk) in new.chunks(65536).enumerate() {
        recv.write_record(&source.seal_data((n * 65536) as u64, chunk).unwrap())
            .unwrap();
    }
    let finish = source
        .seal_control(crate::fleet::control::ControlBody::Finish(
            crate::fleet::control::Finish {
                size: new.len() as u64,
                sha256: Sha256::digest(new).into(),
            },
        ))
        .unwrap();
    (source, recv, finish)
}

#[test]
fn replacement_job_replaces_existing_target_and_keeps_v10_unknown_state() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let old = b"old-content".to_vec();
    let new = b"new-bytes".to_vec();
    let (_source, recv, finish) = fill_replacing(&h, &p, &new, &old, 0);
    let sealed = recv.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    let dest = PathBuf::from(&candidate.snapshot().job().destination_path);
    assert_eq!(fs::read(&dest).unwrap(), old);
    let renamed = candidate.attempt_local_publication().unwrap();
    // The target now holds the new bytes and the metadata gate is v10, not v7,
    // so a v7/v8/v9 reader cannot reinterpret a replacing rename.
    assert_eq!(fs::read(&dest).unwrap(), new);
    assert_eq!(schema(&p), 10);
    let observed = renamed.record_target_observation().unwrap();
    let finished = observed.settle_local().unwrap();
    let s = finished.snapshot();
    assert_eq!(s.phase(), Phase::Completed);
    assert!(s.receipt().is_some());
    assert_eq!(fs::read(&dest).unwrap(), new);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
    drop(finished);
    h.close().unwrap();
}

#[test]
fn schema10_reopens_for_second_replacement_and_retains_receipts() {
    let (_t, p, runtime) = fixture();
    for tag in [20, 21] {
        let host = runtime
            .open_fleet_host(&p, InventoryLimits::default())
            .unwrap();
        let (_source, receiver, finish) = fill_replacing(&host, &p, b"new", b"old", tag);
        let done = receiver
            .seal_finish(&finish)
            .unwrap()
            .prepare_commit()
            .unwrap()
            .attempt_local_publication()
            .unwrap()
            .record_target_observation()
            .unwrap()
            .settle_local()
            .unwrap();
        assert_eq!(done.snapshot().phase(), Phase::Completed);
        assert_eq!(schema(&p), 10);
        drop(done);
        assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
        host.close().unwrap();
    }
    let conn = rusqlite::Connection::open(&p).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM ferroc_fleet_jobs_v1", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        2
    );
}

#[test]
fn schema9_create_then_replace_must_upgrade_to10_before_rename() {
    let (_t, p, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&p, InventoryLimits::default())
        .unwrap();
    let (_source, receiver, finish) = fill(&host, &p, b"abc");
    let done = receiver
        .seal_finish(&finish)
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    drop(done);
    assert_eq!(schema(&p), 9);
    host.close().unwrap();
    drop(host);
    let host = runtime
        .open_fleet_host(&p, InventoryLimits::default())
        .unwrap();
    let (_source, receiver, finish) = fill_replacing(&host, &p, b"new", b"old", 22);
    let renamed = receiver
        .seal_finish(&finish)
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap();
    assert_eq!(
        schema(&p),
        10,
        "a prior v9 settlement cannot suppress the replace schema gate"
    );
    let done = renamed
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    drop(done);
    assert_eq!(schema(&p), 10);
    assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
    host.close().unwrap();
}

#[test]
fn replacement_refuses_when_the_real_target_no_longer_matches_the_pre_image() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let old = b"old-content".to_vec();
    let new = b"new-bytes".to_vec();
    let (_source, recv, finish) = fill_replacing(&h, &p, &new, &old, 1);
    let sealed = recv.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    let dest = PathBuf::from(&candidate.snapshot().job().destination_path);
    // A same-size change after admission must NOT be overwritten.
    fs::write(&dest, b"OLD-CONTENT").unwrap();
    let error = candidate
        .attempt_local_publication()
        .err()
        .expect("must refuse");
    assert!(format!("{error:#}").contains("pre-image"), "{error:#}");
    assert_eq!(fs::read(&dest).unwrap(), b"OLD-CONTENT");
    // Debt and the retained stage survive: nothing was settled or released.
    assert_eq!(h.inventory().unwrap().recorded_usage(), (9, 1));
}

#[test]
fn replacement_refuses_when_the_target_disappears() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let old = b"old-content".to_vec();
    let new = b"new-bytes".to_vec();
    let (_source, recv, finish) = fill_replacing(&h, &p, &new, &old, 2);
    let sealed = recv.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    let dest = PathBuf::from(&candidate.snapshot().job().destination_path);
    fs::remove_file(&dest).unwrap();
    let error = candidate
        .attempt_local_publication()
        .err()
        .expect("must refuse");
    assert!(!error.to_string().is_empty());
    // A replace permission never degrades into a create.
    assert!(!dest.exists());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (9, 1));
}

#[test]
fn create_job_cannot_publish_over_an_existing_target() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (_source, recv, finish) = fill(&h, &p, b"abc");
    let sealed = recv.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    let dest = PathBuf::from(&candidate.snapshot().job().destination_path);
    fs::write(&dest, b"squatter").unwrap();
    let error = candidate
        .attempt_local_publication()
        .err()
        .expect("must refuse");
    assert!(!error.to_string().is_empty());
    assert_eq!(fs::read(&dest).unwrap(), b"squatter");
}

/// Explicit probe: a real archived pre-replacement binary must refuse a v10
/// database at open, leaving the row and target bytes untouched.
#[test]
#[ignore = "explicit real archived settlement binary only"]
fn actual_settlement_binary_refuses_v10_at_entry() {
    let exe = PathBuf::from(
        std::env::var_os("FERROC_SETTLEMENT_LEGACY_TEST")
            .expect("explicit archived settlement binary required"),
    );
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let old = b"old-content".to_vec();
    let new = b"new-bytes".to_vec();
    let (_source, recv, finish) = fill_replacing(&h, &p, &new, &old, 3);
    let sealed = recv.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    let dest = PathBuf::from(&candidate.snapshot().job().destination_path);
    drop(candidate.attempt_local_publication().unwrap());
    assert_eq!(schema(&p), 10);
    let before = fs::read(&dest).unwrap();
    drop(h);
    // The archived binary is asked to open the SAME database through the
    // existing bounded child entry point, using that child's own env contract.
    let log = {
        let mut child = process(
            &exe,
            &p,
            "old",
            "fleet::inventory::tests::inventory_process_child",
        );
        assert!(!child.wait().success());
        child.logs()
    };
    assert!(
        log.contains("unsupported") || log.contains("schema"),
        "{log}"
    );
    assert_eq!(schema(&p), 10);
    assert_eq!(fs::read(&dest).unwrap(), before);
}

/// Explicit native evidence probe for the host replacement path. Writes JSON and
/// is not a two-host, restart or durability test.
#[test]
#[ignore = "explicit native host replacement evidence probe"]
fn native_host_replacement_probe() {
    let out = match std::env::var_os("FERROC_FLEET_HOST_REPLACE_OUTPUT") {
        Some(v) => PathBuf::from(v),
        None => return,
    };
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let old = vec![b'o'; 1024 * 1024];
    let new = vec![b'n'; 3 * 1024 * 1024 + 7];
    let (_source, recv, finish) = fill_replacing(&h, &p, &new, &old, 4);
    let sealed = recv.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    let dest = PathBuf::from(&candidate.snapshot().job().destination_path);
    let started = std::time::Instant::now();
    let renamed = candidate.attempt_local_publication().unwrap();
    let publish_ms = started.elapsed().as_millis() as u64;
    let schema_after = schema(&p);
    let written = fs::read(&dest).unwrap();
    let observed = renamed.record_target_observation().unwrap();
    let finished = observed.settle_local().unwrap();
    let settled = finished.snapshot().phase();
    let receipt = finished.snapshot().receipt().is_some();
    let usage = h.inventory().unwrap().recorded_usage();
    let report = serde_json::json!({
        "status": if written == new
            && schema_after == 10
            && settled == Phase::Completed
            && receipt
            && usage == (0, 0)
        { "passed" } else { "failed" },
        "preImageBytes": old.len(),
        "newBytes": new.len(),
        "newSha256": format!("{:x}", Sha256::digest(&new)),
        "writtenBytes": written.len(),
        "writtenSha256": format!("{:x}", Sha256::digest(&written)),
        "databaseSchema": schema_after,
        "publishMs": publish_ms,
        "finalPhase": format!("{settled:?}"),
        "hasReceipt": receipt,
        "usageAfter": [usage.0, usage.1],
        "scope": "LOCAL host replacement on a real NTFS directory; not two-host, not restart-resume",
    });
    fs::write(&out, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    assert_eq!(report["status"], "passed");
    drop(finished);
    h.close().unwrap();
}
