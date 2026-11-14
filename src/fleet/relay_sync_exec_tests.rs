use super::*;
use crate::fleet::journal::JobKey;
use crate::fleet::sync_run::RunState;
use crate::fleet::{
    manifest::{Comparison, EntryKind, Manifest, ManifestEntry, ManifestLimits, diff},
    sync_exec::{
        CancelToken, ExecOutcome, PreparedFile, execute_file, execute_file_cancellable, run_plan,
    },
    sync_grant::{GrantTemplate, issue_for_plan},
    sync_plan::{SyncTemplate, plan_add_only},
    sync_run::{FileState, RunLedger},
};

/// Two real files, one additive plan, real grants, real ledger, real relay.
/// PUBLIC cfg(test) issuance; one process; NOT two hosts or production enrollment.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn additive_plan_runs_in_order_through_real_relay_and_settles() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let files: [(&str, Vec<u8>); 2] = [("a.bin", vec![0x21]), ("b.bin", vec![0x42; 131_072])];
    let mut entries = Vec::new();
    for (name, data) in &files {
        std::fs::write(root.join("source").join(name), data).unwrap();
        entries.push(ManifestEntry {
            path: (*name).into(),
            kind: EntryKind::File {
                size: data.len() as u64,
                mtime_ns: 1,
                sha256: Some(Sha256::digest(data).into()),
            },
        });
    }
    let source_manifest = Manifest::new(entries, ManifestLimits::default()).unwrap();
    let target_manifest = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let source_root = root.join("source").to_str().unwrap().to_string();
    let target_root = root.join("target").to_str().unwrap().to_string();
    let plan = plan_add_only(
        &source_manifest,
        &diff(&source_manifest, &target_manifest, Comparison::Checksum).unwrap(),
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("source-A").unwrap(),
            target_device: device_digest("target-B").unwrap(),
            transfer_id: Uuid::from_bytes([9; 16]),
            source_root: &source_root,
            target_root: &target_root,
            deadline_ms: 60_000,
            idempotency_prefix: "sync-run-1",
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    let batch = issue_for_plan(
        &plan,
        &GrantTemplate {
            source_session: Uuid::from_bytes([3; 16]),
            target_session: Uuid::from_bytes([4; 16]),
            authorization_seed: 31,
            epoch_seed: 41,
            issued_at_ms: 100,
            lease_ms: 30_000,
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    assert_eq!(batch.len(), 2);

    drop(new_private(&root.join("target/host.db")).unwrap());
    let registry = Arc::new(FleetRelay::new());
    let (url, _relay, server) = server(&root, Some(registry.clone())).await;
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut ledger = RunLedger::new(&plan);
    for (index, file) in plan.files().iter().enumerate() {
        let grant = batch.grants()[index].clone();
        assert_eq!(ledger.start_next().unwrap(), Some(file.path.as_str()));
        let tickets = registry
            .approve_local(&grant, "source-A", "target-B", Duration::from_secs(30))
            .unwrap();
        let source_link = link(
            &url,
            tickets.source.expose_secret(),
            &grant,
            Direction::SourceToTarget,
        )
        .await
        .unwrap();
        let target_link = link(
            &url,
            tickets.target.expose_secret(),
            &grant,
            Direction::TargetToSource,
        )
        .await
        .unwrap();
        let window = SourceWindow::new(
            srt.open_fleet_source(records(&grant, Direction::SourceToTarget))
                .unwrap(),
            4,
        )
        .unwrap();
        let receiver = host
            .admit_receiver(records(&grant, Direction::TargetToSource))
            .unwrap();
        let receipt = execute_file(window, source_link, receiver, target_link)
            .await
            .unwrap();
        assert_eq!(receipt.size, file.bytes);
        ledger.settle(&receipt).unwrap();
        let written = std::fs::read(root.join("target").join(&file.path)).unwrap();
        assert_eq!(written.len() as u64, file.bytes);
    }
    assert_eq!(ledger.start_next().unwrap(), None);
    assert_eq!(ledger.settled_count(), 2);
    assert_eq!(ledger.settled_bytes(), 1 + 131_072);
    assert!(
        ledger
            .entries()
            .iter()
            .all(|e| e.state() == FileState::Settled)
    );
    assert_eq!(
        std::fs::read(root.join("target/b.bin")).unwrap(),
        files[1].1
    );
    assert_eq!(
        std::fs::read(root.join("source/b.bin")).unwrap(),
        files[1].1
    );
    host.close().unwrap();
    registry.close();
    server.abort();
    let _ = server.await;
}

/// The driver owns ordering: two files run through `run_plan` with a caller-supplied
/// prepare closure, and the returned status is Complete with both receipts.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_plan_drives_two_files_in_order_to_complete() {
    run_driver_fixture(false).await;
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_plan_wrong_prepared_target_job_blocks_before_data_and_keeps_debt() {
    run_driver_fixture(true).await;
}

#[cfg(windows)]
async fn run_driver_fixture(wrong_job: bool) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let files: [(&str, Vec<u8>); 2] =
        [("x.bin", vec![0x11; 70_000]), ("y.bin", vec![0x22; 70_000])];
    let mut entries = Vec::new();
    for (name, data) in &files {
        std::fs::write(root.join("source").join(name), data).unwrap();
        entries.push(ManifestEntry {
            path: (*name).into(),
            kind: EntryKind::File {
                size: data.len() as u64,
                mtime_ns: 1,
                sha256: Some(Sha256::digest(data).into()),
            },
        });
    }
    let source_manifest = Manifest::new(entries, ManifestLimits::default()).unwrap();
    let target_manifest = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let source_root = root.join("source").to_str().unwrap().to_string();
    let target_root = root.join("target").to_str().unwrap().to_string();
    let plan = plan_add_only(
        &source_manifest,
        &diff(&source_manifest, &target_manifest, Comparison::Checksum).unwrap(),
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("source-A").unwrap(),
            target_device: device_digest("target-B").unwrap(),
            transfer_id: Uuid::from_bytes([9; 16]),
            source_root: &source_root,
            target_root: &target_root,
            deadline_ms: 60_000,
            idempotency_prefix: "sync-drive-1",
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    let batch = issue_for_plan(
        &plan,
        &GrantTemplate {
            source_session: Uuid::from_bytes([3; 16]),
            target_session: Uuid::from_bytes([4; 16]),
            authorization_seed: 91,
            epoch_seed: 101,
            issued_at_ms: 100,
            lease_ms: 30_000,
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let registry = Arc::new(FleetRelay::new());
    let (url, _relay, server) = server(&root, Some(registry.clone())).await;
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut ledger = RunLedger::new(&plan);
    let token = CancelToken::new();
    let status = run_plan(&plan, &mut ledger, &token, |index| {
        // Deliberately provide a valid live owner for the other same-size job.
        let grant = batch.grants()[if wrong_job { 1 } else { index }].clone();
        let registry = registry.clone();
        let url = url.clone();
        let host = &host;
        let srt = &srt;
        async move {
            let tickets =
                registry.approve_local(&grant, "source-A", "target-B", Duration::from_secs(30))?;
            let source = link(
                &url,
                tickets.source.expose_secret(),
                &grant,
                Direction::SourceToTarget,
            )
            .await?;
            let target = link(
                &url,
                tickets.target.expose_secret(),
                &grant,
                Direction::TargetToSource,
            )
            .await?;
            let window = SourceWindow::new(
                srt.open_fleet_source(records(&grant, Direction::SourceToTarget))?,
                4,
            )?;
            let receiver = host.admit_receiver(records(&grant, Direction::TargetToSource))?;
            Ok(PreparedFile {
                window,
                source,
                receiver,
                target,
            })
        }
    })
    .await
    .unwrap();
    if wrong_job {
        assert_eq!(status.state, RunState::Blocked);
        assert_eq!(status.settled, 0);
        assert_eq!(status.failed, 1);
        assert_eq!(ledger.entries()[1].state(), FileState::Pending);
        assert!(
            ledger
                .failure()
                .unwrap()
                .reason
                .contains("prepared target job differs")
        );
        assert!(!root.join("target/x.bin").exists());
        assert!(!root.join("target/y.bin").exists());
        let snapshot = host
            .get(&JobKey::from_job(batch.grants()[1].job()))
            .unwrap()
            .unwrap();
        let stage = snapshot.stage().unwrap();
        // No DATA was pumped, but the admitted reservation is not forgiven.
        assert_eq!(host.inventory().unwrap().recorded_usage(), (70_000, 1));
        assert_eq!(std::fs::metadata(stage.path()).unwrap().len(), 0);
        assert!(snapshot.receipt().is_none());
        assert_eq!(
            std::fs::read(root.join("source/y.bin")).unwrap(),
            files[1].1
        );
        assert!(ledger.start_next().is_err());
    } else {
        assert_eq!(status.state, RunState::Complete);
        assert_eq!(status.settled, 2);
        assert_eq!(status.settled_bytes, 140_000);
        assert_eq!(
            std::fs::read(root.join("target/y.bin")).unwrap(),
            files[1].1
        );
        assert_eq!(
            std::fs::read(root.join("target/x.bin")).unwrap(),
            files[0].1
        );
        assert_eq!(status.failed, 0);
    }
    host.close().unwrap();
    registry.close();
    server.abort();
    let _ = server.await;
}

/// A token cancelled before the driver starts means no link is even prepared.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_plan_with_pre_cancelled_token_prepares_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    std::fs::write(root.join("source/one.bin"), b"abc").unwrap();
    let source_manifest = Manifest::new(
        vec![ManifestEntry {
            path: "one.bin".into(),
            kind: EntryKind::File {
                size: 3,
                mtime_ns: 1,
                sha256: Some(Sha256::digest(b"abc").into()),
            },
        }],
        ManifestLimits::default(),
    )
    .unwrap();
    let target_manifest = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let source_root = root.join("source").to_str().unwrap().to_string();
    let target_root = root.join("target").to_str().unwrap().to_string();
    let plan = plan_add_only(
        &source_manifest,
        &diff(&source_manifest, &target_manifest, Comparison::Checksum).unwrap(),
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("source-A").unwrap(),
            target_device: device_digest("target-B").unwrap(),
            transfer_id: Uuid::from_bytes([9; 16]),
            source_root: &source_root,
            target_root: &target_root,
            deadline_ms: 60_000,
            idempotency_prefix: "sync-drive-2",
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    let mut ledger = RunLedger::new(&plan);
    let token = CancelToken::new();
    token.cancel();
    let mut prepared = 0usize;
    let status = run_plan(&plan, &mut ledger, &token, |_| {
        prepared += 1;
        async { unreachable!("cancelled runs must not prepare a file") }
    })
    .await
    .unwrap();
    assert_eq!(prepared, 0);
    assert_eq!(status.state, RunState::Cancelled);
    assert_eq!(status.settled, 0);
    assert!(!root.join("target/one.bin").exists());
}
/// Cancelling before any byte moves still leaves the admitted stage and its full
/// debt: there is no rollback, no cleanup and no receipt.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_before_any_byte_keeps_stage_and_debt_without_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x5a; 131_072];
    std::fs::write(root.join("source/only.bin"), &data).unwrap();
    let entries = vec![ManifestEntry {
        path: "only.bin".into(),
        kind: EntryKind::File {
            size: data.len() as u64,
            mtime_ns: 1,
            sha256: Some(Sha256::digest(&data).into()),
        },
    }];
    let source_manifest = Manifest::new(entries, ManifestLimits::default()).unwrap();
    let target_manifest = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let source_root = root.join("source").to_str().unwrap().to_string();
    let target_root = root.join("target").to_str().unwrap().to_string();
    let plan = plan_add_only(
        &source_manifest,
        &diff(&source_manifest, &target_manifest, Comparison::Checksum).unwrap(),
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("source-A").unwrap(),
            target_device: device_digest("target-B").unwrap(),
            transfer_id: Uuid::from_bytes([9; 16]),
            source_root: &source_root,
            target_root: &target_root,
            deadline_ms: 60_000,
            idempotency_prefix: "sync-cancel-1",
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    let batch = issue_for_plan(
        &plan,
        &GrantTemplate {
            source_session: Uuid::from_bytes([3; 16]),
            target_session: Uuid::from_bytes([4; 16]),
            authorization_seed: 71,
            epoch_seed: 81,
            issued_at_ms: 100,
            lease_ms: 30_000,
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let registry = Arc::new(FleetRelay::new());
    let (url, _relay, server) = server(&root, Some(registry.clone())).await;
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut ledger = RunLedger::new(&plan);
    let grant = batch.grants()[0].clone();
    assert_eq!(ledger.start_next().unwrap(), Some("only.bin"));
    let tickets = registry
        .approve_local(&grant, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let source_link = link(
        &url,
        tickets.source.expose_secret(),
        &grant,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    let target_link = link(
        &url,
        tickets.target.expose_secret(),
        &grant,
        Direction::TargetToSource,
    )
    .await
    .unwrap();
    let window = SourceWindow::new(
        srt.open_fleet_source(records(&grant, Direction::SourceToTarget))
            .unwrap(),
        4,
    )
    .unwrap();
    let receiver = host
        .admit_receiver(records(&grant, Direction::TargetToSource))
        .unwrap();
    let token = CancelToken::new();
    token.cancel();
    let outcome = execute_file_cancellable(window, source_link, receiver, target_link, &token)
        .await
        .unwrap();
    assert_eq!(outcome, ExecOutcome::Cancelled);
    assert!(!root.join("target/only.bin").exists());
    let snapshot = host.get(&JobKey::from_job(grant.job())).unwrap().unwrap();
    assert!(snapshot.stage().is_some());
    let usage = host.inventory().unwrap().recorded_usage();
    assert_eq!(usage.0, data.len() as u64);
    assert_eq!(usage.1, 1);
    ledger.cancel("operator stop").unwrap();
    assert_eq!(ledger.entries()[0].state(), FileState::Cancelled);
    assert!(ledger.entries()[0].receipt().is_none());
    host.close().unwrap();
    registry.close();
    server.abort();
    let _ = server.await;
}
/// A refused target (missing parent) must fail the run and block the ledger.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_file_blocks_the_run_and_keeps_earlier_settlement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = b"xyz";
    std::fs::write(root.join("source/one.bin"), data).unwrap();
    std::fs::write(root.join("source/two.bin"), data).unwrap();
    let entries = vec![
        ManifestEntry {
            path: "one.bin".into(),
            kind: EntryKind::File {
                size: 3,
                mtime_ns: 1,
                sha256: Some(Sha256::digest(data).into()),
            },
        },
        ManifestEntry {
            path: "two.bin".into(),
            kind: EntryKind::File {
                size: 3,
                mtime_ns: 1,
                sha256: Some(Sha256::digest(data).into()),
            },
        },
    ];
    let source_manifest = Manifest::new(entries, ManifestLimits::default()).unwrap();
    let target_manifest = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let source_root = root.join("source").to_str().unwrap().to_string();
    let target_root = root.join("target").to_str().unwrap().to_string();
    let plan = plan_add_only(
        &source_manifest,
        &diff(&source_manifest, &target_manifest, Comparison::Checksum).unwrap(),
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("source-A").unwrap(),
            target_device: device_digest("target-B").unwrap(),
            transfer_id: Uuid::from_bytes([9; 16]),
            source_root: &source_root,
            target_root: &target_root,
            deadline_ms: 60_000,
            idempotency_prefix: "sync-run-2",
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    let batch = issue_for_plan(
        &plan,
        &GrantTemplate {
            source_session: Uuid::from_bytes([3; 16]),
            target_session: Uuid::from_bytes([4; 16]),
            authorization_seed: 51,
            epoch_seed: 61,
            issued_at_ms: 100,
            lease_ms: 30_000,
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let registry = Arc::new(FleetRelay::new());
    let (url, _relay, server) = server(&root, Some(registry.clone())).await;
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut ledger = RunLedger::new(&plan);
    for index in 0..2 {
        let file = &plan.files()[index];
        let grant = batch.grants()[index].clone();
        assert_eq!(ledger.start_next().unwrap(), Some(file.path.as_str()));
        let tickets = registry
            .approve_local(&grant, "source-A", "target-B", Duration::from_secs(30))
            .unwrap();
        let source_link = link(
            &url,
            tickets.source.expose_secret(),
            &grant,
            Direction::SourceToTarget,
        )
        .await
        .unwrap();
        let target_link = link(
            &url,
            tickets.target.expose_secret(),
            &grant,
            Direction::TargetToSource,
        )
        .await
        .unwrap();
        let window = SourceWindow::new(
            srt.open_fleet_source(records(&grant, Direction::SourceToTarget))
                .unwrap(),
            4,
        )
        .unwrap();
        let receiver = match host.admit_receiver(records(&grant, Direction::TargetToSource)) {
            Ok(receiver) => receiver,
            Err(e) => {
                // Admission refuses an existing destination before any byte moves.
                assert_eq!(index, 1, "first admission must succeed: {e:#}");
                ledger.fail(&format!("{e:#}")).unwrap();
                continue;
            }
        };
        let receipt = execute_file(window, source_link, receiver, target_link)
            .await
            .unwrap();
        assert_eq!(receipt.size, 3);
        ledger.settle(&receipt).unwrap();
        // A target that appears before the next file must not be overwritten.
        std::fs::write(root.join("target/two.bin"), b"planted").unwrap();
    }
    assert!(ledger.is_blocked());
    assert_eq!(ledger.settled_count(), 1);
    assert_eq!(ledger.failed_count(), 1);
    assert_eq!(ledger.settled_bytes(), 3);
    assert_eq!(ledger.failure().unwrap().path, "two.bin");
    assert!(ledger.start_next().is_err());
    assert_eq!(
        std::fs::read(root.join("target/two.bin")).unwrap(),
        b"planted"
    );
    host.close().unwrap();
    registry.close();
    server.abort();
    let _ = server.await;
}
