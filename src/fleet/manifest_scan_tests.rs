use super::*;
use crate::{
    config::Policy,
    fleet::{
        manifest::{Comparison, EntryKind, diff},
        protocol::device_digest,
        sync_plan::{SyncTemplate, plan_add_only},
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    time::Duration,
};
use uuid::Uuid;

fn runtime(root: &Path) -> Runtime {
    Runtime::new(Policy::new(vec![root.to_path_buf()], false).unwrap())
}
fn scan(rt: &Runtime, root: &Path) -> ManifestObservation {
    rt.scan_fleet_manifest(root, ScanLimits::default(), &CancelToken::new())
        .unwrap()
}
fn file_sha(manifest: &Manifest, name: &str) -> [u8; 32] {
    let (_, kind) = manifest.entries().find(|(p, _)| *p == name).unwrap();
    match kind {
        EntryKind::File { sha256, .. } => sha256.unwrap(),
        _ => panic!("not a file"),
    }
}
/// Explicit bounded actual-file tree probe, NOT metadata-only or network sync.
#[test]
#[ignore = "explicit actual 273-entry tree/8MiB observation probe"]
fn native_bounded_tree_observation_probe() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    for directory in 0..16 {
        fs::create_dir(root.join(format!("d{directory:02}"))).unwrap();
        for file in 0..16 {
            fs::write(
                root.join(format!("d{directory:02}/f{file:02}")),
                vec![file as u8; 129],
            )
            .unwrap();
        }
    }
    fs::write(root.join("large"), vec![0x42; 8 * 1024 * 1024]).unwrap();
    let rt = runtime(&root);
    let start = std::time::Instant::now();
    let before = scan(&rt, &root);
    let elapsed_ms = start.elapsed().as_millis();
    assert_eq!(before.manifest().len(), 273);
    assert_eq!(before.files_hashed(), 257);
    assert_eq!(before.bytes_hashed(), 8 * 1024 * 1024 + 256 * 129);
    for (name, kind) in before.manifest().entries() {
        if let EntryKind::File {
            sha256: Some(expected),
            ..
        } = kind
        {
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(fs::read(root.join(name)).unwrap())),
                *expected
            );
        }
    }
    let again = scan(&rt, &root);
    assert_eq!(
        diff(before.manifest(), again.manifest(), Comparison::Checksum)
            .unwrap()
            .changes()
            .len(),
        0
    );
    let changed = root.join("d15/f15");
    let modified = fs::metadata(&changed).unwrap().modified().unwrap();
    fs::write(&changed, vec![99; 129]).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&changed)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let after = scan(&rt, &root);
    let delta = diff(after.manifest(), before.manifest(), Comparison::Checksum).unwrap();
    assert_eq!(delta.changes().len(), 1);
    assert_eq!(delta.changes()[0].path, "d15/f15");
    let expected_bytes = before.bytes_hashed();
    drop(before);
    drop(again);
    drop(after);
    drop(rt);
    drop(temp);
    assert!(!root.exists());
    if let Ok(output) = std::env::var("FERROC_FLEET_SCAN_OUTPUT") {
        let exe = std::env::current_exe().unwrap();
        fs::write(output,serde_json::to_vec_pretty(&serde_json::json!({
            "status":"passed","scope":"Windows actual generated tree, sequential read only; not network/two-host/production",
            "entries":273,"files":257,"bytes_hashed":expected_bytes,"first_scan_ms":elapsed_ms,
            "all_observed_sha_match_disk":true,"second_scan_changes":0,"third_scan_changes":1,
            "changed_path":"d15/f15","workspace_removed":true,
            "test_sha256":format!("{:x}",Sha256::digest(fs::read(exe).unwrap())),
            "consistency":"read_sequence","namespace":"exact_utf8_unqualified"
        })).unwrap()).unwrap();
    }
}

#[test]
fn actual_nested_tree_hashes_and_second_scan_selects_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("nested/empty")).unwrap();
    fs::write(root.join("one"), b"x").unwrap();
    fs::write(root.join("nested/zero"), []).unwrap();
    let data = vec![0x5a; 131073];
    fs::write(root.join("nested/cross"), &data).unwrap();
    let rt = runtime(root);
    let a = scan(&rt, root);
    let b = scan(&rt, root);
    assert_eq!(a.manifest().len(), 5);
    assert_eq!(a.files_hashed(), 3);
    assert_eq!(a.bytes_hashed(), 131074);
    assert_eq!(
        file_sha(a.manifest(), "nested/cross"),
        <[u8; 32]>::from(Sha256::digest(&data))
    );
    assert_eq!(a.consistency(), ScanConsistency::ReadSequence);
    assert_eq!(
        a.namespace(),
        crate::fleet::manifest::Namespace::ExactUtf8Unqualified
    );
    let d = diff(a.manifest(), b.manifest(), Comparison::Checksum).unwrap();
    assert_eq!(d.changes().len(), 0);
    assert_eq!(fs::read(root.join("nested/cross")).unwrap(), data);
}
#[test]
fn same_size_same_mtime_change_is_selected_by_checksum() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let path = root.join("same.bin");
    fs::write(&path, b"abc").unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let rt = runtime(root);
    let before = scan(&rt, root);
    fs::write(&path, b"xyz").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    let after = scan(&rt, root);
    let d = diff(after.manifest(), before.manifest(), Comparison::Checksum).unwrap();
    assert_eq!(d.changes().len(), 1);
    assert_eq!(d.changes()[0].path, "same.bin");
    assert_eq!(
        diff(after.manifest(), before.manifest(), Comparison::Quick)
            .unwrap()
            .changes()
            .len(),
        0
    );
}
#[test]
fn empty_and_zero_file_are_valid_at_zero_hash_budget() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let rt = runtime(root);
    let limits = ScanLimits {
        max_hashed_bytes: 0,
        ..Default::default()
    };
    assert!(
        rt.scan_fleet_manifest(root, limits, &CancelToken::new())
            .unwrap()
            .manifest()
            .is_empty()
    );
    fs::write(root.join("zero"), []).unwrap();
    let o = rt
        .scan_fleet_manifest(root, limits, &CancelToken::new())
        .unwrap();
    assert_eq!(o.files_hashed(), 1);
    assert_eq!(o.bytes_hashed(), 0);
    assert_eq!(
        file_sha(o.manifest(), "zero"),
        <[u8; 32]>::from(Sha256::digest([]))
    );
}
#[test]
fn global_entry_budget_counts_names_queued_in_ancestor_frames() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("a")).unwrap();
    fs::write(root.join("z"), b"z").unwrap();
    fs::write(root.join("a/x"), b"x").unwrap();
    let rt = runtime(root);
    let limits = ScanLimits {
        manifest: ManifestLimits {
            max_entries: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut chunks = 0;
    let error = rt
        .scan_fleet_manifest_for_test(root, limits, &CancelToken::new(), |event| {
            if matches!(event, ScanEvent::FileChunk(_, _)) {
                chunks += 1;
            }
            Ok(())
        })
        .unwrap_err();
    assert!(format!("{error:#}").contains("entry limit"));
    assert_eq!(chunks, 0);
    assert_eq!(fs::read(root.join("a/x")).unwrap(), b"x");
}
#[test]
fn path_depth_and_hash_budgets_return_errors_not_partial_manifests() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("a")).unwrap();
    fs::write(root.join("a/data"), b"abc").unwrap();
    let rt = runtime(root);
    for limits in [
        ScanLimits {
            max_depth: 1,
            ..Default::default()
        },
        ScanLimits {
            max_hashed_bytes: 2,
            ..Default::default()
        },
        ScanLimits {
            manifest: ManifestLimits {
                max_total_path_bytes: 1,
                ..Default::default()
            },
            ..Default::default()
        },
        ScanLimits {
            max_hashed_bytes: MAX_HASHED_BYTES + 1,
            ..Default::default()
        },
        ScanLimits {
            max_depth: 0,
            ..Default::default()
        },
        ScanLimits {
            manifest: ManifestLimits {
                max_entries: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    ] {
        assert!(
            rt.scan_fleet_manifest(root, limits, &CancelToken::new())
                .is_err()
        );
    }
    assert_eq!(fs::read(root.join("a/data")).unwrap(), b"abc");
}
#[test]
fn outside_missing_file_root_and_traversal_are_not_empty_directories() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("allowed")).unwrap();
    fs::write(root.join("file"), b"x").unwrap();
    let rt = runtime(&root.join("allowed"));
    for path in [
        root.to_path_buf(),
        root.join("allowed/missing"),
        root.join("file"),
        root.join("allowed/../allowed"),
    ] {
        assert!(
            rt.scan_fleet_manifest(&path, ScanLimits::default(), &CancelToken::new())
                .is_err()
        );
    }
}
#[test]
fn multi_link_files_are_refused_without_modification() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::write(root.join("original"), b"abc").unwrap();
    fs::hard_link(root.join("original"), root.join("alias")).unwrap();
    let rt = runtime(root);
    assert!(
        rt.scan_fleet_manifest(root, ScanLimits::default(), &CancelToken::new())
            .is_err()
    );
    assert_eq!(fs::read(root.join("original")).unwrap(), b"abc");
    assert_eq!(fs::read(root.join("alias")).unwrap(), b"abc");
}
#[test]
fn junction_root_ancestor_and_child_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("actual/sub")).unwrap();
    fs::create_dir(root.join("tree")).unwrap();
    let result = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.join("tree").join("link"))
        .arg(root.join("actual"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let rt = runtime(root);
    for path in [
        root.join("tree/link"),
        root.join("tree/link/sub"),
        root.join("tree"),
    ] {
        assert!(
            rt.scan_fleet_manifest(&path, ScanLimits::default(), &CancelToken::new())
                .is_err()
        );
    }
}
#[test]
fn reserved_and_non_utf8_names_are_not_skipped_or_lossily_mapped() {
    use std::os::windows::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("reserved")).unwrap();
    fs::create_dir(root.join("unicode")).unwrap();
    fs::write(root.join("reserved/.ferroc-fleet-owned"), b"x").unwrap();
    let odd = std::ffi::OsString::from_wide(&[0xd800]);
    fs::write(root.join("unicode").join(odd), b"y").unwrap();
    let rt = runtime(root);
    for path in [root.join("reserved"), root.join("unicode")] {
        assert!(
            rt.scan_fleet_manifest(&path, ScanLimits::default(), &CancelToken::new())
                .is_err()
        );
    }
}
#[test]
fn cancellation_before_and_after_first_native_chunk_returns_no_observation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let data = vec![7; 131073];
    fs::write(root.join("data"), &data).unwrap();
    let rt = runtime(root);
    let token = CancelToken::new();
    token.cancel();
    assert!(
        rt.scan_fleet_manifest(root, ScanLimits::default(), &token)
            .is_err()
    );
    let token = CancelToken::new();
    let mut chunks = 0;
    let error = rt
        .scan_fleet_manifest_for_test(root, ScanLimits::default(), &token, |event| {
            if let ScanEvent::FileChunk(path, bytes) = event {
                assert!(path.ends_with("data"));
                assert_eq!(bytes, 65536);
                chunks += 1;
                token.cancel();
            }
            Ok(())
        })
        .unwrap_err();
    assert!(format!("{error:#}").contains("cancelled"));
    assert_eq!(chunks, 1);
    assert_eq!(fs::read(root.join("data")).unwrap(), data);
}
#[test]
fn truncation_mid_read_returns_error_and_releases_read_handles() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let path = root.join("data");
    let data = vec![8; 131073];
    fs::write(&path, &data).unwrap();
    let rt = runtime(root);
    let result = rt.scan_fleet_manifest_for_test(
        root,
        ScanLimits::default(),
        &CancelToken::new(),
        |event| {
            if let ScanEvent::FileChunk(path, 65536) = event {
                fs::OpenOptions::new().write(true).open(path)?.set_len(0)?;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    fs::write(&path, &data).unwrap();
    let moved = root.join("moved");
    fs::rename(&path, &moved).unwrap();
    fs::rename(&moved, &path).unwrap();
    assert_eq!(fs::read(path).unwrap(), data);
}
#[test]
fn external_same_size_rewrite_with_restored_time_proves_read_sequence_not_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let path = root.join("data");
    let data = vec![9; 131073];
    fs::write(&path, &data).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let rt = runtime(root);
    let o = rt
        .scan_fleet_manifest_for_test(root, ScanLimits::default(), &CancelToken::new(), |event| {
            if let ScanEvent::FileChunk(path, 65536) = event {
                let mut writer = fs::OpenOptions::new().write(true).open(path)?;
                writer.seek(SeekFrom::Start(0))?;
                writer.write_all(b"x")?;
                writer.flush()?;
                writer.set_times(fs::FileTimes::new().set_modified(modified))?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        file_sha(o.manifest(), "data"),
        <[u8; 32]>::from(Sha256::digest(&data))
    );
    let current = fs::read(&path).unwrap();
    assert_ne!(current, data);
    assert_ne!(
        file_sha(o.manifest(), "data"),
        <[u8; 32]>::from(Sha256::digest(&current))
    );
    fs::write(&path, &data).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(
        file_sha(scan(&rt, root).manifest(), "data"),
        file_sha(o.manifest(), "data")
    );
}
#[test]
fn directory_addition_after_enumeration_is_not_silently_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::write(root.join("a"), b"a").unwrap();
    let rt = runtime(root);
    let mut changed = false;
    let result = rt.scan_fleet_manifest_for_test(
        root,
        ScanLimits::default(),
        &CancelToken::new(),
        |event| {
            if let ScanEvent::DirectoryRead(path) = event
                && !changed
            {
                fs::write(path.join("late"), b"late")?;
                changed = true;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("late")).unwrap(), b"late");
}
#[test]
fn native_ancestor_handles_deny_root_rename_only_until_scan_returns() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let root = base.join("tree");
    fs::create_dir(&root).unwrap();
    let rt = runtime(base);
    let moved = base.join("moved");
    rt.scan_fleet_manifest_for_test(&root, ScanLimits::default(), &CancelToken::new(), |event| {
        if let ScanEvent::DirectoryRead(_) = event {
            assert_eq!(
                fs::rename(&root, &moved).unwrap_err().raw_os_error(),
                Some(32)
            );
        }
        Ok(())
    })
    .unwrap();
    fs::rename(&root, &moved).unwrap();
    fs::rename(&moved, &root).unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_disable_and_runtime_shutdown_block_new_scans_and_drain_accepted_one() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    fs::write(root.join("data"), b"x").unwrap();
    let mut policy = Policy::new(vec![root.clone()], false).unwrap();
    policy.allow_transfers = false;
    let disabled = Runtime::new(policy);
    assert!(
        disabled
            .scan_fleet_manifest(&root, ScanLimits::default(), &CancelToken::new())
            .is_err()
    );
    let rt = Arc::new(runtime(&root));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let reader = rt.clone();
    let path = root.clone();
    let scan = tokio::task::spawn_blocking(move || {
        reader.scan_fleet_manifest_for_test(
            &path,
            ScanLimits::default(),
            &CancelToken::new(),
            |event| {
                if let ScanEvent::FileChunk(_, _) = event {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                Ok(())
            },
        )
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let stopped = rt.clone();
    let mut stop = tokio::spawn(async move { stopped.shutdown_fleet_host().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut stop)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    scan.await.unwrap().unwrap();
    stop.await.unwrap().unwrap();
    assert!(
        rt.scan_fleet_manifest(&root, ScanLimits::default(), &CancelToken::new())
            .is_err()
    );
}
#[test]
fn actual_scanned_additions_feed_existing_plan_without_claiming_apply() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let source = base.join("source");
    let target = base.join("target");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&target).unwrap();
    fs::create_dir(source.join("nested")).unwrap();
    fs::write(source.join("nested/a"), b"abc").unwrap();
    let rt = runtime(base);
    let a = scan(&rt, &source);
    let b = scan(&rt, &target);
    let d = diff(a.manifest(), b.manifest(), Comparison::Checksum).unwrap();
    let plan = plan_add_only(
        a.manifest(),
        &d,
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: device_digest("A").unwrap(),
            target_device: device_digest("B").unwrap(),
            transfer_id: Uuid::from_bytes([2; 16]),
            source_root: source.to_str().unwrap(),
            target_root: target.to_str().unwrap(),
            deadline_ms: 60000,
            idempotency_prefix: "native-scan",
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    assert_eq!(plan.files().len(), 1);
    assert_eq!(plan.files()[0].path, "nested/a");
    assert_eq!(plan.planned_bytes(), 3);
    assert_eq!(plan.directories_ensured(), 1);
    assert!(!target.join("nested/a").exists());
}
