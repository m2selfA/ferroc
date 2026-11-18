use super::*;
use crate::config::Policy;
use std::{
    fs,
    os::unix::{ffi::OsStringExt, fs::symlink},
};
fn fixture() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}
fn rt(root: &Path) -> Runtime {
    Runtime::new(Policy::new(vec![root.to_owned()], false).unwrap())
}
fn scan(runtime: &Runtime, root: &Path) -> Result<ManifestObservation> {
    runtime.scan_fleet_manifest(root, ScanLimits::default(), &CancelToken::new())
}
fn sha(observation: &ManifestObservation, path: &str) -> [u8; 32] {
    match observation
        .manifest()
        .entries()
        .find(|(name, _)| *name == path)
        .unwrap()
        .1
    {
        EntryKind::File { sha256, .. } => sha256.unwrap(),
        _ => panic!("not file"),
    }
}
#[test]
fn nested_empty_and_cross_chunk_files_have_real_sha_and_no_changes_on_second_scan() {
    let temp = fixture();
    let root = temp.path();
    fs::create_dir_all(root.join("one/empty")).unwrap();
    fs::write(root.join("zero"), []).unwrap();
    let bytes = vec![0x42; 131073];
    fs::write(root.join("one/large"), &bytes).unwrap();
    let runtime = rt(root);
    let a = scan(&runtime, root).unwrap();
    let b = scan(&runtime, root).unwrap();
    assert_eq!(a.manifest().len(), 4);
    assert_eq!(a.files_hashed(), 2);
    assert_eq!(a.bytes_hashed(), 131073);
    assert_eq!(
        sha(&a, "one/large"),
        <[u8; 32]>::from(Sha256::digest(&bytes))
    );
    assert_eq!(a.consistency(), super::super::ScanConsistency::ReadSequence);
    assert_eq!(
        crate::fleet::manifest::diff(
            a.manifest(),
            b.manifest(),
            crate::fleet::manifest::Comparison::Checksum
        )
        .unwrap()
        .changes()
        .len(),
        0
    );
    assert_eq!(fs::read(root.join("one/large")).unwrap(), bytes);
}
#[test]
fn hardlink_and_symlink_objects_are_refused_without_opening_targets() {
    let temp = fixture();
    let root = temp.path();
    let runtime = rt(root);
    fs::write(root.join("a"), b"keep").unwrap();
    fs::hard_link(root.join("a"), root.join("b")).unwrap();
    assert!(scan(&runtime, root).is_err());
    fs::remove_file(root.join("b")).unwrap();
    symlink(root.join("a"), root.join("link")).unwrap();
    assert!(scan(&runtime, root).is_err());
    assert_eq!(fs::read(root.join("a")).unwrap(), b"keep");
}
#[test]
fn fifo_and_socket_are_rejected_without_read_io_or_waiting_for_a_peer() {
    let temp = fixture();
    let root = temp.path();
    let runtime = rt(root);
    let name = CString::new(root.join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: test-owned path and mode; no producer is started.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(scan(&runtime, root).is_err());
    fs::remove_file(root.join("fifo")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
    assert!(scan(&runtime, root).is_err());
}
#[test]
fn non_utf8_names_reject_the_whole_observation() {
    let temp = fixture();
    let root = temp.path();
    fs::write(root.join(std::ffi::OsString::from_vec(vec![0xff])), b"x").unwrap();
    assert!(scan(&rt(root), root).is_err());
}
#[test]
fn global_entry_budget_counts_excluded_and_ancestor_queued_names() {
    let temp = fixture();
    let root = temp.path();
    fs::create_dir(root.join("a")).unwrap();
    fs::write(root.join("a/x"), b"x").unwrap();
    fs::write(root.join("b"), b"b").unwrap();
    let runtime = rt(root);
    let mut limits = ScanLimits::default();
    limits.manifest.max_entries = 2;
    assert!(
        runtime
            .scan_fleet_manifest(root, limits, &CancelToken::new())
            .is_err()
    );
    let rules = ScanRules::new(vec!["a".into(), "b".into()]).unwrap();
    limits.manifest.max_entries = 1;
    assert!(
        runtime
            .scan_fleet_manifest_with_rules(root, limits, &rules, &CancelToken::new())
            .is_err()
    );
}
#[test]
fn explicit_exclusion_skips_external_symlink_and_descendant_hash_io() {
    let temp = fixture();
    let root = temp.path();
    let other = fixture();
    fs::write(other.path().join("large"), [3; 8192]).unwrap();
    symlink(other.path(), root.join("skip")).unwrap();
    fs::write(root.join("keep"), b"x").unwrap();
    let limits = ScanLimits {
        max_hashed_bytes: 1,
        ..ScanLimits::default()
    };
    let rules = ScanRules::new(vec!["skip".into()]).unwrap();
    let v = rt(root)
        .scan_fleet_manifest_with_rules(root, limits, &rules, &CancelToken::new())
        .unwrap();
    assert_eq!(v.files_hashed(), 1);
    assert_eq!(v.manifest().len(), 1);
    assert_eq!(v.bytes_hashed(), 1);
}
#[test]
fn byte_path_and_depth_budgets_fail_closed_without_partial_manifest() {
    let temp = fixture();
    let root = temp.path();
    fs::create_dir(root.join("one")).unwrap();
    fs::write(root.join("one/a"), b"abc").unwrap();
    let runtime = rt(root);
    let limits = ScanLimits {
        max_hashed_bytes: 2,
        ..ScanLimits::default()
    };
    assert!(
        runtime
            .scan_fleet_manifest(root, limits, &CancelToken::new())
            .is_err()
    );
    let limits = ScanLimits {
        max_depth: 1,
        ..ScanLimits::default()
    };
    assert!(
        runtime
            .scan_fleet_manifest(root, limits, &CancelToken::new())
            .is_err()
    );
    let limits = ScanLimits {
        manifest: crate::fleet::manifest::ManifestLimits {
            max_total_path_bytes: 3,
            ..crate::fleet::manifest::ManifestLimits::default()
        },
        ..ScanLimits::default()
    };
    assert!(
        runtime
            .scan_fleet_manifest(root, limits, &CancelToken::new())
            .is_err()
    );
}
#[test]
fn cancellation_before_and_after_first_read_returns_no_observation() {
    let temp = fixture();
    let root = temp.path();
    fs::write(root.join("large"), vec![0x11; 131073]).unwrap();
    let runtime = rt(root);
    let token = CancelToken::new();
    token.cancel();
    assert!(scan_cancel(&runtime, root, &token).is_err());
    let token = CancelToken::new();
    let mut reads = 0;
    let result = observe_with(
        &runtime,
        &Mutex::new(()),
        root,
        ScanLimits::default(),
        &token,
        &ScanRules::default(),
        |event| {
            if let Event::FileChunk(_, _) = event {
                reads += 1;
                token.cancel();
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(reads, 1);
}
fn scan_cancel(runtime: &Runtime, root: &Path, token: &CancelToken) -> Result<ManifestObservation> {
    runtime.scan_fleet_manifest(root, ScanLimits::default(), token)
}
#[test]
fn moved_root_and_external_symlink_replacement_are_detected_before_any_file_read() {
    let temp = fixture();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a"), b"private").unwrap();
    let other = fixture();
    fs::write(other.path().join("a"), b"foreign").unwrap();
    let runtime = rt(&root);
    let mut reads = 0;
    let result = observe_with(
        &runtime,
        &Mutex::new(()),
        &root,
        ScanLimits::default(),
        &CancelToken::new(),
        &ScanRules::default(),
        |event| {
            match event {
                Event::DirectoryRead(path) if path == root => {
                    fs::rename(&root, temp.path().join("moved"))?;
                    symlink(other.path(), &root)?;
                }
                Event::FileChunk(_, _) => reads += 1,
                _ => {}
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(reads, 0);
    assert_eq!(fs::read(other.path().join("a")).unwrap(), b"foreign");
}
#[test]
fn file_replacement_after_read_is_rejected_by_original_inode_check() {
    let temp = fixture();
    let root = temp.path();
    let path = root.join("a");
    fs::write(&path, b"abc").unwrap();
    let runtime = rt(root);
    let mut changed = false;
    let result = observe_with(
        &runtime,
        &Mutex::new(()),
        root,
        ScanLimits::default(),
        &CancelToken::new(),
        &ScanRules::default(),
        |event| {
            if let Event::FileChunk(p, _) = event
                && !changed
            {
                fs::rename(p, root.join("old"))?;
                fs::write(p, b"xyz")?;
                changed = true;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(changed);
    assert_eq!(fs::read(path).unwrap(), b"xyz");
}
#[test]
fn added_directory_name_after_enumeration_rejects_without_partial_result() {
    let temp = fixture();
    let root = temp.path();
    fs::write(root.join("a"), b"abc").unwrap();
    let runtime = rt(root);
    let mut added = false;
    let result = observe_with(
        &runtime,
        &Mutex::new(()),
        root,
        ScanLimits::default(),
        &CancelToken::new(),
        &ScanRules::default(),
        |event| {
            if let Event::DirectoryRead(_) = event
                && !added
            {
                fs::write(root.join("new"), b"new")?;
                added = true;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(added);
}
#[test]
fn same_mtime_read_prefix_mutation_is_detected_by_ctime_not_called_a_snapshot() {
    use std::io::{Seek, SeekFrom, Write};
    let temp = fixture();
    let root = temp.path();
    let path = root.join("a");
    fs::write(&path, vec![0x33; 131073]).unwrap();
    let old = fs::metadata(&path).unwrap().modified().unwrap();
    let runtime = rt(root);
    let mut changed = false;
    let result = observe_with(
        &runtime,
        &Mutex::new(()),
        root,
        ScanLimits::default(),
        &CancelToken::new(),
        &ScanRules::default(),
        |event| {
            if let Event::FileChunk(p, offset) = event
                && offset == 65536
                && !changed
            {
                let mut f = OpenOptions::new().write(true).open(p)?;
                f.seek(SeekFrom::Start(0))?;
                f.write_all(&vec![0x44; 65536])?;
                f.set_times(fs::FileTimes::new().set_modified(old))?;
                changed = true;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(changed);
    assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), old);
}
#[tokio::test]
async fn runtime_shutdown_and_disabled_transfers_refuse_new_scans() {
    let temp = fixture();
    let root = temp.path();
    let mut policy = Policy::new(vec![root.to_owned()], false).unwrap();
    policy.allow_transfers = false;
    assert!(scan(&Runtime::new(policy), root).is_err());
    let runtime = rt(root);
    runtime.shutdown().await;
    assert!(scan(&runtime, root).is_err());
}
#[test]
fn linux_case_distinct_names_stay_distinct_exact_utf8_keys() {
    let temp = fixture();
    let root = temp.path();
    fs::write(root.join("a"), b"a").unwrap();
    fs::write(root.join("A"), b"A").unwrap();
    let v = scan(&rt(root), root).unwrap();
    assert_eq!(v.files_hashed(), 2);
    assert_ne!(sha(&v, "a"), sha(&v, "A"));
}
