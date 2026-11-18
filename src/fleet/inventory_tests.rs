use super::*;
use crate::fleet::{
    fence::{FencedConnection, OwnerFence},
    identity::{make_directory, new_private},
    job::{JobSpec, RoutePolicy},
    journal::{JobKey, StageReference},
    protocol::device_digest,
    stage::StageFile,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
fn fixture() -> (tempfile::TempDir, PathBuf, Policy) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let db = root.join("relay.db");
    drop(new_private(&db).unwrap());
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("CREATE TABLE sentinel(v TEXT);INSERT INTO sentinel VALUES('keep');")
        .unwrap();
    drop(c);
    let policy = Policy::new(vec![root], false).unwrap();
    (t, db, policy)
}
fn spec(root: &Path, n: u8, total: u64) -> JobSpec {
    JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::from_bytes([n; 16]),
        file_id: Uuid::from_bytes([n + 1; 16]),
        source_path: root.join(format!("source{n}")).to_str().unwrap().into(),
        destination_path: root.join(format!("target{n}")).to_str().unwrap().into(),
        bytes_total: total,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: format!("inventory-{n}"),
    }
}
fn attach(db: &mut FencedConnection, root: &Path, n: u8, path: PathBuf, total: u64) -> JobKey {
    let job = spec(root, n, total);
    let key = JobKey::from_job(&job);
    let mut j = db.journal().unwrap();
    let (_, s) = j.admit(job, 200).unwrap();
    j.attach_stage(
        &key,
        s.revision(),
        StageReference::observed_local(path, total).unwrap(),
    )
    .unwrap();
    key
}
fn stage(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    let mut f = new_private(&path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
    path
}
fn scan(
    db: &mut FencedConnection,
    p: &Policy,
    root: &Path,
    limits: InventoryLimits,
) -> RecoveryInventory {
    db.inventory(p, &[root.into()], Arc::default(), limits)
        .unwrap()
}
fn has(r: &RecoveryInventory, k: FindingKind) -> bool {
    r.findings().iter().any(|f| f.kind == k)
}
#[test]
fn empty_scan_excludes_own_controls_but_never_opens_receive() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    db.journal().unwrap();
    let r = scan(
        &mut db,
        &p,
        path.parent().unwrap(),
        InventoryLimits::default(),
    );
    assert!(r.complete());
    assert!(r.findings().is_empty());
    let b = r.quarantined_budget().unwrap();
    assert_eq!(b.usage().unwrap(), (0, 0));
    assert!(b.is_quarantined().unwrap());
    assert!(b.reconcile_removed().is_err());
    assert!(
        StageFile::prepare(
            p,
            path.with_file_name("new-target").to_str().unwrap(),
            0,
            b,
            Arc::default()
        )
        .is_err()
    );
}
#[test]
fn partial_and_zero_stage_restore_full_logical_debt_without_mutation_or_cleanup() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let a = stage(root, ".ferroc-fleet-partial", b"a");
    let z = stage(root, ".ferroc-fleet-zero", b"");
    let key = attach(&mut db, root, 5, a.clone(), 3);
    attach(&mut db, root, 7, z.clone(), 0);
    let before = db.journal().unwrap().get(&key).unwrap().unwrap();
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert!(r.complete());
    assert_eq!(r.recorded_usage(), (3, 2));
    assert_eq!(r.stages().len(), 2);
    assert!(has(&r, FindingKind::LegacyIdentityUnproven));
    assert_eq!(r.quarantined_budget().unwrap().usage().unwrap(), (3, 2));
    assert!(r.quarantined_budget().unwrap().reconcile_removed().is_err());
    let after = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert_eq!(before.revision(), after.revision());
    assert_eq!(before.owner(), after.owner());
    assert_eq!(before.phase(), after.phase());
    drop(r);
    assert_eq!(fs::read(a).unwrap(), b"a");
    assert_eq!(fs::read(z).unwrap(), b"");
}
#[test]
fn missing_reference_retains_recorded_debt_and_returns_no_partial_budget() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    attach(&mut db, root, 5, root.join(".ferroc-fleet-missing"), 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert_eq!(r.recorded_usage(), (3, 1));
    assert!(!r.complete());
    assert!(has(&r, FindingKind::MissingStage));
    assert!(r.quarantined_budget().is_none());
}
#[test]
fn oversized_known_file_is_not_charged_as_small_received_counter() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = stage(root, ".ferroc-fleet-grown", b"abcd");
    attach(&mut db, root, 5, s.clone(), 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert!(has(&r, FindingKind::OversizedStage));
    assert!(r.quarantined_budget().is_none());
    assert_eq!(r.recorded_usage(), (3, 1));
    assert_eq!(fs::read(s).unwrap(), b"abcd");
}
#[test]
fn duplicate_ownership_is_not_deduplicated_into_a_smaller_quota() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = stage(root, ".ferroc-fleet-shared", b"abc");
    attach(&mut db, root, 5, s.clone(), 3);
    attach(&mut db, root, 7, s, 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert_eq!(r.recorded_usage(), (6, 2));
    assert!(has(&r, FindingKind::DuplicatePath));
    assert!(r.quarantined_budget().is_none());
}
#[test]
fn hardlinked_reference_is_unsafe_and_neither_link_is_deleted() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = stage(root, ".ferroc-fleet-link", b"abc");
    let alias = root.join(".ferroc-fleet-alias");
    fs::hard_link(&s, &alias).unwrap();
    attach(&mut db, root, 5, s.clone(), 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert!(has(&r, FindingKind::UnsafeStage));
    assert!(r.quarantined_budget().is_none());
    assert_eq!(fs::read(s).unwrap(), b"abc");
    assert_eq!(fs::read(alias).unwrap(), b"abc");
}
#[test]
fn control_reference_is_refused_not_misidentified_as_zero_byte_stage() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let marker = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".ferroc-fleet-owner-")
        })
        .unwrap();
    let mut db = f.open_connection().unwrap();
    attach(&mut db, root, 5, marker.clone(), 0);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert!(has(&r, FindingKind::ControlReference));
    assert_eq!(r.recorded_usage(), (0, 1));
    assert!(r.quarantined_budget().is_none());
    assert!(marker.exists());
}
#[test]
fn unknown_data_and_foreign_control_both_block_without_touching_bytes() {
    for name in [".ferroc-fleet-orphan", ".ferroc-fleet-owner-foreign.lock"] {
        let (_t, path, p) = fixture();
        let root = path.parent().unwrap();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        db.journal().unwrap();
        let file = stage(root, name, b"keep");
        let r = scan(&mut db, &p, root, InventoryLimits::default());
        assert!(!r.complete());
        assert!(r.quarantined_budget().is_none());
        assert!(has(
            &r,
            if name.contains("owner-") {
                FindingKind::ForeignControl
            } else {
                FindingKind::UnknownStage
            }
        ));
        assert_eq!(fs::read(file).unwrap(), b"keep");
    }
}
#[test]
fn referenced_directory_and_outside_policy_path_cannot_become_owned_files() {
    for outside in [false, true] {
        let (t, path, p) = fixture();
        let root = path.parent().unwrap();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let s = if outside {
            stage(t.path(), ".ferroc-fleet-outside", b"keep")
        } else {
            let s = root.join(".ferroc-fleet-directory");
            make_directory(&s).unwrap();
            s
        };
        attach(&mut db, root, 5, s.clone(), 3);
        let r = scan(&mut db, &p, root, InventoryLimits::default());
        assert!(!r.complete());
        assert!(has(&r, FindingKind::UnsafeStage));
        assert!(r.quarantined_budget().is_none());
        assert!(s.exists());
    }
}
#[test]
fn entry_and_findings_caps_do_not_return_a_partial_admission_budget() {
    for findings_cap in [false, true] {
        let (_t, path, p) = fixture();
        let root = path.parent().unwrap();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        db.journal().unwrap();
        for n in [5, 7] {
            let s = stage(root, &format!(".ferroc-fleet-{n}"), b"abc");
            attach(&mut db, root, n, s, 3);
        }
        let limits = if findings_cap {
            InventoryLimits {
                max_findings: 1,
                ..Default::default()
            }
        } else {
            InventoryLimits {
                max_entries: 1,
                ..Default::default()
            }
        };
        let r = scan(&mut db, &p, root, limits);
        assert!(!r.complete());
        assert!(r.quarantined_budget().is_none());
        assert_eq!(r.recorded_usage(), (6, 2));
        if findings_cap {
            assert!(r.findings_truncated());
        } else {
            assert!(has(&r, FindingKind::ScanLimit));
            assert_eq!(r.entries_seen(), 1);
        }
    }
}
#[test]
fn slot_and_byte_overbudget_do_not_partially_seed() {
    for slots in [false, true] {
        let (_t, path, p) = fixture();
        let root = path.parent().unwrap();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let a = stage(root, ".ferroc-fleet-a", if slots { b"" } else { b"abc" });
        attach(&mut db, root, 5, a, if slots { 0 } else { 3 });
        if slots {
            let b = stage(root, ".ferroc-fleet-b", b"");
            attach(&mut db, root, 7, b, 0);
        }
        let limits = if slots {
            InventoryLimits {
                max_active: 1,
                ..Default::default()
            }
        } else {
            InventoryLimits {
                byte_limit: 2,
                ..Default::default()
            }
        };
        let r = scan(&mut db, &p, root, limits);
        assert!(has(&r, FindingKind::QuotaExceeded));
        assert!(r.quarantined_budget().is_none());
        assert_eq!(r.recorded_usage(), if slots { (0, 2) } else { (3, 1) });
    }
}
#[test]
fn invalid_limits_and_uninitialized_schema_do_not_create_tables() {
    let (_t, path, p) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let before = fs::read(&path).unwrap();
    assert!(
        db.inventory(
            &p,
            &[path.parent().unwrap().into()],
            Arc::default(),
            InventoryLimits::default()
        )
        .is_err()
    );
    assert!(
        db.inventory(
            &p,
            &[],
            Arc::default(),
            InventoryLimits {
                max_entries: 0,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    let c = rusqlite::Connection::open(&path).unwrap();
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'ferroc_fleet_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}
#[test]
fn concurrent_reports_are_closed_snapshots_not_two_receive_permissions() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = stage(root, ".ferroc-fleet-one", b"abc");
    attach(&mut db, root, 5, s, 3);
    let gate = Arc::new(Mutex::new(()));
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..2 {
            let gate = gate.clone();
            let f = &f;
            let p = &p;
            handles.push(scope.spawn(move || {
                let mut db = f.open_connection().unwrap();
                db.inventory(p, &[root.into()], gate, InventoryLimits::default())
                    .unwrap()
            }));
        }
        for h in handles {
            let r = h.join().unwrap();
            assert!(r.complete());
            assert_eq!(r.quarantined_budget().unwrap().usage().unwrap(), (3, 1));
            assert!(r.quarantined_budget().unwrap().is_quarantined().unwrap());
        }
    });
}
struct Process {
    child: Child,
    log: std::fs::File,
}
impl Process {
    fn wait(&mut self) -> std::process::ExitStatus {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            if Instant::now() >= end {
                self.child.kill().unwrap();
                self.child.wait().unwrap();
                panic!("inventory child timed out; killed/reaped");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn logs(&mut self) -> String {
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
fn child(path: &Path, mode: &str) -> (Process, Uuid) {
    let ready = path.with_file_name("inventory-ready");
    let log = tempfile::tempfile().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fleet::inventory::tests::inventory_process_child",
            "--ignored",
            "--nocapture",
        ])
        .env("FERROC_INVENTORY_DB", path)
        .env("FERROC_INVENTORY_MODE", mode)
        .env("FERROC_INVENTORY_READY", &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let mut child = Process { child, log };
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(s) = fs::read_to_string(&ready)
            && let Ok(owner) = Uuid::parse_str(&s)
        {
            return (child, owner);
        }
        if child.child.try_wait().unwrap().is_some() {
            panic!("child failed: {}", child.logs());
        }
        assert!(
            Instant::now() < end,
            "child readiness timeout; Drop reaps owned child"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
#[ignore = "bounded crash helper invoked only by parent"]
fn inventory_process_child() {
    let path = std::env::var_os("FERROC_INVENTORY_DB").unwrap();
    let path = Path::new(&path);
    let mode = std::env::var("FERROC_INVENTORY_MODE").unwrap();
    assert!(["before_attach", "attached"].contains(&mode.as_str()));
    let f = OwnerFence::acquire(path).unwrap();
    let mut db = f.open_connection().unwrap();
    let job = spec(path.parent().unwrap(), 5, 3);
    let key = JobKey::from_job(&job);
    let (_, row) = db.journal().unwrap().admit(job.clone(), 200).unwrap();
    let b = StageBudget::new(3, 1).unwrap();
    let p = Policy::new(vec![path.parent().unwrap().into()], false).unwrap();
    let mut file = StageFile::prepare(p, &job.destination_path, 3, &b, Arc::default()).unwrap();
    file.write_chunk(0, b"abc").unwrap();
    if mode == "attached" {
        db.journal()
            .unwrap()
            .attach_stage(
                &key,
                row.revision(),
                StageReference::observed_local(file.stage_path().into(), 3).unwrap(),
            )
            .unwrap();
    }
    let _file = file.verify_with(job.sha256, || Ok(())).unwrap();
    fs::write(
        std::env::var_os("FERROC_INVENTORY_READY").unwrap(),
        f.owner().to_string(),
    )
    .unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
    std::process::exit(23);
}
#[test]
fn create_before_attach_crash_is_orphan_not_zero_debt_admission() {
    let (_t, path, p) = fixture();
    let (mut child, _) = child(&path, "before_attach");
    child.child.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert_eq!(child.wait().code(), Some(23), "{}", child.logs());
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let r = scan(
        &mut db,
        &p,
        path.parent().unwrap(),
        InventoryLimits::default(),
    );
    assert_eq!(r.recorded_usage(), (0, 0));
    assert!(has(&r, FindingKind::UnknownStage));
    assert!(r.quarantined_budget().is_none());
    let o = r
        .findings()
        .iter()
        .find(|x| x.kind == FindingKind::UnknownStage)
        .unwrap();
    assert_eq!(fs::read(&o.path).unwrap(), b"abc");
}
#[test]
fn attached_crash_restores_closed_debt_without_reassigning_or_resuming() {
    let (_t, path, p) = fixture();
    let (mut child, old) = child(&path, "attached");
    child.child.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert_eq!(child.wait().code(), Some(23), "{}", child.logs());
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let key = JobKey::from_job(&spec(path.parent().unwrap(), 5, 3));
    let before = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert_eq!(before.owner(), old);
    let r = scan(
        &mut db,
        &p,
        path.parent().unwrap(),
        InventoryLimits::default(),
    );
    assert!(r.complete());
    assert_eq!(r.quarantined_budget().unwrap().usage().unwrap(), (3, 1));
    assert!(has(&r, FindingKind::LegacyIdentityUnproven));
    let after = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert_eq!(after.owner(), old);
    assert_eq!(before.revision(), after.revision());
    assert_eq!(before.phase(), after.phase());
    assert_eq!(fs::read(&r.stages()[0].path).unwrap(), b"abc");
}
#[cfg(windows)]
#[test]
fn native_stage_acl_fault_blocks_inventory_and_restores_original_descriptor() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = stage(root, ".ferroc-fleet-acl", b"abc");
    attach(&mut db, root, 5, s.clone(), 3);
    let file = open_private(&s, false).unwrap();
    crate::fleet::identity_windows::test_world_read_then_restore(&s, &file, || {
        let r = scan(&mut db, &p, root, InventoryLimits::default());
        assert!(has(&r, FindingKind::UnsafeStage));
        assert!(r.quarantined_budget().is_none());
    })
    .unwrap();
    assert!(scan(&mut db, &p, root, InventoryLimits::default()).complete());
    assert_eq!(fs::read(s).unwrap(), b"abc");
}
#[cfg(windows)]
#[test]
fn actual_junction_reference_is_not_followed_or_deleted() {
    use base64::Engine;
    use std::os::windows::fs::MetadataExt;
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let target = root.join("real-directory");
    make_directory(&target).unwrap();
    let sentinel = stage(&target, "keep", b"keep");
    let link = root.join(".ferroc-fleet-junction");
    let script = "$ErrorActionPreference='Stop';New-Item -ItemType Junction -Path $env:FERROC_INVENTORY_LINK -Target $env:FERROC_INVENTORY_TARGET -ErrorAction Stop | Out-Null";
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let exe = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let log = tempfile::tempfile().unwrap();
    let mut child = Process {
        child: Command::new(exe)
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .env("FERROC_INVENTORY_LINK", &link)
            .env("FERROC_INVENTORY_TARGET", &target)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log.try_clone().unwrap()))
            .spawn()
            .unwrap(),
        log,
    };
    assert!(child.wait().success(), "{}", child.logs());
    assert_ne!(
        fs::symlink_metadata(&link).unwrap().file_attributes() & 0x400,
        0
    );
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    attach(&mut db, root, 5, link.clone(), 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert!(has(&r, FindingKind::UnsafeStage));
    assert!(r.quarantined_budget().is_none());
    assert_eq!(fs::read(sentinel).unwrap(), b"keep");
    assert_ne!(
        fs::symlink_metadata(&link).unwrap().file_attributes() & 0x400,
        0
    );
    fs::remove_dir(link).unwrap();
}

#[test]
fn report_becomes_stale_without_releasing_debt_or_creating_new_stages() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = stage(root, ".ferroc-fleet-prior", b"abc");
    attach(&mut db, root, 5, s.clone(), 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    let b = r.quarantined_budget().unwrap().clone();
    assert_eq!(b.usage().unwrap(), (3, 1));
    fs::remove_file(s).unwrap();
    assert!(b.reconcile_removed().is_err());
    assert_eq!(b.usage().unwrap(), (3, 1));
    drop(r);
    let dest = root.join("must-not-create");
    let before = fs::read_dir(root).unwrap().count();
    let error = StageFile::prepare(p, dest.to_str().unwrap(), 0, &b, Arc::default())
        .err()
        .unwrap();
    assert!(error.to_string().contains("quarantined"));
    assert_eq!(fs::read_dir(root).unwrap().count(), before);
    assert!(!dest.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
}

#[test]
fn corrupt_unbounded_sql_columns_are_rejected_before_rust_row_allocation() {
    for column in ["k", "fleet", "idem", "parameters", "digest", "body"] {
        let (_t, path, p) = fixture();
        let root = path.parent().unwrap();
        let f = OwnerFence::acquire(&path).unwrap();
        let mut db = f.open_connection().unwrap();
        let s = stage(root, ".ferroc-fleet-unchanged", b"abc");
        attach(&mut db, root, 5, s.clone(), 3);
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        let value = if column == "parameters" || column == "digest" {
            "zeroblob(1048576)"
        } else {
            "replace(hex(zeroblob(524288)),'0','x')"
        };
        c.execute_batch(&format!(
            "UPDATE ferroc_fleet_jobs_v1 SET {column}={value};"
        ))
        .unwrap();
        let error = db
            .inventory(
                &p,
                &[root.into()],
                Arc::default(),
                InventoryLimits::default(),
            )
            .expect_err("corrupt column refused");
        assert!(format!("{error:?}").contains("Null"), "{error:?}");
        assert_eq!(fs::read(s).unwrap(), b"abc");
    }
}
#[test]
fn poisoned_actual_fs_gate_returns_error_without_touching_stage_or_revision() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let s = stage(root, ".ferroc-fleet-preserved", b"abc");
    let key = attach(&mut db, root, 5, s.clone(), 3);
    let before = db.journal().unwrap().get(&key).unwrap().unwrap();
    let gate = Arc::new(Mutex::new(()));
    let _ = std::panic::catch_unwind(|| {
        let _g = gate.lock().unwrap();
        panic!("injected inventory gate poison");
    });
    assert!(
        db.inventory(&p, &[root.into()], gate, InventoryLimits::default())
            .is_err()
    );
    assert_eq!(
        db.journal().unwrap().get(&key).unwrap().unwrap().revision(),
        before.revision()
    );
    assert_eq!(fs::read(s).unwrap(), b"abc");
}

#[cfg(windows)]
#[test]
fn distinct_unicode_directories_must_not_hide_a_real_orphan_in_an_unscanned_scope() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let a = root.join("\u{0130}");
    let b = root.join("i\u{0307}");
    make_directory(&a).unwrap();
    make_directory(&b).unwrap();
    assert_ne!(fs::canonicalize(&a).unwrap(), fs::canonicalize(&b).unwrap());
    assert_eq!(
        a.to_string_lossy().to_lowercase(),
        b.to_string_lossy().to_lowercase()
    );
    let orphan = stage(&a, ".ferroc-fleet-hidden-before-fix", b"keep");
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    db.journal().unwrap();
    let r = db
        .inventory(&p, &[a, b], Arc::default(), InventoryLimits::default())
        .unwrap();
    assert!(
        has(&r, FindingKind::UnknownStage),
        "distinct scope must not be overwritten: {r:?}"
    );
    assert!(!r.complete());
    assert!(r.quarantined_budget().is_none());
    assert_eq!(fs::read(orphan).unwrap(), b"keep");
}
#[cfg(windows)]
#[test]
fn distinct_unicode_stage_objects_are_not_a_false_duplicate_ownership_fault() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let a = stage(root, ".ferroc-fleet-\u{0130}", b"abc");
    let b = stage(root, ".ferroc-fleet-i\u{0307}", b"abc");
    assert_ne!(
        file_id(&open_private(&a, false).unwrap()).unwrap(),
        file_id(&open_private(&b, false).unwrap()).unwrap()
    );
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    attach(&mut db, root, 5, a, 3);
    attach(&mut db, root, 7, b, 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert!(
        r.complete(),
        "two real distinct objects are not duplicates: {r:?}"
    );
    assert_eq!(r.recorded_usage(), (6, 2));
    assert_eq!(r.quarantined_budget().unwrap().usage().unwrap(), (6, 2));
}
#[cfg(windows)]
#[test]
fn actual_case_alias_is_canonicalized_not_reported_as_an_unknown_data_stage() {
    let (_t, path, p) = fixture();
    let root = path.parent().unwrap();
    let actual = stage(root, ".ferroc-fleet-MixedCase", b"abc");
    let alias = root.join(".ferroc-fleet-mIXEDcASE");
    assert_eq!(
        file_id(&open_private(&actual, false).unwrap()).unwrap(),
        file_id(&open_private(&alias, false).unwrap()).unwrap()
    );
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    attach(&mut db, root, 5, alias, 3);
    let r = scan(&mut db, &p, root, InventoryLimits::default());
    assert!(r.complete(), "actual OS aliases must converge: {r:?}");
    assert_eq!(r.quarantined_budget().unwrap().usage().unwrap(), (3, 1));
}

#[test]
fn seed_rejects_unrepresentable_or_excessive_obligations() {
    assert!(
        StageBudget::reconstruct_quarantined(MAX_FILE_BYTES, 4, &[(PathBuf::new(), u64::MAX)])
            .is_err()
    );
    assert!(
        StageBudget::reconstruct_quarantined(0, 1, &[(PathBuf::new(), 0), (PathBuf::new(), 0)])
            .is_err()
    );
}
