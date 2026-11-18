use super::*;
use crate::fleet::{
    job::{JobSpec, RoutePolicy},
    protocol::device_digest,
    state::Phase,
};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
fn expect_busy(path: &Path) {
    let error = OwnerFence::acquire(path)
        .err()
        .expect("independent process must hold native lock");
    assert!(
        matches!(
            error.downcast_ref::<std::fs::TryLockError>(),
            Some(std::fs::TryLockError::WouldBlock)
        ),
        "{error:?}"
    );
}
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("private");
    super::super::identity::make_directory(&dir).unwrap();
    let path = dir.join("relay.db");
    drop(new_private(&path).unwrap());
    let c = Connection::open(&path).unwrap();
    c.execute_batch(
        "CREATE TABLE kv(k TEXT PRIMARY KEY,v TEXT);INSERT INTO kv VALUES('sentinel','keep');",
    )
    .unwrap();
    drop(c);
    (tmp, path)
}
fn spec(path: &Path) -> JobSpec {
    let root = path.parent().unwrap();
    JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::from_bytes([5; 16]),
        file_id: Uuid::from_bytes([6; 16]),
        source_path: root.join("source.bin").to_str().unwrap().into(),
        destination_path: root.join("target.bin").to_str().unwrap().into(),
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: "native-fence".into(),
    }
}
#[test]
fn independent_handle_contention_is_wouldblock_and_does_not_modify_database() {
    let (_t, path) = fixture();
    let before = fs::read(&path).unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let error = OwnerFence::acquire(&path)
        .err()
        .expect("second owner rejected");
    assert!(
        matches!(
            error.downcast_ref::<std::fs::TryLockError>(),
            Some(std::fs::TryLockError::WouldBlock)
        ),
        "{error:?}"
    );
    assert_eq!(fs::read(path).unwrap(), before);
    assert!(!f.owner().is_nil());
}
#[test]
fn dropping_owner_releases_lock_but_never_unlinks_or_replaces_marker() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let marker = f.domain.marker.clone();
    let id = file_id(&f.domain.lock).unwrap();
    let owner = f.owner();
    drop(f);
    assert!(marker.exists());
    assert_eq!(fs::metadata(&marker).unwrap().len(), 0);
    let next = OwnerFence::acquire(&path).unwrap();
    assert_eq!(file_id(&next.domain.lock).unwrap(), id);
    assert_eq!(next.domain.marker, marker);
    assert_ne!(next.owner(), owner);
}
#[test]
fn canonical_spelling_cannot_create_another_lock_domain() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let alias = path
        .parent()
        .unwrap()
        .join(".")
        .join(path.file_name().unwrap());
    assert!(OwnerFence::acquire(&alias).is_err());
    #[cfg(windows)]
    {
        let alias = PathBuf::from(path.to_str().unwrap().to_uppercase());
        assert!(OwnerFence::acquire(&alias).is_err());
    }
    assert_eq!(
        fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with(".ferroc-fleet-owner-"))
            .count(),
        1
    );
    drop(f);
}
#[test]
fn hardlinked_database_or_marker_fails_closed() {
    let (_t, path) = fixture();
    let alias = path.with_file_name("alias.db");
    fs::hard_link(&path, &alias).unwrap();
    assert!(OwnerFence::acquire(&path).is_err());
    assert!(OwnerFence::acquire(&alias).is_err());
    fs::remove_file(alias).unwrap();
    let f = OwnerFence::acquire(&path).unwrap();
    let marker = f.domain.marker.clone();
    drop(f);
    let other = path.with_file_name("alias.lock");
    fs::hard_link(&marker, &other).unwrap();
    assert!(OwnerFence::acquire(&path).is_err());
    fs::remove_file(other).unwrap();
    OwnerFence::acquire(&path).unwrap();
}
#[test]
fn marker_content_is_never_truncated_into_an_accepted_lock() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let marker = f.domain.marker.clone();
    drop(f);
    fs::write(&marker, b"preserve").unwrap();
    assert!(OwnerFence::acquire(&path).is_err());
    assert_eq!(fs::read(marker).unwrap(), b"preserve");
}
#[test]
fn missing_relative_directory_and_traversal_inputs_are_rejected_without_creation() {
    let (t, path) = fixture();
    let missing = path.with_file_name("missing.db");
    assert!(OwnerFence::acquire(&missing).is_err());
    assert!(!missing.exists());
    assert!(OwnerFence::acquire(Path::new("relative.db")).is_err());
    assert!(OwnerFence::acquire(path.parent().unwrap()).is_err());
    assert!(OwnerFence::acquire(&t.path().join("private/../private/relay.db")).is_err());
}
#[test]
fn all_connections_retain_native_lock_after_factory_drop_until_sqlite_closes() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let owner = f.owner();
    let mut a = f.open_connection().unwrap();
    let b = f.open_connection().unwrap();
    drop(f);
    assert!(OwnerFence::acquire(&path).is_err());
    a.journal().unwrap().admit(spec(&path), 200).unwrap();
    drop(a);
    assert!(OwnerFence::acquire(&path).is_err());
    drop(b);
    let next = OwnerFence::acquire(&path).unwrap();
    assert_ne!(owner, next.owner());
}
#[cfg(windows)]
#[test]
fn widened_db_marker_and_directory_acl_are_denied_and_exact_descriptor_restored() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    for (path, file) in [
        (path.as_path(), &f.domain.database),
        (f.domain.marker.as_path(), &f.domain.lock),
        (path.parent().unwrap(), &f.domain.directory),
    ] {
        super::super::identity_windows::test_world_read_then_restore(path, file, || {
            assert!(OwnerFence::acquire(&f.domain.path).is_err());
            assert!(db.journal().is_err());
        })
        .unwrap();
        f.domain.check_paths().unwrap();
        assert!(db.journal().is_ok());
    }
}
#[cfg(windows)]
#[test]
fn native_parent_junction_alias_converges_to_same_db_lock_domain() {
    use base64::Engine;
    use std::os::windows::fs::MetadataExt;
    let (t, path) = fixture();
    let link = t.path().join("junction");
    let log = tempfile::tempfile().unwrap();
    let script = "$ErrorActionPreference='Stop';New-Item -ItemType Junction -Path $env:FERROC_FENCE_JUNCTION -Target $env:FERROC_FENCE_TARGET -ErrorAction Stop | Out-Null";
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let exe = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut process = Process {
        child: Command::new(exe)
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .env("FERROC_FENCE_JUNCTION", &link)
            .env("FERROC_FENCE_TARGET", path.parent().unwrap())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log.try_clone().unwrap()))
            .spawn()
            .unwrap(),
        log,
    };
    assert!(process.wait().success(), "{}", process.logs());
    assert_ne!(
        fs::symlink_metadata(&link).unwrap().file_attributes() & 0x400,
        0
    );
    let f = OwnerFence::acquire(&path).unwrap();
    let marker = f.domain.marker.clone();
    assert!(OwnerFence::acquire(&link.join("relay.db")).is_err());
    drop(f);
    let alias = OwnerFence::acquire(&link.join("relay.db")).unwrap();
    assert_eq!(alias.domain.marker, marker);
    assert_eq!(alias.domain.path, fs::canonicalize(&path).unwrap());
    drop(alias);
    fs::remove_dir(link).unwrap();
}
#[test]
fn crash_after_durable_intent_recovers_unknown_and_preserves_real_stage() {
    let (_t, path) = fixture();
    let (mut child, old) = child(&path, "intent");
    expect_busy(&path);
    child.child.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert_eq!(child.wait().code(), Some(23), "{}", child.logs());
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let mut j = db.journal().unwrap();
    let rows = j.recover_stopped_owner(old).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.phase(), Phase::CommitUnknown);
    assert_eq!(row.owner(), f.owner());
    assert!(row.intent().is_some());
    assert!(row.receipt().is_none());
    let stage = row.stage().unwrap();
    assert_eq!(fs::read(stage.path()).unwrap(), b"abc");
    let key = crate::fleet::journal::JobKey::from_job(row.job());
    assert!(j.attach_stage(&key, row.revision(), stage.clone()).is_err());
    assert_eq!(fs::read(stage.path()).unwrap(), b"abc");
}

#[test]
fn same_database_factory_preserves_other_tables_and_rejects_domain_mismatch() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let value: String = db
        .connection
        .query_row("SELECT v FROM kv WHERE k='sentinel'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(value, "keep");
    let job = spec(&path);
    let key = crate::fleet::journal::JobKey::from_job(&job);
    {
        let mut j = db.journal().unwrap();
        let (_, s) = j.admit(job, 200).unwrap();
        assert_eq!(s.owner(), f.owner());
        assert_eq!(j.get(&key).unwrap().unwrap().owner(), f.owner());
    }
    let mut memory = Connection::open_in_memory().unwrap();
    assert!(Journal::attach_fenced(&mut memory, &f.domain).is_err());
    let (_u, other) = fixture();
    let mut wrong = Connection::open(other).unwrap();
    assert!(Journal::attach_fenced(&mut wrong, &f.domain).is_err());
}
#[test]
fn failed_fence_validation_prevents_sqlite_open_and_journal_schema_writes() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let before = fs::read(&path).unwrap();
    f.domain.lock.set_len(1).unwrap();
    assert!(f.open_connection().is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    f.domain.lock.set_len(0).unwrap();
    let mut db = f.open_connection().unwrap();
    f.domain.lock.set_len(1).unwrap();
    assert!(db.journal().is_err());
    let count: i64 = db
        .connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'ferroc_fleet_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    f.domain.lock.set_len(0).unwrap();
    db.journal().unwrap();
}
#[cfg(windows)]
#[test]
fn live_native_handles_pin_database_and_marker_against_rename() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    for path in [&path, &f.domain.marker] {
        assert!(path.is_file());
        let moved = path.with_extension("moved");
        assert!(!moved.exists());
        let error = fs::rename(path, &moved).unwrap_err();
        assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
        assert!(!moved.exists());
        assert!(path.is_file());
        f.domain.check_paths().unwrap();
    }
}

#[test]
fn per_operation_fence_validation_rejects_marker_mutation() {
    let (_t, path) = fixture();
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let mut j = db.journal().unwrap();
    let job = spec(&path);
    let key = crate::fleet::journal::JobKey::from_job(&job);
    let (_, s) = j.admit(job, 200).unwrap();
    // Inject via the OWN locking handle, not a foreign handle that Windows
    // can legitimately refuse before the mutation. No vacuous if-is_ok pass.
    f.domain.lock.set_len(1).unwrap();
    assert_eq!(f.domain.lock.metadata().unwrap().len(), 1);
    assert!(j.get(&key).is_err());
    assert!(j.cancel(&key, s.revision()).is_err());
    f.domain.lock.set_len(0).unwrap();
    let unchanged = j.get(&key).unwrap().unwrap();
    assert_eq!(unchanged.revision(), s.revision());
    assert_eq!(unchanged.phase(), Phase::Queued);
}
struct Process {
    child: Child,
    log: File,
}
impl Process {
    fn wait(&mut self) -> std::process::ExitStatus {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= until {
                self.child.kill().unwrap();
                self.child.wait().unwrap();
                panic!("owned fence child timed out and was reaped");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn logs(&mut self) -> String {
        self.log.seek(SeekFrom::Start(0)).unwrap();
        let mut out = String::new();
        Read::by_ref(&mut self.log)
            .take(65537)
            .read_to_string(&mut out)
            .unwrap();
        assert!(out.len() <= 65536);
        out
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
    let ready = path.with_file_name("child-ready.txt");
    let log = tempfile::tempfile().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fleet::fence::tests::fence_process_child",
            "--ignored",
            "--nocapture",
        ])
        .env("FERROC_FENCE_DB", path)
        .env("FERROC_FENCE_MODE", mode)
        .env("FERROC_FENCE_READY", &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let mut child = Process { child, log };
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(value) = fs::read_to_string(&ready)
            && let Ok(owner) = Uuid::parse_str(&value)
        {
            return (child, owner);
        }
        if child.child.try_wait().unwrap().is_some() {
            panic!("child exited before ready: {}", child.logs());
        }
        assert!(
            Instant::now() < until,
            "fence child readiness timeout; Drop reaps child"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
#[ignore = "bounded owner-fence subprocess helper invoked only by parent"]
fn fence_process_child() {
    let path = std::env::var_os("FERROC_FENCE_DB").expect("parent-owned DB");
    let path = Path::new(&path);
    let mode = std::env::var("FERROC_FENCE_MODE").unwrap();
    assert!(["normal", "exit", "kill", "intent"].contains(&mode.as_str()));
    let f = OwnerFence::acquire(path).unwrap();
    let mut db = f.open_connection().unwrap();
    let mut journal = db.journal().unwrap();
    let job = spec(path);
    let (_, row) = journal.admit(job.clone(), 200).unwrap();
    // Keep the actual StageFile live until process::exit: no Rust Drop is run.
    let _live_stage = if mode == "intent" {
        use crate::{
            config::Policy,
            fleet::{
                journal::{JobKey, StageReference},
                stage::{StageBudget, StageFile},
            },
        };
        let budget = StageBudget::new(3, 1).unwrap();
        let mut stage = StageFile::prepare(
            Policy::new(vec![path.parent().unwrap().into()], false).unwrap(),
            &job.destination_path,
            3,
            &budget,
            std::sync::Arc::default(),
        )
        .unwrap();
        let key = JobKey::from_job(&job);
        let row = journal
            .attach_stage(
                &key,
                row.revision(),
                StageReference::observed_local(stage.stage_path().into(), 3).unwrap(),
            )
            .unwrap();
        stage.write_chunk(0, b"abc").unwrap();
        let stage = stage.verify_with(job.sha256, || Ok(())).unwrap();
        let row = journal.progress(&key, row.revision(), 3).unwrap();
        let row = journal
            .readback(&key, row.revision(), stage.sha256())
            .unwrap();
        journal.begin_commit(&key, row.revision()).unwrap();
        Some(stage)
    } else {
        None
    };
    fs::write(
        std::env::var_os("FERROC_FENCE_READY").unwrap(),
        f.owner().to_string(),
    )
    .unwrap();
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    if mode == "exit" || mode == "intent" {
        std::process::exit(23);
    }
}
#[test]
fn independent_process_excludes_competitor_then_releases_on_graceful_exit() {
    let (_t, path) = fixture();
    let (mut child, owner) = child(&path, "normal");
    let before = fs::read(&path).unwrap();
    expect_busy(&path);
    assert_eq!(fs::read(&path).unwrap(), before);
    child.child.stdin.take().unwrap().write_all(&[1]).unwrap();
    let status = child.wait();
    assert!(status.success(), "{}", child.logs());
    let f = OwnerFence::acquire(&path).unwrap();
    assert_ne!(f.owner(), owner);
    let mut db = f.open_connection().unwrap();
    let recovered = db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].owner(), f.owner());
    assert_eq!(recovered[0].phase(), Phase::Queued);
}
#[test]
fn unclean_exit_without_rust_drop_releases_native_fence_and_recovers_old_owner() {
    let (_t, path) = fixture();
    let (mut child, owner) = child(&path, "exit");
    expect_busy(&path);
    child.child.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert_eq!(child.wait().code(), Some(23), "{}", child.logs());
    let f = OwnerFence::acquire(&path).unwrap();
    let mut db = f.open_connection().unwrap();
    let rows = db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].owner(), f.owner());
}
#[test]
fn forced_child_termination_releases_lock_not_a_timeout_or_pid_guess() {
    let (_t, path) = fixture();
    let (mut child, owner) = child(&path, "kill");
    expect_busy(&path);
    child.child.kill().unwrap();
    assert!(!child.wait().success());
    let f = OwnerFence::acquire(&path).unwrap();
    assert_ne!(f.owner(), owner);
    let mut db = f.open_connection().unwrap();
    assert_eq!(
        db.journal()
            .unwrap()
            .recover_stopped_owner(owner)
            .unwrap()
            .len(),
        1
    );
}
#[cfg(unix)]
#[test]
fn widened_file_mode_is_denied_without_automatic_repair() {
    use std::os::unix::fs::PermissionsExt;
    let (_t, path) = fixture();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(OwnerFence::acquire(&path).is_err());
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o644
    );
}
