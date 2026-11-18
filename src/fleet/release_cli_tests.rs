use super::*;
use crate::config::Policy;
use crate::fleet::{
    fence::OwnerFence,
    identity::{make_directory, new_private},
    inventory::InventoryLimits,
    job::{JobSpec, RoutePolicy},
    journal::Snapshot,
    protocol::device_digest,
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Runtime) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let db = root.join("relay.db");
    drop(new_private(&db).unwrap());
    let runtime = Runtime::new(Policy::new(vec![root.clone()], false).unwrap());
    (t, root, db, runtime)
}

fn spec(path: &Path, bytes: u64) -> JobSpec {
    JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: uuid::Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: uuid::Uuid::from_bytes([5; 16]),
        file_id: uuid::Uuid::from_bytes([6; 16]),
        source_path: path.join("source.bin").to_str().unwrap().into(),
        destination_path: path.join("target.bin").to_str().unwrap().into(),
        bytes_total: bytes,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 60_100,
        idempotency_key: "release-cli".into(),
    }
}

/// A NAMED stage belonging to an owner that is now stopped, so the object can be
/// checked by path (an anonymous stage could never be).
fn stopped_named(db: &Path, policy: &Policy) -> (JobKey, uuid::Uuid, PathBuf) {
    let fence = OwnerFence::acquire(db).unwrap();
    let stopped = fence.owner();
    let mut connection = fence.open_connection().unwrap();
    let job = spec(db.parent().unwrap(), 4096);
    let key = JobKey::from_job(&job);
    let (_, snapshot) = connection.journal().unwrap().admit(job, 200).unwrap();
    let staged: Snapshot = connection
        .reserve_stage(
            &key,
            snapshot.revision(),
            policy,
            Arc::default(),
            InventoryLimits::default(),
        )
        .unwrap();
    let path = staged.stage().unwrap().path().to_path_buf();
    drop(connection);
    drop(fence);
    (key, stopped, path)
}

#[test]
fn absent_named_stage_is_released_after_owner_takeover() {
    let (_t, root, db, runtime) = fixture();
    let policy = Policy::new(vec![root.clone()], false).unwrap();
    let (_key, stopped, stage_path) = stopped_named(&db, &policy);
    // The reservation committed but its object was never created (the two-step
    // contract allows exactly that after a crash), so the path is ABSENT.
    assert!(!stage_path.exists());
    let (digest, _) = report_digest(&runtime, &db);
    // Takeover AND release happen in ONE process: the eligibility proof binds the
    // owning fence instance, so a fingerprint from an earlier run can never match.
    let released = run(
        &runtime,
        ReleaseArgs {
            db: db.clone(),
            root: vec![root.clone()],
            recover_owner: Some(stopped),
            release: true,
            digest: Some(digest),
            fingerprint: None,
        },
    )
    .unwrap();
    assert_eq!(released["authority"], serde_json::json!(false));
    assert_eq!(
        released["released"]["stagePresent"],
        serde_json::json!(false)
    );
    assert_eq!(released["recordedBytes"], serde_json::json!(0));
    assert_eq!(released["recordedSlots"], serde_json::json!(0));
    assert_eq!(released["complete"], serde_json::json!(true));
}

fn report_digest(runtime: &Runtime, db: &Path) -> (String, String) {
    let host = runtime
        .open_fleet_host(db, InventoryLimits::default())
        .unwrap();
    let row = host.obligations().unwrap().pop().unwrap();
    let digest = hex(&row.job().digest().unwrap());
    let report = host
        .inspect_allocation(&JobKey::from_job(row.job()))
        .unwrap();
    (digest, hex(&report.fingerprint()))
}

#[test]
fn wrong_fingerprint_is_refused_before_any_release() {
    let (_t, root, db, runtime) = fixture();
    let policy = Policy::new(vec![root.clone()], false).unwrap();
    let (_key, stopped, _stage_path) = stopped_named(&db, &policy);
    let (digest, _) = report_digest(&runtime, &db);
    let error = run(
        &runtime,
        ReleaseArgs {
            db: db.clone(),
            root: vec![root.clone()],
            recover_owner: Some(stopped),
            release: true,
            digest: Some(digest),
            fingerprint: Some("00".repeat(32)),
        },
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("does not match this process"),
        "{error:#}"
    );
    // Nothing was released: the obligation is still recorded.
    let host = runtime
        .open_fleet_host(&db, InventoryLimits::default())
        .unwrap();
    assert_eq!(host.inventory().unwrap().recorded_usage(), (4096, 1));
}

#[test]
fn present_object_is_never_released() {
    let (_t, root, db, runtime) = fixture();
    let policy = Policy::new(vec![root.clone()], false).unwrap();
    let (_key, stopped, stage_path) = stopped_named(&db, &policy);
    // A real object sits at the recorded path: it must never be retired as absent.
    std::fs::write(&stage_path, b"still-here").unwrap();
    run(
        &runtime,
        ReleaseArgs {
            db: db.clone(),
            root: vec![root.clone()],
            recover_owner: Some(stopped),
            release: false,
            digest: None,
            fingerprint: None,
        },
    )
    .unwrap();
    let (digest, fingerprint) = report_digest(&runtime, &db);
    let error = run(
        &runtime,
        ReleaseArgs {
            db: db.clone(),
            root: vec![root.clone()],
            recover_owner: None,
            release: true,
            digest: Some(digest),
            fingerprint: Some(fingerprint),
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("not eligible"), "{error:#}");
    let host = runtime
        .open_fleet_host(&db, InventoryLimits::default())
        .unwrap();
    assert_eq!(host.inventory().unwrap().recorded_usage(), (4096, 1));
}
