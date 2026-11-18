use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::{make_directory, new_private},
        job::{JobSpec, RoutePolicy},
        protocol::device_digest,
    },
    runtime::Runtime,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Runtime) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let db = root.join("relay.db");
    drop(new_private(&db).unwrap());
    let runtime = Runtime::new(Policy::new(vec![root.clone()], false).unwrap());
    (t, root, db, runtime)
}

fn job(path: &Path, bytes: u64) -> JobSpec {
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
        idempotency_key: "inventory-cli".into(),
    }
}

#[test]
fn clean_database_reports_no_obligation_and_no_authority() {
    let (_t, root, db, runtime) = fixture();
    let value = run(
        &runtime,
        InventoryArgs {
            db: db.clone(),
            root: vec![root.clone()],
        },
    )
    .unwrap();
    assert_eq!(value["authority"], serde_json::json!(false));
    assert_eq!(value["complete"], serde_json::json!(true));
    assert_eq!(value["recordedBytes"], serde_json::json!(0));
    assert_eq!(value["obligations"], serde_json::json!([]));
}

#[test]
fn read_only_view_works_with_transfers_disabled() {
    let (_t, root, db, _runtime) = fixture();
    // Read-only recovery must not depend on transfers being enabled: a paused or
    // disabled policy still has to let an operator SEE the obligation.
    let mut policy = Policy::new(vec![root.clone()], false).unwrap();
    policy.allow_transfers = false;
    let runtime = Runtime::new(policy);
    let value = run(
        &runtime,
        InventoryArgs {
            db,
            root: vec![root],
        },
    )
    .unwrap();
    assert_eq!(value["authority"], serde_json::json!(false));
    assert_eq!(value["complete"], serde_json::json!(true));
}

#[test]
fn staged_obligation_is_reported_with_its_bytes_and_phase() {
    let (_t, root, db, runtime) = fixture();
    {
        let host = runtime
            .open_fleet_host(&db, crate::fleet::inventory::InventoryLimits::default())
            .unwrap();
        host.resume().unwrap();
        host.admit(job(&root, 4096), 1000).unwrap();
        host.close().unwrap();
    }
    let value = run(
        &runtime,
        InventoryArgs {
            db: db.clone(),
            root: vec![root.clone()],
        },
    )
    .unwrap();
    let rows = value["obligations"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{value}");
    assert_eq!(rows[0]["hasReceipt"], serde_json::json!(false));
    assert_eq!(rows[0]["reservedBytes"], serde_json::json!(4096));
    // Closing a host that still owns an unbound reservation leaves it interrupted:
    // the row reports that durable state, not an optimistic "still queued".
    assert_eq!(rows[0]["phase"], serde_json::json!("Interrupted"));
    assert_eq!(value["authority"], serde_json::json!(false));
    assert_eq!(
        rows[0]["reconciliation"]["eligibleForAbsenceRelease"],
        serde_json::json!(false)
    );
}

#[test]
fn relative_paths_are_refused_before_any_database_access() {
    let (_t, root, db, runtime) = fixture();
    let error = run(
        &runtime,
        InventoryArgs {
            db: PathBuf::from("relay.db"),
            root: vec![root.clone()],
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("absolute"), "{error:#}");
    let error = run(
        &runtime,
        InventoryArgs {
            db,
            root: vec![PathBuf::from("private")],
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("absolute"), "{error:#}");
}
