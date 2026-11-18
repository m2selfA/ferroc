use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::{EndpointSlot, PeerApproval, Protection},
        job::JOB_VERSION,
        setup_config::SetupProvision,
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn wrap() -> Protection {
    let hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut key = Zeroizing::new([0u8; 32]);
    for (i, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap(), 16).unwrap();
    }
    Protection::supplied_key(key).unwrap()
}

fn fixture() -> (tempfile::TempDir, Arc<SetupProvision>, Arc<Runtime>, Uuid) {
    let root = tempfile::tempdir().unwrap();
    let fleet = Uuid::new_v4();
    let a = crate::fleet::identity::IdentityStore::create(
        &root.path().join("a"),
        wrap(),
        fleet,
        "dev-a",
    )
    .unwrap();
    let b = crate::fleet::identity::IdentityStore::create(
        &root.path().join("b"),
        wrap(),
        fleet,
        "dev-b",
    )
    .unwrap();
    let fb = {
        let ka = a.create_identity().unwrap();
        let kb = b.create_identity().unwrap();
        let fa = a.local_fingerprint().unwrap();
        let fb = b.local_fingerprint().unwrap();
        a.enroll_peer(
            PeerApproval::verify(fleet, "dev-b", kb.public(), &fb).unwrap(),
            "peer-b",
            1,
        )
        .unwrap();
        b.enroll_peer(
            PeerApproval::verify(fleet, "dev-a", ka.public(), &fa).unwrap(),
            "peer-a",
            1,
        )
        .unwrap();
        fb
    };
    a.set_peer_endpoint("dev-b", EndpointSlot::Primary, "https://relay.example", &fb)
        .unwrap();
    std::fs::write(root.path().join("s.bin"), b"abc").unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let round = Uuid::new_v4();
    let job = json!({"version":JOB_VERSION,"fleetId":fleet,"sourceDevice":crate::fleet::protocol::device_digest("dev-a").unwrap(),"targetDevice":crate::fleet::protocol::device_digest("dev-b").unwrap(),"transferId":Uuid::new_v4(),"fileId":Uuid::new_v4(),"sourcePath":root.path().join("s.bin").to_str().unwrap(),"destinationPath":root.path().join("d.bin").to_str().unwrap(),"bytesTotal":3,"sha256":Sha256::digest(b"abc").to_vec(),"overwrite":false,"route":"relayOnly","deadlineMs":now+900000,"idempotencyKey":"mcp-test"});
    let value = json!({"version":2,"identityStore":root.path().join("a"),"fleet":fleet,"device":"dev-a","protection":{"kind":"suppliedKeyEnv","name":"FERROC_TEST_WRAP"},"peer":{"device":"dev-b","fingerprint":fb.hex(),"slot":"primary","profile":"singleOwner"},"rounds":[{"id":round,"role":"source","job":job,"sourceSession":Uuid::new_v4(),"targetSession":Uuid::new_v4(),"chunkBytes":65536,"leaseMs":120000,"issuedAtMs":now-5000,"authorizationId":Uuid::new_v4(),"keyEpoch":Uuid::new_v4()}],"dataRoutes":true,"leaseAuthority":{"kind":"singleOwnerSystemClock","uncertaintyMs":100},"transfer":{"windowChunks":4,"hostDb":root.path().join("host.db").to_str().unwrap(),"mcp":true}});
    let path = root.path().join("setup.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    unsafe {
        std::env::set_var(
            "FERROC_TEST_WRAP",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    };
    let provision = Arc::new(SetupProvision::load(&path, "dev-a").unwrap());
    let runtime = Arc::new(Runtime::new(
        Policy::new(vec![root.path().to_path_buf()], false).unwrap(),
    ));
    (root, provision, runtime, round)
}

#[test]
fn tool_definitions_are_exactly_the_four_local_tasks() {
    let names: Vec<_> = tool_definitions().into_iter().map(|t| t.name).collect();
    assert_eq!(
        names,
        vec!["send_file", "sync_dir", "transfer_get", "transfer_cancel"]
    );
}

#[tokio::test]
async fn local_mcp_surface_is_attached_only_after_explicit_registration() {
    let (_root, provision, runtime, round) = fixture();
    let base = runtime.tools_for().unwrap();
    assert!(!base.iter().any(|t| t.name == "send_file"));
    runtime.open_fleet_mcp(provision, 4).unwrap();
    let attached = runtime.tools_for().unwrap();
    assert_eq!(attached.len(), base.len() + 4);
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    let task = mcp.send_file(round, Duration::from_secs(30)).unwrap();
    let snap = mcp.get(task).unwrap();
    assert!(matches!(
        snap.phase,
        super::super::transfer_tasks::TaskPhase::Queued
            | super::super::transfer_tasks::TaskPhase::Running
    ));
    assert!(mcp.cancel(task).unwrap());
    let _ = mcp.get(task).unwrap();
}

#[tokio::test]
async fn local_stdio_mcp_lists_and_dispatches_the_four_tools() {
    let (_root, provision, runtime, round) = fixture();
    runtime.open_fleet_mcp(provision, 4).unwrap();
    let mut mcp = crate::stdio::Mcp::default();
    let init = mcp
        .handle(
            &runtime,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}),
        )
        .await
        .unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "ferroc");
    let list = mcp
        .handle(
            &runtime,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .await
        .unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names.len(), crate::runtime::tools().len() + 4);
    for name in ["send_file", "sync_dir", "transfer_get", "transfer_cancel"] {
        assert!(names.contains(&name), "missing local tool {name}");
    }
    let sent = mcp
        .handle(
            &runtime,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"send_file","arguments":{"roundId":round}}}),
        )
        .await
        .unwrap();
    let text = sent["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("taskId"), "send_file returns a local task id");
    let cancelled = mcp
        .handle(
            &runtime,
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"transfer_cancel","arguments":{"roundId":round}}}),
        )
        .await
        .unwrap();
    let cancelled: serde_json::Value =
        serde_json::from_str(cancelled["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(cancelled["cancelled"], true);
    let task = runtime
        .fleet_mcp()
        .unwrap()
        .unwrap()
        .get(Uuid::nil())
        .is_err();
    assert!(task, "unknown task id is rejected");
    let unknown = mcp
        .handle(
            &runtime,
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"transfer_get","arguments":{"taskId":"00000000-0000-0000-0000-000000000000"}}}),
        )
        .await
        .unwrap();
    assert_eq!(unknown["result"]["isError"], true);
}

#[tokio::test]
async fn unknown_round_and_out_of_range_batch_are_rejected() {
    let (_root, provision, runtime, round) = fixture();
    runtime.open_fleet_mcp(provision, 4).unwrap();
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    assert!(
        mcp.send_file(Uuid::new_v4(), Duration::from_secs(5))
            .is_err()
    );
    assert!(
        mcp.sync_dir(&[round; 9], Duration::from_secs(5)).is_err(),
        "sync_dir is bounded to eight preapproved rounds"
    );
}

#[tokio::test]
async fn cancel_by_round_withdraws_undelivered_waiter_and_batch_cancel_counts_once() {
    let (_root, provision, runtime, round) = fixture();
    runtime.open_fleet_mcp(provision, 4).unwrap();
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    let task = mcp.send_file(round, Duration::from_secs(30)).unwrap();
    // The owner was never delivered, so the round-level cancel must withdraw
    // the waiter: a later delivery has to be refused instead of starting DATA.
    assert!(
        mcp.cancel_round(round).unwrap(),
        "queued round is cancellable"
    );
    assert!(
        !mcp.cancel_round(round).unwrap(),
        "repeat request is not new"
    );
    let snap = tokio::time::timeout(Duration::from_secs(2), mcp.tasks.wait(task))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snap.phase,
        super::super::transfer_tasks::TaskPhase::Interrupted
    );
    assert!(!snap.remote_cleanup_confirmed);
    assert_eq!(mcp.cancel_batch(&[round]).unwrap(), 0);
    assert!(mcp.cancel_round(Uuid::new_v4()).is_err(), "unknown round");
}

async fn batch_fixture(capacity: usize) -> (tempfile::TempDir, Arc<Runtime>, Vec<Uuid>) {
    let (root, _old, runtime, first) = fixture();
    let path = root.path().join("setup.json");
    let mut cfg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut rounds = vec![first];
    for index in 1..3 {
        let mut next = cfg["rounds"][0].clone();
        let id = Uuid::new_v4();
        next["id"] = json!(id);
        next["authorizationId"] = json!(Uuid::new_v4());
        next["keyEpoch"] = json!(Uuid::new_v4());
        next["job"]["fileId"] = json!(Uuid::new_v4());
        next["job"]["idempotencyKey"] = json!(format!("mcp-batch-{index}"));
        next["job"]["destinationPath"] = json!(root.path().join(format!("dst-{index}.bin")));
        cfg["rounds"].as_array_mut().unwrap().push(next);
        rounds.push(id);
    }
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let provision = Arc::new(SetupProvision::load(&path, "dev-a").unwrap());
    runtime.open_fleet_mcp(provision, capacity).unwrap();
    (root, runtime, rounds)
}

#[tokio::test]
async fn batch_invalid_later_round_has_no_partial_registration() {
    let (_root, runtime, rounds) = batch_fixture(4).await;
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    assert!(
        mcp.sync_dir(&[rounds[0], Uuid::new_v4()], Duration::from_secs(5))
            .is_err()
    );
    assert!(
        mcp.active.lock().unwrap().is_empty(),
        "invalid request registered earlier jobs"
    );
    assert!(mcp.waiters.lock().unwrap().is_empty());
}

#[tokio::test]
async fn batch_precancel_never_enqueues_setup() {
    let (_root, runtime, rounds) = batch_fixture(4).await;
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    let mut starts = mcp.take_starts().unwrap();
    let ids = mcp.sync_dir(&rounds, Duration::from_secs(10)).unwrap();
    assert!(mcp.cancel(ids[0]).unwrap());
    for id in ids {
        tokio::time::timeout(Duration::from_secs(2), mcp.tasks.wait(id))
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        starts.try_recv().is_err(),
        "cancelled round still enqueued setup"
    );
    assert!(mcp.waiters.lock().unwrap().is_empty());
}

#[tokio::test]
async fn batch_running_cancel_drains_remaining_waiters_without_starts() {
    let (_root, runtime, rounds) = batch_fixture(4).await;
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    let mut starts = mcp.take_starts().unwrap();
    let ids = mcp.sync_dir(&rounds, Duration::from_secs(10)).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), starts.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.round, rounds[0]);
    assert!(mcp.cancel(ids[0]).unwrap());
    for id in ids {
        let snap = tokio::time::timeout(Duration::from_secs(2), mcp.tasks.wait(id))
            .await
            .unwrap()
            .unwrap();
        assert!(snap.phase.is_terminal());
        assert!(!snap.remote_cleanup_confirmed);
    }
    assert!(starts.try_recv().is_err());
    assert!(mcp.waiters.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancel_invalid_selector_and_batch_have_no_effects() {
    let (_root, runtime, rounds) = batch_fixture(4).await;
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    let task = mcp.send_file(rounds[0], Duration::from_secs(10)).unwrap();
    let bad = runtime
        .call(
            "transfer_cancel",
            json!({"taskId":task,"roundId":rounds[0]}),
        )
        .await;
    assert_eq!(bad.is_error, Some(true), "ambiguous selector accepted");
    assert!(!mcp.get(task).unwrap().phase.is_terminal());
    assert!(mcp.cancel_batch(&[rounds[0], Uuid::new_v4()]).is_err());
    assert_ne!(
        mcp.get(task).unwrap().phase,
        super::super::transfer_tasks::TaskPhase::CancelRequested
    );
    assert!(mcp.cancel_batch(&[]).is_err());
    assert!(mcp.cancel_batch(&[rounds[0]; 9]).is_err());
    assert!(mcp.cancel_batch(&[rounds[0]; 2]).is_err());
    mcp.cancel(task).unwrap();
}

#[tokio::test]
async fn duplicate_batch_rounds_are_rejected() {
    let (_root, provision, runtime, round) = fixture();
    runtime.open_fleet_mcp(provision, 4).unwrap();
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    // A repeated round is rejected as a duplicate batch entry rather than
    // silently starting twice.
    assert!(
        mcp.sync_dir(&[round, round], Duration::from_secs(5))
            .is_err()
    );
}

#[tokio::test]
async fn runtime_shutdown_closes_mcp_task_table_and_stale_service() {
    let (_root, provision, runtime, round) = fixture();
    runtime.open_fleet_mcp(provision, 4).unwrap();
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    let task = mcp.send_file(round, Duration::from_secs(30)).unwrap();
    tokio::time::timeout(Duration::from_secs(2), runtime.shutdown())
        .await
        .unwrap();
    assert_eq!(
        mcp.get(task).unwrap().phase,
        super::super::transfer_tasks::TaskPhase::Interrupted,
        "Runtime returned with MCP worker still live"
    );
    assert!(
        runtime.fleet_tasks().unwrap().is_some(),
        "MCP ids were outside Runtime lifecycle"
    );
    assert!(
        mcp.send_file(Uuid::new_v4(), Duration::from_secs(5))
            .is_err()
    );
    let same = runtime.fleet_tasks().unwrap().unwrap().get(task).unwrap();
    assert_eq!(same.phase, mcp.get(task).unwrap().phase);
}

#[tokio::test]
async fn runtime_mcp_cannot_replace_an_existing_task_attachment() {
    let (_root, provision, runtime, _round) = fixture();
    let old = runtime.open_fleet_tasks(2).unwrap();
    assert!(runtime.open_fleet_mcp(provision, 4).is_err());
    assert!(runtime.fleet_mcp().unwrap().is_none());
    old.stop_admission().unwrap();
    assert!(runtime.open_fleet_tasks(4).is_err());
}

#[tokio::test]
async fn oversized_batch_capacity_is_rejected_before_registration() {
    let (_root, runtime, rounds) = batch_fixture(1).await;
    let mcp = runtime.fleet_mcp().unwrap().unwrap();
    assert!(mcp.sync_dir(&rounds, Duration::from_secs(5)).is_err());
    assert!(mcp.active.lock().unwrap().is_empty());
    assert!(mcp.waiters.lock().unwrap().is_empty());
}
