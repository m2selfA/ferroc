use super::*;
#[path = "relay_backpressure_tests.rs"]
mod backpressure_tests;
#[path = "relay_negative_tests.rs"]
mod negative_tests;
#[cfg(windows)]
#[path = "relay_process_tests.rs"]
mod process_tests;
#[path = "relay_renewal_tests.rs"]
mod renewal_tests;
#[path = "relay_sync_exec_tests.rs"]
mod sync_exec_tests;
#[cfg(windows)]
use crate::{
    config::Policy,
    fleet::{
        identity::{make_directory, new_private},
        inventory::InventoryLimits,
        relay_io::run_source,
        source_window::SourceWindow,
    },
    runtime::Runtime,
};
use crate::{
    fleet::{
        auth::{DevicePin, EphemeralKey, IdentityKey, Transcript},
        job::{FileGrant, JobSpec, Permission},
        lease::{ClockSample, LeasedRecords, TrustedTimeAnchor},
        relay_io::FleetLink,
    },
    network::Network,
};
use std::path::Path;
fn grant(root: &Path, data: &[u8]) -> ValidatedGrant {
    let job = JobSpec {
        version: 1,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::new_v4(),
        file_id: Uuid::new_v4(),
        source_path: root.join("source/input.bin").to_str().unwrap().into(),
        destination_path: root.join("target/output.bin").to_str().unwrap().into(),
        bytes_total: data.len() as u64,
        sha256: Sha256::digest(data).into(),
        overwrite: false,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 60100,
        idempotency_key: Uuid::new_v4().to_string(),
    };
    FileGrant {
        binding: Binding {
            fleet_id: job.fleet_id,
            source_device: job.source_device,
            target_device: job.target_device,
            source_session: Uuid::from_bytes([3; 16]),
            target_session: Uuid::from_bytes([4; 16]),
            transfer_id: job.transfer_id,
            file_id: job.file_id,
            authorization_id: Uuid::from_bytes([7; 16]),
            key_epoch: Uuid::from_bytes([8; 16]),
        },
        job_digest: job.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 65536,
        issued_at_ms: 100,
        expires_at_ms: 50100,
    }
    .validate_for(job)
    .unwrap()
}
fn records(g: &ValidatedGrant, role: Direction) -> LeasedRecords {
    // PUBLIC cfg(test) fixture keys/time. Not operational issuance/registration.
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let s = EphemeralKey::from_test_bytes([0x33; 32]);
    let t = EphemeralKey::from_test_bytes([0x44; 32]);
    let tr = Transcript::for_grant(g, sk.public(), tk.public(), s.public(), t.public());
    let a = sk.sign(&tr, Direction::SourceToTarget).unwrap();
    let b = tk.sign(&tr, Direction::TargetToSource).unwrap();
    let key = if role == Direction::SourceToTarget {
        s
    } else {
        t
    };
    key.authenticate_leased(
        &tr,
        role,
        g,
        &DevicePin::approved("source-A", sk.public()).unwrap(),
        &DevicePin::approved("target-B", tk.public()).unwrap(),
        &a,
        &b,
        TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 200).unwrap(),
    )
    .unwrap()
}
fn devices(r: &Relay) {
    for (id, token) in [
        ("source-A", "TEST-source-token"),
        ("target-B", "TEST-target-token"),
    ] {
        let h = hash(token);
        r.store
            .put(
                "device",
                id,
                &serde_json::json!({"tokenHash":h,"paused":false}),
                120,
            )
            .unwrap();
        r.store
            .put("device_token", &h, &serde_json::json!({"deviceId":id}), 120)
            .unwrap();
    }
}
async fn server(
    root: &Path,
    fleet: Option<Arc<FleetRelay>>,
) -> (String, Arc<Relay>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let relay = Relay::new(
        &root.join("relay.db"),
        &url,
        "PUBLIC TEST admin password only",
    )
    .unwrap();
    devices(&relay);
    let router = if let Some(f) = fleet {
        relay.clone().router_with_fleet(f)
    } else {
        relay.clone().router()
    };
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, relay, task)
}
async fn link(url: &str, secret: &str, g: &ValidatedGrant, role: Direction) -> Result<FleetLink> {
    FleetLink::connect(
        &Network::direct(),
        url,
        if role == Direction::SourceToTarget {
            "TEST-source-token"
        } else {
            "TEST-target-token"
        },
        secret,
        g,
        role,
        Duration::from_secs(30),
    )
    .await
}
#[tokio::test]
async fn default_router_has_no_fleet_route() {
    let root = tempfile::tempdir().unwrap();
    let (url, _r, task) = server(root.path(), None).await;
    assert_eq!(
        reqwest::get(format!("{url}/fleet/ws"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    task.abort();
    let _ = task.await;
}
#[test]
fn explicit_approval_rejects_mismatched_ids_replay_ttl_and_stopped_registry() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = FleetRelay::new();
    assert!(
        f.approve_local(&g, "target-B", "source-A", Duration::from_secs(30))
            .is_err()
    );
    assert!(
        f.approve_local(&g, "source-A", "target-B", Duration::ZERO)
            .is_err()
    );
    assert!(
        f.approve_local(&g, "source-A", "target-B", Duration::from_secs(301))
            .is_err()
    );
    let _tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    assert!(
        f.approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
            .is_err()
    );
    f.close();
    assert!(
        f.approve_local(
            &grant(t.path(), b"x"),
            "source-A",
            "target-B",
            Duration::from_secs(1)
        )
        .is_err()
    );
}
#[tokio::test]
async fn wrong_device_does_not_burn_ticket_and_one_use_prevents_replacement() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(t.path(), Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    assert!(
        link(
            &url,
            tickets.source.expose_secret(),
            &g,
            Direction::TargetToSource
        )
        .await
        .is_err()
    );
    let s = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    assert!(
        link(
            &url,
            tickets.source.expose_secret(),
            &g,
            Direction::SourceToTarget
        )
        .await
        .is_err()
    );
    let p = link(
        &url,
        tickets.target.expose_secret(),
        &g,
        Direction::TargetToSource,
    )
    .await
    .unwrap();
    drop(s);
    drop(p);
    f.close();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn opaque_binary_forwarding_still_requires_peer_aead() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(t.path(), Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let mut s = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    let mut p = link(
        &url,
        tickets.target.expose_secret(),
        &g,
        Direction::TargetToSource,
    )
    .await
    .unwrap();
    let mut sr = records(&g, Direction::SourceToTarget);
    let mut pr = records(&g, Direction::TargetToSource);
    let a = sr.seal_data(0, b"abc").unwrap();
    let mut bad = a.clone();
    *bad.last_mut().unwrap() ^= 1;
    s.send(bad).await.unwrap();
    assert!(pr.open_record(&p.receive().await.unwrap()).is_err());
    s.send(a.clone()).await.unwrap();
    let got = p.receive().await.unwrap();
    assert_eq!(got, a);
    assert!(matches!(
        pr.open_record(&got).unwrap(),
        super::super::auth::PeerRecord::Data { .. }
    ));
    drop(s);
    drop(p);
    f.close();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn paused_or_revoked_device_closes_both_directions() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = Arc::new(FleetRelay::new());
    let (url, r, task) = server(t.path(), Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let mut s = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    let p = link(
        &url,
        tickets.target.expose_secret(),
        &g,
        Direction::TargetToSource,
    )
    .await
    .unwrap();
    r.store.delete("device", "target-B").unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), s.receive())
            .await
            .unwrap()
            .is_err()
    );
    drop(p);
    f.close();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn expiry_closes_unpaired_connection_and_cannot_reapprove_same_grant() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(t.path(), Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_millis(500))
        .unwrap();
    let mut s = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), s.receive())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        f.approve_local(&g, "source-A", "target-B", Duration::from_secs(2))
            .is_err()
    );
    f.close();
    task.abort();
    let _ = task.await;
}
#[cfg(windows)]
async fn actual_file_roundtrip(data: Vec<u8>) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let f = Arc::new(FleetRelay::new());
    let (url, _r, server) = server(&root, Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(50))
        .unwrap();
    // Keep authoritative actor errors/Target history even when Source fails.
    // Earlier fixture unwrapped Source first and lost this diagnostic channel.
    let pair = f
        .table
        .lock()
        .unwrap()
        .pairs
        .values()
        .next()
        .unwrap()
        .clone();
    let mut events = pair.test_events.subscribe();
    let handle = tokio::runtime::Handle::current();
    let target_root = root.clone();
    let target_g = g.clone();
    let target_url = url.clone();
    let target = tokio::task::spawn_blocking(move || {
        let rt = Runtime::new(Policy::new(vec![target_root.join("target")], false).unwrap());
        let host = rt
            .open_fleet_host(
                &target_root.join("target/host.db"),
                InventoryLimits::default(),
            )
            .unwrap();
        host.resume().unwrap();
        let recv = host
            .admit_receiver(records(&target_g, Direction::TargetToSource))
            .unwrap();
        let receipt = handle.block_on(async {
            let link = link(
                &target_url,
                tickets.target.expose_secret(),
                &target_g,
                Direction::TargetToSource,
            )
            .await?;
            super::super::relay_io::run_target(recv, link).await
        });
        let observation = serde_json::json!({"phase":host.get(&crate::fleet::journal::JobKey::from_job(target_g.job())).unwrap().map(|s|format!("{:?}",s.phase())),"recordedUsage":host.inventory().unwrap().recorded_usage(),"inFlight":host.status().unwrap().in_flight});
        host.close().unwrap();
        (receipt, observation)
    });
    let handle = tokio::runtime::Handle::current();
    let src_root = root.clone();
    let src_g = g.clone();
    let start = Instant::now();
    let source = tokio::task::spawn_blocking(move || {
        let rt = Runtime::new(Policy::new(vec![src_root.join("source")], false).unwrap());
        let source = SourceWindow::new(
            rt.open_fleet_source(records(&src_g, Direction::SourceToTarget))
                .unwrap(),
            8,
        )
        .unwrap();
        handle.block_on(async {
            let l = link(
                &url,
                tickets.source.expose_secret(),
                &src_g,
                Direction::SourceToTarget,
            )
            .await?;
            run_source(source, l).await
        })
    });
    let (src, dst) = tokio::join!(source, target);
    f.close();
    let mut actor_errors = Vec::new();
    let mut lagged = 0u64;
    let actor_drain = tokio::time::timeout(Duration::from_secs(3), async {
        while actor_errors.len() < 2 {
            match events.recv().await {
                Ok(RelayTestEvent::Exit {
                    destination, error, ..
                }) => actor_errors.push((destination, error)),
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => lagged += n,
                Err(e) => return Err(anyhow::anyhow!(e)),
            }
        }
        Ok(())
    })
    .await;
    server.abort();
    let _ = server.await;
    println!(
        "RELAY_NATIVE_DIAGNOSTIC bytes={} source_error={:?} target_error={:?} target_observation={:?} actors={:?} lagged={lagged} drain={actor_drain:?}",
        data.len(),
        src.as_ref().err().map(|e| e.to_string()).or_else(|| src
            .as_ref()
            .ok()
            .and_then(|s| s.as_ref().err().map(|e| format!("{e:#}")))),
        dst.as_ref().err().map(|e| e.to_string()).or_else(|| dst
            .as_ref()
            .ok()
            .and_then(|(s, _)| s.as_ref().err().map(|e| format!("{e:#}")))),
        dst.as_ref().ok().map(|(_, o)| o),
        actor_errors
    );
    assert_eq!(f.sockets.available_permits(), MAX_PAIRS * 2);
    let src = src.unwrap().unwrap();
    let (dst, _) = dst.unwrap();
    let dst = dst.unwrap();
    assert_eq!(src.receipt(), &dst);
    assert_eq!(std::fs::read(root.join("target/output.bin")).unwrap(), data);
    assert_eq!(std::fs::read(root.join("source/input.bin")).unwrap(), data);
    println!(
        "RELAY_NATIVE bytes={} elapsed_ms={} actualLoopbackRelay+Source+TargetV9/sameProcess/notTwoHost",
        data.len(),
        start.elapsed().as_millis()
    );
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_actual_relay_zero_one_cross_chunk_and_final_ack() {
    for data in [vec![], vec![2], vec![0x71; 131073]] {
        actual_file_roundtrip(data).await;
    }
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_actual_relay_eight_mib() {
    actual_file_roundtrip(vec![0x39; 8 * 1024 * 1024]).await;
}
