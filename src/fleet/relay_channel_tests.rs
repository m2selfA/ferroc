use super::*;
#[path = "relay_backpressure_tests.rs"]
mod backpressure_tests;
#[path = "relay_negative_tests.rs"]
mod negative_tests;
#[path = "relay_process_tests.rs"]
mod process_tests;
#[cfg(windows)]
#[path = "renew_handshake_tests.rs"]
mod renew_handshake_tests;
#[cfg(windows)]
#[path = "renew_pump_tests.rs"]
mod renew_pump_tests;
#[path = "renewal_tests.rs"]
mod renewal_issue_tests;
#[path = "relay_renewal_tests.rs"]
mod renewal_tests;
#[path = "runtime_task_tests.rs"]
mod runtime_task_tests;
#[cfg(windows)]
#[path = "relay_sync_exec_tests.rs"]
mod sync_exec_tests;
#[path = "transfer_task_tests.rs"]
mod transfer_task_tests;
#[cfg(windows)]
use crate::fleet::inventory::InventoryLimits;
use crate::{
    config::Policy,
    fleet::{
        identity::{make_directory, new_private},
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
    grant_for_paths(
        root.join("source/input.bin").to_str().unwrap(),
        root.join("target/output.bin").to_str().unwrap(),
        data,
    )
}
/// Fixture-only local policy. It is never obtained from the peer's JSON.
fn fixture_profile() -> crate::fleet::job::LeaseProfile {
    use crate::fleet::job::LeaseProfile;
    match std::env::var("FERROC_FLEET_TEST_PROFILE").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("rotating") => LeaseProfile::Rotating,
        Ok("single-owner") => LeaseProfile::SingleOwner,
        _ => panic!("invalid explicit TEST lease profile"),
    }
}
/// Explicit fixture budget so a scale run can outlive the default 60 s window.
/// Still a test-only knob: it does not change any product deadline.
fn fixture_window() -> (u64, u64, std::time::Duration, u64) {
    let deadline_ms: u64 = std::env::var("FERROC_FLEET_TEST_DEADLINE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_100);
    let ttl_secs: u64 = std::env::var("FERROC_FLEET_TEST_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    // Do not silently clamp: rotating workers must reject an overlong lease;
    // a long SingleOwner lease requires explicit local opt-in on every worker.
    let lease_ms: u64 = std::env::var("FERROC_FLEET_TEST_LEASE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);
    (
        deadline_ms,
        ttl_secs,
        std::time::Duration::from_secs(ttl_secs),
        lease_ms,
    )
}
/// Same explicit test-seed grant, but with paths that can point at two hosts.
fn grant_for_paths(source: &str, destination: &str, data: &[u8]) -> ValidatedGrant {
    grant_for_metadata(
        source,
        destination,
        data.len() as u64,
        Sha256::digest(data).into(),
    )
}
/// Metadata-based fixture setup avoids allocating an entire scale payload.
fn grant_for_metadata(
    source: &str,
    destination: &str,
    bytes_total: u64,
    sha256: [u8; 32],
) -> ValidatedGrant {
    let job = JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: Uuid::new_v4(),
        file_id: Uuid::new_v4(),
        source_path: source.into(),
        destination_path: destination.into(),
        bytes_total,
        sha256,
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: fixture_window().0,
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
        chunk_bytes: std::env::var("FERROC_FLEET_TEST_CHUNK_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(65_536),
        issued_at_ms: 100,
        expires_at_ms: 100 + fixture_window().3,
    }
    .validate_for_profile(job, fixture_profile())
    .unwrap()
}
fn records(g: &ValidatedGrant, role: Direction) -> LeasedRecords {
    // PUBLIC cfg(test) fixture keys/time. Not operational issuance/registration.
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let s = EphemeralKey::from_test_bytes([0x33; 32]);
    let t = EphemeralKey::from_test_bytes([0x44; 32]);
    let tr = Transcript::for_grant(g, sk.public(), tk.public(), s.public(), t.public());
    let a = sk
        .sign_with_profile(&tr, Direction::SourceToTarget, g.lease_profile())
        .unwrap();
    let b = tk
        .sign_with_profile(&tr, Direction::TargetToSource, g.lease_profile())
        .unwrap();
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
                i64::try_from(fixture_window().1.saturating_add(30).max(120)).unwrap(),
            )
            .unwrap();
        r.store
            .put(
                "device_token",
                &h,
                &serde_json::json!({"deviceId":id}),
                i64::try_from(fixture_window().1.saturating_add(30).max(120)).unwrap(),
            )
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
        // Fixture link lifetime. The 30 s default kept early tests honest about
        // short sessions; a scale run needs a longer window, and the product
        // lease ceiling still applies on top of it.
        Duration::from_secs(
            std::env::var("FERROC_FLEET_TEST_LINK_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
        ),
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
        .approve_local(&g, "source-A", "target-B", fixture_window().2)
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

/// Successor with rotated authorization + key epoch, same job, later window.
fn successor(g: &ValidatedGrant, generation: u128) -> ValidatedGrant {
    let old = g.grant();
    let mut binding = old.binding.clone();
    binding.authorization_id = Uuid::from_u128(7000 + generation);
    binding.key_epoch = Uuid::from_u128(8000 + generation);
    FileGrant {
        binding,
        job_digest: old.job_digest,
        permission: old.permission,
        chunk_bytes: old.chunk_bytes,
        issued_at_ms: old.issued_at_ms + generation as u64,
        expires_at_ms: old.expires_at_ms + generation as u64,
    }
    .validate_for(g.job().clone())
    .unwrap()
}
fn offer_of(current: &ValidatedGrant, next: &ValidatedGrant) -> RenewOffer {
    RenewOffer {
        current_authorization_id: current.grant().binding.authorization_id,
        current_key_epoch: current.grant().binding.key_epoch,
        next_authorization_id: next.grant().binding.authorization_id,
        next_key_epoch: next.grant().binding.key_epoch,
    }
}
/// The relay advances routing only after BOTH roles present the successor on
/// their own authenticated sockets. One side alone cannot rotate the route.
#[test]
fn renewal_advances_only_after_both_roles_present() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = FleetRelay::new();
    let _tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(60))
        .unwrap();
    let next = successor(&g, 1);
    // Not offered yet: presenting is refused, so a peer cannot invent a route.
    assert!(f.present("source-A", &offer_of(&g, &next)).is_err());
    f.offer_renewal(&g, &next).unwrap();
    // One role is not enough.
    assert_eq!(
        f.present("source-A", &offer_of(&g, &next)).unwrap(),
        (false, 0)
    );
    // The same role presenting twice still does not advance.
    assert_eq!(
        f.present("source-A", &offer_of(&g, &next)).unwrap(),
        (false, 0)
    );
    // Both roles presented: the successor is ARMED, not yet adopted. The route
    // still points at the old binding because the commit has not been delivered.
    assert_eq!(
        f.present("target-B", &offer_of(&g, &next)).unwrap(),
        (true, 1)
    );
    assert!(f.present("target-B", &offer_of(&g, &next)).is_err());
    assert!(f.offer_renewal(&g, &successor(&g, 2)).is_err());
    assert!(
        f.offer_renewal(&next, &successor(&next, 3)).is_ok(),
        "the adopted binding must be the routable one"
    );
}
/// A stranger device, a stale current binding or a non-rotating successor is
/// refused before any route change.
#[test]
fn renewal_rejects_stranger_stale_and_non_rotating_offers() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = FleetRelay::new();
    let _tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(60))
        .unwrap();
    let next = successor(&g, 1);
    // A successor that keeps the old authorization cannot be adopted at all.
    let stale = FileGrant {
        binding: g.grant().binding.clone(),
        job_digest: g.grant().job_digest,
        permission: g.grant().permission,
        chunk_bytes: g.grant().chunk_bytes,
        issued_at_ms: g.grant().issued_at_ms + 1,
        expires_at_ms: g.grant().expires_at_ms + 1,
    }
    .validate_for(g.job().clone())
    .unwrap();
    assert!(f.offer_renewal(&g, &stale).is_err(), "no rotation refused");
    f.offer_renewal(&g, &next).unwrap();
    assert!(
        f.present("stranger", &offer_of(&g, &next)).is_err(),
        "unknown device refused"
    );
    assert!(
        f.present("target-B", &offer_of(&next, &next)).is_err(),
        "stale current binding refused"
    );
    assert_eq!(
        f.present("source-A", &offer_of(&g, &next)).unwrap(),
        (false, 0)
    );
}
/// The endpoint is not reachable on the default router, and it authenticates
/// the device token before it looks at the body.
#[tokio::test]
async fn renewal_endpoint_is_absent_by_default_and_requires_a_device_token() {
    let root = tempfile::tempdir().unwrap();
    let (url, _r, task) = server(root.path(), None).await;
    assert_eq!(
        reqwest::Client::new()
            .post(format!("{url}/fleet/renew"))
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    task.abort();
    let _ = task.await;
    let (url, _r, task) = server(root.path(), Some(Arc::new(FleetRelay::new()))).await;
    let response = reqwest::Client::new()
        .post(format!("{url}/fleet/renew"))
        .header("authorization", "Bearer not-a-device-token")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    task.abort();
    let _ = task.await;
}

/// The real HTTP endpoint: both roles present, the relay reports advancement,
/// and the route is then routable under the successor binding only.
#[tokio::test]
async fn renewal_endpoint_advances_after_both_authenticated_roles_present() {
    let root = tempfile::tempdir().unwrap();
    let g = grant(root.path(), b"abc");
    let fleet = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(root.path(), Some(fleet.clone())).await;
    let _tickets = fleet
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(120))
        .unwrap();
    let next = successor(&g, 1);
    fleet.offer_renewal(&g, &next).unwrap();
    let post = |token: &'static str| {
        let url = url.clone();
        let offer = offer_of(&g, &next);
        async move {
            reqwest::Client::new()
                .post(format!("{url}/fleet/renew"))
                .header("authorization", format!("Bearer {token}"))
                .json(&serde_json::json!({
                    "currentAuthorizationId": offer.current_authorization_id,
                    "currentKeyEpoch": offer.current_key_epoch,
                    "nextAuthorizationId": offer.next_authorization_id,
                    "nextKeyEpoch": offer.next_key_epoch,
                }))
                .send()
                .await
                .unwrap()
        }
    };
    let first = post("TEST-source-token").await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first.json::<serde_json::Value>().await.unwrap()["advanced"],
        serde_json::json!(false)
    );
    let second = post("TEST-target-token").await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        second.json::<serde_json::Value>().await.unwrap()["advanced"],
        serde_json::json!(true)
    );
    // Old binding is no longer routable, the successor is.
    assert!(fleet.offer_renewal(&g, &successor(&g, 2)).is_err());
    assert!(fleet.offer_renewal(&next, &successor(&next, 3)).is_ok());
    // A paused device cannot present a renewal even with a valid token.
    _r.store
        .put(
            "device",
            "target-B",
            &serde_json::json!({"tokenHash":hash("TEST-target-token"),"paused":true}),
            120,
        )
        .unwrap();
    let offered = successor(&next, 4);
    fleet.offer_renewal(&next, &offered).unwrap();
    let blocked = reqwest::Client::new()
        .post(format!("{url}/fleet/renew"))
        .header("authorization", "Bearer TEST-target-token")
        .json(&serde_json::json!({
            "currentAuthorizationId": next.grant().binding.authorization_id,
            "currentKeyEpoch": next.grant().binding.key_epoch,
            "nextAuthorizationId": offered.grant().binding.authorization_id,
            "nextKeyEpoch": offered.grant().binding.key_epoch,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
    task.abort();
    let _ = task.await;
}
/// Single-owner operation does not expose remote grant/job upload for renewal.
#[tokio::test]
async fn remote_renewal_offer_is_not_exposed() {
    let root = tempfile::tempdir().unwrap();
    let (url, _relay, task) = server(root.path(), Some(Arc::new(FleetRelay::new()))).await;
    let result = reqwest::Client::new()
        .post(format!("{url}/fleet/renew/offer"))
        .header("authorization", "Bearer TEST-source-token")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::NOT_FOUND);
    task.abort();
    let _ = task.await;
}
