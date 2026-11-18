use super::*;
#[tokio::test]
async fn signed_setup_crosses_real_ws_then_local_leased_aead_roundtrip() {
    use crate::{
        config::Policy,
        fleet::{
            auth::PeerRecord,
            identity::{EndpointSlot, IdentityStore, PeerApproval, Protection},
            issuance::{ProposalOptions, propose},
            job::{JOB_VERSION, JobSpec, LeaseProfile, RoutePolicy},
            lease::{ClockSample, TrustedTimeAnchor},
            protocol::device_digest,
            setup::{SetupConfirmation, SetupOffer, SetupPeer, SetupResponse},
        },
        runtime::Runtime,
    };
    use rand_core::{OsRng, RngCore};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;
    let (root, url, relay, _broker, server) = start_server(true).await;
    let fleet = Uuid::new_v4();
    let wrap = || {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        Protection::supplied_key(key).unwrap()
    };
    let a = IdentityStore::create(&root.path().join("id-a"), wrap(), fleet, A).unwrap();
    let b = IdentityStore::create(&root.path().join("id-b"), wrap(), fleet, B).unwrap();
    let (af, bf) = {
        let ka = a.create_identity().unwrap();
        let kb = b.create_identity().unwrap();
        let af = a.local_fingerprint().unwrap();
        let bf = b.local_fingerprint().unwrap();
        a.enroll_peer(
            PeerApproval::verify(fleet, B, kb.public(), &bf).unwrap(),
            "peer-b",
            1,
        )
        .unwrap();
        b.enroll_peer(
            PeerApproval::verify(fleet, A, ka.public(), &af).unwrap(),
            "peer-a",
            1,
        )
        .unwrap();
        (af, bf)
    };
    a.set_peer_endpoint(B, EndpointSlot::Primary, &url, &bf)
        .unwrap();
    b.set_peer_endpoint(A, EndpointSlot::Primary, &url, &af)
        .unwrap();
    std::fs::create_dir(root.path().join("work-a")).unwrap();
    std::fs::create_dir(root.path().join("work-b")).unwrap();
    let source = root.path().join("work-a/input.bin");
    std::fs::write(&source, b"abc").unwrap();
    let target = root.path().join("work-b/output.bin");
    let ra = Runtime::new(Policy::new(vec![root.path().join("work-a")], false).unwrap());
    let rb = Runtime::new(Policy::new(vec![root.path().join("work-b")], false).unwrap());
    let job = JobSpec {
        version: JOB_VERSION,
        fleet_id: fleet,
        source_device: device_digest(A).unwrap(),
        target_device: device_digest(B).unwrap(),
        transfer_id: Uuid::new_v4(),
        file_id: Uuid::new_v4(),
        source_path: source.to_str().unwrap().into(),
        destination_path: target.to_str().unwrap().into(),
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 60_100,
        idempotency_key: "real-ws-signed-setup".into(),
    };
    // PUBLIC synthetic authority decision, not an operational trusted clock.
    let proposal = propose(
        job,
        ProposalOptions {
            source_session: Uuid::new_v4(),
            target_session: Uuid::new_v4(),
            profile: LeaseProfile::SingleOwner,
            issued_at_ms: 100,
            lease_ms: 60_000,
            chunk_bytes: 65536,
        },
    )
    .unwrap();
    let peer_a = SetupPeer {
        device: B,
        expected_fingerprint: &bf,
        endpoint_slot: EndpointSlot::Primary,
        profile: LeaseProfile::SingleOwner,
    };
    let peer_b = SetupPeer {
        device: A,
        expected_fingerprint: &af,
        endpoint_slot: EndpointSlot::Primary,
        profile: LeaseProfile::SingleOwner,
    };
    let mut ws_a = native(&url, A).await;
    let mut ws_b = native(&url, B).await;
    let (pending_a, offer) = ra.begin_fleet_setup(&a, &proposal, peer_a, 200).unwrap();
    let id = Uuid::new_v4();
    send(&mut ws_a,json!({"stage":"offer","id":id,"peerDevice":B,"payload":String::from_utf8(offer.encode().unwrap()).unwrap()})).await;
    let v = receive(&mut ws_b).await.unwrap();
    assert_eq!(v["fromDevice"], A);
    assert_eq!(v["id"], id.to_string());
    let (pending_b, response) = rb
        .accept_fleet_setup(
            &b,
            &proposal,
            peer_b,
            SetupOffer::decode(v["payload"].as_str().unwrap().as_bytes()).unwrap(),
            200,
        )
        .unwrap();
    send(&mut ws_b,json!({"stage":"response","id":id,"payload":String::from_utf8(response.encode().unwrap()).unwrap()})).await;
    let v = receive(&mut ws_a).await.unwrap();
    assert_eq!(v["fromDevice"], B);
    let (ready_a, confirmation) = pending_a
        .confirm(
            SetupResponse::decode(v["payload"].as_str().unwrap().as_bytes()).unwrap(),
            200,
        )
        .unwrap();
    send(&mut ws_a,json!({"stage":"confirmation","id":id,"payload":String::from_utf8(confirmation.encode().unwrap()).unwrap()})).await;
    let v = receive(&mut ws_b).await.unwrap();
    assert_eq!(v["fromDevice"], A);
    let ready_b = pending_b
        .finish(
            SetupConfirmation::decode(v["payload"].as_str().unwrap().as_bytes()).unwrap(),
            200,
        )
        .unwrap();
    let anchor = || TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 201).unwrap();
    let mut records_a = ready_a.authenticate(anchor()).unwrap();
    let mut records_b = ready_b.authenticate(anchor()).unwrap();
    // LOCAL record readback only: DATA is NOT sent over the control socket.
    let data = records_a.seal_data(0, b"abc").unwrap();
    match records_b.open_record(&data).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("expected local DATA readback"),
    }
    assert!(!target.exists());
    assert_eq!(
        std::fs::read_dir(root.path().join("work-b"))
            .unwrap()
            .count(),
        0
    );
    drop(ws_a);
    drop(ws_b);
    offline(&relay).await;
    server.abort();
    let _ = server.await;
    drop(relay);
    drop(root);
}

use crate::{
    fleet::{
        relay_channel::FleetRelay,
        setup_broker::tests::{public_confirmation, public_offer, public_response},
    },
    network::Network,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::{
    sync::mpsc,
    time::{Duration, timeout},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};
type Client = WebSocketStream<reqwest::Upgraded>;
async fn data_control_socket(url: &str, id: &str) -> Client {
    let mut ws = Network::direct()
        .websocket(
            crate::transport::websocket_url(url).unwrap(),
            &token(id),
            WebSocketConfig::default(),
        )
        .await
        .unwrap()
        .unwrap();
    ws.send(Message::Text(json!({"type":"hello","protocol":1,"device":{"deviceId":id},"tools":[],"fleetSetupProtocol":1,"fleetDataProtocol":1}).to_string().into())).await.unwrap();
    ws
}
async fn route_server() -> (
    tempfile::TempDir,
    String,
    Arc<Relay>,
    crate::fleet::job::ValidatedGrant,
    Uuid,
    tokio::task::JoinHandle<()>,
) {
    use crate::fleet::{
        job::{FileGrant, JobSpec, LeaseProfile},
        route_control::ApprovedDataRoutes,
    };
    let root = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let relay = Relay::new(
        &root.path().join("relay.db"),
        &url,
        "PUBLIC TEST ROUTE PASSWORD",
    )
    .unwrap();
    for id in [A, B, "third"] {
        enroll(&relay, id);
    }
    // This tests routing-only/token/ticket semantics with INVALID signatures,
    // not local E2E authentication or file permission. Real signing is separate.
    let v: Value = serde_json::from_str(&public_offer(A, B, 900)).unwrap();
    let job: JobSpec = serde_json::from_value(v["job"].clone()).unwrap();
    let grant: FileGrant = serde_json::from_value(v["grant"].clone()).unwrap();
    let g = grant
        .validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap();
    let b = &g.grant().binding;
    let id = Uuid::new_v4();
    let round = json!({"id":id,"role":"source","job":g.job(),"sourceSession":b.source_session,"targetSession":b.target_session,"authorizationId":b.authorization_id,"keyEpoch":b.key_epoch,"chunkBytes":g.grant().chunk_bytes,"issuedAtMs":g.grant().issued_at_ms,"leaseMs":g.grant().expires_at_ms-g.grant().issued_at_ms});
    let p = root.path().join("local-routes.json");
    std::fs::write(&p,serde_json::to_vec(&json!({"version":1,"approvals":[{"sourceDeviceId":A,"targetDeviceId":B,"round":round,"profile":"singleOwner","ttlMs":10000}]})).unwrap()).unwrap();
    let router = relay
        .clone()
        .router_with_approved_routes(ApprovedDataRoutes::load(&p).unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (root, url, relay, g, id, server)
}
#[tokio::test]
async fn native_data_route_two_authenticated_presenters_and_single_use_device_bound_tickets() {
    use crate::fleet::{protocol::Direction, relay_io::FleetLink};
    let (root, url, relay, g, id, server) = route_server().await;
    let mut a = data_control_socket(&url, A).await;
    let mut b = data_control_socket(&url, B).await;
    let mut third = data_control_socket(&url, "third").await;
    for ws in [&mut a, &mut b, &mut third] {
        let v = receive(ws).await.unwrap();
        assert_eq!(v["fleetDataProtocol"], 1);
    }
    let request = json!({"type":"fleetRoute","id":id,"grantDigest":g.digest()});
    a.send(Message::Text(request.to_string().into()))
        .await
        .unwrap();
    third
        .send(Message::Text(request.to_string().into()))
        .await
        .unwrap();
    assert_eq!(
        receive(&mut third).await.unwrap()["code"],
        "FLEET_DATA_REJECTED"
    );
    assert!(receive(&mut third).await.is_none());
    b.send(Message::Text(request.to_string().into()))
        .await
        .unwrap();
    let sa = receive(&mut a).await.unwrap();
    let sb = receive(&mut b).await.unwrap();
    assert_eq!(sa["type"], "fleetRoute");
    assert_eq!(sb["grantDigest"], json!(g.digest()));
    let ta = zeroize::Zeroizing::new(sa["ticket"].as_str().unwrap().to_owned());
    let tb = zeroize::Zeroizing::new(sb["ticket"].as_str().unwrap().to_owned());
    assert!(
        FleetLink::connect(
            &Network::direct(),
            &url,
            &token(B),
            &ta,
            &g,
            Direction::SourceToTarget,
            Duration::from_secs(2)
        )
        .await
        .is_err()
    );
    let la = FleetLink::connect(
        &Network::direct(),
        &url,
        &token(A),
        &ta,
        &g,
        Direction::SourceToTarget,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let lb = FleetLink::connect(
        &Network::direct(),
        &url,
        &token(B),
        &tb,
        &g,
        Direction::TargetToSource,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(
        FleetLink::connect(
            &Network::direct(),
            &url,
            &token(A),
            &ta,
            &g,
            Direction::SourceToTarget,
            Duration::from_secs(2)
        )
        .await
        .is_err()
    );
    // Control disconnect retires the route even when a DATA socket still lives.
    drop(a);
    offline_device(&relay, A).await;
    assert!(
        FleetLink::connect(
            &Network::direct(),
            &url,
            &token(B),
            &tb,
            &g,
            Direction::TargetToSource,
            Duration::from_secs(2)
        )
        .await
        .is_err()
    );
    drop(la);
    drop(lb);
    drop(b);
    drop(third);
    offline(&relay).await;
    server.abort();
    let _ = server.await;
    drop(relay);
    drop(root);
}
#[tokio::test]
async fn native_control_disconnect_invalidates_an_unclaimed_data_ticket() {
    use crate::fleet::{protocol::Direction, relay_io::FleetLink};
    let (root, url, relay, g, id, server) = route_server().await;
    let mut a = data_control_socket(&url, A).await;
    let mut b = data_control_socket(&url, B).await;
    receive(&mut a).await.unwrap();
    receive(&mut b).await.unwrap();
    let request = json!({"type":"fleetRoute","id":id,"grantDigest":g.digest()}).to_string();
    a.send(Message::Text(request.clone().into())).await.unwrap();
    b.send(Message::Text(request.into())).await.unwrap();
    let sa = receive(&mut a).await.unwrap();
    let sb = receive(&mut b).await.unwrap();
    let ta = zeroize::Zeroizing::new(sa["ticket"].as_str().unwrap().to_owned());
    let tb = zeroize::Zeroizing::new(sb["ticket"].as_str().unwrap().to_owned());
    let mut endpoint = crate::transport::websocket_url(&url).unwrap();
    endpoint.set_path("/fleet/ws");
    let mut data = Network::direct()
        .fleet_websocket(endpoint, &token(A), &ta, WebSocketConfig::default())
        .await
        .unwrap()
        .unwrap();
    // B has NOT claimed yet. Observe the actual waiting A socket close, not a
    // spent-ticket error that would pass even if disconnect forgot the route.
    drop(a);
    let closed = timeout(Duration::from_secs(5), data.next()).await.unwrap();
    assert!(matches!(
        closed,
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
    assert!(
        FleetLink::connect(
            &Network::direct(),
            &url,
            &token(B),
            &tb,
            &g,
            Direction::TargetToSource,
            Duration::from_secs(2)
        )
        .await
        .is_err()
    );
    drop(data);
    drop(b);
    offline(&relay).await;
    server.abort();
    let _ = server.await;
    drop(relay);
    drop(root);
}
async fn offline_device(r: &Relay, id: &str) {
    timeout(Duration::from_secs(5), async {
        while r.devices.lock().unwrap().contains_key(id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn native_data_negotiation_requires_independent_approval_router() {
    let (root, url, relay, _broker, server) = start_server(true).await;
    let mut a = data_control_socket(&url, A).await;
    assert_eq!(
        receive(&mut a).await.unwrap()["code"],
        "FLEET_DATA_UNAVAILABLE"
    );
    assert!(receive(&mut a).await.is_none());
    drop(a);
    offline(&relay).await;
    server.abort();
    let _ = server.await;
    drop(relay);
    drop(root);
}

const A: &str = "source-A";
const B: &str = "target-B";
fn token(id: &str) -> String {
    format!("PUBLIC_TEST_SETUP_{id}")
}
fn enroll(r: &Relay, id: &str) {
    let h = super::super::hash(&token(id));
    r.store
        .put("device", id, &json!({"tokenHash":h,"paused":false}), 600)
        .unwrap();
    r.store
        .put("device_token", &h, &json!({"deviceId":id}), 600)
        .unwrap();
}
async fn start_server(
    native: bool,
) -> (
    tempfile::TempDir,
    String,
    Arc<Relay>,
    Arc<SetupBroker>,
    tokio::task::JoinHandle<()>,
) {
    let root = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let relay = Relay::new(
        &root.path().join("relay.db"),
        &url,
        "PUBLIC TEST SETUP ADMIN PASSWORD",
    )
    .unwrap();
    enroll(&relay, A);
    enroll(&relay, B);
    let broker = Arc::new(SetupBroker::default());
    // Exact production router composition, but retain the registry for queue tests.
    let router = if native {
        relay
            .clone()
            .router_extra(crate::fleet::relay_channel::routes(Arc::new(
                FleetRelay::new(),
            )))
            .layer(axum::Extension(broker.clone()))
    } else {
        relay.clone().router()
    };
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (root, url, relay, broker, task)
}
async fn receive(ws: &mut Client) -> Option<Value> {
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(end, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "ping" {
                    ws.send(Message::Text(
                        json!({"type":"pong","ts":v["ts"]}).to_string().into(),
                    ))
                    .await
                    .unwrap();
                    continue;
                }
                return Some(v);
            }
            Ok(Some(Ok(Message::Ping(p)))) => ws.send(Message::Pong(p)).await.unwrap(),
            Ok(Some(Ok(Message::Pong(_)))) => {}
            Err(error) => panic!("native setup probe observation deadline: {error}"),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => return None,
            _ => panic!("unexpected native setup probe frame"),
        }
    }
}
async fn join(url: &str, id: &str, cap: Option<u64>, query: bool) -> Client {
    let mut endpoint = crate::transport::websocket_url(url).unwrap();
    if query {
        endpoint.set_query(Some("not-native=1"));
    }
    let mut ws = Network::direct()
        .websocket(endpoint, &token(id), WebSocketConfig::default())
        .await
        .unwrap()
        .unwrap();
    let mut hello = json!({"type":"hello","protocol":1,"device":{"deviceId":id},"tools":[]});
    if let Some(c) = cap {
        hello["fleetSetupProtocol"] = json!(c)
    }
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    ws
}
async fn native(url: &str, id: &str) -> Client {
    let mut ws = join(url, id, Some(1), false).await;
    let welcome = receive(&mut ws).await.unwrap();
    assert_eq!(welcome["fleetSetupProtocol"], 1);
    ws
}
async fn send(ws: &mut Client, request: Value) {
    ws.send(Message::Text(
        json!({"type":"fleetSetup","request":request})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
}
async fn offline(relay: &Relay) {
    timeout(Duration::from_secs(5), async {
        loop {
            if relay.devices.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn native_tcp_ws_forwards_three_phases_and_rejects_replay_replacement_pause_and_queue_overflow()
 {
    let (root, url, relay, broker, server) = start_server(true).await;
    let mut a = native(&url, A).await;
    let mut b = native(&url, B).await;
    let id = Uuid::new_v4();
    let offer = public_offer(A, B, 1);
    let response = public_response(&offer);
    let confirmation = public_confirmation(&response);
    send(
        &mut a,
        json!({"stage":"offer","id":id,"peerDevice":B,"payload":offer}),
    )
    .await;
    let v = receive(&mut b).await.unwrap();
    assert_eq!(v["fromDevice"], A);
    assert_eq!(v["stage"], "offer");
    assert_eq!(v["payload"], offer);
    send(
        &mut b,
        json!({"stage":"response","id":id,"payload":response}),
    )
    .await;
    let v = receive(&mut a).await.unwrap();
    assert_eq!(v["fromDevice"], B);
    assert_eq!(v["stage"], "response");
    assert_eq!(v["payload"], response);
    send(
        &mut a,
        json!({"stage":"confirmation","id":id,"payload":confirmation}),
    )
    .await;
    assert_eq!(receive(&mut b).await.unwrap()["payload"], confirmation);
    // Same binding under a new correlation id does NOT reopen a route.
    send(
        &mut a,
        json!({"stage":"offer","id":Uuid::new_v4(),"peerDevice":B,"payload":offer}),
    )
    .await;
    assert!(receive(&mut a).await.is_none());
    drop(a);
    let mut a = native(&url, A).await;
    let old = relay
        .devices
        .lock()
        .unwrap()
        .get(A)
        .unwrap()
        .generation
        .clone();
    let id = Uuid::new_v4();
    let offer = public_offer(A, B, 2);
    let response = public_response(&offer);
    send(
        &mut a,
        json!({"stage":"offer","id":id,"peerDevice":B,"payload":offer}),
    )
    .await;
    assert!(receive(&mut b).await.is_some());
    let mut replacement = native(&url, A).await;
    assert_ne!(
        relay.devices.lock().unwrap().get(A).unwrap().generation,
        old
    );
    send(
        &mut b,
        json!({"stage":"response","id":id,"payload":response}),
    )
    .await;
    assert!(receive(&mut b).await.is_none());
    assert!(
        timeout(Duration::from_millis(150), receive(&mut replacement))
            .await
            .is_err(),
        "old-generation response leaked to replacement socket"
    );
    drop(a);
    drop(b);
    let mut b = native(&url, B).await;
    // Synthetic full queue isolates enqueue failure; NOT a TCP sink-Pending test.
    enroll(&relay, "queue-target");
    let (tx, _rx) = mpsc::channel(1);
    tx.try_send(Outbound::Frame(json!({"type":"PUBLIC_TEST_QUEUE_FILL"})))
        .ok()
        .unwrap();
    relay.devices.lock().unwrap().insert(
        "queue-target".into(),
        Connected {
            generation: "queue-generation".into(),
            tools: vec![],
            tx,
            token_hash: super::super::hash(&token("queue-target")),
            setup_scope: Some(broker.scope()),
            route_scope: None,
        },
    );
    let before = broker.counts();
    let source_gen = relay
        .devices
        .lock()
        .unwrap()
        .get(A)
        .unwrap()
        .generation
        .clone();
    let raw=json!({"type":"fleetSetup","request":{"stage":"offer","id":Uuid::new_v4(),"peerDevice":"queue-target","payload":public_offer(A,"queue-target",3)}}).to_string();
    assert!(forward(&relay, &broker, A, &source_gen, &raw).is_err());
    let after = broker.counts();
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1 + 1);
    relay.devices.lock().unwrap().remove("queue-target");
    relay
        .store
        .put(
            "device",
            A,
            &json!({"tokenHash":super::super::hash(&token(A)),"paused":true}),
            600,
        )
        .unwrap();
    send(
        &mut replacement,
        json!({"stage":"offer","id":Uuid::new_v4(),"peerDevice":B,"payload":public_offer(A,B,4)}),
    )
    .await;
    assert!(receive(&mut replacement).await.is_none());
    assert!(
        timeout(Duration::from_millis(150), receive(&mut b))
            .await
            .is_err()
    );
    drop(replacement);
    drop(b);
    offline(&relay).await;
    server.abort();
    let _ = server.await;
    drop(relay);
    drop(root);
}
#[tokio::test]
async fn default_router_and_unnegotiated_or_queried_native_hello_do_not_enable_setup() {
    let (root, url, relay, _broker, server) = start_server(false).await;
    let mut legacy = join(&url, A, None, false).await;
    let v = receive(&mut legacy).await.unwrap();
    assert_eq!(v["type"], "welcome");
    assert!(v.get("fleetSetupProtocol").is_none());
    let mut denied = join(&url, B, Some(1), false).await;
    let error = receive(&mut denied).await.unwrap();
    assert_eq!(error["code"], "FLEET_SETUP_UNAVAILABLE");
    assert_eq!(error["fatal"], true);
    assert!(receive(&mut denied).await.is_none());
    drop(denied);
    drop(legacy);
    offline(&relay).await;
    server.abort();
    let _ = server.await;
    drop(relay);
    drop(root);
    let (root, url, relay, _broker, server) = start_server(true).await;
    let mut denied = join(&url, A, Some(2), false).await;
    assert_eq!(
        receive(&mut denied).await.unwrap()["code"],
        "FLEET_SETUP_UNAVAILABLE"
    );
    assert!(receive(&mut denied).await.is_none());
    drop(denied);
    let mut denied = join(&url, A, Some(1), true).await;
    assert_eq!(
        receive(&mut denied).await.unwrap()["code"],
        "FLEET_SETUP_UNAVAILABLE"
    );
    assert!(receive(&mut denied).await.is_none());
    drop(denied);
    let mut legacy = join(&url, A, None, false).await;
    assert!(receive(&mut legacy).await.is_some());
    send(
        &mut legacy,
        json!({"stage":"offer","id":Uuid::new_v4(),"peerDevice":B,"payload":public_offer(A,B,5)}),
    )
    .await;
    assert!(receive(&mut legacy).await.is_none());
    drop(legacy);
    offline(&relay).await;
    server.abort();
    let _ = server.await;
    drop(relay);
    drop(root);
}
#[test]
fn native_envelope_rejects_unknown_duplicate_fields_and_bad_phase() {
    let id = Uuid::new_v4();
    let valid = json!({"type":"fleetSetup","request":{"stage":"response","id":id,"payload":"{}"}});
    let mut v = valid.clone();
    v["fromDevice"] = json!("spoofed");
    assert!(serde_json::from_value::<Envelope>(v).is_err());
    let mut v = valid.clone();
    v["request"]["peerDevice"] = json!(B);
    assert!(serde_json::from_value::<Envelope>(v).is_err());
    let mut v = valid;
    v["request"]["stage"] = json!("restart");
    assert!(serde_json::from_value::<Envelope>(v).is_err());
    assert!(serde_json::from_str::<Envelope>(r#"{"type":"fleetSetup","type":"fleetSetup","request":{"stage":"response","id":"00000000-0000-0000-0000-000000000001","payload":"{}"}}"#).is_err());
}
