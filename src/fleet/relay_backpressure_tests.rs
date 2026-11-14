//! Real kernel TCP + native WS, explicit release probes. PUBLIC fixture auth.
//! Opaque relay stress intentionally sends without SourceWindow progress ACKs.
//! It does NOT publish a file, emulate trusted issuance, or prove v9 completion.
use super::*;
use futures_util::StreamExt;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::{
    Message as Wire, client::IntoClientRequest, protocol::WebSocketConfig,
};
type RawTarget = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;
const DATA_BYTES: usize = 8 * 1024 * 1024;
const CHUNK: usize = 65536;
async fn limited_target(url: &str, secret: &str) -> Result<(RawTarget, u32)> {
    let uri = reqwest::Url::parse(url)?;
    let addr = std::net::SocketAddr::new(uri.host_str().unwrap().parse()?, uri.port().unwrap());
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(65536)?;
    let actual = socket.recv_buffer_size()?;
    let tcp = socket.connect(addr).await?;
    tcp.set_nodelay(true)?;
    let mut url = crate::transport::websocket_url(url)?;
    url.set_path("/fleet/ws");
    let mut request = url.as_str().into_client_request()?;
    for (name, value) in [
        ("authorization", "Bearer TEST-target-token"),
        ("x-ferroc-fleet-protocol", "1"),
        ("x-ferroc-fleet-join", secret),
    ] {
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(name.as_bytes())?,
            value.parse()?,
        );
    }
    let config = WebSocketConfig::default()
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_FRAME * 2)
        .max_frame_size(Some(MAX_FRAME))
        .max_message_size(Some(MAX_FRAME));
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::client_async_with_config(request, tcp, Some(config)),
    )
    .await
    .context("limited Target upgrade deadline")??;
    Ok((ws, actual))
}
#[derive(Default)]
struct Seen {
    full: Option<Instant>,
    pending: Option<Instant>,
    exit: [Option<(Instant, String)>; 2],
    events: usize,
}
impl Seen {
    fn accept(&mut self, e: RelayTestEvent) {
        self.events += 1;
        match e {
            RelayTestEvent::QueueFull { destination: 1, at } => {
                self.full.get_or_insert(at);
            }
            RelayTestEvent::WritePending { destination: 1, at } => self.pending = Some(at),
            RelayTestEvent::Exit {
                destination,
                at,
                error,
            } => self.exit[destination] = Some((at, error.unwrap_or_default())),
            _ => {}
        }
    }
    async fn next(&mut self, rx: &mut broadcast::Receiver<RelayTestEvent>) -> Result<()> {
        self.accept(rx.recv().await.context("relay observation closed/lagged")?);
        Ok(())
    }
}
async fn actual_saturated_pair(mode: &str) {
    let temp = tempfile::tempdir().unwrap();
    let data = vec![0x5c; DATA_BYTES];
    let g = grant(temp.path(), &data);
    let registry = Arc::new(FleetRelay::new());
    let (url, relay, server) = server(temp.path(), Some(registry.clone())).await;
    let tickets = registry
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let pair = registry
        .table
        .lock()
        .unwrap()
        .pairs
        .values()
        .next()
        .unwrap()
        .clone();
    let mut events = pair.test_events.subscribe();
    let source = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    let (target, actual_rcvbuf) = limited_target(&url, tickets.target.expose_secret())
        .await
        .unwrap();
    let mut target = Some(target);
    let source_g = g.clone();
    let mut producer = Some(tokio::spawn(async move {
        let mut source = source;
        let mut records = records(&source_g, Direction::SourceToTarget);
        let result = async {
            for offset in (0..DATA_BYTES).step_by(CHUNK) {
                let frame = records.seal_data(offset as u64, &vec![0x5c; CHUNK])?;
                source.send(frame).await?;
            }
            Ok::<_, anyhow::Error>(DATA_BYTES / CHUNK)
        }
        .await;
        (result, source)
    }));
    let mut held_source = None;
    let mut seen = Seen::default();
    let started = Instant::now();
    let mut delivered = 0u64;
    let result = async {
        tokio::time::timeout(Duration::from_secs(4), async {
            while seen.full.is_none() || seen.pending.is_none() {
                seen.next(&mut events).await?;
                ensure!(
                    seen.exit.iter().all(Option::is_none),
                    "actor exited before observed saturation"
                );
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("did not observe actual QUEUE=8 full + native sink pending")??;
        ensure!(pair.tx[1].max_capacity() == QUEUE, "lane capacity changed");
        if mode == "revoke" {
            let paused = Instant::now();
            relay.store.put(
                "device",
                "target-B",
                &serde_json::json!({"paused":true,"tokenHash":hash("TEST-target-token")}),
                120,
            )?;
            tokio::time::timeout(Duration::from_secs(3), async {
                while seen.exit.iter().any(Option::is_none) {
                    seen.next(&mut events).await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("revocation did not interrupt saturated native pair")??;
            ensure!(
                seen.exit
                    .iter()
                    .flatten()
                    .any(|(_, e)| e.contains("device paused/credential rotated")),
                "no actual device revocation error"
            );
            ensure!(
                paused.elapsed() < IO_BUDGET,
                "revocation merely waited for5s writer timeout"
            );
        } else if mode == "resume" {
            let mut decoder = records(&g, Direction::TargetToSource);
            let mut hash = Sha256::new();
            tokio::time::timeout(Duration::from_secs(15), async {
                while delivered < DATA_BYTES as u64 {
                    let msg = target
                        .as_mut()
                        .unwrap()
                        .next()
                        .await
                        .context("Target EOF while draining")??;
                    if let Wire::Binary(b) = msg {
                        match decoder.open_record(&b)? {
                            crate::fleet::auth::PeerRecord::Data { header, bytes } => {
                                ensure!(
                                    header.offset == delivered && bytes.len() == CHUNK,
                                    "lost/reordered DATA"
                                );
                                hash.update(&bytes);
                                delivered += bytes.len() as u64;
                            }
                            _ => anyhow::bail!("not DATA"),
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("slow Target resume did not drain bounded sender")??;
            ensure!(
                <[u8; 32]>::from(hash.finalize()) == g.job().sha256,
                "native resumed stream SHA mismatch"
            );
            let (out, s) = tokio::time::timeout(Duration::from_secs(2), producer.as_mut().unwrap())
                .await
                .context("producer drain timeout")?
                .context("producer task panic")?;
            producer.take();
            held_source = Some(s);
            ensure!(out? == DATA_BYTES / CHUNK, "wrong sink invocation count");
        } else {
            tokio::time::timeout(Duration::from_secs(8), async {
                while seen.exit[1].is_none() {
                    seen.next(&mut events).await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("stalled relay did not enforce original5s write budget")??;
            let (at, error) = seen.exit[1].as_ref().unwrap();
            ensure!(
                error.contains("fleet write timeout"),
                "wrong native closing cause: {error}"
            );
            let blocked = at.duration_since(seen.pending.unwrap());
            ensure!(
                blocked >= IO_BUDGET - Duration::from_millis(20),
                "not original5s send deadline: {blocked:?}"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Always drop client sockets and join producer/server actors before fixture removal.
    if let Some(p) = producer.take() {
        p.abort();
        let _ = p.await;
    }
    drop(held_source);
    drop(target.take());
    registry.close();
    let drained = tokio::time::timeout(Duration::from_secs(3), async {
        while seen.exit.iter().any(Option::is_none) {
            seen.next(&mut events).await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    server.abort();
    let _ = server.await;
    let permits = registry.sockets.available_permits();
    let remaining = registry.table.lock().unwrap().pairs.len();
    let summary = serde_json::json!({"case":mode,"scope":"real native TCP/WS opaque authenticated DATA, one test process; NOT SourceWindow/v9/production/twoHost","socketReceiveRequested":65536,"socketReceiveActual":actual_rcvbuf,"queueCapacity":QUEUE,"observedFull":seen.full.is_some(),"observedNativeWritePending":seen.pending.is_some(),"deliveredDecoded":delivered,"plannedBytes":DATA_BYTES,"targetLastPendingUntilExitMs":seen.exit[1].as_ref().zip(seen.pending).map(|((at,_),pending)|at.saturating_duration_since(pending).as_millis()),"elapsedMs":started.elapsed().as_millis(),"actorErrors":seen.exit.iter().map(|e|e.as_ref().map(|(_,s)|s.clone())).collect::<Vec<_>>(),"allActorsExited":seen.exit.iter().all(Option::is_some),"socketPermitsAfter":permits,"pairsAfter":remaining,"result":if result.is_ok(){"passed"}else{"failed"}});
    println!("NATIVE_WS_BACKPRESSURE {summary}");
    if let Some(out) = std::env::var_os("FERROC_FLEET_PRESSURE_OUTPUT") {
        let p = std::path::PathBuf::from(out);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(
            p.join(format!("{mode}.json")),
            serde_json::to_vec_pretty(&summary).unwrap(),
        )
        .unwrap();
    }
    assert!(
        drained.is_ok_and(|r| r.is_ok()),
        "native actor observation/drain failed"
    );
    assert_eq!(permits, MAX_PAIRS * 2);
    assert_eq!(remaining, 0);
    assert!(result.is_ok(), "{result:?}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit release native TCP nonreading Target/original5s deadline probe"]
async fn actual_nonreading_target_saturates_eight_lane_and_hits_original_write_deadline() {
    actual_saturated_pair("never-read").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit release native TCP pause/resume DATA/SHA/no-loss contrast"]
async fn actual_paused_target_resumes_after_observed_saturation_without_losing_records() {
    actual_saturated_pair("resume").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit release native saturated-pair credential revocation probe"]
async fn actual_revocation_interrupts_native_blocked_write_before_five_second_deadline() {
    actual_saturated_pair("revoke").await;
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit release actual SourceFile/window +Targetv9, lost final ACK is not rollback"]
async fn actual_v9_settlement_survives_failed_native_final_ack_without_source_completion() {
    use crate::fleet::{journal::JobKey, state::Phase};
    use std::sync::atomic::{AtomicBool, Ordering};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x5c; DATA_BYTES];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let registry = Arc::new(FleetRelay::new());
    let (url, _relay, server) = server(&root, Some(registry.clone())).await;
    let tickets = registry
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let pair = registry
        .table
        .lock()
        .unwrap()
        .pairs
        .values()
        .next()
        .unwrap()
        .clone();
    let mut events = pair.test_events.subscribe();
    let callback = Arc::new(AtomicBool::new(false));
    let hook_called = callback.clone();
    let target_root = root.clone();
    let target_g = g.clone();
    let target_url = url.clone();
    let stop = registry.clone();
    let handle = tokio::runtime::Handle::current();
    let target = tokio::task::spawn_blocking(move || {
        let runtime = Runtime::new(Policy::new(vec![target_root.join("target")], false).unwrap());
        let host = runtime
            .open_fleet_host(
                &target_root.join("target/host.db"),
                InventoryLimits::default(),
            )
            .unwrap();
        host.resume().unwrap();
        let receiver = host
            .admit_receiver(records(&target_g, Direction::TargetToSource))
            .unwrap();
        let result = handle.block_on(async {
            let link = link(
                &target_url,
                tickets.target.expose_secret(),
                &target_g,
                Direction::TargetToSource,
            )
            .await
            .unwrap();
            crate::fleet::relay_io::run_target_after_settle(receiver, link, async |link| {
                hook_called.store(true, Ordering::SeqCst);
                stop.close();
                let disconnected = tokio::time::timeout(Duration::from_secs(3), link.receive())
                    .await
                    .context("after-settlement real relay EOF missing")?;
                ensure!(
                    disconnected.is_err(),
                    "unexpected peer DATA after settlement"
                );
                Ok(())
            })
            .await
        });
        let error = match result {
            Ok(_) => panic!("final ACK write must fail after actual native EOF"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            error.contains("target settled locally; final ACK delivery unknown"),
            "{error}"
        );
        let snapshot = host
            .get(&JobKey::from_job(target_g.job()))
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.phase(), Phase::Completed);
        assert!(snapshot.settlement_origin().is_some());
        assert!(snapshot.receipt().is_some());
        assert!(snapshot.stage().is_none());
        assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
        assert_eq!(host.status().unwrap().in_flight, 0);
        assert_eq!(
            std::fs::read(target_root.join("target/output.bin")).unwrap(),
            vec![0x5c; DATA_BYTES]
        );
        host.close().unwrap();
        error
    });
    let source_root = root.clone();
    let source_g = g.clone();
    let source_url = url.clone();
    let handle = tokio::runtime::Handle::current();
    let source = tokio::task::spawn_blocking(move || {
        let runtime = Runtime::new(Policy::new(vec![source_root.join("source")], false).unwrap());
        let window = SourceWindow::new(
            runtime
                .open_fleet_source(records(&source_g, Direction::SourceToTarget))
                .unwrap(),
            8,
        )
        .unwrap();
        handle.block_on(async {
            let link = link(
                &source_url,
                tickets.source.expose_secret(),
                &source_g,
                Direction::SourceToTarget,
            )
            .await
            .unwrap();
            match run_source(window, link).await {
                Ok(_) => panic!("Source must not claim completion without authenticated final ACK"),
                Err(e) => format!("{e:#}"),
            }
        })
    });
    let (source, target) = tokio::join!(source, target);
    registry.close();
    let mut seen = Seen::default();
    let drained = tokio::time::timeout(Duration::from_secs(3), async {
        while seen.exit.iter().any(Option::is_none) {
            seen.next(&mut events).await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    server.abort();
    let _ = server.await;
    assert!(drained.is_ok_and(|v| v.is_ok()));
    let source = source.unwrap();
    let target = target.unwrap();
    assert!(callback.load(Ordering::SeqCst));
    assert_eq!(registry.sockets.available_permits(), MAX_PAIRS * 2);
    assert!(registry.table.lock().unwrap().pairs.is_empty());
    assert_eq!(std::fs::read(root.join("source/input.bin")).unwrap(), data);
    let summary = serde_json::json!({"case":"settled-final-ack-failure","scope":"actual SourceFile/window and Windows Targetv9 over native relay TCP in one TEST process, NOT twoHost","sourceReturnedError":source,"targetReturnedError":target,"afterV9HookObserved":true,"targetHistoricalCompleted":true,"targetReceiptExists":true,"targetBytesMatch":true,"sourceBytesUnchanged":true,"stageDebt":[0,0],"allActorsExited":true,"socketPermitsAfter":registry.sockets.available_permits(),"pairsAfter":0,"bytes":DATA_BYTES,"result":"passed"});
    println!("NATIVE_ACK_FAILURE {summary}");
    if let Some(out) = std::env::var_os("FERROC_FLEET_PRESSURE_OUTPUT") {
        let out = std::path::PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            out.join("settled-final-ack-failure.json"),
            serde_json::to_vec_pretty(&summary).unwrap(),
        )
        .unwrap();
    }
}
