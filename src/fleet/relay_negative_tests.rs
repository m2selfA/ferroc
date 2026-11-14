use super::*;
use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::{Message as Wire, protocol::WebSocketConfig};
async fn raw(url: &str, secret: &str) -> tokio_tungstenite::WebSocketStream<reqwest::Upgraded> {
    let mut url = crate::transport::websocket_url(url).unwrap();
    url.set_path("/fleet/ws");
    Network::direct()
        .fleet_websocket(url, "TEST-source-token", secret, WebSocketConfig::default())
        .await
        .unwrap()
        .unwrap()
}
#[test]
fn active_pair_and_lifetime_approval_caps_do_not_forget_spent_history() {
    let t = tempfile::tempdir().unwrap();
    let f = FleetRelay::new();
    let mut first = None;
    for _ in 0..MAX_PAIRS {
        let g = grant(t.path(), b"x");
        if first.is_none() {
            first = Some(g.clone())
        }
        f.approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
            .unwrap();
    }
    assert!(
        f.approve_local(
            &grant(t.path(), b"x"),
            "source-A",
            "target-B",
            Duration::from_secs(30)
        )
        .is_err()
    );
    {
        let mut table = f.table.lock().unwrap();
        let ids: Vec<_> = table.pairs.keys().copied().collect();
        for id in ids {
            FleetRelay::retire_locked(&mut table, id);
        }
    }
    assert!(
        f.approve_local(
            &first.unwrap(),
            "source-A",
            "target-B",
            Duration::from_secs(30)
        )
        .is_err()
    );
    for _ in MAX_PAIRS..MAX_APPROVALS {
        let g = grant(t.path(), b"x");
        f.approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
            .unwrap();
        let mut table = f.table.lock().unwrap();
        let id = *table.pairs.keys().next().unwrap();
        FleetRelay::retire_locked(&mut table, id);
    }
    assert!(
        f.approve_local(
            &grant(t.path(), b"x"),
            "source-A",
            "target-B",
            Duration::from_secs(30)
        )
        .is_err()
    );
    assert_eq!(f.table.lock().unwrap().spent.len(), 64);
}
#[tokio::test]
async fn native_header_origin_query_duplicate_and_wrong_protocol_rejected_before_ticket_claim() {
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(t.path(), Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    for mode in ["origin", "query", "authorization", "ticket", "protocol"] {
        let mut request = Network::direct()
            .client(Some(Duration::from_secs(5)))
            .unwrap()
            .get(format!(
                "{url}/fleet/ws{}",
                if mode == "query" { "?forbidden=1" } else { "" }
            ))
            .bearer_auth("TEST-source-token")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("x-ferroc-fleet-join", tickets.source.expose_secret())
            .header(
                "x-ferroc-fleet-protocol",
                if mode == "protocol" { "2" } else { "1" },
            );
        request = match mode {
            "origin" => request.header("origin", &url),
            "authorization" => request.header("authorization", "Bearer TEST-source-token"),
            "ticket" => request.header("x-ferroc-fleet-join", tickets.source.expose_secret()),
            _ => request,
        };
        assert_eq!(
            request.send().await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "{mode}"
        );
    }
    let s = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    drop(s);
    f.close();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn relay_rejects_wrong_binding_direction_and_oversized_ws_not_just_client_validator() {
    let t = tempfile::tempdir().unwrap();
    let f = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(t.path(), Some(f.clone())).await;
    for mode in ["binding", "direction", "oversize"] {
        let g = grant(t.path(), b"abc");
        let tickets = f
            .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
            .unwrap();
        let mut s = raw(&url, tickets.source.expose_secret()).await;
        let mut p = link(
            &url,
            tickets.target.expose_secret(),
            &g,
            Direction::TargetToSource,
        )
        .await
        .unwrap();
        let bytes = match mode {
            "binding" => records(&grant(t.path(), b"abc"), Direction::SourceToTarget)
                .seal_data(0, b"abc")
                .unwrap(),
            "direction" => records(&g, Direction::TargetToSource)
                .seal_control(crate::fleet::control::ControlBody::Ready(
                    crate::fleet::control::Ready {
                        chunk_bytes: 65536,
                        window_chunks: 8,
                    },
                ))
                .unwrap(),
            _ => vec![0x37; MAX_FRAME + 1],
        };
        let _ = s.send(Wire::Binary(bytes.into())).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(3), p.receive())
                .await
                .unwrap()
                .is_err(),
            "{mode}"
        );
    }
    f.close();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn token_rotation_or_pause_after_join_closes_pair_without_sending_more_data() {
    let t = tempfile::tempdir().unwrap();
    let f = Arc::new(FleetRelay::new());
    let (url, r, task) = server(t.path(), Some(f.clone())).await;
    for pause in [false, true] {
        devices(&r);
        let g = grant(t.path(), b"abc");
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
        r.store.put("device","target-B",&serde_json::json!({"paused":pause,"tokenHash":if pause{hash("TEST-target-token")}else{hash("TEST-rotated-token")}}),120).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), s.receive())
                .await
                .unwrap()
                .is_err()
        );
        drop(p);
    }
    f.close();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn blocked_real_io_send_deadline_is_not_starved_by_always_ready_control_and_not_restarted() {
    use tokio::io::AsyncWriteExt;
    let (mut writer, _reader) = tokio::io::duplex(1);
    let calls = std::cell::Cell::new(0usize);
    let seen = std::cell::Cell::new(0usize);
    let send = async {
        calls.set(calls.get() + 1);
        tokio::time::timeout(Duration::from_millis(20), writer.write_all(&[0; 1024]))
            .await
            .context("controlled blocked send deadline")??;
        Ok(())
    };
    let input = futures_util::stream::repeat_with(|| Ok(vec![]));
    let start = Instant::now();
    let result = crate::fleet::relay_io::sending_with_controls(send, input, |_| {
        seen.set(seen.get() + 1);
        Ok(())
    })
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("controlled blocked send deadline")
    );
    assert!(start.elapsed() >= Duration::from_millis(20));
    assert!(seen.get() >= 8);
    assert_eq!(calls.get(), 1);
    assert!(start.elapsed() < Duration::from_secs(2));
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_disconnect_after_one_ack_preserves_partial_stage_full_debt_and_no_target() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x35; 131073];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let f = Arc::new(FleetRelay::new());
    let (url, _r, server) = server(&root, Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let target_g = g.clone();
    let target_root = root.clone();
    let target_url = url.clone();
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
        let stage = receiver.snapshot().stage().unwrap().path().to_path_buf();
        let result = handle.block_on(async {
            let l = link(
                &target_url,
                tickets.target.expose_secret(),
                &target_g,
                Direction::TargetToSource,
            )
            .await
            .unwrap();
            crate::fleet::relay_io::run_target(receiver, l).await
        });
        assert!(result.is_err());
        assert_eq!(host.inventory().unwrap().recorded_usage(), (131073, 1));
        assert_eq!(std::fs::metadata(&stage).unwrap().len(), 65536);
        assert!(!target_root.join("target/output.bin").exists());
        assert_eq!(host.status().unwrap().in_flight, 0);
        host.close().unwrap();
    });
    let runtime = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let mut w = SourceWindow::new(
        runtime
            .open_fleet_source(records(&g, Direction::SourceToTarget))
            .unwrap(),
        8,
    )
    .unwrap();
    let mut s = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    w.observe_control(&s.receive().await.unwrap()).unwrap();
    let frame = match w.next_record().unwrap() {
        crate::fleet::source_window::WindowRecord::Data { ciphertext, .. } => ciphertext.to_vec(),
        _ => panic!("DATA expected"),
    };
    s.send(frame).await.unwrap();
    w.observe_control(&s.receive().await.unwrap()).unwrap();
    assert_eq!(w.bytes_peer_reported_contiguous(), 65536);
    drop(s);
    drop(w);
    target.await.unwrap();
    f.close();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn fleet_route_explicit_http_proxy_407_has_no_direct_fallback_and_hides_credentials() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(t.path(), Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = Network::proxy(&format!(
        "http://TEST-proxy-user:TEST-proxy-password@{}",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let probe = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut data = vec![];
        let mut b = [0u8; 1];
        while !data.ends_with(b"\r\n\r\n") {
            assert!(data.len() < 8192);
            stream.read_exact(&mut b).await.unwrap();
            data.push(b[0]);
        }
        let text = String::from_utf8(data).unwrap();
        assert!(text.starts_with("GET http://127.0.0.1:"));
        assert!(text.to_ascii_lowercase().contains("proxy-authorization:"));
        stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let result = FleetLink::connect(
        &proxy,
        &url,
        "TEST-source-token",
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
        Duration::from_secs(5),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("proxy407 must not succeed"),
        Err(e) => e.to_string(),
    };
    assert!(error.contains("407"));
    for secret in [
        "TEST-source-token",
        "TEST-proxy-user",
        "TEST-proxy-password",
        tickets.source.expose_secret(),
    ] {
        assert!(!error.contains(secret));
    }
    probe.await.unwrap();
    assert_eq!(f.table.lock().unwrap().tickets.len(), 2);
    let s = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    drop(s);
    f.close();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn fleet_route_explicit_http_proxy_forwards_real_authenticated_binary() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let t = tempfile::tempdir().unwrap();
    let g = grant(t.path(), b"abc");
    let f = Arc::new(FleetRelay::new());
    let (url, _r, task) = server(t.path(), Some(f.clone())).await;
    let tickets = f
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = Network::proxy(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let origin = reqwest::Url::parse(&url).unwrap();
    let probe = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        let mut b = [0u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 8192);
            stream.read_exact(&mut b).await.unwrap();
            bytes.push(b[0]);
        }
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("GET http://127.0.0.1:"));
        let mut forwarded = String::from("GET /fleet/ws HTTP/1.1\r\n");
        for line in text.split("\r\n").skip(1) {
            if !line.is_empty()
                && !line
                    .to_ascii_lowercase()
                    .starts_with("proxy-authorization:")
            {
                forwarded.push_str(line);
                forwarded.push_str("\r\n");
            }
        }
        forwarded.push_str("\r\n");
        let mut upstream =
            tokio::net::TcpStream::connect((origin.host_str().unwrap(), origin.port().unwrap()))
                .await
                .unwrap();
        upstream.write_all(forwarded.as_bytes()).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    });
    let mut s = FleetLink::connect(
        &proxy,
        &url,
        "TEST-source-token",
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
        Duration::from_secs(10),
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
    let data = records(&g, Direction::SourceToTarget)
        .seal_data(0, b"abc")
        .unwrap();
    s.send(data.clone()).await.unwrap();
    let got = p.receive().await.unwrap();
    assert_eq!(got, data);
    assert!(matches!(
        records(&g, Direction::TargetToSource)
            .open_record(&got)
            .unwrap(),
        crate::fleet::auth::PeerRecord::Data { .. }
    ));
    drop(s);
    drop(p);
    f.close();
    tokio::time::timeout(Duration::from_secs(3), probe)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    let _ = task.await;
}
