//! Native Linux TCP EOF tail probe, PUBLIC fixture keys only.
//! Authenticated DATA is decoded, but this is not SourceWindow or private v9 IO.
use super::*;
use std::os::fd::AsRawFd;

async fn small_send_server(
    root: &Path,
    registry: Arc<FleetRelay>,
) -> (String, tokio::task::JoinHandle<()>, i32) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bytes: libc::c_int = 32768;
    // SAFETY: fd is a live Linux TCP listener, pointer and length describe a
    // valid c_int. The option bounds only this isolated PUBLIC TEST listener.
    let result = unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::from_ref(&bytes).cast(),
            std::mem::size_of_val(&bytes) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    let mut observed: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&observed) as libc::socklen_t;
    // SAFETY: the fd is live; both outputs point to initialized, sized storage.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_mut(&mut observed).cast(),
                &mut length,
            )
        },
        0
    );
    assert!(observed >= bytes);
    let url = format!("http://{}", listener.local_addr().unwrap());
    let relay = Relay::new(
        &root.join("relay.db"),
        &url,
        "PUBLIC TEST admin password only",
    )
    .unwrap();
    devices(&relay);
    let router = relay.router_with_fleet(registry);
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task, observed)
}

#[tokio::test]
async fn native_sender_eof_preserves_already_accepted_tail() {
    const TOTAL: usize = 1024 * 1024;
    let temp = tempfile::tempdir().unwrap();
    let data = vec![0x61; TOTAL];
    let grant = grant(temp.path(), &data);
    let registry = Arc::new(FleetRelay::new());
    let (url, server, send_buffer) = small_send_server(temp.path(), registry.clone()).await;
    // Approve only after the expensive test relay is ready; budgets unchanged.
    let tickets = registry
        .approve_local(&grant, "source-A", "target-B", Duration::from_secs(30))
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
        &grant,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    let (target, recv_buffer) = limited_target(&url, tickets.target.expose_secret())
        .await
        .unwrap();
    let mut target = Some(target);
    let source_grant = grant.clone();
    let mut producer = Some(tokio::spawn(async move {
        let mut source = source;
        let mut encoder = records(&source_grant, Direction::SourceToTarget);
        for offset in (0..TOTAL).step_by(CHUNK) {
            source
                .send(encoder.seal_data(offset as u64, &vec![0x61; CHUNK])?)
                .await?;
        }
        // Normal stock pumps also drop their link after their last send. The
        // original resume probe deliberately retained this socket until reads.
        drop(source);
        Ok::<_, anyhow::Error>(TOTAL / CHUNK)
    }));
    let mut seen = Seen::default();
    let mut delivered = 0usize;
    let result = async {
        tokio::time::timeout(Duration::from_secs(4), async {
            while seen.full.is_none() || seen.pending.is_none() {
                seen.next(&mut events).await?;
                ensure!(
                    seen.exit.iter().all(Option::is_none),
                    "actor exited before native saturation"
                );
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("real QUEUE8/sink Pending not observed")??;
        ensure!(pair.tx[1].max_capacity() == QUEUE, "queue capacity changed");
        let mut decoder = records(&grant, Direction::TargetToSource);
        let mut digest = Sha256::new();
        tokio::time::timeout(Duration::from_secs(15), async {
            while delivered < TOTAL {
                if delivered == 4 * CHUNK {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let message = target
                    .as_mut()
                    .unwrap()
                    .next()
                    .await
                    .context("EOF lost accepted DATA tail")?
                    .context("socket failed before tail drained")?;
                if let Wire::Binary(bytes) = message {
                    match decoder.open_record(&bytes)? {
                        crate::fleet::auth::PeerRecord::Data { header, bytes } => {
                            ensure!(
                                header.offset == delivered as u64 && bytes.len() == CHUNK,
                                "reordered or changed tail"
                            );
                            digest.update(&bytes);
                            delivered += bytes.len();
                        }
                        _ => anyhow::bail!("not DATA"),
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("native EOF drain observation timeout")??;
        ensure!(
            <[u8; 32]>::from(digest.finalize()) == grant.job().sha256,
            "full native DATA SHA mismatch"
        );
        let produced = tokio::time::timeout(Duration::from_secs(2), producer.as_mut().unwrap())
            .await
            .context("producer did not finish")?
            .context("producer panicked")??;
        producer.take();
        ensure!(produced == TOTAL / CHUNK, "producer count mismatch");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Some(task) = producer.take() {
        task.abort();
        let _ = task.await;
    }
    drop(target.take());
    registry.close();
    let cleanup = tokio::time::timeout(Duration::from_secs(3), async {
        while seen.exit.iter().any(Option::is_none) {
            seen.next(&mut events).await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    server.abort();
    let _ = server.await;
    eprintln!(
        "{}",
        serde_json::json!({"probe":"native-sender-eof-tail","expectedBytes":TOTAL,"deliveredBytes":delivered,"nativeSinkPendingObserved":seen.pending.is_some(),"queueFullObserved":seen.full.is_some(),"listenerSendBuffer":send_buffer,"targetReceiveBuffer":recv_buffer,"actorExitErrors":seen.exit.iter().map(|x|x.as_ref().map(|(_,error)|error)).collect::<Vec<_>>(),"originalIoBudgetMs":IO_BUDGET.as_millis(),"originalQueue":QUEUE,"result":result.as_ref().err().map(|error|format!("{error:#}"))})
    );
    assert!(
        matches!(cleanup, Ok(Ok(()))),
        "native actors did not exit: {cleanup:?}"
    );
    result.expect("closing Source discarded authenticated, already accepted tail");
}
