use super::*;
#[path = "../tests/support/proxy.rs"]
mod proxy_fixture;

#[tokio::test]
async fn transfer_upload_download_share_the_proxy_and_refusal_preserves_key_and_target() {
    use proxy_fixture::{Kind, ProxyFixture};
    let dir = tempfile::tempdir().unwrap();
    let mut p = enabled(dir.path());
    let (mut t, state, server) = fixture().await;
    let origin: reqwest::Url = t.origin_override.as_ref().unwrap().parse().unwrap();
    let target = format!("127.0.0.1:{}", origin.port().unwrap())
        .parse()
        .unwrap();
    // This loopback alias is NOT listening. The fixture proxy maps it to the actual 127.0.0.1 listener.
    t.origin_override = Some(format!("http://127.0.0.2:{}", origin.port().unwrap()));
    let direct = crate::network::Network::direct()
        .client(Some(Duration::from_secs(2)))
        .unwrap()
        .get(t.origin_override.as_ref().unwrap())
        .send()
        .await;
    assert!(
        direct.is_err(),
        "provider test route must not be directly reachable"
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), 0);
    let proxy = ProxyFixture::start(Kind::Http, target, true).await;
    p.network = crate::network::Network::proxy(&proxy.url("http", true)).unwrap();
    let source = dir.path().join("proxy-source.bin");
    let destination = dir.path().join("proxy-result.bin");
    let data = (0..100000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    fs::write(&source, &data).unwrap();
    let gate = Arc::new(Mutex::new(()));
    let receive = t
        .call(&p, "prepare_file_transfer", json!({}), gate.clone())
        .await
        .unwrap();
    let sent = t
        .call(
            &p,
            "send_file_transfer",
            json!({"sourcePath":source,"recipientPublicKey":receive["recipientPublicKey"]}),
            gate.clone(),
        )
        .await
        .unwrap();
    let args = json!({"receiveId":receive["receiveId"],"transferToken":sent["transferToken"],"destinationPath":destination});
    let before = state.requests.load(Ordering::SeqCst);
    p.network = crate::network::Network::proxy(&proxy.url("http", false)).unwrap();
    assert!(
        t.call(&p, "receive_file_transfer", args.clone(), gate.clone())
            .await
            .is_err()
    );
    assert_eq!(
        state.requests.load(Ordering::SeqCst),
        before,
        "must not fall back to direct provider IO"
    );
    assert!(!destination.exists());
    assert!(
        t.keys
            .lock()
            .unwrap()
            .contains_key(receive["receiveId"].as_str().unwrap())
    );
    p.network = crate::network::Network::proxy(&proxy.url("http", true)).unwrap();
    t.call(&p, "receive_file_transfer", args, gate)
        .await
        .unwrap();
    assert_eq!(fs::read(destination).unwrap(), data);
    eprintln!(
        "transfer route metric: proxy_connections={}, provider_requests={}",
        proxy.count(),
        state.requests.load(Ordering::SeqCst)
    );
    assert_eq!(
        proxy.count(),
        3,
        "one fixture connection per upload/page/download"
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), 3);
    assert!(
        !t.keys
            .lock()
            .unwrap()
            .contains_key(receive["receiveId"].as_str().unwrap())
    );
    server.abort();
    let _ = server.await;
}

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn enabled(root: &std::path::Path) -> Policy {
    let mut p = Policy::new(vec![root.into()], false).unwrap();
    p.allow_transfers = true;
    p
}
fn envelope(data: &[u8], secret: &StaticSecret) -> (Envelope, Vec<u8>) {
    let (mut e, c) = seal(Zeroizing::new(data.to_vec()), &public_b64(secret), 3600).unwrap();
    e.url = "https://tmpfiles.org/page".into();
    (e, c)
}
#[test]
fn crypto_authentication_and_manifest_failures() {
    for data in [
        Vec::new(),
        b"binary\0\xff payload".to_vec(),
        (0..65536).map(|i| (i % 251) as u8).collect(),
    ] {
        let secret = StaticSecret::random();
        let (e, c) = envelope(&data, &secret);
        assert_eq!(
            &*unseal(
                &Envelope::decode(&e.encode().unwrap()).unwrap(),
                &secret,
                Zeroizing::new(c.clone())
            )
            .unwrap(),
            &data
        );
        assert!(unseal(&e, &StaticSecret::random(), Zeroizing::new(c.clone())).is_err());
        for field in [
            "fileTag",
            "wrapTag",
            "wrapSalt",
            "fileIv",
            "wrapIv",
            "wrappedKey",
        ] {
            let mut v = serde_json::to_value(&e).unwrap();
            let mut bytes = STANDARD.decode(v[field].as_str().unwrap()).unwrap();
            bytes[0] ^= 1;
            v[field] = json!(b64(&bytes));
            let bad: Envelope = serde_json::from_value(v).unwrap();
            assert!(
                unseal(&bad, &secret, Zeroizing::new(c.clone())).is_err(),
                "tampered {field}"
            );
        }
        let mut bad = e.clone();
        bad.sha256 = "0".repeat(64);
        assert!(unseal(&bad, &secret, Zeroizing::new(c.clone())).is_err());
        if !c.is_empty() {
            let mut bad = c.clone();
            bad[0] ^= 1;
            assert!(unseal(&e, &secret, Zeroizing::new(bad)).is_err());
        }
    }
    let mut der = SPKI.to_vec();
    der.extend([0; 32]);
    let secret = StaticSecret::random();
    assert!(wrapping(&secret, &public(&b64(&der)).unwrap(), &[0; 16]).is_err());
}
#[test]
fn full_99mb_crypto_roundtrip() {
    let secret = StaticSecret::random();
    let data = Zeroizing::new(vec![0xa5; MAX_BYTES]);
    let (mut e, cipher) = seal(data, &public_b64(&secret), 3600).unwrap();
    e.url = "https://tmpfiles.org/dl/scale".into();
    let result = unseal(&e, &secret, Zeroizing::new(cipher)).unwrap();
    assert_eq!(result.len(), MAX_BYTES);
    assert!(result.iter().all(|b| *b == 0xa5));
}
#[test]
fn envelope_rejects_untrusted_urls_and_bad_fields() {
    for bad in [
        "http://tmpfiles.org/dl/x",
        "https://evil.example/dl/x",
        "https://tmpfiles.org.evil.example/dl/x",
        "https://tmpfiles.org@evil.example/dl/x",
        "https://u:p@tmpfiles.org/dl/x",
        "https://tmpfiles.org:8443/dl/x",
        "https://tmpfiles.org/dl/x#frag",
        "file:///tmpfiles.org/x",
    ] {
        assert!(provider_url(bad).is_err(), "{bad}");
    }
    let (e, _) = envelope(b"payload", &StaticSecret::random());
    for (field, value) in [
        ("v", json!(2)),
        ("provider", json!("other")),
        ("size", json!(MAX_BYTES + 1)),
        ("size", json!(-1)),
        ("expiresAt", json!(0)),
        ("expiresAt", json!(now() + 7_300_000)),
        ("fileIv", json!("AAAA")),
        ("senderPublicKey", json!("not a key")),
        ("sha256", json!("deadbeef")),
    ] {
        let mut v = serde_json::to_value(&e).unwrap();
        v[field] = value;
        assert!(
            Envelope::decode(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())).is_err(),
            "{field}"
        );
    }
    assert!(Envelope::decode(&"A".repeat(16385)).is_err());
}
#[tokio::test]
async fn key_limits_expiry_shutdown_and_explicit_disable() {
    let dir = tempfile::tempdir().unwrap();
    let t = Transfers::default();
    let mut p = Policy::new(vec![dir.path().into()], false).unwrap();
    assert!(p.allow_transfers, "Policy defaults must enable transfers");
    p.allow_transfers = false;
    let gate = Arc::new(Mutex::new(()));
    for tool in [
        "prepare_file_transfer",
        "send_file_transfer",
        "receive_file_transfer",
    ] {
        assert!(
            t.call(&p, tool, json!({}), gate.clone())
                .await
                .unwrap_err()
                .to_string()
                .contains("disabled")
        );
    }
    for args in [
        json!({"ttlSeconds":false}),
        json!({"ttlSeconds":59}),
        json!({"ttlSeconds":7201}),
    ] {
        assert!(t.prepare(&args).is_err());
    }
    let first = t.prepare(&json!({"ttlSeconds":60})).unwrap();
    let id = first["receiveId"].as_str().unwrap();
    assert_eq!(id.len(), 32);
    public(first["recipientPublicKey"].as_str().unwrap()).unwrap();
    t.keys.lock().unwrap().get_mut(id).unwrap().expires = 0;
    for _ in 0..MAX_KEYS {
        t.prepare(&json!({})).unwrap();
    }
    assert_eq!(t.keys.lock().unwrap().len(), MAX_KEYS);
    assert!(t.prepare(&json!({})).is_err());
    t.shutdown();
    assert!(t.keys.lock().unwrap().is_empty());
}
#[derive(Default)]
struct Fixture {
    data: Mutex<Vec<u8>>,
    mode: AtomicUsize,
    requests: AtomicUsize,
}
async fn provider(State(s): State<Arc<Fixture>>, req: Request) -> Response {
    assert!(
        req.headers().get("proxy-authorization").is_none(),
        "proxy credentials must never reach provider fixture"
    );
    s.requests.fetch_add(1, Ordering::SeqCst);
    let mode = s.mode.load(Ordering::SeqCst);
    if mode == 3 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if mode == 6 {
        return (
            StatusCode::FOUND,
            [("location", "https://evil.example/never-follow")],
        )
            .into_response();
    }
    if req.method() == "POST" {
        let boundary = req.headers()["content-type"]
            .to_str()
            .unwrap()
            .split("boundary=")
            .nth(1)
            .unwrap()
            .to_owned();
        let bytes = to_bytes(req.into_body(), MAX_BYTES + 16384).await.unwrap();
        let start = bytes.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
        let delim = format!("\r\n--{boundary}");
        let end = bytes[start..]
            .windows(delim.len())
            .position(|x| x == delim.as_bytes())
            .unwrap()
            + start;
        *s.data.lock().unwrap() = bytes[start..end].to_vec();
        let url = if mode == 1 {
            "https://evil.example/data"
        } else {
            "https://tmpfiles.org/page"
        };
        return axum::Json(json!({"status":"success","data":{"url":url}})).into_response();
    }
    if req.uri().path() == "/page" {
        return axum::response::Html("<a class=\"download\" href=\"/dl/file\">download</a>")
            .into_response();
    }
    let mut data = s.data.lock().unwrap().clone();
    if mode == 4 {
        data.pop();
    }
    if mode == 5 {
        data.push(1);
        return Response::new(Body::from_stream(futures_util::stream::iter([Ok::<
            _,
            std::convert::Infallible,
        >(
            data
        )])));
    }
    if mode == 2 {
        return (
            [("content-length", "100000001")],
            Body::from_stream(futures_util::stream::pending::<
                Result<Vec<u8>, std::convert::Infallible>,
            >()),
        )
            .into_response();
    }
    data.into_response()
}
async fn fixture() -> (Transfers, Arc<Fixture>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Fixture::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .fallback(any(provider))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        Transfers {
            origin_override: Some(origin),
            ..Transfers::default()
        },
        state,
        server,
    )
}
#[tokio::test]
async fn http_roundtrip_preserves_files_on_every_failure() {
    let dir = tempfile::tempdir().unwrap();
    let p = enabled(dir.path());
    let fs_gate = Arc::new(Mutex::new(()));
    let (t, state, server) = fixture().await;
    let source = dir.path().join("source.bin");
    let dest = dir.path().join("sub/received.bin");
    let data = (0..100000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    fs::write(&source, &data).unwrap();
    let receive = t
        .call(&p, "prepare_file_transfer", json!({}), fs_gate.clone())
        .await
        .unwrap();
    let id = receive["receiveId"].as_str().unwrap();
    let sent = t
        .call(
            &p,
            "send_file_transfer",
            json!({"sourcePath":source,"recipientPublicKey":receive["recipientPublicKey"]}),
            fs_gate.clone(),
        )
        .await
        .unwrap();
    assert_ne!(*state.data.lock().unwrap(), data);
    let args = json!({"receiveId":id,"transferToken":sent["transferToken"],"destinationPath":dest});
    for mode in [2, 3, 4, 5, 6] {
        state.mode.store(mode, Ordering::SeqCst);
        let before = state.requests.load(Ordering::SeqCst);
        let error = t
            .call(&p, "receive_file_transfer", args.clone(), fs_gate.clone())
            .await
            .unwrap_err()
            .to_string();
        let expected = match mode {
            2 | 5 => "provider body exceeds byte limit",
            3 => "503",
            4 => "ciphertext size mismatch",
            6 => "missing download link",
            _ => unreachable!(),
        };
        assert!(error.contains(expected), "mode {mode}: {error}");
        if mode == 6 {
            assert_eq!(
                state.requests.load(Ordering::SeqCst),
                before + 1,
                "redirect must never be followed"
            );
        }
        assert!(!dest.exists());
        assert!(t.keys.lock().unwrap().contains_key(id));
    }
    state.mode.store(0, Ordering::SeqCst);
    let mut token = Envelope::decode(sent["transferToken"].as_str().unwrap()).unwrap();
    let mut tag = fixed::<16>(&token.file_tag).unwrap();
    tag[0] ^= 1;
    token.file_tag = b64(&tag);
    let mut bad = args.clone();
    bad["transferToken"] = json!(token.encode().unwrap());
    assert!(
        t.call(&p, "receive_file_transfer", bad, fs_gate.clone())
            .await
            .is_err()
    );
    assert!(!dest.exists());
    let mut bad = args.clone();
    bad["overwrite"] = json!("true");
    let before = state.requests.load(Ordering::SeqCst);
    assert!(
        t.call(&p, "receive_file_transfer", bad, fs_gate.clone())
            .await
            .is_err()
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), before);
    let result = t
        .call(&p, "receive_file_transfer", args.clone(), fs_gate.clone())
        .await
        .unwrap();
    assert_eq!(result["verified"], true);
    assert_eq!(fs::read(&dest).unwrap(), data);
    assert!(!t.keys.lock().unwrap().contains_key(id));
    assert!(
        t.call(&p, "receive_file_transfer", args, fs_gate.clone())
            .await
            .is_err()
    );
    let r = t.prepare(&json!({})).unwrap();
    let sent = t
        .call(
            &p,
            "send_file_transfer",
            json!({"sourcePath":source,"recipientPublicKey":r["recipientPublicKey"]}),
            fs_gate.clone(),
        )
        .await
        .unwrap();
    let args = json!({"receiveId":r["receiveId"],"transferToken":sent["transferToken"],"destinationPath":dest});
    fs::write(&dest, b"original").unwrap();
    let before = state.requests.load(Ordering::SeqCst);
    assert!(
        t.call(&p, "receive_file_transfer", args.clone(), fs_gate.clone())
            .await
            .is_err()
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), before);
    assert_eq!(fs::read(&dest).unwrap(), b"original");
    let mut overwrite = args;
    overwrite["overwrite"] = json!(true);
    let mut bad = overwrite.clone();
    let mut env = Envelope::decode(sent["transferToken"].as_str().unwrap()).unwrap();
    env.sha256 = "0".repeat(64);
    bad["transferToken"] = json!(env.encode().unwrap());
    assert!(
        t.call(&p, "receive_file_transfer", bad, fs_gate.clone())
            .await
            .is_err()
    );
    assert_eq!(fs::read(&dest).unwrap(), b"original");
    t.call(&p, "receive_file_transfer", overwrite, fs_gate.clone())
        .await
        .unwrap();
    assert_eq!(fs::read(&dest).unwrap(), data);
    // Sparse oversize source is refused without uploading; out-of-root source is refused too.
    let large = dir.path().join("large");
    fs::File::create(&large)
        .unwrap()
        .set_len(MAX_BYTES as u64 + 1)
        .unwrap();
    let before = state.requests.load(Ordering::SeqCst);
    assert!(
        t.call(
            &p,
            "send_file_transfer",
            json!({"sourcePath":large,"recipientPublicKey":r["recipientPublicKey"]}),
            fs_gate.clone()
        )
        .await
        .is_err()
    );
    assert_eq!(state.requests.load(Ordering::SeqCst), before);
    assert!(t.call(&p,"send_file_transfer",json!({"sourcePath":dir.path().parent().unwrap().join("outside"),"recipientPublicKey":r["recipientPublicKey"]}),fs_gate.clone()).await.is_err());
    assert!(
        !fs::read_dir(dest.parent().unwrap()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".tmp"))
    );
    server.abort();
    let _ = server.await;
}
#[tokio::test]
async fn cancelled_read_still_holds_the_transfer_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let p = enabled(dir.path());
    let path = dir.path().join("data");
    fs::write(&path, b"test").unwrap();
    let t = Arc::new(Transfers::default());
    let fs_gate = Arc::new(Mutex::new(()));
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let held = fs_gate.clone();
    let blocker = std::thread::spawn(move || {
        let _lock = held.lock().unwrap();
        ready_tx.send(()).unwrap();
        let _ = release_rx.recv();
    });
    ready_rx.await.unwrap();
    let args = json!({"sourcePath":path,"recipientPublicKey":public_b64(&StaticSecret::random())});
    let owned = t.clone();
    let policy = p.clone();
    let gate = fs_gate.clone();
    let task =
        tokio::spawn(async move { owned.call(&policy, "send_file_transfer", args, gate).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while t.gate.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        t.call(&p, "prepare_file_transfer", json!({}), fs_gate.clone())
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    blocker.join().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while t.gate.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    t.prepare(&json!({})).unwrap();
}
#[tokio::test]
async fn cancelled_commit_consumes_key_inside_the_blocking_commit() {
    let dir = tempfile::tempdir().unwrap();
    let p = enabled(dir.path());
    let fs_gate = Arc::new(Mutex::new(()));
    let (mut t, state, server) = fixture().await;
    let r = t.prepare(&json!({})).unwrap();
    let id = r["receiveId"].as_str().unwrap().to_owned();
    let secret = t.keys.lock().unwrap().get(&id).unwrap().secret.clone();
    let (e, c) = envelope(b"cancelled but committed", &secret);
    *state.data.lock().unwrap() = c;
    let ready = Arc::new(tokio::sync::Notify::new());
    t.commit_ready = Some(ready.clone());
    let t = Arc::new(t);
    let destination = dir.path().join("committed.bin");
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let held = fs_gate.clone();
    let blocker = std::thread::spawn(move || {
        let _guard = held.lock().unwrap();
        locked_tx.send(()).unwrap();
        let _ = release_rx.recv();
    });
    locked_rx.await.unwrap();
    let args =
        json!({"receiveId":id,"transferToken":e.encode().unwrap(),"destinationPath":destination});
    let owned = t.clone();
    let policy = p.clone();
    let gate = fs_gate.clone();
    let call_args = args.clone();
    let task = tokio::spawn(async move {
        owned
            .call(&policy, "receive_file_transfer", call_args, gate)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), ready.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(t.gate.available_permits(), 0);
    assert!(!destination.exists());
    release_tx.send(()).unwrap();
    blocker.join().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while t.gate.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"cancelled but committed");
    assert!(!t.keys.lock().unwrap().contains_key(&id));
    assert!(
        t.call(&p, "receive_file_transfer", args, fs_gate.clone())
            .await
            .is_err()
    );
    server.abort();
    let _ = server.await;
}
#[tokio::test]
#[ignore = "requires Node 24+ and FERROC_UPSTREAM pointing to the pinned checkout"]
async fn original_node_brcx1_interop() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let root = std::env::var("FERROC_UPSTREAM").expect("set FERROC_UPSTREAM");
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/transfer-oracle.mjs");
    let dir = tempfile::tempdir().unwrap();
    let mut child = tokio::process::Command::new("node")
        .args([script.to_str().unwrap(), &root])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    async fn ask(
        input: &mut tokio::process::ChildStdin,
        output: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        v: Value,
    ) -> Value {
        input.write_all(format!("{v}\n").as_bytes()).await.unwrap();
        let line = tokio::time::timeout(Duration::from_secs(10), output.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert!(v.get("error").is_none(), "oracle error: {v}");
        v
    }
    let identity = ask(&mut input, &mut output, json!({"action":"identity"})).await;
    eprintln!("Pinned original Node oracle identity: {identity}");
    let (t, state, server) = fixture().await;
    let policy = enabled(dir.path());
    let fs_gate = Arc::new(Mutex::new(()));
    for data in [
        Vec::new(),
        b"interop\0\xff data".to_vec(),
        (0..1048576).map(|i| (i % 251) as u8).collect(),
    ] {
        let source = dir.path().join(format!("source-{}", data.len()));
        fs::write(&source, &data).unwrap();
        let n = ask(&mut input, &mut output, json!({"action":"prepare"})).await;
        let sent = t
            .call(
                &policy,
                "send_file_transfer",
                json!({"sourcePath":source,"recipientPublicKey":n["recipientPublicKey"]}),
                fs_gate.clone(),
            )
            .await
            .unwrap();
        let cipher = state.data.lock().unwrap().clone();
        let dest = dir.path().join(format!("node-{}", data.len()));
        let v=ask(&mut input,&mut output,json!({"action":"receive","id":n["receiveId"],"token":sent["transferToken"],"path":dest,"ciphertext":b64(&cipher)})).await;
        assert_eq!(v["size"], data.len());
        assert_eq!(fs::read(&dest).unwrap(), data);
        let r = t.prepare(&json!({})).unwrap();
        let sent = ask(
            &mut input,
            &mut output,
            json!({"action":"send","path":source,"recipient":r["recipientPublicKey"]}),
        )
        .await;
        *state.data.lock().unwrap() = STANDARD
            .decode(sent["ciphertext"].as_str().unwrap())
            .unwrap();
        let dest = dir.path().join(format!("rust-{}", data.len()));
        t.call(&policy,"receive_file_transfer",json!({"receiveId":r["receiveId"],"transferToken":sent["transferToken"],"destinationPath":dest}),fs_gate.clone()).await.unwrap();
        assert_eq!(fs::read(&dest).unwrap(), data);
    }
    server.abort();
    let _ = server.await;
    ask(&mut input, &mut output, json!({"action":"stop"})).await;
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
