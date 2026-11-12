use ferroc::{
    config::Policy,
    runtime::Runtime,
    transport::{self, Credentials},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::Command,
};
use tokio_tungstenite::{
    accept_async, accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{Request, Response},
    },
};

fn runtime(dir: &std::path::Path, shell: bool) -> Arc<Runtime> {
    Arc::new(Runtime::new(
        Policy::new(vec![dir.to_owned()], shell).unwrap(),
    ))
}
fn creds(port: u16) -> Credentials {
    Credentials {
        relay_url: format!("http://127.0.0.1:{port}"),
        device_id: "loopback-fixture".into(),
        device_token: "synthetic-not-real".into(),
        name: "test".into(),
        paired_at: "manual".into(),
    }
}
async fn recv(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Value {
    let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(msg.to_text().unwrap()).unwrap()
}
async fn send(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}
// tungstenite requires a concrete (large) HTTP ErrorResponse in its callback API.
#[allow(clippy::result_large_err)]
#[tokio::test]
async fn websocket_real_handshake_hello_call_and_heartbeat() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path(), false);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let c = creds(listener.local_addr().unwrap().port());
    let authorized = Arc::new(AtomicBool::new(false));
    let auth = authorized.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = accept_hdr_async(socket, move |req: &Request, res: Response| {
            auth.store(
                req.uri().path() == "/ws"
                    && req.headers()["authorization"] == "Bearer synthetic-not-real"
                    && req.headers()["x-brc-protocol"] == "1",
                Ordering::SeqCst,
            );
            Ok(res)
        })
        .await
        .unwrap();
        let hello = recv(&mut ws).await;
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["protocol"], 1);
        assert_eq!(hello["device"]["deviceId"], "loopback-fixture");
        assert_eq!(hello["tools"].as_array().unwrap().len(), 25);
        send(
            &mut ws,
            json!({"type":"welcome","protocol":1,"relayVersion":"fixture","serverTime":0}),
        )
        .await;
        send(&mut ws, json!({"type":"ping","ts":12345})).await;
        assert_eq!(recv(&mut ws).await, json!({"type":"pong","ts":12345}));
        send(
            &mut ws,
            json!({"type":"call","id":"cfg-1","tool":"get_config","args":{}}),
        )
        .await;
        let result = recv(&mut ws).await;
        assert_eq!(result["type"], "result");
        assert_eq!(result["id"], "cfg-1");
        assert!(result.get("ok").is_none());
        assert_eq!(result["result"]["content"][0]["type"], "text");
        send(
            &mut ws,
            json!({"type":"call","id":"bad-1","tool":"missing","args":{}}),
        )
        .await;
        assert_eq!(recv(&mut ws).await["result"]["isError"], true);
        send(
            &mut ws,
            json!({"type":"error","code":"TEST_STOP","message":"test complete","fatal":true}),
        )
        .await;
    });
    let result = tokio::time::timeout(Duration::from_secs(15), transport::run(r.clone(), &c, true))
        .await
        .unwrap();
    assert!(result.is_err());
    server.await.unwrap();
    assert!(authorized.load(Ordering::SeqCst));
    r.shutdown().await;
}
#[tokio::test]
async fn websocket_heartbeat_not_blocked_by_slow_tool() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path(), true);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let c = creds(listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        recv(&mut ws).await;
        send(&mut ws, json!({"type":"welcome","protocol":1})).await;
        #[cfg(windows)]
        let command = "Start-Sleep -Seconds 30";
        #[cfg(not(windows))]
        let command = "sleep 30";
        send(&mut ws,json!({"type":"call","id":"slow","tool":"start_process","args":{"command":command,"timeout_ms":1500}})).await;
        send(&mut ws, json!({"type":"ping","ts":99})).await;
        let pong = tokio::time::timeout(Duration::from_millis(500), recv(&mut ws))
            .await
            .unwrap();
        assert_eq!(pong["type"], "pong");
        let result = recv(&mut ws).await;
        assert_eq!(result["id"], "slow");
        send(
            &mut ws,
            json!({"type":"error","code":"STOP","message":"done","fatal":true}),
        )
        .await;
    });
    assert!(
        tokio::time::timeout(Duration::from_secs(15), transport::run(r.clone(), &c, true))
            .await
            .unwrap()
            .is_err()
    );
    server.await.unwrap();
    r.shutdown().await;
}
#[tokio::test]
async fn websocket_rejects_duplicate_id_without_replaying_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path(), false);
    let path = dir.path().join("append.txt");
    let p = path.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let c = creds(listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(s).await.unwrap();
        recv(&mut ws).await;
        send(&mut ws, json!({"type":"welcome","protocol":1})).await;
        let call = json!({"type":"call","id":"same","tool":"write_file","args":{"path":p,"content":"x","mode":"append"}});
        send(&mut ws, call.clone()).await;
        let result = recv(&mut ws).await;
        assert!(result["result"]["isError"].is_null());
        send(&mut ws, call).await;
    });
    let result = tokio::time::timeout(Duration::from_secs(10), transport::run(r.clone(), &c, true))
        .await
        .unwrap()
        .unwrap_err();
    assert!(result.to_string().contains("duplicate"));
    server.await.unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap(), "x");
    r.shutdown().await;
}
#[tokio::test]
async fn websocket_refuses_calls_before_welcome_and_protocol_mismatch() {
    for msg in [
        json!({"type":"welcome","protocol":99}),
        json!({"type":"call","id":"bad","tool":"get_config","args":{}}),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let r = runtime(dir.path(), false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = creds(listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(s).await.unwrap();
            recv(&mut ws).await;
            send(&mut ws, msg).await;
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(5), transport::run(r.clone(), &c, true))
                .await
                .unwrap()
                .is_err()
        );
        server.await.unwrap();
        r.shutdown().await;
    }
}
#[tokio::test]
async fn websocket_unauthorized_does_not_retry_or_pair() {
    let dir = tempfile::tempdir().unwrap();
    let r = runtime(dir.path(), false);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let c = creds(listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0; 4096];
        let _ = s.read(&mut buf).await.unwrap();
        s.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let error = tokio::time::timeout(Duration::from_secs(5), transport::run(r.clone(), &c, false))
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("rejected/revoked"));
    server.await.unwrap();
    r.shutdown().await;
}

async fn http_json(listener: &TcpListener, expected: &str, response: Value) -> Value {
    let (socket, _) = listener.accept().await.unwrap();
    let mut socket = BufReader::new(socket);
    let mut first = String::new();
    socket.read_line(&mut first).await.unwrap();
    assert!(first.starts_with(&format!("POST {expected} ")));
    let mut length = 0;
    loop {
        let mut line = String::new();
        socket.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse::<usize>().unwrap();
        }
    }
    assert!(length < 4096);
    let mut body = vec![0; length];
    socket.read_exact(&mut body).await.unwrap();
    let text = response.to_string();
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",text.len()).as_bytes()).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}
#[tokio::test]
async fn pairing_http_roundtrip_persists_only_approved_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.json");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server_base = base.clone();
    let server = tokio::spawn(async move {
        let start=http_json(&listener,"/device/start",json!({"device_code":"secret-poll-code","user_code":"ABCD-EFGH","verification_uri":format!("{server_base}/device/verify"),"expires_in":20,"interval":2})).await;
        assert_eq!(start["client_name"], "Rust probe");
        let poll = http_json(
            &listener,
            "/device/poll",
            json!({"device_token":"synthetic-approved-token","device_id":"approved-id"}),
        )
        .await;
        assert_eq!(poll["device_code"], "secret-poll-code");
        assert_eq!(poll["name"], "Rust probe");
    });
    let c = tokio::time::timeout(
        Duration::from_secs(10),
        transport::pair(&base, "Rust probe", &path),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(c.device_id, "approved-id");
    assert_eq!(
        transport::load_credentials(&path)
            .await
            .unwrap()
            .unwrap()
            .device_token,
        "synthetic-approved-token"
    );
    server.await.unwrap();
}
#[tokio::test]
async fn pairing_denial_does_not_write_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.json");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        http_json(&listener,"/device/start",json!({"device_code":"test","user_code":"TEST","verification_uri":"http://localhost/device/verify","expires_in":10,"interval":2})).await;
        http_json(&listener, "/device/poll", json!({"error":"access_denied"})).await;
    });
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        transport::pair(&base, "test", &path),
    )
    .await
    .unwrap()
    .err()
    .expect("pairing must be denied");
    assert!(error.to_string().contains("denied"));
    assert!(!path.exists());
    server.await.unwrap();
}
#[tokio::test]
async fn actual_binary_stdio_roundtrip_is_clean_jsonrpc() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .current_dir(dir.path())
        .arg("stdio")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let file = dir.path().join("stdio.txt");
    let messages = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":file,"content":"native stdio"}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":file}}}),
    ];
    for msg in messages {
        input
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
    }
    drop(input);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    let replies: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[2]["id"], 3);
    let read: Value =
        serde_json::from_str(replies[2]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(read["text"], "native stdio");
    assert_eq!(std::fs::read_to_string(file).unwrap(), "native stdio");
}
