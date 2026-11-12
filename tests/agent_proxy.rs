#[path = "support/proxy.rs"]
mod proxy;
use futures_util::{SinkExt, StreamExt};
use proxy::{Kind, ProxyFixture, Stream};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    task::{JoinHandle, JoinSet},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
struct Origin {
    address: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    config: Arc<Mutex<Option<Value>>>,
    task: JoinHandle<()>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Origin {
    async fn start(tls: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let config = Arc::new(Mutex::new(None));
        let r = requests.clone();
        let c = config.clone();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    next=listener.accept()=>{let (socket,_)=next.unwrap();let r=r.clone();let c=c.clone();children.spawn(async move{let stream:Stream=if tls{let Ok(s)=proxy::tls_acceptor().accept(socket).await else{return;};Box::new(s)}else{Box::new(socket)};let _=origin_request(stream,r,c).await;});},
                    _=children.join_next(),if !children.is_empty()=>{}
                }
            }
        });
        Self {
            address,
            requests,
            config,
            task,
        }
    }
    fn url(&self, tls: bool, host: &str) -> String {
        format!(
            "{}://{host}:{}",
            if tls { "https" } else { "http" },
            self.address.port()
        )
    }
}
async fn origin_request(
    mut stream: Stream,
    requests: Arc<AtomicUsize>,
    config: Arc<Mutex<Option<Value>>>,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    let bytes = proxy::head(&mut *stream).await?;
    let text = std::str::from_utf8(&bytes)?;
    requests.fetch_add(1, Ordering::SeqCst);
    ensure!(
        proxy::header(text, "proxy-authorization").is_none(),
        "proxy auth leaked to origin"
    );
    let length = proxy::header(text, "content-length")
        .unwrap_or("0")
        .parse::<usize>()?;
    ensure!(length <= 8192, "fixture body limit");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    let path = text.split_whitespace().nth(1).unwrap_or("");
    if path == "/device/start" {
        return proxy::reply(&mut stream,"200 OK",&json!({"device_code":"fixture-poll","user_code":"TEST-CODE","verification_uri":"https://relay.invalid/device/verify","expires_in":30,"interval":2}).to_string()).await;
    }
    if path == "/device/poll" {
        return proxy::reply(
            &mut stream,
            "200 OK",
            &json!({"device_id":"proxy-fixture","device_token":"synthetic-relay-token"})
                .to_string(),
        )
        .await;
    }
    ensure!(path == "/ws", "unexpected origin path");
    ensure!(
        proxy::header(text, "authorization") == Some("Bearer synthetic-relay-token"),
        "relay auth missing"
    );
    ensure!(
        proxy::header(text, "x-brc-protocol") == Some("1"),
        "BRC header missing"
    );
    let accept = derive_accept_key(proxy::header(text, "sec-websocket-key").unwrap().as_bytes());
    stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
    let mut ws =
        WebSocketStream::from_raw_socket(stream, Role::Server, Some(WebSocketConfig::default()))
            .await;
    let hello: Value = serde_json::from_str(ws.next().await.unwrap()?.to_text()?)?;
    ensure!(
        hello["type"] == "hello" && hello["tools"].as_array().unwrap().len() == 25,
        "wrong hello"
    );
    ws.send(Message::Text(
        json!({"type":"welcome","protocol":1}).to_string().into(),
    ))
    .await?;
    ws.send(Message::Text(
        json!({"type":"call","id":"proxy-policy","tool":"get_config","args":{}})
            .to_string()
            .into(),
    ))
    .await?;
    let result: Value = serde_json::from_str(ws.next().await.unwrap()?.to_text()?)?;
    let policy: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap())?;
    *config.lock().unwrap() = Some(policy);
    ws.send(Message::Text(json!({"type":"error","code":"FIXTURE_DONE","message":"controlled test shutdown","fatal":true}).to_string().into())).await?;
    Ok(())
}
fn command(home: &std::path::Path, url: &str, ca: bool) -> Command {
    let binary = std::env::var_os("FERROC_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_ferroc").into());
    let mut c = Command::new(binary);
    c.current_dir(home)
        .args(["agent", "--once", "--relay", url, "--home"])
        .arg(home)
        .kill_on_drop(true);
    for name in [
        "FERROC_PROXY",
        "FERROC_CA_CERT",
        "FERROC_TOKEN",
        "FERROC_DEVICE_ID",
        "FERROC_RELAY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        c.env_remove(name);
    }
    if ca {
        c.arg("--ca-cert").arg(proxy::ca_file());
    }
    c
}
async fn output(c: Command) -> std::process::Output {
    let mut c = c;
    tokio::time::timeout(Duration::from_secs(25), c.output())
        .await
        .expect("agent proxy process deadline")
        .unwrap()
}
fn safe(output: &std::process::Output) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains(proxy::PASSWORD), "proxy secret leaked");
    assert!(!text.contains(proxy::USER), "proxy username leaked");
    use base64::Engine;
    for password in [
        proxy::PASSWORD.to_owned(),
        format!("wrong-{}", proxy::PASSWORD),
    ] {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{password}", proxy::USER));
        assert!(!text.contains(&encoded), "encoded proxy credential leaked");
    }
}
#[tokio::test]
async fn actual_agent_pairing_and_rpc_over_authenticated_proxy_matrix() {
    for (kind, scheme, tls, host) in [
        (Kind::Http, "http", false, "127.0.0.1"),
        (Kind::Http, "http", true, "relay.invalid"),
        (Kind::Https, "https", true, "relay.invalid"),
        (Kind::Https, "https", false, "127.0.0.1"),
        (Kind::Socks, "socks5", true, "localhost"),
        (Kind::Socks, "socks5h", true, "relay.invalid"),
    ] {
        let origin = Origin::start(tls).await;
        let proxy = ProxyFixture::start(kind, origin.address, true).await;
        let dir = tempfile::tempdir().unwrap();
        let mut c = command(dir.path(), &origin.url(tls, host), true);
        c.env("FERROC_PROXY", proxy.url(scheme, true))
            .env("NO_PROXY", "*");
        let out = output(c).await;
        safe(&out);
        let policy = origin.config.lock().unwrap().clone().unwrap_or_else(|| {
            panic!(
                "{scheme} route failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        assert_eq!(policy["outboundNetwork"]["mode"], "explicit");
        assert_eq!(policy["outboundNetwork"]["scheme"], scheme);
        assert_eq!(policy["outboundNetwork"]["authenticationConfigured"], true);
        assert!(proxy.count() >= 3);
        assert!(origin.requests.load(Ordering::SeqCst) >= 3);
        let saved = std::fs::read_to_string(dir.path().join("device.json")).unwrap();
        assert!(
            !saved.contains(proxy::PASSWORD) && !saved.contains("outboundNetwork"),
            "proxy config must not be persisted with credentials"
        );
        if scheme == "socks5h" {
            assert!(
                proxy
                    .records
                    .socks_types
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|t| *t == 3)
            );
            assert!(
                proxy
                    .records
                    .targets
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|s| s.starts_with("relay.invalid:"))
            );
        }
        if scheme == "socks5" {
            assert!(
                proxy
                    .records
                    .socks_types
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|t| matches!(t, 1 | 4))
            );
        }
    }
}
#[tokio::test]
async fn actual_agent_environment_no_proxy_and_cli_precedence() {
    for mode in [
        "environment",
        "https-env",
        "all-env",
        "bypass",
        "ip-bypass",
        "domain-bypass",
        "direct",
        "cli",
    ] {
        let tls = mode == "https-env";
        let origin = Origin::start(tls).await;
        let proxy = ProxyFixture::start(Kind::Http, origin.address, false).await;
        let dir = tempfile::tempdir().unwrap();
        let host = if tls {
            "relay.invalid"
        } else if mode == "domain-bypass" {
            "localhost"
        } else {
            "127.0.0.1"
        };
        let mut c = command(dir.path(), &origin.url(tls, host), tls);
        c.env("HTTP_PROXY", proxy.url("http", false));
        match mode {
            "https-env" => {
                c.env("HTTPS_PROXY", proxy.url("http", false));
            }
            "all-env" => {
                c.env_remove("HTTP_PROXY")
                    .env("ALL_PROXY", proxy.url("http", false));
            }
            "bypass" => {
                c.env("NO_PROXY", "*");
            }
            "ip-bypass" => {
                c.env("NO_PROXY", "127.0.0.0/8");
            }
            "domain-bypass" => {
                c.env("NO_PROXY", ".localhost");
            }
            "direct" => {
                c.env("FERROC_PROXY", "invalid-secret-value")
                    .arg("--no-proxy");
            }
            "cli" => {
                c.env("FERROC_PROXY", "invalid-secret-value")
                    .env("NO_PROXY", "*")
                    .arg("--proxy")
                    .arg(proxy.url("http", false));
            }
            _ => {}
        }
        let out = output(c).await;
        safe(&out);
        let policy = origin
            .config
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| panic!("{mode}: {}", String::from_utf8_lossy(&out.stderr)));
        assert_eq!(
            policy["outboundNetwork"]["mode"],
            if mode == "direct" {
                "direct"
            } else if mode == "cli" {
                "explicit"
            } else {
                "environment"
            }
        );
        eprintln!(
            "proxy precedence probe: mode={mode}, proxy_connections={}",
            proxy.count()
        );
        if matches!(mode, "direct" | "bypass" | "ip-bypass" | "domain-bypass") {
            assert_eq!(proxy.count(), 0);
        } else {
            assert!(proxy.count() >= 3);
        }
    }
}
#[tokio::test]
async fn rejected_proxy_auth_never_falls_back_or_saves_credentials() {
    let origin = Origin::start(false).await;
    let proxy = ProxyFixture::start(Kind::Http, origin.address, true).await;
    let dir = tempfile::tempdir().unwrap();
    let mut c = command(dir.path(), &origin.url(false, "127.0.0.1"), false);
    c.env(
        "FERROC_PROXY",
        format!(
            "http://fixture-user:wrong-{}@{}",
            proxy::PASSWORD,
            proxy.address
        ),
    );
    let out = output(c).await;
    safe(&out);
    assert!(!out.status.success());
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    assert!(!dir.path().join("device.json").exists());
    eprintln!(
        "proxy rejection stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("407"));
}
#[tokio::test]
async fn tls_trust_and_hostname_validation_remain_enabled() {
    for (kind, host, ca) in [
        (Kind::Http, "relay.invalid", false),
        (Kind::Http, "unlisted.invalid", true),
        (Kind::Https, "relay.invalid", false),
    ] {
        let origin = Origin::start(true).await;
        let proxy = ProxyFixture::start(kind, origin.address, false).await;
        let dir = tempfile::tempdir().unwrap();
        let mut c = command(dir.path(), &origin.url(true, host), ca);
        c.env(
            "FERROC_PROXY",
            proxy.url(
                if matches!(kind, Kind::Https) {
                    "https"
                } else {
                    "http"
                },
                false,
            ),
        );
        let out = output(c).await;
        safe(&out);
        assert!(!out.status.success());
        assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
        if matches!(kind, Kind::Https) {
            assert_eq!(proxy.count(), 0);
        } else {
            assert!(proxy.count() >= 1);
        }
        assert!(!dir.path().join("device.json").exists());
    }
}
#[tokio::test]
async fn malformed_proxy_and_conflicting_flags_fail_without_echoing_values() {
    // Independently exercise failed pairing and failed WS startup. The origin stays reachable
    // directly, so any silent fallback would be observed and fail this control.
    for paired in [false, true] {
        let reserve = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unreachable = reserve.local_addr().unwrap();
        drop(reserve);
        let origin = Origin::start(false).await;
        let dir = tempfile::tempdir().unwrap();
        let mut c = command(dir.path(), &origin.url(false, "127.0.0.1"), false);
        c.arg("--proxy").arg(format!(
            "http://{}:{}@{unreachable}",
            proxy::USER,
            proxy::PASSWORD
        ));
        if paired {
            c.args([
                "--token",
                "synthetic-relay-token",
                "--device-id",
                "proxy-fixture",
            ]);
        }
        let out = output(c).await;
        safe(&out);
        assert!(!out.status.success());
        assert_eq!(
            origin.requests.load(Ordering::SeqCst),
            0,
            "unreachable proxy must NOT fall back directly for pairing or WS"
        );
        assert!(!dir.path().join("device.json").exists());
        assert!(String::from_utf8_lossy(&out.stderr).contains("connection/proxy/DNS/TLS failure"));
        eprintln!("unreachable proxy control: credentials_supplied={paired}, origin_requests=0");
    }
    for conflict in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut c = command(dir.path(), "http://127.0.0.1:1", false);
        c.arg("--proxy").arg(format!(
            "ftp://fixture-user:{}@127.0.0.1:9",
            proxy::PASSWORD
        ));
        if conflict {
            c.arg("--no-proxy");
        }
        let out = output(c).await;
        safe(&out);
        assert!(!out.status.success());
        assert!(!dir.path().join("device.json").exists());
    }
}
#[tokio::test]
async fn malformed_upgrade_responses_are_rejected_before_framing() {
    for mode in [
        "accept",
        "duplicate",
        "extension",
        "subprotocol",
        "connection",
        "redirect",
        "proxy-auth",
        "unauthorized",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let h = proxy::head(&mut socket).await.unwrap();
            let text = std::str::from_utf8(&h).unwrap();
            let key =
                derive_accept_key(proxy::header(text, "sec-websocket-key").unwrap().as_bytes());
            let status = match mode {
                "redirect" => "302 Found",
                "proxy-auth" => "407 Proxy Authentication Required",
                "unauthorized" => "401 Unauthorized",
                _ => "101 Switching Protocols",
            };
            let extra = match mode {
                "extension" => "Sec-WebSocket-Extensions: permessage-deflate\r\n".to_owned(),
                "subprotocol" => "Sec-WebSocket-Protocol: unsolicited\r\n".to_owned(),
                "duplicate" => format!("Sec-WebSocket-Accept: {key}\r\n"),
                "redirect" => "Location: http://127.0.0.1:1/\r\n".to_owned(),
                _ => String::new(),
            };
            let accept = if mode == "accept" {
                proxy::PASSWORD
            } else {
                &key
            };
            let connection = if mode == "connection" {
                "close"
            } else {
                "Upgrade"
            };
            let _=socket.write_all(format!("HTTP/1.1 {status}\r\nUpgrade: websocket\r\nConnection: {connection}\r\nSec-WebSocket-Accept: {accept}\r\n{extra}Content-Length: 0\r\n\r\n").as_bytes()).await;
        });
        let result = ferroc::network::Network::direct()
            .websocket(
                reqwest::Url::parse(&format!("ws://127.0.0.1:{port}/ws")).unwrap(),
                "synthetic-token",
                WebSocketConfig::default(),
            )
            .await;
        if mode == "unauthorized" {
            assert!(result.unwrap().is_none());
        } else {
            let error = result.expect_err("must reject handshake");
            assert!(!format!("{error:#}").contains(proxy::PASSWORD));
        }
        task.await.unwrap();
    }
}
#[tokio::test]
async fn stalled_upgrade_has_a_total_fifteen_second_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        proxy::head(&mut socket).await.unwrap();
        let mut byte = [0];
        let n = tokio::time::timeout(Duration::from_secs(20), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "timed-out client must close stalled stream");
    });
    let result = ferroc::network::Network::direct()
        .websocket(
            reqwest::Url::parse(&format!("ws://127.0.0.1:{port}/ws")).unwrap(),
            "synthetic-token",
            WebSocketConfig::default(),
        )
        .await;
    assert!(result.unwrap_err().to_string().contains("15s"));
    task.await.unwrap();
}
