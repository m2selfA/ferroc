use ferroc::{
    config::Policy,
    http_mcp::{HttpMcp, random_token},
    runtime::Runtime,
};
use reqwest::{Client, Response, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

struct Live {
    root: tempfile::TempDir,
    runtime: Arc<Runtime>,
    server: HttpMcp,
    client: Client,
    url: String,
    token: String,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}
impl Live {
    async fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let runtime = Arc::new(Runtime::new(
            Policy::new(vec![root.path().into()], false).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = random_token();
        let server = HttpMcp::new(
            runtime.clone(),
            listener.local_addr().unwrap(),
            token.clone(),
        )
        .unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let (stop, rx) = oneshot::channel();
        let router = server.router();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            root,
            runtime,
            server,
            url,
            token,
            stop,
            task,
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }
    fn request(&self, value: Value) -> reqwest::RequestBuilder {
        self.client
            .post(&self.url)
            .bearer_auth(&self.token)
            .header("accept", "application/json, text/event-stream")
            .json(&value)
    }
    async fn init(&self) -> String {
        let response = self.request(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"wire-test","version":"1"}}})).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let value: Value = response.json().await.unwrap();
        assert_eq!(value["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(value["result"]["serverInfo"]["name"], "ferroc-gui");
        let response = self
            .request(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-06-18")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(response.bytes().await.unwrap().is_empty());
        session
    }
    async fn post(&self, session: &str, value: Value) -> Response {
        self.request(value)
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-06-18")
            .send()
            .await
            .unwrap()
    }
    async fn close(self) {
        self.server.close();
        let _ = self.stop.send(());
        self.task.await.unwrap();
        self.server.wait_idle().await;
        self.runtime.shutdown().await;
    }
}
#[tokio::test]
async fn http_roundtrip_policy_pause_delete_and_secret_free_status() {
    let live = Live::start().await;
    let session = live.init().await;
    let list: Value = live
        .post(
            &session,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        list["result"]["tools"].as_array().unwrap().len(),
        ferroc::runtime::tools().len()
    );
    let file = live
        .root
        .path()
        .join("roundtrip.txt")
        .to_string_lossy()
        .into_owned();
    let write = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":file,"content":"hello HTTP MCP","mode":"rewrite"}}});
    let written: Value = live
        .post(&session, write.clone())
        .await
        .json()
        .await
        .unwrap();
    assert_ne!(written["result"]["isError"], true, "{written}");
    let read: Value = live.post(&session, json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":file}}})).await.json().await.unwrap();
    assert!(read.to_string().contains("hello HTTP MCP"));
    let denied: Value = live.post(&session, json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"start_process","arguments":{"command":"echo forbidden"}}})).await.json().await.unwrap();
    assert_eq!(denied["result"]["isError"], true);
    live.server.set_paused(true);
    assert_eq!(
        live.post(&session, write).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(live.server.snapshot().paused);
    live.server.set_paused(false);
    assert_eq!(
        live.post(&session, json!({"jsonrpc":"2.0","id":6,"method":"ping"}))
            .await
            .status(),
        StatusCode::OK
    );
    let status = serde_json::to_string(&live.server.snapshot()).unwrap();
    assert!(!status.contains(&live.token));
    assert!(!status.contains(&session));
    let deleted = live
        .client
        .delete(&live.url)
        .bearer_auth(&live.token)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        live.post(&session, json!({"jsonrpc":"2.0","id":7,"method":"ping"}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(live.server.snapshot().sessions, 0);
    live.close().await;
}
#[tokio::test]
async fn http_auth_origin_host_and_methods_cannot_mutate_files() {
    let live = Live::start().await;
    let session = live.init().await;
    let file = live.root.path().join("must-not-exist.txt");
    let write = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":file,"content":"forbidden"}}});
    for (name, value, expected) in [
        ("authorization", "Bearer bad", StatusCode::UNAUTHORIZED),
        ("origin", "https://attacker.invalid", StatusCode::FORBIDDEN),
        ("host", "attacker.invalid", StatusCode::FORBIDDEN),
        ("origin", "null", StatusCode::FORBIDDEN),
    ] {
        let mut request = live
            .request(write.clone())
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-06-18")
            .build()
            .unwrap();
        request.headers_mut().insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(value).unwrap(),
        );
        let response = live.client.execute(request).await.unwrap();
        assert_eq!(response.status(), expected, "{name}");
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        assert!(!file.exists());
    }
    assert_eq!(
        live.client.get(&live.url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let get = live
        .client
        .get(&live.url)
        .bearer_auth(&live.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(get.headers()["allow"], "POST, DELETE");
    assert_eq!(
        live.client
            .request(reqwest::Method::OPTIONS, &live.url)
            .bearer_auth(&live.token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    live.close().await;
}
#[tokio::test]
async fn http_envelope_media_session_and_version_negative_cases() {
    let live = Live::start().await;
    let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    assert_eq!(
        live.request(ping.clone()).send().await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let session = live.init().await;
    for value in [
        json!([ping.clone()]),
        json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
        json!({"jsonrpc":"1.0","id":2,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":[]}),
    ] {
        assert_eq!(
            live.post(&session, value).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        live.request(ping.clone())
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2099-01-01")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        live.request(ping.clone())
            .header("mcp-session-id", &session)
            .header("mcp-protocol-version", "2025-03-26")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut json_only = live
        .request(ping.clone())
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-06-18")
        .build()
        .unwrap();
    json_only.headers_mut().insert(
        "accept",
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    assert_eq!(
        live.client.execute(json_only).await.unwrap().status(),
        StatusCode::NOT_ACCEPTABLE
    );
    let duplicate_auth = live
        .request(ping.clone())
        .header("authorization", "Bearer duplicate")
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate_auth.status(), StatusCode::BAD_REQUEST);
    let invalid = live
        .client
        .post(&live.url)
        .bearer_auth(&live.token)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let oversized = live
        .client
        .post(&live.url)
        .bearer_auth(&live.token)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .body("x".repeat(ferroc::protocol::MAX_FRAME + 1))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let notify = live
        .post(
            &session,
            json!({"jsonrpc":"2.0","method":"notifications/unknown"}),
        )
        .await;
    assert_eq!(notify.status(), StatusCode::ACCEPTED);
    let missing: Value = live
        .post(
            &session,
            json!({"jsonrpc":"2.0","id":3,"method":"unsupported"}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(missing["error"]["code"], -32601);
    live.server.close();
    assert_eq!(
        live.post(&session, ping).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    live.close().await;
}
#[tokio::test]
async fn http_rejects_nonloopback_and_invalid_secrets() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(Runtime::new(
        Policy::new(vec![root.path().into()], false).unwrap(),
    ));
    assert!(
        HttpMcp::new(
            runtime.clone(),
            "0.0.0.0:3211".parse().unwrap(),
            random_token()
        )
        .is_err()
    );
    assert!(
        HttpMcp::new(
            runtime.clone(),
            "127.0.0.1:0".parse().unwrap(),
            random_token()
        )
        .is_err()
    );
    assert!(
        HttpMcp::new(
            runtime.clone(),
            "127.0.0.1:3211".parse().unwrap(),
            "weak".into()
        )
        .is_err()
    );
    assert!(
        HttpMcp::new(
            runtime.clone(),
            "127.0.0.1:3211".parse().unwrap(),
            "x".repeat(32) + "\r\n"
        )
        .is_err()
    );
    runtime.shutdown().await;
}
