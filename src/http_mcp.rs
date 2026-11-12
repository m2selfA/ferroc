//! Authenticated, loopback-only Streamable HTTP MCP; no relay/OAuth service is started.
//! JSON responses only (GET deliberately returns 405). Session deletion/pause is NOT
//! cancellation: already admitted operations finish, and may have side effects.
use crate::{protocol::MAX_FRAME, runtime::Runtime, stdio::Mcp};
use anyhow::{Result, ensure};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequest, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

const SESSION: &str = "mcp-session-id";
const VERSION: &str = "mcp-protocol-version";
const TTL: Duration = Duration::from_secs(1800);
const MAX_SESSIONS: usize = 64;
const MAX_CALLS: usize = 4;
const VERSIONS: [&str; 2] = ["2025-03-26", "2025-06-18"];

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Clone)]
pub struct HttpMcp(Arc<Inner>);
struct Inner {
    runtime: Arc<Runtime>,
    authority: String,
    origin: String,
    bearer: String,
    control: Mutex<Control>,
    bodies: Semaphore,
    idle: tokio::sync::Notify,
}
#[derive(Default)]
struct Control {
    paused: bool,
    closing: bool,
    sessions: HashMap<String, Session>,
    active: usize,
    accepted: u64,
    last_tool: String,
}
struct Session {
    mcp: Mcp,
    version: String,
    ready: bool,
    seen: Instant,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HttpSnapshot {
    pub paused: bool,
    pub closing: bool,
    pub sessions: usize,
    pub active: usize,
    pub accepted: u64,
    pub last_tool: String,
}
struct Admission(HttpMcp);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.0.control.lock().expect("HTTP control").active -= 1;
        self.0.0.idle.notify_waiters();
    }
}
fn prune(control: &mut Control) {
    control.sessions.retain(|_, s| s.seen.elapsed() < TTL);
}
fn fail(status: StatusCode, id: Value, code: i64, message: &str) -> Response {
    let mut response = (
        status,
        axum::Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
// Allocate only rejection responses; keep successful gate Results small.
fn gate_fail(status: StatusCode, id: Value, code: i64, message: &str) -> Box<Response> {
    Box::new(fail(status, id, code, message))
}
fn unavailable(message: &str) -> Response {
    let mut response = fail(
        StatusCode::SERVICE_UNAVAILABLE,
        Value::Null,
        -32000,
        message,
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}
fn bounded_json(value: Value) -> Response {
    let encoded = serde_json::to_vec(&value).expect("JSON response");
    let mut response = if encoded.len() > MAX_FRAME {
        fail(
            StatusCode::OK,
            value["id"].clone(),
            -32000,
            "Response exceeds 1 MiB; operation may have completed. Request smaller pages.",
        )
    } else {
        ([(header::CONTENT_TYPE, "application/json")], encoded).into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
fn id_valid(id: &Value) -> bool {
    id.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 128)
        || id.as_i64().is_some()
        || id.as_u64().is_some()
}
impl HttpMcp {
    /// `bound` must be the actual listener address, including its assigned port.
    /// Secrets are deliberately neither Debug nor Serialize and never enter snapshots.
    pub fn new(runtime: Arc<Runtime>, bound: SocketAddr, token: String) -> Result<Self> {
        ensure!(
            bound.ip().is_loopback() && bound.port() != 0,
            "HTTP MCP requires a bound loopback address"
        );
        ensure!(
            token.len() >= 32
                && token.len() <= 256
                && token
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
            "invalid HTTP bearer token"
        );
        Ok(Self(Arc::new(Inner {
            runtime,
            authority: bound.to_string(),
            origin: format!("http://{bound}"),
            bearer: format!("Bearer {token}"),
            control: Mutex::new(Control::default()),
            bodies: Semaphore::new(16),
            idle: tokio::sync::Notify::new(),
        })))
    }
    pub fn router(&self) -> Router {
        Router::new()
            .route("/mcp", any(endpoint))
            .layer(DefaultBodyLimit::max(MAX_FRAME))
            .with_state(self.clone())
    }
    pub fn set_paused(&self, paused: bool) {
        self.0.control.lock().expect("HTTP control").paused = paused;
    }
    /// Stops admissions and invalidates sessions; owner must gracefully drain the
    /// HTTP server BEFORE Runtime::shutdown. No claim of rollback/cancellation.
    pub fn close(&self) {
        let mut control = self.0.control.lock().expect("HTTP control");
        control.closing = true;
        control.sessions.clear();
    }
    pub async fn wait_idle(&self) {
        loop {
            let changed = self.0.idle.notified();
            if self.0.control.lock().expect("HTTP control").active == 0 {
                return;
            }
            changed.await;
        }
    }
    pub fn snapshot(&self) -> HttpSnapshot {
        let mut control = self.0.control.lock().expect("HTTP control");
        prune(&mut control);
        HttpSnapshot {
            paused: control.paused,
            closing: control.closing,
            sessions: control.sessions.len(),
            active: control.active,
            accepted: control.accepted,
            last_tool: control.last_tool.clone(),
        }
    }
    fn guard(&self, headers: &HeaderMap) -> Result<(), Box<Response>> {
        for name in [
            "host",
            "authorization",
            "origin",
            SESSION,
            VERSION,
            "content-type",
        ] {
            if headers.get_all(name).iter().count() > 1 {
                return Err(gate_fail(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32600,
                    "Duplicate security header",
                ));
            }
        }
        if headers.get(header::HOST).and_then(|h| h.to_str().ok())
            != Some(self.0.authority.as_str())
        {
            return Err(gate_fail(
                StatusCode::FORBIDDEN,
                Value::Null,
                -32000,
                "Host not allowed",
            ));
        }
        if headers
            .get(header::ORIGIN)
            .is_some_and(|h| h.to_str().ok() != Some(self.0.origin.as_str()))
        {
            return Err(gate_fail(
                StatusCode::FORBIDDEN,
                Value::Null,
                -32000,
                "Origin not allowed",
            ));
        }
        let authorized = headers
            .get(header::AUTHORIZATION)
            .map(|h| h.as_bytes().ct_eq(self.0.bearer.as_bytes()).into())
            .unwrap_or(false);
        if !authorized {
            let mut response = gate_fail(
                StatusCode::UNAUTHORIZED,
                Value::Null,
                -32000,
                "Bearer token required",
            );
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"ferroc-local\""),
            );
            return Err(response);
        }
        Ok(())
    }
    fn session(&self, headers: &HeaderMap, id: &Value) -> Result<Mcp, Box<Response>> {
        let Some(key) = headers.get(SESSION).and_then(|h| h.to_str().ok()) else {
            return Err(gate_fail(
                StatusCode::BAD_REQUEST,
                id.clone(),
                -32000,
                "Mcp-Session-Id required; initialize first",
            ));
        };
        let mut control = self.0.control.lock().expect("HTTP control");
        prune(&mut control);
        let Some(session) = control.sessions.get_mut(key) else {
            return Err(gate_fail(
                StatusCode::NOT_FOUND,
                id.clone(),
                -32000,
                "Session expired or unknown; initialize again",
            ));
        };
        let version = headers
            .get(VERSION)
            .map(|h| h.to_str().unwrap_or(""))
            .unwrap_or("2025-03-26");
        if !VERSIONS.contains(&version) || version != session.version {
            return Err(gate_fail(
                StatusCode::BAD_REQUEST,
                id.clone(),
                -32600,
                "Unsupported or mismatched MCP-Protocol-Version",
            ));
        }
        session.seen = Instant::now();
        Ok(session.mcp.clone())
    }
}
async fn endpoint(State(server): State<HttpMcp>, request: Request) -> Response {
    if let Err(response) = server.guard(request.headers()) {
        return *response;
    }
    if request.method() == Method::GET || request.method() == Method::HEAD {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST, DELETE"));
        return response; // JSON-only transport, not an SSE stream.
    }
    if request.method() == Method::DELETE {
        if let Err(response) = server.session(request.headers(), &Value::Null) {
            return *response;
        }
        let key = request.headers()[SESSION]
            .to_str()
            .expect("validated session");
        server
            .0
            .control
            .lock()
            .expect("HTTP control")
            .sessions
            .remove(key);
        return StatusCode::NO_CONTENT.into_response();
    }
    if request.method() != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    {
        let c = server.0.control.lock().expect("HTTP control");
        if c.closing {
            return unavailable("Server is stopping; admitted operations may still finish");
        }
        if c.paused {
            return unavailable("HTTP MCP is paused; admitted operations may still finish");
        }
    }
    let accepts = request
        .headers()
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|s| {
            s.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .collect::<Vec<_>>();
    if !["application/json", "text/event-stream"]
        .iter()
        .all(|v| accepts.iter().any(|s| s == v))
    {
        return fail(
            StatusCode::NOT_ACCEPTABLE,
            Value::Null,
            -32600,
            "Accept must include application/json and text/event-stream",
        );
    }
    if !request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|s| {
            s.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
    {
        return fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Value::Null,
            -32600,
            "Content-Type must be application/json",
        );
    }
    let headers = request.headers().clone();
    let Ok(_body_slot) = server.0.bodies.try_acquire() else {
        return unavailable("Too many request bodies");
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(5),
        Bytes::from_request(request, &server),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(rejection)) => return rejection.into_response(),
        Err(_) => {
            return fail(
                StatusCode::REQUEST_TIMEOUT,
                Value::Null,
                -32600,
                "Request body timeout; no tool was admitted",
            );
        }
    };
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, Value::Null, -32700, "Parse error"),
    };
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let response_envelope = value.is_object()
        && value["jsonrpc"] == "2.0"
        && value.get("method").is_none()
        && value.get("id").is_some_and(id_valid)
        && (value.get("result").is_some() ^ value.get("error").is_some());
    let request_envelope = value.is_object()
        && value["jsonrpc"] == "2.0"
        && value["method"]
            .as_str()
            .is_some_and(|m| !m.is_empty() && m.len() <= 128)
        && value.get("id").is_none_or(id_valid)
        && value.get("params").is_none_or(Value::is_object)
        && value.get("result").is_none()
        && value.get("error").is_none();
    if !response_envelope && !request_envelope {
        return fail(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Invalid JSON-RPC envelope (batch unsupported)",
        );
    }
    let initialize = value["method"] == "initialize";
    let mut mcp = if initialize {
        if value.get("id").is_none() || headers.contains_key(SESSION) {
            return fail(
                StatusCode::BAD_REQUEST,
                id,
                -32600,
                "Initialize must be a request without an existing session",
            );
        }
        Mcp::default()
    } else {
        match server.session(&headers, &id) {
            Ok(mcp) => mcp,
            Err(r) => return *r,
        }
    };
    if !initialize {
        let key = headers[SESSION].to_str().expect("validated session");
        let mut c = server.0.control.lock().expect("HTTP control");
        let Some(s) = c.sessions.get_mut(key) else {
            return fail(
                StatusCode::NOT_FOUND,
                id,
                -32000,
                "Session deleted before admission",
            );
        };
        if value["method"] == "notifications/initialized" && value.get("id").is_none() {
            s.ready = true;
            return StatusCode::ACCEPTED.into_response();
        }
        if !s.ready {
            return fail(
                StatusCode::BAD_REQUEST,
                id,
                -32000,
                "Send notifications/initialized first",
            );
        }
    }
    if response_envelope || value.get("id").is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let admission = {
        let mut c = server.0.control.lock().expect("HTTP control");
        if c.closing || c.paused {
            return unavailable("HTTP MCP is stopping or paused; no tool was admitted");
        }
        if c.active >= MAX_CALLS {
            return unavailable("At most four in-flight MCP requests; no tool was admitted");
        }
        c.active += 1;
        c.accepted += 1;
        if let Some(name) = value["params"]["name"].as_str() {
            c.last_tool = name.chars().take(128).filter(|c| !c.is_control()).collect();
        }
        Admission(server.clone())
    };
    drop(_body_slot);
    // Detach *execution* from connection lifetime. Dropping the HTTP observer must
    // not cancel an admitted operation; wait_idle() drains these owned workers.
    tokio::spawn(async move {
        let _admission = admission;
        let mut result = mcp
            .handle(&server.0.runtime, value)
            .await
            .expect("validated request has an id");
        if initialize && result.get("error").is_none() {
            let version = result["result"]["protocolVersion"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            if !VERSIONS.contains(&version.as_str()) {
                // stdio also supports 2024-11-05; HTTP must negotiate a HTTP-capable version.
                result["result"]["protocolVersion"] = json!("2025-06-18");
            }
            result["result"]["serverInfo"]["name"] = json!("ferroc-gui");
            let version = result["result"]["protocolVersion"]
                .as_str()
                .expect("version")
                .to_owned();
            let key = uuid::Uuid::new_v4().to_string();
            {
                let mut c = server.0.control.lock().expect("HTTP control");
                prune(&mut c);
                if c.closing {
                    return unavailable("HTTP MCP stopped during initialization");
                }
                if c.sessions.len() >= MAX_SESSIONS {
                    return unavailable("Session limit reached; delete unused sessions");
                }
                c.sessions.insert(
                    key.clone(),
                    Session {
                        mcp,
                        version,
                        ready: false,
                        seen: Instant::now(),
                    },
                );
            }
            let mut response = bounded_json(result);
            response
                .headers_mut()
                .insert(SESSION, HeaderValue::from_str(&key).expect("UUID header"));
            return response;
        }
        bounded_json(result)
    })
    .await
    .unwrap_or_else(|_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            Value::Null,
            -32603,
            "MCP worker failed; inspect state before retrying",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Policy;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnect_pause_and_shutdown_do_not_cancel_an_admitted_file_write() {
        let root = tempfile::tempdir().unwrap();
        let runtime = Arc::new(Runtime::new(
            Policy::new(vec![root.path().into()], false).unwrap(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = random_token();
        let server = HttpMcp::new(runtime.clone(), address, token.clone()).unwrap();
        let router = server.router();
        let (stop, rx) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = format!("http://{address}/mcp");
        let post = |v: Value| {
            client
                .post(&url)
                .bearer_auth(&token)
                .header("accept", "application/json, text/event-stream")
                .header(VERSION, "2025-06-18")
                .json(&v)
        };
        let initialized = post(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})).send().await.unwrap();
        let session = initialized.headers()[SESSION].to_str().unwrap().to_owned();
        assert_eq!(
            post(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .header(SESSION, &session)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
        // Test-only Rust accessor holds the real filesystem gate. There is no
        // release/runtime bypass, fake tool implementation or timing-only oracle.
        let gate = runtime.test_fs_gate();
        let (release, hold) = std::sync::mpsc::channel::<()>();
        let (held, acquired) = tokio::sync::oneshot::channel();
        let blocker = std::thread::spawn(move || {
            let _lock = gate.lock().unwrap();
            let _ = held.send(());
            let _ = hold.recv();
        });
        acquired.await.unwrap();
        let file = root.path().join("admitted.txt");
        let call = post(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":file,"content":"must finish"}}})).header(SESSION, &session);
        let observer = tokio::spawn(async move { call.send().await });
        tokio::time::timeout(Duration::from_secs(3), async {
            while server.snapshot().active != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let mut observers = vec![observer];
        for id in 3..6 {
            let call = post(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"write_file","arguments":{"path":file,"content":"must finish"}}})).header(SESSION, &session);
            observers.push(tokio::spawn(async move { call.send().await }));
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while server.snapshot().active != 4 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            post(json!({"jsonrpc":"2.0","id":6,"method":"tools/list"}))
                .header(SESSION, &session)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        for observer in observers {
            observer.abort();
        }
        server.set_paused(true);
        server.close();
        assert!(!file.exists());
        assert!(
            tokio::time::timeout(Duration::from_millis(40), server.wait_idle())
                .await
                .is_err()
        );
        assert_eq!(server.snapshot().active, 4);
        release.send(()).unwrap();
        blocker.join().unwrap();
        tokio::time::timeout(Duration::from_secs(3), server.wait_idle())
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "must finish");
        assert_eq!(server.snapshot().active, 0);
        let _ = stop.send(());
        serving.await.unwrap();
        runtime.shutdown().await;
    }
    #[test]
    fn expired_sessions_are_pruned_without_dropping_fresh_sessions() {
        let mut c = Control::default();
        c.sessions.insert(
            "expired".into(),
            Session {
                mcp: Mcp::default(),
                version: "2025-06-18".into(),
                ready: false,
                seen: Instant::now() - TTL,
            },
        );
        c.sessions.insert(
            "fresh".into(),
            Session {
                mcp: Mcp::default(),
                version: "2025-06-18".into(),
                ready: true,
                seen: Instant::now(),
            },
        );
        prune(&mut c);
        assert_eq!(c.sessions.len(), 1);
        assert!(c.sessions.contains_key("fresh"));
        assert_eq!(MAX_CALLS, 4);
        assert_eq!(MAX_SESSIONS, 64);
    }
}
