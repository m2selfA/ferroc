//! Native Rust relay: bounded WS routing, SQLite, device pairing and remote MCP.
//! Browser/OAuth handlers live in relay_auth; no upstream Node code is imported.
use crate::{
    protocol::{MAX_FRAME, ToolDefinition, ToolResult},
    store::{Store, now},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::SinkExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout},
};
use uuid::Uuid;

pub(crate) fn random() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
pub(crate) fn hash(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
pub(crate) fn escaped(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub(crate) fn value_str<'a>(v: &'a Value, k: &str) -> WebResult<&'a str> {
    v[k].as_str()
        .ok_or_else(|| ApiError::bad("invalid_request"))
}
pub(crate) fn require(ok: bool, code: &'static str) -> WebResult<()> {
    if ok { Ok(()) } else { Err(ApiError::bad(code)) }
}
#[derive(Debug)]
pub(crate) struct ApiError(pub StatusCode, pub &'static str);
impl ApiError {
    pub(crate) fn bad(s: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, s)
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(_: anyhow::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
pub(crate) type WebResult<T> = std::result::Result<T, ApiError>;
#[derive(Clone)]
struct Connected {
    generation: String,
    tools: Vec<ToolDefinition>,
    tx: mpsc::Sender<Outbound>,
}
enum Outbound {
    Frame(Value),
    Close,
}
struct Pending {
    device: String,
    generation: String,
    tx: oneshot::Sender<ToolResult>,
}
struct PendingLease<'a> {
    table: &'a Mutex<HashMap<String, Pending>>,
    id: String,
}
impl Drop for PendingLease<'_> {
    fn drop(&mut self) {
        self.table.lock().expect("pending lock").remove(&self.id);
    }
}
pub struct Relay {
    pub(crate) store: Store,
    pub(crate) origin: String,
    pub(crate) password_hash: String,
    pub(crate) login_gate: tokio::sync::Mutex<(u32, i64)>,
    devices: Mutex<HashMap<String, Connected>>,
    pending: Mutex<HashMap<String, Pending>>,
}
impl Relay {
    pub fn new(db: &Path, public_url: &str, password: &str) -> Result<Arc<Self>> {
        let url = crate::transport::relay_url(public_url)?;
        ensure!(
            url.path() == "/" || url.path().is_empty(),
            "native relay public URL must be an origin, without a path prefix"
        );
        ensure!(
            password.len() >= 16 && password.len() <= 1024,
            "admin password must be 16..1024 bytes"
        );
        use scrypt::{
            Scrypt,
            password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
        };
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Scrypt
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("password hashing failed"))?
            .to_string();
        Ok(Arc::new(Self {
            store: Store::open(db)?,
            origin: url.to_string().trim_end_matches('/').to_owned(),
            password_hash,
            login_gate: tokio::sync::Mutex::new((0, 0)),
            devices: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }))
    }
    pub fn router(self: Arc<Self>) -> Router {
        let router = Router::new()
            .route("/health", get(health))
            .route(
                "/favicon.ico",
                get(|| async { ([("content-type", "image/x-icon")], crate::icons::ICO) }),
            )
            .route(
                "/icon.png",
                get(|| async { ([("content-type", "image/png")], crate::icons::PNG_32) }),
            )
            .route("/ws", get(upgrade))
            .route("/device/start", post(pair_start))
            .route("/device/poll", post(pair_poll))
            .route("/mcp", post(mcp));
        let secure = self.origin.starts_with("https:");
        let metadata_url = format!("{}/.well-known/oauth-protected-resource/mcp", self.origin);
        crate::relay_auth::routes(router)
            .layer(DefaultBodyLimit::max(MAX_FRAME))
            .with_state(self)
            .layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let metadata_url = metadata_url.clone();
                    async move {
                        let is_mcp = req.uri().path() == "/mcp";
                        let mut res = next.run(req).await;
                        if secure {
                            res.headers_mut().insert(
                                "strict-transport-security",
                                "max-age=31536000".parse().expect("header"),
                            );
                        }
                        if is_mcp && res.status() == StatusCode::UNAUTHORIZED {
                            res.headers_mut().insert(
                                "www-authenticate",
                                format!("Bearer resource_metadata=\"{metadata_url}\"")
                                    .parse()
                                    .expect("metadata header"),
                            );
                        }
                        for (k, v) in [
                            ("x-content-type-options", "nosniff"),
                            ("x-frame-options", "DENY"),
                            ("referrer-policy", "no-referrer"),
                            ("cache-control", "no-store"),
                        ] {
                            res.headers_mut().insert(
                                axum::http::HeaderName::from_static(k),
                                axum::http::HeaderValue::from_static(v),
                            );
                        }
                        res
                    }
                },
            ))
    }
    pub fn disconnect_all(&self) {
        for d in self.devices.lock().expect("devices lock").values() {
            let _ = d.tx.try_send(Outbound::Close);
        }
    }
    pub(crate) fn disconnect(&self, id: &str) {
        if let Some(d) = self.devices.lock().expect("devices lock").remove(id) {
            let _ = d.tx.try_send(Outbound::Close);
        }
    }
    pub(crate) fn listed_devices(&self) -> Result<Value> {
        let records = self.store.list("device")?;
        let live = self.devices.lock().expect("devices lock");
        Ok(json!(
            records
                .into_iter()
                .map(|(id, mut v)| {
                    v.as_object_mut()
                        .expect("device object")
                        .remove("tokenHash");
                    v["deviceId"] = json!(id);
                    v["online"] =
                        json!(live.contains_key(v["deviceId"].as_str().unwrap_or_default()));
                    v
                })
                .collect::<Vec<_>>()
        ))
    }
    async fn invoke(&self, client: &str, name: &str, mut args: Value) -> ToolResult {
        if !args.is_object() || name.len() > 128 {
            return ToolResult::error("invalid tool call");
        }
        let requested = args.as_object_mut().expect("args").remove("deviceId");
        let selected = {
            let devices = self.devices.lock().expect("devices lock");
            match requested {
                Some(Value::String(id)) => devices.get(&id).cloned().map(|d| (id, d)),
                None if devices.len() == 1 => {
                    devices.iter().next().map(|(id, d)| (id.clone(), d.clone()))
                }
                _ => None,
            }
        };
        let Some((device, d)) = selected else {
            return ToolResult::error(
                "No unambiguous online device; specify deviceId from list_devices",
            );
        };
        match self.store.get("device", &device) {
            Ok(Some(v)) if v["paused"] != true => {}
            _ => return ToolResult::error("device paused or revoked"),
        };
        if !d.tools.iter().any(|t| t.name == name) {
            return ToolResult::error("unknown tool on selected device");
        }
        let id = random();
        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.pending.lock().expect("pending lock");
            if p.len() >= 256 {
                return ToolResult::error("relay call capacity exceeded");
            }
            p.insert(
                id.clone(),
                Pending {
                    device: device.clone(),
                    generation: d.generation,
                    tx,
                },
            );
        }
        let _lease = PendingLease {
            table: &self.pending,
            id: id.clone(),
        };
        let start = Instant::now();
        let sent=timeout(Duration::from_secs(5),d.tx.send(Outbound::Frame(json!({"type":"call","id":id,"tool":name,"args":args,"timeoutMs":120000,"client":{"name":client}})))).await;
        let result = if matches!(sent, Ok(Ok(()))) {
            match timeout(Duration::from_secs(120), rx).await {
                Ok(Ok(r)) => r,
                _ => ToolResult::error(
                    "call disconnected or timed out; operation may already have effects",
                ),
            }
        } else {
            ToolResult::error("device connection unavailable")
        };
        self.pending.lock().expect("pending lock").remove(&id);
        if self
            .store
            .audit(
                &device,
                client,
                name,
                &hash(&args.to_string()),
                result.is_error != Some(true),
                start.elapsed().as_millis() as i64,
            )
            .is_err()
        {
            return ToolResult::error("audit persistence failed; operation may have completed");
        }
        result
    }
}
async fn health(State(s): State<Arc<Relay>>) -> Json<Value> {
    Json(
        json!({"status":"ok","name":"ferroc","version":env!("CARGO_PKG_VERSION"),"devices":s.devices.lock().expect("devices lock").len()}),
    )
}
async fn pair_start(State(s): State<Arc<Relay>>, Json(v): Json<Value>) -> WebResult<Json<Value>> {
    let name = v
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("ferroc");
    require(name.len() <= 80, "invalid_request")?;
    let code = random();
    let user = Uuid::new_v4().simple().to_string()[..8].to_uppercase();
    let user = format!("{}-{}", &user[..4], &user[4..]);
    s.store.put(
        "pair",
        &hash(&code),
        &json!({"name":name,"user_code":user,"approved":false,"denied":false}),
        900,
    )?;
    Ok(Json(
        json!({"device_code":code,"user_code":user,"verification_uri":format!("{}/device/verify",s.origin),"verification_uri_complete":format!("{}/device/verify?user_code={user}",s.origin),"expires_in":900,"interval":5}),
    ))
}
async fn pair_poll(State(s): State<Arc<Relay>>, Json(v): Json<Value>) -> WebResult<Json<Value>> {
    let code = value_str(&v, "device_code")?;
    let key = hash(code);
    let row = s
        .store
        .get("pair", &key)?
        .ok_or_else(|| ApiError::bad("expired_token"))?;
    if row["denied"] == true {
        s.store.delete("pair", &key)?;
        return Err(ApiError::bad("access_denied"));
    }
    if row["approved"] != true {
        return Err(ApiError::bad("authorization_pending"));
    }
    let id = value_str(&v, "device_id")?;
    require(!id.is_empty() && id.len() <= 128, "invalid_request")?;
    require(s.store.get("device", id)?.is_none(), "device_id_exists")?;
    let name = v.get("name").and_then(Value::as_str).unwrap_or("ferroc");
    require(name.len() <= 80, "invalid_request")?;
    require(s.store.take("pair", &key)?.is_some(), "expired_token")?;
    let token = random();
    let token_hash = hash(&token);
    s.store.insert_new(
        "device",
        id,
        &json!({"name":name,"platform":v.get("platform"),"tokenHash":token_hash,"paused":false}),
        10 * 365 * 86400,
    )?;
    s.store.put(
        "device_token",
        &token_hash,
        &json!({"deviceId":id}),
        10 * 365 * 86400,
    )?;
    Ok(Json(
        json!({"device_token":token,"device_id":id,"token_type":"bearer"}),
    ))
}
pub(crate) fn bearer(h: &HeaderMap) -> WebResult<&str> {
    h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| s.len() <= 256 && !s.is_empty())
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))
}
async fn upgrade(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> WebResult<Response> {
    let token = bearer(&h)?;
    let row = s
        .store
        .get("device_token", &hash(token))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let id = value_str(&row, "deviceId")?.to_owned();
    require(s.store.get("device", &id)?.is_some(), "invalid_token")?;
    Ok(ws
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |ws| socket(s, id, ws))
        .into_response())
}
async fn send(ws: &mut WebSocket, v: Value) -> Result<()> {
    timeout(
        Duration::from_secs(5),
        ws.send(Message::Text(v.to_string().into())),
    )
    .await??;
    Ok(())
}
async fn socket(s: Arc<Relay>, id: String, mut ws: WebSocket) {
    let generation = random();
    let run=async {
        let msg=timeout(Duration::from_secs(15),ws.recv()).await?.context("no hello")??;
        let Message::Text(text)=msg else{anyhow::bail!("hello must be text");};let hello:Value=serde_json::from_str(&text)?;
        ensure!(hello["type"]=="hello" && hello["protocol"]==1 && hello["device"]["deviceId"]==id,"hello identity/protocol mismatch");
        let tools:Vec<ToolDefinition>=serde_json::from_value(hello["tools"].clone())?;
        ensure!(tools.len()<=256,"too many tools");let mut names=HashSet::new();
        for t in &tools{ensure!(!t.name.is_empty() && t.name.len()<=128 && names.insert(t.name.clone()) && t.input_schema.is_object(),"invalid tool definition");}
        let(tx,mut rx)=mpsc::channel(32);
        {let mut live=s.devices.lock().expect("devices lock");ensure!(live.len()<1024 || live.contains_key(&id),"device limit");if let Some(old)=live.insert(id.clone(),Connected{generation:generation.clone(),tools,tx}){let _=old.tx.try_send(Outbound::Close);}}
        send(&mut ws,json!({"type":"welcome","protocol":1,"relayVersion":env!("CARGO_PKG_VERSION"),"serverTime":now()*1000})).await?;
        let mut heartbeat=tokio::time::interval(Duration::from_secs(20));let mut seen=Instant::now();
        loop{
            tokio::select!{
                _=heartbeat.tick()=>{ensure!(seen.elapsed()<Duration::from_secs(45),"stale agent");ensure!(s.store.get("device",&id)?.is_some(),"revoked");send(&mut ws,json!({"type":"ping","ts":now()*1000})).await?;},
                msg=rx.recv()=>match msg{Some(Outbound::Frame(v))=>send(&mut ws,v).await?,_=>{let _=ws.send(Message::Close(Some(axum::extract::ws::CloseFrame{code:4401,reason:"device revoked or connection replaced".into()}))).await;break;}},
                msg=ws.recv()=>{
                    let msg=msg.context("closed")??;
                    match msg{
                        Message::Text(text)=>{
                            let v:Value=serde_json::from_str(&text)?;
                            ensure!(s.devices.lock().expect("devices lock").get(&id).is_some_and(|d|d.generation==generation),"stale socket");
                            match v["type"].as_str(){
                                Some("pong")=>{ensure!(v["ts"].is_u64(),"invalid pong");seen=Instant::now();},
                                Some("result")=>{
                                    let call_id=v["id"].as_str().context("invalid result id")?;
                                    let mut pending=s.pending.lock().expect("pending lock");
                                    if pending.get(call_id).is_some_and(|p|p.device==id && p.generation==generation){
                                        let p=pending.remove(call_id).expect("pending");
                                        let result=if !v["error"].is_null(){ToolResult::error("agent reported a transport error")}else{serde_json::from_value(v["result"].clone())?};
                                        let _=p.tx.send(result);
                                    }
                                },
                                _=>anyhow::bail!("unexpected agent message"),
                            }
                        },
                        Message::Ping(p)=>{timeout(Duration::from_secs(5),ws.send(Message::Pong(p))).await??;},
                        Message::Pong(_)=>{},Message::Close(_)=>break,_=>anyhow::bail!("unexpected binary frame"),
                    }
                },
            }
        }
        Ok::<_,anyhow::Error>(())
    }.await;
    if run.is_err() {
        let _ = timeout(Duration::from_secs(2), ws.close()).await;
    }
    {
        let mut live = s.devices.lock().expect("devices lock");
        if live.get(&id).is_some_and(|d| d.generation == generation) {
            live.remove(&id);
        }
    }
    let mut pending = s.pending.lock().expect("pending lock");
    pending.retain(|_, p| p.device != id || p.generation != generation);
}
async fn mcp(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> WebResult<Response> {
    if let Some(origin) = h.get(axum::http::header::ORIGIN)
        && origin.to_str().ok() != Some(s.origin.as_str())
    {
        return Err(ApiError(StatusCode::FORBIDDEN, "origin_mismatch"));
    }
    let token = bearer(&h)?;
    let row = s
        .store
        .get("access", &hash(token))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let client = value_str(&row, "client_id")?;
    require(s.store.get("client", client)?.is_some(), "invalid_client")?;
    require(
        row["resource"] == format!("{}/mcp", s.origin),
        "invalid_target",
    )?;
    let valid_id = v
        .get("id")
        .is_none_or(|id| id.is_string() || id.is_i64() || id.is_u64());
    if v["jsonrpc"] != "2.0"
        || !v["method"].is_string()
        || !valid_id
        || v.get("params").is_some_and(|p| !p.is_object())
    {
        return Ok(Json(
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}),
        )
        .into_response());
    }
    let Some(id) = v.get("id") else {
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    let result = match v["method"].as_str().unwrap_or_default() {
        "initialize" => {
            json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"ferroc-relay","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        "tools/list" => {
            let mut all = vec![
                json!({"name":"list_devices","description":"List paired device status and IDs","inputSchema":{"type":"object","properties":{}}}),
            ];
            let mut names = HashSet::new();
            let snapshots: Vec<_> = s
                .devices
                .lock()
                .expect("devices lock")
                .iter()
                .map(|(id, d)| (id.clone(), d.clone()))
                .collect();
            for (device, d) in snapshots {
                if s.store
                    .get("device", &device)?
                    .is_some_and(|v| v["paused"] != true)
                {
                    for mut t in d.tools {
                        if names.insert(t.name.clone()) {
                            if let Some(props) = t
                                .input_schema
                                .get_mut("properties")
                                .and_then(Value::as_object_mut)
                            {
                                props.insert("deviceId".into(),json!({"type":"string","description":"Target paired device ID"}));
                            }
                            all.push(serde_json::to_value(t).map_err(anyhow::Error::from)?);
                        }
                    }
                }
            }
            json!({"tools":all})
        }
        "tools/call" => {
            let name = value_str(&v["params"], "name")?;
            let args = v["params"].get("arguments").cloned().unwrap_or(json!({}));
            if name == "list_devices" {
                serde_json::to_value(ToolResult::json(json!({"devices":s.listed_devices()?})))
                    .map_err(anyhow::Error::from)?
            } else {
                serde_json::to_value(s.invoke(client, name, args).await)
                    .map_err(anyhow::Error::from)?
            }
        }
        _ => return Ok(Json(
            json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}}),
        )
        .into_response()),
    };
    let result = json!({"jsonrpc":"2.0","id":id,"result":result});
    if result.to_string().len() > MAX_FRAME {
        return Ok(Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"Response too large; operation may have effects; request smaller pages"}})).into_response());
    }
    Ok(Json(result).into_response())
}
