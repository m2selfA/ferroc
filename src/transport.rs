use crate::{
    protocol::{MAX_FRAME, RelayMessage, VERSION},
    runtime::{Runtime, tools},
};
use anyhow::{Context, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashSet, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc,
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_tungstenite::tungstenite::{Message, protocol::WebSocketConfig};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub relay_url: String,
    pub device_id: String,
    pub device_token: String,
    pub name: String,
    pub paired_at: String,
}

pub fn relay_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input)?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "relay URL must not contain credentials, query or fragment"
    );
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "use HTTPS except for loopback development"
    );
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url)
}
pub fn websocket_url(input: &str) -> Result<Url> {
    let mut url = relay_url(input)?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("invalid WS scheme"))?;
    if !url.path().ends_with("/ws") {
        url.set_path(&format!("{}/ws", url.path().trim_end_matches('/')));
    }
    Ok(url)
}
async fn post(
    client: &reqwest::Client,
    url: String,
    body: Value,
) -> Result<(reqwest::StatusCode, Value)> {
    let res = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(crate::network::http_error)?;
    let status = res.status();
    ensure!(
        res.content_length()
            .is_none_or(|len| len <= MAX_FRAME as u64),
        "pairing response too large"
    );
    let mut res = res;
    let mut bytes = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(crate::network::http_error)? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_FRAME,
            "pairing response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok((
        status,
        serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid pairing response (HTTP {status})"))?,
    ))
}
pub async fn save_credentials(path: &Path, creds: &Credentials) -> Result<()> {
    let parent = path.parent().context("credential directory")?;
    tokio::fs::create_dir_all(parent).await?;
    ensure!(
        !path.try_exists()?,
        "credential file already exists; use a different --home"
    );
    let temp = parent.join(format!(".device-{}.tmp", uuid::Uuid::new_v4()));
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&temp).await?;
    #[cfg(windows)]
    {
        // Restrict the empty temporary file BEFORE any secret is written.
        let identity = timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("whoami.exe")
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        ensure!(
            identity.status.success(),
            "unable to determine Windows credential owner"
        );
        let user = String::from_utf8(identity.stdout)?.trim().to_owned();
        let status = timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("icacls.exe")
                .arg(&temp)
                .args(["/inheritance:r", "/grant:r", &format!("{user}:F")])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await??;
        ensure!(
            status.success(),
            "unable to restrict credential ACL; refusing to save token"
        );
    }
    file.write_all(&serde_json::to_vec_pretty(creds)?).await?;
    file.sync_all().await?;
    drop(file);
    // Windows rename cannot replace an existing file atomically. Do not delete it and expose a gap.
    ensure!(
        !path.try_exists()?,
        "credential file already exists; preserve it and use a different --home for pairing"
    );
    // Atomic create-without-replacement; retains private ACL/mode and refuses a raced destination.
    tokio::fs::hard_link(&temp, path).await?;
    Ok(())
}
pub async fn load_credentials(path: &Path) -> Result<Option<Credentials>> {
    match tokio::fs::metadata(path).await {
        Ok(m) => {
            ensure!(
                m.is_file() && m.len() <= MAX_FRAME as u64,
                "invalid credential file"
            );
            Ok(Some(serde_json::from_slice(&tokio::fs::read(path).await?)?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
pub async fn pair(input: &str, name: &str, path: &Path) -> Result<Credentials> {
    pair_with_network(input, name, path, &crate::network::Network::default()).await
}
pub async fn pair_with_network(
    input: &str,
    name: &str,
    path: &Path,
    network: &crate::network::Network,
) -> Result<Credentials> {
    let base = relay_url(input)?
        .to_string()
        .trim_end_matches('/')
        .to_owned();
    let client = network.client(Some(Duration::from_secs(15)))?;
    let (status, start) = post(
        &client,
        format!("{base}/device/start"),
        json!({"client_name":name}),
    )
    .await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "relay rejected pairing start: {status}"
    );
    let code = start["device_code"]
        .as_str()
        .context("missing device_code")?;
    let user_code = start["user_code"].as_str().context("missing user_code")?;
    let uri = start["verification_uri"]
        .as_str()
        .context("missing verification_uri")?;
    // Print only user-facing verification URI/code, never the secret polling code/token.
    eprintln!("Pair device: {uri}\nCode: {user_code}");
    let expires = start["expires_in"].as_u64().context("missing expires_in")?;
    ensure!((1..=3600).contains(&expires), "invalid pairing expiry");
    let deadline = Instant::now() + Duration::from_secs(expires);
    let mut interval = start["interval"].as_u64().unwrap_or(5).clamp(2, 60);
    let device_id = uuid::Uuid::new_v4().to_string();
    loop {
        ensure!(Instant::now() < deadline, "pairing expired");
        tokio::time::sleep_until((Instant::now() + Duration::from_secs(interval)).min(deadline))
            .await;
        ensure!(Instant::now() < deadline, "pairing expired");
        let (status,poll)=timeout(deadline.saturating_duration_since(Instant::now()),post(&client,format!("{base}/device/poll"),json!({"device_code":code,"device_id":device_id,"name":name,"platform":format!("{}/{}",std::env::consts::OS,std::env::consts::ARCH)}))).await.context("pairing expired")??;
        if status.is_success()
            && let (Some(token), Some(id)) =
                (poll["device_token"].as_str(), poll["device_id"].as_str())
        {
            let creds = Credentials {
                relay_url: base,
                device_id: id.to_owned(),
                device_token: token.to_owned(),
                name: name.to_owned(),
                paired_at: format!(
                    "unix:{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs()
                ),
            };
            save_credentials(path, &creds).await?;
            return Ok(creds);
        }
        match poll["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval = (interval + 5).min(120),
            Some("access_denied") => bail!("pairing denied"),
            Some("expired_token") => bail!("pairing expired"),
            _ => bail!("pairing failed (HTTP {status})"),
        }
    }
}
pub fn hello(creds: &Credentials) -> Value {
    let platform = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        s => s,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        s => s,
    };
    json!({"type":"hello","protocol":VERSION,"device":{"deviceId":creds.device_id,"name":creds.name,"platform":platform,"arch":arch,
        "hostname":std::env::var("COMPUTERNAME").or_else(|_|std::env::var("HOSTNAME")).unwrap_or_else(|_|"ferroc-host".into()),
        "agentVersion":env!("CARGO_PKG_VERSION"),"coreVersion":concat!("ferroc-",env!("CARGO_PKG_VERSION"))},"tools":tools()})
}

async fn session(runtime: Arc<Runtime>, creds: &Credentials) -> Result<bool> {
    let url = websocket_url(&creds.relay_url)?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME));
    let Some(mut ws) = runtime
        .policy
        .network
        .websocket(url, &creds.device_token, config)
        .await?
    else {
        return Ok(false);
    };
    timeout(
        Duration::from_secs(5),
        ws.send(Message::Text(hello(creds).to_string().into())),
    )
    .await??;
    let (tx, mut rx) = mpsc::channel::<Value>(8);
    let mut calls = JoinSet::new();
    let mut seen = HashSet::new();
    let mut welcomed = false;
    let mut deadline = Instant::now() + Duration::from_secs(15);
    loop {
        tokio::select! {
            _=tokio::time::sleep_until(deadline)=>bail!("relay heartbeat/welcome timeout"),
            result=calls.join_next(),if !calls.is_empty()=>{result.context("call task missing")??;},
            Some(value)=rx.recv()=>{
                let text=value.to_string();
                let text=if text.len()>MAX_FRAME {json!({"type":"result","id":value["id"],"error":{"code":"OUTPUT_LIMIT","message":"Response exceeds 1 MiB; operation may have completed; request smaller pages"}}).to_string()}else{text};
                timeout(Duration::from_secs(5),ws.send(Message::Text(text.into()))).await??;
            },
            message=ws.next()=>{
                let message=message.context("relay disconnected")??;
                let msg=match message {
                    Message::Text(t)=>serde_json::from_str::<RelayMessage>(&t).context("malformed relay frame")?,
                    Message::Ping(data)=>{timeout(Duration::from_secs(5),ws.send(Message::Pong(data))).await??;continue;},
                    Message::Pong(_)=>continue,
                    Message::Close(c)=>{if c.is_some_and(|c|matches!(u16::from(c.code),4401|4403)){return Ok(false);}bail!("relay closed connection");},
                    _=>bail!("unexpected non-text relay frame"),
                };
                match msg {
                    RelayMessage::Welcome {protocol}=>{ensure!(!welcomed && protocol==VERSION,"invalid relay protocol/welcome");welcomed=true;deadline=Instant::now()+Duration::from_secs(45);},
                    RelayMessage::Ping {ts}=>{
                        ensure!(welcomed,"ping before welcome");deadline=Instant::now()+Duration::from_secs(45);
                        timeout(Duration::from_secs(5),ws.send(Message::Text(json!({"type":"pong","ts":ts}).to_string().into()))).await??;
                    },
                    RelayMessage::Error {code,message,fatal}=>{eprintln!("relay error {code}: {message}");if fatal{return Ok(false);}},
                    RelayMessage::Call {id,tool,args,timeout_ms}=>{
                        ensure!(welcomed,"call before welcome");ensure!(id.len()<=128 && !id.is_empty(),"invalid call id");
                        ensure!(seen.len()<10000 && seen.insert(id.clone()),"duplicate call id or connection call limit reached");
                        if calls.len()>=4 || timeout_ms.is_some_and(|t|t==0 || t>120_000) {
                            let result=json!({"type":"result","id":id,"error":{"code":"BUSY_OR_INVALID_DEADLINE","message":"At most 4 in-flight calls; timeoutMs must be 1..120000"}});
                            timeout(Duration::from_secs(5),ws.send(Message::Text(result.to_string().into()))).await??;continue;
                        }
                        let runtime=runtime.clone();let tx=tx.clone();
                        calls.spawn(async move {
                            let result=timeout(Duration::from_millis(timeout_ms.unwrap_or(120_000)),runtime.call(&tool,args)).await;
                            let value=match result {Ok(result)=>json!({"type":"result","id":id,"result":result}),Err(_)=>json!({"type":"result","id":id,"error":{"code":"CALL_TIMEOUT","message":"Observation deadline exceeded; admitted operations may still have effects; inspect state before retrying"}})};
                            let _=tx.send(value).await;
                        });
                    },
                }
            }
        }
    }
}
pub async fn run(runtime: Arc<Runtime>, creds: &Credentials, once: bool) -> Result<()> {
    let mut backoff = 1;
    loop {
        let started = Instant::now();
        match session(runtime.clone(), creds).await {
            Ok(false) => bail!(
                "relay rejected/revoked credentials or sent fatal error; no automatic re-pairing; use a new --home and explicitly pair"
            ),
            Ok(true) => return Ok(()),
            Err(e) if once => return Err(e),
            Err(e) => eprintln!("relay connection lost: {e}; reconnecting in {backoff}s"),
        }
        // Do not leave a shell mutation running and then advertise a fresh connection/session.
        runtime.processes.shutdown().await;
        if started.elapsed() > Duration::from_secs(60) {
            backoff = 1;
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}
