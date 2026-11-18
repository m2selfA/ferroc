use crate::{
    protocol::{MAX_FRAME, RelayMessage, VERSION},
    runtime::{Runtime, tools},
};
use anyhow::{Context, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(feature = "fleet-core")]
use std::collections::HashMap;
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentEvent {
    Pairing {
        verification_uri: String,
        user_code: String,
    },
    Connecting,
    Connected,
    Reconnecting {
        delay_seconds: u64,
    },
}
pub async fn pair_with_network(
    input: &str,
    name: &str,
    path: &Path,
    network: &crate::network::Network,
) -> Result<Credentials> {
    pair_with_network_observed(input, name, path, network, &|_| {}).await
}
pub async fn pair_with_network_observed(
    input: &str,
    name: &str,
    path: &Path,
    network: &crate::network::Network,
    observe: &(dyn Fn(AgentEvent) + Send + Sync),
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
    observe(AgentEvent::Pairing {
        verification_uri: uri.chars().filter(|c| !c.is_control()).take(512).collect(),
        user_code: user_code
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect(),
    });
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
pub fn hello(creds: &Credentials, setup: bool) -> Value {
    hello_with_tools(creds, setup, tools())
}
/// Same handshake with an explicit local tool catalog (fleet MCP attaches its
/// own four tools only when the local service exists).
pub fn hello_with_tools(
    creds: &Credentials,
    setup: bool,
    tools: Vec<crate::protocol::ToolDefinition>,
) -> Value {
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
    let mut value = json!({"type":"hello","protocol":VERSION,"device":{"deviceId":creds.device_id,"name":creds.name,"platform":platform,"arch":arch,
        "hostname":std::env::var("COMPUTERNAME").or_else(|_|std::env::var("HOSTNAME")).unwrap_or_else(|_|"ferroc-host".into()),
        "agentVersion":env!("CARGO_PKG_VERSION"),"coreVersion":concat!("ferroc-",env!("CARGO_PKG_VERSION"))},"tools":tools});
    if setup {
        value["fleetSetupProtocol"] = json!(1);
    }
    value
}

#[cfg(feature = "fleet-core")]
type SetupArg<'a> = Option<&'a crate::fleet::setup_config::SetupProvision>;
#[cfg(not(feature = "fleet-core"))]
type SetupArg<'a> = Option<&'a ()>;
#[cfg(feature = "fleet-core")]
type TransferTask = (
    uuid::Uuid,
    Result<crate::fleet::transport_driver::TransferOutcome>,
);
#[cfg(not(feature = "fleet-core"))]
type TransferTask = (uuid::Uuid, Result<()>);
#[cfg(feature = "fleet-core")]
async fn next_mcp_start(
    rx: &mut Option<
        tokio::sync::mpsc::UnboundedReceiver<crate::fleet::mcp_transfer::ApprovedStart>,
    >,
) -> Option<crate::fleet::mcp_transfer::ApprovedStart> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}
#[cfg(not(feature = "fleet-core"))]
async fn next_mcp_start(_rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<()>>) -> Option<()> {
    std::future::pending().await
}
/// One value headed for the socket, optionally with a setup write receipt.
struct Pending(Value, Option<tokio::sync::oneshot::Sender<()>>);
struct SetupCompletion {
    prepared: bool,
    #[cfg(feature = "fleet-core")]
    proof: Option<crate::fleet::setup::PreparedSetup>,
}
async fn session(
    runtime: Arc<Runtime>,
    creds: &Credentials,
    setup: SetupArg<'_>,
    observe: &(dyn Fn(AgentEvent) + Send + Sync),
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<bool> {
    if *stop.borrow() {
        return Ok(true);
    }
    #[cfg(feature = "fleet-core")]
    if let Some(provision) = setup {
        provision.validate_route_origin(&creds.relay_url)?;
    }
    let url = websocket_url(&creds.relay_url)?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME));
    let connection = tokio::select! {
        result = runtime.policy.network.websocket(url, &creds.device_token, config) => result?,
        _ = stop.changed() => return Ok(true),
    };
    let Some(mut ws) = connection else {
        return Ok(false);
    };
    // A backend exists only for an explicitly provisioned agent; the wire
    // never enables it. Replacing a previous scope requires it to be retired.
    #[cfg(feature = "fleet-core")]
    let (mut setup_backend, mut setup_outbox, mut setup_rounds) = match setup {
        Some(provision) => {
            let rounds = provision.rounds()?;
            let (backend, outbox) = runtime.open_fleet_setup(&creds.device_id, 4)?;
            (Some(backend), Some(outbox), rounds)
        }
        None => (None, None, Vec::new()),
    };
    let flag = setup.is_some();
    let (tx, mut rx) = mpsc::channel::<Pending>(8);
    // A completed socket write is the ONLY success signal for an emission.
    #[cfg(feature = "fleet-core")]
    let mut setup_writer = JoinSet::new();
    #[cfg(feature = "fleet-core")]
    if let Some(mut outbox) = setup_outbox.take() {
        let forward = tx.clone();
        setup_writer.spawn(async move {
            while let Some(item) = outbox.recv().await {
                let Ok(frame) = item.wire_frame() else { break };
                let (ack, wait) = tokio::sync::oneshot::channel();
                if forward.send(Pending(frame, Some(ack))).await.is_err() {
                    break;
                }
                if wait.await.is_err() {
                    break;
                }
                item.report_written();
            }
        });
    }
    let mut calls = JoinSet::new();
    let mut seen = HashSet::new();
    let mut welcomed = false;
    let mut setup_waiters: JoinSet<(uuid::Uuid, SetupCompletion)> = JoinSet::new();
    #[cfg(feature = "fleet-core")]
    let mut setup_leases: Vec<(uuid::Uuid, crate::fleet::setup_lease::SetupLease)> = Vec::new();
    #[cfg(feature = "fleet-core")]
    let mut setup_resumes: Vec<(uuid::Uuid, crate::fleet::resume_route::PendingResumeRoute)> =
        Vec::new();
    #[cfg(feature = "fleet-core")]
    let mcp = runtime.fleet_mcp()?;
    #[cfg(feature = "fleet-core")]
    let mut mcp_starts = mcp.as_ref().and_then(|m| m.take_starts());
    #[cfg(not(feature = "fleet-core"))]
    let mut mcp_starts: Option<tokio::sync::mpsc::UnboundedReceiver<()>> = None;
    #[cfg(feature = "fleet-core")]
    let mut mcp_approvals: HashMap<uuid::Uuid, crate::fleet::setup_agent::LocalSetupApproval> =
        HashMap::new();
    #[cfg(feature = "fleet-core")]
    let mut mcp_tasks: HashMap<uuid::Uuid, uuid::Uuid> = HashMap::new();
    let mut transfer_tasks: JoinSet<TransferTask> = JoinSet::new();
    let mut deadline = Instant::now() + Duration::from_secs(15);
    let outcome: Result<bool> = async {
    #[cfg(feature = "fleet-core")]
    let catalog=runtime.tools_for()?;
    #[cfg(not(feature = "fleet-core"))]
    let catalog=tools();
    let greeting=hello_with_tools(creds,flag,catalog);
    #[cfg(feature = "fleet-core")]
    let greeting=if setup.is_some_and(|p|p.data_routes_requested()){let mut v=greeting;v["fleetDataProtocol"]=json!(1);v}else{greeting};
    timeout(Duration::from_secs(5), ws.send(Message::Text(greeting.to_string().into()))).await??;
    loop {
        tokio::select! {
            Some(_start)=next_mcp_start(&mut mcp_starts)=>{
                #[cfg(feature = "fleet-core")]
                {
                    let start = _start;
                    if !mcp.as_ref().is_some_and(|service| service.start_allowed(start.round,start.task)) {
                        if let Some(service)=mcp.as_ref(){service.abandon(start.round);}
                        continue;
                    }
                    let Some(approval)=mcp_approvals.remove(&start.round) else {
                        if let Some(service)=mcp.as_ref(){service.abandon(start.round);}
                        continue;
                    };
                    let Some(backend)=setup_backend.as_ref() else {continue;};
                    let waiter=backend.start_source(start.round,approval)?;
                    mcp_tasks.insert(start.round,start.task);
                    setup_waiters.spawn(async move {
                        let proof=waiter.await.ok().and_then(Result::ok);
                        (start.round,SetupCompletion{prepared:proof.is_some(),proof})
                    });
                    eprintln!("fleet setup round {}: started by local MCP",start.round);
                }
                #[cfg(not(feature = "fleet-core"))]
                { continue; }
            },
            result=transfer_tasks.join_next(), if !transfer_tasks.is_empty()=>{
                let (id,result)=result.context("transfer task missing")?.context("transfer task failed")?;
                // Re-arm the idle window only once no transfer is running, so an
                // already-expired deadline cannot fire the moment a task drains.
                if transfer_tasks.is_empty(){deadline=Instant::now()+Duration::from_secs(45);}
                #[cfg(feature = "fleet-core")]
                match result {
                    Ok(crate::fleet::transport_driver::TransferOutcome::SourceObserved(observed))=>eprintln!("fleet setup round {id}: source observed peer completion bytes={}",observed.receipt().size),
                    #[cfg(any(windows, target_os = "linux"))]
                    Ok(crate::fleet::transport_driver::TransferOutcome::TargetSettled(receipt))=>eprintln!("fleet setup round {id}: target settled locally bytes={}",receipt.size),
                    Err(error)=>eprintln!("fleet setup round {id}: transfer failed locally; effects may exist: {error:#}"),
                }
                #[cfg(not(feature = "fleet-core"))]
                { let _=(id,result); }
            },
            result=setup_waiters.join_next(), if !setup_waiters.is_empty()=>{
                let (id, completed) = result.context("setup observer missing")?.context("setup observer failed")?;
                if completed.prepared { eprintln!("fleet setup round {id}: prepared locally"); }
                else { eprintln!("fleet setup round {id}: failed locally"); }
                #[cfg(feature = "fleet-core")]
                if completed.proof.is_none() {
                    mcp_tasks.remove(&id);
                    if let Some(service)=mcp.as_ref(){service.abandon(id);}
                }
                #[cfg(feature = "fleet-core")]
                if let (Some(provision), Some(proof)) = (setup, completed.proof)
                    && provision.lease_requested() {
                    ensure!(setup_leases.len() + setup_resumes.len() < 4, "setup lease capacity full");
                    if provision.recovery(id).is_some() {
                        let pending=provision.prepare_resume_route(&runtime,id,proof)?;
                        tx.try_send(Pending(pending.request(),None)).map_err(|_|anyhow::anyhow!("resume DATA presentation queue unavailable"))?;
                        setup_resumes.push((id,pending));
                        eprintln!("fleet setup round {id}: resume proof presented locally");
                        continue;
                    }
                    match provision.authenticate_prepared(&runtime, id, proof) {
                        Ok(mut owner) => {
                            eprintln!("fleet setup round {id}: leased locally");
                            if provision.data_routes_requested(){
                                let frame=owner.request_data_route(id)?;
                                tx.try_send(Pending(frame,None)).map_err(|_|anyhow::anyhow!("DATA presentation queue unavailable"))?;
                                eprintln!("fleet setup round {id}: DATA route requested");
                            }
                            setup_leases.push((id,owner));
                        },
                        Err(_) => {
                            eprintln!("fleet setup round {id}: lease rejected locally");
                            mcp_tasks.remove(&id);
                            if let Some(service)=mcp.as_ref(){service.abandon(id);}
                            bail!("local leased setup rejected");
                        }
                    }
                }
            },
            _=stop.changed()=>{
                drop(rx); // Do not strand result senders while draining admitted calls.
                while let Some(result) = calls.join_next().await { result?; }
                // Never let a later connection inherit this one's pending rounds.
                #[cfg(feature = "fleet-core")]
                if let Some(backend)=setup_backend.take(){backend.shutdown().await?;}
                let _=timeout(Duration::from_secs(2),ws.close(None)).await;
                return Ok(true);
            },
            // The 45 s liveness window exists to recycle idle or dead sessions. It
            // must NOT abort an owned provisioned transfer: a congested relay can
            // delay pings behind DATA backpressure for minutes, and killing the
            // session mid-transfer (or right after settlement, before the local
            // completion line is written) turns a completed job into a spurious
            // failure. DATA itself stays bounded by its own link/lease budget.
            _=tokio::time::sleep_until(deadline),if transfer_tasks.is_empty()=>bail!("relay heartbeat/welcome timeout"),
            result=calls.join_next(),if !calls.is_empty()=>{result.context("call task missing")??;},
            Some(pending)=rx.recv()=>{
                let Pending(value, ack)=pending;
                let text=value.to_string();
                let text=if text.len()>MAX_FRAME {json!({"type":"result","id":value["id"],"error":{"code":"OUTPUT_LIMIT","message":"Response exceeds 1 MiB; operation may have completed; request smaller pages"}}).to_string()}else{text};
                timeout(Duration::from_secs(5),ws.send(Message::Text(text.into()))).await??;
                if let Some(ack)=ack { let _=ack.send(()); }
            },
            message=ws.next()=>{
                let message=message.context("relay disconnected")??;
                let msg=match message {
                    Message::Text(t)=>{
                        if flag {
                            let value: Value = serde_json::from_str(&t).context("malformed setup relay frame")?;
                            if value["type"] == "welcome" {
                                ensure!(value["fleetSetupProtocol"] == 1, "relay did not negotiate setup control");
                                #[cfg(feature = "fleet-core")]
                                if setup.is_some_and(|p|p.data_routes_requested()){ensure!(value["fleetDataProtocol"]==1,"relay did not negotiate DATA routes");}
                            } else {
                                ensure!(welcomed || value["type"] == "error", "setup frame before welcome");
                            }
                        }
                        #[cfg(feature = "fleet-core")]
                        if serde_json::from_str::<Value>(&t)?["type"]=="fleetRoute" {
                            #[derive(serde::Deserialize)]
                            #[serde(rename_all="camelCase",deny_unknown_fields)]
                            struct Ticket {#[serde(rename="type")]kind:String,id:uuid::Uuid,grant_digest:[u8;32],ticket:String,resume:Option<crate::fleet::resume_route::ResumeRouteProofs>}
                            ensure!(welcomed && setup.is_some_and(|p|p.data_routes_requested()) && t.len()<=2048,"unexpected DATA route response");
                            let ticket:Ticket=serde_json::from_str(&t)?;
                            let secret=zeroize::Zeroizing::new(ticket.ticket);
                            ensure!(ticket.kind=="fleetRoute","unexpected DATA response");
                            if let Some(proofs)=ticket.resume {
                                let provision=setup.context("resume route without local setup")?;
                                let idx=setup_resumes.iter().position(|(id,_)|*id==ticket.id).context("unexpected resume DATA round")?;
                                let (_,pending)=setup_resumes.remove(idx);
                                let owner=provision.authenticate_resumed_route(&runtime,pending,ticket.grant_digest,proofs,secret)?;
                                let recovery=provision.recovery(ticket.id).context("local resume selection vanished")?.clone();
                                let plan=provision.transfer().context("local resume transfer plan vanished")?;
                                let snapshot=crate::fleet::transport_driver::TransferPlanSnapshot::from_plan(plan,owner.role());
                                let rt=runtime.clone();let token=creds.device_token.clone();let stop=stop.clone();
                                transfer_tasks.spawn(async move {
                                    let result=crate::fleet::transport_driver::run_resumed_transfer(rt,owner,token,snapshot,recovery,Duration::from_secs(300),stop).await;
                                    (ticket.id,result)
                                });
                                eprintln!("fleet setup round {}: authenticated resume transfer started",ticket.id);
                                continue;
                            }
                            ensure!(!setup_resumes.iter().any(|(id,_)|*id==ticket.id),"fresh DATA ticket cannot replace resume proofs");
                            let (_,owner)=setup_leases.iter_mut().find(|(id,_)|*id==ticket.id).context("unknown DATA round")?;
                            owner.accept_data_route(ticket.id,ticket.grant_digest,secret)?;
                            eprintln!("fleet setup round {}: DATA ticket held locally",ticket.id);
                            if let Some(task)=mcp_tasks.remove(&ticket.id){
                                let plan=setup.and_then(|p|p.transfer()).context("MCP transfer plan vanished")?;
                                let snapshot=crate::fleet::transport_driver::TransferPlanSnapshot::from_plan(plan,owner.role());
                                let idx=setup_leases.iter().position(|(id,_)|*id==ticket.id).context("DATA round vanished")?;
                                let (_,owner)=setup_leases.remove(idx);
                                let service=mcp.as_ref().context("MCP transfer service vanished")?;
                                let delivered=service.deliver(ticket.id,crate::fleet::mcp_transfer::SourceHandoff{owner,token:creds.device_token.clone(),plan:snapshot,stop:stop.clone()});
                                eprintln!("fleet setup round {}: handed to local MCP task {task}: {delivered}",ticket.id);
                                if !delivered{service.abandon(ticket.id);}
                                continue;
                            }
                            if let Some(plan)=setup.and_then(|p|p.transfer()){
                                let role=owner.role();
                                let snapshot=crate::fleet::transport_driver::TransferPlanSnapshot::from_plan(plan,role);
                                let idx=setup_leases.iter().position(|(id,_)|*id==ticket.id).context("DATA round vanished")?;
                                let (_,owner)=setup_leases.remove(idx);
                                let rt=runtime.clone();let token=creds.device_token.clone();let stop=stop.clone();
                                transfer_tasks.spawn(async move {
                                    let result=crate::fleet::transport_driver::run_leased_transfer(rt,owner,token,snapshot,Duration::from_secs(300),stop).await;
                                    (ticket.id,result)
                                });
                                eprintln!("fleet setup round {}: transfer started",ticket.id);
                            }
                            continue;
                        }
                        #[cfg(feature = "fleet-core")]
                        if let Some(backend)=setup_backend.as_ref()
                            && backend.receive_if_setup(&t)? {continue;}
                        serde_json::from_str::<RelayMessage>(&t).context("malformed relay frame")?
                    },
                    Message::Ping(data)=>{timeout(Duration::from_secs(5),ws.send(Message::Pong(data))).await??;continue;},
                    Message::Pong(_)=>continue,
                    Message::Close(c)=>{if c.is_some_and(|c|matches!(u16::from(c.code),4401|4403)){return Ok(false);}bail!("relay closed connection");},
                    _=>bail!("unexpected non-text relay frame"),
                };
                match msg {
                    RelayMessage::Welcome {protocol}=>{
                        ensure!(!welcomed && protocol==VERSION,"invalid relay protocol/welcome");
                        welcomed=true;observe(AgentEvent::Connected);deadline=Instant::now()+Duration::from_secs(45);
                        #[cfg(feature = "fleet-core")]
                        if let Some(backend)=setup_backend.as_ref(){
                            for (id,role,approval) in setup_rounds.drain(..){
                                #[cfg(feature = "fleet-core")]
                                if mcp.is_some() && role == crate::fleet::setup_config::RoleFile::Source {
                                    mcp_approvals.insert(id, approval);
                                    continue;
                                }
                                let waiter = match role {
                                    crate::fleet::setup_config::RoleFile::Source=>backend.start_source(id,approval)?,
                                    crate::fleet::setup_config::RoleFile::Target=>backend.arm_target(id,approval)?,
                                };
                                setup_waiters.spawn(async move {
                                    let proof = waiter.await.ok().and_then(Result::ok);
                                    (id, SetupCompletion { prepared: proof.is_some(), proof })
                                });
                                eprintln!("fleet setup round {id}: armed locally");
                            }
                        }
                    },
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
                            let _=tx.send(Pending(value,None)).await;
                        });
                    },
                }
            }
        }
    }
    }.await;
    #[cfg(feature = "fleet-core")]
    {
        // Abort owned pumps FIRST: a target task drops its receiver (stage
        // operation) before host close; no pump may outlive this session.
        transfer_tasks.shutdown().await;
        // Pending MCP tasks must fail rather than wait for a dead session.
        if let Some(service) = mcp.as_ref() {
            service.abandon_all();
        }
        let released = setup_leases.len() + setup_resumes.len();
        setup_resumes.clear(); // drop actual pending resume ephemerals before backend retirement
        setup_leases.clear(); // revoke/drop live crypto BEFORE retiring this scope
        if released > 0 {
            eprintln!("fleet setup leases released locally: {released}");
        }
    }
    // Pending rounds belong to THIS connection: drain them before a reconnect
    // can advertise the capability again. Already handed-off proofs stand.
    #[cfg(feature = "fleet-core")]
    if let Some(backend) = setup_backend.take() {
        let _ = backend.shutdown().await;
    }
    #[cfg(feature = "fleet-core")]
    setup_writer.shutdown().await;
    setup_waiters.shutdown().await;
    outcome
}
pub async fn run(runtime: Arc<Runtime>, creds: &Credentials, once: bool) -> Result<()> {
    let (_keepalive, stop) = tokio::sync::watch::channel(false);
    run_observed_until(runtime, creds, once, &|_| {}, stop).await
}
/// Configured agent path: same relay session plus the local setup backend.
/// The provision is loaded BEFORE this call and never derived from the wire.
#[cfg(feature = "fleet-core")]
pub async fn run_with_setup(
    runtime: Arc<Runtime>,
    creds: &Credentials,
    provision: &crate::fleet::setup_config::SetupProvision,
    once: bool,
) -> Result<()> {
    let (_keepalive, stop) = tokio::sync::watch::channel(false);
    run_inner(runtime, creds, Some(provision), once, &|_| {}, stop).await
}
pub async fn run_observed_until(
    runtime: Arc<Runtime>,
    creds: &Credentials,
    once: bool,
    observe: &(dyn Fn(AgentEvent) + Send + Sync),
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    run_inner(runtime, creds, None, once, observe, stop).await
}
/// Same observed/stop session WITH the local setup backend. The provision is
/// loaded by the caller before this call and never derived from the wire; this is
/// the entry the GUI controller uses so it can be a fleet peer too.
#[cfg(feature = "fleet-core")]
pub async fn run_with_setup_observed_until(
    runtime: Arc<Runtime>,
    creds: &Credentials,
    provision: &crate::fleet::setup_config::SetupProvision,
    once: bool,
    observe: &(dyn Fn(AgentEvent) + Send + Sync),
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    run_inner(runtime, creds, Some(provision), once, observe, stop).await
}
async fn run_inner(
    runtime: Arc<Runtime>,
    creds: &Credentials,
    setup: SetupArg<'_>,
    once: bool,
    observe: &(dyn Fn(AgentEvent) + Send + Sync),
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut backoff = 1;
    loop {
        let started = Instant::now();
        if *stop.borrow() {
            return Ok(());
        }
        observe(AgentEvent::Connecting);
        match session(runtime.clone(), creds, setup, observe, stop.clone()).await {
            Ok(false) => bail!(
                "relay rejected/revoked credentials or sent fatal error; no automatic re-pairing; use a new --home and explicitly pair"
            ),
            Ok(true) => return Ok(()),
            Err(e) if once => return Err(e),
            Err(e) => {
                observe(AgentEvent::Reconnecting {
                    delay_seconds: backoff,
                });
                eprintln!("relay connection lost: {e}; reconnecting in {backoff}s");
            }
        }
        // Do not leave a shell mutation running and then advertise a fresh connection/session.
        runtime.processes.shutdown().await;
        if started.elapsed() > Duration::from_secs(60) {
            backoff = 1;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(backoff)) => {},
            _ = stop.changed() => return Ok(()),
        }
        backoff = (backoff * 2).min(30);
    }
}
