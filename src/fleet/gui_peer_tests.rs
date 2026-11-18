//! Real loopback HTTP + control WS + DATA through the GUI controller.
//! In-process component evidence, not native window/tray input or two hosts.
use super::{
    identity::{
        EndpointSlot, IdentityStore, PeerApproval, Protection, make_directory, new_private,
    },
    job::JOB_VERSION,
    route_control::ApprovedDataRoutes,
    setup_config::SetupProvision,
};
use crate::{
    config::Policy,
    gui_service::{GuiControl, GuiOptions, GuiService, Phase},
    relay::Relay,
    runtime::Runtime,
    transport::{self, Credentials},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

async fn phase(control: &GuiControl, want: Phase) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if control.snapshot().phase == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("GUI phase deadline")
}
fn write_json(path: &Path, value: &Value) -> Result<()> {
    std::fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}
struct HttpClient {
    client: reqwest::Client,
    url: String,
    auth: String,
    session: String,
}
impl HttpClient {
    async fn connect(control: &GuiControl) -> Result<Self> {
        let config: Value = serde_json::from_str(&control.client_config().context("GUI config")?)?;
        let mut c = Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()?,
            url: config["mcpServers"]["ferroc"]["url"]
                .as_str()
                .context("URL")?
                .into(),
            auth: config["mcpServers"]["ferroc"]["headers"]["Authorization"]
                .as_str()
                .context("auth")?
                .into(),
            session: String::new(),
        };
        let response = c.post(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})).send().await?.error_for_status()?;
        c.session = response
            .headers()
            .get("mcp-session-id")
            .context("session")?
            .to_str()?
            .into();
        c.post(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .await?
            .error_for_status()?;
        Ok(c)
    }
    fn post(&self, value: Value) -> reqwest::RequestBuilder {
        let mut r = self
            .client
            .post(&self.url)
            .header("authorization", &self.auth)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-06-18")
            .json(&value);
        if !self.session.is_empty() {
            r = r.header("mcp-session-id", &self.session);
        }
        r
    }
    async fn tools(&self) -> Result<Value> {
        Ok(self
            .post(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    async fn call(&self, name: &str, args: Value) -> Result<Value> {
        let v: Value = self.post(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":args}})).send().await?.error_for_status()?.json().await?;
        ensure!(
            v.get("error").is_none() && v["result"]["isError"] != true,
            "MCP call rejected: {v}"
        );
        Ok(serde_json::from_str(
            v["result"]["content"][0]["text"]
                .as_str()
                .context("tool text")?,
        )?)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gui_http_mcp_drives_authenticated_file_to_sql_receipt_and_restarts_without_fleet()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let relay = Relay::new(
        &root.path().join("relay.db"),
        &url,
        "PUBLIC GUI PEER TEST ADMIN",
    )?;
    let creds = |id: &str| Credentials {
        relay_url: url.clone(),
        device_id: id.into(),
        device_token: format!("PUBLIC_GUI_TEST_{id}"),
        name: id.into(),
        paired_at: "test".into(),
    };
    let a = creds("gui-source");
    let b = creds("cli-target");
    for c in [&a, &b] {
        let hash = crate::relay::hash(&c.device_token);
        relay.store.put(
            "device",
            &c.device_id,
            &json!({"tokenHash":hash,"paused":false}),
            600,
        )?;
        relay
            .store
            .put("device_token", &hash, &json!({"deviceId":c.device_id}), 600)?;
    }
    let fleet = Uuid::new_v4();
    let ia = IdentityStore::create(
        &root.path().join("ia"),
        Protection::windows_current_user()?,
        fleet,
        &a.device_id,
    )?;
    let ib = IdentityStore::create(
        &root.path().join("ib"),
        Protection::windows_current_user()?,
        fleet,
        &b.device_id,
    )?;
    let ka = ia.create_identity()?;
    let kb = ib.create_identity()?;
    let fa = ia.local_fingerprint()?;
    let fb = ib.local_fingerprint()?;
    ia.enroll_peer(
        PeerApproval::verify(fleet, &b.device_id, kb.public(), &fb)?,
        "target",
        1,
    )?;
    ib.enroll_peer(
        PeerApproval::verify(fleet, &a.device_id, ka.public(), &fa)?,
        "source",
        1,
    )?;
    ia.set_peer_endpoint(&b.device_id, EndpointSlot::Primary, &url, &fb)?;
    ib.set_peer_endpoint(&a.device_id, EndpointSlot::Primary, &url, &fa)?;
    let source_dir = root.path().join("source");
    let target_dir = root.path().join("target");
    make_directory(&source_dir)?;
    make_directory(&target_dir)?;
    let source = source_dir.join("input.bin");
    let destination = target_dir.join("output.bin");
    let data: Vec<u8> = (0..131073).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &data)?;
    let db = target_dir.join("host.db");
    drop(new_private(&db)?);
    let home = root.path().join("home");
    transport::save_credentials(&home.join("device.json"), &a).await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let round_id = Uuid::new_v4();
    let round = json!({"id":round_id,"role":"source","job":{"version":JOB_VERSION,"fleetId":fleet,"sourceDevice":super::protocol::device_digest(&a.device_id)?,"targetDevice":super::protocol::device_digest(&b.device_id)?,"transferId":Uuid::new_v4(),"fileId":Uuid::new_v4(),"sourcePath":source,"destinationPath":destination,"bytesTotal":data.len(),"sha256":Sha256::digest(&data).to_vec(),"overwrite":false,"route":"relayOnly","deadlineMs":now+180000,"idempotencyKey":"gui-real-http"},"sourceSession":Uuid::new_v4(),"targetSession":Uuid::new_v4(),"chunkBytes":65536,"leaseMs":120000,"issuedAtMs":now-1000,"authorizationId":Uuid::new_v4(),"keyEpoch":Uuid::new_v4()});
    let cfg = |store: &str,
               device: &str,
               peer: &str,
               fingerprint: String,
               r: Value,
               transfer: Value| json!({"version":2,"identityStore":root.path().join(store),"fleet":fleet,"device":device,"protection":{"kind":"windowsCurrentUser"},"peer":{"device":peer,"fingerprint":fingerprint,"slot":"primary","profile":"singleOwner"},"rounds":[r],"dataRoutes":true,"leaseAuthority":{"kind":"singleOwnerSystemClock","uncertaintyMs":100},"transfer":transfer});
    let source_config = root.path().join("source.json");
    write_json(
        &source_config,
        &cfg(
            "ia",
            &a.device_id,
            &b.device_id,
            fb.hex(),
            round.clone(),
            json!({"windowChunks":4,"mcp":true}),
        ),
    )?;
    let mut target_round = round.clone();
    target_round["role"] = json!("target");
    let target_config = root.path().join("target.json");
    write_json(
        &target_config,
        &cfg(
            "ib",
            &b.device_id,
            &a.device_id,
            fa.hex(),
            target_round,
            json!({"windowChunks":4,"hostDb":db}),
        ),
    )?;
    let route_config = root.path().join("routes.json");
    write_json(
        &route_config,
        &json!({"version":1,"approvals":[{"sourceDeviceId":a.device_id,"targetDeviceId":b.device_id,"round":round,"profile":"singleOwner","ttlMs":120000}]}),
    )?;
    let router = relay.router_with_approved_routes(ApprovedDataRoutes::load(&route_config)?);
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let target_runtime = Arc::new(Runtime::new(Policy::new(vec![target_dir.clone()], false)?));
    let provision = SetupProvision::load(&target_config, &b.device_id)?;
    let (stop_target, target_stop) = tokio::sync::watch::channel(false);
    let target_owner = target_runtime.clone();
    let target = tokio::spawn(async move {
        transport::run_with_setup_observed_until(
            target_owner,
            &b,
            &provision,
            false,
            &|_| {},
            target_stop,
        )
        .await
    });
    let service = GuiService::new()?;
    let control = service.control();
    let mut opts = GuiOptions {
        root: source_dir,
        bind: "127.0.0.1:0".parse()?,
        allow_shell: false,
        allow_transfers: true,
        proxy: None,
        no_proxy: true,
        ca_cert: None,
        relay: Some(url),
        home,
        name: "GUI source test".into(),
        fleet_setup: Some(source_config),
    };
    control.start(opts.clone())?;
    // Cleanup runs even if an MCP/SQL assertion returns an error.
    let result: Result<()> = async {
        phase(&control, Phase::Running).await?;
        let client = HttpClient::connect(&control).await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let tools = client.tools().await?;
                if tools["result"]["tools"]
                    .as_array()
                    .context("tools")?
                    .iter()
                    .any(|t| t["name"] == "send_file")
                {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("fleet attachment deadline")??;
        let tools = client.tools().await?;
        for name in ["send_file", "sync_dir", "transfer_get", "transfer_cancel"] {
            ensure!(
                tools["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t["name"] == name),
                "missing tool {name}"
            );
        }
        ensure!(!destination.exists(), "MCP mode must wait for send_file");
        let task = client
            .call("send_file", json!({"roundId":round_id,"timeoutMs":60000}))
            .await?;
        let snapshot = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let snapshot = client
                    .call("transfer_get", json!({"taskId":task["taskId"]}))
                    .await?;
                if snapshot["phase"] == "peerReportedCompleted" {
                    return Ok::<_, anyhow::Error>(snapshot);
                }
                ensure!(
                    snapshot["phase"] != "failed" && snapshot["phase"] != "interrupted",
                    "task failed: {snapshot}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("file completion deadline")??;
        ensure!(
            std::fs::read(&destination)? == data,
            "target bytes mismatch"
        );
        let connection =
            rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let body: String =
            connection.query_row("SELECT body FROM ferroc_fleet_jobs_v1", [], |r| r.get(0))?;
        let row: Value = serde_json::from_str(&body)?;
        ensure!(
            row["phase"] == "completed" && row["stage"].is_null(),
            "not settled: {row}"
        );
        ensure!(
            row["receipt"] == snapshot["peerObservation"]["receipt"],
            "source/SQL receipt mismatch"
        );
        let summary = control.snapshot().fleet_tasks.context("GUI task summary")?;
        ensure!(
            summary.pending == 0 && summary.peer_reported_completed == 1 && summary.failed == 0,
            "GUI observed wrong task counts: {summary:?}"
        );
        let late = client
            .call("transfer_cancel", json!({"taskId":task["taskId"]}))
            .await?;
        ensure!(
            late["cancelled"] == false,
            "late cancellation changed completion"
        );
        control.stop()?;
        phase(&control, Phase::Stopped).await?;
        ensure!(
            client.client.get(&client.url).send().await.is_err(),
            "old HTTP listener leaked"
        );
        opts.fleet_setup = None;
        opts.relay = None;
        control.start(opts.clone())?;
        phase(&control, Phase::Running).await?;
        ensure!(
            control.snapshot().fleet_tasks.is_none(),
            "stale task summary survived restart"
        );
        let restarted = HttpClient::connect(&control).await?;
        ensure!(restarted.auth != client.auth, "token did not rotate");
        let tools = restarted.tools().await?;
        ensure!(
            !tools["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["name"] == "send_file"),
            "fleet attachment survived restart"
        );
        Ok(())
    }
    .await;
    control.quit()?;
    let exited = phase(&control, Phase::Exited).await;
    let finished = tokio::task::spawn_blocking(move || service.finish()).await?;
    let _ = stop_target.send(true);
    let target_result = tokio::time::timeout(Duration::from_secs(10), target).await;
    target_runtime.shutdown().await;
    server.abort();
    let _ = server.await;
    result?;
    exited?;
    finished?;
    target_result.context("target stop deadline")???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gui_rejects_invalid_provision_without_ws_or_fleet_tools() -> Result<()> {
    let root = tempfile::tempdir()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let home = root.path().join("home");
    transport::save_credentials(
        &home.join("device.json"),
        &Credentials {
            relay_url: url.clone(),
            device_id: "real-device".into(),
            device_token: "PUBLIC_BAD_CONFIG_TEST".into(),
            name: "gui".into(),
            paired_at: "test".into(),
        },
    )
    .await?;
    let config = root.path().join("invalid.json");
    write_json(&config, &json!({"version":999}))?;
    let service = GuiService::new()?;
    let control = service.control();
    control.start(GuiOptions {
        root: root.path().to_path_buf(),
        bind: "127.0.0.1:0".parse()?,
        allow_shell: false,
        allow_transfers: true,
        proxy: None,
        no_proxy: true,
        ca_cert: None,
        relay: Some(url),
        home,
        name: "gui".into(),
        fleet_setup: Some(config.clone()),
    })?;
    let result: Result<()> = async {
        phase(&control, Phase::Running).await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !control.snapshot().relay.starts_with("连接/配对失败") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("invalid provision was not rejected")?;
        // Saved credentials exist, so invalid approval must fail BEFORE a WS
        // handshake, with no automatic unconfigured fallback or pairing.
        ensure!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "invalid config caused a network connection"
        );
        let client = HttpClient::connect(&control).await?;
        let tools = client.tools().await?;
        ensure!(
            !tools["result"]["tools"]
                .as_array()
                .context("tools")?
                .iter()
                .any(|t| t["name"] == "send_file"),
            "invalid config exposed fleet tools"
        );
        ensure!(
            client
                .call("send_file", json!({"roundId":Uuid::new_v4()}))
                .await
                .is_err(),
            "invalid config accepted a task"
        );
        ensure!(
            control.snapshot().fleet_tasks.is_none(),
            "invalid config attached a task table"
        );
        ensure!(
            !format!("{:?}", control.snapshot()).contains(config.to_str().unwrap()),
            "diagnostic leaked config path"
        );
        Ok(())
    }
    .await;
    control.quit()?;
    let exited = phase(&control, Phase::Exited).await;
    let finished = tokio::task::spawn_blocking(move || service.finish()).await?;
    result?;
    exited?;
    finished?;
    Ok(())
}
