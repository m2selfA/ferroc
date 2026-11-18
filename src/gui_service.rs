//! GUI-independent lifecycle/controller. A single background runtime owns both
//! the local MCP listener and optional outbound relay; never a child relay service.
use crate::{
    config::Policy,
    http_mcp::{HttpMcp, HttpSnapshot, random_token},
    network::Network,
    runtime::Runtime,
    transport::{self, AgentEvent},
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

#[cfg(all(test, feature = "fleet-core"))]
#[path = "gui_service_tests.rs"]
mod tests;

#[derive(Clone)]
pub struct GuiOptions {
    pub root: PathBuf,
    pub bind: SocketAddr,
    pub allow_shell: bool,
    pub allow_transfers: bool,
    pub proxy: Option<String>,
    pub no_proxy: bool,
    pub ca_cert: Option<PathBuf>,
    pub relay: Option<String>,
    pub home: PathBuf,
    pub name: String,
    /// Explicit LOCAL fleet setup file. Loaded per connection against the real
    /// device id; never supplied by the relay or by a remote caller.
    #[cfg(feature = "fleet-core")]
    pub fleet_setup: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
    Exited,
}
/// Counts from the SAME Runtime attachment used by local MCP. A completed
/// source task is still only an authenticated peer report, never disk attestation.
#[cfg(feature = "fleet-core")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FleetTaskSummary {
    pub pending: usize,
    pub peer_reported_completed: usize,
    pub interrupted: usize,
    pub failed: usize,
}
#[cfg(feature = "fleet-core")]
impl FleetTaskSummary {
    fn from_snapshots(tasks: Vec<crate::fleet::transfer_tasks::TaskSnapshot>) -> Self {
        use crate::fleet::transfer_tasks::TaskPhase;
        let mut summary = Self::default();
        for task in tasks {
            match task.phase {
                TaskPhase::Queued | TaskPhase::Running | TaskPhase::CancelRequested => {
                    summary.pending += 1
                }
                TaskPhase::PeerReportedCompleted => summary.peer_reported_completed += 1,
                TaskPhase::Interrupted => summary.interrupted += 1,
                TaskPhase::Failed => summary.failed += 1,
            }
        }
        summary
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiSnapshot {
    pub phase: Phase,
    pub detail: String,
    pub endpoint: Option<String>,
    pub network: String,
    pub relay: String,
    pub has_runtime: bool,
    pub http: Option<HttpSnapshot>,
    #[cfg(feature = "fleet-core")]
    pub fleet_tasks: Option<FleetTaskSummary>,
}
struct State {
    phase: Phase,
    detail: String,
    endpoint: Option<String>,
    token: Option<String>,
    network: String,
    relay: String,
    http: Option<HttpMcp>,
    #[cfg(feature = "fleet-core")]
    fleet_runtime: std::sync::Weak<Runtime>,
}
#[derive(Clone)]
pub struct GuiControl {
    state: Arc<Mutex<State>>,
    tx: mpsc::Sender<Command>,
}
pub struct GuiService {
    control: GuiControl,
    thread: thread::JoinHandle<()>,
}
enum Command {
    Start(Box<GuiOptions>),
    Stop,
    Quit,
}
struct Running {
    runtime: Arc<Runtime>,
    http: HttpMcp,
    stop: watch::Sender<bool>,
    server: JoinHandle<()>,
    relay: Option<JoinHandle<()>>,
}
impl GuiService {
    pub fn new() -> Result<Self> {
        let state = Arc::new(Mutex::new(State {
            phase: Phase::Stopped,
            detail: "选择授权目录，然后启动。".into(),
            endpoint: None,
            token: None,
            network: "未启动".into(),
            relay: "未启用".into(),
            http: None,
            #[cfg(feature = "fleet-core")]
            fleet_runtime: std::sync::Weak::new(),
        }));
        let (tx, mut rx) = mpsc::channel(32);
        let control = GuiControl {
            state: state.clone(),
            tx,
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("ferroc-agent")
            .build()?;
        let thread = thread::Builder::new()
            .name("ferroc-controller".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let mut active: Option<Running> = None;
                    while let Some(command) = rx.recv().await {
                        match command {
                            Command::Start(options) if active.is_none() => {
                                {
                                    let mut s = state.lock().expect("GUI state");
                                    s.phase = Phase::Starting;
                                    s.detail = "正在校验目录并绑定本机端口…".into();
                                }
                                match start(*options, state.clone()).await {
                                    Ok(running) => active = Some(running),
                                    Err(error) => {
                                        let mut s = state.lock().expect("GUI state");
                                        s.phase = Phase::Failed;
                                        s.detail = error.to_string();
                                        s.token = None;
                                        s.endpoint = None;
                                        s.http = None;
                                        s.relay = "未启用".into();
                                    }
                                }
                            }
                            Command::Start(_) => {}
                            Command::Stop | Command::Quit => {
                                let quit = matches!(command, Command::Quit);
                                if let Some(running) = active.take() {
                                    stop(running, &state).await;
                                }
                                let mut s = state.lock().expect("GUI state");
                                s.phase = if quit { Phase::Exited } else { Phase::Stopped };
                                s.detail = if quit {
                                    "已停止监听并排空，退出。"
                                } else {
                                    "已停止；再次启动将更换口令和会话。"
                                }
                                .into();
                                if quit {
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(running) = active {
                        stop(running, &state).await;
                    }
                })
            })?;
        Ok(Self { control, thread })
    }
    pub fn control(&self) -> GuiControl {
        self.control.clone()
    }
    pub fn finish(self) -> Result<()> {
        // Normally Quit completed before the UI exits. Also handles a duplicate
        // instance (WindUI returns before any interval can start the listener).
        if self.control.snapshot().phase != Phase::Exited {
            let _ = self.control.tx.blocking_send(Command::Quit);
        }
        self.thread
            .join()
            .map_err(|_| anyhow::anyhow!("GUI controller thread failed"))
    }
}
impl GuiControl {
    pub fn snapshot(&self) -> GuiSnapshot {
        let s = self.state.lock().expect("GUI state");
        GuiSnapshot {
            phase: s.phase,
            detail: s.detail.clone(),
            endpoint: s.endpoint.clone(),
            network: s.network.clone(),
            relay: s.relay.clone(),
            has_runtime: s.http.is_some(),
            http: s.http.as_ref().map(HttpMcp::snapshot),
            #[cfg(feature = "fleet-core")]
            fleet_tasks: s
                .fleet_runtime
                .upgrade()
                .and_then(|runtime| runtime.fleet_tasks().ok().flatten()?.snapshots().ok())
                .map(FleetTaskSummary::from_snapshots),
        }
    }
    pub fn start(&self, options: GuiOptions) -> Result<()> {
        self.tx
            .try_send(Command::Start(Box::new(options)))
            .map_err(|_| anyhow::anyhow!("GUI command queue unavailable"))
    }
    pub fn stop(&self) -> Result<()> {
        self.tx
            .try_send(Command::Stop)
            .map_err(|_| anyhow::anyhow!("GUI command queue unavailable"))
    }
    pub fn quit(&self) -> Result<()> {
        self.tx
            .try_send(Command::Quit)
            .map_err(|_| anyhow::anyhow!("GUI command queue unavailable"))
    }
    pub fn pause(&self, paused: bool) {
        if let Some(http) = &self.state.lock().expect("GUI state").http {
            http.set_paused(paused);
        }
    }
    /// Secret-bearing client configuration is only obtained on an explicit copy
    /// action. It never appears in status snapshots, tooltips or diagnostics.
    pub fn client_config(&self) -> Option<String> {
        let s = self.state.lock().expect("GUI state");
        Some(serde_json::to_string_pretty(&json!({"mcpServers":{"ferroc":{"type":"http","url":s.endpoint.as_ref()?,"headers":{"Authorization":format!("Bearer {}",s.token.as_ref()?)}}}})).expect("client config"))
    }
}
async fn start(options: GuiOptions, state: Arc<Mutex<State>>) -> Result<Running> {
    ensure!(
        options.bind.ip().is_loopback(),
        "HTTP MCP仅允许loopback地址，不能绑定公网或局域网接口。"
    );
    // A fleet setup file is only meaningful together with a relay connection; a
    // silent no-op would look like "fleet enabled" while nothing could ever arm.
    #[cfg(feature = "fleet-core")]
    ensure!(
        options.fleet_setup.is_none() || options.relay.is_some(),
        "fleet setup需要同时配置中继地址：否则本机永远无法装载任何一轮。"
    );
    #[cfg(feature = "fleet-core")]
    ensure!(
        options.fleet_setup.is_none() || options.allow_transfers,
        "fleet setup与--no-transfers冲突：传输已被本机策略关闭。"
    );
    let dedicated = if options.no_proxy || options.proxy.is_some() {
        None
    } else {
        match std::env::var("FERROC_PROXY") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("FERROC_PROXY必须为有效Unicode（值已省略）")
            }
        }
    };
    let mut network = Network::select(
        options.proxy.as_deref(),
        options.no_proxy,
        dedicated.as_deref(),
    )
    .context("代理配置无效（值已省略）")?;
    if let Some(path) = &options.ca_cert {
        network = network
            .with_ca_file(path)
            .context("无法加载附加CA（路径与值已省略）")?;
    }
    if let Some(url) = &options.relay {
        transport::relay_url(url)
            .context("中继地址无效：HTTPS或本机HTTP，禁止凭据、query和fragment")?;
    }
    let network_description = network.describe().to_string();
    let mut policy = Policy::new(vec![options.root], options.allow_shell)
        .context("授权目录不可用，请选择已存在的目录。")?;
    policy.allow_transfers = options.allow_transfers;
    policy.network = network;
    let listener = tokio::net::TcpListener::bind(options.bind)
        .await
        .context("HTTP端口无法绑定：可能已被占用，请更换端口。")?;
    let bound = listener.local_addr()?;
    let root_display = policy.roots[0].display().to_string();
    let runtime = Arc::new(Runtime::new(policy));
    let token = random_token();
    let http = HttpMcp::new(runtime.clone(), bound, token.clone())?;
    let (stop, mut stopped) = watch::channel(false);
    let router = http.router();
    let error_state = state.clone();
    let server = tokio::spawn(async move {
        if axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = stopped.changed().await;
            })
            .await
            .is_err()
        {
            let mut s = error_state.lock().expect("GUI state");
            s.phase = Phase::Failed;
            s.detail = "HTTP监听异常停止；请停止后重启。".into();
        }
    });
    {
        let mut s = state.lock().expect("GUI state");
        s.phase = Phase::Running;
        s.detail = format!("当前授权目录：{root_display}；配置更改仅在下次启动生效。");
        s.endpoint = Some(format!("http://{bound}/mcp"));
        s.token = Some(token);
        s.network = network_description;
        s.http = Some(http.clone());
        s.relay = if options.relay.is_some() {
            "正在连接…"
        } else {
            "未启用（仅本机HTTP MCP）"
        }
        .into();
    }
    let relay = options.relay.map(|url| {
        let runtime = runtime.clone();
        let state = state.clone();
        let mut stopped = stop.subscribe();
        tokio::spawn(async move {
            let event_state = state.clone();
            let observe = move |event: AgentEvent| {
                let text = match event {
                    AgentEvent::Pairing {
                        verification_uri,
                        user_code,
                    } => format!("等待批准 · 代码 {user_code} · {verification_uri}"),
                    AgentEvent::Connecting => "连接中…".into(),
                    AgentEvent::Connected => "在线".into(),
                    AgentEvent::Reconnecting { delay_seconds } => {
                        format!("已断开 · {delay_seconds}秒后重连")
                    }
                };
                event_state.lock().expect("GUI state").relay = text;
            };
            let connect = async {
                let path = options.home.join("device.json");
                let credentials = if let Some(saved) = transport::load_credentials(&path).await? {
                    ensure!(
                        transport::relay_url(&url)? == transport::relay_url(&saved.relay_url)?,
                        "saved credentials relay mismatch"
                    );
                    saved
                } else {
                    transport::pair_with_network_observed(
                        &url,
                        &options.name,
                        &path,
                        &runtime.policy.network,
                        &observe,
                    )
                    .await?
                };
                Ok::<_, anyhow::Error>(credentials)
            };
            let credentials =
                tokio::select! { result=connect=>result, _=stopped.changed()=>return };
            #[cfg(feature = "fleet-core")]
            let fleet = match (&credentials, options.fleet_setup.as_deref()) {
                // The provision is loaded HERE, against the real device id, and is
                // never derived from the relay: a remote frame cannot grant it.
                (Ok(credentials), Some(path)) => Some(
                    crate::fleet::setup_config::SetupProvision::load(path, &credentials.device_id)
                        .and_then(|provision| {
                            // Registration consumes one Arc handle; the session keeps
                            // the same provision, so both see identical approvals.
                            let shared = std::sync::Arc::new(provision);
                            if shared.mcp_transfer_requested() {
                                runtime.open_fleet_mcp(shared.clone(), 8)?;
                                state.lock().expect("GUI state").fleet_runtime =
                                    Arc::downgrade(&runtime);
                            }
                            Ok(shared)
                        }),
                ),
                (Err(_), Some(_)) => None,
                (_, None) => None,
            };
            let result = match credentials {
                Ok(credentials) => {
                    #[cfg(feature = "fleet-core")]
                    if let Some(fleet) = fleet {
                        match fleet {
                            Ok(provision) => {
                                transport::run_with_setup_observed_until(
                                    runtime,
                                    &credentials,
                                    &provision,
                                    false,
                                    &observe,
                                    stopped,
                                )
                                .await
                            }
                            // A rejected provision fails the connection instead of
                            // silently running without fleet capability.
                            Err(error) => Err(error),
                        }
                    } else {
                        transport::run_observed_until(
                            runtime,
                            &credentials,
                            false,
                            &observe,
                            stopped,
                        )
                        .await
                    }
                    #[cfg(not(feature = "fleet-core"))]
                    transport::run_observed_until(runtime, &credentials, false, &observe, stopped)
                        .await
                }
                Err(error) => Err(error),
            };
            state.lock().expect("GUI state").relay = if result.is_ok() {
                "已停止"
            } else {
                "连接/配对失败或凭据被拒绝；检查中继与独立home，未自动重新配对。"
            }
            .into();
        })
    });
    Ok(Running {
        runtime,
        http,
        stop,
        server,
        relay,
    })
}
async fn stop(running: Running, state: &Arc<Mutex<State>>) {
    {
        let mut s = state.lock().expect("GUI state");
        s.phase = Phase::Stopping;
        s.detail = "停止接收新请求；等待已接收调用完成，不承诺回滚。".into();
        s.token = None;
    }
    running.http.close();
    let _ = running.stop.send(true);
    let _ = running.server.await;
    running.http.wait_idle().await;
    if let Some(relay) = running.relay {
        let _ = relay.await;
    }
    running.runtime.shutdown().await;
    let mut s = state.lock().expect("GUI state");
    s.http = None;
    #[cfg(feature = "fleet-core")]
    {
        s.fleet_runtime = std::sync::Weak::new();
    }
    s.endpoint = None;
    s.relay = "已停止".into();
}
