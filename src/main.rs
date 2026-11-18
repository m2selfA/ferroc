use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use ferroc::{
    config::Policy,
    network::Network,
    runtime::Runtime,
    transport::{self, Credentials},
};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(
    version,
    about = "ferroc — Ferrum + Commander. Native Rust MCP tools and BRC-compatible outbound agent."
)]
struct Cli {
    /// Allowed file roots (repeatable). Defaults to the current directory, never all disks.
    #[arg(long, global = true)]
    allow_dir: Vec<PathBuf>,
    /// Enable unrestricted user-level shell execution. Directory policy is NOT a shell sandbox.
    #[arg(long, global = true)]
    allow_shell: bool,
    /// Explicitly enable encrypted transfers (already the default). Provider sees size/timing.
    #[arg(long, global = true, conflicts_with = "no_transfers")]
    allow_transfers: bool,
    /// Disable all encrypted transfer tools for this process.
    #[arg(long, global = true)]
    no_transfers: bool,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// LOCAL fleet identity/peer/endpoint setup only (no transfer or network).
    #[cfg(feature = "fleet-core")]
    Fleet(ferroc::fleet::admin_cli::FleetArgs),
    /// LOCAL read-only directory scan/checksum dry-run; no apply or network.
    #[cfg(feature = "fleet-core")]
    FleetDir(ferroc::fleet::directory_cli::DirectoryArgs),
    /// LOCAL read-only fleet obligation view; no admission, release or network.
    #[cfg(feature = "fleet-core")]
    FleetInventory(ferroc::fleet::inventory_cli::InventoryArgs),
    /// LOCAL explicit recovery of a STOPPED owner's absent allocation; no network.
    #[cfg(feature = "fleet-core")]
    FleetRelease(ferroc::fleet::release_cli::ReleaseArgs),
    /// Serve local MCP over newline-delimited JSON-RPC on stdio.
    Stdio,
    /// Native Rust relay preview: SQLite, OAuth/PKCE, remote MCP and Web admin.
    Relay {
        #[arg(long, default_value = "127.0.0.1:3210")]
        bind: std::net::SocketAddr,
        #[arg(long, env = "FERROC_PUBLIC_URL")]
        public_url: String,
        #[arg(long, default_value = "ferroc-relay.sqlite")]
        db: PathBuf,
        #[arg(long, env = "FERROC_ADMIN_PASSWORD", hide_env_values = true)]
        admin_password: String,
        /// Enable candidate setup control on existing /ws only (no DATA routes).
        #[cfg(feature = "fleet-core")]
        #[arg(long)]
        fleet_setup: bool,
        /// Explicit LOCAL DATA routing approvals on this same relay. No file authority.
        #[cfg(feature = "fleet-core")]
        #[arg(long, requires = "fleet_setup")]
        fleet_data_config: Option<PathBuf>,
    },
    /// Print the implemented tool definitions (not the upstream full feature set).
    Tools,
    /// Execute one tool locally. Output is an MCP ToolResult; tool errors exit 1.
    Call {
        tool: String,
        #[arg(default_value = "{}")]
        args: String,
    },
    /// Connect outbound to an existing BRC relay. No listening port or extra relay service.
    Agent {
        #[arg(long, env = "FERROC_RELAY")]
        relay: Option<String>,
        #[arg(long, env = "FERROC_NAME", default_value = "ferroc")]
        name: String,
        /// Prefer FERROC_TOKEN over command-line secrets. Explicit tokens are not persisted.
        #[arg(long, env = "FERROC_TOKEN", hide_env_values = true)]
        token: Option<String>,
        #[arg(long, env = "FERROC_DEVICE_ID")]
        device_id: Option<String>,
        /// Separate credential directory; never reads or writes ~/.brc.
        #[arg(long, env = "FERROC_HOME")]
        home: Option<PathBuf>,
        /// Outbound HTTP/HTTPS/SOCKS5/SOCKS5h proxy for pairing, WS and transfers. Prefer FERROC_PROXY for credentials.
        #[arg(long, conflicts_with = "no_proxy")]
        proxy: Option<String>,
        /// Force direct connections; overrides FERROC_PROXY and standard proxy environment variables.
        #[arg(long)]
        no_proxy: bool,
        /// Additional PEM CA bundle trusted for BOTH proxy TLS and relay/provider TLS; validation stays enabled.
        #[arg(long, env = "FERROC_CA_CERT", hide_env_values = true)]
        ca_cert: Option<PathBuf>,
        /// Fail on first disconnect, useful for supervised execution and diagnostics.
        #[arg(long)]
        once: bool,
        /// Explicit LOCAL setup provisioning (fleet-core builds only). Absent means
        /// the stock agent: no capability flag and no setup backend.
        #[cfg(feature = "fleet-core")]
        #[arg(long, env = "FERROC_FLEET_SETUP")]
        fleet_setup: Option<PathBuf>,
    },
}

/// Absent provisioning keeps the stock agent byte-identical in behaviour.
async fn run_agent(
    runtime: Arc<Runtime>,
    creds: &transport::Credentials,
    once: bool,
    #[cfg(feature = "fleet-core")] fleet_setup: Option<PathBuf>,
) -> Result<()> {
    #[cfg(feature = "fleet-core")]
    if let Some(path) = fleet_setup {
        let provision = std::sync::Arc::new(ferroc::fleet::setup_config::SetupProvision::load(
            &path,
            &creds.device_id,
        )?);
        if provision.mcp_transfer_requested() {
            runtime.open_fleet_mcp(provision.clone(), 8)?;
        }
        return transport::run_with_setup(runtime, creds, &provision, once).await;
    }
    transport::run(runtime, creds, once).await
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let roots = if cli.allow_dir.is_empty() {
        vec![std::env::current_dir()?]
    } else {
        cli.allow_dir
    };
    let mut policy = Policy::new(roots, cli.allow_shell)?;
    policy.allow_transfers = cli.allow_transfers || !cli.no_transfers;
    if let Commands::Agent {
        proxy,
        no_proxy,
        ca_cert,
        ..
    } = &cli.command
    {
        let dedicated = if *no_proxy || proxy.is_some() {
            None
        } else {
            match std::env::var("FERROC_PROXY") {
                Ok(v) => Some(v),
                Err(std::env::VarError::NotPresent) => None,
                Err(std::env::VarError::NotUnicode(_)) => {
                    bail!("FERROC_PROXY must be valid Unicode (value omitted)")
                }
            }
        };
        let mut network = Network::select(proxy.as_deref(), *no_proxy, dedicated.as_deref())?;
        if let Some(path) = ca_cert {
            network = network.with_ca_file(path)?;
        }
        policy.network = network;
    }
    let runtime = Arc::new(Runtime::new(policy));
    let is_relay = matches!(&cli.command, Commands::Relay { .. });
    let run = async {
        match cli.command {
            #[cfg(feature = "fleet-core")]
            Commands::Fleet(args) => {
                ensure!(
                    runtime.policy.allow_transfers,
                    "fleet configuration disabled by --no-transfers"
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ferroc::fleet::admin_cli::run(args)?)?
                );
            }
            #[cfg(feature = "fleet-core")]
            Commands::FleetDir(args) => {
                ferroc::fleet::directory_cli::run(&runtime, args, &mut std::io::stdout().lock())?;
            }
            #[cfg(feature = "fleet-core")]
            Commands::FleetRelease(args) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ferroc::fleet::release_cli::run(
                        &runtime, args
                    )?)?
                );
            }
            #[cfg(feature = "fleet-core")]
            Commands::FleetInventory(args) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ferroc::fleet::inventory_cli::run(
                        &runtime, args
                    )?)?
                );
            }
            Commands::Tools => println!(
                "{}",
                serde_json::to_string_pretty(&ferroc::runtime::tools())?
            ),
            Commands::Stdio => ferroc::stdio::serve(runtime.clone()).await?,
            Commands::Relay {
                bind,
                public_url,
                db,
                admin_password,
                #[cfg(feature = "fleet-core")]
                fleet_setup,
                #[cfg(feature = "fleet-core")]
                fleet_data_config,
            } => {
                #[cfg(feature = "fleet-core")]
                let routes = fleet_data_config
                    .as_deref()
                    .map(ferroc::fleet::route_control::ApprovedDataRoutes::load)
                    .transpose()?;
                let relay = ferroc::relay::Relay::new(&db, &public_url, &admin_password)?;
                let listener = tokio::net::TcpListener::bind(bind).await?;
                eprintln!(
                    "ferroc native relay preview listening on {}",
                    listener.local_addr()?
                );
                let shutdown = relay.clone();
                #[cfg(feature = "fleet-core")]
                let router = if let Some(routes) = routes {
                    relay.router_with_approved_routes(routes)
                } else if fleet_setup {
                    relay.router_with_setup()
                } else {
                    relay.router()
                };
                #[cfg(not(feature = "fleet-core"))]
                let router = relay.router();
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move {
                        let _ = tokio::signal::ctrl_c().await;
                        shutdown.disconnect_all();
                    })
                    .await?;
            }
            Commands::Call { tool, args } => {
                let result = runtime.call(&tool, serde_json::from_str(&args)?).await;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if result.is_error == Some(true) {
                    bail!("tool failed");
                }
            }
            Commands::Agent {
                relay,
                name,
                token,
                device_id,
                home,
                once,
                proxy: _,
                no_proxy: _,
                ca_cert: _,
                #[cfg(feature = "fleet-core")]
                fleet_setup,
            } => {
                eprintln!(
                    "agent outbound network: {}",
                    runtime.policy.network.describe()
                );
                let home = home
                    .or_else(|| {
                        std::env::var_os("USERPROFILE")
                            .or_else(|| std::env::var_os("HOME"))
                            .map(|p| PathBuf::from(p).join(".ferroc"))
                    })
                    .context("set --home or FERROC_HOME")?;
                let path = home.join("device.json");
                let creds = if let Some(token) = token {
                    let relay = relay.context("--token requires --relay")?;
                    let id = device_id.context("--token requires --device-id")?;
                    ensure!(
                        !token.is_empty() && !id.is_empty(),
                        "token and device id must not be empty"
                    );
                    Credentials {
                        relay_url: transport::relay_url(&relay)?.to_string(),
                        device_id: id,
                        device_token: token,
                        name,
                        paired_at: "manual".into(),
                    }
                } else if let Some(saved) = transport::load_credentials(&path).await? {
                    if let Some(relay) = relay {
                        ensure!(
                            transport::relay_url(&relay)?
                                == transport::relay_url(&saved.relay_url)?,
                            "saved credentials belong to another relay; use another --home"
                        );
                    }
                    transport::relay_url(&saved.relay_url)?;
                    saved
                } else {
                    #[cfg(feature = "fleet-core")]
                    ensure!(
                        fleet_setup.is_none(),
                        "--fleet-setup requires existing paired credentials; pair without setup first"
                    );
                    let relay =
                        relay.context("no saved credentials; specify --relay <HTTPS URL>")?;
                    transport::pair_with_network(&relay, &name, &path, &runtime.policy.network)
                        .await?
                };
                run_agent(
                    runtime.clone(),
                    &creds,
                    once,
                    #[cfg(feature = "fleet-core")]
                    fleet_setup,
                )
                .await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    let result = if is_relay {
        run.await
    } else {
        tokio::select! {r=run=>r,_=tokio::signal::ctrl_c()=>Ok(())}
    };
    runtime.shutdown().await;
    result
}
