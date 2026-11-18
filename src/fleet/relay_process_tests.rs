//! Test-executable workers only: explicit public seeds + local approved time,
//! NOT operational grant issuance/registration and not a production CLI mode.
use super::*;
use serde::{Deserialize, Serialize};
use std::io::Write;
#[derive(Serialize, Deserialize)]
struct Setup {
    /// Local working root. Optional so one job/grant pair can be reused by
    /// several hosts that each keep their own directories.
    root: Option<std::path::PathBuf>,
    job: JobSpec,
    grant: FileGrant,
}
#[derive(Serialize, Deserialize)]
struct Rendezvous {
    url: String,
    source: String,
    target: String,
}
fn worker_root(setup: &Setup) -> std::path::PathBuf {
    std::env::var_os("FERROC_FLEET_TEST_ROOT")
        .map(std::path::PathBuf::from)
        .or_else(|| setup.root.clone())
        .expect("worker root missing")
}
fn save_private(path: &Path, value: &impl Serialize) {
    let mut f = new_private(path).unwrap();
    serde_json::to_writer(&mut f, value).unwrap();
    f.flush().unwrap();
    f.sync_all().unwrap();
}
#[test]
#[ignore = "invoked only by explicit three-process controller"]
fn relay_process_worker() {
    let role = match std::env::var("FERROC_FLEET_TEST_ROLE") {
        Ok(v) => v,
        Err(_) => return,
    };
    // The setup role mints the job/grant pair, so it cannot depend on a config
    // file that does not exist yet.
    if role == "setup" {
        let root = std::env::var_os("FERROC_FLEET_TEST_ROOT")
            .map(std::path::PathBuf::from)
            .expect("setup role needs FERROC_FLEET_TEST_ROOT");
        std::fs::create_dir_all(&root).unwrap();
        let size: usize = std::env::var("FERROC_FLEET_TEST_SIZE")
            .unwrap()
            .parse()
            .unwrap();
        let source = std::env::var("FERROC_FLEET_TEST_SOURCE_PATH").unwrap();
        let destination = std::env::var("FERROC_FLEET_TEST_DEST_PATH").unwrap();
        let digest = fixture_digest(size as u64);
        let g = grant_for_metadata(&source, &destination, size as u64, digest);
        save_private(
            &root.join("setup.json"),
            &Setup {
                root: None,
                job: g.job().clone(),
                grant: g.grant().clone(),
            },
        );
        let sha = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        println!("FLEET_SETUP bytes={size} sha={sha}");
        return;
    }
    let Some(config) = std::env::var_os("FERROC_FLEET_TEST_CONFIG") else {
        return;
    };
    let setup: Setup = serde_json::from_reader(std::fs::File::open(config).unwrap()).unwrap();
    let root = worker_root(&setup);
    let root = &root;
    let g = setup
        .grant
        .validate_for_profile(setup.job, fixture_profile())
        .unwrap();
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    match role.as_str() {
        "relay" => {
            executor.block_on(async {
                let listener = tokio::net::TcpListener::bind(
                    std::env::var("FERROC_FLEET_TEST_BIND")
                        .unwrap_or_else(|_| "127.0.0.1:0".into()),
                )
                .await
                .unwrap();
                // A cross-host run advertises a URL the peers can dial; the
                // loopback default keeps the local three-process test intact.
                let url = std::env::var("FERROC_FLEET_TEST_URL")
                    .unwrap_or_else(|_| format!("http://{}", listener.local_addr().unwrap()));
                let init_started = std::time::Instant::now();
                eprintln!("FLEET_RELAY_INIT_START");
                let relay = Relay::new(
                    &root.join("relay.db"),
                    &url,
                    "PUBLIC TEST admin password only",
                )
                .unwrap();
                eprintln!(
                    "FLEET_RELAY_INIT_DONE elapsed_ms={}",
                    init_started.elapsed().as_millis()
                );
                devices(&relay);
                let f = Arc::new(FleetRelay::new());
                let tickets = f
                    .approve_local(&g, "source-A", "target-B", fixture_window().2)
                    .unwrap();
                save_private(
                    &root.join("rendezvous.json"),
                    &Rendezvous {
                        url,
                        source: tickets.source.expose_secret().into(),
                        target: tickets.target.expose_secret().into(),
                    },
                );
                let (tx, rx) = tokio::sync::oneshot::channel();
                if std::env::var_os("FERROC_FLEET_TEST_RELAY_FOREVER").is_some() {
                    // Cross-host relay has no controlling terminal: wait for a signal.
                    tokio::spawn(async move {
                        let _ = tokio::signal::ctrl_c().await;
                        let _ = tx.send(());
                    });
                } else {
                    std::thread::spawn(move || {
                        let mut line = String::new();
                        let _ = std::io::stdin().read_line(&mut line);
                        let _ = tx.send(());
                    });
                }
                let shutdown = f.clone();
                let server = axum::serve(listener, relay.router_with_fleet(f))
                    .with_graceful_shutdown(async move {
                        let _ = rx.await;
                        shutdown.close();
                    });
                // Signal only readiness, NEVER the header ticket/credentials to stdout.
                println!("FLEET_RELAY_READY");
                std::io::stdout().flush().unwrap();
                server.await.unwrap();
            });
        }
        "source" => {
            if std::env::var_os("FERROC_FLEET_TEST_WRITE_INPUT").is_some() {
                let p = std::path::PathBuf::from(&g.job().source_path);
                write_fixture_input(&p, g.job().bytes_total).unwrap();
            }
            let c: Rendezvous =
                serde_json::from_reader(std::fs::File::open(root.join("rendezvous.json")).unwrap())
                    .unwrap();
            let metadata = g.clone();
            let source_runtime = Arc::new(Runtime::new(
                Policy::new(vec![root.join("source")], false).unwrap(),
            ));
            let source_owner = source_runtime.clone();
            let work = async move {
                let window = SourceWindow::new(
                    source_owner.open_fleet_source(records(&g, Direction::SourceToTarget))?,
                    8,
                )?;
                let socket = link(&c.url, &c.source, &g, Direction::SourceToTarget).await?;
                let observation = run_source(window, socket).await?;
                // The parent owns shutdown; a worker must never wait for its
                // own task table to drain itself.
                Ok::<_, anyhow::Error>(observation)
            };
            let observation = executor.block_on(async {
                if metadata.lease_profile() == crate::fleet::job::LeaseProfile::SingleOwner {
                    // Real future ownership/polling, not an inline RPC-sized await.
                    // PUBLIC test provisioning only; no product MCP dispatch.
                    let tasks = source_runtime.open_fleet_tasks(1).unwrap();
                    let id = tasks
                        .launch(metadata.clone(), fixture_window().2, move |_| work)
                        .unwrap();
                    println!("SOURCE_TASK_ADMITTED id={id}");
                    let snapshot = tasks.wait(id).await.unwrap();
                    save_private(&root.join("source-task.json"), &snapshot);
                    assert_eq!(
                        snapshot.phase,
                        crate::fleet::transfer_tasks::TaskPhase::PeerReportedCompleted
                    );
                    assert!(!snapshot.remote_cleanup_confirmed);
                    assert!(!tasks.request_cancel(id).unwrap());
                    source_runtime.shutdown().await;
                    let shared = source_runtime.fleet_tasks().unwrap().unwrap();
                    let retained = shared.get(id).unwrap();
                    assert_eq!(retained.id, snapshot.id);
                    assert_eq!(retained.phase, snapshot.phase);
                    let refused = shared
                        .launch(metadata, fixture_window().2, |_| std::future::pending())
                        .unwrap_err()
                        .to_string();
                    assert!(refused.contains("stopped"));
                    save_private(
                        &root.join("source-runtime-task.json"),
                        &serde_json::json!({
                            "taskId":id, "owner":"Runtime", "shutdownCompleted":true,
                            "historyRetained":true, "lateAdmissionRejected":true
                        }),
                    );
                    snapshot.peer_observation.unwrap()
                } else {
                    let observation = work.await.unwrap();
                    source_runtime.shutdown().await;
                    observation
                }
            });
            save_private(&root.join("source-observation.json"), &observation);
            println!("SOURCE_PEER_REPORTED bytes={}", observation.receipt().size);
        }
        #[cfg(windows)]
        "target" => {
            let c: Rendezvous =
                serde_json::from_reader(std::fs::File::open(root.join("rendezvous.json")).unwrap())
                    .unwrap();
            let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
            std::fs::create_dir_all(root.join("target")).unwrap();
            if !root.join("target/host.db").exists() {
                drop(new_private(&root.join("target/host.db")).unwrap());
            }
            let host = rt
                .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
                .unwrap();
            host.resume().unwrap();
            let receiver = host
                .admit_receiver(records(&g, Direction::TargetToSource))
                .unwrap();
            let receipt = executor.block_on(async {
                let socket = link(&c.url, &c.target, &g, Direction::TargetToSource)
                    .await
                    .unwrap();
                super::super::super::relay_io::run_target(receiver, socket)
                    .await
                    .unwrap()
            });
            assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
            host.close().unwrap();
            save_private(&root.join("target-receipt.json"), &receipt);
            println!("TARGET_LOCAL_SETTLED bytes={} slot_debt=0", receipt.size);
        }
        #[cfg(not(windows))]
        "target" => panic!("target role needs the Windows publish sink"),
        _ => panic!("unknown TEST worker role"),
    }
}
async fn spawn_worker(
    exe: &Path,
    config: &Path,
    root: &Path,
    role: &str,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> (tokio::process::Child, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let stderr = std::fs::File::create(root.join(format!("{role}.stderr.log"))).unwrap();
    let mut child = tokio::process::Command::new(exe)
        .args([
            "--exact",
            "fleet::relay_channel::tests::process_tests::relay_process_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("FERROC_FLEET_TEST_CONFIG", config)
        .env("FERROC_FLEET_TEST_ROLE", role)
        .env("RUST_BACKTRACE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(stderr)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let log = root.join(format!("{role}.stdout.log"));
    let logger = tokio::spawn(async move {
        let mut f = tokio::fs::File::create(log).await.unwrap();
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        let mut ready = ready;
        while let Some(line) = lines.next_line().await.unwrap() {
            f.write_all(line.as_bytes()).await.unwrap();
            f.write_all(b"\n").await.unwrap();
            f.flush().await.unwrap();
            if line == "FLEET_RELAY_READY"
                && let Some(tx) = ready.take()
            {
                let _ = tx.send(());
            }
        }
    });
    (child, logger)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release-only actual relay+Source+Target three OS processes; explicit public test provisioning"]
async fn three_process_real_relay_file_roundtrips() {
    use tokio::io::AsyncWriteExt;
    let exe = std::env::current_exe().unwrap();
    let exe_sha = format!("{:x}", Sha256::digest(std::fs::read(&exe).unwrap()));
    for size in [0usize, 1, 131073, 8 * 1024 * 1024] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        make_directory(&root).unwrap();
        make_directory(&root.join("source")).unwrap();
        make_directory(&root.join("target")).unwrap();
        let data = vec![0x39; size];
        std::fs::write(root.join("source/input.bin"), &data).unwrap();
        drop(new_private(&root.join("target/host.db")).unwrap());
        let g = grant(&root, &data);
        save_private(
            &root.join("setup.json"),
            &Setup {
                root: Some(root.clone()),
                job: g.job().clone(),
                grant: g.grant().clone(),
            },
        );
        let config = root.join("setup.json");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (mut relay, relay_logger) =
            spawn_worker(&exe, &config, &root, "relay", Some(ready_tx)).await;
        let relay_pid = relay.id().unwrap();
        let mut children = Vec::new();
        let mut loggers = vec![relay_logger];
        let mut child_pids = Vec::new();
        let start = Instant::now();
        let result = async {
            tokio::time::timeout(Duration::from_secs(30), ready_rx).await.context("relay initialization/readiness timeout")?.context("relay readiness closed")?;
            for role in ["target", "source"] {
                let (child, logger) = spawn_worker(&exe, &config, &root, role, None).await;
                child_pids.push(child.id().unwrap());children.push(child);loggers.push(logger);
            }
            let target_pid=child_pids[0];let source_pid=child_pids[1];
            ensure!(source_pid!=target_pid && source_pid!=relay_pid && target_pid!=relay_pid,"not three distinct processes");
            let source=tokio::time::timeout(Duration::from_secs(35),children[1].wait()).await.context("Source process deadline")??;
            let target=tokio::time::timeout(Duration::from_secs(5),children[0].wait()).await.context("Target process drain deadline")??;
            ensure!(source.success() && target.success(),"worker failure; inspect per-role raw logs");
            ensure!(std::fs::read(root.join("target/output.bin"))?==data && std::fs::read(root.join("source/input.bin"))?==data,"three-process byte mismatch");
            let source:serde_json::Value=serde_json::from_reader(std::fs::File::open(root.join("source-observation.json"))?)?;
            let target:serde_json::Value=serde_json::from_reader(std::fs::File::open(root.join("target-receipt.json"))?)?;
            ensure!(source["receipt"]==target,"Source peer observation does not match actual Target local receipt");
            println!("THREE_PROCESS bytes={size} relay_pid={relay_pid} source_pid={source_pid} target_pid={target_pid} elapsed_ms={} TEST_SHA256={exe_sha} realLoopback+actualSourceFile+v9Target+finalACK/notTwoHost/publicFixtureProvisioning",start.elapsed().as_millis());
            Ok::<_,anyhow::Error>(())
        }.await;
        // Always stop and WAIT original owned children before deleting any fixture.
        for c in &mut children {
            if c.try_wait().unwrap().is_none() {
                c.kill().await.unwrap();
            }
            let _ = c.wait().await.unwrap();
        }
        if let Some(mut stdin) = relay.stdin.take() {
            let _ = stdin.write_all(b"stop\n").await;
        }
        match tokio::time::timeout(Duration::from_secs(5), relay.wait()).await {
            Ok(v) => {
                assert!(v.unwrap().success());
            }
            Err(_) => {
                relay.kill().await.unwrap();
                relay.wait().await.unwrap();
            }
        }
        // Child exit is not stdout EOF/flush: join every transfer task before copying evidence.
        for logger in loggers {
            logger.await.unwrap();
        }
        if let Some(out) = std::env::var_os("FERROC_FLEET_TEST_OUTPUT") {
            let dest = std::path::PathBuf::from(out).join(format!("bytes-{size}"));
            std::fs::create_dir_all(&dest).unwrap();
            for entry in std::fs::read_dir(&root).unwrap() {
                let e = entry.unwrap();
                let name = e.file_name();
                let text = name.to_string_lossy();
                if text.ends_with(".log")
                    || text.ends_with("observation.json")
                    || text.ends_with("receipt.json")
                {
                    std::fs::copy(e.path(), dest.join(name)).unwrap();
                }
            }
            std::fs::write(dest.join("provenance.json"),serde_json::to_vec_pretty(&serde_json::json!({"testSha256":exe_sha,"bytes":size,"sourceSha256":format!("{:x}",Sha256::digest(&data)),"relayPid":relay_pid,"childPids":child_pids,"status":if result.is_ok(){"passed"}else{"failed"},"allOwnedChildrenWaited":true,"scope":"three test workers/loopback/public fixture time+keys, not two-host/production"})).unwrap()).unwrap();
        }
        if let Err(e) = result {
            let keep = temp.keep();
            panic!(
                "Three-process failure: {e:#}; retained owned fixture {}",
                keep.display()
            );
        }
    }
}
static FIXTURE_BLOCK: [u8; 65_536] = [0x39; 65_536];
fn fixture_digest(mut size: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    while size > 0 {
        let n = size.min(FIXTURE_BLOCK.len() as u64) as usize;
        h.update(&FIXTURE_BLOCK[..n]);
        size -= n as u64;
    }
    h.finalize().into()
}
fn write_fixture_input(path: &Path, mut size: u64) -> std::io::Result<()> {
    std::fs::create_dir_all(path.parent().expect("source parent"))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    while size > 0 {
        let n = size.min(FIXTURE_BLOCK.len() as u64) as usize;
        f.write_all(&FIXTURE_BLOCK[..n])?;
        size -= n as u64;
    }
    f.sync_all()
}
#[test]
fn streaming_fixture_matches_small_oracle_and_never_overwrites() {
    let root = tempfile::tempdir().unwrap();
    for size in [0, 1, 65_537] {
        let p = root.path().join(format!("{size}.bin"));
        write_fixture_input(&p, size).unwrap();
        let oracle = vec![0x39; size as usize];
        assert_eq!(std::fs::read(&p).unwrap(), oracle);
        assert_eq!(
            fixture_digest(size),
            <[u8; 32]>::from(Sha256::digest(&oracle))
        );
        assert!(write_fixture_input(&p, size).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), oracle);
    }
}
#[test]
fn worker_setup_requires_local_single_owner_opt_in_for_long_grants() {
    for single_owner in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("FERROC_FLEET_TEST_") {
                command.env_remove(k);
            }
        }
        command
            .args([
                "--exact",
                "fleet::relay_channel::tests::process_tests::relay_process_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("FERROC_FLEET_TEST_ROLE", "setup")
            .env("FERROC_FLEET_TEST_ROOT", root.path())
            .env("FERROC_FLEET_TEST_SIZE", "65537")
            .env(
                "FERROC_FLEET_TEST_SOURCE_PATH",
                root.path().join("source/input.bin"),
            )
            .env(
                "FERROC_FLEET_TEST_DEST_PATH",
                root.path().join("target/output.bin"),
            )
            .env("FERROC_FLEET_TEST_DEADLINE_MS", "180100")
            .env("FERROC_FLEET_TEST_LEASE_MS", "180000");
        if single_owner {
            command.env("FERROC_FLEET_TEST_PROFILE", "single-owner");
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.success(),
            single_owner,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let p = root.path().join("setup.json");
        if single_owner {
            let setup: Setup = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            assert_eq!(
                setup.grant.expires_at_ms - setup.grant.issued_at_ms,
                180_000
            );
            assert_eq!(setup.job.sha256, fixture_digest(65_537));
        } else {
            assert!(!p.exists());
        }
    }
}
