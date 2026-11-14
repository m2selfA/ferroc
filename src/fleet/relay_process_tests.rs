//! Test-executable workers only: explicit public seeds + local approved time,
//! NOT operational grant issuance/registration and not a production CLI mode.
use super::*;
use serde::{Deserialize, Serialize};
use std::io::Write;
#[derive(Serialize, Deserialize)]
struct Setup {
    root: std::path::PathBuf,
    job: JobSpec,
    grant: FileGrant,
}
#[derive(Serialize, Deserialize)]
struct Rendezvous {
    url: String,
    source: String,
    target: String,
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
    let Some(config) = std::env::var_os("FERROC_FLEET_TEST_CONFIG") else {
        return;
    };
    let setup: Setup = serde_json::from_reader(std::fs::File::open(config).unwrap()).unwrap();
    let g = setup.grant.validate_for(setup.job).unwrap();
    let role = std::env::var("FERROC_FLEET_TEST_ROLE").unwrap();
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    match role.as_str() {
        "relay" => {
            executor.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let relay = Relay::new(
                    &setup.root.join("relay.db"),
                    &url,
                    "PUBLIC TEST admin password only",
                )
                .unwrap();
                devices(&relay);
                let f = Arc::new(FleetRelay::new());
                let tickets = f
                    .approve_local(&g, "source-A", "target-B", Duration::from_secs(50))
                    .unwrap();
                save_private(
                    &setup.root.join("rendezvous.json"),
                    &Rendezvous {
                        url,
                        source: tickets.source.expose_secret().into(),
                        target: tickets.target.expose_secret().into(),
                    },
                );
                let (tx, rx) = tokio::sync::oneshot::channel();
                std::thread::spawn(move || {
                    let mut line = String::new();
                    let _ = std::io::stdin().read_line(&mut line);
                    let _ = tx.send(());
                });
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
            let c: Rendezvous = serde_json::from_reader(
                std::fs::File::open(setup.root.join("rendezvous.json")).unwrap(),
            )
            .unwrap();
            let rt = Runtime::new(Policy::new(vec![setup.root.join("source")], false).unwrap());
            let window = SourceWindow::new(
                rt.open_fleet_source(records(&g, Direction::SourceToTarget))
                    .unwrap(),
                8,
            )
            .unwrap();
            let observation = executor.block_on(async {
                let socket = link(&c.url, &c.source, &g, Direction::SourceToTarget)
                    .await
                    .unwrap();
                run_source(window, socket).await.unwrap()
            });
            save_private(&setup.root.join("source-observation.json"), &observation);
            println!("SOURCE_PEER_REPORTED bytes={}", observation.receipt().size);
        }
        "target" => {
            let c: Rendezvous = serde_json::from_reader(
                std::fs::File::open(setup.root.join("rendezvous.json")).unwrap(),
            )
            .unwrap();
            let rt = Runtime::new(Policy::new(vec![setup.root.join("target")], false).unwrap());
            let host = rt
                .open_fleet_host(
                    &setup.root.join("target/host.db"),
                    InventoryLimits::default(),
                )
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
            save_private(&setup.root.join("target-receipt.json"), &receipt);
            println!("TARGET_LOCAL_SETTLED bytes={} slot_debt=0", receipt.size);
        }
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
                root: root.clone(),
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
