use ferroc::gui_service::{GuiControl, GuiOptions, GuiService, Phase};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path, time::Duration};

/// SDK oracle against the actual GUI controller HTTP service, NOT evidence of
/// executable GUI input, clipboard, or tray hover. Node is a test dependency only.
#[tokio::test]
#[ignore = "requires Node and the separately checked-out upstream MCP SDK"]
async fn gui_controller_sdk_oracle() {
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let project = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let upstream = project.parent().unwrap().join("better-remote-commander");
    let report = project.join("artifacts/gui-sdk-component.json");
    std::fs::create_dir_all(report.parent().unwrap()).unwrap();
    let service = GuiService::new().unwrap();
    let control = service.control();
    control
        .start(options(root.path(), "127.0.0.1:0".parse().unwrap()))
        .unwrap();
    phase(&control, Phase::Running).await;
    let binary = std::env::current_exe().unwrap();
    let hash = format!("{:x}", Sha256::digest(std::fs::read(binary).unwrap()));
    let output = std::process::Command::new("node")
        .arg(project.join("scripts/gui-http-sdk-probe.mjs"))
        .arg(&project)
        .arg(upstream)
        .env("FERROC_GUI_CLIENT_CONFIG", control.client_config().unwrap())
        .env("FERROC_GUI_BINARY_SHA256", hash)
        .env(
            "FERROC_GUI_PROBE_KIND",
            "GUI-controller-component-test-binary",
        )
        .env("FERROC_GUI_PROBE_WORKDIR", root.path())
        .env("FERROC_GUI_PROBE_REPORT", &report)
        .output();
    // Cleanly close the service even when SDK/client assertions fail.
    control.quit().unwrap();
    phase(&control, Phase::Exited).await;
    service.finish().unwrap();
    let output = output.expect("SDK oracle process");
    assert!(
        output.status.success(),
        "SDK oracle failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(receipt["state"], "passed");
    assert_eq!(receipt["kind"], "GUI-controller-component-test-binary");
    assert_eq!(receipt["checks"].as_array().unwrap().len(), 5);
    println!("SDK controller-component oracle passed; no GUI-input equivalence claimed.");
}

fn options(root: &Path, bind: SocketAddr) -> GuiOptions {
    GuiOptions {
        root: root.to_owned(),
        bind,
        allow_shell: false,
        allow_transfers: false,
        proxy: None,
        no_proxy: true,
        ca_cert: None,
        relay: None,
        home: root.join("credentials"),
        name: "GUI lifecycle test".into(),
        // The lifecycle fixture never arms fleet rounds; the dedicated tests in
        // src/gui_service_tests.rs cover the fail-fast rules for this field.
        #[cfg(feature = "fleet-core")]
        fleet_setup: None,
    }
}
async fn phase(control: &GuiControl, expected: Phase) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let s = control.snapshot();
            if s.phase == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("GUI phase deadline");
}
fn access(control: &GuiControl) -> (String, String) {
    let config: Value =
        serde_json::from_str(&control.client_config().expect("running config")).unwrap();
    (
        config["mcpServers"]["ferroc"]["url"]
            .as_str()
            .unwrap()
            .into(),
        config["mcpServers"]["ferroc"]["headers"]["Authorization"]
            .as_str()
            .unwrap()
            .into(),
    )
}
#[tokio::test]
async fn gui_controller_starts_pauses_stops_restarts_with_rotated_token_and_exits() {
    let root = tempfile::tempdir().unwrap();
    let service = GuiService::new().unwrap();
    let control = service.control();
    assert_eq!(control.snapshot().phase, Phase::Stopped);
    assert!(control.client_config().is_none());
    let opts = options(root.path(), "127.0.0.1:0".parse().unwrap());
    control.start(opts.clone()).unwrap();
    phase(&control, Phase::Running).await;
    let (url, auth) = access(&control);
    assert!(!format!("{:?}", control.snapshot()).contains(&auth));
    assert!(
        control
            .snapshot()
            .detail
            .contains(root.path().file_name().unwrap().to_str().unwrap())
    );
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}});
    control.pause(true);
    assert!(control.snapshot().http.unwrap().paused);
    assert_eq!(
        client
            .post(&url)
            .header("authorization", &auth)
            .header("accept", "application/json, text/event-stream")
            .json(&init)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    control.pause(false);
    assert_eq!(
        client
            .post(&url)
            .header("authorization", &auth)
            .header("accept", "application/json, text/event-stream")
            .json(&init)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    control.stop().unwrap();
    phase(&control, Phase::Stopped).await;
    assert!(control.client_config().is_none());
    assert!(
        client.get(&url).send().await.is_err(),
        "old listener must close"
    );
    control.start(opts).unwrap();
    phase(&control, Phase::Running).await;
    let (new_url, new_auth) = access(&control);
    assert_ne!(auth, new_auth);
    assert_eq!(
        client
            .get(&new_url)
            .header("authorization", auth)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    control.quit().unwrap();
    phase(&control, Phase::Exited).await;
    assert!(control.client_config().is_none());
    tokio::task::spawn_blocking(move || service.finish())
        .await
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn gui_controller_reports_bind_conflicts_and_recovers_without_fallback_port() {
    let root = tempfile::tempdir().unwrap();
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service = GuiService::new().unwrap();
    let control = service.control();
    control
        .start(options(root.path(), occupied.local_addr().unwrap()))
        .unwrap();
    phase(&control, Phase::Failed).await;
    assert!(control.snapshot().detail.contains("端口"));
    assert!(control.snapshot().endpoint.is_none());
    assert!(!control.snapshot().has_runtime);
    assert!(control.client_config().is_none());
    control
        .start(options(root.path(), "0.0.0.0:3211".parse().unwrap()))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !control.snapshot().detail.contains("loopback") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    control
        .start(options(root.path(), "127.0.0.1:0".parse().unwrap()))
        .unwrap();
    phase(&control, Phase::Running).await;
    control.quit().unwrap();
    phase(&control, Phase::Exited).await;
    tokio::task::spawn_blocking(move || service.finish())
        .await
        .unwrap()
        .unwrap();
}
