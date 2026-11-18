use ferroc::{
    config::Policy,
    files,
    protocol::{RelayMessage, ToolResult},
    runtime::{Runtime, tools},
    search::Searches,
    stdio::{Mcp, bounded_line},
    transport::{self, Credentials},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tempfile::TempDir;

fn setup(shell: bool) -> (TempDir, Runtime) {
    let dir = tempfile::tempdir().unwrap();
    let r = Runtime::new(Policy::new(vec![dir.path().to_owned()], shell).unwrap());
    (dir, r)
}
fn data(r: ToolResult) -> Value {
    assert_ne!(r.is_error, Some(true), "{:?}", r);
    serde_json::from_str(r.content[0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn policy_rejects_traversal_and_prefix_sibling() {
    let parent = tempfile::tempdir().unwrap();
    let a = parent.path().join("allowed");
    let sibling = parent.path().join("allowed-other");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&sibling).unwrap();
    let p = Policy::new(vec![a.clone()], false).unwrap();
    assert!(p.resolve(sibling.to_str().unwrap()).is_err());
    assert!(
        p.resolve(a.join("../allowed-other").to_str().unwrap())
            .is_err()
    );
    assert!(p.resolve("relative.txt").is_err());
    assert!(
        p.resolve(a.join("new/nested.txt").to_str().unwrap())
            .is_ok()
    );
    assert!(Policy::new(vec![], false).is_err());
}
#[cfg(unix)]
#[test]
fn policy_rejects_symlink_escape() {
    let (dir, r) = setup(false);
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
    assert!(
        r.policy
            .resolve(dir.path().join("link/file").to_str().unwrap())
            .is_err()
    );
}
#[cfg(windows)]
#[test]
fn policy_rejects_ntfs_alternate_data_stream() {
    let (dir, r) = setup(false);
    assert!(
        r.policy
            .resolve(dir.path().join("a.txt:secret").to_str().unwrap())
            .is_err()
    );
}

#[test]
fn pagination_ranges_and_tail() {
    assert_eq!(files::paginate("a\nb\nc\n", 1, 1), "b");
    assert_eq!(files::paginate("a\nb\nc\n", -2, 1), "b\nc");
    assert_eq!(files::paginate("a", 100, 2), "");
}

#[tokio::test]
async fn files_roundtrip_and_fail_closed_edits() {
    let (dir, r) = setup(false);
    let path = dir.path().join("a.txt");
    data(
        r.call(
            "write_file",
            json!({"path":path,"content":"one\ntwo\ntwo\n"}),
        )
        .await,
    );
    let failed = r
        .call(
            "edit_block",
            json!({"file_path":path,"old_string":"two","new_string":"2"}),
        )
        .await;
    assert_eq!(failed.is_error, Some(true));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\ntwo\n");
    data(
        r.call(
            "edit_block",
            json!({"file_path":path,"old_string":"two","new_string":"2","expected_replacements":2}),
        )
        .await,
    );
    assert_eq!(
        data(r.call("read_file", json!({"path":path,"offset":-2})).await)["text"],
        "2\n2"
    );
    let other = dir.path().join("b.txt");
    std::fs::write(&other, "untouched").unwrap();
    assert_eq!(
        r.call("move_file", json!({"source":path,"destination":other}))
            .await
            .is_error,
        Some(true)
    );
    assert_eq!(std::fs::read_to_string(other).unwrap(), "untouched");
}
#[tokio::test]
async fn directory_move_and_multi_read() {
    let (dir, r) = setup(false);
    let sub = dir.path().join("sub");
    data(r.call("create_directory", json!({"path":sub})).await);
    let from = sub.join("a.txt");
    let to = sub.join("b.txt");
    data(
        r.call("write_file", json!({"path":from,"content":"hello"}))
            .await,
    );
    data(
        r.call(
            "write_file",
            json!({"path":from,"content":" world","mode":"append"}),
        )
        .await,
    );
    data(
        r.call("move_file", json!({"source":from,"destination":to}))
            .await,
    );
    assert_eq!(
        data(r.call("read_multiple_files", json!({"paths":[to]})).await)[0]["text"],
        "hello world"
    );
    assert_eq!(
        data(r.call("get_file_info", json!({"path":to})).await)["size"],
        11
    );
    assert!(
        !data(r.call("list_directory", json!({"path":dir.path()})).await)["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn invalid_args_binary_and_size_limits() {
    let (dir, r) = setup(false);
    let path = dir.path().join("binary.bin");
    std::fs::write(&path, b"a\0b").unwrap();
    for (tool, args) in [
        ("read_file", json!({"path":path})),
        ("read_file", json!({"path":path,"isUrl":true})),
        ("read_file", json!({"path":path,"length":-1})),
        (
            "write_file",
            json!({"path":path,"content":"x","mode":"typo"}),
        ),
        ("read_file", json!({"path":path,"sheet":"0"})),
        ("missing", json!({})),
        ("get_config", json!([])),
    ] {
        assert_eq!(r.call(tool, args).await.is_error, Some(true), "{tool}");
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"a\0b");
    let large = std::fs::File::create(&path).unwrap();
    large.set_len(ferroc::config::MAX_FILE + 1).unwrap();
    assert_eq!(
        r.call("read_file", json!({"path":path})).await.is_error,
        Some(true)
    );
}
#[tokio::test]
async fn shell_and_remote_policy_mutation_denied_by_default() {
    let (_, r) = setup(false);
    assert_eq!(
        r.call("start_process", json!({"command":"echo no","timeout_ms":0}))
            .await
            .is_error,
        Some(true)
    );
    assert_eq!(
        r.call(
            "set_config_value",
            json!({"key":"allowedDirectories","value":[]})
        )
        .await
        .is_error,
        Some(true)
    );
    assert_eq!(
        data(r.call("get_config", json!({})).await)["telemetryEnabled"],
        false
    );
    assert!(!tools().iter().any(|t| t.name == "set_config_value"));
}
#[test]
fn registry_is_unique_and_does_not_advertise_placeholders() {
    let defs = tools();
    let names: std::collections::HashSet<_> = defs.iter().map(|t| &t.name).collect();
    assert_eq!(names.len(), defs.len());
    assert_eq!(defs.len(), 25);
    for t in defs {
        assert_eq!(t.input_schema["type"], "object");
        assert!(!t.description.is_empty());
        assert!(!["write_pdf"].contains(&t.name.as_str()));
    }
}
async fn search_done(s: &Searches, id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let v = s.results(&json!({"sessionId":id,"length":1000})).unwrap();
            if v["done"] == true {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn search_literal_hidden_filter_and_pagination() {
    let (dir, r) = setup(false);
    std::fs::write(dir.path().join("main.rs"), "before\na.b\naXb\na.b\n").unwrap();
    std::fs::write(dir.path().join(".hidden.rs"), "a.b").unwrap();
    let v=r.searches.start(r.policy.clone(),json!({"path":dir.path(),"pattern":"a.b","literalSearch":true,"searchType":"content","filePattern":"*.rs","contextLines":0})).unwrap();
    let id = v["sessionId"].as_str().unwrap();
    let v = search_done(&r.searches, id).await;
    assert_eq!(v["totalResults"], 2);
    assert_eq!(v["results"][0]["lineNumber"], 2);
    assert_eq!(
        r.searches
            .results(&json!({"sessionId":id,"offset":-1}))
            .unwrap()["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        r.searches
            .start(r.policy.clone(), json!({"path":dir.path(),"pattern":"["}))
            .is_err()
    );
    assert!(r.searches.results(&json!({"sessionId":"missing"})).is_err());
}
#[tokio::test]
async fn search_cancellation_and_truncation_are_visible() {
    let (dir, r) = setup(false);
    std::fs::write(dir.path().join("many.txt"), "needle\n".repeat(10000)).unwrap();
    let v = r
        .searches
        .start(
            r.policy.clone(),
            json!({"path":dir.path(),"pattern":"needle","searchType":"content","maxResults":2}),
        )
        .unwrap();
    let id = v["sessionId"].as_str().unwrap();
    let result = search_done(&r.searches, id).await;
    assert_eq!(result["totalResults"], 2);
    assert_eq!(result["truncated"], true);
    let v = r
        .searches
        .start(
            r.policy.clone(),
            json!({"path":dir.path(),"pattern":"needle","searchType":"content"}),
        )
        .unwrap();
    let id = v["sessionId"].as_str().unwrap();
    r.searches.stop(&json!({"sessionId":id})).unwrap();
    assert_eq!(search_done(&r.searches, id).await["done"], true);
}
#[tokio::test]
async fn search_output_byte_budget_is_enforced() {
    let (dir, r) = setup(false);
    std::fs::write(
        dir.path().join("big.txt"),
        ("needle".to_owned() + &"x".repeat(1024) + "\n").repeat(1000),
    )
    .unwrap();
    let v=r.searches.start(r.policy.clone(),json!({"path":dir.path(),"pattern":"needle","searchType":"content","maxResults":10000,"contextLines":20})).unwrap();
    let result = search_done(&r.searches, v["sessionId"].as_str().unwrap()).await;
    assert_eq!(result["truncated"], true);
    assert!(result.to_string().len() < 600 * 1024);
}
#[tokio::test]
async fn mcp_initialization_and_jsonrpc_errors() {
    let (_, r) = setup(false);
    let mut m = Mcp::default();
    assert_eq!(
        m.handle(&r, json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .await
            .unwrap()["error"]["code"],
        -32000
    );
    let init=m.handle(&r,json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-03-26"}})).await.unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert!(
        m.handle(
            &r,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .await
        .is_none()
    );
    assert_eq!(
        m.handle(&r, json!({"jsonrpc":"2.0","id":2,"method":"not-real"}))
            .await
            .unwrap()["error"]["code"],
        -32601
    );
    let defs = m
        .handle(&r, json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}))
        .await
        .unwrap();
    assert_eq!(
        defs["result"]["tools"].as_array().unwrap().len(),
        tools().len()
    );
    assert_eq!(
        m.handle(
            &r,
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"not-real"}})
        )
        .await
        .unwrap()["result"]["isError"],
        true
    );
}
#[tokio::test]
async fn bounded_stdio_rejects_oversized_frames() {
    let mut data = tokio::io::BufReader::new(&b"{}\nnext"[..]);
    assert_eq!(bounded_line(&mut data).await.unwrap().unwrap(), b"{}\n");
    assert_eq!(bounded_line(&mut data).await.unwrap().unwrap(), b"next");
    assert!(bounded_line(&mut data).await.unwrap().is_none());
    let bytes = vec![b'x'; ferroc::protocol::MAX_FRAME + 1];
    let mut input = tokio::io::BufReader::new(bytes.as_slice());
    assert!(bounded_line(&mut input).await.is_err());
}
#[test]
fn protocol_fixtures_match_pinned_upstream() {
    let call:RelayMessage=serde_json::from_value(json!({"type":"call","id":"fixture-1","tool":"read_file","args":{"path":"/tmp/a"},"timeoutMs":2000})).unwrap();
    assert!(matches!(
        call,
        RelayMessage::Call {
            timeout_ms: Some(2000),
            ..
        }
    ));
    let c = Credentials {
        relay_url: "https://example.com".into(),
        device_id: "test".into(),
        device_token: "never-in-hello".into(),
        name: "test".into(),
        paired_at: "manual".into(),
    };
    let h = transport::hello(&c, false);
    assert_eq!(h["protocol"], 1);
    assert_eq!(h["device"]["deviceId"], "test");
    // The default agent must never advertise a capability it does not serve.
    assert!(h.get("fleetSetupProtocol").is_none());
    let provisioned = transport::hello(&c, true);
    assert_eq!(provisioned["fleetSetupProtocol"], 1);
    assert!(!h.to_string().contains("never-in-hello"));
    assert!(transport::relay_url("http://example.com").is_err());
    assert!(transport::relay_url("https://user:pass@example.com").is_err());
    assert!(transport::relay_url("https://example.com?token=x").is_err());
    assert_eq!(
        transport::websocket_url("http://127.0.0.1:3000/prefix")
            .unwrap()
            .as_str(),
        "ws://127.0.0.1:3000/prefix/ws"
    );
}
#[tokio::test]
async fn credentials_are_private_and_not_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.json");
    let c = Credentials {
        relay_url: "https://example.com".into(),
        device_id: "test".into(),
        device_token: "synthetic-test-token".into(),
        name: "test".into(),
        paired_at: "manual".into(),
    };
    assert!(transport::load_credentials(&path).await.unwrap().is_none());
    transport::save_credentials(&path, &c).await.unwrap();
    assert_eq!(
        transport::load_credentials(&path)
            .await
            .unwrap()
            .unwrap()
            .device_token,
        c.device_token
    );
    assert!(transport::save_credentials(&path, &c).await.is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("icacls.exe")
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success());
        let acl = String::from_utf8_lossy(&out.stdout);
        assert!(
            !acl.contains("(I)"),
            "credential ACL must not inherit grants: {acl}"
        );
    }
}
#[tokio::test]
async fn process_lifecycle_observation_is_not_kill_timeout() {
    let (dir, r) = setup(true);
    #[cfg(windows)]
    let command = "Write-Output 'first'; Start-Sleep -Seconds 30";
    #[cfg(not(windows))]
    let command = "printf 'first\\n'; sleep 30";
    let v = data(
        r.call("start_process", json!({"command":command,"timeout_ms":100}))
            .await,
    );
    let pid = v["pid"].as_u64().unwrap();
    assert_eq!(v["running"], true);
    assert_eq!(
        r.call("kill_process", json!({"pid":1})).await.is_error,
        Some(true)
    );
    data(r.call("force_terminate", json!({"pid":pid})).await);
    let v = data(r.call("read_process_output", json!({"pid":pid})).await);
    assert_eq!(v["running"], false);
    r.shutdown().await;
    drop(dir);
}
#[tokio::test]
async fn process_pagination_does_not_drop_unread_lines() {
    let (_dir, r) = setup(true);
    #[cfg(windows)]
    let command = "1..12 | ForEach-Object { Write-Output $_ }; Start-Sleep -Seconds 30";
    #[cfg(not(windows))]
    let command = "seq 1 12; sleep 30";
    let v = data(
        r.call("start_process", json!({"command":command,"timeout_ms":0}))
            .await,
    );
    let pid = v["pid"].as_u64().unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut seen = Vec::new();
    for _ in 0..4 {
        let v = data(
            r.call("read_process_output", json!({"pid":pid,"length":3}))
                .await,
        );
        seen.extend(v["output"].as_str().unwrap().lines().map(str::to_owned));
    }
    r.shutdown().await;
    assert_eq!(seen, (1..=12).map(|n| n.to_string()).collect::<Vec<_>>());
}
#[tokio::test]
async fn concurrent_file_edits_have_one_winner() {
    let (dir, r) = setup(false);
    let r = Arc::new(r);
    let path = dir.path().join("race.txt");
    std::fs::write(&path, "old").unwrap();
    let mut jobs = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let r = r.clone();
        let path = path.clone();
        jobs.spawn(async move {
            r.call(
                "edit_block",
                json!({"file_path":path,"old_string":"old","new_string":"new"}),
            )
            .await
        });
    }
    let mut successes = 0;
    while let Some(job) = jobs.join_next().await {
        if job.unwrap().is_error != Some(true) {
            successes += 1;
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(std::fs::read_to_string(path).unwrap(), "new");
}
