//! Rust-only integration: actual relay + agent OS processes. No Node/imported upstream.
//! FERROC_TEST_BINARY may select the independently hashed release executable.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ferroc::store::Store;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

async fn as_json(r: reqwest::Response) -> Value {
    let status = r.status();
    let text = r.text().await.unwrap();
    assert!(status.is_success(), "HTTP {status}: {text}");
    serde_json::from_str(&text).unwrap()
}
fn csrf(html: &str) -> String {
    regex::Regex::new("name=csrf value=\"([^\"]+)\"")
        .unwrap()
        .captures(html)
        .expect("csrf form")[1]
        .to_owned()
}
fn unpack(r: &Value) -> Value {
    assert_ne!(r["result"]["isError"], true, "{r}");
    serde_json::from_str(r["result"]["content"][0]["text"].as_str().expect("text")).unwrap()
}
async fn rpc(
    c: &reqwest::Client,
    base: &str,
    token: &str,
    id: i64,
    method: &str,
    params: Value,
) -> Value {
    as_json(
        c.post(format!("{base}/mcp"))
            .bearer_auth(token)
            .json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .send()
            .await
            .unwrap(),
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_oauth_pairing_mcp_admin_revocation() {
    let scratch = tempfile::tempdir().unwrap();
    let work = scratch.path().join("work");
    std::fs::create_dir(&work).unwrap();
    // Reserve loopback briefly; a competing binder causes a clear child/health failure, not a retry loop.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = listener.local_addr().unwrap().to_string();
    drop(listener);
    let base = format!("http://{bind}");
    let db = scratch.path().join("relay.sqlite");
    let binary = std::env::var_os("FERROC_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_ferroc").into());
    let binary = binary.canonicalize().expect("native test executable");
    eprintln!("native relay AND agent binary: {}", binary.display());
    let mut relay = Command::new(&binary)
        .current_dir(&work)
        .args([
            "relay",
            "--bind",
            &bind,
            "--public-url",
            &base,
            "--db",
            db.to_str().unwrap(),
        ])
        .env("FERROC_ADMIN_PASSWORD", "native-only-test-password-123")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let c = reqwest::Client::builder()
        // Keep recommended scrypt N=2^17/r=8/p=1 even in unoptimized tests.
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            assert!(
                relay.try_wait().unwrap().is_none(),
                "native relay process exited before readiness"
            );
            if let Ok(r) = c
                .get(format!("{base}/health"))
                .timeout(Duration::from_secs(1))
                .send()
                .await
                && r.status().is_success()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("relay readiness including unoptimized scrypt setup");
    for (path, content_type, expected) in [
        ("/favicon.ico", "image/x-icon", ferroc::icons::ICO),
        ("/icon.png", "image/png", ferroc::icons::PNG_32),
    ] {
        let response = c.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(response.bytes().await.unwrap().as_ref(), expected);
    }
    let meta = as_json(
        c.get(format!("{base}/.well-known/oauth-authorization-server"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(meta["issuer"], base);
    for invalid in ["/\\evil", "//evil.example", "/\0", "/\t", "/\x7f"] {
        let html = c
            .get(format!("{base}/auth/login"))
            .query(&[("returnTo", invalid)])
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(html.contains("href=/favicon.ico") && html.contains("href=/icon.png"));
        assert!(
            html.contains("name=returnTo value=\"/admin\""),
            "unsafe redirect must be normalized"
        );
    }
    assert_eq!(
        c.post(format!("{base}/mcp"))
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        c.post(format!("{base}/register"))
            .json(&json!({"redirect_uris":["http://public.invalid/callback"]}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let reg=as_json(c.post(format!("{base}/register")).json(&json!({"client_name":"native-test","redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"none"})).send().await.unwrap()).await;
    let client = reg["client_id"].as_str().unwrap();
    let verifier = "v".repeat(64);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let auth_url = format!("{base}/authorize");
    let q = [
        ("response_type", "code"),
        ("client_id", client),
        ("redirect_uri", "https://client.example/callback"),
        ("code_challenge_method", "S256"),
        ("code_challenge", &challenge),
        ("state", "original-state"),
        ("scope", "mcp:tools"),
    ];
    let r = c.get(&auth_url).query(&q).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let login = reqwest::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    let target = login
        .query_pairs()
        .find(|(k, _)| k == "returnTo")
        .unwrap()
        .1
        .to_string();
    assert_eq!(
        c.post(format!("{base}/auth/login"))
            .form(&[
                ("username", "admin"),
                ("password", "native-only-test-password-123")
            ])
            .send()
            .await
            .unwrap()
            .status(),
        400,
        "missing Origin must be denied"
    );
    let r = c
        .post(format!("{base}/auth/login"))
        .header("origin", &base)
        .form(&[
            ("username", "admin"),
            ("password", "native-only-test-password-123"),
            ("returnTo", &target),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let consent_html = c
        .get(format!("{base}{target}"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf_token = csrf(&consent_html);
    let pending = reqwest::Url::parse(&format!("{base}{target}"))
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "pending")
        .unwrap()
        .1
        .to_string();
    assert_eq!(
        c.post(format!("{base}/auth/consent"))
            .header("origin", &base)
            .header("cookie", &cookie)
            .form(&[
                ("pending", pending.as_str()),
                ("decision", "allow"),
                ("csrf", "bad")
            ])
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let r = c
        .post(format!("{base}/auth/consent"))
        .header("origin", &base)
        .header("cookie", &cookie)
        .form(&[
            ("pending", pending.as_str()),
            ("decision", "allow"),
            ("csrf", csrf_token.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let callback = reqwest::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();
    assert!(callback.query_pairs().any(|(k, v)| k == "iss" && v == base));
    assert!(
        callback
            .query_pairs()
            .any(|(k, v)| k == "state" && v == "original-state")
    );
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client),
        ("redirect_uri", "https://client.example/callback"),
        ("code", code.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let mut wrong = form;
    wrong[4] = ("code_verifier", "wrong");
    assert_eq!(
        c.post(format!("{base}/token"))
            .form(&wrong)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let tokens = as_json(
        c.post(format!("{base}/token"))
            .form(&form)
            .send()
            .await
            .unwrap(),
    )
    .await;
    let token = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(
        c.post(format!("{base}/mcp"))
            .bearer_auth(token)
            .header("origin", "https://evil.example")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "cross-origin MCP must be rejected"
    );
    assert_eq!(
        rpc(&c, &base, token, 0, "ping", json!([])).await["error"]["code"],
        -32600
    );
    for invalid in [Value::Null, json!({}), json!(1.5), json!(false)] {
        let bad = as_json(
            c.post(format!("{base}/mcp"))
                .bearer_auth(token)
                .json(&json!({"jsonrpc":"2.0","id":invalid,"method":"ping"}))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(bad["error"]["code"], -32600);
        assert!(bad["id"].is_null());
    }
    assert_eq!(
        c.post(format!("{base}/token"))
            .form(&form)
            .send()
            .await
            .unwrap()
            .status(),
        400,
        "authorization code is one-shot"
    );
    assert_eq!(
        rpc(
            &c,
            &base,
            token,
            1,
            "initialize",
            json!({"protocolVersion":"2025-06-18"})
        )
        .await["result"]["serverInfo"]["name"],
        "ferroc-relay"
    );
    let mut agent = Command::new(&binary)
        .current_dir(&work)
        .args([
            "--allow-dir",
            work.to_str().unwrap(),
            "--allow-shell",
            "agent",
            "--relay",
            &base,
            "--home",
            scratch.path().join("agent-home").to_str().unwrap(),
            "--name",
            "native-agent",
            "--once",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(agent.stderr.take().unwrap()).lines();
    let user_code = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("agent pairing output");
            if let Some(code) = line.strip_prefix("Code: ") {
                break code.to_owned();
            }
        }
    })
    .await
    .unwrap();
    let r = c
        .post(format!("{base}/device/approve"))
        .header("origin", &base)
        .header("cookie", &cookie)
        .form(&[
            ("user_code", user_code.as_str()),
            ("decision", "allow"),
            ("csrf", csrf_token.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let health = as_json(c.get(format!("{base}/health")).send().await.unwrap()).await;
            if health["devices"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let list = rpc(&c, &base, token, 2, "tools/list", json!({})).await;
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 26);
    let devices = unpack(
        &rpc(
            &c,
            &base,
            token,
            3,
            "tools/call",
            json!({"name":"list_devices","arguments":{}}),
        )
        .await,
    );
    let device = devices["devices"][0]["deviceId"].as_str().unwrap();
    let transfer = unpack(
        &rpc(
            &c,
            &base,
            token,
            19,
            "tools/call",
            json!({"name":"prepare_file_transfer","arguments":{"ttlSeconds":60}}),
        )
        .await,
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(transfer["recipientPublicKey"].as_str().unwrap())
            .unwrap()
            .len(),
        44
    );
    for (name, args) in [
        (
            "send_file_transfer",
            json!({"sourcePath":work,"recipientPublicKey":"invalid-public-key"}),
        ),
        (
            "receive_file_transfer",
            json!({"receiveId":transfer["receiveId"],"transferToken":"invalid-token","destinationPath":work.join("must-not-exist")}),
        ),
    ] {
        let bad = rpc(
            &c,
            &base,
            token,
            19,
            "tools/call",
            json!({"name":name,"arguments":args}),
        )
        .await;
        assert_eq!(bad["result"]["isError"], true);
    }
    let file = work.join("native.txt");
    unpack(
        &rpc(
            &c,
            &base,
            token,
            4,
            "tools/call",
            json!({"name":"write_file","arguments":{"path":file,"content":"native full stack"}}),
        )
        .await,
    );
    assert_eq!(
        unpack(
            &rpc(
                &c,
                &base,
                token,
                5,
                "tools/call",
                json!({"name":"read_file","arguments":{"path":file}})
            )
            .await
        )["text"],
        "native full stack"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "native full stack");
    assert_eq!(
        rpc(
            &c,
            &base,
            token,
            6,
            "tools/call",
            json!({"name":"read_file","arguments":{"path":db}})
        )
        .await["result"]["isError"],
        true
    );
    // Exercise every advertised agent handler through the native relay, not direct Runtime calls.
    let sub = work.join("sub");
    let renamed = work.join("renamed.txt");
    let extra = [
        ("get_config", json!({})),
        ("get_usage_stats", json!({})),
        ("get_recent_tool_calls", json!({"maxResults":2})),
        ("read_multiple_files", json!({"paths":[file]})),
        ("get_file_info", json!({"path":file})),
        (
            "edit_block",
            json!({"file_path":file,"old_string":"native full stack","new_string":"native full stack"}),
        ),
        ("create_directory", json!({"path":sub})),
        ("list_directory", json!({"path":work})),
        ("move_file", json!({"source":file,"destination":renamed})),
    ];
    for (name, args) in extra {
        let v = rpc(
            &c,
            &base,
            token,
            20,
            "tools/call",
            json!({"name":name,"arguments":args}),
        )
        .await;
        assert_ne!(v["result"]["isError"], true, "native {name}: {v}");
    }
    let search=unpack(&rpc(&c,&base,token,21,"tools/call",json!({"name":"start_search","arguments":{"path":work,"pattern":"native full stack","searchType":"content","literalSearch":true,"contextLines":0}})).await);
    for (name, args) in [
        ("list_searches", json!({})),
        (
            "get_more_search_results",
            json!({"sessionId":search["sessionId"]}),
        ),
        ("stop_search", json!({"sessionId":search["sessionId"]})),
    ] {
        let v = rpc(
            &c,
            &base,
            token,
            22,
            "tools/call",
            json!({"name":name,"arguments":args}),
        )
        .await;
        assert_ne!(v["result"]["isError"], true, "{name}: {v}");
    }
    #[cfg(windows)]
    let command = "$l=[Console]::ReadLine();[Console]::WriteLine($l);Start-Sleep -Seconds 30";
    #[cfg(not(windows))]
    let command = "read line; printf '%s\\n' \"$line\"; sleep 30";
    let process = unpack(
        &rpc(
            &c,
            &base,
            token,
            23,
            "tools/call",
            json!({"name":"start_process","arguments":{"command":command,"timeout_ms":0}}),
        )
        .await,
    );
    let pid = &process["pid"];
    let interaction=unpack(&rpc(&c,&base,token,24,"tools/call",json!({"name":"interact_with_process","arguments":{"pid":pid,"input":"native-interaction","timeout_ms":1500}})).await);
    assert!(
        interaction["output"]
            .as_str()
            .unwrap()
            .contains("native-interaction")
    );
    for (name, args) in [
        ("read_process_output", json!({"pid":pid})),
        ("list_sessions", json!({})),
        ("list_processes", json!({})),
        ("kill_process", json!({"pid":pid})),
        ("force_terminate", json!({"pid":pid})),
    ] {
        let v = rpc(
            &c,
            &base,
            token,
            25,
            "tools/call",
            json!({"name":name,"arguments":args}),
        )
        .await;
        assert_ne!(v["result"]["isError"], true, "{name}: {v}");
    }
    for (action, paused) in [("pause", true), ("resume", false)] {
        assert_eq!(
            c.post(format!("{base}/admin/device"))
                .header("origin", &base)
                .header("cookie", &cookie)
                .form(&[
                    ("device_id", device),
                    ("action", action),
                    ("csrf", csrf_token.as_str())
                ])
                .send()
                .await
                .unwrap()
                .status(),
            303
        );
        let v = rpc(
            &c,
            &base,
            token,
            7,
            "tools/call",
            json!({"name":"get_config","arguments":{}}),
        )
        .await;
        assert_eq!(v["result"]["isError"] == true, paused);
    }
    assert_eq!(
        c.post(format!("{base}/admin/device"))
            .header("origin", &base)
            .header("cookie", &cookie)
            .form(&[
                ("device_id", device),
                ("action", "rename"),
                ("name", "renamed-native"),
                ("csrf", csrf_token.as_str())
            ])
            .send()
            .await
            .unwrap()
            .status(),
        303
    );
    let admin_html = c
        .get(format!("{base}/admin"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(admin_html.contains("renamed-native"));
    assert!(admin_html.contains("argsHash"));
    assert!(
        !admin_html.contains("native full stack"),
        "audit must not retain argument content"
    );
    let refreshed = as_json(
        c.post(format!("{base}/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client),
                ("refresh_token", refresh),
            ])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_ne!(refreshed["refresh_token"], refresh);
    assert_eq!(
        c.post(format!("{base}/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client),
                ("refresh_token", refresh)
            ])
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    as_json(
        c.post(format!("{base}/revoke"))
            .form(&[("client_id", client), ("token", token)])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        c.post(format!("{base}/mcp"))
            .bearer_auth(token)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        c.post(format!("{base}/auth/clients/delete"))
            .header("origin", &base)
            .header("cookie", &cookie)
            .form(&[("client_id", client), ("csrf", csrf_token.as_str())])
            .send()
            .await
            .unwrap()
            .status(),
        303
    );
    assert!(
        !c.post(format!("{base}/mcp"))
            .bearer_auth(refreshed["access_token"].as_str().unwrap())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert_eq!(
        c.post(format!("{base}/admin/device"))
            .header("origin", &base)
            .header("cookie", &cookie)
            .form(&[
                ("device_id", device),
                ("action", "delete"),
                ("csrf", csrf_token.as_str())
            ])
            .send()
            .await
            .unwrap()
            .status(),
        303
    );
    let status = tokio::time::timeout(Duration::from_secs(10), agent.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
    // Both processes are isolated test fixtures, never installed services; agent was revoked and joined above.
    relay.kill().await.unwrap();
    relay.wait().await.unwrap();
    let mut persisted = std::fs::read(&db).unwrap();
    if let Ok(wal) = std::fs::read(db.with_extension("sqlite-wal")) {
        persisted.extend(wal);
    }
    let credentials: Value = serde_json::from_slice(
        &std::fs::read(scratch.path().join("agent-home/device.json")).unwrap(),
    )
    .unwrap();
    for secret in [
        token,
        refresh,
        code.as_str(),
        refreshed["access_token"].as_str().unwrap(),
        refreshed["refresh_token"].as_str().unwrap(),
        credentials["deviceToken"].as_str().unwrap(),
    ] {
        assert!(
            !persisted
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "SQLite must never contain raw bearer/code material"
        );
    }
}
#[test]
fn sqlite_atomic_take_and_persistence() {
    let d = tempfile::tempdir().unwrap();
    let db = d.path().join("state.sqlite");
    let store = Arc::new(Store::open(&db).unwrap());
    store
        .put("code", "hashed-key", &json!({"safe":"metadata"}), 60)
        .unwrap();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let s = store.clone();
            std::thread::spawn(move || s.take("code", "hashed-key").unwrap().is_some())
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|won| *won)
            .count(),
        1
    );
    store
        .put("device", "fixture", &json!({"name":"persistent"}), 60)
        .unwrap();
    drop(store);
    let reloaded = Store::open(&db).unwrap();
    assert!(
        reloaded
            .insert_new("device", "fixture", &json!({"name":"bad replacement"}), 60)
            .is_err()
    );
    assert_eq!(
        reloaded.get("device", "fixture").unwrap().unwrap()["name"],
        "persistent"
    );
    assert!(reloaded.get("code", "hashed-key").unwrap().is_none());
}
