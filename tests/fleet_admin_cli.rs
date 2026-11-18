#![cfg(feature = "fleet-core")]
//! Actual CLI subprocesses. PUBLIC test wrapping material, no network.
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};
const KEY: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const FLEET: &str = "77777777-7777-4777-8777-777777777777";
fn run_key(root: &Path, device: &str, args: &[&str], key: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args([
            "fleet",
            "--store",
            root.to_str().unwrap(),
            "--fleet-id",
            FLEET,
            "--device-id",
            device,
            "--wrapping-key-env",
            "FERROC_TEST_WRAP",
        ])
        .args(args)
        .env("FERROC_TEST_WRAP", key)
        .output()
        .unwrap()
}
fn run(root: &Path, device: &str, args: &[&str]) -> Output {
    run_key(root, device, args, KEY)
}
fn ok(out: Output) -> Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["localOnly"], true);
    assert_eq!(value["mcpFleetToolsEnabled"], false);
    assert!(!String::from_utf8_lossy(&out.stdout).contains(KEY));
    value["result"].clone()
}
fn enroll(root: &Path, device: &str, peer: &str, identity: &Value) -> Output {
    run(
        root,
        device,
        &[
            "peer",
            "enroll",
            "--peer-device",
            peer,
            "--label",
            peer,
            "--public-key",
            identity["publicKeyHex"].as_str().unwrap(),
            "--expected-fingerprint",
            identity["fingerprint"].as_str().unwrap(),
        ],
    )
}
fn pair() -> (tempfile::TempDir, PathBuf, Value) {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    ok(run(&a, "a", &["init"]));
    let bi = ok(run(&b, "b", &["init"]));
    ok(enroll(&a, "a", "b", &bi));
    (tmp, a, bi)
}

#[test]
fn cli_setup_flags_are_explicit_and_require_prior_pairing() {
    for subcommand in ["relay", "agent"] {
        let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
            .args([subcommand, "--help"])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("--fleet-setup"));
    }
    let root = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args([
            "agent",
            "--no-proxy",
            "--home",
            root.path().to_str().unwrap(),
            "--relay",
            "https://example.invalid",
            "--fleet-setup",
            "missing.json",
        ])
        .env_remove("FERROC_TOKEN")
        .env_remove("FERROC_DEVICE_ID")
        .env_remove("FERROC_FLEET_SETUP")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("requires existing paired credentials"),
        "{err}"
    );
    assert!(!err.contains("Pair device"));
    assert!(!root.path().join("device.json").exists());
}

#[test]
fn cli_native_default_protection_never_falls_back_to_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("identity");
    let command = |action: &str| {
        Command::new(env!("CARGO_BIN_EXE_ferroc"))
            .args([
                "fleet",
                "--store",
                root.to_str().unwrap(),
                "--fleet-id",
                FLEET,
                "--device-id",
                "a",
                action,
            ])
            .output()
            .unwrap()
    };
    if cfg!(windows) {
        let identity = ok(command("init"));
        assert_eq!(ok(command("identity")), identity);
        let raw = std::fs::read(root.join("identity.fid")).unwrap();
        // Backend isolation, not an ASCII-substring proxy for encryption.
        assert!(!run_key(&root, "a", &["identity"], KEY).status.success());
        assert_eq!(raw, std::fs::read(root.join("identity.fid")).unwrap());
    } else {
        assert!(!command("init").status.success());
        assert!(!root.exists(), "no implicit non-Windows plaintext backend");
    }
}

#[test]
fn cli_init_show_is_persistent_and_never_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("identity");
    let first = ok(run(&root, "a", &["init"]));
    assert_eq!(first["publicKeyHex"].as_str().unwrap().len(), 64);
    assert_eq!(first["fingerprint"].as_str().unwrap().len(), 64);
    let before = std::fs::read(root.join("identity.fid")).unwrap();
    assert!(!run(&root, "a", &["init"]).status.success());
    assert_eq!(ok(run(&root, "a", &["identity"])), first);
    assert_eq!(before, std::fs::read(root.join("identity.fid")).unwrap());
}
#[test]
fn cli_peer_requires_explicit_matching_fingerprint_no_tofu() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    ok(run(&a, "a", &["init"]));
    let bi = ok(run(&b, "b", &["init"]));
    let public = bi["publicKeyHex"].as_str().unwrap();
    assert!(
        !run(
            &a,
            "a",
            &[
                "peer",
                "enroll",
                "--peer-device",
                "b",
                "--label",
                "b",
                "--public-key",
                public
            ]
        )
        .status
        .success()
    );
    let mut wrong = bi.clone();
    wrong["fingerprint"] = json!("00".repeat(32));
    assert!(!enroll(&a, "a", "b", &wrong).status.success());
    assert_eq!(
        ok(run(&a, "a", &["peer", "list"]))["peers"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(ok(enroll(&a, "a", "b", &bi))["admission"], "created");
    assert_eq!(ok(enroll(&a, "a", "b", &bi))["admission"], "existing");
    let peers = ok(run(&a, "a", &["peer", "list"]));
    assert_eq!(peers["peers"][0]["fingerprint"], bi["fingerprint"]);
}
#[test]
fn cli_endpoint_lifecycle_and_revoke_order_are_explicit() {
    let (_tmp, a, bi) = pair();
    let fp = bi["fingerprint"].as_str().unwrap();
    let set = |url: &str| {
        run(
            &a,
            "a",
            &[
                "endpoint",
                "set",
                "--peer-device",
                "b",
                "--slot",
                "primary",
                "--url",
                url,
                "--expected-fingerprint",
                fp,
            ],
        )
    };
    ok(set("https://relay.example:8441"));
    assert!(!set("http://nonloopback.example").status.success());
    ok(set("https://fallback.example"));
    assert_eq!(
        ok(run(&a, "a", &["endpoint", "list", "--peer-device", "b"]))["endpoints"][0]["url"],
        "https://fallback.example"
    );
    let revoke = || {
        run(
            &a,
            "a",
            &[
                "peer",
                "revoke",
                "--peer-device",
                "b",
                "--expected-fingerprint",
                fp,
            ],
        )
    };
    assert!(
        !revoke().status.success(),
        "do not orphan an approved endpoint on ordinary revoke"
    );
    ok(run(
        &a,
        "a",
        &[
            "endpoint",
            "clear",
            "--peer-device",
            "b",
            "--slot",
            "primary",
            "--expected-fingerprint",
            fp,
        ],
    ));
    ok(revoke());
    assert!(
        ok(run(&a, "a", &["peer", "list"]))["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
#[test]
fn cli_wrong_key_or_corruption_never_regenerates_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("identity");
    ok(run(&root, "a", &["init"]));
    let path = root.join("identity.fid");
    let before = std::fs::read(&path).unwrap();
    assert!(
        !run_key(&root, "a", &["identity"], &"43".repeat(32))
            .status
            .success()
    );
    assert!(!run(&root, "other-device", &["identity"]).status.success());
    assert_eq!(before, std::fs::read(&path).unwrap());
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(!run(&root, "a", &["identity"]).status.success());
    assert!(!run(&root, "a", &["init"]).status.success());
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
}
#[test]
fn cli_wrapping_key_errors_do_not_echo_secret_values() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("identity");
    let secret = "NOT_HEX_SUPER_SECRET_SENTINEL_DO_NOT_ECHO";
    let out = run_key(&root, "a", &["init"], secret);
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
    assert!(!String::from_utf8_lossy(&out.stdout).contains(secret));
    assert!(!root.exists());
    let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args([
            "fleet",
            "--store",
            root.to_str().unwrap(),
            "--fleet-id",
            FLEET,
            "--device-id",
            "a",
            "--wrapping-key-env",
            "FERROC_TEST_MISSING_WRAP",
            "init",
        ])
        .env_remove("FERROC_TEST_MISSING_WRAP")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!root.exists());
}
#[test]
fn cli_no_transfers_rejects_configuration_before_creating_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("identity");
    let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args([
            "--no-transfers",
            "fleet",
            "--store",
            root.to_str().unwrap(),
            "--fleet-id",
            FLEET,
            "--device-id",
            "a",
            "--wrapping-key-env",
            "FERROC_TEST_WRAP",
            "init",
        ])
        .env("FERROC_TEST_WRAP", KEY)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!root.exists());
    // The old shared tool catalog is unchanged even in a fleet-core build.
    let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .arg("tools")
        .output()
        .unwrap();
    assert!(out.status.success());
    let catalog = String::from_utf8(out.stdout).unwrap();
    for tool in ["send_file", "sync_dir", "transfer_get", "transfer_cancel"] {
        assert!(
            !catalog.contains(&format!("\"{tool}\"")),
            "premature fleet tool exposure"
        );
    }
}
