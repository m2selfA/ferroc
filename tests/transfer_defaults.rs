//! Actual binary policy probes. prepare creates only a volatile key; no provider request.
use serde_json::Value;
use std::process::Command;
fn run(args: &[&str]) -> (bool, Value) {
    let work = tempfile::tempdir().unwrap();
    let binary = std::env::var_os("FERROC_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_ferroc").into());
    let output = Command::new(binary)
        .current_dir(work.path())
        .args(args)
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output.status.success(), value)
}
fn unpack(v: Value) -> Value {
    assert_ne!(v["isError"], true);
    serde_json::from_str(v["content"][0]["text"].as_str().unwrap()).unwrap()
}
#[test]
fn transfers_enabled_by_default_and_legacy_enable_still_works() {
    for prefix in [vec![], vec!["--allow-transfers"]] {
        let mut args = prefix.clone();
        args.extend(["call", "get_config"]);
        let (ok, v) = run(&args);
        assert!(ok);
        assert_eq!(unpack(v)["encryptedTransfersEnabled"], true);
        let mut args = prefix;
        args.extend(["call", "prepare_file_transfer"]);
        let (ok, v) = run(&args);
        assert!(ok);
        assert_eq!(unpack(v)["receiveId"].as_str().unwrap().len(), 32);
    }
}
#[test]
fn no_transfers_disables_all_handlers_and_conflicts_with_enable() {
    let (ok, v) = run(&["--no-transfers", "call", "get_config"]);
    assert!(ok);
    assert_eq!(unpack(v)["encryptedTransfersEnabled"], false);
    for tool in [
        "prepare_file_transfer",
        "send_file_transfer",
        "receive_file_transfer",
    ] {
        let (ok, v) = run(&["--no-transfers", "call", tool]);
        assert!(!ok);
        assert_eq!(v["isError"], true);
        assert!(
            v["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("--no-transfers")
        );
    }
    let (ok, v) = run(&[
        "--no-transfers",
        "--allow-transfers",
        "call",
        "prepare_file_transfer",
    ]);
    assert!(!ok);
    assert!(v.is_null(), "clap conflict must reject before dispatch");
}
