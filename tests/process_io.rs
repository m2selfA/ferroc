use ferroc::{config::Policy, protocol::ToolResult, runtime::Runtime};
use serde_json::{Value, json};
use std::time::Duration;
fn unpack(r: ToolResult) -> Value {
    assert_ne!(r.is_error, Some(true), "{:?}", r);
    serde_json::from_str(r.content[0]["text"].as_str().unwrap()).unwrap()
}
#[tokio::test]
async fn stdin_roundtrip_and_output_cap() {
    let dir = tempfile::tempdir().unwrap();
    let r = Runtime::new(Policy::new(vec![dir.path().to_owned()], true).unwrap());
    #[cfg(windows)]
    let command = "$line=[Console]::ReadLine(); [Console]::WriteLine(('received:'+$line)); Start-Sleep -Seconds 30";
    #[cfg(not(windows))]
    let command = "read line; printf 'received:%s\\n' \"$line\"; sleep 30";
    let v = unpack(
        r.call("start_process", json!({"command":command,"timeout_ms":0}))
            .await,
    );
    let pid = v["pid"].as_u64().unwrap();
    let v = unpack(
        r.call(
            "interact_with_process",
            json!({"pid":pid,"input":"hello-native","timeout_ms":1500}),
        )
        .await,
    );
    r.shutdown().await;
    assert!(
        v["output"]
            .as_str()
            .unwrap()
            .contains("received:hello-native"),
        "{v}"
    );
    #[cfg(windows)]
    let command = "[Console]::Write(('x' * 1200000)); Start-Sleep -Seconds 30";
    #[cfg(not(windows))]
    let command = "head -c 1200000 /dev/zero | tr '\\0' x; sleep 30";
    let v = unpack(
        r.call("start_process", json!({"command":command,"timeout_ms":0}))
            .await,
    );
    let pid = v["pid"].as_u64().unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let v = unpack(r.call("read_process_output", json!({"pid":pid})).await);
    r.shutdown().await;
    assert!(v["droppedBytes"].as_u64().unwrap() > 0, "{v}");
    assert_eq!(v["output"].as_str().unwrap().len(), 1024 * 1024);
}
#[tokio::test]
async fn wrong_optional_types_do_not_default_into_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let r = Runtime::new(Policy::new(vec![dir.path().to_owned()], true).unwrap());
    let file = dir.path().join("safe.txt");
    std::fs::write(&file, "original").unwrap();
    assert_eq!(
        r.call("write_file", json!({"path":file,"content":"bad","mode":3}))
            .await
            .is_error,
        Some(true)
    );
    assert_eq!(std::fs::read_to_string(file).unwrap(), "original");
    assert_eq!(
        r.call(
            "start_process",
            json!({"command":"echo no","timeout_ms":0,"shell":false})
        )
        .await
        .is_error,
        Some(true)
    );
    assert_eq!(
        r.call(
            "start_search",
            json!({"path":dir.path(),"pattern":"x","searchType":false})
        )
        .await
        .is_error,
        Some(true)
    );
    assert_eq!(
        r.call(&"x".repeat(129), json!({})).await.is_error,
        Some(true)
    );
    r.shutdown().await;
}
