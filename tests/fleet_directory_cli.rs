#![cfg(feature = "fleet-core")]
#[cfg(any(windows, target_os = "linux"))]
use serde_json::Value;
#[cfg(any(windows, target_os = "linux"))]
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Output},
};
fn run(allow: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args(["--allow-dir", allow.to_str().unwrap(), "fleet-dir"])
        .args(args)
        .output()
        .unwrap()
}
#[cfg(any(windows, target_os = "linux"))]
fn verify(bytes: &[u8]) -> anyhow::Result<Vec<Value>> {
    anyhow::ensure!(bytes.ends_with(b"\n"), "missing LF");
    let lines: Vec<_> = bytes.split_inclusive(|b| *b == b'\n').collect();
    let values: Vec<Value> = lines
        .iter()
        .map(|l| serde_json::from_slice(l))
        .collect::<Result<_, _>>()?;
    let end = values.last().ok_or_else(|| anyhow::anyhow!("empty"))?;
    anyhow::ensure!(
        end["record"] == "complete" && end["version"] == 1,
        "incomplete stream"
    );
    anyhow::ensure!(
        values.iter().filter(|v| v["record"] == "complete").count() == 1,
        "duplicate terminal"
    );
    anyhow::ensure!(
        end["precedingRecords"].as_u64() == Some((lines.len() - 1) as u64),
        "record count mismatch"
    );
    let mut hash = Sha256::new();
    for line in &lines[..lines.len() - 1] {
        hash.update(line);
    }
    let digest: [u8; 32] = hash.finalize().into();
    anyhow::ensure!(
        end["streamSha256"] == serde_json::to_value(digest)?,
        "stream digest mismatch"
    );
    Ok(values)
}
#[cfg(any(windows, target_os = "linux"))]
fn ok(output: Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    verify(&output.stdout).unwrap()
}
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn real_scan_pages_hashes_exclusions_and_readonly_output() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("skip")).unwrap();
    std::fs::write(root.path().join("skip/large"), [9; 8192]).unwrap();
    for n in ["a", "b", "c"] {
        std::fs::write(root.path().join(n), b"abc").unwrap();
    }
    let rows = ok(run(
        root.path(),
        &[
            "scan",
            "--root",
            root.path().to_str().unwrap(),
            "--exclude-subtree",
            "skip",
            "--max-hashed-bytes",
            "9",
            "--page-entries",
            "1",
            "--page-bytes",
            "2048",
        ],
    ));
    let pages: Vec<_> = rows
        .iter()
        .filter(|r| r["record"] == "manifestPage")
        .collect();
    assert_eq!(pages.len(), 3);
    for (i, row) in pages.iter().enumerate() {
        assert_eq!(row["page"]["offset"], i);
        assert_eq!(row["page"]["consistency"], "readSequence");
        assert_eq!(row["page"]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(
            row["page"]["entries"][0]["kind"]["sha256"],
            serde_json::to_value(<[u8; 32]>::from(Sha256::digest(b"abc"))).unwrap()
        );
    }
    assert_eq!(rows.last().unwrap()["details"]["source"]["bytesHashed"], 9);
    assert!(
        rows.iter()
            .all(|r| serde_json::to_vec(r).unwrap().len() <= 2048)
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 4);
    assert_eq!(
        std::fs::read(root.path().join("skip/large")).unwrap(),
        [9; 8192]
    );
}
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn real_checksum_dry_run_selects_add_replace_retains_target_and_never_applies() {
    let temp = tempfile::tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    std::fs::create_dir(&dst).unwrap();
    for root in [&src, &dst] {
        std::fs::write(root.join("same"), b"abc").unwrap();
        std::fs::create_dir(root.join("skip")).unwrap();
        std::fs::write(root.join("skip/hidden"), [5; 8192]).unwrap();
    }
    std::fs::write(src.join("changed"), b"abc").unwrap();
    std::fs::write(dst.join("changed"), b"xyz").unwrap();
    std::fs::write(src.join("new"), b"new").unwrap();
    std::fs::write(dst.join("only"), b"old").unwrap();
    let rows = ok(run(
        temp.path(),
        &[
            "dry-run",
            "--source-root",
            src.to_str().unwrap(),
            "--target-root",
            dst.to_str().unwrap(),
            "--exclude-subtree",
            "skip",
            "--page-entries",
            "1",
        ],
    ));
    let summary = &rows.last().unwrap()["details"];
    assert_eq!(summary["comparison"], "checksum");
    assert_eq!(summary["changes"], 2);
    assert_eq!(summary["unchangedFiles"], 1);
    assert_eq!(summary["retainedTargetOnly"], 1);
    assert_eq!(summary["selectedFileBytes"], 6);
    let changes: Vec<_> = rows
        .iter()
        .filter(|r| r["record"] == "difference")
        .collect();
    assert_eq!(changes[0]["entry"]["path"], "changed");
    assert_eq!(changes[0]["entry"]["difference"]["target"], "existingFile");
    assert_eq!(changes[1]["entry"]["path"], "new");
    assert_eq!(std::fs::read(dst.join("changed")).unwrap(), b"xyz");
    assert!(!dst.join("new").exists());
    assert_eq!(std::fs::read(dst.join("only")).unwrap(), b"old");
    assert_eq!(std::fs::read_dir(&dst).unwrap().count(), 4);
}
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn same_size_same_mtime_checksum_and_explicit_quick_contrast() {
    let temp = tempfile::tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    std::fs::create_dir(&dst).unwrap();
    std::fs::write(src.join("f"), b"abc").unwrap();
    std::fs::write(dst.join("f"), b"xyz").unwrap();
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    for path in [src.join("f"), dst.join("f")] {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(time))
            .unwrap();
    }
    let args = [
        "dry-run",
        "--source-root",
        src.to_str().unwrap(),
        "--target-root",
        dst.to_str().unwrap(),
    ];
    let rows = ok(run(temp.path(), &args));
    assert_eq!(rows.last().unwrap()["details"]["changes"], 1);
    let mut quick = args.to_vec();
    quick.push("--quick");
    let rows = ok(run(temp.path(), &quick));
    assert_eq!(rows.last().unwrap()["details"]["changes"], 0);
    assert_eq!(rows.last().unwrap()["details"]["comparison"], "quick");
}
#[test]
fn malformed_rules_limits_and_disabled_transfers_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    for extra in [
        ["--exclude-subtree", "../x"],
        ["--exclude-subtree", "*.tmp"],
        ["--page-entries", "0"],
        ["--page-bytes", "1048577"],
    ] {
        let output = run(temp.path(), &["scan", "--root", root, extra[0], extra[1]]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    let disabled = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args(["--no-transfers", "fleet-dir", "scan", "--root", root])
        .output()
        .unwrap();
    assert!(!disabled.status.success());
    assert!(disabled.stdout.is_empty());
}
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn outside_policy_missing_target_and_hash_failure_do_not_emit_complete() {
    let temp = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    std::fs::write(temp.path().join("f"), b"abc").unwrap();
    for args in [
        vec!["scan", "--root", other.path().to_str().unwrap()],
        vec!["scan", "--root", root, "--max-hashed-bytes", "0"],
        vec![
            "dry-run",
            "--source-root",
            root,
            "--target-root",
            temp.path().join("missing").to_str().unwrap(),
        ],
    ] {
        let out = run(temp.path(), &args);
        assert!(!out.status.success());
        assert!(
            out.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn real_stream_truncation_mutation_and_duplication_rejected() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("f"), b"abc").unwrap();
    let out = run(
        root.path(),
        &["scan", "--root", root.path().to_str().unwrap()],
    );
    assert!(out.status.success());
    verify(&out.stdout).unwrap();
    let lines: Vec<_> = out.stdout.split_inclusive(|b| *b == b'\n').collect();
    assert!(verify(&lines[..lines.len() - 1].concat()).is_err());
    let mut changed = out.stdout.clone();
    let i = changed.iter().position(|b| *b == b'a').unwrap();
    changed[i] = b'b';
    assert!(verify(&changed).is_err());
    let mut duplicated = lines[..lines.len() - 1].concat();
    duplicated.extend_from_slice(lines[1]);
    duplicated.extend_from_slice(lines.last().unwrap());
    assert!(verify(&duplicated).is_err());
}
#[cfg(not(any(windows, target_os = "linux")))]
#[test]
fn unsupported_platform_scan_is_explicitly_rejected_not_empty() {
    let temp = tempfile::tempdir().unwrap();
    let out = run(
        temp.path(),
        &["scan", "--root", temp.path().to_str().unwrap()],
    );
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires Windows or Linux"));
}
