use super::*;
use crate::config::Policy;
use crate::fleet::identity::make_directory;
use std::path::Path;

fn runtime(source: &Path, target: &Path) -> Runtime {
    // Both roots are explicit local policy entries; preflight itself only ever
    // observes the target.
    Runtime::new(Policy::new(vec![source.to_path_buf(), target.to_path_buf()], true).unwrap())
}
fn args(source: &Path, target: &Path, allow: bool) -> DirectoryArgs {
    DirectoryArgs {
        action: Action::Preflight {
            source_root: source.to_path_buf(),
            target_root: target.to_path_buf(),
            quick: false,
            allow_planned_directories: allow,
            view: ViewArgs {
                exclude_subtree: Vec::new(),
                max_hashed_bytes: 8 * 1024 * 1024,
                page_entries: 256,
                page_bytes: 64 * 1024,
            },
        },
    }
}
fn tree() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    make_directory(&source).unwrap();
    make_directory(&target).unwrap();
    (temp, source, target)
}
fn records(out: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn run_ok(rt: &Runtime, args: DirectoryArgs) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    run(rt, args, &mut out).unwrap_or_else(|error| panic!("preflight failed: {error:#}"));
    records(&out)
}

#[test]
fn preflight_reports_absent_destinations_and_creates_nothing() {
    let (_t, source, target) = tree();
    make_directory(&source.join("sub")).unwrap();
    std::fs::write(source.join("a.bin"), b"aaa").unwrap();
    std::fs::write(source.join("sub/b.bin"), b"bbbbb").unwrap();
    make_directory(&target.join("sub")).unwrap();
    let rt = runtime(&source, &target);
    let rows = run_ok(&rt, args(&source, &target, false));
    let entries: Vec<_> = rows
        .iter()
        .filter(|r| r["record"] == "preflightEntry")
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["path"], "a.bin");
    assert_eq!(entries[1]["path"], "sub/b.bin");
    assert_eq!(entries[0]["bytes"], 3);
    let header = rows
        .iter()
        .find(|r| r["record"] == "preflightHeader")
        .unwrap();
    assert_eq!(header["authorization"], false);
    assert_eq!(header["applySupported"], false);
    assert_eq!(header["plannedDirectoriesAllowed"], false);
    let complete = rows.last().unwrap();
    assert_eq!(complete["record"], "complete");
    assert_eq!(complete["details"]["entries"], 2);
    assert_eq!(complete["details"]["plannedBytes"], 8);
    assert_eq!(complete["details"]["plannedDirectories"], 0);
    // Observation only: nothing was created on either side.
    assert!(!target.join("a.bin").exists());
    assert!(!target.join("sub/b.bin").exists());
}

#[test]
fn missing_parent_is_refused_and_listed_only_when_explicitly_allowed() {
    let (_t, source, target) = tree();
    make_directory(&source.join("sub")).unwrap();
    make_directory(&source.join("sub/deep")).unwrap();
    std::fs::write(source.join("sub/deep/c.bin"), b"c").unwrap();
    let rt = runtime(&source, &target);
    let mut out = Vec::new();
    let error = run(&rt, args(&source, &target, false), &mut out).unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("existing private parent") || text.contains("planned directory"),
        "{text}"
    );
    assert!(
        out.is_empty(),
        "a refused plan must not emit a record stream"
    );
    assert!(!target.join("sub").exists());
    let rows = run_ok(&rt, args(&source, &target, true));
    let declared: Vec<_> = rows
        .iter()
        .filter(|r| r["record"] == "plannedDirectory")
        .collect();
    // Ancestors first: `sub` then `sub/deep`, both still absent on disk.
    assert_eq!(declared.len(), 2);
    assert_eq!(declared[0]["path"], "sub");
    assert_eq!(declared[1]["path"], "sub/deep");
    assert!(!target.join("sub").exists());
    assert!(!target.join("sub/deep").exists());
    assert!(!target.join("sub/deep/c.bin").exists());
}

#[test]
fn existing_target_file_refuses_the_whole_preflight() {
    let (_t, source, target) = tree();
    std::fs::write(source.join("a.bin"), b"aaa").unwrap();
    std::fs::write(target.join("a.bin"), b"different").unwrap();
    let rt = runtime(&source, &target);
    let mut out = Vec::new();
    // The add-only planner rejects an update outright: a preflight stream that
    // silently described a replace would misrepresent what apply may do.
    let error = run(&rt, args(&source, &target, false), &mut out).unwrap_err();
    let text = format!("{error:#}");
    // The add-only planner names the real reason: it has no overwrite engine.
    assert!(text.contains("overwrite"), "{text}");
    assert!(out.is_empty(), "refusal must not emit a partial stream");
    assert_eq!(std::fs::read(target.join("a.bin")).unwrap(), b"different");
}
