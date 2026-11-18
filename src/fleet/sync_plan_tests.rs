use super::*;
use crate::fleet::manifest::{EntryKind, Manifest, ManifestEntry, ManifestLimits, diff};
fn f(path: &str, size: u64, mtime_ns: i64, hash: Option<u8>) -> ManifestEntry {
    ManifestEntry {
        path: path.into(),
        kind: EntryKind::File {
            size,
            mtime_ns,
            sha256: hash.map(|b| [b; 32]),
        },
    }
}
fn d(path: &str) -> ManifestEntry {
    ManifestEntry {
        path: path.into(),
        kind: EntryKind::Directory,
    }
}
fn m(v: Vec<ManifestEntry>) -> Manifest {
    Manifest::new(v, ManifestLimits::default()).unwrap()
}
fn template<'a>(s: &'a str, t: &'a str) -> SyncTemplate<'a> {
    SyncTemplate {
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: [2; 32],
        target_device: [3; 32],
        transfer_id: Uuid::from_bytes([4; 16]),
        source_root: s,
        target_root: t,
        deadline_ms: 60_000,
        idempotency_prefix: "sync-1",
        chunk_bytes: 65536,
    }
}
fn plan(
    source: Vec<ManifestEntry>,
    target: Vec<ManifestEntry>,
    comparison: Comparison,
) -> Result<SyncPlan> {
    let source = m(source);
    let diff = diff(&source, &m(target), comparison)?;
    plan_add_only(&source, &diff, &template("C:/src", "C:/dst"))
}
#[test]
fn add_only_plans_missing_files_and_keeps_extra_targets() {
    let plan = plan(
        vec![
            d("a"),
            f("a/one.bin", 3, 10, Some(1)),
            f("b.bin", 5, 11, Some(2)),
        ],
        vec![
            d("a"),
            f("a/one.bin", 3, 10, Some(1)),
            f("extra.bin", 1, 1, Some(9)),
        ],
        Comparison::Checksum,
    )
    .unwrap();
    assert_eq!(plan.mode(), PlanMode::AddOnly);
    assert_eq!(plan.comparison(), Comparison::Checksum);
    assert_eq!(plan.files().len(), 1);
    let file = &plan.files()[0];
    assert_eq!(file.path, "b.bin");
    assert_eq!(file.bytes, 5);
    assert_eq!(file.reason, CopyReason::MissingTarget);
    assert_eq!(file.job().source_path, "C:/src/b.bin");
    assert_eq!(file.job().destination_path, "C:/dst/b.bin");
    assert!(!file.job().overwrite);
    assert_eq!(plan.planned_bytes(), 5);
    assert_eq!(plan.retained_target_only(), 1);
    assert_eq!(plan.unchanged_files(), 1);
}
#[test]
fn existing_file_updates_are_refused_as_a_whole_plan() {
    let error = plan(
        vec![f("x", 3, 10, Some(1)), f("y", 4, 10, Some(1))],
        vec![f("x", 3, 10, Some(2))],
        Comparison::Checksum,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("needs an overwrite"), "{error}");
    // Even the addable file is not returned: there is no partial plan.
}
#[test]
fn quick_comparison_and_missing_digest_are_refused() {
    let quick = plan(vec![f("x", 3, 10, Some(1))], vec![], Comparison::Quick)
        .unwrap_err()
        .to_string();
    assert!(quick.contains("requires checksum"), "{quick}");
    let no_digest = plan(vec![f("x", 3, 10, None)], vec![], Comparison::Checksum)
        .unwrap_err()
        .to_string();
    assert!(
        no_digest.contains("checksum required"),
        "unexpected: {no_digest}"
    );
}
#[test]
fn type_conflict_and_blocked_subtree_are_refused() {
    let conflict = plan(
        vec![f("node", 3, 10, Some(1))],
        vec![d("node"), f("node/inner", 1, 1, Some(1))],
        Comparison::Checksum,
    )
    .unwrap_err()
    .to_string();
    assert!(conflict.contains("conflict"), "{conflict}");
}
#[test]
fn directories_are_counted_but_never_planned_as_files() {
    let plan = plan(
        vec![d("new"), f("new/a.bin", 2, 5, Some(4))],
        vec![],
        Comparison::Checksum,
    )
    .unwrap();
    assert_eq!(plan.files().len(), 1);
    assert!(plan.directories_ensured() >= 1);
    // Declared directories are exposed ancestor-first and never as files.
    assert_eq!(plan.directories(), ["new".to_string()]);
    assert!(!plan.files().iter().any(|f| f.path == "new"));
    let summary: serde_json::Value = serde_json::from_str(&plan.summary_json().unwrap()).unwrap();
    assert_eq!(summary["files"][0]["path"], "new/a.bin");
    assert!(summary["directoriesEnsured"].as_u64().unwrap() >= 1);
}
#[test]
fn nested_declared_directories_keep_ancestor_first_order() {
    let plan = plan(
        vec![
            d("a"),
            d("a/b"),
            d("a/b/c"),
            f("a/b/c/leaf.bin", 4, 7, Some(5)),
        ],
        vec![],
        Comparison::Checksum,
    )
    .unwrap();
    assert_eq!(plan.files().len(), 1);
    assert_eq!(plan.directories_ensured(), 3);
    assert_eq!(
        plan.directories(),
        ["a".to_string(), "a/b".to_string(), "a/b/c".to_string()]
    );
}
#[test]
fn unsafe_roots_and_unsafe_relative_paths_fail_validation() {
    let source = m(vec![f("x", 3, 10, Some(1))]);
    let target = m(vec![]);
    let planned = diff(&source, &target, Comparison::Checksum).unwrap();
    for root in ["", "C:/src/", "C:/src\\", "not-rooted", "/"] {
        assert!(
            plan_add_only(&source, &planned, &template(root, "C:/dst")).is_err(),
            "root {root:?}"
        );
    }
    // Unsafe spellings never reach a plan: the manifest itself refuses them.
    for path in ["a:b", ".ferroc-fleet-x", "../x", "/abs"] {
        assert!(
            Manifest::new(vec![f(path, 3, 10, Some(1))], ManifestLimits::default()).is_err(),
            "manifest accepted {path:?}"
        );
    }
}
#[test]
fn deterministic_ids_digests_and_byte_ordering() {
    let source = vec![
        d("a"),
        f("a/b.bin", 1, 1, Some(1)),
        f("a-", 1, 1, Some(2)),
        f("a0", 1, 1, Some(3)),
    ];
    let first = plan(source.clone(), vec![], Comparison::Checksum).unwrap();
    let second = plan(source, vec![], Comparison::Checksum).unwrap();
    let paths: Vec<&str> = first.files().iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, vec!["a-", "a/b.bin", "a0"]);
    for (left, right) in first.files().iter().zip(second.files()) {
        assert_eq!(left.path, right.path);
        assert_eq!(left.job_digest().unwrap(), right.job_digest().unwrap());
        assert_eq!(left.job().file_id, right.job().file_id);
    }
    let ids: BTreeSet<Uuid> = first.files().iter().map(|f| f.job().file_id).collect();
    assert_eq!(ids.len(), first.files().len());
}
#[test]
fn plan_limits_and_deadline_bounds_are_enforced() {
    let source = m(vec![f("x", 3, 10, Some(1))]);
    let target = m(vec![]);
    let planned = diff(&source, &target, Comparison::Checksum).unwrap();
    assert!(plan_add_only(&source, &planned, &template("C:/src", "C:/dst")).is_ok());
    let mut bad = template("C:/src", "C:/dst");
    bad.chunk_bytes = 0;
    assert!(plan_add_only(&source, &planned, &bad).is_err());
    let mut bad = template("C:/src", "C:/dst");
    bad.deadline_ms = 0;
    assert!(plan_add_only(&source, &planned, &bad).is_err());
    let long = "p".repeat(200);
    let mut bad = template("C:/src", "C:/dst");
    bad.idempotency_prefix = &long;
    let source2 = m(vec![f("x", 3, 10, Some(1))]);
    let diff2 = diff(&source2, &m(vec![]), Comparison::Checksum).unwrap();
    assert!(plan_add_only(&source2, &diff2, &bad).is_err());
}

#[test]
fn add_or_replace_binds_each_replacement_to_the_observed_target_digest() {
    let source = m(vec![
        f("keep.bin", 3, 10, Some(1)),
        f("new.bin", 4, 11, Some(2)),
        f("edit.bin", 5, 12, Some(3)),
    ]);
    let target = m(vec![
        f("keep.bin", 3, 10, Some(1)),
        f("edit.bin", 5, 12, Some(7)),
    ]);
    let diff = diff(&source, &target, Comparison::Checksum).unwrap();
    let plan = plan_add_or_replace(&source, &target, &diff, &template("C:/src", "C:/dst")).unwrap();
    assert_eq!(plan.mode(), PlanMode::AddOrReplace);
    assert_eq!(plan.files().len(), 2);
    let added = plan.files().iter().find(|p| p.path == "new.bin").unwrap();
    assert!(!added.job().overwrite);
    assert_eq!(added.job().pre_image_sha256, None);
    let replaced = plan.files().iter().find(|p| p.path == "edit.bin").unwrap();
    assert!(replaced.job().overwrite);
    // Pre-image is the digest OBSERVED on the target, not the source digest.
    assert_eq!(replaced.job().pre_image_sha256, Some([7u8; 32]));
    assert_ne!(replaced.job().sha256, [7u8; 32]);
}

#[test]
fn add_or_replace_refuses_a_replacement_without_an_observed_target_digest() {
    // A missing digest already fails inside diff(); this guards the placeholder
    // case, which would otherwise authorize replacing unknown content.
    let source = m(vec![f("edit.bin", 5, 12, Some(3))]);
    let target = m(vec![f("edit.bin", 5, 12, Some(0))]);
    let diff = diff(&source, &target, Comparison::Checksum).unwrap();
    let error = plan_add_or_replace(&source, &target, &diff, &template("C:/src", "C:/dst"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("observed target digest"), "{error}");
}

#[test]
fn add_or_replace_still_refuses_type_conflicts_and_blocked_subtrees() {
    let source = m(vec![d("a"), f("a/x.bin", 3, 10, Some(1))]);
    let target = m(vec![f("a", 3, 10, Some(9))]);
    let diff = diff(&source, &target, Comparison::Checksum).unwrap();
    let error = plan_add_or_replace(&source, &target, &diff, &template("C:/src", "C:/dst"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("conflict") || error.contains("blocked"),
        "{error}"
    );
}

#[test]
fn add_only_mode_still_refuses_replacements() {
    let source = m(vec![f("edit.bin", 5, 12, Some(3))]);
    let target = m(vec![f("edit.bin", 5, 12, Some(7))]);
    let diff = diff(&source, &target, Comparison::Checksum).unwrap();
    let error = plan_add_only(&source, &diff, &template("C:/src", "C:/dst"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("needs an overwrite"), "{error}");
}
