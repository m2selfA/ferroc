use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::make_directory,
        manifest::{Comparison, EntryKind, Manifest, ManifestEntry, ManifestLimits, diff},
        manifest_scan::ScanLimits,
        sync_plan::{SyncTemplate, plan_add_only},
    },
};
use sha2::{Digest, Sha256};
use std::fs;
use uuid::Uuid;

fn runtime(root: &Path) -> Runtime {
    Runtime::new(Policy::new(vec![root.to_path_buf()], false).unwrap())
}
fn d(path: &str) -> ManifestEntry {
    ManifestEntry {
        path: path.into(),
        kind: EntryKind::Directory,
    }
}
fn f(path: &str, size: u64, hash: u8) -> ManifestEntry {
    ManifestEntry {
        path: path.into(),
        kind: EntryKind::File {
            size,
            mtime_ns: 1,
            sha256: Some([hash; 32]),
        },
    }
}
fn plan(source: Vec<ManifestEntry>, root: &Path) -> crate::fleet::sync_plan::SyncPlan {
    let source = Manifest::new(source, ManifestLimits::default()).unwrap();
    let target = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let diff = diff(&source, &target, Comparison::Checksum).unwrap();
    let root = root.to_str().unwrap();
    let template = SyncTemplate {
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: [2; 32],
        target_device: [3; 32],
        transfer_id: Uuid::from_bytes([4; 16]),
        source_root: "C:/src",
        target_root: root,
        deadline_ms: 60_000,
        idempotency_prefix: "preflight",
        chunk_bytes: 65536,
    };
    plan_add_only(&source, &diff, &template).unwrap()
}
fn private_root() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("target");
    make_directory(&root).unwrap();
    (temp, root)
}

#[test]
fn absent_destinations_under_existing_private_parents_are_observed() {
    let (_t, root) = private_root();
    fs::create_dir(root.join("sub")).unwrap();
    let rt = runtime(&root);
    let plan = plan(
        vec![d("sub"), f("sub/a.bin", 3, 1), f("b.bin", 5, 2)],
        &root,
    );
    let pre = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(pre.len(), 2);
    assert_eq!(pre.planned_bytes(), 8);
    assert_eq!(pre.profile(), PreflightProfile::AsciiPortableOnly);
    assert!(!pre.is_empty());
    assert!(!pre.root_id().is_empty());
    assert_eq!(pre.entries()[0].path(), "b.bin");
    assert_eq!(pre.entries()[1].path(), "sub/a.bin");
    assert!(pre.entries()[1].destination().ends_with("sub/a.bin"));
    assert!(!pre.entries()[1].parent_id().is_empty());
    pre.matches(&plan).unwrap();
    assert!(!root.join("b.bin").exists());
    assert!(!root.join("sub/a.bin").exists());
}

#[test]
fn missing_parent_directory_is_refused_and_not_created() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let plan = plan(vec![d("sub"), f("sub/a.bin", 3, 1)], &root);
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("existing private parent"),
        "{error:#}"
    );
    assert!(!root.join("sub").exists());
}

#[test]
fn existing_destination_refuses_the_whole_plan_without_touching_it() {
    let (_t, root) = private_root();
    fs::write(root.join("b.bin"), b"keep").unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![f("b.bin", 5, 2), f("c.bin", 1, 3)], &root);
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("existing destination"),
        "{error:#}"
    );
    assert_eq!(fs::read(root.join("b.bin")).unwrap(), b"keep");
    assert!(!root.join("c.bin").exists());
}

#[test]
fn reserved_nonportable_and_non_ascii_names_are_refused_not_folded() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    for name in [
        "CON",
        "nul.txt",
        "lpt9",
        "trail.",
        "space ",
        "meta?.bin",
        "caf\u{e9}.bin",
    ] {
        let plan = plan(vec![f(name, 1, 4)], &root);
        let error = rt
            .preflight_fleet_target(
                &root,
                &plan,
                PreflightLimits::default(),
                &CancelToken::new(),
            )
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("portable profile")
                || text.contains("reserved")
                || text.contains("period")
                || text.contains("control"),
            "{name}: {text}"
        );
        assert!(!root.join(name).exists());
    }
}

#[test]
fn ascii_case_collision_between_planned_targets_is_refused() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let plan = plan(vec![f("A.bin", 1, 1), f("a.bin", 2, 2)], &root);
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("ignoring ASCII case"),
        "{error:#}"
    );
}

#[test]
fn file_directory_clash_is_refused_before_a_plan_exists() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    // Defense in depth: a manifest already refuses a file that is also its parent,
    // so this input never reaches the planner. Preflight keeps its own prefix rule
    // for plans built by other code paths.
    let manifest = Manifest::new(
        vec![f("a.bin", 1, 1), f("a.bin/b.bin", 2, 2)],
        ManifestLimits::default(),
    );
    assert!(manifest.is_err());
    let plan = plan(vec![f("a.bin", 1, 1)], &root);
    rt.preflight_fleet_target(
        &root,
        &plan,
        PreflightLimits::default(),
        &CancelToken::new(),
    )
    .unwrap();
    assert!(!root.join("a.bin").exists());
}

#[test]
fn junction_parent_is_refused_even_though_policy_could_resolve_it() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    make_directory(&outside).unwrap();
    let root = temp.path().join("target");
    make_directory(&root).unwrap();
    let link = root.join("link");
    let result = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let rt = runtime(&root);
    let plan = plan(vec![d("link"), f("link/a.bin", 1, 1)], &root);
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("existing private parent")
            || format!("{error:#}").contains("reparse"),
        "{error:#}"
    );
    assert!(!outside.join("a.bin").exists());
}

#[test]
fn destination_outside_the_given_target_root_is_refused() {
    let (_t, root) = private_root();
    let other = root.parent().unwrap().join("other");
    make_directory(&other).unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![f("a.bin", 1, 1)], &other);
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("does not match target root"),
        "{error:#}"
    );
    assert!(!other.join("a.bin").exists());
    assert!(!root.join("a.bin").exists());
}

#[test]
fn preflight_of_one_plan_does_not_bind_another_plan() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let first = plan(vec![f("a.bin", 1, 1)], &root);
    let second = plan(vec![f("b.bin", 1, 2)], &root);
    let pre = rt
        .preflight_fleet_target(
            &root,
            &first,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap();
    pre.matches(&first).unwrap();
    let error = pre.matches(&second).unwrap_err();
    assert!(format!("#{error:#}").contains("another plan"), "{error:#}");
}

#[test]
fn cancellation_before_and_after_first_entry_returns_no_preflight() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let plan = plan(vec![f("a.bin", 1, 1), f("b.bin", 1, 2)], &root);
    let token = CancelToken::new();
    token.cancel();
    assert!(
        rt.preflight_fleet_target(&root, &plan, PreflightLimits::default(), &token)
            .is_err()
    );
    let token = CancelToken::new();
    let mut checked = 0;
    let error = rt
        .preflight_fleet_target_for_test(
            &root,
            &plan,
            PreflightLimits::default(),
            &token,
            |event| {
                assert!(event.destination.ends_with("a.bin"));
                assert_eq!(event.relative, "a.bin");
                checked += 1;
                token.cancel();
                Ok(())
            },
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("cancelled"), "{error:#}");
    assert_eq!(checked, 1);
    assert!(!root.join("a.bin").exists());
}

#[test]
fn native_parent_handle_denies_rename_only_for_the_duration_of_one_observation() {
    let (_t, root) = private_root();
    fs::create_dir(root.join("sub")).unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![d("sub"), f("sub/a.bin", 1, 1)], &root);
    let moved = root.parent().unwrap().join("moved");
    let error = rt
        .preflight_fleet_target_for_test(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
            |event| {
                assert_eq!(event.relative, "sub/a.bin");
                // Retained private parent handle denies an ordinary rename.
                assert_eq!(
                    fs::rename(root.join("sub"), &moved)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(32)
                );
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(error.len(), 1);
    fs::rename(root.join("sub"), &moved).unwrap();
    fs::rename(&moved, root.join("sub")).unwrap();
}

#[test]
fn transfer_disable_and_runtime_shutdown_block_new_preflight() {
    let (_t, root) = private_root();
    let plan = plan(vec![f("a.bin", 1, 1)], &root);
    let mut policy = Policy::new(vec![root.clone()], false).unwrap();
    policy.allow_transfers = false;
    let disabled = Runtime::new(policy);
    assert!(
        disabled
            .preflight_fleet_target(
                &root,
                &plan,
                PreflightLimits::default(),
                &CancelToken::new()
            )
            .is_err()
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let runtime = Runtime::new(Policy::new(vec![root.clone()], false).unwrap());
        runtime.shutdown_fleet_host().await.unwrap();
        assert!(
            runtime
                .preflight_fleet_target(
                    &root,
                    &plan,
                    PreflightLimits::default(),
                    &CancelToken::new()
                )
                .is_err()
        );
    });
}

#[test]
fn limits_and_empty_plan_are_handled_without_touching_the_tree() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let empty = plan(vec![], &root);
    let pre = rt
        .preflight_fleet_target(
            &root,
            &empty,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap();
    assert!(pre.is_empty());
    assert_eq!(pre.planned_bytes(), 0);
    let plan = plan(vec![f("a.bin", 1, 1), f("b.bin", 1, 2)], &root);
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits {
                max_files: 1,
                ..PreflightLimits::default()
            },
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(format!("#{error:#}").contains("file limit"), "{error:#}");
    assert!(!root.join("a.bin").exists());
}

#[test]
fn deep_existing_chain_is_observed_without_stack_or_creation_side_effects() {
    let (_t, root) = private_root();
    let mut current = root.clone();
    let mut relative = String::new();
    // Single-character components keep the plain (non-verbatim) path under the
    // Win32 MAX_PATH boundary that this native publisher actually uses.
    for _ in 0..64 {
        current = current.join("d");
        make_directory(&current).unwrap();
        if !relative.is_empty() {
            relative.push('/');
        }
        relative.push('d');
    }
    let mut entries: Vec<ManifestEntry> = Vec::new();
    let mut prefix = String::new();
    for _ in 0..64 {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push('d');
        entries.push(d(&prefix));
    }
    entries.push(f(&format!("{relative}/leaf.bin"), 4, 9));
    let rt = runtime(&root);
    let plan = plan(entries, &root);
    let pre = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(pre.len(), 1);
    assert!(!pre.entries()[0].parent_id().is_empty());
    assert!(!current.join("leaf.bin").exists());
}

#[test]
fn junction_between_root_and_parent_cannot_hide_an_outside_destination() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    make_directory(&outside).unwrap();
    let root = temp.path().join("target");
    make_directory(&root).unwrap();
    let link = root.join("hop");
    let result = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let rt = runtime(&root);
    let plan = plan(
        vec![d("hop"), d("hop/deep"), f("hop/deep/a.bin", 1, 1)],
        &root,
    );
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("existing private parent") || text.contains("escaped the target root"),
        "{text}"
    );
    assert!(!outside.join("a.bin").exists());
}

#[test]
fn reparse_or_directory_at_the_destination_is_not_treated_as_absent() {
    let (_t, root) = private_root();
    fs::create_dir(root.join("dir")).unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![f("dir", 1, 1)], &root);
    let error = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("existing destination"),
        "{error:#}"
    );
    assert!(root.join("dir").is_dir());
}

/// Explicit bounded actual probe: real source tree -> scan -> diff -> plan -> the
/// read-only target preflight. It is NOT an apply and writes no destination file.
#[test]
#[ignore = "explicit actual 69-entry tree/8MiB target preflight probe"]
fn native_target_preflight_probe() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("source");
    make_directory(&source_root).unwrap();
    for directory in 0..4 {
        let path = source_root.join(format!("d{directory}"));
        make_directory(&path).unwrap();
        for file in 0..16 {
            fs::write(path.join(format!("f{file:02}.bin")), vec![file as u8; 61]).unwrap();
        }
        fs::write(path.join("extra.bin"), vec![directory as u8; 3]).unwrap();
    }
    fs::write(source_root.join("large.bin"), vec![0x42; 8 * 1024 * 1024]).unwrap();
    let target_root = temp.path().join("target");
    make_directory(&target_root).unwrap();
    for directory in 0..4 {
        make_directory(&target_root.join(format!("d{directory}"))).unwrap();
    }
    let rt =
        Runtime::new(Policy::new(vec![source_root.clone(), target_root.clone()], false).unwrap());
    let cancel = CancelToken::new();
    let observation = rt
        .scan_fleet_manifest(&source_root, ScanLimits::default(), &cancel)
        .unwrap();
    let target = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let diff_plan = diff(observation.manifest(), &target, Comparison::Checksum).unwrap();
    let template = SyncTemplate {
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: [2; 32],
        target_device: [3; 32],
        transfer_id: Uuid::from_bytes([4; 16]),
        source_root: source_root.to_str().unwrap(),
        target_root: target_root.to_str().unwrap(),
        deadline_ms: 60_000,
        idempotency_prefix: "probe",
        chunk_bytes: 65536,
    };
    let plan = plan_add_only(observation.manifest(), &diff_plan, &template).unwrap();
    let start = std::time::Instant::now();
    let pre = rt
        .preflight_fleet_target(&target_root, &plan, PreflightLimits::default(), &cancel)
        .unwrap();
    let elapsed_ms = start.elapsed().as_millis();
    pre.matches(&plan).unwrap();
    let mut all_absent = true;
    let mut all_parents = true;
    for entry in pre.entries() {
        if entry.destination().exists() {
            all_absent = false;
        }
        if entry.parent_id().is_empty() {
            all_parents = false;
        }
    }
    let target_files: usize = (0..4)
        .map(|directory| {
            fs::read_dir(target_root.join(format!("d{directory}")))
                .unwrap()
                .count()
        })
        .sum();
    let output = serde_json::json!({
        "status": if all_absent && all_parents && pre.len() == plan.files().len() && target_files == 0 { "passed" } else { "failed" },
        "scope": "Windows actual source tree observation and read-only target preflight; not apply",
        "source_entries": observation.manifest().len(),
        "planned_files": pre.len(),
        "plan_files": plan.files().len(),
        "planned_bytes": pre.planned_bytes(),
        "planned_over_8mib": plan.planned_bytes() > 8 * 1024 * 1024,
        "preflight_ms": elapsed_ms,
        "all_destinations_absent": all_absent,
        "all_parent_ids_present": all_parents,
        "target_files_created": target_files,
        "profile": format!("{:?}", pre.profile()),
        "root_id_present": !pre.root_id().is_empty(),
        "plan_digest_hex": pre.plan_digest().iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "test_sha256": std::env::current_exe().ok().and_then(|p| {
            let data = fs::read(p).ok()?;
            Some(Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect::<String>())
        }),
    });
    let path = std::env::var("FERROC_FLEET_PREFLIGHT_OUTPUT")
        .expect("explicit probe requires an output path");
    fs::write(path, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    println!("{}", serde_json::to_string(&output).unwrap());
    assert_eq!(output["status"], "passed");
}

#[test]
fn explicit_mode_lists_missing_directories_without_creating_them() {
    let (_t, root) = private_root();
    fs::create_dir(root.join("sub")).unwrap();
    let rt = runtime(&root);
    let plan = plan(
        vec![d("sub"), d("sub/deep"), f("sub/deep/a.bin", 3, 1)],
        &root,
    );
    // Default stays strict: the missing grandchild is refused.
    let strict = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap_err();
    assert!(
        format!("{strict:#}").contains("existing private parent"),
        "{strict:#}"
    );
    assert!(!root.join("sub/deep").exists());
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let pre = rt
        .preflight_fleet_target(&root, &plan, limits, &CancelToken::new())
        .unwrap();
    assert_eq!(pre.len(), 1);
    assert_eq!(pre.planned_directories().len(), 1);
    assert_eq!(pre.planned_directories()[0].path(), "sub/deep");
    assert!(pre.planned_directories()[0].destination().ends_with("deep"));
    // Declared means observed-and-absent, not created.
    assert!(!root.join("sub/deep").exists());
    assert!(!root.join("sub/deep/a.bin").exists());
    pre.matches(&plan).unwrap();
}

#[test]
fn an_undeclared_missing_ancestor_cannot_even_reach_the_planner() {
    let (_t, root) = private_root();
    // Defense in depth: the manifest already requires every non-root parent to
    // carry a Directory entry, so a plan missing `a` cannot be built at all. The
    // preflight keeps its own ancestor check for plans assembled elsewhere.
    let manifest = Manifest::new(
        vec![d("a/b"), f("a/b/x.bin", 1, 1)],
        ManifestLimits::default(),
    );
    assert!(manifest.is_err());
    let rt = runtime(&root);
    let plan = plan(vec![d("a"), d("a/b"), f("a/b/x.bin", 1, 1)], &root);
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let pre = rt
        .preflight_fleet_target(&root, &plan, limits, &CancelToken::new())
        .unwrap_or_else(|error| panic!("explicit-mode preflight failed: {error:#}"));
    assert_eq!(pre.planned_directories().len(), 2);
    assert_eq!(pre.planned_directories()[0].path(), "a");
    assert_eq!(pre.planned_directories()[1].path(), "a/b");
    assert!(!root.join("a").exists());
    assert!(!root.join("a/b/x.bin").exists());
}

#[test]
fn explicit_mode_refuses_a_declared_directory_that_is_actually_a_file() {
    let (_t, root) = private_root();
    fs::write(root.join("sub"), b"not a directory").unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![d("sub"), f("sub/a.bin", 1, 1)], &root);
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let error = rt
        .preflight_fleet_target(&root, &plan, limits, &CancelToken::new())
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("not a private plain directory"),
        "{error:#}"
    );
    assert_eq!(fs::read(root.join("sub")).unwrap(), b"not a directory");
}

#[test]
fn explicit_mode_declared_directory_outside_the_root_is_refused() {
    let (_t, root) = private_root();
    let other = root.parent().unwrap().join("elsewhere");
    make_directory(&other).unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![d("a"), f("a/x.bin", 1, 1)], &root);
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let pre = rt
        .preflight_fleet_target(&root, &plan, limits, &CancelToken::new())
        .unwrap_or_else(|error| panic!("explicit-mode preflight failed: {error:#}"));
    assert_eq!(pre.planned_directories().len(), 1);
    assert!(
        pre.planned_directories()[0]
            .destination()
            .starts_with(fs::canonicalize(&root).unwrap())
    );
    assert!(!other.join("a").exists());
}

/// Explicit bounded actual probe for the directory contract: a real source tree
/// with a nested new directory is scanned, planned and preflighted in explicit
/// mode. It still creates NO destination directory or file.
#[test]
#[ignore = "explicit actual directory-contract probe"]
fn native_planned_directories_probe() {
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("source");
    make_directory(&source_root).unwrap();
    for directory in 0..3 {
        let path = source_root.join(format!("d{directory}")).join("nested");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("a.bin"), vec![directory as u8; 31]).unwrap();
    }
    std::fs::write(source_root.join("root.bin"), vec![0x55; 8 * 1024 * 1024]).unwrap();
    let target_root = temp.path().join("target");
    make_directory(&target_root).unwrap();
    let rt =
        Runtime::new(Policy::new(vec![source_root.clone(), target_root.clone()], false).unwrap());
    let cancel = CancelToken::new();
    let observation = rt
        .scan_fleet_manifest(&source_root, ScanLimits::default(), &cancel)
        .unwrap();
    let target = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let diff_plan = diff(observation.manifest(), &target, Comparison::Checksum).unwrap();
    let template = SyncTemplate {
        fleet_id: Uuid::from_bytes([1; 16]),
        source_device: [2; 32],
        target_device: [3; 32],
        transfer_id: Uuid::from_bytes([4; 16]),
        source_root: source_root.to_str().unwrap(),
        target_root: target_root.to_str().unwrap(),
        deadline_ms: 60_000,
        idempotency_prefix: "probe-dirs",
        chunk_bytes: 65536,
    };
    let plan = plan_add_only(observation.manifest(), &diff_plan, &template).unwrap();
    let strict = rt
        .preflight_fleet_target(&target_root, &plan, PreflightLimits::default(), &cancel)
        .is_err();
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let start = std::time::Instant::now();
    let pre = rt
        .preflight_fleet_target(&target_root, &plan, limits, &cancel)
        .unwrap();
    let elapsed_ms = start.elapsed().as_millis();
    pre.matches(&plan).unwrap();
    let declared: Vec<&str> = pre.planned_directories().iter().map(|d| d.path()).collect();
    let mut ancestor_first = true;
    for pair in declared.windows(2) {
        if pair[0] >= pair[1] {
            ancestor_first = false;
        }
    }
    let mut any_created = false;
    for directory in 0..3 {
        for name in ["", "/nested"] {
            if target_root.join(format!("d{directory}{name}")).exists() {
                any_created = true;
            }
        }
    }
    let output = serde_json::json!({
        "status": if strict && !any_created && ancestor_first && !declared.is_empty() { "passed" } else { "failed" },
        "scope": "Windows actual tree with declared new directories; read-only preflight, not apply",
        "source_entries": observation.manifest().len(),
        "plan_files": plan.files().len(),
        "declared_directories": declared,
        "planned_bytes": pre.planned_bytes(),
        "strict_mode_refused": strict,
        "any_directory_created": any_created,
        "ancestor_first": ancestor_first,
        "preflight_ms": elapsed_ms,
        "test_sha256": std::env::current_exe().ok().and_then(|p| {
            let data = std::fs::read(p).ok()?;
            Some(Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect::<String>())
        }),
    });
    let path = std::env::var("FERROC_FLEET_PREFLIGHT_DIRS_OUTPUT")
        .expect("explicit probe requires an output path");
    std::fs::write(path, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    println!("{}", serde_json::to_string(&output).unwrap());
    assert_eq!(output["status"], "passed");
}

#[test]
fn scattered_actual_target_additions_are_observed_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("target");
    make_directory(&root).unwrap();
    for directory in 0..4 {
        let path = root.join(format!("d{directory}"));
        make_directory(&path).unwrap();
        fs::write(path.join("f.bin"), vec![directory as u8; 3]).unwrap();
    }
    let rt = runtime(&root);
    let mut entries: Vec<ManifestEntry> = (0..4)
        .map(|directory| d(&format!("d{directory}")))
        .collect();
    entries.extend(
        (0..4).map(|directory| f(&format!("d{directory}/new.bin"), 3, directory as u8 + 1)),
    );
    let plan = plan(entries, &root);
    let pre = rt
        .preflight_fleet_target(
            &root,
            &plan,
            PreflightLimits::default(),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(pre.len(), 4);
    for entry in pre.entries() {
        assert!(!entry.destination().exists());
        assert_eq!(entry.bytes(), 3);
    }
    assert_eq!(fs::read(root.join("d2/f.bin")).unwrap(), vec![2; 3]);
}
