use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::make_directory,
        manifest::{Comparison, EntryKind, Manifest, ManifestEntry, ManifestLimits, diff},
        sync_plan::{SyncTemplate, plan_add_only},
    },
};
use std::os::unix::fs::PermissionsExt;

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
    let template = SyncTemplate {
        fleet_id: uuid::Uuid::from_bytes([1; 16]),
        source_device: [2; 32],
        target_device: [3; 32],
        transfer_id: uuid::Uuid::from_bytes([4; 16]),
        source_root: "/srv/src",
        target_root: root.to_str().unwrap(),
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
fn run(
    rt: &Runtime,
    root: &Path,
    plan: &crate::fleet::sync_plan::SyncPlan,
    limits: PreflightLimits,
) -> Result<TargetPreflight> {
    rt.preflight_fleet_target(root, plan, limits, &CancelToken::new())
}

#[test]
fn absent_destinations_under_existing_private_parents_are_observed() {
    let (_t, root) = private_root();
    make_directory(&root.join("sub")).unwrap();
    let rt = runtime(&root);
    let plan = plan(
        vec![d("sub"), f("sub/a.bin", 3, 1), f("b.bin", 5, 2)],
        &root,
    );
    let pre = run(&rt, &root, &plan, PreflightLimits::default()).unwrap();
    assert_eq!(pre.len(), 2);
    assert_eq!(pre.planned_bytes(), 8);
    assert_eq!(pre.profile(), PreflightProfile::AsciiPortableOnly);
    assert!(pre.planned_directories().is_empty());
    assert!(!pre.root_id().is_empty());
    assert_eq!(pre.entries()[0].path(), "b.bin");
    assert_eq!(pre.entries()[1].path(), "sub/a.bin");
    assert!(pre.entries()[1].destination().ends_with("sub/a.bin"));
    assert!(!pre.entries()[1].parent_id().is_empty());
    pre.matches(&plan).unwrap();
    // Observation only: nothing was created.
    assert!(!root.join("b.bin").exists());
    assert!(!root.join("sub/a.bin").exists());
}

#[test]
fn missing_parent_directory_is_refused_and_not_created() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let plan = plan(vec![d("sub"), f("sub/a.bin", 3, 1)], &root);
    let error = run(&rt, &root, &plan, PreflightLimits::default()).unwrap_err();
    assert!(
        format!("{error:#}").contains("existing private parent"),
        "{error:#}"
    );
    assert!(!root.join("sub").exists());
}

#[test]
fn non_private_parent_is_refused_by_the_existing_private_requirement() {
    let (_t, root) = private_root();
    let loose = root.join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![d("loose"), f("loose/a.bin", 1, 1)], &root);
    let error = run(&rt, &root, &plan, PreflightLimits::default()).unwrap_err();
    assert!(format!("{error:#}").contains("private"), "{error:#}");
    assert!(!loose.join("a.bin").exists());
}

#[test]
fn existing_destination_refuses_the_whole_plan_without_touching_it() {
    let (_t, root) = private_root();
    std::fs::write(root.join("b.bin"), b"keep").unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![f("b.bin", 5, 2), f("c.bin", 1, 3)], &root);
    let error = run(&rt, &root, &plan, PreflightLimits::default()).unwrap_err();
    assert!(
        format!("{error:#}").contains("existing destination"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(root.join("b.bin")).unwrap(), b"keep");
    assert!(!root.join("c.bin").exists());
}

#[test]
fn symlinked_parent_is_refused_rather_than_followed() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    make_directory(&outside).unwrap();
    let root = temp.path().join("target");
    make_directory(&root).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![d("sub"), f("sub/a.bin", 1, 1)], &root);
    let error = run(&rt, &root, &plan, PreflightLimits::default()).unwrap_err();
    assert!(!format!("{error:#}").is_empty());
    assert!(!outside.join("a.bin").exists());
}

#[test]
fn declared_directories_stay_declarations_even_when_opted_in() {
    let (_t, root) = private_root();
    make_directory(&root.join("sub")).unwrap();
    let rt = runtime(&root);
    let plan = plan(
        vec![d("sub"), d("sub/deep"), f("sub/deep/a.bin", 1, 1)],
        &root,
    );
    // Strict default refuses the absent parent outright.
    assert!(run(&rt, &root, &plan, PreflightLimits::default()).is_err());
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let pre = run(&rt, &root, &plan, limits).unwrap();
    assert_eq!(pre.planned_directories().len(), 1);
    assert_eq!(pre.planned_directories()[0].path(), "sub/deep");
    assert_eq!(pre.entries()[0].parent_id(), "planned-directory");
    assert!(!root.join("sub/deep").exists());
    assert!(!root.join("sub/deep/a.bin").exists());
}

#[test]
fn ancestors_are_listed_first_and_still_not_created() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let plan = plan(vec![d("a"), d("a/b"), f("a/b/x.bin", 1, 1)], &root);
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let pre = run(&rt, &root, &plan, limits).unwrap();
    assert_eq!(pre.planned_directories().len(), 2);
    assert_eq!(pre.planned_directories()[0].path(), "a");
    assert_eq!(pre.planned_directories()[1].path(), "a/b");
    assert!(!root.join("a").exists());
}

#[test]
fn only_the_absent_level_is_declared_when_the_base_parent_exists() {
    let (_t, root) = private_root();
    make_directory(&root.join("a")).unwrap();
    let rt = runtime(&root);
    let plan = plan(vec![d("a"), d("a/b"), f("a/b/x.bin", 1, 1)], &root);
    let limits = PreflightLimits {
        allow_planned_directories: true,
        ..PreflightLimits::default()
    };
    let pre = run(&rt, &root, &plan, limits).unwrap();
    // `a` already exists privately, so only `a/b` is a declaration.
    assert_eq!(pre.planned_directories().len(), 1);
    assert_eq!(pre.planned_directories()[0].path(), "a/b");
    assert_eq!(pre.entries()[0].parent_id(), "planned-directory");
    assert!(!root.join("a/b").exists());
    assert!(!root.join("a/b/x.bin").exists());
}

#[test]
fn ascii_case_collision_in_the_plan_is_refused() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    // Two distinct files whose names collide only when ASCII case is folded.
    let plan = plan(vec![f("A.bin", 1, 1), f("a.bin", 1, 2)], &root);
    let error = run(&rt, &root, &plan, PreflightLimits::default()).unwrap_err();
    assert!(
        format!("{error:#}").contains("collide ignoring ASCII case"),
        "{error:#}"
    );
}

#[test]
fn observation_is_bound_to_one_ordered_plan() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let first = plan(vec![f("b.bin", 1, 1)], &root);
    let second = plan(vec![f("b.bin", 1, 1), f("c.bin", 2, 2)], &root);
    let pre = run(&rt, &root, &first, PreflightLimits::default()).unwrap();
    pre.matches(&first).unwrap();
    assert!(pre.matches(&second).is_err());
}

#[test]
fn hook_observation_is_ordered_and_cancellation_stops_the_round() {
    let (_t, root) = private_root();
    make_directory(&root.join("sub")).unwrap();
    let rt = runtime(&root);
    let plan = plan(
        vec![d("sub"), f("a.bin", 1, 1), f("sub/b.bin", 2, 2)],
        &root,
    );
    let cancel = CancelToken::new();
    let mut seen: Vec<(String, PathBuf)> = Vec::new();
    let error = rt
        .preflight_fleet_target_for_test(
            &root,
            &plan,
            PreflightLimits::default(),
            &cancel,
            |event| {
                seen.push((event.relative.to_string(), event.destination.to_path_buf()));
                cancel.cancel();
                Ok(())
            },
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("cancelled"), "{error:#}");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "a.bin");
    assert!(seen[0].1.ends_with("a.bin"));
    assert!(!root.join("a.bin").exists());
    assert!(!root.join("sub/b.bin").exists());
}

#[test]
fn cancelled_preflight_observes_nothing() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let plan = plan(vec![f("b.bin", 1, 1)], &root);
    let cancel = CancelToken::new();
    cancel.cancel();
    let error = rt
        .preflight_fleet_target(&root, &plan, PreflightLimits::default(), &cancel)
        .unwrap_err();
    assert!(format!("{error:#}").contains("cancelled"), "{error:#}");
    assert!(!root.join("b.bin").exists());
}

#[test]
fn portable_component_profile_refuses_windows_only_names_and_separators() {
    for name in [
        "CON",
        "lpt1.txt",
        "trailing.",
        "trailing ",
        "a:b",
        "a/b",
        "..",
    ] {
        assert!(
            portable_component(name).is_err(),
            "accepted unportable component {name}"
        );
    }
    for name in ["ok.bin", "a-b_c.txt", "..hidden"] {
        portable_component(name).unwrap();
    }
    assert!(portable_component(&"a".repeat(MAX_COMPONENT_BYTES + 1)).is_err());
}

#[test]
fn limits_are_validated_before_any_observation() {
    let (_t, root) = private_root();
    let rt = runtime(&root);
    let plan = plan(vec![f("b.bin", 1, 1)], &root);
    let error = run(
        &rt,
        &root,
        &plan,
        PreflightLimits {
            max_files: 0,
            ..PreflightLimits::default()
        },
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("limits outside hard ceilings"),
        "{error:#}"
    );
}
