use super::*;
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
fn p(s: Vec<ManifestEntry>, t: Vec<ManifestEntry>, c: Comparison) -> DiffPlan {
    diff(&m(s), &m(t), c).unwrap()
}
fn copy(plan: &DiffPlan, index: usize) -> (u64, CopyReason, CopyTarget) {
    match plan.changes()[index].difference {
        Difference::CopyWholeFile {
            bytes,
            reason,
            target,
        } => (bytes, reason, target),
        ref other => panic!("not a copy: {other:?}"),
    }
}
#[test]
fn checksum_is_default_and_dry_run_is_not_native_name_or_apply_permission() {
    let plan = p(vec![], vec![], Comparison::default());
    assert_eq!(plan.comparison(), Comparison::Checksum);
    assert!(plan.is_dry_run());
    assert_eq!(plan.namespace(), Namespace::ExactUtf8Unqualified);
    assert!(plan.changes().is_empty());
    assert_eq!(plan.file_bytes_selected(), 0);
    let j = serde_json::to_value(plan).unwrap();
    assert_eq!(j["dry_run"], true);
    assert_eq!(j["namespace"], "exactUtf8Unqualified");
}
#[test]
fn equal_size_and_mtime_but_different_sha_is_a_whole_file_change() {
    let plan = p(
        vec![f("x", 3, 10, Some(1))],
        vec![f("x", 3, 10, Some(2))],
        Comparison::default(),
    );
    assert_eq!(
        copy(&plan, 0),
        (3, CopyReason::ChecksumChanged, CopyTarget::ExistingFile)
    );
    assert_eq!(plan.unchanged_files(), 0);
    assert_eq!(plan.file_bytes_selected(), 3);
}
#[test]
fn quick_detects_backdated_or_newer_mtime_not_just_source_newer() {
    for mtime in [-10, 1, 9, 11, 100] {
        let plan = p(
            vec![f("x", 3, mtime, None)],
            vec![f("x", 3, 10, None)],
            Comparison::Quick,
        );
        assert_eq!(copy(&plan, 0).1, CopyReason::MtimeChanged);
    }
}
#[test]
fn checksum_ignores_mtime_only_changes_when_size_and_sha_equal() {
    for mtime in [-10, 10, 100] {
        let plan = p(
            vec![f("x", 3, mtime, Some(1))],
            vec![f("x", 3, 10, Some(1))],
            Comparison::Checksum,
        );
        assert!(plan.changes().is_empty());
        assert_eq!(plan.unchanged_files(), 1);
    }
}
#[test]
fn quick_equal_metadata_can_miss_real_digest_change_and_is_only_heuristic() {
    let s = vec![f("x", 3, 10, Some(1))];
    let t = vec![f("x", 3, 10, Some(2))];
    let quick = p(s.clone(), t.clone(), Comparison::Quick);
    assert!(quick.changes().is_empty());
    assert_eq!(quick.unchanged_files(), 1);
    assert_eq!(
        copy(&p(s, t, Comparison::Checksum), 0).1,
        CopyReason::ChecksumChanged
    );
}
#[test]
fn size_difference_is_not_skipped_even_if_offered_digest_is_equal() {
    for mode in [Comparison::Checksum, Comparison::Quick] {
        let plan = p(
            vec![f("x", 3, 10, Some(1))],
            vec![f("x", 4, 10, Some(1))],
            mode,
        );
        assert_eq!(copy(&plan, 0).1, CopyReason::SizeChanged);
    }
}
#[test]
fn missing_source_digest_does_not_fall_back_to_metadata_or_partial_plan() {
    for target in [
        vec![],
        vec![f("x", 3, 10, Some(1))],
        vec![f("x", 4, 10, None)],
    ] {
        let e = diff(
            &m(vec![f("a", 0, 0, Some(0)), f("x", 3, 10, None)]),
            &m(target),
            Comparison::Checksum,
        )
        .unwrap_err();
        assert!(e.to_string().contains("source checksum required"));
    }
}
#[test]
fn missing_equal_size_target_digest_is_rejected_but_irrelevant_hashes_are_not_required() {
    let s = m(vec![f("x", 3, 10, Some(1))]);
    let e = diff(&s, &m(vec![f("x", 3, 10, None)]), Comparison::Checksum).unwrap_err();
    assert!(e.to_string().contains("target checksum required"));
    let plan = diff(
        &s,
        &m(vec![f("x", 4, 10, None), f("extra", 100, 0, None)]),
        Comparison::Checksum,
    )
    .unwrap();
    assert_eq!(copy(&plan, 0).1, CopyReason::SizeChanged);
    assert_eq!(plan.retained_target_only()[0].path, "extra");
}
#[test]
fn target_only_files_and_subtrees_are_retained_never_scheduled_for_delete() {
    let plan = p(
        vec![],
        vec![d("keep"), d("keep/empty"), f("keep/file", 3, 10, None)],
        Comparison::Checksum,
    );
    assert!(plan.changes().is_empty());
    assert_eq!(
        plan.retained_target_only()
            .iter()
            .map(|x| x.path.as_str())
            .collect::<Vec<_>>(),
        vec!["keep", "keep/empty", "keep/file"]
    );
    assert_eq!(plan.file_bytes_selected(), 0);
}
#[test]
fn empty_directories_and_new_tree_are_described_in_parent_first_order() {
    let plan = p(
        vec![d("z"), d("a"), d("a/empty"), f("a/file", 3, 0, Some(1))],
        vec![],
        Comparison::Checksum,
    );
    assert_eq!(
        plan.changes()
            .iter()
            .map(|x| x.path.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "a/empty", "a/file", "z"]
    );
    assert!(matches!(
        plan.changes()[0].difference,
        Difference::EnsureDirectory
    ));
    assert!(matches!(
        plan.changes()[1].difference,
        Difference::EnsureDirectory
    ));
    assert_eq!(copy(&plan, 2).2, CopyTarget::Absent);
    assert_eq!(plan.file_bytes_selected(), 3);
}
#[test]
fn duplicate_paths_missing_parents_and_file_parents_are_rejected() {
    for v in [
        vec![d("x"), d("x")],
        vec![f("x", 1, 0, Some(1)), d("x")],
        vec![f("x/y", 1, 0, Some(1))],
        vec![f("x", 1, 0, Some(1)), f("x/y", 1, 0, Some(1))],
    ] {
        assert!(Manifest::new(v, ManifestLimits::default()).is_err());
    }
}
#[test]
fn traversal_absolute_alias_spellings_controls_and_stage_components_are_rejected() {
    for path in [
        "",
        "/x",
        "//x",
        "C:/x",
        "C:\\x",
        "x\\y",
        "./x",
        "../x",
        "x/../y",
        "x/./y",
        "x//y",
        "x/",
        "x:y",
        "x\ny",
        "x\0y",
        "x\u{202e}y",
        ".ferroc-fleet-x",
        "x/.FERROC-FLEET-x/y",
    ] {
        assert!(
            Manifest::new(vec![f(path, 1, 0, Some(1))], ManifestLimits::default()).is_err(),
            "rejected {path:?}"
        );
    }
}
#[test]
fn distinct_utf8_unicode_and_case_keys_are_not_lowercased_or_normalized() {
    let names = ["A", "a", "\u{0130}", "i\u{0307}", "\u{00e9}", "e\u{0301}"];
    let source = m(names.iter().map(|n| f(n, 1, 0, Some(1))).collect());
    assert_eq!(source.len(), 6);
    let plan = diff(&source, &m(vec![]), Comparison::Checksum).unwrap();
    assert_eq!(plan.changes().len(), 6);
    assert_eq!(plan.namespace(), Namespace::ExactUtf8Unqualified);
    assert_ne!(names[2], names[3]);
    assert_eq!(names[2].to_lowercase(), names[3]);
}
#[test]
fn per_path_and_aggregate_limits_count_utf8_bytes_not_characters() {
    let ok = "é".repeat(MAX_PATH_BYTES / 2);
    let manifest = m(vec![f(&ok, 1, 0, Some(1))]);
    assert_eq!(manifest.path_bytes(), MAX_PATH_BYTES);
    assert!(
        Manifest::new(
            vec![f(&(ok + "a"), 1, 0, Some(1))],
            ManifestLimits::default()
        )
        .is_err()
    );
    let limits = ManifestLimits {
        max_entries: 2,
        max_total_path_bytes: 3,
    };
    assert_eq!(
        Manifest::new(vec![d("é"), d("x")], limits)
            .unwrap()
            .path_bytes(),
        3
    );
    assert!(Manifest::new(vec![d("é"), d("xy")], limits).is_err());
}
#[test]
fn entry_and_total_byte_limits_are_exact_no_silent_truncation() {
    let limits = ManifestLimits {
        max_entries: 2,
        max_total_path_bytes: 2,
    };
    let manifest = Manifest::new(vec![d("a"), d("b")], limits).unwrap();
    assert_eq!(manifest.len(), 2);
    assert_eq!(manifest.path_bytes(), 2);
    let e = Manifest::new(vec![d("a"), d("b"), d("c")], limits).unwrap_err();
    assert!(e.to_string().contains("entry limit"));
    let e = Manifest::new(vec![d("a"), d("bb")], limits).unwrap_err();
    assert!(e.to_string().contains("aggregate path bytes"));
}
#[test]
fn directory_over_file_conflict_blocks_descendants_instead_of_scheduling_copy() {
    let plan = p(
        vec![
            d("a"),
            d("a/b"),
            f("a/b/file", 3, 0, None),
            f("z", 1, 0, Some(1)),
        ],
        vec![f("a", 3, 0, None)],
        Comparison::Checksum,
    );
    assert!(matches!(
        plan.changes()[0].difference,
        Difference::TypeConflict {
            source: EntryType::Directory,
            target: EntryType::File
        }
    ));
    for i in [1, 2] {
        assert!(
            matches!(&plan.changes()[i].difference,Difference::BlockedByAncestor{ancestor}if ancestor=="a")
        );
    }
    assert_eq!(copy(&plan, 3).0, 1);
    assert_eq!(plan.file_bytes_selected(), 1);
}
#[test]
fn blocked_ancestor_matches_component_boundary_not_similar_prefix() {
    let plan = p(
        vec![d("a"), f("a/file", 3, 0, None), f("ab", 2, 0, Some(1))],
        vec![f("a", 1, 0, None)],
        Comparison::Checksum,
    );
    assert!(
        matches!(&plan.changes()[1].difference,Difference::BlockedByAncestor{ancestor}if ancestor=="a")
    );
    assert_eq!(plan.changes()[2].path, "ab");
    assert_eq!(copy(&plan, 2).0, 2);
}

#[test]
fn file_over_directory_conflict_does_not_delete_or_replace_target_tree() {
    let plan = p(
        vec![f("a", 3, 0, None)],
        vec![d("a"), f("a/file", 2, 0, None)],
        Comparison::Checksum,
    );
    assert!(matches!(
        plan.changes()[0].difference,
        Difference::TypeConflict {
            source: EntryType::File,
            target: EntryType::Directory
        }
    ));
    assert_eq!(plan.retained_target_only()[0].path, "a/file");
    assert_eq!(plan.file_bytes_selected(), 0);
}
#[test]
fn lexical_plan_is_deterministic_under_all_three_entry_permutations() {
    let entries = [d("a"), f("a/x", 3, 0, Some(1)), f("b", 4, 0, Some(2))];
    let target = m(vec![f("b", 4, 0, Some(2)), d("a")]);
    let expected = diff(&m(entries.to_vec()), &target, Comparison::Checksum).unwrap();
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        assert_eq!(
            diff(
                &m(order.map(|i| entries[i].clone()).to_vec()),
                &target,
                Comparison::Checksum
            )
            .unwrap(),
            expected
        );
    }
}
#[test]
fn file_size_hard_limits_and_depth_and_config_cannot_be_weakened() {
    m(vec![f("x", MAX_FILE_BYTES, 0, Some(1))]);
    assert!(
        Manifest::new(
            vec![f("x", MAX_FILE_BYTES + 1, 0, Some(1))],
            ManifestLimits::default()
        )
        .is_err()
    );
    for limits in [
        ManifestLimits {
            max_entries: 0,
            ..Default::default()
        },
        ManifestLimits {
            max_entries: MAX_ENTRIES + 1,
            ..Default::default()
        },
        ManifestLimits {
            max_total_path_bytes: 0,
            ..Default::default()
        },
        ManifestLimits {
            max_total_path_bytes: MAX_TOTAL_PATH_BYTES + 1,
            ..Default::default()
        },
    ] {
        assert!(Manifest::new(vec![], limits).is_err());
    }
    let mut v = vec![];
    let mut path = String::new();
    for _ in 0..MAX_DEPTH {
        if !path.is_empty() {
            path.push('/');
        }
        path.push('a');
        v.push(d(&path));
    }
    assert_eq!(m(v.clone()).len(), MAX_DEPTH);
    v.push(d(&(path + "/a")));
    let e = Manifest::new(v, ManifestLimits::default()).unwrap_err();
    assert!(e.to_string().contains("depth"));
}
#[test]
fn checksum_size_selection_and_zero_files_are_descriptive_not_network_counters() {
    let plan = p(
        vec![
            f("empty", 0, 0, Some(0)),
            f("large", MAX_FILE_BYTES, 0, Some(1)),
        ],
        vec![],
        Comparison::Checksum,
    );
    assert_eq!(plan.changes().len(), 2);
    assert_eq!(copy(&plan, 0).0, 0);
    assert_eq!(plan.file_bytes_selected(), MAX_FILE_BYTES);
    assert_eq!(copy(&plan, 1).2, CopyTarget::Absent);
    assert!(plan.is_dry_run());
}
#[test]
fn scalar_small_state_oracle_covers_presence_type_sha_and_backdated_mtime() {
    let cell = |path: &str, n: usize| match n {
        0 => None,
        1 => Some(d(path)),
        2 => Some(f(path, 3, 10, Some(1))),
        _ => Some(f(path, 3, 9, Some(2))),
    };
    for a in 0..16 {
        for b in 0..16 {
            for mode in [Comparison::Checksum, Comparison::Quick] {
                let av = [a % 4, a / 4];
                let bv = [b % 4, b / 4];
                let source = m(["a", "b"]
                    .iter()
                    .zip(av)
                    .filter_map(|(p, n)| cell(p, n))
                    .collect());
                let target = m(["a", "b"]
                    .iter()
                    .zip(bv)
                    .filter_map(|(p, n)| cell(p, n))
                    .collect());
                let plan = diff(&source, &target, mode).unwrap();
                let (mut changes, mut retained, mut unchanged, mut dirs, mut bytes) =
                    (vec![], vec![], 0, 0, 0);
                for (i, path) in ["a", "b"].iter().enumerate() {
                    let (s, t) = (av[i], bv[i]);
                    if s == 0 {
                        if t != 0 {
                            retained.push((*path).to_owned());
                        }
                        continue;
                    }
                    if s == 1 && t == 1 {
                        dirs += 1;
                        continue;
                    }
                    if s >= 2 && s == t {
                        unchanged += 1;
                        continue;
                    }
                    let action = if t == 0 {
                        if s == 1 {
                            Difference::EnsureDirectory
                        } else {
                            bytes += 3;
                            Difference::CopyWholeFile {
                                bytes: 3,
                                reason: CopyReason::MissingTarget,
                                target: CopyTarget::Absent,
                            }
                        }
                    } else if s == 1 || t == 1 {
                        Difference::TypeConflict {
                            source: if s == 1 {
                                EntryType::Directory
                            } else {
                                EntryType::File
                            },
                            target: if t == 1 {
                                EntryType::Directory
                            } else {
                                EntryType::File
                            },
                        }
                    } else {
                        bytes += 3;
                        Difference::CopyWholeFile {
                            bytes: 3,
                            reason: if mode == Comparison::Checksum {
                                CopyReason::ChecksumChanged
                            } else {
                                CopyReason::MtimeChanged
                            },
                            target: CopyTarget::ExistingFile,
                        }
                    };
                    changes.push(PathDifference {
                        path: (*path).into(),
                        difference: action,
                    });
                }
                assert_eq!(plan.changes(), changes);
                assert_eq!(
                    plan.retained_target_only()
                        .iter()
                        .map(|x| x.path.clone())
                        .collect::<Vec<_>>(),
                    retained
                );
                assert_eq!(plan.unchanged_files(), unchanged);
                assert_eq!(plan.matching_directories(), dirs);
                assert_eq!(plan.file_bytes_selected(), bytes);
            }
        }
    }
}
#[test]
fn hundred_thousand_entries_second_pass_zero_change_then_exactly_one_hash_change() {
    let start = std::time::Instant::now();
    let make = |changed: bool| {
        (0..MAX_ENTRIES)
            .map(|i| {
                f(
                    &format!("file{i:06}"),
                    3,
                    10,
                    Some(if changed && i == MAX_ENTRIES - 1 {
                        2
                    } else {
                        1
                    }),
                )
            })
            .collect()
    };
    let baseline = m(make(false));
    let same = m(make(false));
    let first = diff(&baseline, &same, Comparison::Checksum).unwrap();
    assert_eq!(first.unchanged_files(), MAX_ENTRIES);
    assert!(first.changes().is_empty());
    let changed = m(make(true));
    let next = diff(&changed, &baseline, Comparison::Checksum).unwrap();
    assert_eq!(next.unchanged_files(), MAX_ENTRIES - 1);
    assert_eq!(next.changes().len(), 1);
    assert_eq!(next.changes()[0].path, "file099999");
    assert_eq!(
        copy(&next, 0),
        (3, CopyReason::ChecksumChanged, CopyTarget::ExistingFile)
    );
    let too_many = (0..=MAX_ENTRIES).map(|i| d(&format!("f{i}"))).collect();
    assert!(Manifest::new(too_many, ManifestLimits::default()).is_err());
    println!(
        "MANIFEST_PURE_SCALE: entries={} elapsed_ms={} zeroChangePass+oneSHAChange/metadataOnly/noFilesystemScan/noNativeNamespace/noNetwork/noApply",
        MAX_ENTRIES,
        start.elapsed().as_millis()
    );
}
