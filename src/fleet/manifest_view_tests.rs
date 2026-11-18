use super::*;
use crate::fleet::manifest::EntryKind;
fn manifest(n: usize) -> Manifest {
    Manifest::new(
        (0..n)
            .map(|i| ManifestEntry {
                path: format!("file-{i:05}"),
                kind: EntryKind::File {
                    size: i as u64,
                    mtime_ns: -7,
                    sha256: Some([i as u8; 32]),
                },
            })
            .collect(),
        ManifestLimits::default(),
    )
    .unwrap()
}
#[test]
fn exact_subtree_rules_and_canonical_digest() {
    let a = ScanRules::new(vec!["skip".into(), "other/nested".into()]).unwrap();
    let b = ScanRules::new(vec!["other/nested".into(), "skip".into()]).unwrap();
    assert_eq!(a.digest(), b.digest());
    for p in ["skip", "skip/x", "other/nested/x"] {
        assert!(a.excludes(p));
    }
    for p in ["skipper", "Skip", "x/skip", "other/nestedish"] {
        assert!(!a.excludes(p));
    }
    assert_ne!(a.digest(), ScanRules::default().digest());
}
#[test]
fn invalid_duplicate_glob_and_excess_rules_rejected() {
    for p in [
        "",
        "../x",
        "/x",
        "a\\b",
        "a/",
        "a/*",
        "a/?",
        "a/[x]",
        ".ferroc-fleet-hidden",
    ] {
        assert!(ScanRules::new(vec![p.into()]).is_err(), "{p}");
    }
    assert!(ScanRules::new(vec!["a".into(), "a".into()]).is_err());
    assert!(ScanRules::new((0..129).map(|i| format!("x{i}")).collect()).is_err());
    assert!(ScanRules::new((0..5).map(|i| format!("{i}{}", "x".repeat(3999))).collect()).is_err());
}
#[test]
fn filtering_preserves_parents_and_exact_keys() {
    let m = Manifest::new(
        vec![
            ManifestEntry {
                path: "a".into(),
                kind: EntryKind::Directory,
            },
            ManifestEntry {
                path: "a/drop".into(),
                kind: EntryKind::Directory,
            },
            ManifestEntry {
                path: "a/drop/child".into(),
                kind: EntryKind::Directory,
            },
            ManifestEntry {
                path: "a/dropper".into(),
                kind: EntryKind::Directory,
            },
        ],
        ManifestLimits::default(),
    )
    .unwrap();
    let out = ScanRules::new(vec!["a/drop".into()])
        .unwrap()
        .filter(&m)
        .unwrap();
    assert_eq!(
        out.entries().map(|(p, _)| p).collect::<Vec<_>>(),
        vec!["a", "a/dropper"]
    );
}
#[test]
fn pages_roundtrip_order_and_exact_json_bounds() {
    let pages = ManifestPages::new(
        manifest(19),
        &ScanRules::default(),
        PageLimits {
            max_entries: 3,
            max_json_bytes: 1600,
        },
    )
    .unwrap();
    let mut cursor = None;
    let mut all = vec![];
    let mut id = None;
    loop {
        let page = pages.page(cursor.as_deref()).unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() <= 1600);
        assert!(page.entries.len() <= 3);
        assert_eq!(page.offset, all.len());
        if let Some(id) = id {
            assert_eq!(page.scan_id, id);
        } else {
            id = Some(page.scan_id);
        }
        assert_eq!(page.consistency, "callerSuppliedMetadata");
        all.extend(page.entries.into_iter().map(|e| e.path));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        all,
        (0..19).map(|i| format!("file-{i:05}")).collect::<Vec<_>>()
    );
}
#[test]
fn cursor_tamper_offset_and_other_owner_rejected() {
    let limits = PageLimits {
        max_entries: 1,
        ..PageLimits::default()
    };
    let pages = ManifestPages::new(manifest(3), &ScanRules::default(), limits).unwrap();
    let first = pages.page(None).unwrap();
    let token = first.next_cursor.unwrap();
    let mut bad = token.clone().into_bytes();
    bad[15] = if bad[15] == b'1' { b'2' } else { b'1' };
    assert!(
        pages
            .page(Some(std::str::from_utf8(&bad).unwrap()))
            .is_err()
    );
    for bad in ["", "ff", &"g".repeat(80), &"0".repeat(82)] {
        assert!(pages.page(Some(bad)).is_err());
    }
    for (m, r) in [
        (manifest(3), ScanRules::default()),
        (manifest(4), ScanRules::default()),
        (manifest(3), ScanRules::new(vec!["other".into()]).unwrap()),
    ] {
        assert!(
            ManifestPages::new(m, &r, limits)
                .unwrap()
                .page(Some(&token))
                .is_err()
        );
    }
    assert_eq!(pages.page(Some(&token)).unwrap().offset, 1);
    assert_eq!(pages.page(Some(&token)).unwrap().offset, 1); // immutable read replay
}
#[test]
fn empty_page_and_oversized_entry_fail_closed() {
    let pages =
        ManifestPages::new(manifest(0), &ScanRules::default(), PageLimits::default()).unwrap();
    let empty = pages.page(None).unwrap();
    assert!(empty.entries.is_empty() && empty.next_cursor.is_none());
    let long = Manifest::new(
        vec![ManifestEntry {
            path: "x".repeat(3000),
            kind: EntryKind::Directory,
        }],
        ManifestLimits::default(),
    )
    .unwrap();
    assert!(
        ManifestPages::new(
            long,
            &ScanRules::default(),
            PageLimits {
                max_entries: 1,
                max_json_bytes: 1024
            }
        )
        .unwrap()
        .page(None)
        .is_err()
    );
    for limits in [
        PageLimits {
            max_entries: 0,
            max_json_bytes: 4096,
        },
        PageLimits {
            max_entries: 1001,
            max_json_bytes: 4096,
        },
        PageLimits {
            max_entries: 1,
            max_json_bytes: MAX_PAGE_BYTES + 1,
        },
    ] {
        assert!(ManifestPages::new(manifest(0), &ScanRules::default(), limits).is_err());
    }
}
#[test]
fn content_digest_is_order_independent_but_changes_with_content() {
    let a = ManifestPages::new(manifest(4), &ScanRules::default(), PageLimits::default()).unwrap();
    let b = ManifestPages::new(manifest(4), &ScanRules::default(), PageLimits::default()).unwrap();
    let c = ManifestPages::new(manifest(5), &ScanRules::default(), PageLimits::default()).unwrap();
    assert_eq!(a.manifest_digest(), b.manifest_digest());
    assert_ne!(a.manifest_digest(), c.manifest_digest());
    assert_ne!(a.page(None).unwrap().scan_id, b.page(None).unwrap().scan_id);
}
#[test]
fn byte_cap_forces_pages_before_entry_cap_and_binds_policy() {
    let mut pages = ManifestPages::new(
        manifest(40),
        &ScanRules::default(),
        PageLimits {
            max_entries: 1000,
            max_json_bytes: 1500,
        },
    )
    .unwrap();
    let first = pages.page(None).unwrap();
    assert!(!first.entries.is_empty());
    assert!(first.entries.len() < 40);
    assert!(serde_json::to_vec(&first).unwrap().len() <= 1500);
    let token = first.next_cursor.unwrap();
    pages.limits.max_entries = 999;
    assert!(pages.page(Some(&token)).is_err());
    pages.limits.max_entries = 1000;
    pages.rules[0] ^= 1;
    assert!(pages.page(Some(&token)).is_err());
    pages.rules[0] ^= 1;
    pages.digest[0] ^= 1;
    assert!(pages.page(Some(&token)).is_err());
    pages.digest[0] ^= 1;
    let id = pages.id;
    pages.id = Uuid::new_v4();
    assert!(pages.page(Some(&token)).is_err());
    pages.id = id;
    assert!(pages.page(Some(&token)).is_ok());
}
#[test]
fn hundred_thousand_metadata_entries_page_without_gaps() {
    let pages = ManifestPages::new(
        manifest(100_000),
        &ScanRules::default(),
        PageLimits {
            max_entries: 1000,
            max_json_bytes: MAX_PAGE_BYTES,
        },
    )
    .unwrap();
    let mut cursor = None;
    let mut total = 0;
    loop {
        let page = pages.page(cursor.as_deref()).unwrap();
        assert_eq!(page.offset, total);
        for entry in &page.entries {
            assert_eq!(entry.path, format!("file-{total:05}"));
            total += 1;
        }
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_PAGE_BYTES);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(total, 100_000); // metadata-only, not an actual filesystem tree
}

#[cfg(windows)]
#[test]
fn native_excluded_subtree_is_not_hashed_but_names_count() {
    use crate::fleet::{manifest_scan::ScanLimits, sync_exec::CancelToken};
    use crate::{config::Policy, runtime::Runtime};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir(root.join("skip")).unwrap();
    std::fs::write(root.join("skip/large"), [0; 8192]).unwrap();
    std::fs::write(root.join("keep"), b"abc").unwrap();
    let rt = Runtime::new(Policy::new(vec![root.into()], false).unwrap());
    let limits = ScanLimits {
        max_hashed_bytes: 3,
        ..ScanLimits::default()
    };
    let stop = CancelToken::new();
    assert!(rt.scan_fleet_manifest(root, limits, &stop).is_err()); // old unfiltered path exhausts budget
    let rules = ScanRules::new(vec!["skip".into()]).unwrap();
    let observed = rt
        .scan_fleet_manifest_with_rules(root, limits, &rules, &stop)
        .unwrap();
    assert_eq!(observed.bytes_hashed(), 3);
    assert_eq!(observed.files_hashed(), 1);
    assert_eq!(observed.manifest().len(), 1);
    assert_eq!(observed.rules_digest(), rules.digest());
    let pages = ManifestPages::observed(observed, PageLimits::default()).unwrap();
    assert_eq!(pages.page(None).unwrap().consistency, "readSequence");
    let small = ScanLimits {
        manifest: ManifestLimits {
            max_entries: 1,
            ..ManifestLimits::default()
        },
        ..limits
    };
    assert!(
        rt.scan_fleet_manifest_with_rules(root, small, &rules, &stop)
            .is_err()
    );
    stop.cancel();
    assert!(
        rt.scan_fleet_manifest_with_rules(root, limits, &rules, &stop)
            .is_err()
    );
}
#[cfg(windows)]
#[test]
fn excluded_paths_cannot_bypass_policy_or_disabled_runtime() {
    use crate::fleet::{manifest_scan::ScanLimits, sync_exec::CancelToken};
    use crate::{config::Policy, runtime::Runtime};
    let temp = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let rules = ScanRules::new(vec!["skip".into()]).unwrap();
    let mut p = Policy::new(vec![temp.path().into()], false).unwrap();
    p.allow_transfers = false;
    let rt = Runtime::new(p);
    assert!(
        rt.scan_fleet_manifest_with_rules(
            temp.path(),
            ScanLimits::default(),
            &rules,
            &CancelToken::new()
        )
        .is_err()
    );
    let rt = Runtime::new(Policy::new(vec![temp.path().into()], false).unwrap());
    assert!(
        rt.scan_fleet_manifest_with_rules(
            other.path(),
            ScanLimits::default(),
            &rules,
            &CancelToken::new()
        )
        .is_err()
    );
}
