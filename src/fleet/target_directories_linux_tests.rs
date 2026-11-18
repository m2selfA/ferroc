use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::{make_directory, open_private},
        sync_exec::CancelToken,
    },
};
use anyhow::ensure;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn fixture() -> (tempfile::TempDir, PathBuf, Policy) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("target");
    make_directory(&root).unwrap();
    let policy = Policy::new(vec![root.clone()], false).unwrap();
    (temp, root, policy)
}

#[test]
fn nested_private_parents_create_no_file_and_fds_do_not_exclude_rename() {
    let (_temp, root, policy) = fixture();
    let destination = root.join("one/two/a.bin");
    let pinned = prepare(&policy, &root, &destination, || Ok(())).unwrap();
    assert_eq!(pinned.created, 2);
    assert!(open_private(&root.join("one"), true).is_ok());
    assert!(open_private(&root.join("one/two"), true).is_ok());
    assert!(!destination.exists());
    fs::rename(root.join("one"), root.join("moved")).unwrap();
    assert!(
        root.join("moved/two").is_dir(),
        "Linux FD does not deny rename"
    );
    drop(pinned);
}

#[test]
fn existing_private_directories_keep_content_and_second_round_creates_nothing() {
    let (_temp, root, policy) = fixture();
    make_directory(&root.join("one")).unwrap();
    fs::write(root.join("one/keep"), b"untouched").unwrap();
    let first = prepare(&policy, &root, &root.join("one/two/a"), || Ok(())).unwrap();
    assert_eq!(first.created, 1);
    drop(first);
    let again = prepare(&policy, &root, &root.join("one/two/a"), || Ok(())).unwrap();
    assert_eq!(again.created, 0);
    assert_eq!(fs::read(root.join("one/keep")).unwrap(), b"untouched");
}

#[test]
fn invalid_names_outside_traversal_and_missing_root_make_nothing() {
    let (temp, root, policy) = fixture();
    for relative in [
        "../escape/a",
        "good/CON/a",
        "good/a./b",
        "good/非ASCII/a",
        "good/.ferroc-fleet-stage/a",
    ] {
        assert!(
            prepare(&policy, &root, &root.join(relative), || Ok(())).is_err(),
            "{relative}"
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }
    assert!(prepare(&policy, &root, &temp.path().join("outside/a"), || Ok(())).is_err());
    assert!(prepare(&policy, &root, &root, || Ok(())).is_err());
    assert!(
        prepare(
            &policy,
            &root.join("missing"),
            &root.join("missing/child/a"),
            || Ok(())
        )
        .is_err()
    );
    assert!(!root.join("missing").exists());
}

#[test]
fn file_symlink_parent_and_symlink_root_never_get_descendants() {
    let (_temp, root, policy) = fixture();
    fs::write(root.join("file"), b"keep").unwrap();
    assert!(prepare(&policy, &root, &root.join("file/child/a"), || Ok(())).is_err());
    make_directory(&root.join("real")).unwrap();
    symlink(root.join("real"), root.join("link")).unwrap();
    assert!(prepare(&policy, &root, &root.join("link/child/a"), || Ok(())).is_err());
    assert!(!root.join("real/child").exists());
    assert!(
        prepare(
            &policy,
            &root.join("link"),
            &root.join("link/child/a"),
            || Ok(())
        )
        .is_err()
    );
    assert!(!root.join("real/child").exists());
    assert_eq!(fs::read(root.join("file")).unwrap(), b"keep");
}

#[test]
fn nonprivate_root_or_parent_is_rejected_without_chmod_or_creation() {
    let (_temp, root, policy) = fixture();
    for path in [&root, &root.join("existing")] {
        if !path.exists() {
            make_directory(path).unwrap();
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        let destination = path.join("new/a");
        assert!(prepare(&policy, &root, &destination, || Ok(())).is_err());
        assert!(!path.join("new").exists());
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn cancellation_before_and_between_mkdirs_keeps_only_partial_private_dirs() {
    let (_temp, root, policy) = fixture();
    let token = CancelToken::new();
    token.cancel();
    assert!(
        prepare(&policy, &root, &root.join("never/a"), || {
            ensure!(!token.is_cancelled(), "cancelled");
            Ok(())
        })
        .is_err()
    );
    assert!(!root.join("never").exists());
    let token = CancelToken::new();
    assert!(
        prepare_with(
            &policy,
            &root,
            &root.join("one/two/a"),
            || {
                ensure!(!token.is_cancelled(), "cancelled");
                Ok(())
            },
            |point, path| {
                if point == CreatePoint::Before && path.ends_with("two") {
                    token.cancel();
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert!(open_private(&root.join("one"), true).is_ok());
    assert!(!root.join("one/two").exists());
}

#[test]
fn concurrent_creator_is_not_adopted_or_deleted() {
    let (_temp, root, policy) = fixture();
    assert!(
        prepare_with(
            &policy,
            &root,
            &root.join("one/two/a"),
            || Ok(()),
            |point, path| {
                if point == CreatePoint::Before && path.ends_with("two") {
                    make_directory(path)?;
                    fs::write(path.join("foreign"), b"do not delete")?;
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(
        fs::read(root.join("one/two/foreign")).unwrap(),
        b"do not delete"
    );
    assert!(!root.join("one/two/a").exists());
}

#[test]
fn ancestor_move_before_mkdir_is_detected_without_creating_in_old_parent() {
    let (_temp, root, policy) = fixture();
    assert!(
        prepare_with(
            &policy,
            &root,
            &root.join("one/two/a"),
            || Ok(()),
            |point, path| {
                if point == CreatePoint::Before && path.ends_with("two") {
                    fs::rename(root.join("one"), root.join("moved"))?;
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert!(root.join("moved").is_dir());
    assert!(!root.join("moved/two").exists());
    assert!(!root.join("one").exists());
}

#[test]
fn ancestor_move_after_mkdir_can_leave_private_child_without_file_or_rollback() {
    let (_temp, root, policy) = fixture();
    assert!(
        prepare_with(
            &policy,
            &root,
            &root.join("one/two/a"),
            || Ok(()),
            |point, path| {
                if point == CreatePoint::After && path.ends_with("two") {
                    fs::rename(root.join("one"), root.join("moved"))?;
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert!(open_private(&root.join("moved/two"), true).is_ok());
    assert!(!root.join("moved/two/a").exists());
    assert!(!root.join("one").exists());
}

#[test]
fn lease_failure_after_mkdir_keeps_private_dir_and_creates_nothing_further() {
    let (_temp, root, policy) = fixture();
    assert!(
        prepare(&policy, &root, &root.join("one/two/a"), || {
            ensure!(!root.join("one").exists(), "lease expired after syscall");
            Ok(())
        })
        .is_err()
    );
    assert!(open_private(&root.join("one"), true).is_ok());
    assert!(!root.join("one/two").exists());
    assert!(!root.join("one/two/a").exists());
}
