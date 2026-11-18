use super::*;
use crate::{
    config::Policy,
    fleet::{
        identity::{make_directory, open_private},
        sync_exec::CancelToken,
    },
};
use std::fs;

fn fixture() -> (tempfile::TempDir, PathBuf, Policy) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("target");
    make_directory(&root).unwrap();
    let policy = Policy::new(vec![root.clone()], false).unwrap();
    (temp, root, policy)
}

#[test]
fn nested_private_parents_created_without_destination_and_guards_pin_them() {
    let (_temp, root, policy) = fixture();
    let destination = root.join("one/two/a.bin");
    let pinned = prepare(&policy, &root, &destination, || Ok(())).unwrap();
    assert_eq!(pinned.created, 2);
    assert!(root.join("one/two").is_dir());
    assert!(!destination.exists());
    assert!(open_private(&root.join("one"), true).is_ok());
    assert!(open_private(&root.join("one/two"), true).is_ok());
    assert!(fs::rename(root.join("one"), root.join("moved")).is_err());
    drop(pinned);
    fs::rename(root.join("one"), root.join("moved")).unwrap();
    assert!(root.join("moved/two").is_dir());
}

#[test]
fn existing_private_directories_and_their_contents_are_not_modified() {
    let (_temp, root, policy) = fixture();
    make_directory(&root.join("one")).unwrap();
    fs::write(root.join("one/keep"), b"untouched").unwrap();
    let first = prepare(&policy, &root, &root.join("one/two/a.bin"), || Ok(())).unwrap();
    assert_eq!(first.created, 1);
    drop(first);
    let again = prepare(&policy, &root, &root.join("one/two/a.bin"), || Ok(())).unwrap();
    assert_eq!(again.created, 0);
    assert_eq!(fs::read(root.join("one/keep")).unwrap(), b"untouched");
}

#[test]
fn invalid_names_traversal_outside_and_missing_root_create_nothing() {
    let (temp, root, policy) = fixture();
    for relative in [
        "../escape/a",
        "valid/CON/a",
        "valid/a./b",
        "valid/非ASCII/a",
        "valid/.ferroc-fleet-stage/a",
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
fn file_or_junction_parent_is_rejected_without_writing_through_it() {
    let (_temp, root, policy) = fixture();
    fs::write(root.join("file"), b"keep").unwrap();
    assert!(prepare(&policy, &root, &root.join("file/child/a"), || Ok(())).is_err());
    make_directory(&root.join("real")).unwrap();
    let output = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(root.join("link"))
        .arg(root.join("real"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(prepare(&policy, &root, &root.join("link/child/a"), || Ok(())).is_err());
    assert!(!root.join("real/child").exists());
    assert_eq!(fs::read(root.join("file")).unwrap(), b"keep");
}

#[test]
fn cancellation_before_first_create_and_between_creates_preserves_partial_effects() {
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
            |path| {
                if path.ends_with("two") {
                    token.cancel();
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert!(root.join("one").is_dir());
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
            |path| {
                if path.ends_with("two") {
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
}

#[test]
fn lease_failure_immediately_after_create_keeps_private_directory_but_no_file() {
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
