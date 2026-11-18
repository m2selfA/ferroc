//! Linux reserved-name replacement: primitive-level native cases only.
//! These do NOT prove host admission, journal state, receipts or crash recovery.
use super::*;
use std::ffi::OsStr;
use std::io::Write;

fn private_parent() -> (tempfile::TempDir, File) {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("parent");
    super::super::identity::make_directory(&dir).unwrap();
    let handle = super::super::identity::open_private(&dir, true).unwrap();
    (temp, handle)
}

fn stage(parent: &File, bytes: &[u8]) -> File {
    let file = create(parent).unwrap();
    (&file).write_all(bytes).unwrap();
    file
}

#[test]
fn replacement_swaps_the_destination_and_leaves_no_reserved_name() {
    let (_t, parent) = private_parent();
    let file = stage(&parent, b"replacement-bytes");
    let destination = _t.path().join("parent/dest.bin");
    std::fs::write(&destination, b"old-content").unwrap();
    let temporary = replace_temporary(&[0x11; 32]);
    replace(&file, &parent, OsStr::new("dest.bin"), &temporary).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"replacement-bytes");
    // Exactly one live name after the rename; the reserved one is gone.
    assert_eq!(file.metadata().unwrap().nlink(), 1);
    assert!(!_t.path().join("parent").join(&temporary).exists());
    object_id(&file, true).unwrap();
}

#[test]
fn existing_reserved_name_is_refused_without_touching_the_destination() {
    let (_t, parent) = private_parent();
    let file = stage(&parent, b"new");
    let destination = _t.path().join("parent/dest.bin");
    std::fs::write(&destination, b"old").unwrap();
    let temporary = replace_temporary(&[0x22; 32]);
    std::fs::write(_t.path().join("parent").join(&temporary), b"squatter").unwrap();
    let error = replace(&file, &parent, OsStr::new("dest.bin"), &temporary).unwrap_err();
    assert!(
        format!("{error:#}").contains("reserved replacement link"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"old");
    // The stage was never linked, so its byte owner is still anonymous.
    assert_eq!(file.metadata().unwrap().nlink(), 0);
    assert_eq!(
        std::fs::read(_t.path().join("parent").join(&temporary)).unwrap(),
        b"squatter"
    );
}

#[test]
fn directory_destination_fails_and_reports_the_residual_name() {
    let (_t, parent) = private_parent();
    let file = stage(&parent, b"new");
    std::fs::create_dir(_t.path().join("parent/dest.bin")).unwrap();
    let temporary = replace_temporary(&[0x33; 32]);
    let error = replace(&file, &parent, OsStr::new("dest.bin"), &temporary).unwrap_err();
    // rename(2) cannot replace a directory with a regular file.
    assert!(
        format!("{error:#}").contains("replacement rename"),
        "{error:#}"
    );
    assert!(_t.path().join("parent/dest.bin").is_dir());
    // The reserved name is deliberately left in place: no silent cleanup.
    assert_eq!(
        std::fs::read(_t.path().join("parent").join(&temporary)).unwrap(),
        b"new"
    );
    assert_eq!(file.metadata().unwrap().nlink(), 1);
}

#[test]
fn reserved_name_is_derived_from_the_job_digest_only() {
    let a = replace_temporary(&[0x01; 32]);
    let b = replace_temporary(&[0x01; 32]);
    let c = replace_temporary(&[0x02; 32]);
    assert_eq!(a, b);
    assert_ne!(a, c);
    let text = a.to_string_lossy().to_string();
    assert!(text.starts_with(".ferroc-fleet-repl-"));
    assert_eq!(text.len(), ".ferroc-fleet-repl-".len() + 32);
}

#[test]
fn invalid_components_are_refused_before_any_link() {
    let (_t, parent) = private_parent();
    let file = stage(&parent, b"new");
    for bad in ["", "a/b", ".", ".."] {
        let error = replace(&file, &parent, OsStr::new("dest.bin"), OsStr::new(bad)).unwrap_err();
        assert!(
            format!("{error:#}").contains("invalid target filename"),
            "{error:#}"
        );
    }
    assert_eq!(file.metadata().unwrap().nlink(), 0);
}
