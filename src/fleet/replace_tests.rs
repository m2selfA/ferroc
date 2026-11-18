//! Replace-mode publication contracts. These are LOCAL component probes: they
//! prove the pre-image gate and the atomic rename, not crash durability,
//! external-writer exclusion or any two-host behaviour.
use super::*;
use crate::config::Policy;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn stage_links(root: &tempfile::TempDir) -> usize {
    fs::read_dir(root.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|f| {
            f.file_name()
                .to_string_lossy()
                .starts_with(".ferroc-fleet-")
        })
        .count()
}

fn gate() -> Arc<Mutex<()>> {
    Arc::new(Mutex::new(()))
}
fn policy(root: &Path) -> Policy {
    Policy::new(vec![root.into()], false).unwrap()
}
/// Stage new bytes for `target`, with the destination already present as `old`.
fn replacing(root: &Path, old: &[u8], new: &[u8]) -> (StageFile, StageBudget, PreImage, PathBuf) {
    let target = root.join("target.bin");
    fs::write(&target, old).unwrap();
    let pre = PreImage::new(Sha256::digest(old).into(), old.len() as u64).unwrap();
    let budget = StageBudget::new(new.len() as u64, 1).unwrap();
    let mut stage = StageFile::prepare_replacing(
        policy(root),
        target.to_str().unwrap(),
        new.len() as u64,
        &budget,
        gate(),
        pre,
    )
    .unwrap();
    for (n, c) in new.chunks(64 * 1024).enumerate() {
        stage.write_chunk((n * 64 * 1024) as u64, c).unwrap();
    }
    (stage, budget, pre, target)
}
fn verify(stage: StageFile, new: &[u8]) -> VerifiedStage {
    stage
        .verify_with(Sha256::digest(new).into(), || Ok(()))
        .unwrap()
}

#[test]
fn authorized_replace_overwrites_existing_bytes_atomically() {
    let root = tempfile::tempdir().unwrap();
    let (stage, budget, pre, target) = replacing(root.path(), b"old-content", b"new-bytes");
    let verified = verify(stage, b"new-bytes");
    let published = verified.publish_replacing(pre, || Ok(())).unwrap();
    match published {
        Publication::Published {
            mode, size, sha256, ..
        } => {
            assert_eq!(mode, PublishMode::ReplaceExisting);
            assert_eq!(size, 9);
            assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(b"new-bytes")));
        }
        other => panic!("unexpected publication: {other:?}"),
    }
    assert_eq!(fs::read(&target).unwrap(), b"new-bytes");
    // The replacing path still owns no residual temp link and releases quota.
    assert_eq!(stage_links(&root), 0);
    assert_eq!(budget.usage().unwrap(), (0, 0));
}

#[test]
fn destination_changed_after_prepare_refuses_and_keeps_original_and_quota() {
    let root = tempfile::tempdir().unwrap();
    let (stage, budget, pre, target) = replacing(root.path(), b"old-content", b"new-bytes");
    let verified = verify(stage, b"new-bytes");
    // A different same-size content must not be replaced under the old grant.
    fs::write(&target, b"OLD-CONTENT").unwrap();
    let rejected = verified.publish_replacing(pre, || Ok(())).unwrap_err();
    assert!(
        rejected.reason().to_string().contains("pre-image"),
        "{rejected:?}"
    );
    assert_eq!(fs::read(&target).unwrap(), b"OLD-CONTENT");
    // Ownership is retained: the caller must settle journal state, not retry.
    let (stage, _) = rejected.into_parts();
    let stage = stage.into_stage();
    assert_eq!(budget.usage().unwrap(), (9, 1));
    stage.cancel().unwrap();
    assert_eq!(budget.usage().unwrap(), (0, 0));
}

#[test]
fn destination_removed_after_prepare_is_a_refusal_not_a_create() {
    let root = tempfile::tempdir().unwrap();
    let (stage, budget, pre, target) = replacing(root.path(), b"old-content", b"new-bytes");
    let verified = verify(stage, b"new-bytes");
    fs::remove_file(&target).unwrap();
    let rejected = verified.publish_replacing(pre, || Ok(())).unwrap_err();
    assert!(!target.exists(), "replace must never fall back to create");
    assert_eq!(budget.usage().unwrap(), (9, 1));
    rejected.into_parts().0.into_stage().cancel().unwrap();
    assert_eq!(budget.usage().unwrap(), (0, 0));
}

#[test]
fn create_stage_cannot_use_the_replacing_publication() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("fresh.bin");
    let budget = StageBudget::new(3, 1).unwrap();
    let mut stage = StageFile::prepare(
        policy(root.path()),
        target.to_str().unwrap(),
        3,
        &budget,
        gate(),
    )
    .unwrap();
    stage.write_chunk(0, b"abc").unwrap();
    let verified = verify(stage, b"abc");
    let pre = PreImage::new(Sha256::digest(b"abc").into(), 3).unwrap();
    let rejected = verified.publish_replacing(pre, || Ok(())).unwrap_err();
    assert!(
        rejected.reason().to_string().contains("pre-image"),
        "{rejected:?}"
    );
    assert!(!target.exists());
    rejected.into_parts().0.into_stage().cancel().unwrap();
}

#[test]
fn prepare_replacing_requires_the_pre_image_to_match_before_any_byte() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.bin");
    fs::write(&target, b"actual").unwrap();
    let budget = StageBudget::new(8, 1).unwrap();
    let wrong = PreImage::new(Sha256::digest(b"claimed").into(), 7).unwrap();
    let error = StageFile::prepare_replacing(
        policy(root.path()),
        target.to_str().unwrap(),
        7,
        &budget,
        gate(),
        wrong,
    )
    .err()
    .expect("prepare_replacing must refuse");
    assert!(error.to_string().contains("pre-image"), "{error}");
    // Nothing was admitted: no quota, no stage, destination untouched.
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert_eq!(fs::read(&target).unwrap(), b"actual");
    assert_eq!(stage_links(&root), 0);
}

#[test]
fn pre_image_digest_mismatch_refuses_before_staging() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.bin");
    fs::write(&target, b"abc").unwrap();
    let budget = StageBudget::new(3, 1).unwrap();
    let pre = PreImage::new(Sha256::digest(b"abd").into(), 3).unwrap();
    let error = StageFile::prepare_replacing(
        policy(root.path()),
        target.to_str().unwrap(),
        3,
        &budget,
        gate(),
        pre,
    )
    .err()
    .expect("prepare_replacing must refuse");
    assert!(error.to_string().contains("pre-image"), "{error}");
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert_eq!(fs::read(&target).unwrap(), b"abc");
    assert_eq!(stage_links(&root), 0);
}

#[test]
fn hardlinked_target_is_refused_before_any_stage() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.bin");
    fs::write(&target, b"shared").unwrap();
    fs::hard_link(&target, root.path().join("other.bin")).unwrap();
    let budget = StageBudget::new(3, 1).unwrap();
    let pre = PreImage::new(Sha256::digest(b"shared").into(), 6).unwrap();
    let error = StageFile::prepare_replacing(
        policy(root.path()),
        target.to_str().unwrap(),
        3,
        &budget,
        gate(),
        pre,
    )
    .err()
    .expect("multi-link target must be refused");
    assert!(!error.to_string().is_empty());
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert_eq!(fs::read(&target).unwrap(), b"shared");
    assert_eq!(fs::read(root.path().join("other.bin")).unwrap(), b"shared");
}

#[test]
fn directory_target_is_refused_before_any_stage() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.bin");
    fs::create_dir(&target).unwrap();
    let budget = StageBudget::new(3, 1).unwrap();
    let pre = PreImage::new(Sha256::digest(b"x").into(), 1).unwrap();
    let error = StageFile::prepare_replacing(
        policy(root.path()),
        target.to_str().unwrap(),
        3,
        &budget,
        gate(),
        pre,
    )
    .err()
    .expect("directory target must be refused");
    assert!(!error.to_string().is_empty());
    assert_eq!(budget.usage().unwrap(), (0, 0));
    assert!(target.is_dir());
}

#[test]
fn replacing_publication_is_uncertain_when_the_stage_link_survives() {
    // The replace path must not report Published unless the temporary link is
    // gone; a surviving link means the rename did not take the intended object.
    let root = tempfile::tempdir().unwrap();
    let (stage, budget, pre, target) = replacing(root.path(), b"old-content", b"new-bytes");
    let verified = verify(stage, b"new-bytes");
    let published = verified.publish_replacing(pre, || Ok(())).unwrap();
    assert!(matches!(
        published,
        Publication::Published {
            mode: PublishMode::ReplaceExisting,
            ..
        }
    ));
    assert_eq!(fs::read(&target).unwrap(), b"new-bytes");
    assert_eq!(budget.usage().unwrap(), (0, 0));
}

/// Explicit native probe. Runs only when the evidence path is provided, writes a
/// JSON artifact, and is NOT a two-host, crash or durability test.
#[test]
#[ignore = "explicit native replace evidence probe"]
fn native_replace_probe() {
    let out = match std::env::var_os("FERROC_FLEET_REPLACE_OUTPUT") {
        Some(v) => PathBuf::from(v),
        None => return,
    };
    let root = tempfile::tempdir().unwrap();
    let old = vec![b'o'; 1024 * 1024];
    let new = vec![b'n'; 3 * 1024 * 1024 + 7];
    let (stage, budget, pre, target) = replacing(root.path(), &old, &new);
    let old_sha = <[u8; 32]>::from(Sha256::digest(&old));
    let new_sha = <[u8; 32]>::from(Sha256::digest(&new));
    let verified = verify(stage, &new);
    let started = std::time::Instant::now();
    let publication = verified.publish_replacing(pre, || Ok(())).unwrap();
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let written = fs::read(&target).unwrap();
    let written_sha = <[u8; 32]>::from(Sha256::digest(&written));
    let mode = match publication {
        Publication::Published { mode, .. } => format!("{mode:?}"),
        other => panic!("unexpected publication: {other:?}"),
    };
    let report = serde_json::json!({
        "status": if written == new && written_sha == new_sha && mode == "ReplaceExisting" { "passed" } else { "failed" },
        "preImageBytes": old.len(),
        "preImageSha256": hex(&old_sha),
        "newBytes": new.len(),
        "newSha256": hex(&new_sha),
        "writtenBytes": written.len(),
        "writtenSha256": hex(&written_sha),
        "mode": mode,
        "publishMs": elapsed_ms,
        "stageLinksRemaining": stage_links(&root),
        "usageAfter": budget.usage().unwrap(),
        "scope": "LOCAL component replace on a real NTFS directory; not two-host, not crash durability",
    });
    fs::write(&out, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    assert_eq!(report["status"], "passed");
}
