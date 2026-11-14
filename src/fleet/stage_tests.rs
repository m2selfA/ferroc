use super::*;
fn fixture(
    root: &Path,
    bytes: &[u8],
    gate: Arc<Mutex<()>>,
) -> (StageFile, StageBudget, [u8; 32], PathBuf) {
    let target = root.join("target.bin");
    let budget = StageBudget::new(bytes.len() as u64, 1).unwrap();
    let mut stage = StageFile::prepare(
        Policy::new(vec![root.into()], false).unwrap(),
        target.to_str().unwrap(),
        bytes.len() as u64,
        &budget,
        gate,
    )
    .unwrap();
    for (n, c) in bytes.chunks(64 * 1024).enumerate() {
        stage.write_chunk((n * 64 * 1024) as u64, c).unwrap();
    }
    (stage, budget, Sha256::digest(bytes).into(), target)
}
#[tokio::test]
async fn runtime_mutation_after_verify_same_size_must_not_publish_old_sha() {
    let root = tempfile::tempdir().unwrap();
    let runtime =
        crate::runtime::Runtime::new(Policy::new(vec![root.path().into()], false).unwrap());
    let (s, b, hash, target) = fixture(root.path(), b"abc", runtime.test_fs_gate());
    let path = s.stage_path().to_owned();
    let verified = s.verify_with(hash, || Ok(())).unwrap();
    let changed = runtime
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(changed.is_error, Some(true), "{changed:?}");
    assert_eq!(fs::metadata(&path).unwrap().len(), 3);
    assert_eq!(fs::read(&path).unwrap(), b"xyz");
    let published = verified.publish_with(|| Ok(()));
    if let Ok(ref p) = published {
        let actual: [u8; 32] = Sha256::digest(fs::read(&target).unwrap()).into();
        println!(
            "NATIVE_SAME_SIZE_OBSERVATION:publication={p:?},actualSHA={actual:02x?},claimedSHA={hash:02x?},quota={:?}",
            b.usage().unwrap()
        );
    }
    assert!(
        published.is_err(),
        "same-size Runtime mutation published under cached old SHA"
    );
    let rejected = published.unwrap_err();
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(!target.exists());
    rejected.into_parts().0.into_stage().cancel().unwrap();
    assert_eq!(b.usage().unwrap(), (0, 0));
}
#[tokio::test]
async fn runtime_mutation_after_verify_path_replacement_must_not_publish_old_handle() {
    let root = tempfile::tempdir().unwrap();
    let runtime =
        crate::runtime::Runtime::new(Policy::new(vec![root.path().into()], false).unwrap());
    let (s, b, hash, target) = fixture(root.path(), b"abc", runtime.test_fs_gate());
    let path = s.stage_path().to_owned();
    let saved = path.with_extension("kept");
    let verified = s.verify_with(hash, || Ok(())).unwrap();
    let moved = runtime
        .call(
            "move_file",
            serde_json::json!({"source":path,"destination":saved}),
        )
        .await;
    if moved.is_error == Some(true) {
        println!("NATIVE_REPLACE_DENIED_BY_HANDLE:{moved:?}");
        verified.into_stage().cancel().unwrap();
        return;
    }
    let changed = runtime
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(changed.is_error, Some(true));
    assert_eq!(fs::read(&saved).unwrap(), b"abc");
    let published = verified.publish_with(|| Ok(()));
    if let Ok(ref p) = published {
        println!(
            "NATIVE_PATH_REPLACED_OBSERVATION:{p:?},actual={:?}",
            fs::read(&target).unwrap()
        );
    }
    assert!(
        published.is_err(),
        "replaced stage path published while original handle hash was used"
    );
    let rejected = published.unwrap_err();
    assert!(!target.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    let failed = rejected.into_parts().0;
    assert!(b.is_quarantined().unwrap());
    let foreign = path.with_extension("foreign-kept");
    fs::rename(&path, &foreign).unwrap();
    fs::rename(&saved, &path).unwrap();
    let mut admitted = false;
    let still_rejected = failed
        .publish_with(|| {
            admitted = true;
            Ok(())
        })
        .unwrap_err();
    assert!(
        !admitted,
        "restoring a path cannot revive quarantined publication"
    );
    assert!(still_rejected.into_parts().0.into_stage().cancel().is_err());
    assert_eq!(fs::read(&foreign).unwrap(), b"xyz");
    assert_eq!(fs::read(path).unwrap(), b"abc");
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(b.reconcile_removed().is_err());
}

#[test]
fn final_rehash_cancel_checks_each64k_before_admission_retains_stage() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Mutex::new(()));
    let (s, b, hash, target) = fixture(root.path(), &vec![42; 131073], gate.clone());
    let path = s.stage_path().to_owned();
    let v = s.verify_with(hash, || Ok(())).unwrap();
    let mut checks = 0;
    let mut admitted = false;
    let failure = v
        .publish_checked(
            || {
                assert!(matches!(
                    gate.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                checks += 1;
                ensure!(checks < 3, "cancel after first final read");
                Ok(())
            },
            || {
                admitted = true;
                Ok(())
            },
        )
        .unwrap_err();
    assert!(!admitted);
    assert_eq!(checks, 3);
    let mut s = failure.into_parts().0.into_stage();
    assert_eq!(s.stage.as_file_mut().stream_position().unwrap(), 65536);
    assert_eq!(b.usage().unwrap(), (131073, 1));
    assert!(!target.exists());
    assert!(path.exists());
    s.cancel().unwrap();
}
#[test]
fn detected_replacement_drop_preserves_foreign_file_and_quota_even_when_path_goes_missing() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, hash, target) = fixture(root.path(), b"abc", Arc::default());
    let path = s.stage_path().to_owned();
    let original = path.with_extension("original-kept");
    let v = s.verify_with(hash, || Ok(())).unwrap();
    fs::rename(&path, &original).unwrap();
    fs::write(&path, b"xyz").unwrap();
    let rejected = v.publish_with(|| Ok(())).unwrap_err();
    drop(rejected);
    assert_eq!(fs::read(&path).unwrap(), b"xyz");
    assert_eq!(fs::read(original).unwrap(), b"abc");
    assert!(!target.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(b.is_quarantined().unwrap());
    fs::rename(&path, path.with_extension("replacement-kept")).unwrap();
    assert!(!path.exists());
    assert!(b.reconcile_removed().is_err());
    assert_eq!(b.usage().unwrap(), (3, 1));
}
#[test]
fn explicit_cancel_does_not_unlink_a_replaced_name() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, _, target) = fixture(root.path(), b"abc", Arc::default());
    let path = s.stage_path().to_owned();
    let original = path.with_extension("original-kept");
    fs::rename(&path, &original).unwrap();
    fs::write(&path, b"xyz").unwrap();
    assert!(s.cancel().is_err());
    assert_eq!(fs::read(path).unwrap(), b"xyz");
    assert_eq!(fs::read(original).unwrap(), b"abc");
    assert!(!target.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(b.is_quarantined().unwrap());
}

#[tokio::test]
async fn drop_after_rejected_publish_and_runtime_path_replacement_never_deletes_foreign() {
    let root = tempfile::tempdir().unwrap();
    let runtime =
        crate::runtime::Runtime::new(Policy::new(vec![root.path().into()], false).unwrap());
    let (s, b, hash, target) = fixture(root.path(), b"abc", runtime.test_fs_gate());
    let path = s.stage_path().to_owned();
    let saved = path.with_extension("original-kept");
    let rejected = s
        .verify_with(hash, || Ok(()))
        .unwrap()
        .publish_with(|| anyhow::bail!("cancelled before admission"))
        .unwrap_err();
    assert_eq!(b.usage().unwrap(), (3, 1));
    let moved = runtime
        .call(
            "move_file",
            serde_json::json!({"source":path,"destination":saved}),
        )
        .await;
    assert_ne!(moved.is_error, Some(true));
    let changed = runtime
        .call(
            "write_file",
            serde_json::json!({"path":path,"content":"xyz"}),
        )
        .await;
    assert_ne!(changed.is_error, Some(true));
    drop(rejected);
    assert!(
        path.exists(),
        "rejected Stage Drop deleted the foreign Runtime replacement"
    );
    assert_eq!(fs::read(path).unwrap(), b"xyz");
    assert_eq!(fs::read(saved).unwrap(), b"abc");
    assert!(!target.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(b.is_quarantined().unwrap());
}
#[test]
fn drop_while_real_gate_is_busy_never_deadlocks_or_claims_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Mutex::new(()));
    let (s, b, _, _) = fixture(root.path(), b"abc", gate.clone());
    let path = s.stage_path().to_owned();
    let held = gate.lock().unwrap();
    drop(s);
    assert!(
        path.exists(),
        "Drop cannot clean without filesystem serialization"
    );
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(b.is_quarantined().unwrap());
    drop(held);
    assert!(b.reconcile_removed().is_err());
}

#[test]
fn cancelled_before_readback_retains_stage_bytes_and_slot() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, hash, target) = fixture(root.path(), b"abc", Arc::default());
    let path = s.stage_path().to_path_buf();
    let failed = s
        .verify_with(hash, || anyhow::bail!("cancelled"))
        .unwrap_err();
    assert!(failed.reason().to_string().contains("cancelled"));
    assert_eq!(fs::read(&path).unwrap(), b"abc");
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(!target.exists());
    let (s, _) = failed.into_parts();
    s.cancel().unwrap();
    assert_eq!(b.usage().unwrap(), (0, 0));
}
#[test]
fn cancellation_after_one_real_read_stops_at_64k_and_can_reverify() {
    let root = tempfile::tempdir().unwrap();
    let bytes = vec![42; 131073];
    let (s, b, hash, target) = fixture(root.path(), &bytes, Arc::default());
    let mut calls = 0;
    let failed = s
        .verify_with(hash, || {
            calls += 1;
            ensure!(calls < 3, "cancel after first read");
            Ok(())
        })
        .unwrap_err();
    let (mut s, _) = failed.into_parts();
    assert_eq!(s.stage.as_file_mut().stream_position().unwrap(), 65536);
    assert_eq!(b.usage().unwrap(), (131073, 1));
    assert!(!target.exists());
    let v = s.verify_with(hash, || Ok(())).unwrap();
    assert_eq!(v.size(), 131073);
    assert_eq!(v.sha256(), hash);
    v.publish_with(|| Ok(())).unwrap();
    assert_eq!(fs::read(target).unwrap(), bytes);
    assert_eq!(b.usage().unwrap(), (0, 0));
}
#[test]
fn readback_sha_failure_does_not_cleanup_until_caller_settles() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, _, target) = fixture(root.path(), b"abc", Arc::default());
    let path = s.stage_path().to_path_buf();
    let failed = s.verify_with([0; 32], || Ok(())).unwrap_err();
    assert!(path.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(!target.exists());
    failed.into_parts().0.cancel().unwrap();
    assert!(!path.exists());
}
#[test]
fn empty_file_post_sync_checkpoint_keeps_zero_byte_active_slot() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, hash, target) = fixture(root.path(), b"", Arc::default());
    let mut calls = 0;
    let failed = s
        .verify_with(hash, || {
            calls += 1;
            ensure!(calls < 4, "after sync cancellation");
            Ok(())
        })
        .unwrap_err();
    assert_eq!(calls, 4);
    assert_eq!(b.usage().unwrap(), (0, 1));
    assert!(!target.exists());
    failed.into_parts().0.cancel().unwrap();
    assert_eq!(b.usage().unwrap(), (0, 0));
}
#[test]
fn rejection_after_readback_is_not_a_reusable_publication_permit() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, hash, target) = fixture(root.path(), b"abc", Arc::default());
    let path = s.stage_path().to_path_buf();
    let v = s.verify_with(hash, || Ok(())).unwrap();
    let mut calls = 0;
    let failed = v
        .publish_with(|| {
            calls += 1;
            anyhow::bail!("lease/revision/fence refused")
        })
        .unwrap_err();
    assert_eq!(calls, 1);
    assert_eq!(fs::read(path).unwrap(), b"abc");
    assert_eq!(b.usage().unwrap(), (3, 1));
    assert!(!target.exists());
    failed.into_parts().0.into_stage().cancel().unwrap();
}
#[test]
fn preexisting_target_never_calls_admission_or_overwrites() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, hash, target) = fixture(root.path(), b"abc", Arc::default());
    let v = s.verify_with(hash, || Ok(())).unwrap();
    fs::write(&target, b"prior").unwrap();
    let mut called = false;
    let failed = v
        .publish_with(|| {
            called = true;
            Ok(())
        })
        .unwrap_err();
    assert!(!called);
    assert_eq!(fs::read(target).unwrap(), b"prior");
    assert_eq!(b.usage().unwrap(), (3, 1));
    failed.into_parts().0.into_stage().cancel().unwrap();
}
#[test]
fn size_changed_after_verification_rejects_before_admission() {
    let root = tempfile::tempdir().unwrap();
    let (s, b, hash, target) = fixture(root.path(), b"abc", Arc::default());
    let path = s.stage_path().to_path_buf();
    let v = s.verify_with(hash, || Ok(())).unwrap();
    fs::write(path, b"abcd").unwrap();
    let mut called = false;
    let failed = v
        .publish_with(|| {
            called = true;
            Ok(())
        })
        .unwrap_err();
    assert!(!called);
    assert!(!target.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    failed.into_parts().0.into_stage().cancel().unwrap();
}
#[test]
fn callback_owns_actual_gate_and_collision_after_it_is_uncertain_not_rejection() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Mutex::new(()));
    let (s, _, hash, target) = fixture(root.path(), b"abc", gate.clone());
    let v = s.verify_with(hash, || Ok(())).unwrap();
    let result = v
        .publish_with(|| {
            assert!(matches!(
                gate.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            fs::write(&target, b"prior")?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(result, Publication::Uncertain { .. }));
    assert_eq!(fs::read(target).unwrap(), b"prior");
}
#[test]
fn cancellation_is_checked_fresh_after_actual_fs_gate_handoff() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Mutex::new(()));
    let (s, b, hash, target) = fixture(root.path(), b"abc", gate.clone());
    let v = s.verify_with(hash, || Ok(())).unwrap();
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let (ready, started) = std::sync::mpsc::channel();
    let held = gate.lock().unwrap();
    let rejected = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            ready.send(()).unwrap();
            v.publish_with(|| {
                ensure!(
                    !cancelled.load(std::sync::atomic::Ordering::SeqCst),
                    "cancelled at gate handoff"
                );
                Ok(())
            })
        });
        let start = started.recv_timeout(std::time::Duration::from_secs(5));
        cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(held);
        start.unwrap();
        worker.join().unwrap().unwrap_err()
    });
    assert!(!target.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    rejected.into_parts().0.into_stage().cancel().unwrap();
    assert_eq!(b.usage().unwrap(), (0, 0));
}

#[test]
fn poisoned_gate_rejects_without_releasing_stage_or_calling_admission() {
    let root = tempfile::tempdir().unwrap();
    let gate = Arc::new(Mutex::new(()));
    let (s, b, hash, target) = fixture(root.path(), b"abc", gate.clone());
    let v = s.verify_with(hash, || Ok(())).unwrap();
    let _ = std::panic::catch_unwind(|| {
        let _g = gate.lock().unwrap();
        panic!("injected gate poison")
    });
    let mut called = false;
    let failed = v
        .publish_with(|| {
            called = true;
            Ok(())
        })
        .unwrap_err();
    assert!(!called);
    assert!(!target.exists());
    assert_eq!(b.usage().unwrap(), (3, 1));
    failed.into_parts().0.into_stage().cancel().unwrap();
}
