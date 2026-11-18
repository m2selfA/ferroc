//! LOCAL retained recovery: legacy manual records, actual source/window, and explicit WS probes.
//! PUBLIC fixture proofs/local anchors; no stock-process or restart claim.
use super::*;
use crate::fleet::{
    host::{HostMode, StoppedCreators},
    job::LeaseProfile,
    journal::PrefixCheckpoint,
    resume_condition::ResumeProposal,
    resume_lease::ResumeLease,
};
#[path = "resume_window_tests.rs"]
mod resume_window_tests;
#[path = "resume_ws_pump_tests.rs"]
mod resume_ws_pump_tests;
#[path = "stopped_recovery_tests.rs"]
mod stopped_recovery_tests;
struct Recovery {
    _temp: tempfile::TempDir,
    path: PathBuf,
    runtime: crate::runtime::Runtime,
    proof: Option<StoppedCreators>,
    old: JobSpec,
    cp: PrefixCheckpoint,
    key: JobKey,
    stage: PathBuf,
    data: Vec<u8>,
}
fn stopped(data: &[u8], prefix: usize) -> Recovery {
    let (temp, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (mut source, mut recv) = open(&host, &path, data);
    recv.enable_retained_checkpoints().unwrap();
    if prefix > 0 {
        recv.write_record(&source.seal_data(0, &data[..prefix]).unwrap())
            .unwrap();
    }
    let cp = recv.capture_retained_checkpoint().unwrap();
    let old = recv.snapshot().job().clone();
    let key = JobKey::from_job(&old);
    let stage = recv.snapshot().stage().unwrap().path().to_path_buf();
    // A received tail beyond the persisted checkpoint MUST NOT become restored coverage.
    if data.len() > prefix + 1 {
        recv.write_record(
            &source
                .seal_data(prefix as u64, &data[prefix..prefix + 2])
                .unwrap(),
        )
        .unwrap();
    }
    drop(recv);
    drop(source);
    let proof = host.stop_creators().unwrap();
    drop(host);
    Recovery {
        _temp: temp,
        path,
        runtime,
        proof: Some(proof),
        old,
        cp,
        key,
        stage,
        data: data.to_vec(),
    }
}
fn owner(
    f: &Recovery,
    cp: &PrefixCheckpoint,
    source_role: bool,
) -> (Option<LeasedRecords>, ResumeLease) {
    let mut job = f.old.clone();
    job.transfer_id = Uuid::new_v4();
    job.file_id = Uuid::new_v4();
    job.idempotency_key = format!("resume-{}", Uuid::new_v4());
    let mut grant = Offer::new(&f.path, &f.data, 0).g.grant().clone();
    grant.binding.transfer_id = job.transfer_id;
    grant.binding.file_id = job.file_id;
    grant.binding.source_session = Uuid::new_v4();
    grant.binding.target_session = Uuid::new_v4();
    grant.binding.authorization_id = Uuid::new_v4();
    grant.binding.key_epoch = Uuid::new_v4();
    grant.job_digest = job.digest().unwrap();
    let g = grant
        .validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap();
    let p = ResumeProposal::build(&f.old, cp, &g).unwrap();
    let source = EphemeralKey::generate();
    let target = EphemeralKey::generate();
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let t = Transcript::for_grant(
        &g,
        sk.public(),
        tk.public(),
        source.public(),
        target.public(),
    );
    let sp = DevicePin::approved("source-A", sk.public()).unwrap();
    let tp = DevicePin::approved("target-B", tk.public()).unwrap();
    let sa = sk
        .sign_with_profile(&t, Direction::SourceToTarget, g.lease_profile())
        .unwrap();
    let ta = tk
        .sign_with_profile(&t, Direction::TargetToSource, g.lease_profile())
        .unwrap();
    let sr: [u8; 64] = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x11; 32])
        .unwrap()
        .sign(&p.proof_bytes(&g, &t, Direction::SourceToTarget).unwrap())
        .as_ref()
        .try_into()
        .unwrap();
    let tr: [u8; 64] = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x22; 32])
        .unwrap()
        .sign(&p.proof_bytes(&g, &t, Direction::TargetToSource).unwrap())
        .as_ref()
        .try_into()
        .unwrap();
    let anchor = || TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 200).unwrap();
    if source_role {
        return (
            None,
            source
                .authenticate_resume_leased(
                    p,
                    &t,
                    Direction::SourceToTarget,
                    &g,
                    &sp,
                    &tp,
                    &sa,
                    &ta,
                    &sr,
                    &tr,
                    anchor(),
                )
                .unwrap(),
        );
    }
    let s = source
        .authenticate_leased(
            &t,
            Direction::SourceToTarget,
            &g,
            &sp,
            &tp,
            &sa,
            &ta,
            anchor(),
        )
        .unwrap();
    let r = target
        .authenticate_resume_leased(
            p,
            &t,
            Direction::TargetToSource,
            &g,
            &sp,
            &tp,
            &sa,
            &ta,
            &sr,
            &tr,
            anchor(),
        )
        .unwrap();
    (Some(s), r)
}
fn owner_pair(f: &Recovery, cp: &PrefixCheckpoint) -> (ResumeLease, ResumeLease) {
    owner_pair_variant(f, cp, false)
}
fn owner_pair_variant(
    f: &Recovery,
    cp: &PrefixCheckpoint,
    different_source_revision: bool,
) -> (ResumeLease, ResumeLease) {
    let mut job = f.old.clone();
    job.transfer_id = Uuid::new_v4();
    job.file_id = Uuid::new_v4();
    job.idempotency_key = format!("resume-{}", Uuid::new_v4());
    let mut grant = Offer::new(&f.path, &f.data, 0).g.grant().clone();
    grant.binding.transfer_id = job.transfer_id;
    grant.binding.file_id = job.file_id;
    grant.binding.source_session = Uuid::new_v4();
    grant.binding.target_session = Uuid::new_v4();
    grant.binding.authorization_id = Uuid::new_v4();
    grant.binding.key_epoch = Uuid::new_v4();
    grant.job_digest = job.digest().unwrap();
    let g = grant
        .validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap();
    let p = ResumeProposal::build(&f.old, cp, &g).unwrap();
    let mut source_cp = cp.clone();
    if different_source_revision {
        let mut encoded = serde_json::to_value(&source_cp).unwrap();
        encoded["revision"] = serde_json::json!(source_cp.revision() + 1);
        source_cp = serde_json::from_value(encoded).unwrap();
    }
    let source_p = ResumeProposal::build(&f.old, &source_cp, &g).unwrap();
    let source = EphemeralKey::generate();
    let target = EphemeralKey::generate();
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    let t = Transcript::for_grant(
        &g,
        sk.public(),
        tk.public(),
        source.public(),
        target.public(),
    );
    let sp = DevicePin::approved("source-A", sk.public()).unwrap();
    let tp = DevicePin::approved("target-B", tk.public()).unwrap();
    let sa = sk
        .sign_with_profile(&t, Direction::SourceToTarget, g.lease_profile())
        .unwrap();
    let ta = tk
        .sign_with_profile(&t, Direction::TargetToSource, g.lease_profile())
        .unwrap();
    let sr: [u8; 64] = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x11; 32])
        .unwrap()
        .sign(&p.proof_bytes(&g, &t, Direction::SourceToTarget).unwrap())
        .as_ref()
        .try_into()
        .unwrap();
    let tr: [u8; 64] = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x22; 32])
        .unwrap()
        .sign(&p.proof_bytes(&g, &t, Direction::TargetToSource).unwrap())
        .as_ref()
        .try_into()
        .unwrap();
    let anchor = || TrustedTimeAnchor::approved_window(ClockSample::now(), 200, 200).unwrap();
    let source_sr: [u8; 64] = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x11; 32])
        .unwrap()
        .sign(
            &source_p
                .proof_bytes(&g, &t, Direction::SourceToTarget)
                .unwrap(),
        )
        .as_ref()
        .try_into()
        .unwrap();
    let source_tr: [u8; 64] = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x22; 32])
        .unwrap()
        .sign(
            &source_p
                .proof_bytes(&g, &t, Direction::TargetToSource)
                .unwrap(),
        )
        .as_ref()
        .try_into()
        .unwrap();
    let s = source
        .authenticate_resume_leased(
            source_p,
            &t,
            Direction::SourceToTarget,
            &g,
            &sp,
            &tp,
            &sa,
            &ta,
            &source_sr,
            &source_tr,
            anchor(),
        )
        .unwrap();
    let r = target
        .authenticate_resume_leased(
            p,
            &t,
            Direction::TargetToSource,
            &g,
            &sp,
            &tp,
            &sa,
            &ta,
            &sr,
            &tr,
            anchor(),
        )
        .unwrap();
    (s, r)
}

#[cfg(windows)]
#[test]
fn actual_source_file_suffix_to_actual_target_receipt_and_authenticated_ack() {
    for (data, prefix) in [
        (vec![], 0),
        (b"abcdefgh".to_vec(), 0),
        (b"abcdefgh".to_vec(), 3),
        (b"abcdefgh".to_vec(), 8),
        (vec![7; 131073], 65536),
        (vec![9; 8 * 1024 * 1024], 65536),
    ] {
        let mut f = stopped(&data, prefix);
        std::fs::write(&f.old.source_path, &data).unwrap();
        let proof = f.proof.take().unwrap();
        let h = recovered(&f, proof);
        let old = h.get(&f.key).unwrap().unwrap();
        let (source_owner, target) = owner_pair(&f, &f.cp);
        let key = JobKey::from_job(target.grant().job());
        h.resume_retained_recovery().unwrap();
        let mut recv = h
            .admit_retained_receiver(&f.key, old.revision(), target, data.len() as u64)
            .unwrap();
        let source_runtime = crate::runtime::Runtime::new(
            crate::config::Policy::new(vec![f.path.parent().unwrap().to_path_buf()], false)
                .unwrap(),
        );
        let mut source = source_runtime
            .open_fleet_resume_source(source_owner, data.len() as u64)
            .unwrap();
        assert_eq!(source.bytes_encoded(), 0);
        assert_eq!(source.resumed_prefix_bytes(), Some(prefix as u64));
        while let Some(frame) = source.next_record().unwrap() {
            recv.write_record(&frame).unwrap();
        }
        assert_eq!(source.bytes_encoded(), (data.len() - prefix) as u64);
        assert_eq!(source.next_data_offset(), data.len() as u64);
        let mut pending = source.finish().unwrap();
        let finished = recv
            .seal_finish(pending.finish_record())
            .unwrap()
            .prepare_commit()
            .unwrap()
            .attempt_local_publication()
            .unwrap()
            .record_target_observation()
            .unwrap()
            .settle_local()
            .unwrap();
        pending.observe_final(finished.local_commit_ack()).unwrap();
        assert_eq!(
            pending.peer_observation().unwrap().receipt(),
            finished.receipt()
        );
        assert_eq!(
            pending.peer_observation().unwrap().job_digest(),
            pending.job().digest().unwrap()
        );
        let row = h.get(&key).unwrap().unwrap();
        assert_eq!(row.phase(), Phase::Completed);
        assert_eq!(row.receipt().unwrap(), finished.receipt());
        assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
        assert_eq!(schema(&f.path), 13);
        assert!(!f.stage.exists());
        assert_eq!(std::fs::read(&f.old.destination_path).unwrap(), data);
        drop(finished);
        assert_eq!(h.status().unwrap().in_flight, 0);
        h.close().unwrap();
    }
}
#[cfg(target_os = "linux")]
#[test]
fn actual_source_file_suffix_to_actual_target_seal_keeps_debt_not_completion() {
    for (data, prefix) in [
        (vec![], 0),
        (b"abcdefgh".to_vec(), 0),
        (b"abcdefgh".to_vec(), 3),
        (b"abcdefgh".to_vec(), 8),
        (vec![7; 131073], 65536),
        (vec![9; 8 * 1024 * 1024], 65536),
    ] {
        let mut f = stopped(&data, prefix);
        std::fs::write(&f.old.source_path, &data).unwrap();
        let proof = f.proof.take().unwrap();
        let h = recovered(&f, proof);
        let old = h.get(&f.key).unwrap().unwrap();
        let (source_owner, target) = owner_pair(&f, &f.cp);
        let key = JobKey::from_job(target.grant().job());
        h.resume_retained_recovery().unwrap();
        let mut recv = h
            .admit_retained_receiver(&f.key, old.revision(), target, data.len() as u64)
            .unwrap();
        let source_runtime = crate::runtime::Runtime::new(
            crate::config::Policy::new(vec![f.path.parent().unwrap().to_path_buf()], false)
                .unwrap(),
        );
        let mut source = source_runtime
            .open_fleet_resume_source(source_owner, data.len() as u64)
            .unwrap();
        assert_eq!(source.bytes_encoded(), 0);
        while let Some(frame) = source.next_record().unwrap() {
            recv.write_record(&frame).unwrap();
        }
        assert_eq!(source.bytes_encoded(), (data.len() - prefix) as u64);
        let pending = source.finish().unwrap();
        let sealed = recv.seal_finish(pending.finish_record()).unwrap();
        assert!(sealed.snapshot().receipt().is_none());
        assert!(pending.peer_observation().is_none());
        assert_eq!(std::fs::read(&f.stage).unwrap(), data);
        assert!(!std::path::Path::new(&f.old.destination_path).exists());
        assert_eq!(
            h.inventory().unwrap().recorded_usage(),
            (data.len() as u64, 1)
        );
        assert_eq!(schema(&f.path), 13);
        drop(sealed);
        let row = h.get(&key).unwrap().unwrap();
        assert!(row.stage().is_some() && row.receipt().is_none());
        assert_eq!(h.status().unwrap().in_flight, 0);
        h.close().unwrap();
    }
}
#[test]
fn source_prefix_refusal_after_target_migration_keeps_new_full_obligation() {
    let mut f = stopped(b"abcdefgh", 3);
    std::fs::write(&f.old.source_path, b"xyzdefgh").unwrap();
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let (source_owner, target) = owner_pair(&f, &f.cp);
    let key = JobKey::from_job(target.grant().job());
    h.resume_retained_recovery().unwrap();
    let recv = h
        .admit_retained_receiver(&f.key, old.revision(), target, 8)
        .unwrap();
    let source_runtime = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![f.path.parent().unwrap().to_path_buf()], false).unwrap(),
    );
    assert!(
        source_runtime
            .open_fleet_resume_source(source_owner, 8)
            .is_err()
    );
    drop(recv);
    assert_eq!(schema(&f.path), 13);
    assert!(h.get(&f.key).unwrap().unwrap().stage().is_none());
    assert!(h.get(&key).unwrap().unwrap().stage().is_some());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert!(!std::path::Path::new(&f.old.destination_path).exists());
    assert_eq!(std::fs::read(&f.stage).unwrap(), b"abcde");
    assert_eq!(std::fs::read(&f.old.source_path).unwrap(), b"xyzdefgh");
    h.close().unwrap();
}

fn recovered<'r>(f: &'r Recovery, proof: StoppedCreators) -> FleetHost<'r> {
    let h = f
        .runtime
        .open_fleet_host(&f.path, InventoryLimits::default())
        .unwrap();
    h.recover_creators(proof).unwrap();
    h
}
fn bytes(h: &FleetHost<'_>, key: &JobKey) -> Vec<u8> {
    serde_json::to_vec(&h.get(key).unwrap()).unwrap()
}

#[test]
fn same_prefix_substitute_object_is_rejected_and_not_deleted() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    let (_, target) = owner(&f, &f.cp, false);
    let held = f.stage.with_extension("original");
    std::fs::rename(&f.stage, &held).unwrap();
    {
        let mut replacement = new_private(&f.stage).unwrap();
        replacement.write_all(b"abcde").unwrap();
        replacement.sync_all().unwrap();
    }
    h.resume_retained_recovery().unwrap();
    let e = h
        .admit_retained_receiver(&f.key, old.revision(), target, 8)
        .err()
        .unwrap();
    assert!(e.to_string().contains("object/parent changed"), "{e:#}");
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(std::fs::read(&f.stage).unwrap(), b"abcde");
    assert_eq!(std::fs::read(&held).unwrap(), b"abcde");
    assert_eq!(schema(&f.path), 12);
    std::fs::rename(&f.stage, f.stage.with_extension("substitute-preserved")).unwrap();
    std::fs::rename(held, &f.stage).unwrap();
    h.close().unwrap();
}
#[test]
fn stale_row_and_prefix_budget_reject_without_mutation() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    h.resume_retained_recovery().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), target, 2)
            .err()
            .unwrap()
            .to_string()
            .contains("budget")
    );
    let (_, target) = owner(&f, &f.cp, false);
    assert!(
        h.admit_retained_receiver(&f.key, old.revision() - 1, target, 8)
            .err()
            .unwrap()
            .to_string()
            .contains("exact recovered")
    );
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(schema(&f.path), 12);
    assert_eq!(h.status().unwrap().in_flight, 0);
    h.close().unwrap();
}
#[test]
fn begin_failure_after_migration_commit_is_not_rollback() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    let key = JobKey::from_job(target.grant().job());
    let c = rusqlite::Connection::open(&f.path).unwrap();
    c.execute_batch(&format!("CREATE TRIGGER fail_new_begin BEFORE UPDATE OF body ON ferroc_fleet_jobs_v1 WHEN NEW.k='{}' BEGIN SELECT RAISE(ABORT,'post-migration begin rejected'); END",key.id())).unwrap();
    h.resume_retained_recovery().unwrap();
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), target, 8)
            .is_err()
    );
    assert!(h.get(&f.key).unwrap().unwrap().is_migrated_origin());
    let new = h.get(&key).unwrap().unwrap();
    assert_eq!(new.phase(), Phase::Interrupted);
    assert_eq!(new.received(), 0);
    assert!(new.stage().is_some());
    assert_eq!(schema(&f.path), 13);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert_eq!(std::fs::read(&f.stage).unwrap(), b"abcde");
    assert!(!f.path.with_file_name("target.bin").exists());
    h.close().unwrap();
}
fn no_retained_mode(anonymous: bool) {
    let (temp, path, runtime) = fixture();
    let old = Offer::new(&path, b"abcdefgh", 0).g;
    let h = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    h.resume().unwrap();
    let (mut source, target) = Offer::new(&path, b"abcdefgh", 0).pair();
    let mut recv = if anonymous {
        #[cfg(target_os = "linux")]
        {
            h.admit_linux_anonymous_receiver(target).unwrap()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            panic!("Linux-only test")
        }
    } else {
        h.admit_receiver(target).unwrap()
    };
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let stage = recv.snapshot().stage().unwrap().path().to_path_buf();
    let key = JobKey::from_job(old.job());
    drop(recv);
    drop(source);
    let proof = h.stop_creators().unwrap();
    drop(h);
    let cp:PrefixCheckpoint=serde_json::from_value(serde_json::json!({"version":1,"bytes":3,"sha256":<[u8;32]>::from(Sha256::digest(b"abc")),"job_digest":old.job().digest().unwrap(),"grant_digest":old.digest(),"binding":old.grant().binding,"revision":3})).unwrap();
    let mut f = Recovery {
        _temp: temp,
        path,
        runtime,
        proof: Some(proof),
        old: old.job().clone(),
        cp,
        key,
        stage,
        data: b"abcdefgh".to_vec(),
    };
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let s = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    h.resume_retained_recovery().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    let e = h
        .admit_retained_receiver(&f.key, s.revision(), target, 8)
        .err()
        .unwrap();
    assert!(e.to_string().contains("retained opt-in missing"), "{e:#}");
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert_eq!(schema(&f.path), if anonymous { 11 } else { 4 });
    h.close().unwrap();
}
#[test]
fn ordinary_named_stage_cannot_be_retrofitted_by_valid_proofs() {
    no_retained_mode(false);
}
#[cfg(target_os = "linux")]
#[test]
fn anonymous_stage_cannot_be_retrofitted_by_valid_proofs() {
    no_retained_mode(true);
}
#[test]
fn runtime_stop_cannot_be_reopened_for_recovery() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    h.resume_retained_recovery().unwrap();
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    engine.block_on(f.runtime.shutdown_fleet_host()).unwrap();
    assert!(h.resume_retained_recovery().is_err());
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), target, 8)
            .is_err()
    );
    assert_eq!(std::fs::read(&f.stage).unwrap(), b"abcde");
    assert_eq!(schema(&f.path), 12);
    h.close().unwrap();
}

#[test]
fn actual_dual_proof_receiver_continues_only_verified_prefix() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    assert!(h.resume().is_err());
    let old = h.get(&f.key).unwrap().unwrap();
    assert_eq!(old.received(), 5);
    let old_id = old
        .stage()
        .unwrap()
        .allocation()
        .unwrap()
        .file_id()
        .unwrap()
        .to_owned();
    let (source, target) = owner(&f, &f.cp, false);
    let mut source = source.unwrap();
    let new_key = JobKey::from_job(target.grant().job());
    h.resume_retained_recovery().unwrap();
    let mut recv = h
        .admit_retained_receiver(&f.key, old.revision(), target, 8)
        .unwrap();
    assert_eq!(recv.resumed_prefix(), Some(3));
    assert_eq!(recv.snapshot().received(), 3);
    assert_eq!(recv.ranges.contiguous(), 3);
    assert_eq!(file_id(&recv.file).unwrap(), old_id);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert_eq!(schema(&f.path), 13);
    let history = h.get(&f.key).unwrap().unwrap();
    assert!(history.is_migrated_origin() && history.stage().is_none());
    assert_eq!(JobKey::from_job(recv.snapshot().job()), new_key);
    recv.write_record(&source.seal_data(3, b"defgh").unwrap())
        .unwrap();
    assert_eq!(recv.snapshot().received(), 8);
    assert_eq!(std::fs::read(&f.stage).unwrap(), b"abcdefgh");
    assert!(!f.path.with_file_name("target.bin").exists());
    drop(recv);
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn paused_and_recovery_mode_keep_ordinary_admission_closed() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let before = bytes(&h, &f.key);
    let old = h.get(&f.key).unwrap().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), target, 8)
            .err()
            .unwrap()
            .to_string()
            .contains("recovery-only")
    );
    assert_eq!(bytes(&h, &f.key), before);
    h.resume_retained_recovery().unwrap();
    assert_eq!(h.status().unwrap().mode, HostMode::RecoveryOnly);
    let (_, target) = Offer::tagged(&f.path, b"other", 0, 9).pair();
    assert!(h.admit_receiver(target).is_err());
    h.pause().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), target, 8)
            .is_err()
    );
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert_eq!(schema(&f.path), 12);
    h.close().unwrap();
    assert!(h.resume_retained_recovery().is_err());
}
#[test]
fn mismatched_checkpoint_binding_is_rejected_before_file_open() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    let mut value = serde_json::to_value(&f.cp).unwrap();
    value["revision"] = serde_json::json!(f.cp.revision() + 1);
    let fake: PrefixCheckpoint = serde_json::from_value(value).unwrap();
    let (_, target) = owner(&f, &fake, false);
    let moved = f.stage.with_extension("held");
    std::fs::rename(&f.stage, &moved).unwrap();
    h.resume_retained_recovery().unwrap();
    let e = h
        .admit_retained_receiver(&f.key, old.revision(), target, 8)
        .err()
        .unwrap();
    assert!(e.to_string().contains("condition differs"), "{e:#}");
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(std::fs::read(&moved).unwrap(), b"abcde");
    assert_eq!(schema(&f.path), 12);
    std::fs::rename(moved, &f.stage).unwrap();
    h.close().unwrap();
}
#[test]
fn rewritten_prefix_rejects_without_migration() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    let (_, target) = owner(&f, &f.cp, false);
    std::fs::write(&f.stage, b"xyzde").unwrap();
    h.resume_retained_recovery().unwrap();
    let e = h
        .admit_retained_receiver(&f.key, old.revision(), target, 8)
        .err()
        .unwrap();
    assert!(e.to_string().contains("prefix mismatch"), "{e:#}");
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert_eq!(schema(&f.path), 12);
    h.close().unwrap();
}
#[test]
fn sql_writer_rejects_fast_and_restores_timeout() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    let (_, target) = owner(&f, &f.cp, false);
    h.resume_retained_recovery().unwrap();
    let c = rusqlite::Connection::open(&f.path).unwrap();
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    let start = Instant::now();
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), target, 8)
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    c.execute_batch("ROLLBACK").unwrap();
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(schema(&f.path), 12);
    assert_eq!(h.status().unwrap().in_flight, 0);
    let mut g = h.database.lock().unwrap();
    assert_eq!(
        g.as_mut()
            .unwrap()
            .connection
            .query_row("PRAGMA busy_timeout", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        5000
    );
    drop(g);
    h.close().unwrap();
}
#[test]
fn ordinary_ready_is_rejected_and_keeps_debt() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    h.resume_retained_recovery().unwrap();
    let mut recv = h
        .admit_retained_receiver(&f.key, old.revision(), target, 8)
        .unwrap();
    let error = recv.ready_record(8).unwrap_err();
    assert!(error.to_string().contains("resume-base negotiation"));
    assert!(recv.faulted);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn zero_byte_slot_and_drop_preserve_debt() {
    let mut f = stopped(b"", 0);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let (_, target) = owner(&f, &f.cp, false);
    h.resume_retained_recovery().unwrap();
    let recv = h
        .admit_retained_receiver(&f.key, old.revision(), target, 0)
        .unwrap();
    assert_eq!(recv.resumed_prefix(), Some(0));
    assert!(recv.ranges.complete());
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
    drop(recv);
    assert_eq!(h.status().unwrap().in_flight, 0);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 1));
    assert!(f.stage.exists());
    h.close().unwrap();
}
#[test]
fn source_role_and_expired_recovery_owners_are_rejected() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let before = bytes(&h, &f.key);
    h.resume_retained_recovery().unwrap();
    let (_, source) = owner(&f, &f.cp, true);
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), source, 8)
            .err()
            .unwrap()
            .to_string()
            .contains("Target role")
    );
    let (_, mut target) = owner(&f, &f.cp, false);
    target.test_expire();
    assert!(
        h.admit_retained_receiver(&f.key, old.revision(), target, 8)
            .is_err()
    );
    assert_eq!(bytes(&h, &f.key), before);
    assert_eq!(schema(&f.path), 12);
    h.close().unwrap();
}
#[cfg(windows)]
#[test]
fn resumed_target_local_publication_uses_same_file_and_schema13() {
    let mut f = stopped(b"abcdefgh", 3);
    let proof = f.proof.take().unwrap();
    let h = recovered(&f, proof);
    let old = h.get(&f.key).unwrap().unwrap();
    let old_id = old
        .stage()
        .unwrap()
        .allocation()
        .unwrap()
        .file_id()
        .unwrap()
        .to_owned();
    let (source, target) = owner(&f, &f.cp, false);
    let mut source = source.unwrap();
    let key = JobKey::from_job(target.grant().job());
    h.resume_retained_recovery().unwrap();
    let mut recv = h
        .admit_retained_receiver(&f.key, old.revision(), target, 8)
        .unwrap();
    assert_eq!(file_id(&recv.file).unwrap(), old_id);
    recv.write_record(&source.seal_data(3, b"defgh").unwrap())
        .unwrap();
    let finish = source
        .seal_control(crate::fleet::control::ControlBody::Finish(
            crate::fleet::control::Finish {
                size: 8,
                sha256: Sha256::digest(b"abcdefgh").into(),
            },
        ))
        .unwrap();
    let finished = recv
        .seal_finish(&finish)
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    let current = h.get(&key).unwrap().unwrap();
    assert_eq!(current.phase(), Phase::Completed);
    assert!(current.receipt().is_some() && current.stage().is_none());
    assert_eq!(schema(&f.path), 13);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
    assert_eq!(
        std::fs::read(f.path.with_file_name("target.bin")).unwrap(),
        b"abcdefgh"
    );
    assert!(!f.stage.exists());
    drop(finished);
    assert_eq!(h.status().unwrap().in_flight, 0);
    h.close().unwrap();
}
