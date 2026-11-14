use super::*;
use crate::fleet::{
    manifest::{Comparison, EntryKind, Manifest, ManifestEntry, ManifestLimits, diff},
    sync_plan::{SyncTemplate, plan_add_only},
};
use uuid::Uuid;
fn f(path: &str, size: u64, hash: u8) -> ManifestEntry {
    ManifestEntry {
        path: path.into(),
        kind: EntryKind::File {
            size,
            mtime_ns: 7,
            sha256: Some([hash; 32]),
        },
    }
}
fn plan(files: &[(&str, u64, u8)]) -> SyncPlan {
    let entries: Vec<_> = files.iter().map(|(p, s, h)| f(p, *s, *h)).collect();
    let source = Manifest::new(entries, ManifestLimits::default()).unwrap();
    let target = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let d = diff(&source, &target, Comparison::Checksum).unwrap();
    plan_add_only(
        &source,
        &d,
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: [2; 32],
            target_device: [3; 32],
            transfer_id: Uuid::from_bytes([4; 16]),
            source_root: "C:/src",
            target_root: "C:/dst",
            deadline_ms: 60_000,
            idempotency_prefix: "sync-1",
            chunk_bytes: 65536,
        },
    )
    .unwrap()
}
fn template() -> GrantTemplate {
    GrantTemplate {
        source_session: Uuid::from_bytes([5; 16]),
        target_session: Uuid::from_bytes([6; 16]),
        authorization_seed: 11,
        epoch_seed: 22,
        issued_at_ms: 1_000,
        lease_ms: 30_000,
        chunk_bytes: 65536,
    }
}
#[test]
fn one_grant_per_file_with_stable_identity_and_no_clobber() {
    let plan = plan(&[("a.bin", 3, 1), ("b.bin", 5, 2)]);
    let batch = issue_for_plan(&plan, &template()).unwrap();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch.chunk_bytes(), 65536);
    assert_eq!(batch.expires_at_ms(), 31_000);
    for (grant, planned) in batch.grants().iter().zip(plan.files()) {
        assert_eq!(grant.job().file_id, planned.job().file_id);
        assert_eq!(grant.job().transfer_id, plan.files()[0].job().transfer_id);
        assert_eq!(grant.job().destination_path, planned.job().destination_path);
        assert!(grant.grant().binding.source_session == Uuid::from_bytes([5; 16]));
        assert!(grant.grant().binding.target_session == Uuid::from_bytes([6; 16]));
        assert!(matches!(
            grant.grant().permission,
            Permission::SendFileNoClobber
        ));
        assert_eq!(grant.grant().chunk_bytes, 65536);
        assert!(!grant.job().overwrite);
    }
}
#[test]
fn identical_inputs_give_identical_grant_digests() {
    let plan = plan(&[("a.bin", 3, 1), ("b.bin", 5, 2)]);
    let first = issue_for_plan(&plan, &template()).unwrap();
    let second = issue_for_plan(&plan, &template()).unwrap();
    assert_eq!(first.job_digests().unwrap(), second.job_digests().unwrap());
    for (l, r) in first.grants().iter().zip(second.grants()) {
        assert_eq!(l.digest(), r.digest());
        assert_eq!(l.grant().binding, r.grant().binding);
    }
}
#[test]
fn per_file_authorizations_are_distinct_and_never_reused() {
    let plan = plan(&[("a.bin", 3, 1), ("b.bin", 5, 2), ("c.bin", 7, 3)]);
    let batch = issue_for_plan(&plan, &template()).unwrap();
    let auth: BTreeSet<_> = batch
        .grants()
        .iter()
        .map(|g| g.grant().binding.authorization_id)
        .collect();
    let epochs: BTreeSet<_> = batch
        .grants()
        .iter()
        .map(|g| g.grant().binding.key_epoch)
        .collect();
    assert_eq!(auth.len(), 3);
    assert_eq!(epochs.len(), 3);
    assert!(auth.is_disjoint(&epochs));
    assert!(!auth.contains(&Uuid::nil()));
}
#[test]
fn lease_beyond_job_deadline_or_zero_is_refused() {
    let plan = plan(&[("a.bin", 3, 1)]);
    let mut too_long = template();
    too_long.lease_ms = 60_000;
    assert!(issue_for_plan(&plan, &too_long).is_err());
    let mut zero = template();
    zero.lease_ms = 0;
    assert!(issue_for_plan(&plan, &zero).is_err());
    let mut zero_issued = template();
    zero_issued.issued_at_ms = 0;
    zero_issued.lease_ms = 1_000;
    assert!(issue_for_plan(&plan, &zero_issued).is_ok());
}
#[test]
fn chunk_ceiling_and_session_shape_are_enforced() {
    let plan = plan(&[("a.bin", 3, 1)]);
    for chunk in [0u32, 65537] {
        let mut bad = template();
        bad.chunk_bytes = chunk;
        assert!(issue_for_plan(&plan, &bad).is_err(), "chunk {chunk}");
    }
    let mut same_session = template();
    same_session.target_session = same_session.source_session;
    assert!(issue_for_plan(&plan, &same_session).is_err());
    let mut nil = template();
    nil.source_session = Uuid::nil();
    assert!(issue_for_plan(&plan, &nil).is_err());
}
#[test]
fn identical_seeds_or_nil_seeds_are_refused() {
    let plan = plan(&[("a.bin", 3, 1)]);
    let mut same = template();
    same.epoch_seed = same.authorization_seed;
    assert!(issue_for_plan(&plan, &same).is_err());
    let mut nil = template();
    nil.authorization_seed = 0;
    assert!(issue_for_plan(&plan, &nil).is_err());
}
#[test]
fn empty_plan_yields_an_empty_batch_without_ids() {
    let plan = plan(&[]);
    let batch = issue_for_plan(&plan, &template()).unwrap();
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
    assert!(batch.grants().is_empty());
}
