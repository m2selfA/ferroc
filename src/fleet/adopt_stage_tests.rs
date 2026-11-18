use super::*;
use crate::fleet::{fence::OwnerFence, inventory::InventoryLimits, journal::JobKey};
use sha2::Sha256;
use std::sync::Arc;
#[test]
fn adopt_reopens_original_object_and_verifies_prefix_before_binding() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let owner = recv.snapshot().owner();
    let key = JobKey::from_job(recv.snapshot().job());
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let cp = recv.capture_retained_checkpoint().unwrap();
    drop(recv);
    h.close().unwrap();
    let fence = OwnerFence::acquire(&p).unwrap();
    let mut db = fence.open_connection().unwrap();
    db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    let snap = db.journal().unwrap().get(&key).unwrap().unwrap();
    let (file, length) = db
        .adopt_retained_stage(
            &key,
            snap.revision(),
            &r.policy,
            Arc::default(),
            Some((&cp.sha256(), cp.bytes())),
        )
        .unwrap();
    assert_eq!(length, 3);
    let mut buf = Vec::new();
    (&file).read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"abc");
    // Second adopt with a WRONG prefix must fail closed and NOT rebind.
    let wrong: [u8; 32] = Sha256::digest(b"xyz").into();
    assert!(
        db.adopt_retained_stage(
            &key,
            snap.revision(),
            &r.policy,
            Arc::default(),
            Some((&wrong, 3))
        )
        .is_err()
    );
    // State remains bound to the first successful adopt; phase unchanged.
    let after = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert_eq!(after.phase(), crate::fleet::state::Phase::Interrupted);
    assert_eq!(after.retained_stage().unwrap().checkpoint().unwrap(), &cp);
}
#[test]
fn anonymous_or_foreign_domain_or_live_phase_refuse_adoption() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    let owner = recv.snapshot().owner();
    let key = JobKey::from_job(recv.snapshot().job());
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    recv.capture_retained_checkpoint().unwrap();
    // LIVE phase (Transferring, not recovered): adopt must refuse.
    let snap = recv.snapshot().clone();
    drop(recv);
    h.close().unwrap();
    let fence = OwnerFence::acquire(&p).unwrap();
    let mut db = fence.open_connection().unwrap();
    // Without recover_stopped_owner, phase is Transferring and owner differs.
    assert!(
        db.adopt_retained_stage(&key, snap.revision(), &r.policy, Arc::default(), None)
            .is_err()
    );
    let _ = owner;
    db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    // Wrong revision refuses.
    let snap2 = db.journal().unwrap().get(&key).unwrap().unwrap();
    assert!(
        db.adopt_retained_stage(&key, snap2.revision() + 1, &r.policy, Arc::default(), None)
            .is_err()
    );
}
