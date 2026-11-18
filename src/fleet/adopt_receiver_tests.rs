//! A readback or recovered reference must not turn the normal admission path
//! into a restarted writer. The unsigned receiver candidate was rejected.
use super::*;

#[test]
fn recovered_debt_does_not_allow_normal_receiver_admission() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (mut source, mut receiver) = open(&host, &path, b"abcdefgh");
    let key = JobKey::from_job(receiver.snapshot().job());
    receiver.enable_retained_checkpoints().unwrap();
    receiver
        .write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    let cp = receiver.capture_retained_checkpoint().unwrap();
    drop(receiver);
    let stopped = host.stop_creators().unwrap();
    drop(host);
    let next_runtime = crate::runtime::Runtime::new(runtime.policy.clone());
    let next = next_runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    next.recover_creators(stopped).unwrap();
    let before = serde_json::to_vec(&next.get(&key).unwrap().unwrap()).unwrap();
    assert!(
        next.resume()
            .unwrap_err()
            .to_string()
            .contains("reservedBytes=8 slots=1")
    );
    let (_source, target) = Offer::new(&path, b"abcdefgh", 0).pair();
    assert!(
        next.admit_receiver(target)
            .err()
            .unwrap()
            .to_string()
            .contains("paused")
    );
    let after = next.get(&key).unwrap().unwrap();
    assert_eq!(serde_json::to_vec(&after).unwrap(), before);
    assert_eq!(after.phase(), Phase::Interrupted);
    assert_eq!(after.retained_stage().unwrap().checkpoint(), Some(&cp));
    assert_eq!(next.inventory().unwrap().recorded_usage(), (8, 1));
    assert!(!path.with_file_name("target.bin").exists());
}
