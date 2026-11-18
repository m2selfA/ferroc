use super::*;
#[test]
fn metadata_tampering_is_rejected_at_normal_reader_entry() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    let (mut source, mut recv) = open(&h, &p, b"abc");
    recv.enable_retained_checkpoints().unwrap();
    recv.write_record(&source.seal_data(0, b"a").unwrap())
        .unwrap();
    recv.capture_retained_checkpoint().unwrap();
    let key = JobKey::from_job(recv.snapshot().job());
    let original = serde_json::to_value(recv.snapshot()).unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    for field in ["bytes", "job_digest", "revision", "version"] {
        let mut changed = original.clone();
        let cp = &mut changed["retained"]["checkpoint"];
        match field {
            "bytes" => cp[field] = serde_json::json!(4),
            "job_digest" => {
                let n = cp[field][0].as_u64().unwrap();
                cp[field][0] = serde_json::json!(n ^ 1);
            }
            "revision" => cp[field] = serde_json::json!(u64::MAX),
            _ => cp[field] = serde_json::json!(999),
        }
        c.execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1",
            [changed.to_string()],
        )
        .unwrap();
        assert!(h.get(&key).is_err(), "accepted malformed {field}");
        c.execute(
            "UPDATE ferroc_fleet_jobs_v1 SET body=?1",
            [original.to_string()],
        )
        .unwrap();
        assert!(h.get(&key).unwrap().is_some());
    }
}
#[cfg(target_os = "linux")]
#[test]
fn schema12_is_preserved_by_anonymous_reservation_and_settlement() {
    let (_t, p, r) = fixture();
    let h = r.open_fleet_host(&p, InventoryLimits::default()).unwrap();
    h.resume().unwrap();
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute("UPDATE ferroc_fleet_meta SET version=12", [])
        .unwrap();
    drop(c);
    let (mut source, target) = Offer::new(&p, b"abc", 0).pair();
    let mut recv = h.admit_linux_anonymous_receiver(target).unwrap();
    assert_eq!(schema(&p), 12);
    recv.write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    assert_eq!(schema(&p), 12);
    let finish = source
        .seal_control(crate::fleet::control::ControlBody::Finish(
            crate::fleet::control::Finish {
                size: 3,
                sha256: Sha256::digest(b"abc").into(),
            },
        ))
        .unwrap();
    let sealed = recv.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    assert_eq!(schema(&p), 12);
    let renamed = candidate.attempt_local_publication().unwrap();
    let observed = renamed.record_target_observation().unwrap();
    let finished = observed.settle_local().unwrap();
    assert_eq!(schema(&p), 12);
    assert_eq!(finished.snapshot().phase(), Phase::Completed);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
}
