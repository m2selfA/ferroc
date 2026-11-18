use super::*;
use crate::fleet::{
    job::{FileGrant, JOB_VERSION, JobSpec, LeaseProfile, Permission, RoutePolicy},
    protocol::Binding,
};
use serde_json::{Value, json};
/// Deliberately INVALID signatures: these probes prove routing, NOT peer approval.
pub(crate) fn public_offer(source: &str, target: &str, n: u128) -> String {
    let id = |v| Uuid::from_u128(v);
    let job = JobSpec {
        version: JOB_VERSION,
        fleet_id: id(1),
        source_device: device_digest(source).unwrap(),
        target_device: device_digest(target).unwrap(),
        transfer_id: id(100 + n),
        file_id: id(200 + n),
        source_path: "/source/input.bin".into(),
        destination_path: "/target/output.bin".into(),
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: format!("route-{n}"),
    };
    let grant = FileGrant {
        binding: Binding {
            fleet_id: job.fleet_id,
            source_device: job.source_device,
            target_device: job.target_device,
            source_session: id(3),
            target_session: id(4),
            transfer_id: job.transfer_id,
            file_id: job.file_id,
            authorization_id: id(300 + n),
            key_epoch: id(400 + n),
        },
        job_digest: job.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 65536,
        issued_at_ms: 100,
        expires_at_ms: 1000,
    };
    grant
        .clone()
        .validate_for_profile(job.clone(), LeaseProfile::Rotating)
        .unwrap();
    json!({"version":1,"profile":0,"job":job,"grant":grant,"sourceIdentity":vec![1;32],"targetIdentity":vec![2;32],"sourceEphemeral":vec![3;32],"signature":vec![0;64]}).to_string()
}
pub(crate) fn public_response(offer: &str) -> String {
    let (_, digest) = SetupOffer::decode(offer.as_bytes())
        .unwrap()
        .routing_context()
        .unwrap();
    json!({"version":1,"offerDigest":digest,"targetEphemeral":vec![4;32],"grantSignature":vec![0;64],"signature":vec![0;64]}).to_string()
}
pub(crate) fn public_confirmation(response: &str) -> String {
    let (_, digest) = SetupResponse::decode(response.as_bytes())
        .unwrap()
        .routing_context()
        .unwrap();
    json!({"version":1,"responseDigest":digest,"grantSignature":vec![0;64],"signature":vec![0;64]})
        .to_string()
}
fn peer(d: &str, g: &str) -> Peer {
    Peer::new(d, g).unwrap()
}
#[test]
fn phases_bind_public_digests_and_keep_final_queued_until_os_write() {
    let b = SetupBroker::default();
    let now = Instant::now();
    let id = Uuid::new_v4();
    let a = peer("a", "a1");
    let t = peer("b", "b1");
    let o = public_offer("a", "b", 1);
    let r = public_response(&o);
    let c = public_confirmation(&r);
    let d = b.offer(id, a.clone(), t.clone(), o, now).unwrap();
    b.delivery_allowed(&d, now).unwrap();
    b.sent(&d);
    let d = b.response(id, &t, r, now).unwrap();
    assert_eq!(d.recipient(), &a);
    b.sent(&d);
    let d = b.confirmation(id, &a, c, now).unwrap();
    b.delivery_allowed(&d, now).unwrap();
    assert_eq!(b.table.lock().unwrap().active.len(), 1);
    b.sent(&d);
    assert!(b.delivery_allowed(&d, now).is_err());
    assert!(b.table.lock().unwrap().active.is_empty());
    assert!(b.offer(id, a, t, public_offer("a", "b", 2), now).is_err());
}
#[test]
fn foreign_generation_cannot_advance_or_destroy_another_owner() {
    let b = SetupBroker::default();
    let now = Instant::now();
    let id = Uuid::new_v4();
    let a = peer("a", "one");
    let t = peer("b", "one");
    let o = public_offer("a", "b", 1);
    let r = public_response(&o);
    let d = b.offer(id, a.clone(), t.clone(), o, now).unwrap();
    assert!(b.response(id, &peer("b", "two"), r.clone(), now).is_err());
    assert!(b.response(id, &a, r.clone(), now).is_err());
    b.delivery_allowed(&d, now).unwrap();
    assert!(b.response(id, &t, r, now).is_ok());
}
#[test]
fn response_and_confirmation_cannot_cross_exact_offer_instances() {
    let b = SetupBroker::default();
    let now = Instant::now();
    let a = peer("a", "1");
    let t = peer("b", "1");
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let o1 = public_offer("a", "b", 1);
    let o2 = public_offer("a", "b", 2);
    let r1 = public_response(&o1);
    let r2 = public_response(&o2);
    let c1 = public_confirmation(&r1);
    b.offer(first, a.clone(), t.clone(), o1, now).unwrap();
    b.offer(second, a.clone(), t.clone(), o2, now).unwrap();
    assert!(b.response(first, &t, r2.clone(), now).is_err());
    assert!(!b.table.lock().unwrap().active.contains_key(&first));
    b.response(second, &t, r2, now).unwrap();
    assert!(b.confirmation(second, &a, c1, now).is_err());
}
#[test]
fn repeated_phase_or_malformed_current_peer_consumes_route_not_history() {
    let b = SetupBroker::default();
    let now = Instant::now();
    let a = peer("a", "1");
    let t = peer("b", "1");
    let id = Uuid::new_v4();
    let o = public_offer("a", "b", 1);
    let r = public_response(&o);
    b.offer(id, a.clone(), t.clone(), o.clone(), now).unwrap();
    b.response(id, &t, r.clone(), now).unwrap();
    assert!(b.response(id, &t, r, now).is_err());
    assert!(
        b.offer(Uuid::new_v4(), a.clone(), t.clone(), o, now)
            .is_err()
    );
    let id = Uuid::new_v4();
    b.offer(id, a.clone(), t.clone(), public_offer("a", "b", 2), now)
        .unwrap();
    assert!(b.response(id, &t, "{}".into(), now).is_err());
    assert!(b.table.lock().unwrap().active.is_empty());
}
#[test]
fn fixed_deadline_is_not_extended_by_response_and_keeps_spent_ids() {
    let b = SetupBroker::default();
    let now = Instant::now();
    let a = peer("a", "1");
    let t = peer("b", "1");
    let id = Uuid::new_v4();
    let o = public_offer("a", "b", 1);
    let r = public_response(&o);
    let c = public_confirmation(&r);
    let d = b.offer(id, a.clone(), t.clone(), o, now).unwrap();
    b.delivery_allowed(&d, now + Duration::from_millis(29_999))
        .unwrap();
    b.response(id, &t, r, now + Duration::from_millis(29_999))
        .unwrap();
    assert!(
        b.confirmation(id, &a, c, now + Duration::from_secs(30))
            .is_err()
    );
    assert_eq!(b.table.lock().unwrap().ids.len(), 1);
    assert!(b.table.lock().unwrap().active.is_empty());
}
#[test]
fn disconnection_removes_only_that_generation_and_queued_frames_become_invalid() {
    let b = SetupBroker::default();
    let now = Instant::now();
    let old = peer("a", "old");
    let new = peer("a", "new");
    let t = peer("b", "1");
    let d1 = b
        .offer(
            Uuid::new_v4(),
            old.clone(),
            t.clone(),
            public_offer("a", "b", 1),
            now,
        )
        .unwrap();
    let d2 = b
        .offer(Uuid::new_v4(), new, t, public_offer("a", "b", 2), now)
        .unwrap();
    b.disconnected(&old);
    assert!(b.delivery_allowed(&d1, now).is_err());
    b.delivery_allowed(&d2, now).unwrap();
    b.failed(&d2);
    assert!(b.delivery_allowed(&d2, now).is_err());
}
#[test]
fn per_device_global_capacity_and_history_refuse_instead_of_evicting() {
    let b = SetupBroker::default();
    let now = Instant::now();
    for n in 0..MAX_PER_DEVICE {
        b.offer(
            Uuid::new_v4(),
            peer("a", "1"),
            peer(&format!("b{n}"), "1"),
            public_offer("a", &format!("b{n}"), n as u128),
            now,
        )
        .unwrap();
    }
    assert!(
        b.offer(
            Uuid::new_v4(),
            peer("a", "1"),
            peer("extra", "1"),
            public_offer("a", "extra", 99),
            now
        )
        .is_err()
    );
    let b = SetupBroker::default();
    for n in 0..MAX_ACTIVE {
        let a = format!("a{n}");
        let t = format!("b{n}");
        b.offer(
            Uuid::new_v4(),
            peer(&a, "1"),
            peer(&t, "1"),
            public_offer(&a, &t, n as u128),
            now,
        )
        .unwrap();
    }
    assert!(
        b.offer(
            Uuid::new_v4(),
            peer("x", "1"),
            peer("y", "1"),
            public_offer("x", "y", 99),
            now
        )
        .is_err()
    );
    let b = SetupBroker::default();
    for n in 0..MAX_HISTORY {
        let d = b
            .offer(
                Uuid::new_v4(),
                peer("a", "1"),
                peer("b", "1"),
                public_offer("a", "b", n as u128),
                now,
            )
            .unwrap();
        b.failed(&d);
    }
    b.expire(now + Duration::from_secs(1000));
    assert!(b.table.lock().unwrap().active.is_empty());
    assert_eq!(b.table.lock().unwrap().ids.len(), MAX_HISTORY);
    assert!(
        b.offer(
            Uuid::new_v4(),
            peer("a", "1"),
            peer("b", "1"),
            public_offer("a", "b", 999),
            now + Duration::from_secs(1000)
        )
        .is_err()
    );
}
#[test]
fn actor_devices_structural_profile_and_duplicate_job_are_checked() {
    let b = SetupBroker::default();
    let now = Instant::now();
    let a = peer("a", "1");
    let t = peer("b", "1");
    let o = public_offer("a", "b", 1);
    assert!(
        b.offer(Uuid::nil(), a.clone(), t.clone(), o.clone(), now)
            .is_err()
    );
    assert!(
        b.offer(
            Uuid::new_v4(),
            peer("wrong", "1"),
            t.clone(),
            o.clone(),
            now
        )
        .is_err()
    );
    let mut v: Value = serde_json::from_str(&o).unwrap();
    v["profile"] = json!(9);
    assert!(
        b.offer(Uuid::new_v4(), a.clone(), t.clone(), v.to_string(), now)
            .is_err()
    );
    let d = b
        .offer(Uuid::new_v4(), a.clone(), t.clone(), o.clone(), now)
        .unwrap();
    b.failed(&d);
    let mut v: Value = serde_json::from_str(&o).unwrap();
    v["grant"]["binding"]["authorizationId"] = json!(Uuid::new_v4());
    assert!(b.offer(Uuid::new_v4(), a, t, v.to_string(), now).is_err());
}
