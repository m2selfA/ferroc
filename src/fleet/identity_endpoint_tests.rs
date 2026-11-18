//! Local endpoint binding contracts. PUBLIC test keys; no network.
use super::super::auth::IdentityKey;
use super::*;
use std::sync::{Arc, Barrier};
const KEY: [u8; 32] = [0x42; 32];
fn protection() -> Protection {
    Protection::supplied_key(Zeroizing::new(KEY)).unwrap()
}
fn fleet() -> Uuid {
    Uuid::from_bytes([7; 16])
}
fn store(root: &Path) -> IdentityStore {
    IdentityStore::create(&root.join("identity"), protection(), fleet(), "node-A").unwrap()
}
fn public(seed: u8) -> [u8; 32] {
    IdentityKey::from_test_seed([seed; 32]).public()
}
fn approved(device: &str, seed: u8) -> PeerApproval {
    let key = public(seed);
    PeerApproval::verify(
        fleet(),
        device,
        key,
        &fingerprint(fleet(), device, key).unwrap(),
    )
    .unwrap()
}
fn ready(root: &Path) -> (IdentityStore, Fingerprint) {
    let id = store(root);
    id.enroll_peer(approved("node-B", 1), "laptop-b", 1)
        .unwrap();
    let fp = id.peers().unwrap()[0].fingerprint(fleet()).unwrap();
    (id, fp)
}

#[test]
fn authenticated_legacy_endpoint_is_rejected_without_automatic_migration() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    let hash = device_digest("node-B").unwrap();
    let context = id.endpoint_context(&hash, EndpointSlot::Primary);
    // Actual old v1 layout (authenticated), not a random decrypt failure.
    let mut plain = Zeroizing::new(context.clone());
    plain.push(1);
    plain.push(6);
    plain.extend_from_slice(b"node-B");
    let url = b"https://old.example";
    plain.extend_from_slice(&(url.len() as u16).to_be_bytes());
    plain.extend_from_slice(url);
    let ciphertext = id.protection.seal(&context, &plain).unwrap();
    let path = id.endpoint_path(&hash, EndpointSlot::Primary);
    let mut file = new_private(&path).unwrap();
    file.write_all(&ciphertext).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        id.endpoints_for("node-B")
            .unwrap_err()
            .to_string()
            .contains("unsupported endpoint record version")
    );
    assert!(
        id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://new.example", &fp)
            .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), ciphertext);
}

#[test]
fn endpoint_must_not_survive_a_peer_key_rotation_as_an_approved_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://old.example", &fp)
        .unwrap();
    id.revoke_peer("node-B", &fp).unwrap();
    id.enroll_peer(approved("node-B", 2), "laptop-b", 2)
        .unwrap();
    assert!(
        id.endpoints_for("node-B").is_err(),
        "new key inherited an endpoint approved under the old key"
    );
}
#[test]
fn corrupt_endpoint_is_not_silently_overwritten_by_set() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://old.example", &fp)
        .unwrap();
    let path = id.endpoint_path(&device_digest("node-B").unwrap(), EndpointSlot::Primary);
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    f.write_all(b"bad-ciphertext").unwrap();
    f.sync_all().unwrap();
    drop(f);
    assert!(
        id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://new.example", &fp)
            .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), b"bad-ciphertext");
}

#[test]
fn endpoint_requires_the_current_approved_key_and_reuses_https_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    assert!(id.endpoints_for("node-B").unwrap().is_empty());
    assert_eq!(
        id.set_peer_endpoint(
            "node-B",
            EndpointSlot::Primary,
            "https://brc.tecs.ltd:8441",
            &fp
        )
        .unwrap(),
        EndpointAdmission::Created
    );
    let list = id.endpoints_for("node-B").unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].slot(), EndpointSlot::Primary);
    assert_eq!(list[0].url(), "https://brc.tecs.ltd:8441");
    assert_eq!(list[0].device(), "node-B");
    // Loopback plain HTTP is the one development exception, same as transport.
    id.set_peer_endpoint(
        "node-B",
        EndpointSlot::Fallback,
        "http://127.0.0.1:3211",
        &fp,
    )
    .unwrap();
    assert_eq!(id.endpoints_for("node-B").unwrap().len(), 2);
    for bad in [
        "http://brc.tecs.ltd:8441",
        "ftp://brc.tecs.ltd",
        "https://user:pw@brc.tecs.ltd",
        "https://brc.tecs.ltd/?x=1",
        "https://brc.tecs.ltd/#frag",
        "",
    ] {
        assert!(
            id.set_peer_endpoint("node-B", EndpointSlot::Primary, bad, &fp)
                .is_err(),
            "{bad}"
        );
    }
    let long = format!("https://{}.example", "a".repeat(600));
    assert!(
        id.set_peer_endpoint("node-B", EndpointSlot::Primary, &long, &fp)
            .is_err()
    );
    // Failed writes must not have disturbed the existing slot.
    assert_eq!(
        id.endpoints_for("node-B").unwrap()[0].url(),
        "https://brc.tecs.ltd:8441"
    );
}
#[test]
fn endpoint_cannot_be_created_for_unknown_or_drifted_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    assert!(
        id.set_peer_endpoint("node-X", EndpointSlot::Primary, "https://x.example", &fp)
            .is_err()
    );
    let fresh = fingerprint(fleet(), "node-B", public(2)).unwrap();
    assert!(
        id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://x.example", &fresh)
            .is_err()
    );
    assert!(id.endpoints_for("node-B").unwrap().is_empty());
    assert_eq!(id.peers().unwrap().len(), 1);
}
#[test]
fn rotation_is_explicit_atomic_and_never_leaves_a_partial_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://one.example", &fp)
        .unwrap();
    assert_eq!(
        id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://two.example", &fp)
            .unwrap(),
        EndpointAdmission::Rotated
    );
    let list = id.endpoints_for("node-B").unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].url(), "https://two.example");
    assert!(fs::read_dir(tmp.path().join("identity")).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".pending")
    }));
    // Reopening sees exactly the committed value.
    let reopened = IdentityStore::open(
        &tmp.path().join("identity"),
        protection(),
        fleet(),
        "node-A",
    )
    .unwrap();
    assert_eq!(
        reopened.endpoints_for("node-B").unwrap()[0].url(),
        "https://two.example"
    );
}
#[test]
fn endpoint_records_reject_tamper_and_cross_device_copies() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://one.example", &fp)
        .unwrap();
    let hash = device_digest("node-B").unwrap();
    let path = id.endpoint_path(&hash, EndpointSlot::Primary);
    let original = fs::read(&path).unwrap();
    for bytes in [Vec::new(), original[..original.len() / 2].to_vec()] {
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(&bytes).unwrap();
        f.sync_all().unwrap();
        assert!(id.endpoints_for("node-B").is_err());
    }
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    f.write_all(&original).unwrap();
    f.sync_all().unwrap();
    // Copy under another peer's digest is bound to the original device/hash.
    id.enroll_peer(approved("node-C", 2), "laptop-c", 2)
        .unwrap();
    let other = device_digest("node-C").unwrap();
    let copy = id.endpoint_path(&other, EndpointSlot::Primary);
    let mut out = new_private(&copy).unwrap();
    out.write_all(&original).unwrap();
    out.sync_all().unwrap();
    drop(out);
    assert!(id.endpoints_for("node-C").is_err());
    fs::remove_file(&copy).unwrap();
}
#[test]
fn clearing_one_slot_requires_the_approved_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (id, fp) = ready(tmp.path());
    id.set_peer_endpoint("node-B", EndpointSlot::Primary, "https://one.example", &fp)
        .unwrap();
    id.set_peer_endpoint("node-B", EndpointSlot::Fallback, "https://two.example", &fp)
        .unwrap();
    let drifted = fingerprint(fleet(), "node-B", public(2)).unwrap();
    assert!(
        id.clear_peer_endpoint("node-B", EndpointSlot::Primary, &drifted)
            .is_err()
    );
    assert_eq!(id.endpoints_for("node-B").unwrap().len(), 2);
    assert!(
        id.clear_peer_endpoint("node-B", EndpointSlot::Primary, &fp)
            .unwrap()
    );
    assert_eq!(id.endpoints_for("node-B").unwrap().len(), 1);
    assert!(
        !id.clear_peer_endpoint("node-B", EndpointSlot::Primary, &fp)
            .unwrap()
    );
}
#[test]
fn duplicate_labels_are_refused_even_when_two_devices_race_the_same_label() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for (device, seed) in [("node-B", 1u8), ("node-C", 2u8)] {
        let device = device.to_owned();
        let root = tmp.path().join("identity");
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let store = IdentityStore::open(&root, protection(), fleet(), "node-A").unwrap();
            let approval = approved(&device, seed);
            barrier.wait();
            store.enroll_peer(approval, "shared", 1)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // Either one wins, or both fail closed; a readable roster never has two
    // entries with the same label.
    if let Ok(peers) = id.peers() {
        let mut labels: Vec<_> = peers.iter().map(|p| p.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), peers.len());
    }
    assert!(
        results.iter().any(|r| r.is_err())
            || results
                .iter()
                .filter(|r| matches!(r, Ok(PeerAdmission::Created)))
                .count()
                <= 1
    );
}
