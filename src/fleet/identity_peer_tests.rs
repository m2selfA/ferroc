//! Local peer-book contracts. Keys are PUBLIC test seeds; no network.
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
    // create() requires a path it creates itself; tempdir already exists.
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
#[test]
fn enrolment_is_explicit_idempotent_and_recomputes_fingerprints() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    assert!(id.peers().unwrap().is_empty());
    assert_eq!(
        id.enroll_peer(approved("node-B", 1), "laptop-b", 1_700_000_000_000)
            .unwrap(),
        PeerAdmission::Created
    );
    // Repeating the SAME approved key is idempotent, not a new grant.
    assert_eq!(
        id.enroll_peer(approved("node-B", 1), "laptop-b", 5)
            .unwrap(),
        PeerAdmission::Existing
    );
    let peers = id.peers().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].device(), "node-B");
    assert_eq!(peers[0].label(), "laptop-b");
    assert_eq!(peers[0].added_ms(), 1_700_000_000_000);
    assert_eq!(
        peers[0].fingerprint(fleet()).unwrap(),
        fingerprint(fleet(), "node-B", public(1)).unwrap()
    );
    // A reopened store (new process equivalent) reads the same roster.
    let reopened = IdentityStore::open(
        &tmp.path().join("identity"),
        protection(),
        fleet(),
        "node-A",
    )
    .unwrap();
    assert_eq!(reopened.peers().unwrap(), peers);
}
#[test]
fn explicit_approval_mismatch_enrols_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    let key = public(1);
    let wrong = fingerprint(fleet(), "node-B", public(2)).unwrap();
    assert!(PeerApproval::verify(fleet(), "node-B", key, &wrong).is_err());
    // A different device spelling does not satisfy the approved fingerprint.
    assert!(
        PeerApproval::verify(
            fleet(),
            "node-C",
            key,
            &fingerprint(fleet(), "node-B", key).unwrap()
        )
        .is_err()
    );
    // A different fleet does not either.
    assert!(
        PeerApproval::verify(
            Uuid::from_bytes([9; 16]),
            "node-B",
            key,
            &fingerprint(fleet(), "node-B", key).unwrap()
        )
        .is_err()
    );
    assert!(id.peers().unwrap().is_empty());
}
#[test]
fn key_conflict_requires_explicit_revoke_and_never_rotates_silently() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    id.enroll_peer(approved("node-B", 1), "laptop-b", 1)
        .unwrap();
    let conflict = id
        .enroll_peer(approved("node-B", 2), "laptop-b", 2)
        .unwrap_err();
    assert!(conflict.to_string().contains("conflict"), "{conflict}");
    let peers = id.peers().unwrap();
    assert_eq!(peers.len(), 1);
    let old = peers[0].fingerprint(fleet()).unwrap();
    let fresh = fingerprint(fleet(), "node-B", public(2)).unwrap();
    // Revocation by a drifted fingerprint is refused and retains the record.
    assert!(id.revoke_peer("node-B", &fresh).is_err());
    assert_eq!(id.peers().unwrap().len(), 1);
    assert!(id.revoke_peer("node-B", &old).unwrap());
    assert!(id.peers().unwrap().is_empty());
    // Only after the explicit revoke can the new key be enrolled.
    assert_eq!(
        id.enroll_peer(approved("node-B", 2), "laptop-b", 3)
            .unwrap(),
        PeerAdmission::Created
    );
}
#[test]
fn self_wrong_fleet_and_bad_labels_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    let self_approval = approved("node-A", 3);
    assert!(id.enroll_peer(self_approval, "self", 1).is_err());
    let foreign = PeerApproval::verify(
        Uuid::from_bytes([8; 16]),
        "node-B",
        public(1),
        &fingerprint(Uuid::from_bytes([8; 16]), "node-B", public(1)).unwrap(),
    )
    .unwrap();
    assert!(id.enroll_peer(foreign, "laptop-b", 1).is_err());
    for label in [
        "",
        " ",
        "has space",
        "sla/sh",
        "dotdot..",
        "caf\u{e9}",
        "tab\t",
    ] {
        let result = id.enroll_peer(approved("node-B", 1), label, 1);
        assert!(result.is_err(), "label {label:?} must be refused");
    }
    let long = "a".repeat(65);
    assert!(id.enroll_peer(approved("node-B", 1), &long, 1).is_err());
    assert!(id.peers().unwrap().is_empty());
}
#[test]
fn duplicate_label_for_another_device_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    id.enroll_peer(approved("node-B", 1), "shared", 1).unwrap();
    let clash = id
        .enroll_peer(approved("node-C", 2), "shared", 2)
        .unwrap_err();
    assert!(clash.to_string().contains("label"), "{clash}");
    assert_eq!(id.peers().unwrap().len(), 1);
}
#[test]
fn roster_rejects_corrupt_version_truncated_and_mismatched_records() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    id.enroll_peer(approved("node-B", 1), "laptop-b", 1)
        .unwrap();
    let hash = device_digest("node-B").unwrap();
    let path = id.peer_path(&hash);
    let original = fs::read(&path).unwrap();
    let cases: Vec<Vec<u8>> = vec![Vec::new(), original[..original.len() / 2].to_vec(), {
        let mut v = original.clone();
        let n = v.len();
        v[n - 1] ^= 0xff;
        v
    }];
    for bytes in cases {
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(&bytes).unwrap();
        f.sync_all().unwrap();
        assert!(
            id.peers().is_err(),
            "corrupt record must never be silently dropped"
        );
    }
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    f.write_all(&original).unwrap();
    f.sync_all().unwrap();
    assert_eq!(id.peers().unwrap().len(), 1);
    // A copy under another device hash cannot be re-labelled into the roster.
    let other = device_digest("node-Z").unwrap();
    let duplicate = id.peer_path(&other);
    let mut out = new_private(&duplicate).unwrap();
    out.write_all(&original).unwrap();
    out.sync_all().unwrap();
    drop(out);
    // The copied ciphertext is bound to the original device hash, so it must
    // fail authentication or the device/filename binding; never be listed.
    assert!(id.peers().is_err());
    fs::remove_file(&duplicate).unwrap();
}
#[test]
fn roster_is_bounded_and_concurrent_enrolment_has_one_winner() {
    let tmp = tempfile::tempdir().unwrap();
    let id = store(tmp.path());
    let approval = approved("node-B", 1);
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let approval = PeerApproval::verify(
            fleet(),
            "node-B",
            public(1),
            &fingerprint(fleet(), "node-B", public(1)).unwrap(),
        )
        .unwrap();
        let root = tmp.path().join("identity");
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let store = IdentityStore::open(&root, protection(), fleet(), "node-A").unwrap();
            barrier.wait();
            store.enroll_peer(approval, "laptop-b", 1).unwrap()
        }));
    }
    drop(approval);
    let outcomes: Vec<PeerAdmission> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == PeerAdmission::Created)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == PeerAdmission::Existing)
            .count(),
        3
    );
    assert_eq!(id.peers().unwrap().len(), 1);
    for index in 0..63u8 {
        let device = format!("bulk-{index}");
        id.enroll_peer(approved(&device, 100 + index), &device, 1)
            .unwrap();
    }
    assert_eq!(id.peers().unwrap().len(), 64);
    let overflow = id
        .enroll_peer(approved("overflow", 9), "overflow", 1)
        .unwrap_err();
    assert!(overflow.to_string().contains("capacity"), "{overflow}");
    assert_eq!(id.peers().unwrap().len(), 64);
}
