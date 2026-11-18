use super::super::auth::{IdentityKey, Transcript};
use super::super::protocol::{Binding, Direction};
use super::*;
use ring::signature::{ED25519, UnparsedPublicKey};
use std::{
    process::{Command, Stdio},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};
const KEY: [u8; 32] = [0x42; 32]; // Public test wrapping material only, never production.
fn protection() -> Protection {
    Protection::supplied_key(Zeroizing::new(KEY)).unwrap()
}
fn fleet() -> Uuid {
    Uuid::from_bytes([1; 16])
}
fn create(root: &Path) -> IdentityStore {
    IdentityStore::create(root, protection(), fleet(), "node-A").unwrap()
}
fn open(root: &Path) -> IdentityStore {
    IdentityStore::open(root, protection(), fleet(), "node-A").unwrap()
}
fn private_bytes(path: &Path, bytes: &[u8]) {
    let mut f = new_private(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
fn replace(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
fn approval(public: [u8; 32]) -> PeerApproval {
    PeerApproval::verify(
        fleet(),
        "node-B",
        public,
        &fingerprint(fleet(), "node-B", public).unwrap(),
    )
    .unwrap()
}
fn key(seed: u8) -> [u8; 32] {
    IdentityKey::from_test_seed([seed; 32]).public()
}
fn no_pending(path: &Path) {
    assert!(fs::read_dir(path).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".pending")
    }));
}
#[test]
fn released_temp_name_is_not_deleted_again_after_ownership_is_gone() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("owned.tmp");
    private_bytes(&path, b"first");
    let mut pending = Pending {
        path: path.clone(),
        owned: true,
    };
    pending.remove().unwrap();
    private_bytes(&path, b"replacement");
    drop(pending);
    assert_eq!(fs::read(path).unwrap(), b"replacement");
}

#[test]
fn encrypted_create_load_is_stable_and_existing_identity_is_never_replaced() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    let a = s.create_identity().unwrap().public();
    let before = fs::read(path.join("identity.fid")).unwrap();
    assert_eq!(s.load_identity().unwrap().public(), a);
    assert!(s.create_identity().is_err());
    assert_eq!(fs::read(path.join("identity.fid")).unwrap(), before);
    drop(s);
    assert_eq!(open(&path).load_identity().unwrap().public(), a);
    no_pending(&path);
}
#[test]
fn protected_bytes_do_not_contain_plain_pkcs8_and_decrypt_exactly() {
    let (k, secret) = IdentityKey::generate().unwrap();
    let p = protection();
    let blob = p.seal(b"explicit-context", &secret).unwrap();
    assert!(!blob.windows(secret.len()).any(|s| s == secret.as_slice()));
    let plain = p.open(b"explicit-context", &blob).unwrap();
    assert_eq!(plain.as_slice(), secret.as_slice());
    assert_eq!(
        IdentityKey::from_pkcs8(&plain).unwrap().public(),
        k.public()
    );
}
#[test]
fn external_wrong_key_context_and_backend_never_fall_back() {
    assert!(Protection::supplied_key(Zeroizing::new([0; 32])).is_err());
    let p = protection();
    let mut blob = p.seal(b"context", b"secret").unwrap();
    assert!(p.open(b"other", &blob).is_err());
    assert!(
        Protection::supplied_key(Zeroizing::new([7; 32]))
            .unwrap()
            .open(b"context", &blob)
            .is_err()
    );
    blob[b"FROC-VAULT\x01".len()] = 99;
    assert!(p.open(b"context", &blob).is_err());
}
#[test]
fn every_protected_byte_and_truncation_is_rejected() {
    let p = protection();
    let blob = p.seal(b"context", b"secret bytes").unwrap();
    for i in 0..blob.len() {
        assert!(p.open(b"context", &blob[..i]).is_err());
        let mut changed = blob.clone();
        changed[i] ^= 1;
        assert!(p.open(b"context", &changed).is_err());
    }
    let mut extra = blob.clone();
    extra.push(0);
    assert!(p.open(b"context", &extra).is_err());
}
#[test]
fn missing_corrupt_oversized_and_authenticated_malformed_identity_do_not_regenerate() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    assert!(s.load_identity().is_err());
    assert!(!path.join("identity.fid").exists());
    let original = s.create_identity().unwrap().public();
    let name = path.join("identity.fid");
    let before = fs::read(&name).unwrap();
    for bad in [
        vec![],
        vec![0; 17000],
        s.protection
            .seal(&s.context(b"identity"), b"bad but authenticated layout")
            .unwrap(),
    ] {
        replace(&name, &bad);
        assert!(s.load_identity().is_err());
        assert!(s.create_identity().is_err());
        assert_eq!(fs::read(&name).unwrap(), bad);
    }
    replace(&name, &before);
    assert_eq!(s.load_identity().unwrap().public(), original);
}
#[test]
fn authenticated_public_private_mismatch_and_extra_key_bytes_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    s.create_identity().unwrap();
    let c = s.context(b"identity");
    let original = s.read("identity.fid", &c).unwrap();
    let file = path.join("identity.fid");
    for dimension in 0..3 {
        let mut bad = Zeroizing::new(original.to_vec());
        match dimension {
            0 => bad[c.len()] ^= 1,
            1 => bad.push(0),
            _ => {
                bad[c.len() + 32] = 0xff;
            }
        };
        let wrapped = s.protection.seal(&c, &bad).unwrap();
        replace(&file, &wrapped);
        assert!(s.load_identity().is_err());
    }
}
#[test]
fn same_key_cannot_rebind_store_to_other_fleet_or_device() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    s.create_identity().unwrap();
    for (id, name) in [(Uuid::from_bytes([2; 16]), "node-A"), (fleet(), "node-C")] {
        assert!(
            IdentityStore::open(&path, protection(), id, name)
                .unwrap()
                .load_identity()
                .is_err()
        );
    }
}
#[test]
fn approval_requires_exact_context_bound_independent_fingerprint() {
    let public = key(11);
    let fp = fingerprint(fleet(), "node-B", public).unwrap();
    let text = fp.hex();
    assert_eq!(Fingerprint::parse_hex(&text).unwrap(), fp);
    assert!(PeerApproval::verify(fleet(), "node-B", public, &fp).is_ok());
    assert!(PeerApproval::verify(fleet(), "node-C", public, &fp).is_err());
    assert!(PeerApproval::verify(Uuid::from_bytes([2; 16]), "node-B", public, &fp).is_err());
    assert!(PeerApproval::verify(fleet(), "node-B", key(12), &fp).is_err());
    for invalid in ["".into(), "x".repeat(64), "1".repeat(63), "零".repeat(64)] {
        assert!(Fingerprint::parse_hex(&invalid).is_err());
    }
}
#[test]
fn pin_first_create_identical_is_idempotent_and_conflict_preserves_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    let public = key(11);
    assert_eq!(
        s.approve_new_pin(approval(public)).unwrap(),
        PinAdmission::Created
    );
    let (name, _) = s.pin_context("node-B").unwrap();
    let before = fs::read(path.join(&name)).unwrap();
    assert_eq!(
        s.approve_new_pin(approval(public)).unwrap(),
        PinAdmission::Existing
    );
    assert!(s.approve_new_pin(approval(key(12))).is_err());
    assert_eq!(fs::read(path.join(name)).unwrap(), before);
    assert_eq!(
        s.pin_fingerprint("node-B").unwrap(),
        fingerprint(fleet(), "node-B", public).unwrap()
    );
    s.load_pin("node-B").unwrap();
    no_pending(&path);
}
#[test]
fn damaged_pin_does_not_turn_into_new_first_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    s.approve_new_pin(approval(key(11))).unwrap();
    let (name, _) = s.pin_context("node-B").unwrap();
    replace(&path.join(&name), b"corrupt");
    assert!(s.load_pin("node-B").is_err());
    assert!(s.approve_new_pin(approval(key(11))).is_err());
    assert_eq!(fs::read(path.join(name)).unwrap(), b"corrupt");
    no_pending(&path);
}
#[test]
fn copied_pin_ciphertext_cannot_be_relabelled_to_other_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    s.approve_new_pin(approval(key(11))).unwrap();
    let (name, _) = s.pin_context("node-B").unwrap();
    let (other, _) = s.pin_context("node-C").unwrap();
    private_bytes(&path.join(other), &fs::read(path.join(name)).unwrap());
    assert!(s.load_pin("node-C").is_err());
}
#[test]
fn wrong_fleet_and_self_approval_never_publish_a_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    for (id, name) in [(Uuid::from_bytes([2; 16]), "node-B"), (fleet(), "node-A")] {
        let a = PeerApproval::verify(id, name, key(11), &fingerprint(id, name, key(11)).unwrap())
            .unwrap();
        assert!(s.approve_new_pin(a).is_err());
    }
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}
#[test]
fn invalid_roots_and_types_fail_without_repair_or_plaintext_creation() {
    assert!(IdentityStore::create(Path::new("relative"), protection(), fleet(), "node-A").is_err());
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    assert!(IdentityStore::create(&path, protection(), Uuid::nil(), "node-A").is_err());
    assert!(!path.exists());
    let s = create(&path);
    assert!(IdentityStore::create(&path, protection(), fleet(), "node-A").is_err());
    make_directory(&path.join("identity.fid")).unwrap();
    assert!(s.load_identity().is_err());
    assert!(s.create_identity().is_err());
    assert!(path.join("identity.fid").is_dir());
}
#[test]
fn eight_concurrent_identity_creates_have_exactly_one_winner() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    drop(create(&path));
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                let s = open(&path);
                b.wait();
                s.create_identity().ok().map(|k| k.public())
            })
        })
        .collect();
    let keys: Vec<_> = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(open(&path).load_identity().unwrap().public(), keys[0]);
    assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
    no_pending(&path);
}
#[test]
fn concurrent_matching_and_conflicting_pins_keep_atomic_first_approval() {
    for conflict in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("store");
        drop(create(&path));
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let path = path.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    let s = open(&path);
                    b.wait();
                    s.approve_new_pin(approval(key(if conflict && i == 1 { 12 } else { 11 })))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            results
                .iter()
                .filter(|x| matches!(x, Ok(PinAdmission::Created)))
                .count(),
            1
        );
        assert_eq!(
            results.iter().filter(|x| x.is_ok()).count(),
            if conflict { 1 } else { 2 }
        );
        open(&path).load_pin("node-B").unwrap();
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
        no_pending(&path);
    }
}
fn transcript(public: [u8; 32]) -> Transcript {
    Transcript {
        binding: Binding {
            fleet_id: fleet(),
            source_device: device_digest("node-A").unwrap(),
            target_device: device_digest("node-B").unwrap(),
            source_session: Uuid::from_bytes([3; 16]),
            target_session: Uuid::from_bytes([4; 16]),
            transfer_id: Uuid::from_bytes([5; 16]),
            file_id: Uuid::from_bytes([6; 16]),
            authorization_id: Uuid::from_bytes([7; 16]),
            key_epoch: Uuid::from_bytes([8; 16]),
        },
        job_digest: [2; 32],
        grant_digest: [3; 32],
        source_identity: public,
        target_identity: key(22),
        source_ephemeral: [5; 32],
        target_ephemeral: [6; 32],
        max_file_bytes: 3,
        chunk_bytes: 3,
        issued_at_ms: 100,
        expires_at_ms: 1000,
    }
}
fn native_or_external() -> Protection {
    #[cfg(windows)]
    {
        Protection::windows_current_user().unwrap()
    }
    #[cfg(not(windows))]
    {
        protection()
    }
}
#[test]
#[ignore = "isolated subprocess helper invoked only by its owning parent test"]
fn identity_process_child() {
    let root = std::env::var_os("FERROC_IDENTITY_PROBE_PATH")
        .expect("explicit parent-owned probe directory required");
    let action = std::env::var("FERROC_IDENTITY_PROBE_ACTION").unwrap();
    let path = Path::new(&root);
    let store = IdentityStore::open(path, native_or_external(), fleet(), "node-A").unwrap();
    if action == "reject" {
        assert!(store.load_identity().is_err());
        return;
    }
    let loaded = store.load_identity().unwrap();
    let t = transcript(loaded.public());
    let signature = loaded.sign(&t, Direction::SourceToTarget).unwrap();
    let output = serde_json::json!({"public":hex(&loaded.public()),"signature":hex(&signature)});
    println!("IDENTITY-PROBE: {output}");
}
#[test]
fn independent_process_loads_same_key_and_signs_verifiable_transcript() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = IdentityStore::create(&path, native_or_external(), fleet(), "node-A").unwrap();
    let public = s.create_identity().unwrap().public();
    drop(s);
    let mut log = tempfile::tempfile().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fleet::identity::tests::identity_process_child",
            "--ignored",
            "--nocapture",
        ])
        .env("FERROC_IDENTITY_PROBE_PATH", &path)
        .env("FERROC_IDENTITY_PROBE_ACTION", "load")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("identity child timeout; terminated and reaped");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    use std::io::{Seek, SeekFrom};
    log.seek(SeekFrom::Start(0)).unwrap();
    let mut text = String::new();
    Read::by_ref(&mut log)
        .take(65537)
        .read_to_string(&mut text)
        .unwrap();
    assert!(text.len() <= 65536);
    assert!(status.success(), "{text}");
    let line = text
        .lines()
        .find_map(|s| s.strip_prefix("IDENTITY-PROBE: "))
        .expect("actual child proof");
    let result: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(result["public"], hex(&public));
    let sig = result["signature"].as_str().unwrap();
    assert_eq!(sig.len(), 128);
    let bytes: Vec<_> = (0..64)
        .map(|i| u8::from_str_radix(&sig[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    UnparsedPublicKey::new(&ED25519, public)
        .verify(
            &transcript(public).bytes(Direction::SourceToTarget).unwrap(),
            &bytes,
        )
        .unwrap();
    no_pending(&path);
}
#[cfg(windows)]
#[test]
fn native_current_user_dpapi_reopens_without_external_key() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = IdentityStore::create(
        &path,
        Protection::windows_current_user().unwrap(),
        fleet(),
        "node-A",
    )
    .unwrap();
    let key = s.create_identity().unwrap().public();
    let bytes = fs::read(path.join("identity.fid")).unwrap();
    drop(s);
    let reopened = IdentityStore::open(
        &path,
        Protection::windows_current_user().unwrap(),
        fleet(),
        "node-A",
    )
    .unwrap();
    assert_eq!(reopened.load_identity().unwrap().public(), key);
    assert_eq!(fs::read(path.join("identity.fid")).unwrap(), bytes);
    assert!(open(&path).load_identity().is_err());
}
#[cfg(windows)]
#[test]
fn native_dpapi_wrong_entropy_and_tampering_fail_without_recreation() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = IdentityStore::create(
        &path,
        Protection::windows_current_user().unwrap(),
        fleet(),
        "node-A",
    )
    .unwrap();
    let public = s.create_identity().unwrap().public();
    assert!(
        IdentityStore::open(
            &path,
            Protection::windows_current_user().unwrap(),
            fleet(),
            "node-C"
        )
        .unwrap()
        .load_identity()
        .is_err()
    );
    let name = path.join("identity.fid");
    let before = fs::read(&name).unwrap();
    let mut bad = before.clone();
    let i = bad.len() / 2;
    bad[i] ^= 1;
    replace(&name, &bad);
    assert!(s.load_identity().is_err());
    assert!(s.create_identity().is_err());
    assert_eq!(fs::read(&name).unwrap(), bad);
    replace(&name, &before);
    assert_eq!(s.load_identity().unwrap().public(), public);
}
#[cfg(windows)]
#[test]
fn native_broadened_owner_acl_is_refused_and_original_descriptor_restored() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = IdentityStore::create(
        &path,
        Protection::windows_current_user().unwrap(),
        fleet(),
        "node-A",
    )
    .unwrap();
    let public = s.create_identity().unwrap().public();
    let name = path.join("identity.fid");
    let before = fs::read(&name).unwrap();
    let file = open_private(&name, false).unwrap();
    super::super::identity_windows::test_world_read_then_restore(&name, &file, || {
        assert!(s.load_identity().is_err());
    })
    .unwrap();
    assert_eq!(s.load_identity().unwrap().public(), public);
    super::super::identity_windows::test_world_read_then_restore(&path, &s.directory, || {
        assert!(s.load_identity().is_err());
    })
    .unwrap();
    assert_eq!(s.load_identity().unwrap().public(), public);
    assert_eq!(fs::read(&name).unwrap(), before);
}

#[cfg(windows)]
#[test]
fn native_junction_leaf_is_refused_and_target_identity_remains_unchanged() {
    use base64::Engine;
    use std::os::windows::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("real");
    let s = IdentityStore::create(
        &target,
        Protection::windows_current_user().unwrap(),
        fleet(),
        "node-A",
    )
    .unwrap();
    let public = s.create_identity().unwrap().public();
    let before = fs::read(target.join("identity.fid")).unwrap();
    let link = tmp.path().join("junction");
    let script = "$ErrorActionPreference='Stop';New-Item -ItemType Junction -Path $env:FERROC_IDENTITY_JUNCTION -Target $env:FERROC_IDENTITY_TARGET -ErrorAction Stop | Out-Null";
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let exe = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"))
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut log = tempfile::tempfile().unwrap();
    let mut child = Command::new(exe)
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .env("FERROC_IDENTITY_JUNCTION", &link)
        .env("FERROC_IDENTITY_TARGET", &target)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("junction helper timeout; terminated and reaped");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    use std::io::{Seek, SeekFrom};
    log.seek(SeekFrom::Start(0)).unwrap();
    let mut output = String::new();
    Read::by_ref(&mut log)
        .take(65537)
        .read_to_string(&mut output)
        .unwrap();
    assert!(output.len() <= 65536);
    assert!(status.success(), "{output}");
    assert_ne!(
        fs::symlink_metadata(&link).unwrap().file_attributes() & 0x400,
        0
    );
    let error = IdentityStore::open(
        &link,
        Protection::windows_current_user().unwrap(),
        fleet(),
        "node-A",
    )
    .err()
    .expect("junction must fail closed");
    assert!(error.to_string().contains("reparse point"), "{error}");
    fs::remove_dir(&link).unwrap();
    assert!(!link.exists());
    assert_eq!(s.load_identity().unwrap().public(), public);
    assert_eq!(fs::read(target.join("identity.fid")).unwrap(), before);
}
#[test]
fn persisted_identity_and_explicit_pins_authenticate_real_dual_signed_data_roundtrip() {
    use super::super::{
        auth::{EphemeralKey, PeerRecord},
        identity::fingerprint,
        job::{FileGrant, JobSpec, Permission, RoutePolicy},
        lease::{ClockSample, TrustedTimeAnchor},
    };
    let tmp = tempfile::tempdir().unwrap();
    let a_path = tmp.path().join("a");
    let b_path = tmp.path().join("b");
    let a = IdentityStore::create(&a_path, native_or_external(), fleet(), "node-A").unwrap();
    let b = IdentityStore::create(&b_path, native_or_external(), fleet(), "node-B").unwrap();
    let ap = a.create_identity().unwrap().public();
    let bp = b.create_identity().unwrap().public();
    a.approve_new_pin(
        PeerApproval::verify(
            fleet(),
            "node-B",
            bp,
            &fingerprint(fleet(), "node-B", bp).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    b.approve_new_pin(
        PeerApproval::verify(
            fleet(),
            "node-A",
            ap,
            &fingerprint(fleet(), "node-A", ap).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    drop(a);
    drop(b);
    let a = IdentityStore::open(&a_path, native_or_external(), fleet(), "node-A").unwrap();
    let b = IdentityStore::open(&b_path, native_or_external(), fleet(), "node-B").unwrap();
    let source_key = a.load_identity().unwrap();
    let target_key = b.load_identity().unwrap();
    let source_pin = b.load_pin("node-A").unwrap();
    let target_pin = a.load_pin("node-B").unwrap();
    let binding = transcript(ap).binding;
    let job = JobSpec {
        version: crate::fleet::job::JOB_VERSION,
        fleet_id: fleet(),
        source_device: binding.source_device,
        target_device: binding.target_device,
        transfer_id: binding.transfer_id,
        file_id: binding.file_id,
        source_path: "/source/a.bin".into(),
        destination_path: "/target/a.bin".into(),
        bytes_total: 3,
        sha256: Sha256::digest(b"abc").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 5000,
        idempotency_key: "persisted-pins".into(),
    };
    let grant = FileGrant {
        binding,
        job_digest: job.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 3,
        issued_at_ms: 100,
        expires_at_ms: 1000,
    }
    .validate_for(job)
    .unwrap();
    let se = EphemeralKey::generate();
    let te = EphemeralKey::generate();
    let t = Transcript::for_grant(
        &grant,
        source_key.public(),
        target_key.public(),
        se.public(),
        te.public(),
    );
    let ss = source_key.sign(&t, Direction::SourceToTarget).unwrap();
    let ts = target_key.sign(&t, Direction::TargetToSource).unwrap();
    let sample = ClockSample::now();
    let mut sender = se
        .authenticate_leased(
            &t,
            Direction::SourceToTarget,
            &grant,
            &source_pin,
            &target_pin,
            &ss,
            &ts,
            TrustedTimeAnchor::approved_window(sample, 200, 201).unwrap(),
        )
        .unwrap();
    let mut target = te
        .authenticate_leased(
            &t,
            Direction::TargetToSource,
            &grant,
            &source_pin,
            &target_pin,
            &ss,
            &ts,
            TrustedTimeAnchor::approved_window(sample, 200, 201).unwrap(),
        )
        .unwrap();
    let bytes = sender.seal_data(0, b"abc").unwrap();
    match target.open_record(&bytes).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&*bytes, b"abc"),
        _ => panic!("authenticated DATA"),
    };
    // Local persisted identities/pins + actual crypto. No sockets, fleet service,
    // authority clock provider or durable transfer-journal truth is implied.
}

#[cfg(unix)]
#[test]
fn unix_permissions_symlink_and_directory_replacement_fail_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store");
    let s = create(&path);
    let public = s.create_identity().unwrap().public();
    let file = path.join("identity.fid");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(s.load_identity().is_err());
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o644
    );
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(s.load_identity().is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(s.load_identity().unwrap().public(), public);
    let link = tmp.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(IdentityStore::open(&link, protection(), fleet(), "node-A").is_err());
    let old = tmp.path().join("old");
    fs::rename(&path, &old).unwrap();
    drop(create(&path));
    assert!(s.load_identity().is_err());
    assert!(Protection::windows_current_user().is_err());
}
