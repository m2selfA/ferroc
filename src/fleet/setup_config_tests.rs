use super::*;
use crate::fleet::{
    identity::{PeerApproval, Protection},
    job::JOB_VERSION,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
fn wrap() -> Protection {
    // Exactly the bytes the 64-hex environment value encodes.
    let hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut key = Zeroizing::new([0u8; 32]);
    for (i, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(std::str::from_utf8(&hex[i * 2..i * 2 + 2]).unwrap(), 16).unwrap();
    }
    Protection::supplied_key(key).unwrap()
}
struct F {
    _root: tempfile::TempDir,
    path: PathBuf,
    value: Value,
}
fn fixture() -> F {
    let root = tempfile::tempdir().unwrap();
    let fleet = Uuid::new_v4();
    let a = IdentityStore::create(&root.path().join("a"), wrap(), fleet, "dev-a").unwrap();
    let b = IdentityStore::create(&root.path().join("b"), wrap(), fleet, "dev-b").unwrap();
    let (_fa, fb) = {
        let ka = a.create_identity().unwrap();
        let kb = b.create_identity().unwrap();
        let fa = a.local_fingerprint().unwrap();
        let fb = b.local_fingerprint().unwrap();
        a.enroll_peer(
            PeerApproval::verify(fleet, "dev-b", kb.public(), &fb).unwrap(),
            "peer-b",
            1,
        )
        .unwrap();
        b.enroll_peer(
            PeerApproval::verify(fleet, "dev-a", ka.public(), &fa).unwrap(),
            "peer-a",
            1,
        )
        .unwrap();
        (fa, fb)
    };
    a.set_peer_endpoint("dev-b", EndpointSlot::Primary, "https://relay.example", &fb)
        .unwrap();
    std::fs::write(root.path().join("s.bin"), b"abc").unwrap();
    let job = json!({"version":JOB_VERSION,"fleetId":fleet,"sourceDevice":crate::fleet::protocol::device_digest("dev-a").unwrap(),"targetDevice":crate::fleet::protocol::device_digest("dev-b").unwrap(),"transferId":Uuid::new_v4(),"fileId":Uuid::new_v4(),"sourcePath":root.path().join("s.bin").to_str().unwrap(),"destinationPath":root.path().join("d.bin").to_str().unwrap(),"bytesTotal":3,"sha256":Sha256::digest(b"abc").to_vec(),"overwrite":false,"route":"relayOnly","deadlineMs":(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64)+900000,"idempotencyKey":"cfg-test"});
    let value = json!({"version":2,"identityStore":root.path().join("a"),"fleet":fleet,"device":"dev-a","protection":{"kind":"suppliedKeyEnv","name":"FERROC_TEST_WRAP"},"peer":{"device":"dev-b","fingerprint":fb.hex(),"slot":"primary","profile":"singleOwner"},"rounds":[{"id":Uuid::new_v4(),"role":"source","job":job,"sourceSession":Uuid::new_v4(),"targetSession":Uuid::new_v4(),"chunkBytes":65536,"leaseMs":120000,"issuedAtMs":(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64),"authorizationId":Uuid::new_v4(),"keyEpoch":Uuid::new_v4()}]});
    let path = root.path().join("setup.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    F {
        _root: root,
        path,
        value,
    }
}
fn write(f: &F, v: &Value) {
    std::fs::write(&f.path, serde_json::to_vec(v).unwrap()).unwrap()
}
fn with_env<T>(body: impl FnOnce() -> T) -> T {
    // The process environment is shared by Rust's parallel test workers. Serialize
    // every fixture that temporarily installs the public wrapping key; otherwise
    // another setup_config test can remove it while this one is loading a file.
    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = ENV_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("setup test environment lock");
    // PUBLIC test material, 64 hex characters encoding 32 bytes; never production.
    unsafe {
        std::env::set_var(
            "FERROC_TEST_WRAP",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    };
    let out = body();
    unsafe { std::env::remove_var("FERROC_TEST_WRAP") };
    out
}
fn local_recovery_fixture(f: &F) -> (Value, RecoveryPlan, ValidatedGrant) {
    let old: RoundFile = serde_json::from_value(f.value["rounds"][0].clone()).unwrap();
    let old_grant = old.materialize(LeaseProfile::SingleOwner).unwrap();
    let checkpoint=serde_json::from_value(json!({"version":1,"bytes":3,"sha256":Sha256::digest(b"abc").to_vec(),
        "job_digest":old_grant.job().digest().unwrap(),"grant_digest":old_grant.digest(),"binding":old_grant.grant().binding,"revision":3})).unwrap();
    let mut v = f.value.clone();
    let rnd = &mut v["rounds"][0];
    rnd["job"]["transferId"] = json!(Uuid::new_v4());
    rnd["job"]["fileId"] = json!(Uuid::new_v4());
    rnd["job"]["idempotencyKey"] = json!("new-recovery-job");
    for key in [
        "sourceSession",
        "targetSession",
        "authorizationId",
        "keyEpoch",
    ] {
        rnd[key] = json!(Uuid::new_v4());
    }
    rnd["issuedAtMs"] = json!(
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
            - 1000
    );
    let next: RoundFile = serde_json::from_value(rnd.clone()).unwrap();
    let next = next.materialize(LeaseProfile::SingleOwner).unwrap();
    (
        v,
        RecoveryPlan {
            old_job: old_grant.job().clone(),
            checkpoint,
            stopped_owner: None,
            revision: None,
            max_prefix_bytes: 3,
        },
        next,
    )
}
#[test]
fn recovery_selection_is_local_bounded_and_role_specific() {
    let f = fixture();
    let (_, mut recovery, next) = local_recovery_fixture(&f);
    assert!(recovery.validate(RoleFile::Source, &next).is_ok());
    assert!(recovery.validate(RoleFile::Target, &next).is_err());
    recovery.stopped_owner = Some(Uuid::new_v4());
    recovery.revision = Some(4);
    assert!(recovery.validate(RoleFile::Target, &next).is_ok());
    assert!(recovery.validate(RoleFile::Source, &next).is_err());
    recovery.max_prefix_bytes = 2;
    assert!(recovery.validate(RoleFile::Target, &next).is_err());
    recovery.max_prefix_bytes = (1u64 << 30) + 1;
    assert!(recovery.validate(RoleFile::Target, &next).is_err());
}
#[test]
fn recovery_config_requires_explicit_transfer_and_rejects_mcp_shortcut() {
    let f = fixture();
    let (mut v, recovery, _) = local_recovery_fixture(&f);
    v["rounds"][0]["recovery"] =
        json!({"oldJob":recovery.old_job,"checkpoint":recovery.checkpoint,"maxPrefixBytes":3});
    with_env(|| {
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a")
                .err()
                .unwrap()
                .to_string()
                .contains("explicit transfer")
        );
        v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":1});
        v["dataRoutes"] = json!(true);
        v["transfer"] = json!({"windowChunks":4,"mcp":true});
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        v["transfer"]["mcp"] = json!(false);
        write(&f, &v);
        let provision = SetupProvision::load(&f.path, "dev-a").unwrap();
        assert!(
            provision
                .recovery(serde_json::from_value(v["rounds"][0]["id"].clone()).unwrap())
                .is_some()
        );
    });
}
#[test]
fn checkpoint_opt_in_refuses_source_only_and_anonymous_modes() {
    let f = fixture();
    let mut v = f.value.clone();
    v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":1});
    v["dataRoutes"] = json!(true);
    v["transfer"] = json!({"windowChunks":4,"retainedCheckpointBytes":65536});
    with_env(|| {
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
    });
}
#[test]
fn explicit_chunk_capacity_reuses_the_protocol_ceiling_and_binds_the_grant() {
    let f = fixture();
    with_env(|| {
        let original = SetupProvision::load(&f.path, "dev-a")
            .unwrap()
            .rounds()
            .unwrap()
            .remove(0)
            .2
            .proposal;
        assert_eq!(original.grant().chunk_bytes, 65536);
        for chunk in [65536, 65537, crate::fleet::protocol::MAX_DATA as u32] {
            let mut value = f.value.clone();
            value["rounds"][0]["chunkBytes"] = json!(chunk);
            write(&f, &value);
            let provision =
                SetupProvision::load(&f.path, "dev-a").expect("explicit protocol-valid chunk");
            let grant = provision.rounds().unwrap().remove(0).2.proposal;
            assert_eq!(grant.grant().chunk_bytes, chunk);
            assert_eq!(
                grant.job().digest().unwrap(),
                original.job().digest().unwrap()
            );
            if chunk == 65536 {
                assert_eq!(grant.digest(), original.digest());
            } else {
                assert_ne!(
                    grant.digest(),
                    original.digest(),
                    "chunk is authenticated grant authority"
                );
            }
        }
        for chunk in [0, crate::fleet::protocol::MAX_DATA as u32 + 1] {
            let mut value = f.value.clone();
            value["rounds"][0]["chunkBytes"] = json!(chunk);
            write(&f, &value);
            assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        }
    });
}

#[test]
fn configured_round_must_preserve_the_same_locally_approved_grant() {
    let f = fixture();
    with_env(|| {
        let p = SetupProvision::load(&f.path, "dev-a").unwrap();
        let first = p.rounds().unwrap().remove(0).2;
        let second = p.rounds().unwrap().remove(0).2;
        assert_eq!(
            first.proposal.digest(),
            second.proposal.digest(),
            "reloading an approved round must not generate a new grant"
        );
    });
}
#[test]
fn valid_config_loads_and_builds_a_locally_approved_round() {
    let f = fixture();
    with_env(|| {
        let p = SetupProvision::load(&f.path, "dev-a").expect("valid config");
        let rounds = p.rounds().expect("grants");
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].1, RoleFile::Source);
        let approval = &rounds[0].2;
        assert_eq!(approval.peer.device, "dev-b");
        assert!(approval.proposal.job().deadline_ms > 0);
        assert!((approval.now)().expect("local time") > 0);
    });
}
#[test]
fn fixed_grant_rejects_legacy_future_expired_nil_and_overflow() {
    let f = fixture();
    with_env(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut v = f.value.clone();
        v["version"] = json!(1);
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        for issued in [now - 130000, now + 300000] {
            let mut v = f.value.clone();
            v["rounds"][0]["issuedAtMs"] = json!(issued);
            write(&f, &v);
            let p = SetupProvision::load(&f.path, "dev-a").unwrap();
            assert!(p.rounds().is_err(), "must not shift time to revive a grant");
        }
        for field in ["authorizationId", "keyEpoch"] {
            let mut v = f.value.clone();
            v["rounds"][0][field] = json!(Uuid::nil());
            write(&f, &v);
            assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        }
        let mut v = f.value.clone();
        v["rounds"][0]["issuedAtMs"] = json!(u64::MAX);
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
    });
}
#[test]
fn lease_authority_is_explicit_bounded_and_single_owner_only() {
    let f = fixture();
    with_env(|| {
        assert!(
            !SetupProvision::load(&f.path, "dev-a")
                .unwrap()
                .lease_requested()
        );
        let mut v = f.value.clone();
        v["rounds"][0]["issuedAtMs"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                - 5000
        );
        v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100});
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a")
                .unwrap()
                .lease_requested()
        );
        for bad in [
            json!({"kind":"singleOwnerSystemClock","uncertaintyMs":0}),
            json!({"kind":"singleOwnerSystemClock","uncertaintyMs":2001}),
            json!({"kind":"peerClock","uncertaintyMs":100}),
            json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100,"earliestMs":1}),
        ] {
            let mut bad_config = v.clone();
            bad_config["leaseAuthority"] = bad;
            write(&f, &bad_config);
            assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        }
        v["peer"]["profile"] = json!("rotating");
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
    });
}
#[test]
fn configured_local_lease_requires_separate_authority_then_real_proofs() {
    use crate::{config::Policy, fleet::setup::SetupPeer, runtime::Runtime};
    let f = fixture();
    with_env(|| {
        let mut v = f.value.clone();
        v["rounds"][0]["issuedAtMs"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                - 5000
        );
        for enabled in [false, true] {
            if enabled {
                v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100});
            }
            write(&f, &v);
            let p = SetupProvision::load(&f.path, "dev-a").unwrap();
            let (id, _, local) = p.rounds().unwrap().remove(0);
            let runtime = Arc::new(Runtime::new(
                Policy::new(vec![f._root.path().to_owned()], false).unwrap(),
            ));
            let b = IdentityStore::open(
                &f._root.path().join("b"),
                wrap(),
                local.proposal.job().fleet_id,
                "dev-b",
            )
            .unwrap();
            let af = p.store.local_fingerprint().unwrap();
            b.set_peer_endpoint("dev-a", EndpointSlot::Primary, "https://relay.example", &af)
                .unwrap();
            let now = (local.now)().unwrap();
            let (a, offer) = runtime
                .begin_fleet_setup(
                    &p.store,
                    &local.proposal,
                    SetupPeer {
                        device: "dev-b",
                        expected_fingerprint: &p.peer.fingerprint,
                        endpoint_slot: EndpointSlot::Primary,
                        profile: LeaseProfile::SingleOwner,
                    },
                    now,
                )
                .unwrap();
            let (b, response) = runtime
                .accept_fleet_setup(
                    &b,
                    &local.proposal,
                    SetupPeer {
                        device: "dev-a",
                        expected_fingerprint: &af,
                        endpoint_slot: EndpointSlot::Primary,
                        profile: LeaseProfile::SingleOwner,
                    },
                    offer,
                    now,
                )
                .unwrap();
            let (proof, confirmation) = a.confirm(response, (local.now)().unwrap()).unwrap();
            let _other = b.finish(confirmation, (local.now)().unwrap()).unwrap();
            let owner = p.authenticate_prepared(&runtime, id, proof);
            if enabled {
                owner.unwrap().check_active().unwrap();
            } else {
                assert!(owner.is_err());
            }
        }
    });
}

#[test]
fn device_fleet_peer_slot_profile_and_route_mismatches_are_refused() {
    let f = fixture();
    with_env(|| {
        assert!(
            SetupProvision::load(&f.path, "dev-z").is_err(),
            "device mismatch"
        );
        let mut v = f.value.clone();
        v["peer"]["fingerprint"] = json!("11".repeat(32));
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "fingerprint mismatch"
        );
        let mut v = f.value.clone();
        v["peer"]["device"] = json!("dev-c");
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "unenrolled peer"
        );
        let mut v = f.value.clone();
        v["peer"]["slot"] = json!("fallback");
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "missing endpoint slot"
        );
        let mut v = f.value.clone();
        v["fleet"] = json!(Uuid::new_v4());
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "fleet mismatch"
        );
        let mut v = f.value.clone();
        v["rounds"][0]["role"] = json!("target");
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "role/device mismatch"
        );
        let mut v = f.value.clone();
        v["rounds"][0]["job"]["route"] = json!("directQuic");
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "unknown route"
        );
    });
}
#[test]
fn duplicate_jobs_round_bounds_unknown_fields_and_oversize_are_refused() {
    let f = fixture();
    with_env(|| {
        let mut v = f.value.clone();
        let same = v["rounds"][0].clone();
        v["rounds"] = json!([same.clone(), same]);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "duplicate job digest"
        );
        let mut v = f.value.clone();
        v["rounds"] = json!([]);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "empty rounds"
        );
        let mut v = f.value.clone();
        let mut extra = Vec::new();
        for i in 0..5 {
            let mut r = f.value["rounds"][0].clone();
            r["id"] = json!(Uuid::new_v4());
            r["job"]["fileId"] = json!(Uuid::new_v4());
            r["job"]["transferId"] = json!(Uuid::new_v4());
            r["job"]["idempotencyKey"] = json!(format!("k{i}"));
            extra.push(r)
        }
        v["rounds"] = json!(extra);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "too many rounds"
        );
        let mut v = f.value.clone();
        v["extra"] = json!(1);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "unknown field"
        );
        let mut v = f.value.clone();
        v["rounds"][0]["chunkBytes"] = json!(crate::fleet::protocol::MAX_DATA + 1);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "chunk too large"
        );
        let big = vec![b' '; 70 * 1024];
        std::fs::write(&f.path, &big).unwrap();
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "oversize config"
        );
    });
}
#[test]
fn data_route_configuration_is_explicit_and_requires_local_lease_authority() {
    let f = fixture();
    with_env(|| {
        let mut v = f.value.clone();
        v["dataRoutes"] = json!(true);
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        v["rounds"][0]["issuedAtMs"] = json!(v["rounds"][0]["issuedAtMs"].as_u64().unwrap() - 5000);
        v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100});
        write(&f, &v);
        let p = SetupProvision::load(&f.path, "dev-a").unwrap();
        assert!(p.data_routes_requested());
        let mut t = f.value.clone();
        t["transfer"] = json!({"windowChunks":4,"hostDb":"/tmp/host.db"});
        write(&f, &t);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "transfer without DATA routes refused"
        );
        t["dataRoutes"] = json!(true);
        write(&f, &t);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "near-expiry transfer refused by clock"
        );
        let mut z = t.clone();
        z["transfer"]["windowChunks"] = json!(9);
        write(&f, &z);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "window bound"
        );
        z["transfer"]["windowChunks"] = json!(4);
        z["transfer"]["hostDb"] = json!("relative.db");
        write(&f, &z);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "host db must be absolute"
        );
        z["transfer"]["hostDb"] = json!(f._root.path().join("host.db"));
        z["rounds"][0]["issuedAtMs"] = json!(z["rounds"][0]["issuedAtMs"].as_u64().unwrap() - 5000);
        z["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100});
        write(&f, &z);
        assert!(
            SetupProvision::load(&f.path, "dev-a")
                .unwrap()
                .transfer()
                .is_some(),
            "explicit local transfer config accepted"
        );
        assert!(p.validate_route_origin("https://relay.example/").is_ok());
        assert!(p.validate_route_origin("https://other.invalid").is_err());
        assert!(
            p.validate_route_origin("https://relay.example/subpath")
                .is_err()
        );
        v["dataRoutes"] = json!(false);
        v.as_object_mut().unwrap().remove("leaseAuthority");
        write(&f, &v);
        assert!(
            !SetupProvision::load(&f.path, "dev-a")
                .unwrap()
                .data_routes_requested()
        );
    });
}
#[test]
fn anonymous_stage_config_never_grants_source_or_foreign_platform_capability() {
    let f = fixture();
    with_env(|| {
        let mut v = f.value.clone();
        v["dataRoutes"] = json!(true);
        v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100});
        v["rounds"][0]["issuedAtMs"] = json!(v["rounds"][0]["issuedAtMs"].as_u64().unwrap() - 5000);
        v["transfer"] = json!({"windowChunks":4});
        write(&f, &v);
        assert!(
            !SetupProvision::load(&f.path, "dev-a")
                .unwrap()
                .transfer()
                .unwrap()
                .linux_anonymous_stage()
        );
        v["transfer"]["linuxAnonymousStage"] = json!(true);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "source cannot request anonymous target capability"
        );
    });
}
#[cfg(target_os = "linux")]
#[test]
fn linux_target_requires_explicit_anonymous_stage_and_rejects_replace() {
    let f = fixture();
    with_env(|| {
        let mut v = f.value.clone();
        v["dataRoutes"] = json!(true);
        v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100});
        v["rounds"][0]["issuedAtMs"] = json!(v["rounds"][0]["issuedAtMs"].as_u64().unwrap() - 5000);
        v["rounds"][0]["role"] = json!("target");
        v["rounds"][0]["job"]["sourceDevice"] =
            json!(crate::fleet::protocol::device_digest("dev-b").unwrap());
        v["rounds"][0]["job"]["targetDevice"] =
            json!(crate::fleet::protocol::device_digest("dev-a").unwrap());
        v["transfer"] = json!({"windowChunks":4,"hostDb":f._root.path().join("host.db")});
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        v["transfer"]["linuxAnonymousStage"] = json!(true);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a")
                .unwrap()
                .transfer()
                .unwrap()
                .linux_anonymous_stage()
        );
        // A replacement round is accepted ONLY together with its pre-image.
        v["rounds"][0]["job"]["overwrite"] = json!(true);
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "anonymous replacement without a pre-image must be refused"
        );
        v["rounds"][0]["job"]["preImageSha256"] = json!(vec![9; 32]);
        write(&f, &v);
        let loaded = SetupProvision::load(&f.path, "dev-a").unwrap();
        assert!(
            loaded.transfer().unwrap().linux_anonymous_stage(),
            "explicit anonymous replacement should provision"
        );
        drop(loaded);
        // The no-clobber permission and the replacement permission stay distinct:
        // dropping the pre-image again is refused even though overwrite is set.
        v["rounds"][0]["job"]["preImageSha256"] = json!(null);
        write(&f, &v);
        assert!(SetupProvision::load(&f.path, "dev-a").is_err());
    });
}

#[test]
fn wrong_or_absent_wrapping_key_never_falls_back_to_plaintext() {
    let f = fixture();
    unsafe { std::env::remove_var("FERROC_TEST_WRAP") };
    assert!(
        SetupProvision::load(&f.path, "dev-a").is_err(),
        "absent key must fail"
    );
    unsafe { std::env::set_var("FERROC_TEST_WRAP", "short") };
    assert!(
        SetupProvision::load(&f.path, "dev-a").is_err(),
        "short key must fail"
    );
    unsafe { std::env::remove_var("FERROC_TEST_WRAP") };
}

#[cfg(any(windows, target_os = "linux"))]
#[test]
fn parent_creation_config_is_target_only_scoped_and_has_no_load_side_effects() {
    let f = fixture();
    let root = f._root.path().join("target");
    crate::fleet::identity::make_directory(&root).unwrap();
    with_env(|| {
        let mut v = f.value.clone();
        v["dataRoutes"] = json!(true);
        v["leaseAuthority"] = json!({"kind":"singleOwnerSystemClock","uncertaintyMs":100});
        v["rounds"][0]["issuedAtMs"] = json!(v["rounds"][0]["issuedAtMs"].as_u64().unwrap() - 5000);
        v["transfer"] =
            json!({"windowChunks":4,"hostDb":root.join("host.db"),"createParentsBelow":root});
        write(&f, &v);
        assert!(
            SetupProvision::load(&f.path, "dev-a").is_err(),
            "source cannot opt into target mkdir"
        );
        v["rounds"][0]["role"] = json!("target");
        let source = v["rounds"][0]["job"]["sourceDevice"].clone();
        v["rounds"][0]["job"]["sourceDevice"] = v["rounds"][0]["job"]["targetDevice"].clone();
        v["rounds"][0]["job"]["targetDevice"] = source;
        v["rounds"][0]["job"]["destinationPath"] = json!(root.join("new/deep/a.bin"));
        #[cfg(target_os = "linux")]
        {
            v["transfer"]["linuxAnonymousStage"] = json!(true);
        }
        write(&f, &v);
        let loaded = SetupProvision::load(&f.path, "dev-a").unwrap();
        assert_eq!(
            loaded.transfer().unwrap().create_parents_below(),
            Some(root.as_path())
        );
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            0,
            "loading is not mkdir"
        );
        for destination in [
            root.join("../escape/a"),
            root.join("new/CON/a"),
            f._root.path().join("outside/a"),
        ] {
            let mut bad = v.clone();
            bad["rounds"][0]["job"]["destinationPath"] = json!(destination);
            write(&f, &bad);
            assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        }
        for badroot in [PathBuf::from("relative"), root.join("missing")] {
            let mut bad = v.clone();
            bad["transfer"]["createParentsBelow"] = json!(badroot);
            write(&f, &bad);
            assert!(SetupProvision::load(&f.path, "dev-a").is_err());
        }
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    });
}
