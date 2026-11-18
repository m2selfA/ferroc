use super::*;
use crate::fleet::job::{FileGrant, Permission};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::json;
use uuid::Uuid;
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn fixture() -> (JobSpec, PrefixCheckpoint, ValidatedGrant) {
    let old = JobSpec {
        version: 2,
        fleet_id: id(1),
        source_device: [1; 32],
        target_device: [2; 32],
        transfer_id: id(2),
        file_id: id(3),
        source_path: "C:/source/input.bin".into(),
        destination_path: "C:/target/output.bin".into(),
        bytes_total: 8,
        sha256: Sha256::digest(b"abcdefgh").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: crate::fleet::job::RoutePolicy::RelayOnly,
        deadline_ms: 900,
        idempotency_key: "old-attempt".into(),
    };
    let b = Binding {
        fleet_id: old.fleet_id,
        source_device: old.source_device,
        target_device: old.target_device,
        source_session: id(4),
        target_session: id(5),
        transfer_id: old.transfer_id,
        file_id: old.file_id,
        authorization_id: id(6),
        key_epoch: id(7),
    };
    let old_grant = FileGrant {
        binding: b.clone(),
        job_digest: old.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 65536,
        issued_at_ms: 1,
        expires_at_ms: 900,
    }
    .validate_for(old.clone())
    .unwrap();
    let cp=serde_json::from_value(json!({"version":1,"bytes":3,"sha256":<[u8;32]>::from(Sha256::digest(b"abc")),"job_digest":old.digest().unwrap(),"grant_digest":old_grant.digest(),"binding":b,"revision":3})).unwrap();
    let mut new = old.clone();
    new.transfer_id = id(20);
    new.file_id = id(21);
    new.idempotency_key = "new-explicit-attempt".into();
    new.deadline_ms = 10000;
    let mut binding = old_grant.grant().binding.clone();
    binding.transfer_id = new.transfer_id;
    binding.file_id = new.file_id;
    binding.source_session = id(22);
    binding.target_session = id(23);
    binding.authorization_id = id(24);
    binding.key_epoch = id(25);
    let g = FileGrant {
        binding,
        job_digest: new.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 65536,
        issued_at_ms: 1000,
        expires_at_ms: 10000,
    }
    .validate_for_profile(new, LeaseProfile::SingleOwner)
    .unwrap();
    (old, cp, g)
}
fn regrant(g: &ValidatedGrant, job: JobSpec, b: Binding) -> ValidatedGrant {
    let mut f = g.grant().clone();
    f.binding = b;
    f.job_digest = job.digest().unwrap();
    f.permission = if job.overwrite {
        Permission::ReplaceExistingFile
    } else {
        Permission::SendFileNoClobber
    };
    f.validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap()
}
fn transcript(g: &ValidatedGrant) -> Transcript {
    let a = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let b = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
    Transcript::for_grant(
        g,
        a.public_key().as_ref().try_into().unwrap(),
        b.public_key().as_ref().try_into().unwrap(),
        [11; 32],
        [12; 32],
    )
}
#[test]
fn fresh_job_can_propose_same_prefix_after_old_deadline_without_mutating_old() {
    let (old, cp, g) = fixture();
    let before = old.canonical_bytes().unwrap();
    let p = ResumeProposal::build(&old, &cp, &g).unwrap();
    assert_eq!(p.prefix_bytes(), 3);
    assert_eq!(
        p.digest(),
        <[u8; 32]>::from(Sha256::digest(p.canonical_bytes()))
    );
    assert_eq!(old.canonical_bytes().unwrap(), before);
    assert!(g.grant().issued_at_ms > old.deadline_ms);
}
#[test]
fn ordinary_old_job_cannot_relabel_itself_as_resume() {
    let (old, cp, g) = fixture();
    for n in 0..3 {
        let mut job = g.job().clone();
        if n == 0 {
            job.transfer_id = old.transfer_id
        } else if n == 1 {
            job.file_id = old.file_id
        } else {
            job.idempotency_key = old.idempotency_key.clone()
        };
        let mut b = g.grant().binding.clone();
        b.transfer_id = job.transfer_id;
        b.file_id = job.file_id;
        let next = regrant(&g, job, b);
        assert!(ResumeProposal::build(&old, &cp, &next).is_err());
    }
}
#[test]
fn immutable_paths_content_devices_mode_and_preimage_cannot_change() {
    let (old, cp, g) = fixture();
    for n in 0..8 {
        let mut job = g.job().clone();
        match n {
            0 => job.source_path = "C:/other/input.bin".into(),
            1 => job.destination_path = "C:/other/output.bin".into(),
            2 => job.bytes_total += 1,
            3 => job.sha256[0] ^= 1,
            4 => job.source_device[0] ^= 1,
            5 => job.target_device[0] ^= 1,
            6 => job.fleet_id = id(30),
            _ => {
                job.overwrite = true;
                job.pre_image_sha256 = Some([9; 32]);
            }
        }
        let mut b = g.grant().binding.clone();
        b.fleet_id = job.fleet_id;
        b.source_device = job.source_device;
        b.target_device = job.target_device;
        let next = regrant(&g, job, b);
        assert!(
            ResumeProposal::build(&old, &cp, &next).is_err(),
            "mutation {n}"
        );
    }
    let mut replace_old = old.clone();
    replace_old.overwrite = true;
    replace_old.pre_image_sha256 = Some([9; 32]);
    let mut v = serde_json::to_value(&cp).unwrap();
    v["job_digest"] = json!(replace_old.digest().unwrap());
    let cp2: PrefixCheckpoint = serde_json::from_value(v).unwrap();
    let mut new = g.job().clone();
    new.overwrite = true;
    new.pre_image_sha256 = Some([10; 32]);
    let next = regrant(&g, new, g.grant().binding.clone());
    assert!(ResumeProposal::build(&replace_old, &cp2, &next).is_err());
}
#[test]
fn reused_epoch_authorization_or_any_old_session_is_rejected() {
    let (old, cp, g) = fixture();
    for n in 0..6 {
        let mut b = g.grant().binding.clone();
        match n {
            0 => b.authorization_id = cp.binding().authorization_id,
            1 => b.key_epoch = cp.binding().key_epoch,
            2 => b.source_session = cp.binding().source_session,
            3 => b.source_session = cp.binding().target_session,
            4 => b.target_session = cp.binding().source_session,
            _ => b.target_session = cp.binding().target_session,
        };
        assert!(ResumeProposal::build(&old, &cp, &regrant(&g, g.job().clone(), b)).is_err());
    }
}
#[test]
fn checkpoint_job_length_binding_and_empty_prefix_are_checked() {
    let (old, cp, g) = fixture();
    for field in ["job_digest", "bytes", "revision", "binding", "empty"] {
        let mut v = serde_json::to_value(&cp).unwrap();
        match field {
            "job_digest" => v[field][0] = json!(0),
            "bytes" => v[field] = json!(9),
            "revision" => v[field] = json!(0),
            "binding" => v[field]["fileId"] = json!(id(99)),
            _ => v["bytes"] = json!(0),
        }
        let changed = serde_json::from_value(v).unwrap();
        assert!(
            ResumeProposal::build(&old, &changed, &g).is_err(),
            "{field}"
        );
    }
}
#[test]
fn explicit_profile_and_distinct_new_sessions_required() {
    let (old, cp, g) = fixture();
    let short = g.grant().clone().validate_for(g.job().clone()).unwrap();
    assert!(ResumeProposal::build(&old, &cp, &short).is_err());
    let mut b = g.grant().binding.clone();
    b.target_session = b.source_session;
    let bad = regrant(&g, g.job().clone(), b);
    assert!(ResumeProposal::build(&old, &cp, &bad).is_err());
}
#[test]
fn changed_checkpoint_sha_or_revision_changes_condition_and_both_proof_domains() {
    let (old, cp, g) = fixture();
    let p = ResumeProposal::build(&old, &cp, &g).unwrap();
    let t = transcript(&g);
    for field in ["sha256", "revision"] {
        let mut v = serde_json::to_value(&cp).unwrap();
        if field == "revision" {
            v[field] = json!(4)
        } else {
            let n = v[field][0].as_u64().unwrap();
            v[field][0] = json!(n ^ 1)
        }
        let cp2 = serde_json::from_value(v).unwrap();
        let q = ResumeProposal::build(&old, &cp2, &g).unwrap();
        assert_ne!(p.digest(), q.digest());
        assert_ne!(
            p.proof_bytes(&g, &t, Direction::SourceToTarget).unwrap(),
            q.proof_bytes(&g, &t, Direction::SourceToTarget).unwrap()
        );
    }
}
#[test]
fn proof_rejects_other_grant_transcript_limits_or_ephemerals() {
    let (old, cp, g) = fixture();
    let p = ResumeProposal::build(&old, &cp, &g).unwrap();
    let original = transcript(&g);
    for n in 0..8 {
        let mut t = original.clone();
        match n {
            0 => t.max_file_bytes += 1,
            1 => t.chunk_bytes /= 2,
            2 => t.issued_at_ms += 1,
            3 => t.expires_at_ms -= 1,
            4 => t.grant_digest[0] ^= 1,
            5 => t.binding.key_epoch = id(99),
            6 => t.source_ephemeral = [0; 32],
            _ => t.target_ephemeral = t.source_ephemeral,
        };
        assert!(
            p.proof_bytes(&g, &t, Direction::SourceToTarget).is_err(),
            "{n}"
        );
    }
    let mut b = g.grant().binding.clone();
    b.key_epoch = id(98);
    let other = regrant(&g, g.job().clone(), b);
    assert!(
        p.proof_bytes(&other, &transcript(&other), Direction::SourceToTarget)
            .is_err()
    );
}
#[test]
fn public_test_signatures_and_independent_oracle_export() {
    let (old, cp, g) = fixture();
    let p = ResumeProposal::build(&old, &cp, &g).unwrap();
    let t = transcript(&g);
    let a = p.proof_bytes(&g, &t, Direction::SourceToTarget).unwrap();
    let b = p.proof_bytes(&g, &t, Direction::TargetToSource).unwrap();
    assert_ne!(a, b);
    let source = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let target = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
    let sa = source.sign(&a);
    let sb = target.sign(&b);
    UnparsedPublicKey::new(&ED25519, source.public_key())
        .verify(&a, sa.as_ref())
        .unwrap();
    assert!(
        UnparsedPublicKey::new(&ED25519, source.public_key())
            .verify(&b, sa.as_ref())
            .is_err()
    );
    assert!(
        UnparsedPublicKey::new(&ED25519, source.public_key())
            .verify(
                &t.bytes_with_profile(Direction::SourceToTarget, LeaseProfile::SingleOwner)
                    .unwrap(),
                sa.as_ref()
            )
            .is_err()
    );
    if let Some(path) = std::env::var_os("FERROC_RESUME_EXPORT") {
        let export = json!({"scope":"PUBLIC synthetic byte-contract fixture, not trusted Runtime approval or leased IO","oldJob":old,"checkpoint":cp,"newJob":g.job(),"newGrant":g.grant(),"newGrantDigest":g.digest(),"transcript":{"binding":t.binding,"jobDigest":t.job_digest,"grantDigest":t.grant_digest,"sourceIdentity":t.source_identity,"targetIdentity":t.target_identity,"sourceEphemeral":t.source_ephemeral,"targetEphemeral":t.target_ephemeral,"maxFileBytes":t.max_file_bytes,"chunkBytes":t.chunk_bytes,"issuedAtMs":t.issued_at_ms,"expiresAtMs":t.expires_at_ms},"conditionBytes":p.canonical_bytes(),"conditionDigest":p.digest(),"sourceProof":a,"targetProof":b,"sourceSignature":sa.as_ref(),"targetSignature":sb.as_ref()});
        std::fs::write(path, serde_json::to_vec_pretty(&export).unwrap()).unwrap();
    }
}
