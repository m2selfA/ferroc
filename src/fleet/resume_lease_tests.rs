use super::*;
use crate::fleet::{
    auth::{IdentityKey, PeerRecord},
    job::{FileGrant, JobSpec, LeaseProfile, Permission, RoutePolicy},
    journal::PrefixCheckpoint,
    lease::ClockSample,
    protocol::{Binding, device_digest},
    resume_condition::SigningMessage,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
struct Fixture {
    old: JobSpec,
    cp: PrefixCheckpoint,
    grant: ValidatedGrant,
    condition: ResumeProposal,
    transcript: Transcript,
    source: EphemeralKey,
    target: EphemeralKey,
    source_identity: IdentityKey,
    target_identity: IdentityKey,
    source_pin: DevicePin,
    target_pin: DevicePin,
    sa: [u8; 64],
    ta: [u8; 64],
    sr: [u8; 64],
    tr: [u8; 64],
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn fixture() -> Fixture {
    let old = JobSpec {
        version: 2,
        fleet_id: id(1),
        source_device: device_digest("source-A").unwrap(),
        target_device: device_digest("target-B").unwrap(),
        transfer_id: id(2),
        file_id: id(3),
        source_path: "C:/unit-source/input.bin".into(),
        destination_path: "C:/unit-target/output.bin".into(),
        bytes_total: 8,
        sha256: Sha256::digest(b"abcdefgh").into(),
        overwrite: false,
        pre_image_sha256: None,
        route: RoutePolicy::RelayOnly,
        deadline_ms: 900,
        idempotency_key: "old-memory-attempt".into(),
    };
    let binding = Binding {
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
        binding: binding.clone(),
        job_digest: old.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 65536,
        issued_at_ms: 1,
        expires_at_ms: 900,
    }
    .validate_for(old.clone())
    .unwrap();
    let cp:PrefixCheckpoint=serde_json::from_value(json!({"version":1,"bytes":3,"sha256":<[u8;32]>::from(Sha256::digest(b"abc")),"job_digest":old.digest().unwrap(),"grant_digest":old_grant.digest(),"binding":binding,"revision":3})).unwrap();
    let mut next = old.clone();
    next.transfer_id = id(20);
    next.file_id = id(21);
    next.idempotency_key = "new-memory-attempt".into();
    next.deadline_ms = 20000;
    let mut b = old_grant.grant().binding.clone();
    b.transfer_id = next.transfer_id;
    b.file_id = next.file_id;
    b.source_session = id(22);
    b.target_session = id(23);
    b.authorization_id = id(24);
    b.key_epoch = id(25);
    let grant = FileGrant {
        binding: b,
        job_digest: next.digest().unwrap(),
        permission: Permission::SendFileNoClobber,
        chunk_bytes: 65536,
        issued_at_ms: 1000,
        expires_at_ms: 11000,
    }
    .validate_for_profile(next, LeaseProfile::SingleOwner)
    .unwrap();
    let condition = ResumeProposal::build(&old, &cp, &grant).unwrap();
    let source = EphemeralKey::generate();
    let target = EphemeralKey::generate();
    let source_identity = IdentityKey::from_test_seed([0x11; 32]);
    let target_identity = IdentityKey::from_test_seed([0x22; 32]);
    let transcript = Transcript::for_grant(
        &grant,
        source_identity.public(),
        target_identity.public(),
        source.public(),
        target.public(),
    );
    let source_pin = DevicePin::approved("source-A", source_identity.public()).unwrap();
    let target_pin = DevicePin::approved("target-B", target_identity.public()).unwrap();
    let sa = source_identity
        .sign_with_profile(
            &transcript,
            Direction::SourceToTarget,
            LeaseProfile::SingleOwner,
        )
        .unwrap();
    let ta = target_identity
        .sign_with_profile(
            &transcript,
            Direction::TargetToSource,
            LeaseProfile::SingleOwner,
        )
        .unwrap();
    let sr = source_identity
        .sign_resume_message(&SigningMessage {
            proposal: &condition,
            grant: &grant,
            transcript: &transcript,
            role: Direction::SourceToTarget,
        })
        .unwrap();
    let tr = target_identity
        .sign_resume_message(&SigningMessage {
            proposal: &condition,
            grant: &grant,
            transcript: &transcript,
            role: Direction::TargetToSource,
        })
        .unwrap();
    Fixture {
        old,
        cp,
        grant,
        condition,
        transcript,
        source,
        target,
        source_identity,
        target_identity,
        source_pin,
        target_pin,
        sa,
        ta,
        sr,
        tr,
    }
}
fn anchor(earliest: u64, latest: u64) -> TrustedTimeAnchor {
    TrustedTimeAnchor::approved_window(ClockSample::now(), earliest, latest).unwrap()
}
impl Fixture {
    fn source(self) -> Result<ResumeLease> {
        self.source_at(anchor(1200, 1200))
    }
    fn source_at(self, a: TrustedTimeAnchor) -> Result<ResumeLease> {
        self.source.authenticate_resume_leased(
            self.condition,
            &self.transcript,
            Direction::SourceToTarget,
            &self.grant,
            &self.source_pin,
            &self.target_pin,
            &self.sa,
            &self.ta,
            &self.sr,
            &self.tr,
            a,
        )
    }
    fn pair(self) -> (ResumeLease, ResumeLease) {
        let a = self
            .source
            .authenticate_resume_leased(
                self.condition.clone(),
                &self.transcript,
                Direction::SourceToTarget,
                &self.grant,
                &self.source_pin,
                &self.target_pin,
                &self.sa,
                &self.ta,
                &self.sr,
                &self.tr,
                anchor(1200, 1200),
            )
            .unwrap();
        let b = self
            .target
            .authenticate_resume_leased(
                self.condition,
                &self.transcript,
                Direction::TargetToSource,
                &self.grant,
                &self.source_pin,
                &self.target_pin,
                &self.sa,
                &self.ta,
                &self.sr,
                &self.tr,
                anchor(1200, 1200),
            )
            .unwrap();
        (a, b)
    }
}
#[test]
fn both_proofs_and_normal_auth_bind_the_same_new_lease_and_real_aead() {
    let f = fixture();
    assert!(f.grant.grant().issued_at_ms > f.old.deadline_ms);
    let digest = f.condition.digest();
    let grant = f.grant.digest();
    let (mut source, mut target) = f.pair();
    assert_eq!(source.local_role(), Direction::SourceToTarget);
    assert_eq!(target.local_role(), Direction::TargetToSource);
    assert_eq!(source.condition().digest(), digest);
    assert_eq!(target.condition().digest(), digest);
    assert_eq!(source.grant().digest(), grant);
    assert_eq!(source.records.epoch_count(), 1);
    let bytes = source.records.seal_data(0, b"abc").unwrap();
    match target.records.open_record(&bytes).unwrap() {
        PeerRecord::Data { header, bytes } => {
            assert_eq!(header.offset, 0);
            assert_eq!(&bytes[..], b"abc");
        }
        _ => panic!("not real DATA"),
    }
}
#[test]
fn ordinary_auth_source_signature_cannot_replace_resume_proof() {
    let mut f = fixture();
    f.sr = f.sa;
    assert!(f.source().is_err());
}
#[test]
fn ordinary_auth_target_signature_cannot_replace_resume_proof() {
    let mut f = fixture();
    f.tr = f.ta;
    assert!(f.source().is_err());
}
#[test]
fn valid_source_does_not_hide_invalid_target_resume_signature() {
    let mut f = fixture();
    f.tr[0] ^= 1;
    assert!(f.source().is_err());
}
#[test]
fn valid_target_does_not_hide_invalid_source_resume_signature() {
    let mut f = fixture();
    f.sr[0] ^= 1;
    assert!(f.source().is_err());
}
#[test]
fn valid_resume_proofs_do_not_replace_normal_auth_signatures() {
    let mut f = fixture();
    f.sa[0] ^= 1;
    assert!(f.source().is_err());
}
#[test]
fn valid_four_signatures_do_not_bypass_local_expected_pin() {
    let mut f = fixture();
    f.source_pin = DevicePin::approved("source-A", f.target_identity.public()).unwrap();
    assert!(f.source().is_err());
}
#[test]
fn valid_four_signatures_do_not_bypass_actual_private_ephemeral() {
    let mut f = fixture();
    f.source = EphemeralKey::generate();
    assert!(f.source().is_err());
}
#[test]
fn valid_signatures_do_not_import_peer_time_as_local_anchor() {
    assert!(fixture().source_at(anchor(0, 0)).is_err());
}
#[test]
fn genuine_proof_for_other_checkpoint_revision_is_rejected() {
    let mut f = fixture();
    let mut cp = serde_json::to_value(&f.cp).unwrap();
    cp["revision"] = json!(4);
    let cp = serde_json::from_value(cp).unwrap();
    let other = ResumeProposal::build(&f.old, &cp, &f.grant).unwrap();
    f.sr = f
        .source_identity
        .sign_resume_message(&SigningMessage {
            proposal: &other,
            grant: &f.grant,
            transcript: &f.transcript,
            role: Direction::SourceToTarget,
        })
        .unwrap();
    assert!(f.source().is_err());
}
#[test]
fn genuine_proof_for_other_transcript_is_rejected() {
    let mut f = fixture();
    let mut t = f.transcript.clone();
    t.target_ephemeral = EphemeralKey::generate().public();
    f.tr = f
        .target_identity
        .sign_resume_message(&SigningMessage {
            proposal: &f.condition,
            grant: &f.grant,
            transcript: &t,
            role: Direction::TargetToSource,
        })
        .unwrap();
    assert!(f.source().is_err());
}
#[test]
fn same_canonical_grant_with_rotating_profile_cannot_borrow_resume_owner() {
    let mut f = fixture();
    let rotating = f
        .grant
        .grant()
        .clone()
        .validate_for(f.grant.job().clone())
        .unwrap();
    assert_eq!(rotating.digest(), f.grant.digest());
    f.grant = rotating;
    assert!(f.source().is_err());
}
#[test]
fn expiry_still_blocks_new_data_on_typed_owner() {
    let (mut source, _) = fixture().pair();
    source.records.test_expire();
    assert!(source.records.seal_data(0, b"a").is_err());
}
