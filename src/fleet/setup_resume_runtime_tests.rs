//! LOCAL Runtime crypto lifecycle only, no target host/DB/route/restart.
use super::*;
use crate::fleet::{
    control::{Ack, ControlBody},
    setup_agent::{ConfiguredSetupPeer, LocalSetupApproval},
    setup_resume::{LocalResumeSetupApproval, ResumeSetupLease},
};
use std::sync::Arc;
struct H {
    root: tempfile::TempDir,
    a: Arc<IdentityStore>,
    b: Arc<IdentityStore>,
    ra: Arc<Runtime>,
    rb: Arc<Runtime>,
    af: Fingerprint,
    bf: Fingerprint,
    g: ValidatedGrant,
    p: ResumeProposal,
    pa: Option<PreparedSetup>,
    pb: Option<PreparedSetup>,
    sa: [u8; 64],
    sb: [u8; 64],
}
impl H {
    fn new() -> Self {
        let f = Fixture::new();
        let (pa, pb) = prepared(&f);
        let (p, _, _) = condition(&f, 3);
        let (sa, sb) = sign(&f, &pa, &pb, &p);
        let sa = *sa.signature();
        let sb = *sb.signature();
        let Fixture {
            _tmp,
            a,
            b,
            ra,
            rb,
            af,
            bf,
            proposal,
            outside: _,
        } = f;
        Self {
            root: _tmp,
            a: Arc::new(a),
            b: Arc::new(b),
            ra: Arc::new(ra),
            rb: Arc::new(rb),
            af,
            bf,
            g: proposal,
            p,
            pa: Some(pa),
            pb: Some(pb),
            sa,
            sb,
        }
    }
    fn req(&self, role: Direction) -> LocalResumeSetupApproval {
        let (identity, device, fingerprint) = match role {
            Direction::SourceToTarget => (self.a.clone(), "b", self.bf.clone()),
            Direction::TargetToSource => (self.b.clone(), "a", self.af.clone()),
        };
        LocalResumeSetupApproval {
            local: LocalSetupApproval {
                identity,
                proposal: self.g.clone(),
                peer: ConfiguredSetupPeer {
                    device: device.into(),
                    fingerprint,
                    slot: EndpointSlot::Primary,
                    profile: LeaseProfile::SingleOwner,
                },
                now: Arc::new(|| Ok(200)),
            },
            role,
            condition: self.p.clone(),
            source_resume_signature: self.sa,
            target_resume_signature: self.sb,
        }
    }
    fn source(&mut self) -> ResumeSetupLease {
        self.ra
            .authenticate_fleet_resume_setup(
                self.pa.take().unwrap(),
                self.req(Direction::SourceToTarget),
                anchor(200),
            )
            .unwrap()
    }
    fn target(&mut self) -> ResumeSetupLease {
        self.rb
            .authenticate_fleet_resume_setup(
                self.pb.take().unwrap(),
                self.req(Direction::TargetToSource),
                anchor(200),
            )
            .unwrap()
    }
    fn no_data_io(&self) {
        assert!(!PathBuf::from(&self.g.job().destination_path).exists());
        assert_eq!(
            fs::read_dir(self.root.path().join("work-b"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(fs::read(&self.g.job().source_path).unwrap(), b"abc");
    }
}
fn pending_routes(
    h: &mut H,
) -> (
    crate::fleet::resume_route::PendingResumeRoute,
    crate::fleet::resume_route::PendingResumeRoute,
    crate::fleet::resume_route::ResumeRouteProofs,
) {
    use crate::fleet::resume_route::{PendingResumeRoute, ResumeRouteProofs, RoleResumeProof};
    let id = uuid::Uuid::new_v4();
    let a = PendingResumeRoute::begin(
        &h.ra,
        id,
        h.pa.take().unwrap(),
        h.req(Direction::SourceToTarget).local,
        h.p.clone(),
    )
    .unwrap();
    let b = PendingResumeRoute::begin(
        &h.rb,
        id,
        h.pb.take().unwrap(),
        h.req(Direction::TargetToSource).local,
        h.p.clone(),
    )
    .unwrap();
    let ap: RoleResumeProof = serde_json::from_value(a.request()["resume"].clone()).unwrap();
    let bp: RoleResumeProof = serde_json::from_value(b.request()["resume"].clone()).unwrap();
    assert_eq!(ap.condition_digest, bp.condition_digest);
    let both = ResumeRouteProofs {
        condition_digest: ap.condition_digest,
        source_signature: ap.signature,
        target_signature: bp.signature,
    };
    (a, b, both)
}
#[test]
fn resume_route_actual_prepared_keys_need_both_proofs_before_ticket_owner() {
    let mut h = H::new();
    let (a, b, both) = pending_routes(&mut h);
    let ticket = || zeroize::Zeroizing::new("ab".repeat(32));
    let mut a = a
        .finish(&h.ra, h.g.digest(), both.clone(), ticket(), anchor(200))
        .unwrap();
    let mut b = b
        .finish(&h.rb, h.g.digest(), both, ticket(), anchor(200))
        .unwrap();
    let frame = a.seal_data(0, b"abc").unwrap();
    assert!(b.open_record(&frame).is_ok());
    h.no_data_io();
}
#[test]
fn resume_route_corrupt_peer_signature_and_substituted_condition_never_install() {
    let mut h = H::new();
    let (a, _, mut both) = pending_routes(&mut h);
    both.target_signature[0] ^= 1;
    assert!(
        a.finish(
            &h.ra,
            h.g.digest(),
            both,
            zeroize::Zeroizing::new("ab".repeat(32)),
            anchor(200)
        )
        .is_err()
    );
    let mut h = H::new();
    let (a, _, mut both) = pending_routes(&mut h);
    both.condition_digest[0] ^= 1;
    assert!(
        a.finish(
            &h.ra,
            h.g.digest(),
            both,
            zeroize::Zeroizing::new("ab".repeat(32)),
            anchor(200)
        )
        .is_err()
    );
    h.no_data_io();
}
#[test]
fn resume_route_current_revocation_before_both_proofs_is_terminal() {
    let mut h = H::new();
    let (a, _, both) = pending_routes(&mut h);
    h.a.revoke_peer("b", &h.bf).unwrap();
    assert!(
        a.finish(
            &h.ra,
            h.g.digest(),
            both,
            zeroize::Zeroizing::new("ab".repeat(32)),
            anchor(200)
        )
        .is_err()
    );
    h.no_data_io();
}
#[test]
fn runtime_resume_owner_retains_condition_both_roles_and_actual_setup_aead() {
    let mut h = H::new();
    let (mut a, mut b) = (h.source(), h.target());
    assert_eq!(a.role(), Direction::SourceToTarget);
    assert_eq!(b.role(), Direction::TargetToSource);
    assert_eq!(a.condition().unwrap().digest(), h.p.digest());
    assert_eq!(a.grant().digest(), h.g.digest());
    let frame = a.seal_data(0, b"abc").unwrap();
    match b.open_record(&frame).unwrap() {
        PeerRecord::Data { bytes, .. } => assert_eq!(&bytes[..], b"abc"),
        _ => panic!("DATA"),
    };
    h.no_data_io();
}
#[test]
fn wrong_local_expected_grant_role_or_profile_never_installs_owner() {
    for mode in 0..3 {
        let mut h = H::new();
        let mut req = h.req(Direction::SourceToTarget);
        match mode {
            0 => {
                req.local.proposal = propose(
                    h.g.job().clone(),
                    ProposalOptions {
                        source_session: Uuid::new_v4(),
                        target_session: Uuid::new_v4(),
                        profile: LeaseProfile::SingleOwner,
                        issued_at_ms: 100,
                        lease_ms: 3_600_000,
                        chunk_bytes: 65536,
                    },
                )
                .unwrap()
            }
            1 => req.role = Direction::TargetToSource,
            2 => req.local.peer.profile = LeaseProfile::Rotating,
            _ => unreachable!(),
        };
        assert!(
            h.ra.authenticate_fleet_resume_setup(h.pa.take().unwrap(), req, anchor(200))
                .is_err()
        );
        h.no_data_io();
    }
}
#[test]
fn wrong_local_expected_peer_is_rejected_before_return() {
    let mut h = H::new();
    let mut req = h.req(Direction::SourceToTarget);
    req.local.peer.fingerprint = h.af.clone();
    assert!(
        h.ra.authenticate_fleet_resume_setup(h.pa.take().unwrap(), req, anchor(200))
            .is_err()
    );
    h.no_data_io();
}
#[test]
fn different_locally_selected_condition_cannot_borrow_both_valid_proofs() {
    let f = Fixture::new();
    let (pa, pb) = prepared(&f);
    let (p, old, cp) = condition(&f, 3);
    let (sa, sb) = sign(&f, &pa, &pb, &p);
    let mut cp = serde_json::to_value(cp).unwrap();
    cp["revision"] = serde_json::json!(4);
    let cp: PrefixCheckpoint = serde_json::from_value(cp).unwrap();
    let other = ResumeProposal::build(&old, &cp, &f.proposal).unwrap();
    let Fixture {
        _tmp,
        a,
        b: _,
        ra,
        rb: _,
        af: _,
        bf,
        proposal,
        outside: _,
    } = f;
    let ra = Arc::new(ra);
    let req = LocalResumeSetupApproval {
        local: LocalSetupApproval {
            identity: Arc::new(a),
            proposal,
            peer: ConfiguredSetupPeer {
                device: "b".into(),
                fingerprint: bf,
                slot: EndpointSlot::Primary,
                profile: LeaseProfile::SingleOwner,
            },
            now: Arc::new(|| Ok(200)),
        },
        role: Direction::SourceToTarget,
        condition: other,
        source_resume_signature: *sa.signature(),
        target_resume_signature: *sb.signature(),
    };
    assert!(
        ra.authenticate_fleet_resume_setup(pa, req, anchor(200))
            .is_err()
    );
    assert_eq!(fs::read_dir(_tmp.path().join("work-b")).unwrap().count(), 0);
}
#[test]
fn either_corrupt_resume_signature_prevents_runtime_installation() {
    for source in [true, false] {
        let mut h = H::new();
        let mut req = h.req(Direction::SourceToTarget);
        if source {
            req.source_resume_signature[0] ^= 1
        } else {
            req.target_resume_signature[0] ^= 1
        }
        assert!(
            h.ra.authenticate_fleet_resume_setup(h.pa.take().unwrap(), req, anchor(200))
                .is_err()
        );
        h.no_data_io();
    }
}
#[test]
fn revoked_peer_before_installation_is_not_an_historical_signature_approval() {
    let mut h = H::new();
    h.a.revoke_peer("b", &h.bf).unwrap();
    assert!(
        h.ra.authenticate_fleet_resume_setup(
            h.pa.take().unwrap(),
            h.req(Direction::SourceToTarget),
            anchor(200)
        )
        .is_err()
    );
    h.no_data_io();
}
#[test]
fn changed_endpoint_before_installation_is_rejected() {
    let mut h = H::new();
    h.a.set_peer_endpoint("b", EndpointSlot::Primary, "https://rotated.invalid", &h.bf)
        .unwrap();
    assert!(
        h.ra.authenticate_fleet_resume_setup(
            h.pa.take().unwrap(),
            h.req(Direction::SourceToTarget),
            anchor(200)
        )
        .is_err()
    );
    h.no_data_io();
}
#[test]
fn revocation_after_installation_closes_same_owner_on_next_operation() {
    let mut h = H::new();
    let mut owner = h.source();
    h.a.revoke_peer("b", &h.bf).unwrap();
    assert!(owner.seal_data(0, b"abc").is_err());
    assert!(owner.is_closed());
    assert!(owner.condition().is_none());
    h.no_data_io();
}
#[test]
fn endpoint_rotation_after_installation_closes_same_owner() {
    let mut h = H::new();
    let mut owner = h.source();
    h.a.set_peer_endpoint("b", EndpointSlot::Primary, "https://rotated.invalid", &h.bf)
        .unwrap();
    assert!(owner.check_active().is_err());
    assert!(owner.is_closed());
    h.no_data_io();
}
#[test]
fn bad_ciphertext_does_not_poison_healthy_runtime_resume_crypto() {
    let mut h = H::new();
    let (mut a, mut b) = (h.source(), h.target());
    let good = a.seal_data(0, b"abc").unwrap();
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(b.open_record(&bad).is_err());
    assert!(!b.is_closed());
    assert!(b.open_record(&good).is_ok());
    h.no_data_io();
}
#[test]
fn expired_owner_retains_ack_observation_even_after_denied_new_data() {
    let mut h = H::new();
    let (mut a, mut b) = (h.source(), h.target());
    let ack = b
        .seal_control(ControlBody::Ack(Ack {
            contiguous: 0,
            received: 0,
        }))
        .unwrap();
    a.test_expire();
    assert!(a.open_record(&ack).is_ok());
    assert!(a.seal_data(0, b"abc").is_err());
    let ack = b
        .seal_control(ControlBody::Ack(Ack {
            contiguous: 0,
            received: 0,
        }))
        .unwrap();
    assert!(a.open_record(&ack).is_ok());
    assert!(!a.is_closed());
    h.no_data_io();
}
#[test]
fn clock_discontinuity_closes_owner_and_cannot_be_revived() {
    let mut h = H::new();
    let mut owner = h.source();
    owner.test_discontinuous();
    assert!(owner.check_active().is_err());
    assert!(owner.is_closed());
    assert!(owner.seal_data(0, b"abc").is_err());
    h.no_data_io();
}
#[tokio::test]
async fn shutdown_before_and_after_installation_keeps_idle_owner_out_of_drain() {
    let mut h = H::new();
    h.ra.shutdown().await;
    assert!(
        h.ra.authenticate_fleet_resume_setup(
            h.pa.take().unwrap(),
            h.req(Direction::SourceToTarget),
            anchor(200)
        )
        .is_err()
    );
    let mut h = H::new();
    let mut owner = h.source();
    tokio::time::timeout(std::time::Duration::from_secs(1), h.ra.shutdown())
        .await
        .unwrap();
    assert!(owner.check_active().is_err());
    assert!(owner.is_closed());
    h.no_data_io();
}
#[test]
fn explicit_close_is_terminal_and_does_not_create_or_delete_target_data() {
    let mut h = H::new();
    let mut owner = h.source();
    owner.close();
    owner.close();
    assert!(owner.is_closed());
    assert!(owner.check_active().is_err());
    assert!(owner.seal_data(0, b"abc").is_err());
    h.no_data_io();
}
#[test]
fn lost_runtime_weak_reference_closes_idle_owner_at_next_operation() {
    let mut h = H::new();
    let mut owner = h.source();
    assert_eq!(Arc::strong_count(&h.ra), 1);
    let replacement = Arc::new(Runtime::new(
        Policy::new(vec![h.root.path().join("work-a")], false).unwrap(),
    ));
    drop(std::mem::replace(&mut h.ra, replacement));
    assert!(owner.check_active().is_err());
    assert!(owner.is_closed());
    h.no_data_io();
}
