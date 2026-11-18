//! Explicit Runtime-bound resume crypto owner; no wire/route/File/DB handoff.
//! Shares fresh setup's CURRENT trust checker and registry→gate lock order.
use super::{
    auth::PeerRecord,
    control::ControlBody,
    identity::PeerEndpoint,
    job::ValidatedGrant,
    lease::{LeasedRecords, TrustedTimeAnchor},
    protocol::Direction,
    resume_condition::ResumeProposal,
    resume_lease::ResumeLease,
    setup::PreparedSetup,
    setup_agent::LocalSetupApproval,
    setup_lease::{self, TrustCheck},
};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use std::sync::{Arc, Mutex, Weak};

/// Trusted LOCAL decision, NOT deserialized peer/config authority or time.
/// Both proofs must bind this exact expected condition and actual setup keys.
pub struct LocalResumeSetupApproval {
    pub local: LocalSetupApproval,
    pub role: Direction,
    pub condition: ResumeProposal,
    pub source_resume_signature: [u8; 64],
    pub target_resume_signature: [u8; 64],
}
/// Keeps the SAME typed dual-proof lease; no clone/serde/raw records or ordinary
/// transfer conversion. Idle owner does not block shutdown; its next operation
/// fails/closes on its next guarded crypto operation after Runtime stop. Metadata
/// getters and rejected malformed headers do not force idle-key erasure.
/// ```compile_fail
/// fn no_clone(x:ferroc::fleet::setup_resume::ResumeSetupLease){let _=x.clone();}
/// ```
/// ```compile_fail
/// fn no_raw(x:ferroc::fleet::setup_resume::ResumeSetupLease){let _=x.lease;}
/// ```
/// ```compile_fail
/// fn no_fresh_file(x:ferroc::fleet::setup_resume::ResumeSetupLease,r:&ferroc::runtime::Runtime){let _=x.into_source_window(r,8);}
/// ```
pub struct ResumeSetupLease {
    runtime: Weak<Runtime>,
    gate: Arc<Mutex<()>>,
    local: LocalSetupApproval,
    role: Direction,
    endpoint: PeerEndpoint,
    local_public: [u8; 32],
    peer_public: [u8; 32],
    // Separate owner: the existing fresh SetupLease/pump layout is unchanged.
    lease: Option<Box<ResumeLease>>,
    route_ticket: Option<zeroize::Zeroizing<String>>,
    route_claimed: bool,
}
impl ResumeSetupLease {
    pub fn grant(&self) -> &ValidatedGrant {
        &self.local.proposal
    }
    pub fn role(&self) -> Direction {
        self.role
    }
    pub fn condition(&self) -> Option<&ResumeProposal> {
        self.lease.as_ref().map(|r| r.condition())
    }
    pub fn is_closed(&self) -> bool {
        self.lease.is_none()
    }
    pub fn close(&mut self) {
        self.route_ticket.take();
        if let Some(mut lease) = self.lease.take() {
            lease.records_mut().revoke();
        }
    }
    fn trust_current(&self, runtime: &Runtime) -> Result<()> {
        setup_lease::trust_current(TrustCheck {
            runtime,
            local: &self.local,
            role: self.role,
            endpoint: &self.endpoint,
            local_public: self.local_public,
            peer_public: self.peer_public,
        })
    }
    fn operate<T>(
        &mut self,
        live: bool,
        op: impl FnOnce(&mut LeasedRecords) -> Result<T>,
    ) -> Result<T> {
        let result = (|| {
            let runtime = self
                .runtime
                .upgrade()
                .context("resume setup Runtime gone")?;
            let _registry = runtime.fleet_source_guard()?;
            let gate = self.gate.clone();
            let _gate = gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            self.trust_current(&runtime)?;
            let records = self
                .lease
                .as_mut()
                .context("resume setup closed")?
                .records_mut();
            records.check_observation_admission()?;
            let mut value = if live {
                records.check_commit_admission().and_then(|()| op(records))
            } else {
                op(records)
            };
            self.trust_current(&runtime)?;
            let records = self
                .lease
                .as_mut()
                .context("resume setup closed")?
                .records_mut();
            records.check_observation_admission()?;
            if live
                && value.is_ok()
                && let Err(error) = records.check_commit_admission()
            {
                value = Err(error);
            }
            Ok(value)
        })();
        match result {
            Ok(value) => value,
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }
    pub fn check_active(&mut self) -> Result<()> {
        self.operate(true, |_| Ok(()))
    }
    /// Crypto encoding only; not a source file read/sent byte/coverage proof.
    pub fn seal_data(&mut self, offset: u64, bytes: &[u8]) -> Result<Vec<u8>> {
        self.operate(true, |r| r.seal_data(offset, bytes))
    }
    pub fn seal_control(&mut self, body: ControlBody) -> Result<Vec<u8>> {
        self.operate(body.kind().requires_live_grant(), |r| r.seal_control(body))
    }
    /// No target write or stage. Bad ciphertext alone must not poison owner.
    pub fn open_record(&mut self, frame: &[u8]) -> Result<PeerRecord> {
        let live = super::protocol::Frame::decode(frame)?
            .header
            .kind
            .requires_live_grant();
        self.operate(live, |r| r.open_record(frame))
    }
    pub(crate) fn install_route_ticket(
        &mut self,
        id: uuid::Uuid,
        digest: [u8; 32],
        ticket: zeroize::Zeroizing<String>,
    ) -> Result<()> {
        ensure!(
            !id.is_nil()
                && digest == self.grant().digest()
                && self.route_ticket.is_none()
                && !self.route_claimed,
            "unexpected resume route ticket"
        );
        ensure!(
            ticket.len() == 64 && ticket.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid resume DATA ticket"
        );
        self.check_active()?;
        self.route_ticket = Some(ticket);
        Ok(())
    }
    pub(crate) async fn connect_link(
        &mut self,
        net: &crate::network::Network,
        token: &str,
        budget: std::time::Duration,
    ) -> Result<super::relay_io::FleetLink> {
        self.check_active()?;
        let ticket = self
            .route_ticket
            .take()
            .context("resume DATA ticket not held")?;
        self.route_claimed = true;
        let result = super::relay_io::FleetLink::connect(
            net,
            self.endpoint.url(),
            token,
            &ticket,
            self.grant(),
            self.role,
            budget,
        )
        .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    fn handoff(&mut self, runtime: &Runtime) -> Result<ResumeLease> {
        let actual = self
            .runtime
            .upgrade()
            .context("resume setup Runtime gone")?;
        ensure!(
            std::ptr::eq(actual.as_ref(), runtime),
            "resume handoff uses another Runtime"
        );
        ensure!(
            self.route_claimed && self.route_ticket.is_none(),
            "resume DATA ticket not consumed by same owner"
        );
        self.check_active()?;
        Ok(*self.lease.take().context("resume setup closed")?)
    }
    pub(crate) fn into_recovery_source_window<'r>(
        mut self,
        runtime: &'r Runtime,
        window: u8,
        max_prefix: u64,
    ) -> Result<super::source_window::SourceWindow<'r>> {
        ensure!(
            self.role == Direction::SourceToTarget,
            "resume source role required"
        );
        let lease = self.handoff(runtime)?;
        let source = super::source_file::SourceFile::open_resume(
            runtime,
            lease,
            self.gate.clone(),
            max_prefix,
        )?;
        super::source_window::SourceWindow::resuming(source, window)
    }
    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn into_recovery_receiver<'h, 'r>(
        mut self,
        host: &'h super::host::FleetHost<'r>,
        recovery: &super::setup_config::RecoveryPlan,
    ) -> Result<super::host::receiver::HostReceiver<'h, 'r>> {
        ensure!(
            self.role == Direction::TargetToSource,
            "resume target role required"
        );
        let lease = self.handoff(host.runtime())?;
        let key = super::journal::JobKey::from_job(&recovery.old_job);
        let old = host.get(&key)?.context("selected recovery job missing")?;
        ensure!(
            old.job() == &recovery.old_job
                && old.retained_stage().and_then(|r| r.checkpoint()) == Some(&recovery.checkpoint),
            "selected recovery checkpoint/job changed"
        );
        let expected = ResumeProposal::build(old.job(), &recovery.checkpoint, lease.grant())?;
        ensure!(
            expected.canonical_bytes() == lease.condition().canonical_bytes(),
            "selected recovery condition changed"
        );
        let row = host.recover_retained_job(
            &key,
            recovery
                .stopped_owner
                .context("target stopped owner not selected")?,
            recovery
                .revision
                .context("target recovery revision not selected")?,
        )?;
        host.admit_retained_receiver(&key, row.revision(), lease, recovery.max_prefix_bytes)
    }
    #[cfg(test)]
    pub(in crate::fleet) fn test_expire(&mut self) {
        self.lease.as_mut().unwrap().records_mut().test_expire();
    }
    #[cfg(test)]
    pub(in crate::fleet) fn test_discontinuous(&mut self) {
        self.lease
            .as_mut()
            .unwrap()
            .records_mut()
            .test_discontinuous();
    }
}
impl Drop for ResumeSetupLease {
    fn drop(&mut self) {
        self.close();
    }
}
pub(crate) fn authenticate_local(
    runtime: &Arc<Runtime>,
    gate: Arc<Mutex<()>>,
    prepared: PreparedSetup,
    request: LocalResumeSetupApproval,
    anchor: TrustedTimeAnchor,
) -> Result<ResumeSetupLease> {
    let _registry = runtime.fleet_source_guard()?;
    let lock = gate.clone();
    let _gate = lock
        .lock()
        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
    let LocalResumeSetupApproval {
        local,
        role,
        condition,
        source_resume_signature,
        target_resume_signature,
    } = request;
    let a = prepared.approval();
    ensure!(
        a.role() == role
            && a.grant().digest() == local.proposal.digest()
            && a.grant().lease_profile() == local.proposal.lease_profile(),
        "resume setup expected grant/role/profile mismatch"
    );
    ensure!(
        a.peer_fingerprint() == &local.peer.fingerprint
            && a.endpoint().device() == local.peer.device
            && a.endpoint().slot() == local.peer.slot,
        "resume setup expected peer mismatch"
    );
    let t = a.transcript();
    let (local_public, peer_public) = match role {
        Direction::SourceToTarget => (t.source_identity, t.target_identity),
        Direction::TargetToSource => (t.target_identity, t.source_identity),
    };
    let mut owner = ResumeSetupLease {
        runtime: Arc::downgrade(runtime),
        gate,
        local,
        role,
        endpoint: a.endpoint().clone(),
        local_public,
        peer_public,
        lease: None,
        route_ticket: None,
        route_claimed: false,
    };
    owner.trust_current(runtime)?;
    owner.lease = Some(Box::new(prepared.authenticate_resume(
        condition,
        &source_resume_signature,
        &target_resume_signature,
        anchor,
    )?));
    owner.trust_current(runtime)?;
    owner
        .lease
        .as_mut()
        .context("resume setup lease missing")?
        .records_mut()
        .check_commit_admission()?;
    Ok(owner)
}
