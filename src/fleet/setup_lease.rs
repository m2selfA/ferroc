//! Connection-owned authenticated records with one-shot route/file handoff.
//! Explicit target-parent preparation stays inside the original live owner.
//! The caller must independently approve time; setup/relay fields supply none.
use super::{
    auth::PeerRecord,
    control::ControlBody,
    identity::PeerEndpoint,
    job::ValidatedGrant,
    lease::{ClockSample, LeasedRecords, MAX_CLOCK_DIVERGENCE_MS, TrustedTimeAnchor},
    protocol::{Direction, device_digest},
    setup::PreparedSetup,
    setup_agent::LocalSetupApproval,
};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use std::sync::{Arc, Mutex, Weak};

/// An explicit SINGLE-OWNER decision to trust this host's wall epoch within the
/// supplied uncertainty. Not NTP verification, peer time or a silent fallback.
/// Captured ONCE: reusing it never resamples/reanchors/extends a grant.
pub struct ApprovedLocalClock {
    sample: ClockSample,
    earliest: u64,
    latest: u64,
}
impl ApprovedLocalClock {
    pub fn single_owner_system_clock(uncertainty_ms: u64) -> Result<Self> {
        ensure!(
            (1..=MAX_CLOCK_DIVERGENCE_MS).contains(&uncertainty_ms),
            "invalid explicit local clock uncertainty"
        );
        let sample = ClockSample::now();
        let epoch = sample.local_epoch_ms()?;
        Ok(Self {
            sample,
            earliest: epoch
                .checked_sub(uncertainty_ms)
                .context("clock lower overflow")?,
            // local_epoch_ms floors fractional milliseconds; round upper bound
            // outward so the approved uncertainty is never understated.
            latest: epoch
                .checked_add(uncertainty_ms)
                .and_then(|v| v.checked_add(1))
                .context("clock upper overflow")?,
        })
    }
    pub(crate) fn validate_grant(&self, grant: &ValidatedGrant) -> Result<()> {
        ensure!(
            grant.lease_profile() == super::job::LeaseProfile::SingleOwner,
            "local clock approval requires single-owner profile"
        );
        ensure!(
            self.earliest >= grant.grant().issued_at_ms
                && self.latest < grant.grant().expires_at_ms,
            "approved local clock interval outside fixed grant"
        );
        Ok(())
    }
    pub(crate) fn anchor(&self) -> Result<TrustedTimeAnchor> {
        TrustedTimeAnchor::approved_window(self.sample, self.earliest, self.latest)
    }
}

/// Live original crypto owner. No clone, serialization, raw-record extraction,
/// renewal, File, DB, route ticket or publication capability.
/// ```compile_fail
/// fn cannot_clone(x:ferroc::fleet::setup_lease::SetupLease){let _=x.clone();}
/// ```
/// ```compile_fail
/// fn no_raw_records(x:ferroc::fleet::setup_lease::SetupLease){let _=x.records;}
/// ```
pub struct SetupLease {
    runtime: Weak<Runtime>,
    gate: Arc<Mutex<()>>,
    local: LocalSetupApproval,
    role: Direction,
    endpoint: PeerEndpoint,
    local_public: [u8; 32],
    peer_public: [u8; 32],
    records: Option<LeasedRecords>,
    route_request: Option<uuid::Uuid>,
    route_ticket: Option<zeroize::Zeroizing<String>>,
    route_claimed: bool,
}
impl SetupLease {
    pub fn grant(&self) -> &ValidatedGrant {
        &self.local.proposal
    }
    pub fn role(&self) -> Direction {
        self.role
    }
    pub fn is_closed(&self) -> bool {
        self.records.is_none()
    }
    pub fn close(&mut self) {
        self.route_ticket.take();
        self.route_claimed = false;
        if let Some(mut records) = self.records.take() {
            records.revoke();
        }
    }
    fn trust_current(&self, runtime: &Runtime) -> Result<()> {
        trust_current(TrustCheck {
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
            let runtime = self.runtime.upgrade().context("leased Runtime gone")?;
            let _registry = runtime.fleet_source_guard()?;
            let gate = self.gate.clone();
            let _gate = gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            self.trust_current(&runtime)?;
            let records = self.records.as_mut().context("leased setup closed")?;
            records.check_observation_admission()?;
            let mut value = if live {
                records.check_commit_admission().and_then(|()| op(records))
            } else {
                op(records)
            };
            self.trust_current(&runtime)?;
            let records = self.records.as_mut().context("leased setup closed")?;
            records.check_observation_admission()?;
            if live
                && value.is_ok()
                && let Err(error) = records.check_commit_admission()
            {
                value = Err(error);
            }
            Ok(value)
        })();
        // Trust/clock/authenticated-semantic faults consume THIS live owner.
        // An unauthenticated bad ciphertext alone must not poison valid records.
        match result {
            Ok(value) => value,
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }
    /// A separate declaration on the authenticated native control socket. It is
    /// not relay-issued file permission or a proof of this private lease state.
    pub(crate) fn request_data_route(&mut self, id: uuid::Uuid) -> Result<serde_json::Value> {
        ensure!(
            !id.is_nil() && self.route_request.is_none(),
            "DATA route request already used/invalid"
        );
        self.check_active()?;
        self.route_request = Some(id);
        Ok(serde_json::json!({"type":"fleetRoute","id":id,"grantDigest":self.grant().digest()}))
    }
    pub(crate) fn accept_data_route(
        &mut self,
        id: uuid::Uuid,
        digest: [u8; 32],
        ticket: zeroize::Zeroizing<String>,
    ) -> Result<()> {
        ensure!(
            self.route_request == Some(id)
                && self.route_ticket.is_none()
                && digest == self.grant().digest(),
            "unexpected DATA route ticket"
        );
        ensure!(
            ticket.len() == 64 && ticket.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid DATA ticket"
        );
        self.check_active()?;
        self.route_ticket = Some(ticket);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn test_route_ticket_held(&self) -> bool {
        self.route_ticket.is_some()
    }
    #[cfg(test)]
    pub(crate) fn test_set_route_ticket(&mut self, ticket: &str) {
        self.route_ticket = Some(zeroize::Zeroizing::new(ticket.into()));
    }
    #[cfg(test)]
    pub(crate) fn test_claim_route(&mut self) -> Result<()> {
        let _ = self
            .route_ticket
            .take()
            .context("DATA route ticket not held")?;
        self.route_claimed = true;
        Ok(())
    }
    /// Consume the held one-shot ticket into the REAL fleet link. The ticket is
    /// removed before dialing; any failure terminally closes this owner rather
    /// than leaving a reusable routing secret. Role/grant/endpoint are from the
    /// original approved lease, never from the wire.
    pub async fn connect_link(
        &mut self,
        net: &crate::network::Network,
        token: &str,
        budget: std::time::Duration,
    ) -> Result<crate::fleet::relay_io::FleetLink> {
        self.check_active()?;
        let ticket = self
            .route_ticket
            .take()
            .context("DATA route ticket not held")?;
        self.route_claimed = true;
        let result = crate::fleet::relay_io::FleetLink::connect(
            net,
            self.endpoint.url(),
            token,
            &ticket,
            &self.local.proposal,
            self.role,
            budget,
        )
        .await;
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Move the SAME authenticated records into the existing SourceWindow only
    /// after this exact owner consumed its routing ticket. No record export and
    /// no second window from the same lease.
    pub fn into_source_window<'a>(
        mut self,
        runtime: &'a Runtime,
        window_chunks: u8,
    ) -> Result<crate::fleet::source_window::SourceWindow<'a>> {
        ensure!(
            self.role == Direction::SourceToTarget,
            "leased source role required"
        );
        ensure!(
            self.route_claimed && self.route_ticket.is_none(),
            "routing ticket not consumed by this owner"
        );
        self.trust_current(runtime)?;
        let records = self.records.take().context("leased setup closed")?;
        let source =
            crate::fleet::source_file::SourceFile::open(runtime, records, self.gate.clone())?;
        crate::fleet::source_window::SourceWindow::new(source, window_chunks)
    }
    /// Move the SAME authenticated records into the EXISTING target receiver on
    /// the SAME Runtime that owns the host. Host admission still revalidates the
    /// job, target policy, database fence, stage and lease; this is not publish.
    #[cfg(windows)]
    pub fn into_receiver<'h, 'r>(
        mut self,
        host: &'h crate::fleet::host::FleetHost<'r>,
    ) -> Result<crate::fleet::host::receiver::HostReceiver<'h, 'r>> {
        let records = self.take_target_records(host)?;
        host.admit_receiver(records)
    }
    /// Explicit Linux anonymous stage, same ticket/Runtime/records. Unlinked
    /// bytes vanish on final FD drop; persistent full debt is not released.
    #[cfg(target_os = "linux")]
    pub fn into_linux_anonymous_receiver<'h, 'r>(
        mut self,
        host: &'h crate::fleet::host::FleetHost<'r>,
    ) -> Result<crate::fleet::host::receiver::HostReceiver<'h, 'r>> {
        let records = self.take_target_records(host)?;
        host.admit_linux_anonymous_receiver(records)
    }
    #[cfg(any(windows, target_os = "linux"))]
    fn take_target_records(
        &mut self,
        host: &crate::fleet::host::FleetHost<'_>,
    ) -> Result<LeasedRecords> {
        ensure!(
            self.role == Direction::TargetToSource,
            "leased target role required"
        );
        ensure!(
            self.route_claimed && self.route_ticket.is_none(),
            "routing ticket not consumed by this owner"
        );
        let runtime = self.runtime.upgrade().context("leased Runtime gone")?;
        ensure!(
            std::ptr::eq(runtime.as_ref(), host.runtime()),
            "leased host uses another Runtime"
        );
        self.trust_current(&runtime)?;
        let records = self.records.take().context("leased setup closed")?;
        Ok(records)
    }
    /// LOCAL opt-in consumed by the configured target pump. Never called from
    /// a relay frame; source owners and unconsumed tickets cannot create dirs.
    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn prepare_target_parents(
        &mut self,
        root: &std::path::Path,
    ) -> Result<super::target_directories::TargetParents> {
        ensure!(
            self.role == Direction::TargetToSource,
            "leased target role required"
        );
        ensure!(
            self.route_claimed && self.route_ticket.is_none(),
            "routing ticket not consumed by this owner"
        );
        let runtime = self.runtime.upgrade().context("leased Runtime gone")?;
        let destination = std::path::PathBuf::from(&self.grant().job().destination_path);
        self.operate(true, |records| {
            super::target_directories::prepare(&runtime.policy, root, &destination, || {
                records.check_commit_admission()
            })
        })
    }
    pub fn check_active(&mut self) -> Result<()> {
        self.operate(true, |_| Ok(()))
    }
    /// Record encoding only, not a file read or sent-byte counter.
    pub fn seal_data(&mut self, offset: u64, bytes: &[u8]) -> Result<Vec<u8>> {
        self.operate(true, |r| r.seal_data(offset, bytes))
    }
    pub fn seal_control(&mut self, body: ControlBody) -> Result<Vec<u8>> {
        self.operate(body.kind().requires_live_grant(), |r| r.seal_control(body))
    }
    /// AEAD decode only; no receiver/stage or side effects on disk.
    pub fn open_record(&mut self, frame: &[u8]) -> Result<PeerRecord> {
        let live = super::protocol::Frame::decode(frame)?
            .header
            .kind
            .requires_live_grant();
        self.operate(live, |r| r.open_record(frame))
    }
}
impl Drop for SetupLease {
    fn drop(&mut self) {
        self.close();
    }
}

/// Shared CURRENT trust observation; does not acquire locks itself.
/// Factory/record operations hold registry→gate. Legacy fresh handoff retains
/// its existing follow-on SourceFile/host checks; extraction does not strengthen
/// those sites. This checker never issues records or file authority.
pub(super) struct TrustCheck<'a> {
    pub(super) runtime: &'a Runtime,
    pub(super) local: &'a LocalSetupApproval,
    pub(super) role: Direction,
    pub(super) endpoint: &'a PeerEndpoint,
    pub(super) local_public: [u8; 32],
    pub(super) peer_public: [u8; 32],
}
pub(super) fn trust_current(check: TrustCheck<'_>) -> Result<()> {
    let TrustCheck {
        runtime,
        local,
        role,
        endpoint,
        local_public,
        peer_public,
    } = check;
    let (fleet, device) = local.identity.issuance_scope();
    let job = local.proposal.job();
    let (mine, theirs, path) = match role {
        Direction::SourceToTarget => (job.source_device, job.target_device, &job.source_path),
        Direction::TargetToSource => (job.target_device, job.source_device, &job.destination_path),
    };
    ensure!(
        fleet == job.fleet_id
            && device_digest(device)? == mine
            && device_digest(&local.peer.device)? == theirs,
        "leased setup scope mismatch"
    );
    ensure!(
        local.peer.profile == local.proposal.lease_profile(),
        "leased setup profile mismatch"
    );
    runtime.policy.resolve(path)?; // LOCAL role only; not remote path authority.
    ensure!(
        local.identity.load_identity()?.public() == local_public,
        "leased local identity changed"
    );
    let peers = local.identity.peers()?;
    ensure!(
        peers.iter().any(|p| p.device() == local.peer.device
            && p.public_key() == peer_public
            && p.fingerprint(fleet).ok().as_ref() == Some(&local.peer.fingerprint)),
        "leased peer approval changed"
    );
    ensure!(
        local
            .identity
            .endpoints_for(&local.peer.device)?
            .iter()
            .any(|e| e == endpoint && e.slot() == local.peer.slot),
        "leased endpoint changed"
    );
    Ok(())
}

pub(crate) fn authenticate_local(
    runtime: &Arc<Runtime>,
    gate: Arc<Mutex<()>>,
    prepared: PreparedSetup,
    local: LocalSetupApproval,
    role: Direction,
    anchor: TrustedTimeAnchor,
) -> Result<SetupLease> {
    let _registry = runtime.fleet_source_guard()?;
    let lock = gate.clone();
    let _gate = lock
        .lock()
        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
    let approval = prepared.approval();
    ensure!(
        approval.role() == role
            && approval.grant().digest() == local.proposal.digest()
            && approval.grant().lease_profile() == local.proposal.lease_profile(),
        "leased setup expected grant/role mismatch"
    );
    ensure!(
        approval.peer_fingerprint() == &local.peer.fingerprint
            && approval.endpoint().device() == local.peer.device
            && approval.endpoint().slot() == local.peer.slot,
        "leased setup expected peer mismatch"
    );
    let t = approval.transcript();
    let (local_public, peer_public) = match role {
        Direction::SourceToTarget => (t.source_identity, t.target_identity),
        Direction::TargetToSource => (t.target_identity, t.source_identity),
    };
    let mut owner = SetupLease {
        runtime: Arc::downgrade(runtime),
        gate,
        local,
        role,
        endpoint: approval.endpoint().clone(),
        local_public,
        peer_public,
        records: None,
        route_request: None,
        route_ticket: None,
        route_claimed: false,
    };
    owner.trust_current(runtime)?;
    owner.records = Some(prepared.authenticate(anchor)?);
    owner.trust_current(runtime)?;
    owner
        .records
        .as_mut()
        .context("leased records missing")?
        .check_commit_admission()?;
    Ok(owner)
}

#[cfg(test)]
#[test]
fn local_clock_approval_is_explicit_and_rounds_interval_outward() {
    assert!(ApprovedLocalClock::single_owner_system_clock(0).is_err());
    assert!(ApprovedLocalClock::single_owner_system_clock(MAX_CLOCK_DIVERGENCE_MS + 1).is_err());
    let clock = ApprovedLocalClock::single_owner_system_clock(100).unwrap();
    let epoch = clock.sample.local_epoch_ms().unwrap();
    assert_eq!(clock.earliest, epoch - 100);
    assert_eq!(clock.latest, epoch + 101);
    assert!(clock.anchor().is_ok());
}

#[cfg(test)]
impl SetupLease {
    pub(super) fn test_expire(&mut self) {
        self.records.as_mut().unwrap().test_expire();
    }
    pub(super) fn test_discontinuous(&mut self) {
        self.records.as_mut().unwrap().test_discontinuous();
    }
}
