//! Local provisioning for the configured setup backend. Strict, local-only:
//! no token, no remote grant, no clock/trust import. Loading validates every
//! round BEFORE the agent opens a relay connection.
use super::{
    identity::{EndpointSlot, Fingerprint, IdentityStore, Protection},
    job::{FileGrant, JobSpec, LeaseProfile, Permission, RoutePolicy, ValidatedGrant},
    protocol::{Binding, MAX_DATA, device_digest},
    setup::PreparedSetup,
    setup_agent::{ApprovedSetupNow, ConfiguredSetupPeer, LocalSetupApproval},
    setup_lease::{ApprovedLocalClock, SetupLease},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;
const MAX_CONFIG: u64 = 64 * 1024;
#[cfg(test)]
#[path = "setup_config_tests.rs"]
mod tests;
const MAX_ROUNDS: usize = 4;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct File {
    version: u16,
    identity_store: PathBuf,
    fleet: Uuid,
    device: String,
    protection: ProtectionFile,
    peer: PeerFile,
    rounds: Vec<RoundFile>,
    lease_authority: Option<LeaseAuthorityFile>,
    #[serde(default)]
    data_routes: bool,
    #[serde(default)]
    transfer: Option<TransferFile>,
}
/// Explicit LOCAL opt-in to drive the existing source/target pumps for the
/// provisioned rounds. Paths and grants still come from the approved rounds.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransferFile {
    window_chunks: u8,
    retained_checkpoint_bytes: Option<u64>,
    /// Explicit local acceptance of Linux anonymous-byte loss on last-FD drop.
    #[serde(default)]
    linux_anonymous_stage: bool,
    host_db: Option<PathBuf>,
    create_parents_below: Option<PathBuf>,
    #[serde(default)]
    mcp: bool,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum LeaseAuthorityFile {
    SingleOwnerSystemClock {
        #[serde(rename = "uncertaintyMs")]
        uncertainty_ms: u64,
    },
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum ProtectionFile {
    WindowsCurrentUser,
    SuppliedKeyEnv { name: String },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeerFile {
    device: String,
    fingerprint: String,
    slot: SlotFile,
    profile: ProfileFile,
}
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
enum SlotFile {
    Primary,
    Fallback,
}
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
enum ProfileFile {
    Rotating,
    SingleOwner,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RoundFile {
    pub(crate) id: Uuid,
    pub(crate) role: RoleFile,
    job: JobSpec,
    source_session: Uuid,
    target_session: Uuid,
    chunk_bytes: u32,
    lease_ms: u64,
    issued_at_ms: u64,
    authorization_id: Uuid,
    key_epoch: Uuid,
    recovery: Option<RecoveryPlan>,
}
/// LOCAL descriptive selection only. This deserialized object cannot construct
/// a lease, StoppedCreators or a writer. Target admission checks actual same-DB
/// row/object/checkpoint again, and always requires BOTH fresh recovery proofs.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecoveryPlan {
    pub(crate) old_job: JobSpec,
    pub(crate) checkpoint: super::journal::PrefixCheckpoint,
    pub(crate) stopped_owner: Option<Uuid>,
    pub(crate) revision: Option<u64>,
    pub(crate) max_prefix_bytes: u64,
}
impl RecoveryPlan {
    pub(crate) fn condition(
        &self,
        next: &ValidatedGrant,
    ) -> Result<super::resume_condition::ResumeProposal> {
        super::resume_condition::ResumeProposal::build(&self.old_job, &self.checkpoint, next)
    }
    fn validate(&self, role: RoleFile, next: &ValidatedGrant) -> Result<()> {
        self.condition(next)?;
        ensure!(
            self.max_prefix_bytes <= 1u64 << 30 && self.checkpoint.bytes() <= self.max_prefix_bytes,
            "recovery prefix exceeds local budget"
        );
        match role {
            RoleFile::Target => ensure!(
                self.stopped_owner.is_some_and(|o| !o.is_nil())
                    && self.revision.is_some_and(|r| r > 0),
                "target recovery needs explicit stopped owner and row revision"
            ),
            RoleFile::Source => ensure!(
                self.stopped_owner.is_none() && self.revision.is_none(),
                "source cannot select a target DB owner/revision"
            ),
        }
        Ok(())
    }
}
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RoleFile {
    Source,
    Target,
}
impl RoundFile {
    /// Descriptive resume digest from the relay operator's OWN local round file.
    pub(crate) fn recovery_condition(
        &self,
        next: &ValidatedGrant,
    ) -> Result<Option<super::resume_condition::ResumeProposal>> {
        self.recovery
            .as_ref()
            .map(|r| {
                r.validate(self.role, next)?;
                r.condition(next)
            })
            .transpose()
    }
    /// Same canonical builder for LOCAL agent and relay configuration only.
    pub(crate) fn materialize(&self, profile: LeaseProfile) -> Result<ValidatedGrant> {
        ensure!(
            (1..=MAX_DATA).contains(&(self.chunk_bytes as usize))
                && self.job.route == RoutePolicy::RelayOnly,
            "invalid local round route/chunk"
        );
        let binding = Binding {
            fleet_id: self.job.fleet_id,
            source_device: self.job.source_device,
            target_device: self.job.target_device,
            source_session: self.source_session,
            target_session: self.target_session,
            transfer_id: self.job.transfer_id,
            file_id: self.job.file_id,
            authorization_id: self.authorization_id,
            key_epoch: self.key_epoch,
        };
        FileGrant {
            binding,
            job_digest: self.job.digest()?,
            permission: if self.job.overwrite {
                Permission::ReplaceExistingFile
            } else {
                Permission::SendFileNoClobber
            },
            chunk_bytes: self.chunk_bytes,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self
                .issued_at_ms
                .checked_add(self.lease_ms)
                .context("setup lease overflow")?,
        }
        .validate_for_profile(self.job.clone(), profile)
    }
}
pub struct ProvisionedRound {
    pub id: Uuid,
    pub role: RoleFile,
    proposal: ValidatedGrant,
    recovery: Option<RecoveryPlan>,
}
/// Loaded configuration. Holds the DECRYPTED identity store, so it is not
/// Clone/Debug/Serialize and must stay inside the trusted process.
pub struct SetupProvision {
    store: Arc<IdentityStore>,
    peer: ConfiguredSetupPeer,
    rounds: Vec<ProvisionedRound>,
    lease_clock: Option<ApprovedLocalClock>,
    data_routes: bool,
    transfer: Option<TransferPlan>,
}
pub(crate) struct TransferPlan {
    window_chunks: u8,
    retained_checkpoint_bytes: Option<u64>,
    linux_anonymous_stage: bool,
    #[cfg(any(windows, target_os = "linux"))]
    host_db: Option<PathBuf>,
    create_parents_below: Option<PathBuf>,
    mcp: bool,
}
impl TransferPlan {
    pub(crate) fn retained_checkpoint_bytes(&self) -> Option<u64> {
        self.retained_checkpoint_bytes
    }
    pub(crate) fn window_chunks(&self) -> u8 {
        self.window_chunks
    }
    pub(crate) fn linux_anonymous_stage(&self) -> bool {
        self.linux_anonymous_stage
    }
    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn host_db(&self) -> Option<&Path> {
        self.host_db.as_deref()
    }
    pub(crate) fn create_parents_below(&self) -> Option<&Path> {
        self.create_parents_below.as_deref()
    }
    pub(crate) fn mcp(&self) -> bool {
        self.mcp
    }
}
pub(crate) fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).context("setup config missing")?;
    ensure!(meta.is_file(), "setup config must be a regular file");
    ensure!(meta.len() <= MAX_CONFIG, "setup config too large");
    #[cfg(windows)]
    ensure!(
        meta.file_attributes() & 0x400 == 0,
        "setup config must not be a reparse point"
    );
    use std::io::Read;
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .context("setup config unreadable")?
        .take(MAX_CONFIG + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= MAX_CONFIG,
        "setup config grew beyond limit"
    );
    Ok(raw)
}
fn protection(file: ProtectionFile) -> Result<Protection> {
    match file {
        ProtectionFile::WindowsCurrentUser => {
            #[cfg(windows)]
            {
                Protection::windows_current_user()
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!("windowsCurrentUser protection requires Windows")
            }
        }
        ProtectionFile::SuppliedKeyEnv { name } => {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_'),
                "invalid wrapping key environment name"
            );
            let value = Zeroizing::new(
                std::env::var(&name)
                    .with_context(|| format!("wrapping key environment {name} is not set"))?,
            );
            // Same 64-hex encoding as the fleet CLI; the value is never echoed.
            ensure!(
                value.len() == 64 && value.is_ascii(),
                "wrapping key must be exactly 64 hexadecimal characters"
            );
            let mut key = Zeroizing::new([0u8; 32]);
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                    .map_err(|_| anyhow::anyhow!("invalid wrapping key hex"))?;
            }
            Protection::supplied_key(key)
        }
    }
}
impl SetupProvision {
    pub fn load(path: &Path, expected_device: &str) -> Result<Self> {
        let raw = read_bounded(path)?;
        let file: File = serde_json::from_slice(&raw).context("invalid setup config")?;
        ensure!(file.version == 2, "unsupported setup config version");
        ensure!(
            file.device == expected_device,
            "setup config device differs from this agent"
        );
        ensure!(
            (1..=MAX_ROUNDS).contains(&file.rounds.len()),
            "setup config needs 1..=4 rounds"
        );
        let store = Arc::new(IdentityStore::open(
            &file.identity_store,
            protection(file.protection)?,
            file.fleet,
            &file.device,
        )?);
        let fingerprint = Fingerprint::parse_hex(&file.peer.fingerprint)?;
        let peer = store
            .peers()?
            .into_iter()
            .find(|p| p.device() == file.peer.device)
            .context("setup peer is not enrolled")?;
        ensure!(
            peer.fingerprint(file.fleet)? == fingerprint,
            "setup peer fingerprint differs from the enrolled key"
        );
        let slot = match file.peer.slot {
            SlotFile::Primary => EndpointSlot::Primary,
            SlotFile::Fallback => EndpointSlot::Fallback,
        };
        ensure!(
            store
                .endpoints_for(&file.peer.device)?
                .iter()
                .any(|e| e.slot() == slot),
            "configured setup endpoint slot is missing"
        );
        let profile = match file.peer.profile {
            ProfileFile::Rotating => LeaseProfile::Rotating,
            ProfileFile::SingleOwner => LeaseProfile::SingleOwner,
        };
        let lease_clock = match file.lease_authority {
            None => None,
            Some(LeaseAuthorityFile::SingleOwnerSystemClock { uncertainty_ms }) => {
                ensure!(
                    profile == LeaseProfile::SingleOwner,
                    "local clock approval requires single-owner profile"
                );
                Some(ApprovedLocalClock::single_owner_system_clock(
                    uncertainty_ms,
                )?)
            }
        };
        ensure!(
            !file.data_routes || lease_clock.is_some(),
            "DATA routes require explicit local lease authority"
        );
        let transfer = match file.transfer {
            None => None,
            Some(t) => {
                ensure!(
                    file.data_routes && lease_clock.is_some(),
                    "transfer requires DATA routes and local lease authority"
                );
                ensure!(
                    (1..=8).contains(&t.window_chunks),
                    "invalid transfer window"
                );
                if let Some(db) = &t.host_db {
                    ensure!(
                        db.is_absolute() && !db.as_os_str().is_empty(),
                        "transfer host database must be an absolute local path"
                    );
                }
                ensure!(
                    t.host_db.is_some() || !file.rounds.iter().any(|r| r.role == RoleFile::Target),
                    "target rounds require a local host database"
                );
                let has_target = file.rounds.iter().any(|r| r.role == RoleFile::Target);
                if let Some(interval) = t.retained_checkpoint_bytes {
                    ensure!(
                        has_target
                            && !t.linux_anonymous_stage
                            && (65536..=1u64 << 30).contains(&interval),
                        "retained checkpoints require a named target and bounded interval"
                    );
                    ensure!(
                        !file.rounds.iter().any(|r| r.recovery.is_some()),
                        "fresh checkpoint opt-in cannot be mixed with recovery rounds"
                    );
                }
                #[cfg(not(target_os = "linux"))]
                ensure!(
                    !t.linux_anonymous_stage,
                    "linuxAnonymousStage is Linux-only"
                );
                // An anonymous Linux stage may now carry a REPLACEMENT round, but
                // only when the job itself binds the authorized pre-image; the
                // publish step re-hashes the live destination against it inside the
                // retained gate and links once under a reserved name before an
                // atomic rename.
                ensure!(
                    !t.linux_anonymous_stage
                        || (has_target
                            && !file.rounds.iter().any(|r| {
                                r.role == RoleFile::Target
                                    && r.job.overwrite
                                    && r.job.pre_image_sha256.is_none()
                            })),
                    "anonymous stage requires no-clobber rounds or a replacement with its pre-image"
                );
                #[cfg(target_os = "linux")]
                ensure!(
                    !has_target
                        || t.linux_anonymous_stage
                        || file
                            .rounds
                            .iter()
                            .filter(|r| r.role == RoleFile::Target)
                            .all(|r| r.recovery.is_some()),
                    "Linux target requires explicit linuxAnonymousStage approval"
                );
                if let Some(root) = &t.create_parents_below {
                    ensure!(
                        file.rounds.iter().any(|r| r.role == RoleFile::Target),
                        "parent creation needs a local target round"
                    );
                    super::fence::local_path(root)?;
                    #[cfg(not(any(windows, target_os = "linux")))]
                    anyhow::bail!("target parent creation is unsupported on this platform");
                    #[cfg(any(windows, target_os = "linux"))]
                    super::identity::open_private(root, true)
                        .context("parent creation requires an existing private root")?;
                }
                Some(TransferPlan {
                    window_chunks: t.window_chunks,
                    retained_checkpoint_bytes: t.retained_checkpoint_bytes,
                    linux_anonymous_stage: t.linux_anonymous_stage,
                    #[cfg(any(windows, target_os = "linux"))]
                    host_db: t.host_db,
                    create_parents_below: t.create_parents_below,
                    mcp: t.mcp,
                })
            }
        };
        let local = device_digest(&file.device)?;
        let mut seen = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        let mut bindings = std::collections::HashSet::new();
        let mut rounds = Vec::with_capacity(file.rounds.len());
        for round in file.rounds {
            ensure!(
                !round.id.is_nil() && ids.insert(round.id),
                "nil or duplicate setup round id"
            );
            ensure!(
                round.source_session != round.target_session,
                "setup sessions must differ"
            );
            ensure!(
                round.chunk_bytes > 0 && round.chunk_bytes as usize <= MAX_DATA,
                "invalid setup chunk size"
            );
            ensure!(
                round.job.route == RoutePolicy::RelayOnly,
                "setup requires relay-only"
            );
            ensure!(round.job.fleet_id == file.fleet, "setup job fleet mismatch");
            let (mine, theirs) = match round.role {
                RoleFile::Source => (round.job.source_device, round.job.target_device),
                RoleFile::Target => (round.job.target_device, round.job.source_device),
            };
            ensure!(mine == local, "setup role differs from configured device");
            ensure!(
                theirs == device_digest(&file.peer.device)?,
                "setup peer differs from job peer"
            );
            ensure!(
                seen.insert(round.job.digest()?),
                "duplicate setup job digest"
            );

            ensure!(
                bindings.insert((round.authorization_id, round.key_epoch)),
                "duplicate setup binding"
            );
            if round.role == RoleFile::Target
                && let Some(root) = transfer.as_ref().and_then(|t| t.create_parents_below())
            {
                super::target_directories::validate_scope(
                    root,
                    Path::new(&round.job.destination_path),
                )?;
            }
            let proposal = round.materialize(profile)?;
            if let Some(recovery) = &round.recovery {
                let plan = transfer
                    .as_ref()
                    .context("recovery requires explicit transfer configuration")?;
                ensure!(
                    !plan.mcp && plan.create_parents_below.is_none() && !plan.linux_anonymous_stage,
                    "recovery needs existing parents, named stage and automatic stock pump"
                );
                recovery.validate(round.role, &proposal)?;
            }
            if let Some(clock) = &lease_clock {
                clock.validate_grant(&proposal)?;
            }
            rounds.push(ProvisionedRound {
                id: round.id,
                role: round.role,
                proposal,
                recovery: round.recovery,
            });
        }
        Ok(Self {
            store,
            peer: ConfiguredSetupPeer {
                device: file.peer.device,
                fingerprint,
                slot,
                profile,
            },
            rounds,
            lease_clock,
            data_routes: file.data_routes,
            transfer,
        })
    }
    pub(crate) fn validate_route_origin(&self, relay: &str) -> Result<()> {
        if !self.data_routes {
            return Ok(());
        }
        let actual = crate::transport::relay_url(relay)?;
        ensure!(actual.path() == "/", "DATA relay must be origin URL");
        let endpoint = self
            .store
            .endpoints_for(&self.peer.device)?
            .into_iter()
            .find(|e| e.slot() == self.peer.slot)
            .context("DATA endpoint missing")?;
        ensure!(
            crate::transport::relay_url(endpoint.url())? == actual,
            "DATA relay differs from approved endpoint"
        );
        Ok(())
    }
    pub(crate) fn data_routes_requested(&self) -> bool {
        self.data_routes
    }
    pub(crate) fn transfer(&self) -> Option<&TransferPlan> {
        self.transfer.as_ref()
    }
    /// Public boolean for the binary entrypoint: does this local file request the
    /// preapproved-round MCP transfer surface? No grant/path detail is exposed.
    pub fn mcp_transfer_requested(&self) -> bool {
        self.transfer.as_ref().is_some_and(|t| t.mcp)
    }
    pub(crate) fn recovery(&self, id: Uuid) -> Option<&RecoveryPlan> {
        self.rounds
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.recovery.as_ref())
    }
    pub(crate) fn prepare_resume_route(
        &self,
        runtime: &Arc<crate::runtime::Runtime>,
        id: Uuid,
        prepared: PreparedSetup,
    ) -> Result<super::resume_route::PendingResumeRoute> {
        let clock = self
            .lease_clock
            .as_ref()
            .context("no local resume lease authority")?;
        let (_, _, local) = self
            .rounds()?
            .into_iter()
            .find(|(round, _, _)| *round == id)
            .context("unknown resume round")?;
        clock.validate_grant(&local.proposal)?;
        let condition = self
            .recovery(id)
            .context("no local recovery selection")?
            .condition(&local.proposal)?;
        super::resume_route::PendingResumeRoute::begin(runtime, id, prepared, local, condition)
    }
    pub(crate) fn authenticate_resumed_route(
        &self,
        runtime: &Arc<crate::runtime::Runtime>,
        pending: super::resume_route::PendingResumeRoute,
        digest: [u8; 32],
        proofs: super::resume_route::ResumeRouteProofs,
        ticket: Zeroizing<String>,
    ) -> Result<super::setup_resume::ResumeSetupLease> {
        pending.finish(
            runtime,
            digest,
            proofs,
            ticket,
            self.lease_clock
                .as_ref()
                .context("no local resume lease authority")?
                .anchor()?,
        )
    }
    pub(crate) fn lease_requested(&self) -> bool {
        self.lease_clock.is_some()
    }
    /// Separate LOCAL opt-in; neither the proof nor the relay can provide time.
    pub(crate) fn authenticate_prepared(
        &self,
        runtime: &Arc<crate::runtime::Runtime>,
        id: Uuid,
        prepared: PreparedSetup,
    ) -> Result<SetupLease> {
        let clock = self
            .lease_clock
            .as_ref()
            .context("no local lease authority configured")?;
        let round = self
            .rounds
            .iter()
            .find(|r| r.id == id)
            .context("unknown local setup round")?;
        clock.validate_grant(&round.proposal)?;
        let local = LocalSetupApproval {
            identity: self.store.clone(),
            proposal: round.proposal.clone(),
            peer: ConfiguredSetupPeer {
                device: self.peer.device.clone(),
                fingerprint: self.peer.fingerprint.clone(),
                slot: self.peer.slot,
                profile: self.peer.profile,
            },
            now: Arc::new(|| {
                u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
                    .context("local clock overflow")
            }),
        };
        let role = match round.role {
            RoleFile::Source => super::protocol::Direction::SourceToTarget,
            RoleFile::Target => super::protocol::Direction::TargetToSource,
        };
        runtime.authenticate_fleet_setup(prepared, local, role, clock.anchor()?)
    }

    /// Materialize the EXACT locally provisioned grant. Connection/reconnect
    /// cannot mint identifiers, move its issuance time or extend its deadline.
    pub fn rounds(&self) -> Result<Vec<(Uuid, RoleFile, LocalSetupApproval)>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("local clock before epoch")?
            .as_millis();
        let now = u64::try_from(now).context("local clock overflow")?;
        let authority: Arc<ApprovedSetupNow> = Arc::new(|| {
            let ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
            u64::try_from(ms).context("local clock overflow")
        });
        let mut out = Vec::with_capacity(self.rounds.len());
        for round in &self.rounds {
            ensure!(
                now >= round.proposal.grant().issued_at_ms
                    && now < round.proposal.grant().expires_at_ms,
                "local setup time outside fixed grant lease"
            );
            let proposal = round.proposal.clone();
            out.push((
                round.id,
                round.role,
                LocalSetupApproval {
                    identity: self.store.clone(),
                    proposal,
                    peer: ConfiguredSetupPeer {
                        device: self.peer.device.clone(),
                        fingerprint: self.peer.fingerprint.clone(),
                        slot: self.peer.slot,
                        profile: self.peer.profile,
                    },
                    now: authority.clone(),
                },
            ));
        }
        Ok(out)
    }
}
