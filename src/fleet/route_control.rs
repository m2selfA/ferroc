//! Explicit LOCAL relay routing approvals. Not file/grant issuance or proof of
//! peer lease installation. Both authenticated current sockets must present.
use super::{
    job::{LeaseProfile, ValidatedGrant},
    protocol::device_digest,
    relay_channel::FleetRelay,
    setup_broker::Peer,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;
const MAX_APPROVALS: usize = 16;
const PRESENT_TTL: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct File {
    version: u16,
    approvals: Vec<ApprovalFile>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalFile {
    source_device_id: String,
    target_device_id: String,
    round: super::setup_config::RoundFile,
    profile: Profile,
    ttl_ms: u64,
    resume_condition_digest: Option<[u8; 32]>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Profile {
    SingleOwner,
}
struct Approval {
    id: Uuid,
    devices: [String; 2],
    grant: ValidatedGrant,
    ttl: Duration,
    resume_condition_digest: Option<[u8; 32]>,
}
/// A strict local file is an OPERATOR route decision, not something a remote
/// message may deserialize into authority. No tokens/keys or automatic reload.
pub struct ApprovedDataRoutes {
    entries: Vec<Approval>,
}
impl ApprovedDataRoutes {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = super::setup_config::read_bounded(path)?;
        let file: File = serde_json::from_slice(&raw).context("invalid local DATA approvals")?;
        ensure!(
            file.version == 1 && (1..=MAX_APPROVALS).contains(&file.approvals.len()),
            "invalid DATA approval version/capacity"
        );
        let (mut ids, mut grants, mut jobs) = (HashSet::new(), HashSet::new(), HashSet::new());
        let mut entries = Vec::new();
        for a in file.approvals {
            let Profile::SingleOwner = a.profile;
            ensure!(
                a.round.role == super::setup_config::RoleFile::Source,
                "local DATA approval requires source round description"
            );
            let grant = a.round.materialize(LeaseProfile::SingleOwner)?;
            let local_resume = a.round.recovery_condition(&grant)?.map(|c| c.digest());
            if let (Some(explicit), Some(computed)) = (a.resume_condition_digest, local_resume) {
                ensure!(explicit == computed, "local DATA recovery digest mismatch");
            }
            let resume_condition_digest = a.resume_condition_digest.or(local_resume);
            let id = a.round.id;
            ensure!(
                !id.is_nil()
                    && ids.insert(id)
                    && grants.insert(grant.digest())
                    && jobs.insert(grant.job().digest()?),
                "duplicate/nil DATA approval"
            );
            ensure!(
                device_digest(&a.source_device_id)? == grant.job().source_device
                    && device_digest(&a.target_device_id)? == grant.job().target_device,
                "DATA approval device mismatch"
            );
            ensure!(
                grant.job().route == super::job::RoutePolicy::RelayOnly
                    && (1..=300000).contains(&a.ttl_ms),
                "invalid DATA routing policy/TTL"
            );
            entries.push(Approval {
                id,
                devices: [a.source_device_id, a.target_device_id],
                grant,
                ttl: Duration::from_millis(a.ttl_ms),
                resume_condition_digest,
            });
        }
        Ok(Self { entries })
    }
}
struct Entry {
    approval: Approval,
    peers: [Option<Peer>; 2],
    until: Option<Instant>,
    activated: bool,
    failed: bool,
    delivered: [bool; 2],
    resume: [Option<super::resume_route::RoleResumeProof>; 2],
}
pub(crate) struct RouteControl {
    scope: Uuid,
    fleet: Arc<FleetRelay>,
    entries: Mutex<HashMap<Uuid, Entry>>,
}
/// Sensitive one-shot delivery; never Clone/Debug/Serialize or logged.
pub(crate) struct RouteDelivery {
    id: Uuid,
    role: usize,
    recipient: Peer,
    digest: [u8; 32],
    secret: Zeroizing<String>,
    resume: Option<super::resume_route::ResumeRouteProofs>,
}
impl RouteDelivery {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn recipient(&self) -> &Peer {
        &self.recipient
    }
    pub fn frame(&self) -> serde_json::Value {
        let mut frame = serde_json::json!({"type":"fleetRoute","id":self.id,"grantDigest":self.digest,"ticket":self.secret.as_str()});
        if let Some(proofs) = &self.resume {
            frame["resume"] = serde_json::to_value(proofs).expect("public resume proofs serialize");
        }
        frame
    }
}
impl RouteControl {
    pub fn new(scope: Uuid, fleet: Arc<FleetRelay>, local: ApprovedDataRoutes) -> Self {
        Self {
            scope,
            fleet,
            entries: Mutex::new(
                local
                    .entries
                    .into_iter()
                    .map(|a| {
                        (
                            a.id,
                            Entry {
                                approval: a,
                                peers: [None, None],
                                until: None,
                                activated: false,
                                failed: false,
                                delivered: [false, false],
                                resume: [None, None],
                            },
                        )
                    })
                    .collect(),
            ),
        }
    }
    pub fn scope(&self) -> Uuid {
        self.scope
    }
    #[cfg(test)]
    pub fn present(
        &self,
        id: Uuid,
        digest: [u8; 32],
        actor: Peer,
        now: Instant,
    ) -> Result<Option<[RouteDelivery; 2]>> {
        self.present_resume(id, digest, actor, now, None)
    }
    pub(crate) fn present_resume(
        &self,
        id: Uuid,
        digest: [u8; 32],
        actor: Peer,
        now: Instant,
        resume: Option<super::resume_route::RoleResumeProof>,
    ) -> Result<Option<[RouteDelivery; 2]>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("DATA control poisoned"))?;
        let e = entries
            .get_mut(&id)
            .context("DATA route not locally approved")?;
        // Do not let a foreign device invalidate another pair.
        let role = e
            .approval
            .devices
            .iter()
            .position(|d| d == &actor.device)
            .context("DATA presenter not approved")?;
        ensure!(
            digest == e.approval.grant.digest(),
            "DATA grant differs from local approval"
        );
        ensure!(
            !e.failed && !e.activated && e.peers[role].is_none(),
            "DATA approval/presentation spent"
        );
        if let Some(until) = e.until
            && now >= until
        {
            e.failed = true;
            anyhow::bail!("DATA presentation expired");
        }
        match (&resume, e.approval.resume_condition_digest) {
            (None, None) => {}
            (Some(proof), Some(expected)) => {
                proof.validate()?;
                ensure!(
                    proof.condition_digest == expected,
                    "DATA resume condition differs from local approval"
                );
            }
            _ => anyhow::bail!("DATA fresh/resume mode differs from local approval"),
        }
        e.resume[role] = resume;
        e.until = Some(
            e.until.unwrap_or(
                now.checked_add(PRESENT_TTL)
                    .context("DATA presentation deadline overflow")?,
            ),
        );
        e.peers[role] = Some(actor);
        let [Some(source), Some(target)] = &e.peers else {
            return Ok(None);
        };
        let peers = [source.clone(), target.clone()];
        // No implicit approval, no grant from the wire. Failure is consumed too.
        e.failed = true;
        let tickets = self.fleet.approve_local(
            &e.approval.grant,
            &e.approval.devices[0],
            &e.approval.devices[1],
            e.approval.ttl,
        )?;
        e.activated = true;
        e.failed = false;
        e.until = Some(
            now.checked_add(e.approval.ttl)
                .context("DATA route deadline overflow")?,
        );
        let resume = match &e.resume {
            [Some(a), Some(b)] => Some(super::resume_route::ResumeRouteProofs {
                condition_digest: a.condition_digest,
                source_signature: a.signature.clone(),
                target_signature: b.signature.clone(),
            }),
            [None, None] => None,
            _ => anyhow::bail!("DATA resume presentation incomplete"),
        };
        let make = |role: usize, secret: &str| RouteDelivery {
            id,
            role,
            recipient: peers[role].clone(),
            digest,
            secret: Zeroizing::new(secret.to_owned()),
            resume: resume.clone(),
        };
        Ok(Some([
            make(0, tickets.source.expose_secret()),
            make(1, tickets.target.expose_secret()),
        ]))
    }
    pub fn peers(&self, id: Uuid) -> Result<[Peer; 2]> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("DATA control poisoned"))?;
        let e = entries.get(&id).context("DATA route missing")?;
        let [Some(a), Some(b)] = &e.peers else {
            anyhow::bail!("DATA peers incomplete")
        };
        Ok([a.clone(), b.clone()])
    }
    pub fn may_deliver(&self, d: &RouteDelivery, now: Instant) -> Result<()> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("DATA control poisoned"))?;
        let e = entries.get(&d.id).context("DATA route missing")?;
        ensure!(
            e.activated
                && !e.failed
                && !e.delivered[d.role]
                && e.until.is_some_and(|u| now < u)
                && e.peers[d.role].as_ref() == Some(&d.recipient),
            "DATA ticket delivery expired/stale/spent"
        );
        Ok(())
    }
    pub fn sent(&self, d: &RouteDelivery) {
        if let Ok(mut entries) = self.entries.lock()
            && let Some(e) = entries.get_mut(&d.id)
        {
            e.delivered[d.role] = true;
        }
    }
    pub fn failed(&self, id: Uuid) {
        if let Ok(mut entries) = self.entries.lock()
            && let Some(e) = entries.get_mut(&id)
        {
            e.failed = true;
            self.fleet.close_grant(&e.approval.grant);
        }
    }
    pub fn disconnected(&self, peer: &Peer) {
        if let Ok(mut entries) = self.entries.lock() {
            for e in entries.values_mut() {
                if e.peers.iter().any(|p| p.as_ref() == Some(peer)) {
                    e.failed = true;
                    self.fleet.close_grant(&e.approval.grant);
                }
            }
        }
    }
}
#[cfg(test)]
#[path = "route_control_tests.rs"]
mod tests;
