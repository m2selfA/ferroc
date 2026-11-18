//! Same-process routing bookkeeping ONLY. Not peer signature/IO authorization.
use super::{
    protocol::device_digest,
    setup::{SetupConfirmation, SetupOffer, SetupResponse},
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;
pub(crate) const MAX_ACTIVE: usize = 16;
pub(crate) const MAX_PER_DEVICE: usize = 4;
pub(crate) const MAX_HISTORY: usize = 64;
const SETUP_TTL: Duration = Duration::from_secs(30);

/// Device/generation is selected by the relay, never copied from message data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub device: String,
    pub generation: String,
}
impl Peer {
    pub fn new(device: &str, generation: &str) -> Result<Self> {
        device_digest(device)?;
        ensure!(
            !generation.is_empty()
                && generation.len() <= 128
                && generation
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c)),
            "invalid native connection generation"
        );
        Ok(Self {
            device: device.into(),
            generation: generation.into(),
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Offer,
    Response,
    Confirmation,
}
impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Response => "response",
            Self::Confirmation => "confirmation",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Response,
    Confirmation,
    FinalQueued,
}
struct Entry {
    source: Peer,
    target: Peer,
    deadline: Instant,
    phase: Phase,
    offer_digest: [u8; 32],
    response_digest: Option<[u8; 32]>,
}
#[derive(Default)]
struct Table {
    active: HashMap<Uuid, Entry>,
    ids: HashSet<Uuid>,
    bindings: HashSet<[u8; 32]>,
    jobs: HashSet<[u8; 32]>,
}
impl Table {
    fn expire(&mut self, now: Instant) {
        self.active.retain(|_, v| now < v.deadline);
    }
    fn used(&self, device: &str) -> usize {
        self.active
            .values()
            .filter(|v| v.source.device == device || v.target.device == device)
            .count()
    }
}
pub(crate) struct SetupBroker {
    scope: Uuid,
    table: Mutex<Table>,
}
impl Default for SetupBroker {
    fn default() -> Self {
        Self {
            scope: Uuid::new_v4(),
            table: Mutex::new(Table::default()),
        }
    }
}
/// One queued message. Not Clone/Deserialize; admission is never retransmission.
pub(crate) struct Delivery {
    id: Uuid,
    from: Peer,
    to: Peer,
    stage: Stage,
    payload: String,
}
impl Delivery {
    pub fn recipient(&self) -> &Peer {
        &self.to
    }
    pub fn sender(&self) -> &Peer {
        &self.from
    }
    pub fn frame(&self) -> serde_json::Value {
        serde_json::json!({"type":"fleetSetup","id":self.id,"fromDevice":self.from.device,"stage":self.stage.name(),"payload":self.payload})
    }
}
impl SetupBroker {
    pub fn scope(&self) -> Uuid {
        self.scope
    }
    #[cfg(test)]
    pub fn counts(&self) -> (usize, usize) {
        let t = self.table.lock().unwrap();
        (t.active.len(), t.ids.len())
    }
    pub fn offer(
        &self,
        id: Uuid,
        source: Peer,
        target: Peer,
        payload: String,
        now: Instant,
    ) -> Result<Delivery> {
        ensure!(!id.is_nil(), "nil setup id");
        let offer = SetupOffer::decode(payload.as_bytes())?;
        // Structural hashing of UNTRUSTED declared profile, NOT local peer policy.
        let (binding, offer_digest) = offer.routing_context()?;
        ensure!(
            binding.source_device == device_digest(&source.device)?
                && binding.target_device == device_digest(&target.device)?,
            "setup routing device mismatch"
        );
        let key: [u8; 32] = Sha256::digest(binding.bytes()).into();
        let job = offer.offered_job().digest()?;
        let mut table = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("setup registry poisoned"))?;
        table.expire(now);
        ensure!(
            !table.ids.contains(&id)
                && !table.bindings.contains(&key)
                && !table.jobs.contains(&job),
            "setup id/binding already spent"
        );
        ensure!(
            table.ids.len() < MAX_HISTORY && table.bindings.len() < MAX_HISTORY,
            "setup replay history full"
        );
        ensure!(
            table.active.len() < MAX_ACTIVE
                && table.used(&source.device) < MAX_PER_DEVICE
                && table.used(&target.device) < MAX_PER_DEVICE,
            "setup inflight capacity full"
        );
        let deadline = now
            .checked_add(SETUP_TTL)
            .ok_or_else(|| anyhow::anyhow!("setup routing deadline overflow"))?;
        table.ids.insert(id);
        table.bindings.insert(key);
        table.jobs.insert(job);
        table.active.insert(
            id,
            Entry {
                source: source.clone(),
                target: target.clone(),
                deadline,
                phase: Phase::Response,
                offer_digest,
                response_digest: None,
            },
        );
        Ok(Delivery {
            id,
            from: source,
            to: target,
            stage: Stage::Offer,
            payload,
        })
    }
    pub fn response(
        &self,
        id: Uuid,
        sender: &Peer,
        payload: String,
        now: Instant,
    ) -> Result<Delivery> {
        self.advance(id, sender, Stage::Response, payload, now)
    }
    pub fn confirmation(
        &self,
        id: Uuid,
        sender: &Peer,
        payload: String,
        now: Instant,
    ) -> Result<Delivery> {
        self.advance(id, sender, Stage::Confirmation, payload, now)
    }
    fn advance(
        &self,
        id: Uuid,
        sender: &Peer,
        stage: Stage,
        payload: String,
        now: Instant,
    ) -> Result<Delivery> {
        let mut table = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("setup registry poisoned"))?;
        table.expire(now);
        let entry = table
            .active
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("setup absent/expired"))?;
        let (expected, to) = match stage {
            Stage::Response => (&entry.target, &entry.source),
            Stage::Confirmation => (&entry.source, &entry.target),
            Stage::Offer => anyhow::bail!("invalid setup phase"),
        };
        // A foreign/stale generation cannot destroy another connection's owner.
        ensure!(sender == expected, "wrong setup role/generation");
        let to = to.clone();
        let result = (|| -> Result<()> {
            match stage {
                Stage::Response => {
                    ensure!(
                        entry.phase == Phase::Response,
                        "setup response out of order"
                    );
                    let r = SetupResponse::decode(payload.as_bytes())?;
                    let (offered, digest) = r.routing_context()?;
                    ensure!(
                        offered == entry.offer_digest,
                        "response belongs to another setup offer"
                    );
                    entry.response_digest = Some(digest);
                    entry.phase = Phase::Confirmation;
                }
                Stage::Confirmation => {
                    ensure!(
                        entry.phase == Phase::Confirmation,
                        "setup confirmation out of order"
                    );
                    let c = SetupConfirmation::decode(payload.as_bytes())?;
                    ensure!(
                        Some(c.routing_response_digest()?) == entry.response_digest,
                        "confirmation belongs to another response"
                    );
                    entry.phase = Phase::FinalQueued;
                }
                Stage::Offer => unreachable!(),
            };
            Ok(())
        })();
        if let Err(e) = result {
            table.active.remove(&id);
            return Err(e);
        }
        Ok(Delivery {
            id,
            from: sender.clone(),
            to,
            stage,
            payload,
        })
    }
    /// Recheck before the actual WS send. Accepted queued messages need not match
    /// the latest phase: a peer may already have reacted to an earlier delivery.
    pub fn delivery_allowed(&self, d: &Delivery, now: Instant) -> Result<()> {
        let mut table = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("setup registry poisoned"))?;
        table.expire(now);
        let e = table
            .active
            .get(&d.id)
            .ok_or_else(|| anyhow::anyhow!("setup absent/expired"))?;
        let good = match d.stage {
            Stage::Offer | Stage::Confirmation => d.from == e.source && d.to == e.target,
            Stage::Response => d.from == e.target && d.to == e.source,
        };
        ensure!(good, "setup delivery generation mismatch");
        Ok(())
    }
    /// Queue/write failure terminates this route. Keep replay history; no retry.
    pub fn failed(&self, d: &Delivery) {
        if let Ok(mut t) = self.table.lock() {
            t.active.remove(&d.id);
        }
    }
    /// OS write completion is NOT remote processing/consent/file completion.
    pub fn sent(&self, d: &Delivery) {
        if d.stage == Stage::Confirmation {
            self.failed(d)
        }
    }
    pub fn disconnected(&self, p: &Peer) {
        if let Ok(mut t) = self.table.lock() {
            t.active.retain(|_, v| &v.source != p && &v.target != p);
        }
    }
    pub fn expire(&self, now: Instant) {
        if let Ok(mut t) = self.table.lock() {
            t.expire(now);
        }
    }
}

#[cfg(test)]
#[path = "setup_broker_tests.rs"]
pub(crate) mod tests;
