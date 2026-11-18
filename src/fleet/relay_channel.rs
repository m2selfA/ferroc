//! Explicit LOCAL routing approval and bounded opaque relay on the existing
//! Relay listener/Store. This is not grant issuance, key exchange or decryption.
use super::{
    job::{RoutePolicy, ValidatedGrant},
    protocol::{Binding, Direction, Frame, Kind, MAX_FRAME, device_digest},
};
use crate::relay::{ApiError, Relay, WebResult, bearer, hash};
use anyhow::{Context, Result, ensure};
use axum::{
    Extension, Router,
    body::Bytes,
    extract::{
        OriginalUri, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use uuid::Uuid;
const MAX_PAIRS: usize = 16;
const MAX_APPROVALS: usize = 64;
const QUEUE: usize = 8;
const IO_BUDGET: Duration = Duration::from_secs(5);

// A permit tracks transport ownership only, not peer read/crypto/file proof.
// A synchronous watch modification serializes admission with the EOF cut.
#[derive(Clone, Copy, Default)]
struct ForwardState {
    closing: bool,
    pending: [usize; 2],
}
struct ForwardGate {
    state: watch::Sender<ForwardState>,
}
impl ForwardGate {
    fn new() -> Self {
        Self {
            state: watch::channel(ForwardState::default()).0,
        }
    }
    fn admit(&self, role: usize) -> Option<ForwardPermit> {
        let mut admitted = false;
        self.state.send_modify(|state| {
            if !state.closing {
                state.pending[role] += 1;
                admitted = true;
            }
        });
        admitted.then(|| ForwardPermit {
            state: self.state.clone(),
            role,
        })
    }
    fn begin_drain(&self) {
        self.state.send_modify(|state| state.closing = true);
    }
    async fn drained(&self, role: usize) -> Result<()> {
        let mut state = self.state.subscribe();
        loop {
            let empty = state.borrow_and_update().pending[role] == 0;
            if empty {
                return Ok(());
            }
            state
                .changed()
                .await
                .context("fleet forwarding ownership closed")?;
        }
    }
}
struct ForwardPermit {
    state: watch::Sender<ForwardState>,
    role: usize,
}
impl Drop for ForwardPermit {
    fn drop(&mut self) {
        self.state
            .send_modify(|state| state.pending[self.role] -= 1);
    }
}
struct ForwardFrame {
    bytes: Bytes,
    permit: ForwardPermit,
}

/// Credential has no Debug/Serialize. Expose only to the authenticated client;
/// do not log it, put it in a URL or treat it as filesystem authorization.
/// ```compile_fail
/// fn no_debug(t:ferroc::fleet::relay_channel::JoinTicket){let _=format!("{t:?}");}
/// ```
/// ```compile_fail
/// fn no_serialize(t:ferroc::fleet::relay_channel::JoinTicket){let _=serde_json::to_vec(&t);}
/// ```
pub struct JoinTicket(zeroize::Zeroizing<String>);
impl JoinTicket {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}
pub struct JoinTickets {
    pub source: JoinTicket,
    pub target: JoinTicket,
}
const MAX_ADVANCES: usize = 1024;
pub(super) struct Route {
    pub binding: Binding,
    pub chunk: u32,
    pub total: u64,
    job_digest: [u8; 32],
    seen: HashSet<(Uuid, Uuid)>,
    /// Superseded binding, still routable until BOTH roles have been observed
    /// on the current one.
    ///
    /// Adoption is a local decision, but frames sealed under the old binding may
    /// still be queued in the relay when it happens; dropping them kills a live
    /// transfer (observed: `fleet receive failed`). So the old binding retires on
    /// delivery order — the moment both roles have sent a current-binding frame
    /// — not on a timer, and never more than one generation back.
    // One lock keeps previous-binding and role observations coherent. No lock
    // is held across await; unlike RefCell/Cell this route can be borrowed by a
    // Send future in the background task executor.
    retirement: Mutex<Retirement>,
}
#[derive(Clone, Default)]
struct Retirement {
    binding: Option<Binding>,
    switched: u8,
}
impl Clone for Route {
    fn clone(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            chunk: self.chunk,
            total: self.total,
            job_digest: self.job_digest,
            seen: self.seen.clone(),
            retirement: Mutex::new(self.retirement.lock().expect("fleet retirement").clone()),
        }
    }
}
impl Route {
    pub(super) fn from_grant(g: &ValidatedGrant) -> Self {
        let binding = g.grant().binding.clone();
        let mut seen = HashSet::new();
        seen.insert((binding.authorization_id, binding.key_epoch));
        Self {
            binding,
            chunk: g.grant().chunk_bytes,
            total: g.job().bytes_total,
            job_digest: g.grant().job_digest,
            seen,
            retirement: Mutex::new(Retirement::default()),
        }
    }
    /// Explicit successor binding only. Stable routing identity, job parameters,
    /// chunk ceiling and total stay fixed; authorization/key epoch must rotate.
    /// Opaque relay still cannot verify the renewal signature or trusted time.
    pub(super) fn advance(&mut self, next: &ValidatedGrant) -> Result<()> {
        self.validate_successor(next)?;
        let key = (
            next.grant().binding.authorization_id,
            next.grant().binding.key_epoch,
        );
        self.seen.insert(key);
        // Keep the superseded binding routable for frames already in flight, but
        // only until both roles show up on the new one.
        let old = std::mem::replace(&mut self.binding, next.grant().binding.clone());
        *self
            .retirement
            .get_mut()
            .map_err(|_| anyhow::anyhow!("fleet retirement poisoned"))? = Retirement {
            binding: Some(old),
            switched: 0,
        };
        self.chunk = next.grant().chunk_bytes;
        Ok(())
    }
    /// Every rule a successor must satisfy to replace this binding. Separate so
    /// an offer can be checked without adopting it.
    fn validate_successor(&self, next: &ValidatedGrant) -> Result<()> {
        ensure!(
            next.job().route == RoutePolicy::RelayOnly,
            "renewal requires relay-only job"
        );
        ensure!(
            next.grant().job_digest == self.job_digest,
            "renewal changes job parameters or deadline"
        );
        let n = &next.grant().binding;
        ensure!(
            n.fleet_id == self.binding.fleet_id
                && n.source_device == self.binding.source_device
                && n.target_device == self.binding.target_device
                && n.source_session == self.binding.source_session
                && n.target_session == self.binding.target_session
                && n.transfer_id == self.binding.transfer_id
                && n.file_id == self.binding.file_id,
            "renewal changes stable routing identity"
        );
        ensure!(
            n.authorization_id != self.binding.authorization_id
                && n.key_epoch != self.binding.key_epoch,
            "renewal must rotate authorization and key epoch"
        );
        ensure!(
            next.grant().chunk_bytes <= self.chunk && next.job().bytes_total == self.total,
            "renewal expands chunk ceiling or total"
        );
        ensure!(
            !self.seen.contains(&(n.authorization_id, n.key_epoch)),
            "renewal reuses an earlier binding"
        );
        ensure!(self.seen.len() < MAX_ADVANCES, "renewal history exhausted");
        Ok(())
    }
    pub(super) fn validate(&self, bytes: &[u8], role: Direction) -> Result<()> {
        let f = Frame::decode(bytes)?;
        ensure!(
            f.header.direction == role,
            "fleet routing direction mismatch"
        );
        let role_bit = match role {
            Direction::SourceToTarget => 1u8,
            Direction::TargetToSource => 2u8,
        };
        if f.header.binding == self.binding {
            let mut retirement = self
                .retirement
                .lock()
                .map_err(|_| anyhow::anyhow!("fleet retirement poisoned"))?;
            retirement.switched |= role_bit;
            if retirement.switched == 3 {
                // Both roles are on the current binding; retire only one previous generation.
                retirement.binding = None;
            }
        } else {
            ensure!(
                self.retirement
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fleet retirement poisoned"))?
                    .binding
                    .as_ref()
                    .is_some_and(|old| old == &f.header.binding),
                "fleet routing binding mismatch"
            );
        }
        if f.header.kind == Kind::Data {
            ensure!(
                f.header.plaintext_len <= self.chunk
                    && f.header
                        .offset
                        .checked_add(f.header.plaintext_len as u64)
                        .is_some_and(|n| n <= self.total),
                "fleet DATA outside approved route"
            );
        }
        Ok(())
    }
}
// Bounded observation only, compiled OUT of non-test builds. No timing knobs,
// fault injection, new credentials, global logging or wire-format changes.
#[cfg(test)]
#[derive(Debug, Clone)]
enum RelayTestEvent {
    QueueFull {
        destination: usize,
        at: Instant,
    },
    WritePending {
        destination: usize,
        at: Instant,
    },
    Exit {
        destination: usize,
        at: Instant,
        error: Option<String>,
    },
}
#[cfg(test)]
async fn observe_native_write<F: std::future::Future>(
    pair: &Pair,
    destination: usize,
    sending: F,
) -> F::Output {
    tokio::pin!(sending);
    let mut seen = false;
    std::future::poll_fn(|cx| {
        let polled = sending.as_mut().poll(cx);
        if polled.is_pending() && !seen {
            seen = true;
            let _ = pair.test_events.send(RelayTestEvent::WritePending {
                destination,
                at: Instant::now(),
            });
        }
        polled
    })
    .await
}
/// Upper bound on renewal offers kept per pair. Offers are consumed on use, so
/// this only bounds the memory a peer can pin by offering and never presenting.
const MAX_PENDING_RENEWALS: usize = 8;
struct Pair {
    id: Uuid,
    approval_digest: [u8; 32],
    route: Mutex<Route>,
    devices: [String; 2],
    tokens: Mutex<[Option<String>; 2]>,
    /// Successor grants this pair may present. Structural validation only: the
    /// registry still cannot verify a renewal signature, trusted time or pins,
    /// so this is a routing decision and both peers must authenticate it E2E.
    pending: Mutex<Vec<ValidatedGrant>>,
    /// Which roles have presented the pending successor, by binding digest.
    presented: Mutex<HashMap<[u8; 32], u8>>,
    until: Instant,
    tx: [mpsc::Sender<ForwardFrame>; 2],
    rx: Mutex<[Option<mpsc::Receiver<ForwardFrame>>; 2]>,
    forward: ForwardGate,
    joined: watch::Sender<u8>,
    closed: watch::Sender<bool>,
    #[cfg(test)]
    test_events: tokio::sync::broadcast::Sender<RelayTestEvent>,
}
struct StateTable {
    pairs: HashMap<Uuid, Arc<Pair>>,
    tickets: HashMap<[u8; 32], (Uuid, usize)>,
    spent: HashSet<[u8; 32]>,
    stopped: bool,
}
/// Volatile routing registry: at most16 active pairs and64 lifetime approvals.
/// Creating a new registry is not crypto/session recovery. No auto-TOFU/renewal.
pub struct FleetRelay {
    table: Mutex<StateTable>,
    sockets: Arc<Semaphore>,
}
fn ticket_hash(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}
impl Default for FleetRelay {
    fn default() -> Self {
        Self::new()
    }
}
impl FleetRelay {
    pub fn new() -> Self {
        Self {
            table: Mutex::new(StateTable {
                pairs: HashMap::new(),
                tickets: HashMap::new(),
                spent: HashSet::new(),
                stopped: false,
            }),
            sockets: Arc::new(Semaphore::new(MAX_PAIRS * 2)),
        }
    }
    /// Explicit trusted local routing decision only. Structured grant validation
    /// does NOT prove trusted issuance/pins/time; both peers still need leased E2E
    /// authentication and actual Runtime path policy. TTL is routing lifetime only.
    pub fn approve_local(
        &self,
        g: &ValidatedGrant,
        source: &str,
        target: &str,
        ttl: Duration,
    ) -> Result<JoinTickets> {
        ensure!(
            g.job().route == RoutePolicy::RelayOnly,
            "initial relay candidate requires relay-only job"
        );
        ensure!(
            device_digest(source)? == g.job().source_device
                && device_digest(target)? == g.job().target_device,
            "routing device IDs differ from grant"
        );
        ensure!(
            !ttl.is_zero() && ttl <= Duration::from_secs(300),
            "invalid routing TTL"
        );
        let mut t = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet registry poisoned"))?;
        Self::sweep(&mut t);
        ensure!(
            !t.stopped && t.pairs.len() < MAX_PAIRS && t.spent.len() < MAX_APPROVALS,
            "fleet routing closed/capacity exhausted"
        );
        let digest = g.digest();
        ensure!(
            !t.spent.contains(&digest),
            "routing approval replay forbidden"
        );
        let secret1 = crate::relay::random();
        let secret2 = crate::relay::random();
        let id = Uuid::new_v4();
        let (a, ar) = mpsc::channel(QUEUE);
        let (b, br) = mpsc::channel(QUEUE);
        let (joined, _) = watch::channel(0);
        let (closed, _) = watch::channel(false);
        let pair = Arc::new(Pair {
            id,
            approval_digest: digest,
            route: Mutex::new(Route::from_grant(g)),
            pending: Mutex::new(Vec::new()),
            presented: Mutex::new(HashMap::new()),
            devices: [source.into(), target.into()],
            tokens: Mutex::new([None, None]),
            until: Instant::now()
                .checked_add(ttl)
                .context("routing deadline overflow")?,
            tx: [a, b],
            rx: Mutex::new([Some(ar), Some(br)]),
            forward: ForwardGate::new(),
            joined,
            closed,
            #[cfg(test)]
            test_events: tokio::sync::broadcast::channel(256).0,
        });
        t.spent.insert(digest);
        t.tickets.insert(ticket_hash(&secret1), (id, 0));
        t.tickets.insert(ticket_hash(&secret2), (id, 1));
        t.pairs.insert(id, pair);
        Ok(JoinTickets {
            source: JoinTicket(zeroize::Zeroizing::new(secret1)),
            target: JoinTicket(zeroize::Zeroizing::new(secret2)),
        })
    }
    /// Explicit LOCAL successor approval for this SAME pair. The registry cannot
    /// verify renewal signatures, trusted time or pins; both peers still must
    /// authenticate it E2E. After advancement the superseded binding is rejected,
    /// so a delayed old-epoch frame cannot be routed back in.
    pub fn advance_local(&self, current: &ValidatedGrant, next: &ValidatedGrant) -> Result<()> {
        let mut t = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet registry poisoned"))?;
        Self::sweep(&mut t);
        ensure!(!t.stopped, "fleet routing stopped");
        let id = t
            .pairs
            .iter()
            .find(|(_, p)| {
                p.route
                    .lock()
                    .is_ok_and(|r| r.binding == current.grant().binding)
            })
            .map(|(id, _)| *id)
            .context("no approved route for current binding")?;
        let pair = t.pairs.get(&id).context("fleet pair missing")?.clone();
        ensure!(Instant::now() < pair.until, "fleet route expired");
        pair.route
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet route poisoned"))?
            .advance(next)
    }
    /// Offer a successor grant to this SAME pair from the relay's own control
    /// plane. Nothing is applied here: the pair only holds the offer until both
    /// peers present it through their authenticated sockets, so a renewal the
    /// peers never accept cannot advance routing on its own.
    pub fn offer_renewal(&self, current: &ValidatedGrant, next: &ValidatedGrant) -> Result<()> {
        let mut t = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet registry poisoned"))?;
        Self::sweep(&mut t);
        ensure!(!t.stopped, "fleet routing stopped");
        let id = t
            .pairs
            .iter()
            .find(|(_, p)| {
                p.route
                    .lock()
                    .is_ok_and(|r| r.binding == current.grant().binding)
            })
            .map(|(id, _)| *id)
            .context("no approved route for current binding")?;
        let pair = t.pairs.get(&id).context("fleet pair missing")?.clone();
        ensure!(Instant::now() < pair.until, "fleet route expired");
        // Refuse an offer that could not be adopted, so a peer never holds a
        // "successor" the route would reject later.
        {
            let route = pair
                .route
                .lock()
                .map_err(|_| anyhow::anyhow!("fleet route poisoned"))?;
            let mut probe = route.clone();
            probe.advance(next)?;
        }
        let mut pending = pair
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet renewal offers poisoned"))?;
        ensure!(
            pending.len() < MAX_PENDING_RENEWALS,
            "fleet renewal offers exhausted"
        );
        ensure!(
            !pending
                .iter()
                .any(|p| p.grant().binding == next.grant().binding),
            "duplicate renewal offer"
        );
        pending.push(next.clone());
        Ok(())
    }
    /// Authenticated presentation by one role. Returns whether the route
    /// advanced, and which role presented (0=source, 1=target).
    pub(super) fn present(&self, device: &str, offer: &RenewOffer) -> Result<(bool, usize)> {
        let mut t = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet registry poisoned"))?;
        Self::sweep(&mut t);
        ensure!(!t.stopped, "fleet routing stopped");
        let (id, role) = t
            .pairs
            .iter()
            .find_map(|(id, p)| {
                let r = p.route.lock().ok()?;
                let b = &r.binding;
                (b.authorization_id == offer.current_authorization_id
                    && b.key_epoch == offer.current_key_epoch)
                    .then(|| {
                        if p.devices[0] == device {
                            Some((*id, 0usize))
                        } else if p.devices[1] == device {
                            Some((*id, 1usize))
                        } else {
                            None
                        }
                    })
                    .flatten()
            })
            .context("no approved route for current binding")?;
        let pair = t.pairs.get(&id).context("fleet pair missing")?.clone();
        ensure!(Instant::now() < pair.until, "fleet route expired");
        let next = pair
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet renewal offers poisoned"))?
            .iter()
            .find(|p| {
                p.grant().binding.authorization_id == offer.next_authorization_id
                    && p.grant().binding.key_epoch == offer.next_key_epoch
            })
            .cloned()
            .context("renewal was not offered by the relay")?;
        Ok((Self::present_locked(&pair, &next, role)?, role))
    }
    /// One peer presented the pending successor on its own authenticated
    /// socket. The route advances only when BOTH roles have done so, so a
    /// renewal cannot be forced by one side alone.
    /// True when this pair already routes the given successor, so a repeated
    /// presentation can answer "adopted" instead of failing.
    fn adopted_locked(pair: &Pair, offered: &ValidatedGrant) -> bool {
        pair.route
            .lock()
            .is_ok_and(|r| r.binding == offered.grant().binding)
    }
    fn present_locked(pair: &Pair, offered: &ValidatedGrant, role: usize) -> Result<bool> {
        let mut pending = pair
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet renewal offers poisoned"))?;
        let index = match pending
            .iter()
            .position(|p| p.grant().binding == offered.grant().binding)
        {
            Some(index) => index,
            None => {
                // Already adopted: presenting again is a status question, not a
                // second attempt. Without this a peer that lost the race cannot
                // ask "did it happen?" and would have to guess.
                ensure!(
                    Self::adopted_locked(pair, offered),
                    "renewal was not offered by the relay"
                );
                return Ok(true);
            }
        };
        let digest = offered.digest();
        let mut seen = pair
            .presented
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet renewal presentations poisoned"))?;
        let slot = seen.entry(digest).or_insert(0);
        *slot |= 1 << role;
        if *slot != 3 {
            return Ok(false);
        }
        seen.remove(&digest);
        // The relay cannot see inside a sealed commit frame, so adoption has to
        // happen here; `Route::retiring` keeps the superseded binding routable
        // until both roles are observed on the new one.
        pair.route
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet route poisoned"))?
            .advance(offered)?;
        pending.remove(index);
        Ok(true)
    }
    fn retire_locked(t: &mut StateTable, id: Uuid) {
        if let Some(p) = t.pairs.remove(&id) {
            p.closed.send_replace(true);
        }
        t.tickets.retain(|_, v| v.0 != id);
    }
    fn sweep(t: &mut StateTable) {
        let ids: Vec<_> = t
            .pairs
            .values()
            .filter(|p| Instant::now() >= p.until)
            .map(|p| p.id)
            .collect();
        for id in ids {
            Self::retire_locked(t, id);
        }
    }
    #[cfg(test)]
    pub(crate) fn test_pair_count(&self) -> usize {
        self.table.lock().unwrap().pairs.len()
    }
    /// Original approval digest survives binding rotation. Keep replay history.
    pub(crate) fn close_grant(&self, grant: &ValidatedGrant) {
        if let Ok(mut t) = self.table.lock() {
            let ids: Vec<_> = t
                .pairs
                .values()
                .filter(|p| p.approval_digest == grant.digest())
                .map(|p| p.id)
                .collect();
            for id in ids {
                Self::retire_locked(&mut t, id);
            }
        }
    }
    pub fn close(&self) {
        if let Ok(mut t) = self.table.lock() {
            t.stopped = true;
            let ids: Vec<_> = t.pairs.keys().copied().collect();
            for id in ids {
                Self::retire_locked(&mut t, id);
            }
        }
    }
    fn claim(self: &Arc<Self>, secret: &str, device: &str, token_hash: String) -> Result<Claim> {
        let permit = self
            .sockets
            .clone()
            .try_acquire_owned()
            .context("fleet sockets full")?;
        let mut t = self
            .table
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet registry poisoned"))?;
        Self::sweep(&mut t);
        ensure!(!t.stopped, "fleet routing stopped");
        let key = ticket_hash(secret);
        let (id, index) = *t.tickets.get(&key).context("unknown/used fleet join")?;
        let pair = t.pairs.get(&id).context("fleet pair missing")?.clone();
        ensure!(
            pair.devices[index] == device,
            "fleet join role/device mismatch"
        );
        let rx = pair
            .rx
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet receiver poisoned"))?[index]
            .take()
            .context("fleet join already used")?;
        pair.tokens
            .lock()
            .map_err(|_| anyhow::anyhow!("fleet credentials poisoned"))?[index] = Some(token_hash);
        t.tickets.remove(&key);
        pair.joined.send_modify(|v| *v |= 1 << index);
        Ok(Claim {
            fleet: self.clone(),
            pair,
            index,
            rx,
            _permit: permit,
        })
    }
}
struct Claim {
    fleet: Arc<FleetRelay>,
    pair: Arc<Pair>,
    index: usize,
    rx: mpsc::Receiver<ForwardFrame>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Claim {
    fn drop(&mut self) {
        if let Ok(mut t) = self.fleet.table.lock() {
            FleetRelay::retire_locked(&mut t, self.pair.id);
        }
    }
}
fn device_valid(relay: &Relay, id: &str, token_hash: &str) -> Result<()> {
    let row = relay
        .store
        .get("device_token", token_hash)?
        .context("device token revoked")?;
    ensure!(
        row["deviceId"].as_str() == Some(id),
        "device credential mismatch"
    );
    let d = relay.store.get("device", id)?.context("device revoked")?;
    ensure!(
        d["paused"] != true && d["tokenHash"].as_str() == Some(token_hash),
        "device paused/credential rotated"
    );
    Ok(())
}
fn pair_valid(relay: &Relay, p: &Pair) -> Result<()> {
    let tokens = p
        .tokens
        .lock()
        .map_err(|_| anyhow::anyhow!("fleet credentials poisoned"))?;
    for (i, key) in tokens.iter().enumerate() {
        device_valid(
            relay,
            &p.devices[i],
            key.as_deref().context("peer not joined")?,
        )?;
    }
    Ok(())
}
pub(crate) fn routes(fleet: Arc<FleetRelay>) -> Router<Arc<Relay>> {
    Router::new()
        .route("/fleet/ws", get(upgrade))
        .route("/fleet/renew", axum::routing::post(renew))
        .layer(Extension(fleet))
}
/// Renewal presentation. The peer proves its device token, names the successor
/// binding it accepts, and the route advances only once both roles presented.
/// The relay still cannot verify a renewal signature or trusted time, and it
/// does not mint grants: the successor must already be offered locally.
async fn renew(
    State(relay): State<Arc<Relay>>,
    Extension(fleet): Extension<Arc<FleetRelay>>,
    headers: HeaderMap,
    body: Bytes,
) -> WebResult<Response> {
    if headers.contains_key("origin") {
        return Err(ApiError(StatusCode::FORBIDDEN, "fleet_origin_forbidden"));
    }
    let token = bearer(&headers)?;
    let token_hash = hash(token);
    let row = relay
        .store
        .get("device_token", &token_hash)?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let device = row["deviceId"]
        .as_str()
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?
        .to_owned();
    device_valid(&relay, &device, &token_hash)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let offer: RenewOffer = serde_json::from_slice(&body)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_renewal_body"))?;
    let presented = fleet
        .present(&device, &offer)
        .map_err(|_| ApiError(StatusCode::CONFLICT, "renewal_rejected"))?;
    let (advanced, role) = presented;
    Ok(axum::Json(serde_json::json!({"advanced":advanced,"role":role})).into_response())
}
/// Minimal successor description. It is NOT a grant: the relay only needs the
/// binding it should route, and the peers still authenticate the real grant E2E.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RenewOffer {
    current_authorization_id: Uuid,
    current_key_epoch: Uuid,
    next_authorization_id: Uuid,
    next_key_epoch: Uuid,
}
async fn upgrade(
    State(relay): State<Arc<Relay>>,
    Extension(fleet): Extension<Arc<FleetRelay>>,
    OriginalUri(uri): OriginalUri,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> WebResult<Response> {
    if h.get_all("x-ferroc-fleet-protocol").iter().count() != 1
        || h.get("x-ferroc-fleet-protocol")
            .and_then(|v| v.to_str().ok())
            != Some("1")
        || uri.query().is_some()
        || h.contains_key("origin")
        || h.get_all("authorization").iter().count() != 1
        || h.get_all("x-ferroc-fleet-join").iter().count() != 1
    {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "fleet_native_headers_required",
        ));
    }
    let token = bearer(&h)?;
    let token_hash = hash(token);
    let row = relay
        .store
        .get("device_token", &token_hash)?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let id = row["deviceId"]
        .as_str()
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    device_valid(&relay, id, &token_hash)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    let secret = h
        .get("x-ferroc-fleet-join")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_fleet_join"))?;
    let claim = fleet
        .claim(secret, id, token_hash)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_fleet_join"))?;
    #[cfg(test)]
    let events = claim.pair.test_events.clone();
    #[cfg(test)]
    let index = claim.index;
    Ok(ws
        .max_frame_size(MAX_FRAME)
        .max_message_size(MAX_FRAME)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_FRAME * 2)
        .on_upgrade(move |socket| async move {
            let result = run(relay, claim, socket).await;
            #[cfg(test)]
            let _ = events.send(RelayTestEvent::Exit {
                destination: index,
                at: Instant::now(),
                error: result.err().map(|e| format!("{e:#}")),
            });
            #[cfg(not(test))]
            let _ = result;
        })
        .into_response())
}
async fn run(relay: Arc<Relay>, mut claim: Claim, socket: WebSocket) -> Result<()> {
    let pair = claim.pair.clone();
    let mut closed = pair.closed.subscribe();
    let mut joined = pair.joined.subscribe();
    let until = tokio::time::Instant::from_std(pair.until);
    while *joined.borrow() != 3 {
        ensure!(!*closed.borrow(), "fleet pair already closed");
        tokio::select! {biased;_=closed.changed()=>anyhow::bail!("fleet peer closed"),_=tokio::time::sleep_until(until)=>anyhow::bail!("fleet route expired"),v=joined.changed()=>{v.context("fleet join closed")?;}}
    }
    ensure!(!*closed.borrow(), "fleet pair closed");
    pair_valid(&relay, &pair)?;
    let (mut sink, mut input) = socket.split();
    let (local_tx, mut local_rx) = mpsc::channel(2);
    let role = if claim.index == 0 {
        Direction::SourceToTarget
    } else {
        Direction::TargetToSource
    };
    let read = async {
        loop {
            let msg = match input.next().await {
                Some(Ok(msg)) => msg,
                Some(Err(error)) => return Ok::<Result<()>, anyhow::Error>(Err(error.into())),
                None => return Ok(Err(anyhow::anyhow!("fleet input closed"))),
            };
            pair_valid(&relay, &pair)?;
            match msg {
                Message::Binary(bytes) => {
                    pair.route
                        .lock()
                        .map_err(|_| anyhow::anyhow!("fleet route poisoned"))?
                        .validate(&bytes, role)?;
                    let permit = match pair.forward.admit(claim.index) {
                        Some(permit) => permit,
                        // A peer is closing. Stop receiving new work while its
                        // already accepted tail still uses this fixed writer.
                        None => std::future::pending::<ForwardPermit>().await,
                    };
                    #[cfg(test)]
                    if pair.tx[1 - claim.index].capacity() == 0 {
                        let _ = pair.test_events.send(RelayTestEvent::QueueFull {
                            destination: 1 - claim.index,
                            at: Instant::now(),
                        });
                    }
                    tokio::time::timeout(
                        IO_BUDGET,
                        pair.tx[1 - claim.index].send(ForwardFrame { bytes, permit }),
                    )
                    .await
                    .context("fleet forward backpressure timeout")?
                    .context("fleet peer closed")?;
                }
                Message::Ping(p) => {
                    local_tx
                        .try_send(Message::Pong(p))
                        .map_err(|_| anyhow::anyhow!("fleet ping capacity"))?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Ok(Err(anyhow::anyhow!("fleet peer closed"))),
                _ => anyhow::bail!("fleet accepts binary records only"),
            }
        }
    };
    let write = async {
        loop {
            let (msg, permit) = tokio::select! {
                biased;
                v=local_rx.recv() => (v.context("fleet local control closed")?, None),
                v=claim.rx.recv() => {
                    let ForwardFrame { bytes, permit } = v.context("fleet output closed")?;
                    (Message::Binary(bytes), Some(permit))
                }
            };
            pair_valid(&relay, &pair)?;
            #[cfg(test)]
            let sent = tokio::time::timeout(
                IO_BUDGET,
                observe_native_write(&pair, claim.index, sink.send(msg)),
            )
            .await;
            #[cfg(not(test))]
            let sent = tokio::time::timeout(IO_BUDGET, sink.send(msg)).await;
            sent.context("fleet write timeout")??;
            drop(permit);
        }
    };
    let monitor = async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            pair_valid(&relay, &pair)?;
        }
    };
    // Pin whole loops once: auth ticks cannot cancel a consumed frame or send.
    tokio::pin!(read, write, monitor);
    tokio::select! {biased;_=closed.changed()=>Err(anyhow::anyhow!("fleet route closed")),_=tokio::time::sleep_until(until)=>Err(anyhow::anyhow!("fleet route expired")),v=&mut read=> {
        pair.forward.begin_drain();
        // Routing/format/backpressure faults remain immediate hard failures.
        // Only a transport EOF/close gets to drain previously accepted work.
        let v = v?;
        pair_valid(&relay, &pair)?;
        let drain = tokio::time::timeout(IO_BUDGET, pair.forward.drained(claim.index));
        tokio::pin!(drain);
        // The original writer on the OTHER socket owns this role's queued
        // permits. Preserve it until the tail was attempted or the hard cuts
        // win. Zero pending is only permission to retire transport.
        tokio::select! {
            biased;
            _=closed.changed()=>Err(anyhow::anyhow!("fleet route closed")),
            _=tokio::time::sleep_until(until)=>Err(anyhow::anyhow!("fleet route expired")),
            monitor_result=&mut monitor=>monitor_result,
            // Both peers can reach EOF together; keep our same writer alive
            // too, so each direction can release the other drain waiter.
            write_result=&mut write=>write_result,
            drained=&mut drain=>{drained.context("fleet accepted tail drain timeout")??;v}
        }
    },v=&mut write=>v,v=&mut monitor=>v}
}
#[cfg(test)]
#[path = "relay_drain_tests.rs"]
mod drain_tests;
#[cfg(test)]
#[path = "relay_channel_tests.rs"]
mod tests;
