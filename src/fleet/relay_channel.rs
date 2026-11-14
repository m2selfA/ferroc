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
#[derive(Clone)]
pub(super) struct Route {
    pub binding: Binding,
    pub chunk: u32,
    pub total: u64,
    job_digest: [u8; 32],
    seen: HashSet<(Uuid, Uuid)>,
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
        }
    }
    /// Explicit successor binding only. Stable routing identity, job parameters,
    /// chunk ceiling and total stay fixed; authorization/key epoch must rotate.
    /// Opaque relay still cannot verify the renewal signature or trusted time.
    pub(super) fn advance(&mut self, next: &ValidatedGrant) -> Result<()> {
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
        let key = (n.authorization_id, n.key_epoch);
        ensure!(
            !self.seen.contains(&key),
            "renewal reuses an earlier binding"
        );
        ensure!(self.seen.len() < MAX_ADVANCES, "renewal history exhausted");
        self.seen.insert(key);
        self.binding = n.clone();
        self.chunk = next.grant().chunk_bytes;
        Ok(())
    }
    pub(super) fn validate(&self, bytes: &[u8], role: Direction) -> Result<()> {
        let f = Frame::decode(bytes)?;
        ensure!(
            f.header.binding == self.binding && f.header.direction == role,
            "fleet routing binding/direction mismatch"
        );
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
struct Pair {
    id: Uuid,
    route: Mutex<Route>,
    devices: [String; 2],
    tokens: Mutex<[Option<String>; 2]>,
    until: Instant,
    tx: [mpsc::Sender<Bytes>; 2],
    rx: Mutex<[Option<mpsc::Receiver<Bytes>>; 2]>,
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
            route: Mutex::new(Route::from_grant(g)),
            devices: [source.into(), target.into()],
            tokens: Mutex::new([None, None]),
            until: Instant::now()
                .checked_add(ttl)
                .context("routing deadline overflow")?,
            tx: [a, b],
            rx: Mutex::new([Some(ar), Some(br)]),
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
    rx: mpsc::Receiver<Bytes>,
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
        .layer(Extension(fleet))
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
            let msg = input.next().await.context("fleet input closed")??;
            pair_valid(&relay, &pair)?;
            match msg {
                Message::Binary(bytes) => {
                    pair.route
                        .lock()
                        .map_err(|_| anyhow::anyhow!("fleet route poisoned"))?
                        .validate(&bytes, role)?;
                    #[cfg(test)]
                    if pair.tx[1 - claim.index].capacity() == 0 {
                        let _ = pair.test_events.send(RelayTestEvent::QueueFull {
                            destination: 1 - claim.index,
                            at: Instant::now(),
                        });
                    }
                    tokio::time::timeout(IO_BUDGET, pair.tx[1 - claim.index].send(bytes))
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
                Message::Close(_) => anyhow::bail!("fleet peer closed"),
                _ => anyhow::bail!("fleet accepts binary records only"),
            }
        }
    };
    let write = async {
        loop {
            let msg = tokio::select! {biased;v=local_rx.recv()=>v.context("fleet local control closed")?,v=claim.rx.recv()=>Message::Binary(v.context("fleet output closed")?)};
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
    tokio::select! {biased;_=closed.changed()=>Err(anyhow::anyhow!("fleet route closed")),_=tokio::time::sleep_until(until)=>Err(anyhow::anyhow!("fleet route expired")),v=&mut read=>v,v=&mut write=>v,v=&mut monitor=>v}
}
#[cfg(test)]
#[path = "relay_channel_tests.rs"]
mod tests;
