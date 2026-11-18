//! Candidate relay-only IO pump. No MCP/CLI, issuance, reconnection, resume,
//! new service or private-IO attestation. Run synchronous file owners on a
//! dedicated blocking lane; this async pump itself does not spawn/clone them.
#[cfg(any(windows, target_os = "linux"))]
use super::protocol::{Frame, Kind};
use super::{
    job::ValidatedGrant,
    protocol::{Direction, MAX_FRAME},
    relay_channel::Route,
    source::{AwaitingCommit, FinalAckOutcome, PeerCommitObservation},
    source_window::{SourceWindow, WindowRecord},
};
use crate::network::Network;
use anyhow::{Context, Result, ensure};
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use std::time::Duration;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};
type Socket = WebSocketStream<reqwest::Upgraded>;
type Output = SplitSink<Socket, Message>;
type Input = SplitStream<Socket>;
/// Authenticated route admission only; peers still authenticate each E2E record.
/// Handles are private, no Clone/Deserialize and no credential-bearing Debug.
/// ```compile_fail
/// fn no_clone(l:ferroc::fleet::relay_io::FleetLink){let _=l.clone();}
/// ```
/// ```compile_fail
/// fn no_raw_socket(l:ferroc::fleet::relay_io::FleetLink){let _=l.tx;}
/// ```
/// ```compile_fail
/// fn no_restore(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::relay_io::FleetLink::from(s);}
/// ```
pub struct FleetLink {
    tx: Output,
    rx: Input,
    route: Route,
    role: Direction,
    until: tokio::time::Instant,
    /// Kept for the renewal presentation call: the relay adopts a successor only
    /// when BOTH roles present it over HTTP, and a peer must not advance its own
    /// route before that happened.
    net: Network,
    origin: String,
    device_token: String,
}
impl FleetLink {
    pub async fn connect(
        net: &Network,
        origin: &str,
        device_token: &str,
        join_secret: &str,
        g: &ValidatedGrant,
        role: Direction,
        budget: Duration,
    ) -> Result<Self> {
        ensure!(
            !budget.is_zero() && budget <= Duration::from_secs(300),
            "invalid fleet IO budget"
        );
        ensure!(
            g.job().route == super::job::RoutePolicy::RelayOnly,
            "initial fleet link requires relay-only job"
        );
        let until = tokio::time::Instant::now() + budget;
        let mut url = crate::transport::relay_url(origin)?;
        ensure!(
            url.path() == "/" && url.query().is_none(),
            "fleet relay requires origin URL"
        );
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("fleet URL scheme"))?;
        url.set_path("/fleet/ws");
        let config = WebSocketConfig::default()
            .write_buffer_size(0)
            .max_write_buffer_size(MAX_FRAME * 2)
            .max_message_size(Some(MAX_FRAME))
            .max_frame_size(Some(MAX_FRAME));
        let ws = tokio::time::timeout_at(
            until,
            net.fleet_websocket(url, device_token, join_secret, config),
        )
        .await
        .context("fleet connect deadline")??
        .context("fleet authentication rejected")?;
        let (tx, rx) = ws.split();
        Ok(Self {
            tx,
            rx,
            route: Route::from_grant(g),
            role,
            until,
            net: net.clone(),
            origin: origin.to_owned(),
            device_token: device_token.to_owned(),
        })
    }
    pub(super) async fn receive(&mut self) -> Result<Vec<u8>> {
        receive(&mut self.rx, &self.route, self.role, self.until).await
    }
    /// Move this link to the explicitly approved successor binding. Local only:
    /// it does not authenticate the renewal or prove the peer agreed.
    pub fn advance(&mut self, next: &ValidatedGrant) -> Result<()> {
        self.route.advance(next)
    }
    /// Present this role's acceptance of the successor to the relay, and report
    /// whether the relay reports it adopted. The relay is opaque (it cannot read
    /// a sealed commit), so adoption happens on the second presentation; a peer
    /// that advances its own route before that sends frames the relay rejects.
    pub async fn present_renewal(&self, next: &ValidatedGrant) -> Result<bool> {
        let current = self.route.binding.clone();
        let mut url = crate::transport::relay_url(&self.origin)?;
        url.set_path("/fleet/renew");
        let body = serde_json::json!({
            "currentAuthorizationId": current.authorization_id,
            "currentKeyEpoch": current.key_epoch,
            "nextAuthorizationId": next.grant().binding.authorization_id,
            "nextKeyEpoch": next.grant().binding.key_epoch,
        });
        let response = self
            .net
            .client(Some(Duration::from_secs(10)))?
            .post(url)
            .header("authorization", format!("Bearer {}", self.device_token))
            .json(&body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("renewal presentation failed"))?;
        ensure!(
            response.status().is_success(),
            "renewal presentation rejected"
        );
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| anyhow::anyhow!("renewal response is not JSON"))?;
        value["advanced"]
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("renewal response missing advanced"))
    }
    pub(super) async fn send(&mut self, frame: Vec<u8>) -> Result<()> {
        self.route.validate(&frame, self.role)?;
        send(&mut self.tx, frame, self.until).await
    }
}
// Only bounded, locally selected categories cross the logging boundary. Never
// format the underlying error: HTTP bodies/headers, URLs, close reasons and
// custom IO errors may contain credentials or peer-controlled text.
fn socket_failure(
    operation: &'static str,
    error: &tokio_tungstenite::tungstenite::Error,
) -> anyhow::Error {
    use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};
    let category = match error {
        Error::ConnectionClosed => "connection-closed",
        Error::AlreadyClosed => "already-closed",
        Error::Io(error) => match error.kind() {
            std::io::ErrorKind::ConnectionReset => "io-connection-reset",
            std::io::ErrorKind::ConnectionAborted => "io-connection-aborted",
            std::io::ErrorKind::BrokenPipe => "io-broken-pipe",
            std::io::ErrorKind::UnexpectedEof => "io-unexpected-eof",
            std::io::ErrorKind::TimedOut => "io-timed-out",
            _ => "io-other",
        },
        Error::Tls(_) => "tls",
        Error::Capacity(_) => "capacity",
        Error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
            "protocol-reset-without-close"
        }
        Error::Protocol(_) => "protocol",
        Error::WriteBufferFull(_) => "write-buffer-full",
        Error::Utf8(_) => "utf8",
        Error::AttackAttempt => "attack-attempt",
        Error::Url(_) => "url",
        Error::Http(_) => "http",
        Error::HttpFormat(_) => "http-format",
    };
    anyhow::anyhow!("fleet {operation} failed ({category}); effects may exist")
}
#[cfg(test)]
#[path = "relay_io_error_tests.rs"]
mod error_tests;

fn peer(role: Direction) -> Direction {
    if role == Direction::SourceToTarget {
        Direction::TargetToSource
    } else {
        Direction::SourceToTarget
    }
}
async fn receive(
    rx: &mut Input,
    route: &Route,
    role: Direction,
    until: tokio::time::Instant,
) -> Result<Vec<u8>> {
    loop {
        let msg = tokio::time::timeout_at(until, rx.next())
            .await
            .context("fleet receive deadline")?
            .context("fleet disconnected; effects may exist")?
            .map_err(|error| socket_failure("receive", &error))?;
        match msg {
            Message::Binary(b) => {
                route.validate(&b, peer(role))?;
                return Ok(b.to_vec());
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => anyhow::bail!("fleet peer closed; effects may exist"),
            _ => anyhow::bail!("fleet invalid message; effects may exist"),
        }
    }
}
async fn send(tx: &mut Output, frame: Vec<u8>, until: tokio::time::Instant) -> Result<()> {
    let end = until.min(tokio::time::Instant::now() + Duration::from_secs(5));
    tokio::time::timeout_at(end, tx.send(Message::Binary(frame.into())))
        .await
        .context("fleet send deadline; effects may exist")?
        .map_err(|error| socket_failure("send", &error))
}
fn controls<'a>(
    rx: &'a mut Input,
    route: &'a Route,
    role: Direction,
    until: tokio::time::Instant,
) -> impl futures_util::Stream<Item = Result<Vec<u8>>> + 'a {
    futures_util::stream::unfold((rx, route), move |(rx, route)| async move {
        let frame = receive(rx, route, role, until).await;
        Some((frame, (rx, route)))
    })
}
/// A bounded control burst cannot indefinitely prevent polling the SAME send
/// future/deadline. Yielding also keeps timers responsive with always-ready input.
pub(super) async fn sending_with_controls<S, C, F>(
    sending: S,
    control: C,
    mut accept: F,
) -> Result<()>
where
    S: std::future::Future<Output = Result<()>>,
    C: futures_util::Stream<Item = Result<Vec<u8>>>,
    F: FnMut(Vec<u8>) -> Result<()>,
{
    tokio::pin!(sending, control);
    let mut first_send = false;
    let mut burst = 0;
    loop {
        let input = if first_send {
            tokio::select! {biased;result=&mut sending=>return result,input=control.next()=>input}
        } else {
            tokio::select! {biased;input=control.next()=>input,result=&mut sending=>return result}
        };
        accept(input.context("fleet control stream closed")??)?;
        burst += 1;
        if burst == 8 {
            first_send = true;
            burst = 0;
            tokio::task::yield_now().await;
        }
    }
}
async fn send_source(
    window: &mut SourceWindow<'_>,
    link: &mut FleetLink,
    frame: Vec<u8>,
) -> Result<()> {
    link.route.validate(&frame, link.role)?;
    sending_with_controls(
        send(&mut link.tx, frame, link.until),
        controls(&mut link.rx, &link.route, link.role, link.until),
        |input| {
            window.observe_control(&input)?;
            Ok(())
        },
    )
    .await
}
async fn finish_source(
    mut pending: AwaitingCommit,
    mut link: FleetLink,
) -> Result<PeerCommitObservation> {
    let frame = pending.finish_record().to_vec();
    link.route.validate(&frame, link.role)?;
    {
        sending_with_controls(
            send(&mut link.tx, frame, link.until),
            controls(&mut link.rx, &link.route, link.role, link.until),
            |input| {
                pending.observe_final(&input)?;
                Ok(())
            },
        )
        .await?;
    }
    loop {
        if let Some(observation) = pending.peer_observation() {
            let result = observation.clone();
            let _ = tokio::time::timeout(Duration::from_secs(1), link.tx.close()).await;
            return Ok(result);
        }
        let frame = match link.receive().await {
            Ok(f) => f,
            Err(e) => {
                pending.connection_lost();
                return Err(e);
            }
        };
        if pending.observe_final(&frame)? == FinalAckOutcome::Accepted {
            continue;
        }
    }
}
/// Material for one binding rotation. The boundary itself is agreed by the
/// handshake; this only carries the successor both hosts already hold.
///
/// The signatures are supplied by the caller. A real two-host run still needs a
/// signature exchange between the hosts, which is NOT implemented: a caller that
/// fills both signatures locally proves the state machine, not that a peer signed.
pub struct Renewal {
    pub grant: ValidatedGrant,
    pub generation: u64,
    /// Each side installs with its OWN ephemeral; the peer's private half is
    /// never needed and must not be shared across hosts in a real run.
    pub source_key: super::auth::EphemeralKey,
    pub target_key: super::auth::EphemeralKey,
    pub transcript: super::auth::Transcript,
    pub source_signature: [u8; 64],
    pub target_signature: [u8; 64],
}
/// Who asks for a rotation, and with which successor. The pumps never mint
/// grants or signatures and never decide policy: they only run the handshake
/// the answer implies.
pub trait RenewalProvider {
    /// Source: rotate now at `progress` bytes encoded, or keep the session.
    /// Called only where the source can prove the boundary itself.
    fn rotate_source(&mut self, progress: u64) -> Option<Renewal>;
    /// Target: material for the successor an incoming offer names. `None`
    /// refuses the offer, which leaves the old epoch in force.
    fn accept_offer(&mut self, offer: &super::control::RenewOffer) -> Option<Renewal>;
}
/// The default: never rotate. Every existing caller keeps its old behaviour.
pub struct NoRenewal;
impl RenewalProvider for NoRenewal {
    fn rotate_source(&mut self, _progress: u64) -> Option<Renewal> {
        None
    }
    fn accept_offer(&mut self, _offer: &super::control::RenewOffer) -> Option<Renewal> {
        None
    }
}
/// Owns the actual SourceFile/window until FINISH or failure. Keeps input active
/// while one bounded owned send-copy is pending; never restarts that future on
/// a control event. No timer-based retransmit/reconnect. Returned observation
/// only authenticates the peer's receipt statement, never private remote IO.
pub async fn run_source(
    window: SourceWindow<'_>,
    link: FleetLink,
) -> Result<PeerCommitObservation> {
    let mut none = NoRenewal;
    run_source_with_renewal(window, link, &mut none).await
}
/// Same pump plus the renewal handshake.
///
/// The rotation check sits at the TOP of the loop: once an ACK frees a window
/// slot, `next_record` hands back the next chunk immediately, so the
/// drained-and-idle state is only observable before pulling data.
///
/// Ordering that must not change: the source presents to the relay and only
/// advances its own route after the relay reports adoption, and it resumes
/// sealing under the new epoch only after the target's `RENEW_COMMITTED`.
/// Skipping either makes the relay reject a frame and tear the pair down.
pub async fn run_source_with_renewal<P: RenewalProvider>(
    mut window: SourceWindow<'_>,
    mut link: FleetLink,
    renewal: &mut P,
) -> Result<PeerCommitObservation> {
    ensure!(
        link.role == Direction::SourceToTarget,
        "source link role mismatch"
    );
    loop {
        if window.at_renewal_boundary()
            && let Some(next) = renewal.rotate_source(window.bytes_encoded())
        {
            // Boxed: this sequence holds several per-step states and this
            // pump is nested inside a driver future; without boxing the
            // composed state overflows a default 2 MiB test thread stack.
            Box::pin(source_rotation(&mut window, &mut link, next)).await?;
            continue;
        }
        let data = match window.next_record()? {
            WindowRecord::Data { ciphertext, .. } => Some(ciphertext.to_vec()),
            WindowRecord::Exhausted => {
                if window.pending_records() == 0 {
                    break;
                }
                None
            }
            WindowRecord::WaitingForReady | WindowRecord::Backpressured => None,
        };
        if let Some(frame) = data {
            send_source(&mut window, &mut link, frame).await?;
        } else {
            let frame = link.receive().await?;
            window.observe_control(&frame)?;
        }
    }
    if let Some(prefix) = window.resumed_prefix_bytes() {
        eprintln!(
            "{}",
            serde_json::json!({"event":"fleetResumeEncoded","version":1,
            "prefixBytes":prefix,"bytesEncoded":window.bytes_encoded()})
        );
    }
    finish_source(window.finish()?, link).await
}
/// One full rotation on the source side: offer → accept → commit → present →
/// advance → wait for the target's confirmation.
///
/// Ordering that must not change: the presentation happens while this link still
/// routes the OLD binding (it names current+next), the commit travels under the
/// old epoch, and DATA only resumes after `RENEW_COMMITTED` proves the relay
/// adopted the successor and the target installed it.
async fn source_rotation(
    window: &mut SourceWindow<'_>,
    link: &mut FleetLink,
    next: Renewal,
) -> Result<()> {
    let offer = window.begin_renewal(
        next.grant.grant().binding.authorization_id,
        next.grant.grant().binding.key_epoch,
        next.generation,
    )?;
    link.send(offer).await?;
    let frame = link.receive().await?;
    window.observe_control(&frame)?;
    let grant = next.grant.clone();
    let commit = window.commit_renewal(
        next.grant,
        next.source_key,
        &next.transcript,
        &next.source_signature,
        &next.target_signature,
    )?;
    // This call may answer `false`: the target's presentation is usually the one
    // that flips adoption, and its RENEW_COMMITTED below is the proof it did.
    let _ = link.present_renewal(&grant).await?;
    link.send(commit).await?;
    link.advance(&grant)?;
    let confirmed = link.receive().await?;
    window.observe_control(&confirmed)?;
    Ok(())
}
/// One full rotation on the target side: install the successor, present it to
/// the relay (normally the second presentation, so this is the call that makes
/// the relay adopt), advance, then confirm under the NEW epoch.
#[cfg(any(windows, target_os = "linux"))]
async fn target_renewal(
    receiver: &mut super::host::receiver::HostReceiver<'_, '_>,
    link: &mut FleetLink,
    commit_frame: &[u8],
    next: Renewal,
) -> Result<()> {
    // The commit was sealed under the OLD epoch, so it must be read before this
    // link moves to the successor.
    receiver.install_renewal(
        commit_frame,
        next.grant.clone(),
        next.target_key,
        &next.transcript,
        &next.source_signature,
        &next.target_signature,
    )?;
    let adopted = link.present_renewal(&next.grant).await?;
    ensure!(adopted, "relay did not adopt the successor");
    link.advance(&next.grant)?;
    let committed = receiver.renew_committed_record(&next.grant, next.generation)?;
    link.send(committed).await?;
    Ok(())
}
/// Windows live Target v9 path. Drop the receiver before host.close/shutdown.
/// A successful return is LOCAL receipt, not proof Source received its ACK.
#[cfg(any(windows, target_os = "linux"))]
pub async fn run_target(
    receiver: super::host::receiver::HostReceiver<'_, '_>,
    link: FleetLink,
) -> Result<super::control::Receipt> {
    let mut none = NoRenewal;
    run_target_with_renewal(receiver, link, &mut none).await
}
/// Same Target v9 path plus the renewal handshake. The target answers an offer
/// with its OWN contiguous coverage, presents the successor to the relay, and
/// confirms only after the relay adopted it.
#[cfg(any(windows, target_os = "linux"))]
pub async fn run_target_with_renewal<P: RenewalProvider>(
    receiver: super::host::receiver::HostReceiver<'_, '_>,
    link: FleetLink,
    renewal: &mut P,
) -> Result<super::control::Receipt> {
    run_target_inner(receiver, link, renewal, None, async |_| Ok(())).await
}
/// Explicit stock target opt-in: actual same-gate sync/readback checkpoints.
/// Ordinary pump calls keep their original behavior. No counts become coverage.
#[cfg(any(windows, target_os = "linux"))]
pub(crate) async fn run_target_with_checkpoints(
    receiver: super::host::receiver::HostReceiver<'_, '_>,
    link: FleetLink,
    interval: u64,
) -> Result<super::control::Receipt> {
    let mut none = NoRenewal;
    run_target_inner(receiver, link, &mut none, Some(interval), async |_| Ok(())).await
}
#[cfg(any(windows, target_os = "linux"))]
fn log_checkpoint(
    receiver: &super::host::receiver::HostReceiver<'_, '_>,
    checkpoint: &super::journal::PrefixCheckpoint,
) {
    // Descriptive history, no stage path/secret/IO authority. Operator selection
    // still requires the actual same-DB row after the old process has stopped.
    eprintln!(
        "{}",
        serde_json::json!({"event":"fleetRetainedCheckpoint","version":1,
        "jobDigest":checkpoint.job_digest(),"owner":receiver.snapshot().owner(),
        "revision":receiver.snapshot().revision(),"checkpoint":checkpoint})
    );
}
// Private common implementation: production uses the no-op above. Tests observe
// a real network disconnect AFTER actual v9 settlement; no metadata injection,
// cached receipt restoration, deadline override or public callback API.
#[cfg(windows)]
#[cfg(test)]
pub(super) async fn run_target_after_settle(
    receiver: super::host::receiver::HostReceiver<'_, '_>,
    link: FleetLink,
    after_settle: impl for<'a> AsyncFnOnce(&'a mut FleetLink) -> Result<()>,
) -> Result<super::control::Receipt> {
    let mut none = NoRenewal;
    run_target_inner(receiver, link, &mut none, None, after_settle).await
}
#[cfg(any(windows, target_os = "linux"))]
async fn run_target_inner<P: RenewalProvider>(
    mut receiver: super::host::receiver::HostReceiver<'_, '_>,
    mut link: FleetLink,
    renewal: &mut P,
    checkpoint_interval: Option<u64>,
    after_settle: impl for<'a> AsyncFnOnce(&'a mut FleetLink) -> Result<()>,
) -> Result<super::control::Receipt> {
    ensure!(
        link.role == Direction::TargetToSource,
        "target link role mismatch"
    );
    // Derive mode only from the admitted live owner, including Some(0).
    // No peer/caller flag can turn a fresh receiver into recovery.
    let resumed = receiver.resumed_prefix().is_some();
    let mut last_checkpoint = 0;
    if let Some(interval) = checkpoint_interval {
        ensure!(
            !resumed && (65536..=1u64 << 30).contains(&interval),
            "invalid fresh checkpoint pump mode"
        );
        receiver.enable_retained_checkpoints()?;
        let checkpoint = receiver.capture_retained_checkpoint()?;
        log_checkpoint(&receiver, &checkpoint);
    }
    let ready = if resumed {
        receiver.resume_ready_record(8)?
    } else {
        receiver.ready_record(8)?
    }
    .to_vec();
    link.send(ready).await?;
    // Successor material for an offer we accepted but have not installed yet.
    let mut pending_renewal: Option<Renewal> = None;
    loop {
        let frame = link.receive().await?;
        let kind = Frame::decode(&frame)?.header.kind;
        match kind {
            Kind::Data => {
                receiver.write_record(&frame)?;
                if let Some(interval) = checkpoint_interval
                    && receiver
                        .snapshot()
                        .received()
                        .saturating_sub(last_checkpoint)
                        >= interval
                {
                    let checkpoint = receiver.capture_retained_checkpoint()?;
                    last_checkpoint = checkpoint.bytes();
                    log_checkpoint(&receiver, &checkpoint);
                }
                let ack = if resumed {
                    receiver.resume_ack_record()?
                } else {
                    receiver.ack_record()?
                }
                .to_vec();
                link.send(ack).await?;
            }
            Kind::RenewOffer => {
                let (offer, accept) = receiver.accept_renewal(&frame)?;
                let next = renewal
                    .accept_offer(&offer)
                    .context("target refused the renewal offer")?;
                link.send(accept).await?;
                pending_renewal = Some(next);
            }
            Kind::RenewCommit => {
                let next = pending_renewal
                    .take()
                    .context("RENEW_COMMIT without an accepted offer")?;
                // Boxed for the same reason as the source side: this pump is
                // nested inside a driver future, and the composed state would
                // otherwise overflow a default 2 MiB test thread stack.
                Box::pin(target_renewal(&mut receiver, &mut link, &frame, next)).await?;
            }
            Kind::Finish => {
                let done = receiver
                    .seal_finish(&frame)?
                    .prepare_commit()?
                    .attempt_local_publication()?
                    .record_target_observation()?
                    .settle_local()?;
                let receipt = done.receipt().clone();
                after_settle(&mut link).await?;
                link.send(done.local_commit_ack().to_vec())
                    .await
                    .context("target settled locally; final ACK delivery unknown")?;
                // Do not tear down the relay pair immediately after enqueueing final ACK.
                // Peer close lets the source consume it. A timeout/EOF is NOT peer proof.
                let _ = tokio::time::timeout(Duration::from_secs(2), link.receive()).await;
                drop(done);
                return Ok(receipt);
            }
            _ => anyhow::bail!("target pump expects DATA/FINISH; no implicit cleanup/recovery"),
        }
    }
}
