//! Candidate relay-only IO pump. No MCP/CLI, issuance, reconnection, resume,
//! new service or private-IO attestation. Run synchronous file owners on a
//! dedicated blocking lane; this async pump itself does not spawn/clone them.
#[cfg(windows)]
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
    #[cfg(any(windows, test))]
    pub(super) async fn send(&mut self, frame: Vec<u8>) -> Result<()> {
        self.route.validate(&frame, self.role)?;
        send(&mut self.tx, frame, self.until).await
    }
}
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
            .map_err(|_| anyhow::anyhow!("fleet receive failed; effects may exist"))?;
        match msg {
            Message::Binary(b) => {
                route.validate(&b, peer(role))?;
                return Ok(b.to_vec());
            }
            Message::Ping(_) | Message::Pong(_) => {}
            _ => anyhow::bail!("fleet disconnected/invalid message; effects may exist"),
        }
    }
}
async fn send(tx: &mut Output, frame: Vec<u8>, until: tokio::time::Instant) -> Result<()> {
    let end = until.min(tokio::time::Instant::now() + Duration::from_secs(5));
    tokio::time::timeout_at(end, tx.send(Message::Binary(frame.into())))
        .await
        .context("fleet send deadline; effects may exist")?
        .map_err(|_| anyhow::anyhow!("fleet send failed; effects may exist"))
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
/// Owns the actual SourceFile/window until FINISH or failure. Keeps input active
/// while one bounded owned send-copy is pending; never restarts that future on
/// a control event. No timer-based retransmit/reconnect. Returned observation
/// only authenticates the peer's receipt statement, never private remote IO.
pub async fn run_source(
    mut window: SourceWindow<'_>,
    mut link: FleetLink,
) -> Result<PeerCommitObservation> {
    ensure!(
        link.role == Direction::SourceToTarget,
        "source link role mismatch"
    );
    loop {
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
    finish_source(window.finish()?, link).await
}
/// Windows live Target v9 path. Invoke on an owned blocking lane so synchronous
/// stage writes/hash/fsync cannot stall the async network executor. Caller must
/// Drop the live result/receiver before host.close or Runtime.shutdown.
/// A successful return is LOCAL receipt, not proof Source received its ACK.
#[cfg(windows)]
pub async fn run_target(
    receiver: super::host::receiver::HostReceiver<'_, '_>,
    link: FleetLink,
) -> Result<super::control::Receipt> {
    run_target_after_settle(receiver, link, async |_| Ok(())).await
}
// Private common implementation: production uses the no-op above. Tests observe
// a real network disconnect AFTER actual v9 settlement; no metadata injection,
// cached receipt restoration, deadline override or public callback API.
#[cfg(windows)]
pub(super) async fn run_target_after_settle(
    mut receiver: super::host::receiver::HostReceiver<'_, '_>,
    mut link: FleetLink,
    after_settle: impl for<'a> AsyncFnOnce(&'a mut FleetLink) -> Result<()>,
) -> Result<super::control::Receipt> {
    ensure!(
        link.role == Direction::TargetToSource,
        "target link role mismatch"
    );
    let ready = receiver.ready_record(8)?.to_vec();
    link.send(ready).await?;
    loop {
        let frame = link.receive().await?;
        let kind = Frame::decode(&frame)?.header.kind;
        match kind {
            Kind::Data => {
                receiver.write_record(&frame)?;
                let ack = receiver.ack_record()?.to_vec();
                link.send(ack).await?;
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
