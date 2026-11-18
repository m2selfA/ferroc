//! Candidate P1 bounded source IO + authenticated DATA-stage flow, not a socket.
//! Only peer-reported contiguous coverage releases cached ciphertext, never
//! creates final completion or proves private IO. No retry timer/queue outside
//! this owner, persistence, reconnect or automatic retransmission. Renewal is
//! explicit and only at a fully acknowledged boundary; nothing is re-encoded.
use super::{
    auth::{EphemeralKey, PeerRecord, Transcript},
    control::ControlBody,
    job::ValidatedGrant,
    protocol::{HEADER_LEN, TAG_LEN},
    ranges::WINDOW,
    source::AwaitingCommit,
    source_file::SourceFile,
};
use anyhow::{Context, Result, ensure};
use std::collections::VecDeque;

#[derive(Debug, PartialEq, Eq)]
pub enum WindowRecord<'a> {
    WaitingForReady,
    Backpressured,
    Exhausted,
    Data { offset: u64, ciphertext: &'a [u8] },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressOutcome {
    Ready,
    Advanced,
    Duplicate,
    Stale,
    Status,
    /// The peer agreed to a renewal at the boundary this side offered.
    RenewAccepted,
    /// The peer confirmed the relay adopted the successor and installed it.
    RenewCommitted,
}
struct Pending {
    offset: u64,
    end: u64,
    frame: Box<[u8]>,
}
/// Owns a fresh SourceFile and at most WINDOW exact DATA ciphertexts. References
/// cannot outlive/mutate the owner. Caller copies/transport buffers are NOT
/// included in this bound; future transport must bound its own allocations.
/// ```compile_fail
/// fn no_clone(s:ferroc::fleet::source_window::SourceWindow<'_>){let _=s.clone();}
/// ```
/// ```compile_fail
/// fn no_file(s:ferroc::fleet::source_window::SourceWindow<'_>){let _=s.source;}
/// ```
/// ```compile_fail
/// fn no_snapshot(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::source_window::SourceWindow::from(s);}
/// ```
/// ```compile_fail
/// fn no_mutation_while_borrowed(s:&mut ferroc::fleet::source_window::SourceWindow<'_>){let f=s.retry_record(0).unwrap();s.revoke();println!("{}",f.len());}
/// ```
pub struct SourceWindow<'r> {
    source: SourceFile<'r>,
    local_window: usize,
    negotiated: Option<usize>,
    pending: VecDeque<Pending>,
    peer_contiguous: u64,
    peer_received: u64,
    last_ack_sequence: Option<u64>,
    /// Pending renewal handshake, if one is in progress. Only one at a time, so
    /// a peer cannot interleave two generations and confuse which is installed.
    renewal: Option<RenewState>,
    faulted: bool,
}
/// Source-side view of one renewal handshake. It exists only between a drained
/// boundary and the commit frame; a failure here leaves the OLD epoch installed.
#[derive(Debug, Clone)]
struct RenewState {
    generation: u64,
    next_authorization_id: uuid::Uuid,
    next_key_epoch: uuid::Uuid,
    drained_at: u64,
    accepted: bool,
}
impl<'r> SourceWindow<'r> {
    pub fn new(source: SourceFile<'r>, window_chunks: u8) -> Result<Self> {
        Self::build(source, window_chunks, false)
    }
    /// Explicit BOTH-proof original-File mode; never accepts a caller-built base.
    /// No suffix reads before an authenticated identical ResumeReady agreement.
    pub fn resuming(source: SourceFile<'r>, window_chunks: u8) -> Result<Self> {
        Self::build(source, window_chunks, true)
    }
    fn build(mut source: SourceFile<'r>, window_chunks: u8, resumed: bool) -> Result<Self> {
        ensure!(
            (1..=WINDOW as u8).contains(&window_chunks),
            "invalid local flow window"
        );
        ensure!(
            source.bytes_encoded() == 0
                && source.resumed_prefix_bytes().is_some() == resumed
                && source.resume_base().is_some() == resumed,
            "flow mode requires unused source with matching original live resume metadata"
        );
        source.flow_check()?;
        Ok(Self {
            source,
            local_window: window_chunks as usize,
            negotiated: None,
            pending: VecDeque::with_capacity(window_chunks as usize),
            peer_contiguous: 0,
            peer_received: 0,
            last_ack_sequence: None,
            renewal: None,
            faulted: false,
        })
    }
    #[cfg(test)]
    pub(super) fn test_expire(&mut self) {
        self.source.test_expire();
    }
    pub(crate) fn resumed_prefix_bytes(&self) -> Option<u64> {
        self.source.resumed_prefix_bytes()
    }
    pub fn bytes_encoded(&self) -> u64 {
        self.source.bytes_encoded()
    }
    pub fn bytes_peer_reported_contiguous(&self) -> u64 {
        self.peer_contiguous
    }
    pub fn pending_records(&self) -> usize {
        self.pending.len()
    }
    pub fn pending_ciphertext_bytes(&self) -> usize {
        self.pending.iter().map(|p| p.frame.len()).sum()
    }
    /// Exact retained DATA payload bound, excluding VecDeque metadata, transient
    /// one-chunk encoding/plaintext buffers, controls and caller-owned copies.
    pub fn ciphertext_capacity_bytes(&self) -> usize {
        self.local_window * (self.source.flow_chunk_limit() + HEADER_LEN + TAG_LEN)
    }
    /// Only at a fully acknowledged boundary: nothing cached and contiguous
    /// coverage equal to the encoded prefix. Already-sent ciphertext is never
    /// re-encoded, and a superseded epoch cannot be replayed into this window.
    pub fn renew(
        &mut self,
        g: ValidatedGrant,
        k: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<()> {
        self.live()?;
        ensure!(
            self.source.resume_base().is_none(),
            "resume window does not rotate its approved base"
        );
        ensure!(
            self.negotiated.is_some(),
            "renewal requires negotiated READY"
        );
        ensure!(
            self.pending.is_empty() && self.peer_contiguous == self.source.bytes_encoded(),
            "renewal requires drained acknowledged window"
        );
        self.source.renew(g, k, t, a, b)?;
        // A renewed key epoch starts a fresh AEAD sequence, so stale-ACK tracking
        // is scoped to one epoch and must not compare counters across sealers.
        self.last_ack_sequence = None;
        Ok(())
    }
    /// True only when the source can prove the rotation boundary: negotiated,
    /// nothing cached, and the peer's acknowledged prefix equals what has been
    /// encoded. No other point is safe, because cached ciphertext belongs to the
    /// old epoch and would be rejected after rotation.
    pub fn at_renewal_boundary(&self) -> bool {
        self.source.resume_base().is_none()
            && self.negotiated.is_some()
            && self.pending.is_empty()
            && self.peer_contiguous == self.source.bytes_encoded()
    }
    /// Open a renewal handshake at the current boundary and return the sealed
    /// offer frame. Sealed under the CURRENT epoch, so an old-epoch-only peer
    /// still authenticates it. Nothing is installed here.
    pub fn begin_renewal(
        &mut self,
        next_authorization_id: uuid::Uuid,
        next_key_epoch: uuid::Uuid,
        generation: u64,
    ) -> Result<Vec<u8>> {
        self.live()?;
        ensure!(
            self.at_renewal_boundary(),
            "renewal requires a drained acknowledged window"
        );
        ensure!(generation > 0, "renewal generation starts at 1");
        ensure!(self.renewal.is_none(), "renewal handshake already open");
        let drained_at = self.source.bytes_encoded();
        let frame =
            self.source
                .seal_flow_control(ControlBody::RenewOffer(super::control::RenewOffer {
                    next_authorization_id,
                    next_key_epoch,
                    generation,
                }))?;
        self.renewal = Some(RenewState {
            generation,
            next_authorization_id,
            next_key_epoch,
            drained_at,
            accepted: false,
        });
        Ok(frame)
    }
    /// The peer agreed. Its `drained_at` must equal the boundary this side
    /// opened at: a peer that accepted a different offset would install the new
    /// epoch over bytes it never acknowledged.
    pub fn renewal_accepted(&self) -> Option<u64> {
        self.renewal
            .as_ref()
            .filter(|r| r.accepted)
            .map(|r| r.drained_at)
    }
    /// Seal the commit frame under the OLD epoch, then install the successor.
    /// Order matters: after `renew` the old sealer is gone, so a commit frame
    /// sealed afterwards could not be read by a peer still on the old epoch.
    pub fn commit_renewal(
        &mut self,
        g: ValidatedGrant,
        k: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<Vec<u8>> {
        self.live()?;
        let state = self
            .renewal
            .clone()
            .context("no renewal handshake to commit")?;
        ensure!(state.accepted, "renewal not accepted by the peer");
        ensure!(
            g.grant().binding.authorization_id == state.next_authorization_id
                && g.grant().binding.key_epoch == state.next_key_epoch,
            "commit grant is not the offered successor"
        );
        ensure!(
            self.at_renewal_boundary() && self.source.bytes_encoded() == state.drained_at,
            "renewal boundary moved since the offer"
        );
        let frame = self.source.seal_flow_control(ControlBody::RenewCommit(
            super::control::RenewCommit {
                next_authorization_id: state.next_authorization_id,
                next_key_epoch: state.next_key_epoch,
                generation: state.generation,
                drained_at: state.drained_at,
            },
        ))?;
        self.renew(g, k, t, a, b)?;
        self.renewal = None;
        Ok(frame)
    }
    pub fn is_faulted(&self) -> bool {
        self.faulted
    }
    pub fn revoke(&mut self) {
        self.source.revoke();
        self.pending.clear();
        self.faulted = true;
    }
    fn live(&mut self) -> Result<()> {
        ensure!(!self.faulted, "source flow faulted");
        if let Err(e) = self.source.flow_check() {
            self.revoke();
            return Err(e);
        }
        Ok(())
    }
    /// Does no file read/encoding while waiting or full. Await control input,
    /// not a busy poll loop. Ready/ACK observation remains callable when full.
    pub fn next_record(&mut self) -> Result<WindowRecord<'_>> {
        self.live()?;
        let Some(window) = self.negotiated else {
            return Ok(WindowRecord::WaitingForReady);
        };
        if self.pending.len() >= window {
            return Ok(WindowRecord::Backpressured);
        }
        let offset = self.source.next_data_offset();
        match self.source.next_record() {
            Ok(Some(frame)) => {
                let end = self.source.next_data_offset();
                self.pending.push_back(Pending {
                    offset,
                    end,
                    frame: frame.into_boxed_slice(),
                });
                Ok(WindowRecord::Data {
                    offset,
                    ciphertext: &self.pending.back().expect("inserted").frame,
                })
            }
            Ok(None) => Ok(WindowRecord::Exhausted),
            Err(e) => {
                self.revoke();
                Err(e)
            }
        }
    }
    /// Borrow original AEAD bytes; never re-encrypt with a new nonce. No lookup
    /// for an ACK-released frame. This method does not claim network delivery.
    pub fn retry_record(&mut self, offset: u64) -> Result<&[u8]> {
        self.live()?;
        self.pending
            .iter()
            .find(|p| p.offset == offset)
            .map(|p| p.frame.as_ref())
            .ok_or_else(|| anyhow::anyhow!("DATA not retained"))
    }
    pub fn observe_control(&mut self, bytes: &[u8]) -> Result<ProgressOutcome> {
        self.live()?;
        let peer = match self.source.flow_control(bytes) {
            Ok(p) => p,
            Err(e) => {
                if self.source.flow_faulted() {
                    self.revoke();
                }
                return Err(e);
            }
        };
        let result = self.accept(peer);
        if result.is_err() {
            self.revoke();
        }
        result
    }
    fn accept(&mut self, peer: PeerRecord) -> Result<ProgressOutcome> {
        match peer {
            PeerRecord::Duplicate { .. } => Ok(ProgressOutcome::Duplicate),
            PeerRecord::Control { header, message } => match message.body {
                ControlBody::Ready(r) => {
                    ensure!(
                        self.source.resume_base().is_none(),
                        "legacy READY cannot negotiate resumed source"
                    );
                    ensure!(self.negotiated.is_none(), "fresh second READY not allowed");
                    self.negotiated = Some(self.local_window.min(r.window_chunks as usize));
                    Ok(ProgressOutcome::Ready)
                }
                ControlBody::ResumeReady(r) => {
                    ensure!(
                        self.negotiated.is_none(),
                        "fresh second resume READY not allowed"
                    );
                    ensure!(
                        self.source.resume_base() == Some(&r.base),
                        "resume READY differs from local BOTH-proof base"
                    );
                    self.negotiated = Some(self.local_window.min(r.window_chunks as usize));
                    self.peer_contiguous = r.base.prefix_bytes;
                    self.peer_received = r.base.prefix_bytes;
                    Ok(ProgressOutcome::Ready)
                }
                ControlBody::Ack(a) => {
                    ensure!(self.negotiated.is_some(), "ACK before READY");
                    if self.last_ack_sequence.is_some_and(|s| header.sequence < s) {
                        return Ok(ProgressOutcome::Stale);
                    }
                    ensure!(
                        a.contiguous >= self.peer_contiguous && a.received >= self.peer_received,
                        "fresh ACK regressed coverage"
                    );
                    ensure!(
                        a.received <= self.source.next_data_offset(),
                        "ACK exceeds encoded stream"
                    );
                    ensure!(
                        a.contiguous == self.peer_contiguous
                            || self.pending.iter().any(|p| p.end == a.contiguous),
                        "ACK prefix is not an encoded chunk boundary"
                    );
                    while self.pending.front().is_some_and(|p| p.end <= a.contiguous) {
                        self.pending.pop_front();
                    }
                    self.peer_contiguous = a.contiguous;
                    self.peer_received = a.received;
                    self.last_ack_sequence = Some(header.sequence);
                    Ok(ProgressOutcome::Advanced)
                }
                ControlBody::RenewAccept(accept) => {
                    let state = self
                        .renewal
                        .as_mut()
                        .context("RENEW_ACCEPT without an open offer")?;
                    ensure!(
                        accept.generation == state.generation
                            && accept.next_authorization_id == state.next_authorization_id
                            && accept.next_key_epoch == state.next_key_epoch,
                        "RENEW_ACCEPT names a different successor"
                    );
                    ensure!(
                        accept.drained_at == state.drained_at,
                        "RENEW_ACCEPT agreed a different boundary"
                    );
                    ensure!(!state.accepted, "duplicate RENEW_ACCEPT");
                    state.accepted = true;
                    Ok(ProgressOutcome::RenewAccepted)
                }
                ControlBody::RenewCommitted(committed) => {
                    ensure!(
                        self.source.resume_base().is_none(),
                        "resume window does not accept renewal confirmation"
                    );
                    let installed = self.source.current_binding();
                    ensure!(
                        committed.next_authorization_id == installed.authorization_id
                            && committed.next_key_epoch == installed.key_epoch,
                        "RENEW_COMMITTED names a different successor"
                    );
                    Ok(ProgressOutcome::RenewCommitted)
                }
                ControlBody::RenewOffer(_) | ControlBody::RenewCommit(_) => {
                    anyhow::bail!("source window does not accept peer renewal frames")
                }
                // Authenticated STATUS still does not release window/completion.
                ControlBody::Status(s) => {
                    ensure!(
                        s.error.is_none()
                            && !matches!(
                                s.phase,
                                super::state::Phase::Failed | super::state::Phase::Cancelled
                            ),
                        "peer reported terminal flow failure"
                    );
                    Ok(ProgressOutcome::Status)
                }
                _ => anyhow::bail!("unexpected DATA-stage control; final ACK is not progress"),
            },
            _ => anyhow::bail!("source flow requires authenticated target control"),
        }
    }
    /// Consumes IO only after all DATA is peer-reported contiguous. Returned
    /// AwaitingCommit still needs its separate authenticated FINAL ACK.
    pub fn finish(mut self) -> Result<AwaitingCommit> {
        self.live()?;
        ensure!(
            self.negotiated.is_some()
                && self.pending.is_empty()
                && self.peer_contiguous == self.source.flow_total(),
            "FINISH requires READY and fully drained DATA window"
        );
        self.source.finish()
    }
}
