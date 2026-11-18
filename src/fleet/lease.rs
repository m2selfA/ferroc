//! Process-local monotonic lease admission. Not a time synchronization service,
//! restart-recovery protocol, identity enrollment or durable commit journal.
//!
//! Public callers cannot manufacture a raw logical-time record session:
//! ```compile_fail
//! use ferroc::fleet::auth::AuthenticatedRecords;
//! ```
//! Nor can they import local clock samples from serialized peer fields:
//! ```compile_fail
//! use ferroc::fleet::lease::ClockSample;
//! use std::time::{Instant, SystemTime};
//! let forged = ClockSample { mono: Instant::now(), wall: SystemTime::now() };
//! ```
use super::{
    auth::{AuthenticatedRecords, DevicePin, EphemeralKey, PeerRecord, Transcript},
    control::ControlBody,
    job::ValidatedGrant,
    protocol::{Direction, Frame, Kind},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    time::{Duration, Instant, SystemTime},
};
use uuid::Uuid;

pub const MAX_CLOCK_DIVERGENCE_MS: u64 = 2_000;
pub const MAX_LEASE_EPOCHS: usize = 1024;
/// No public field constructor or Deserialize. Captured locally, never on wire.
#[derive(Clone, Copy, Debug)]
pub struct ClockSample {
    mono: Instant,
    wall: SystemTime,
}
impl ClockSample {
    pub fn now() -> Self {
        Self {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }
    pub(crate) fn local_epoch_ms(&self) -> Result<u64> {
        u64::try_from(self.wall.duration_since(std::time::UNIX_EPOCH)?.as_millis())
            .context("local epoch overflow")
    }
    #[cfg(test)]
    pub(super) fn shifted(self, mono: Duration, wall: Duration) -> Self {
        Self {
            mono: self.mono.checked_add(mono).unwrap(),
            wall: self.wall.checked_add(wall).unwrap(),
        }
    }
    #[cfg(test)]
    pub(super) fn rollback(self, mono: Duration, wall: Duration) -> Self {
        Self {
            mono: self.mono.checked_add(mono).unwrap(),
            wall: self.wall.checked_sub(wall).unwrap(),
        }
    }
}
/// Explicit TRUSTED-CALLER boundary. The interval must bound authority time at
/// this LOCAL sample, including source uncertainty, network delay and drift.
/// Copying issued/expires/peer timestamps into this object is NOT verification.
/// No default zero-skew assumption and no SystemTime-as-remote-epoch fallback.
pub struct TrustedTimeAnchor {
    sample: ClockSample,
    earliest_ms: u64,
    latest_ms: u64,
}
impl TrustedTimeAnchor {
    pub fn approved_window(sample: ClockSample, earliest_ms: u64, latest_ms: u64) -> Result<Self> {
        ensure!(earliest_ms <= latest_ms, "inverted trusted clock interval");
        Ok(Self {
            sample,
            earliest_ms,
            latest_ms,
        })
    }
}
#[derive(Clone, Copy, Debug)]
struct Bounds {
    earliest: u64,
    latest: u64,
}
fn floor_ms(d: Duration) -> Result<u64> {
    u64::try_from(d.as_millis()).context("elapsed clock overflow")
}
fn ceil_ms(d: Duration) -> Result<u64> {
    floor_ms(d)?
        .checked_add(u64::from(!d.subsec_nanos().is_multiple_of(1_000_000)))
        .context("elapsed clock overflow")
}
struct LeaseClock {
    anchor: TrustedTimeAnchor,
    last: ClockSample,
    job_until: Instant,
    lease_until: Instant,
    current: ValidatedGrant,
    authorizations: HashSet<Uuid>,
    epochs: HashSet<Uuid>,
    keys: HashSet<[u8; 32]>,
    poisoned: bool,
    revoked: bool,
}
impl LeaseClock {
    fn import(
        current: ValidatedGrant,
        anchor: TrustedTimeAnchor,
        source: [u8; 32],
        target: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            anchor.earliest_ms >= current.grant().issued_at_ms
                && anchor.latest_ms < current.grant().expires_at_ms,
            "trusted interval outside grant lease"
        );
        ensure!(source != target, "reflected ephemeral keys");
        let job_until = anchor
            .sample
            .mono
            .checked_add(Duration::from_millis(
                current
                    .job()
                    .deadline_ms
                    .checked_sub(anchor.latest_ms)
                    .context("expired fixed job deadline")?,
            ))
            .context("job monotonic deadline overflow")?;
        let lease_until = anchor
            .sample
            .mono
            .checked_add(Duration::from_millis(
                current.grant().expires_at_ms - anchor.latest_ms,
            ))
            .context("lease monotonic deadline overflow")?;
        let last = anchor.sample;
        let mut clock = Self {
            anchor,
            last,
            job_until,
            lease_until,
            current,
            authorizations: HashSet::new(),
            epochs: HashSet::new(),
            keys: HashSet::new(),
            poisoned: false,
            revoked: false,
        };
        clock.record_epoch(source, target);
        Ok(clock)
    }
    fn record_epoch(&mut self, source: [u8; 32], target: [u8; 32]) {
        self.authorizations
            .insert(self.current.grant().binding.authorization_id);
        self.epochs.insert(self.current.grant().binding.key_epoch);
        self.keys.insert(source);
        self.keys.insert(target);
    }
    fn observe(&mut self, s: ClockSample) -> Result<Bounds> {
        ensure!(!self.poisoned, "fleet local clock continuity lost");
        let result = (|| {
            ensure!(
                s.mono >= self.last.mono && s.wall >= self.last.wall,
                "fleet local clock moved backwards"
            );
            let mono = s
                .mono
                .checked_duration_since(self.anchor.sample.mono)
                .context("monotonic sample predates anchor")?;
            let wall = s
                .wall
                .duration_since(self.anchor.sample.wall)
                .context("wall sample predates anchor")?;
            let low = floor_ms(mono)?.min(floor_ms(wall)?);
            let high = ceil_ms(mono)?.max(ceil_ms(wall)?);
            ensure!(
                high - low <= MAX_CLOCK_DIVERGENCE_MS,
                "fleet clock divergence/suspend exceeds bound"
            );
            Ok(Bounds {
                earliest: self
                    .anchor
                    .earliest_ms
                    .checked_add(low)
                    .context("trusted time lower overflow")?,
                latest: self
                    .anchor
                    .latest_ms
                    .checked_add(high)
                    .context("trusted time upper overflow")?,
            })
        })();
        self.last = s;
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn require_effect(&self, s: ClockSample, b: Bounds) -> Result<()> {
        ensure!(!self.revoked, "fleet job authorization revoked");
        ensure!(
            s.mono < self.job_until && b.latest < self.current.job().deadline_ms,
            "fixed fleet job deadline expired"
        );
        ensure!(
            s.mono < self.lease_until && b.latest < self.current.grant().expires_at_ms,
            "fleet monotonic lease expired"
        );
        ensure!(
            b.earliest >= self.current.grant().issued_at_ms,
            "fleet grant not yet certainly issued"
        );
        Ok(())
    }
    fn check(&mut self, kind: Kind, s: ClockSample) -> Result<Bounds> {
        let b = self.observe(s)?;
        if kind.requires_live_grant() {
            self.require_effect(s, b)?;
        }
        Ok(b)
    }
    fn candidate(
        &self,
        next: &ValidatedGrant,
        t: &Transcript,
        s: ClockSample,
        b: Bounds,
    ) -> Result<Instant> {
        self.require_effect(s, b)?;
        ensure!(
            self.authorizations.len() < MAX_LEASE_EPOCHS,
            "fleet lease epoch budget exhausted"
        );
        ensure!(
            next.job().digest()? == self.current.job().digest()?,
            "renewal changes stable job parameters/deadline"
        );
        let old = self.current.grant();
        let new = next.grant();
        ensure!(
            new.permission == old.permission && new.chunk_bytes <= old.chunk_bytes,
            "renewal expands permission/chunk ceiling"
        );
        ensure!(
            new.binding.source_session == old.binding.source_session
                && new.binding.target_session == old.binding.target_session,
            "renewal changes live sessions; reconnect requires separate recovery"
        );
        ensure!(
            !self.authorizations.contains(&new.binding.authorization_id)
                && !self.epochs.contains(&new.binding.key_epoch),
            "renewal reuses authorization/key epoch"
        );
        ensure!(
            t.source_ephemeral != t.target_ephemeral
                && !self.keys.contains(&t.source_ephemeral)
                && !self.keys.contains(&t.target_ephemeral),
            "renewal reuses ephemeral key material"
        );
        ensure!(
            new.issued_at_ms > old.issued_at_ms && new.expires_at_ms > old.expires_at_ms,
            "renewal does not advance lease generation/expiry"
        );
        ensure!(
            new.issued_at_ms <= b.earliest && b.latest < new.expires_at_ms,
            "renewal interval not certainly live"
        );
        self.anchor
            .sample
            .mono
            .checked_add(Duration::from_millis(
                new.expires_at_ms
                    .checked_sub(self.anchor.latest_ms)
                    .context("renewal predates anchor")?,
            ))
            .context("renewal monotonic deadline overflow")
    }
    fn install(&mut self, next: ValidatedGrant, until: Instant, t: &Transcript) {
        self.current = next;
        self.lease_until = until;
        self.record_epoch(t.source_ephemeral, t.target_ephemeral);
    }
}

/// Owns one active key epoch and immutable clock anchor. No Clone/Deserialize,
/// raw-time APIs, re-anchor, epoch key retention, or unchecked session import.
pub struct LeasedRecords {
    activity_started: bool,
    clock: LeaseClock,
    records: AuthenticatedRecords,
    role: Direction,
    source_pin: DevicePin,
    target_pin: DevicePin,
}
impl EphemeralKey {
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate_leased(
        self,
        t: &Transcript,
        role: Direction,
        expected: &ValidatedGrant,
        source_pin: &DevicePin,
        target_pin: &DevicePin,
        source_signature: &[u8; 64],
        target_signature: &[u8; 64],
        anchor: TrustedTimeAnchor,
    ) -> Result<LeasedRecords> {
        self.authenticate_leased_between(
            t,
            role,
            expected,
            source_pin,
            target_pin,
            source_signature,
            target_signature,
            anchor,
            ClockSample::now,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn authenticate_leased_between(
        self,
        t: &Transcript,
        role: Direction,
        expected: &ValidatedGrant,
        source_pin: &DevicePin,
        target_pin: &DevicePin,
        source_signature: &[u8; 64],
        target_signature: &[u8; 64],
        anchor: TrustedTimeAnchor,
        end: impl FnOnce() -> ClockSample,
    ) -> Result<LeasedRecords> {
        let mut clock = LeaseClock::import(
            expected.clone(),
            anchor,
            t.source_ephemeral,
            t.target_ephemeral,
        )?;
        let now = clock.anchor.latest_ms;
        let records = self.authenticate(
            t,
            role,
            expected,
            source_pin,
            target_pin,
            source_signature,
            target_signature,
            now,
        )?;
        clock.check(Kind::Prepare, end())?;
        Ok(LeasedRecords {
            activity_started: false,
            clock,
            records,
            role,
            source_pin: source_pin.clone(),
            target_pin: target_pin.clone(),
        })
    }
}
impl LeasedRecords {
    // Only the typed source bridge may consume a truly fresh initial record
    // session. Attempts count as activity, even when rejected before AEAD.
    pub(super) fn source_record_faulted(&self) -> bool {
        self.records.is_faulted() || self.clock.poisoned
    }
    pub(super) fn enter_fresh_source(&mut self) -> Result<()> {
        ensure!(
            self.role == Direction::SourceToTarget,
            "source bridge requires Source role"
        );
        ensure!(
            !self.activity_started && self.epoch_count() == 1,
            "source bridge refuses used/renewed record history"
        );
        self.clock.check(Kind::Data, ClockSample::now())?;
        ensure!(!self.records.is_faulted(), "source record session faulted");
        self.activity_started = true;
        Ok(())
    }
    // Only the receiving peer may bind a filesystem writer. Recheck at each IO
    // boundary; returned wall bound is for journal admission, NOT a reusable permit.
    pub(super) fn receive_admission(&mut self) -> Result<u64> {
        ensure!(
            self.role == Direction::TargetToSource,
            "local writer requires Target role"
        );
        let b = self.clock.check(Kind::Data, ClockSample::now())?;
        ensure!(!self.records.is_faulted(), "fleet record session faulted");
        Ok(b.latest)
    }
    #[cfg(test)]
    pub(super) fn test_discontinuous(&mut self) {
        self.clock.anchor.sample = self
            .clock
            .anchor
            .sample
            .shifted(Duration::ZERO, Duration::from_secs(4));
    }
    #[cfg(test)]
    pub(super) fn test_expire(&mut self) {
        self.clock.lease_until = Instant::now();
    }

    pub fn grant(&self) -> &ValidatedGrant {
        &self.clock.current
    }
    pub fn epoch_count(&self) -> usize {
        self.clock.authorizations.len()
    }
    /// Irreversible for this job instance. Receipts/status/cleanup may settle;
    /// no renewed grant can restore mutation rights in this clock instance.
    pub fn revoke(&mut self) {
        self.clock.revoked = true;
    }
    pub fn seal_data(&mut self, offset: u64, bytes: &[u8]) -> Result<Vec<u8>> {
        self.seal_data_between(offset, bytes, ClockSample::now(), ClockSample::now)
    }
    pub fn seal_control(&mut self, body: ControlBody) -> Result<Vec<u8>> {
        self.seal_control_between(body, ClockSample::now(), ClockSample::now)
    }
    pub fn open_record(&mut self, bytes: &[u8]) -> Result<PeerRecord> {
        self.open_record_between(bytes, ClockSample::now(), ClockSample::now)
    }
    /// Check AT commit admission, after readback and under the actual fs gate.
    /// This is not a reusable permit nor an implementation of that IO boundary.
    pub fn check_commit_admission(&mut self) -> Result<()> {
        self.clock.check(Kind::Finish, ClockSample::now())?;
        ensure!(!self.records.is_faulted(), "fleet record session faulted");
        Ok(())
    }
    /// Read-only observation admission: preserve ACK/status after mutation expiry.
    pub(super) fn check_observation_admission(&mut self) -> Result<()> {
        self.clock.check(Kind::StatusRequest, ClockSample::now())?;
        ensure!(!self.records.is_faulted(), "fleet record session faulted");
        Ok(())
    }
    fn checked_result<T>(&mut self, kind: Kind, result: Result<T>, end: ClockSample) -> Result<T> {
        // Do not deliver an effect after crypto/JSON work crossed expiry. Any
        // burned AEAD sequence stays burned; decrypted data drops on error.
        self.clock.check(kind, end)?;
        result
    }
    fn seal_data_between(
        &mut self,
        offset: u64,
        bytes: &[u8],
        s: ClockSample,
        end: impl FnOnce() -> ClockSample,
    ) -> Result<Vec<u8>> {
        self.activity_started = true;
        let b = self.clock.check(Kind::Data, s)?;
        let result = self.records.seal_data(offset, bytes, b.latest);
        self.checked_result(Kind::Data, result, end())
    }
    fn seal_control_between(
        &mut self,
        body: ControlBody,
        s: ClockSample,
        end: impl FnOnce() -> ClockSample,
    ) -> Result<Vec<u8>> {
        self.activity_started = true;
        let kind = body.kind();
        let b = self.clock.check(kind, s)?;
        let result = self.records.seal_control(body, b.latest);
        self.checked_result(kind, result, end())
    }
    fn open_record_between(
        &mut self,
        bytes: &[u8],
        s: ClockSample,
        end: impl FnOnce() -> ClockSample,
    ) -> Result<PeerRecord> {
        self.activity_started = true;
        let frame = Frame::decode(bytes)?;
        let kind = frame.header.kind;
        let b = self.clock.check(kind, s)?;
        let result = self.records.open_record(bytes, b.latest);
        self.checked_result(kind, result, end())
    }
    #[cfg(test)]
    fn seal_data_at(&mut self, offset: u64, bytes: &[u8], s: ClockSample) -> Result<Vec<u8>> {
        self.seal_data_between(offset, bytes, s, || s)
    }
    #[cfg(test)]
    fn seal_control_at(&mut self, body: ControlBody, s: ClockSample) -> Result<Vec<u8>> {
        self.seal_control_between(body, s, || s)
    }
    #[cfg(test)]
    fn open_record_at(&mut self, bytes: &[u8], s: ClockSample) -> Result<PeerRecord> {
        self.open_record_between(bytes, s, || s)
    }
    pub fn renew(
        &mut self,
        next: ValidatedGrant,
        key: EphemeralKey,
        t: &Transcript,
        source_signature: &[u8; 64],
        target_signature: &[u8; 64],
    ) -> Result<()> {
        self.renew_between(
            next,
            key,
            t,
            source_signature,
            target_signature,
            ClockSample::now(),
            ClockSample::now,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn renew_between(
        &mut self,
        next: ValidatedGrant,
        key: EphemeralKey,
        t: &Transcript,
        source_signature: &[u8; 64],
        target_signature: &[u8; 64],
        start: ClockSample,
        end: impl FnOnce() -> ClockSample,
    ) -> Result<()> {
        ensure!(
            !self.records.is_faulted(),
            "cannot renew faulted record session"
        );
        let b = self.clock.check(Kind::Prepare, start)?;
        self.clock.candidate(&next, t, start, b)?;
        let candidate = key.authenticate(
            t,
            self.role,
            &next,
            &self.source_pin,
            &self.target_pin,
            source_signature,
            target_signature,
            b.latest,
        );
        // Charge crypto time even on failure. Never backdate installation to
        // the start sample or pause expiry while a peer/crypto check is slow.
        let finish = end();
        let b = self.clock.check(Kind::Prepare, finish)?;
        let until = self.clock.candidate(&next, t, finish, b)?;
        let records = candidate?;
        self.clock.install(next, until, t);
        self.records = records;
        Ok(())
    }
}
#[cfg(test)]
#[path = "lease_tests.rs"]
mod tests;
