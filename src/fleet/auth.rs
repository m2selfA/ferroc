//! Dual Ed25519 signatures authenticate fresh X25519 keys against EXTERNAL pins.
//! This module does not enroll/persist pins or silently trust a peer-provided key.
use super::{
    control::{ControlBody, ControlMessage},
    crypto::{Opened, RecordOpener, RecordSealer},
    job::ValidatedGrant,
    protocol::{Binding, Direction, Frame, Kind, MAX_DATA, MAX_FILE_BYTES, device_digest},
};
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const MAX_LEASE_MS: u64 = 60_000;
pub const AUTH_SUITE: u16 = 2;
pub struct IdentityKey(Ed25519KeyPair);
impl IdentityKey {
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("identity generation failed"))?;
        let bytes = Zeroizing::new(doc.as_ref().to_vec());
        Ok((Self::from_pkcs8(&bytes)?, bytes))
    }
    #[cfg(test)]
    pub(super) fn from_test_seed(bytes: [u8; 32]) -> Self {
        Self(Ed25519KeyPair::from_seed_unchecked(&bytes).expect("public test seed"))
    }
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        Ed25519KeyPair::from_pkcs8(bytes)
            .map(Self)
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS8 v2 identity"))
    }
    pub fn public(&self) -> [u8; 32] {
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key size")
    }
    pub fn sign(&self, t: &Transcript, role: Direction) -> Result<[u8; 64]> {
        let expected = match role {
            Direction::SourceToTarget => t.source_identity,
            Direction::TargetToSource => t.target_identity,
        };
        ensure!(
            self.public() == expected,
            "identity does not match signing role"
        );
        Ok(self
            .0
            .sign(&t.bytes(role)?)
            .as_ref()
            .try_into()
            .expect("Ed25519 signature size"))
    }
}

#[derive(Clone, Debug)]
pub struct DevicePin {
    device: [u8; 32],
    public: [u8; 32],
}
impl DevicePin {
    /// Supply a locally approved key, not a key copied from the offered transcript.
    pub fn approved(device_id: &str, public: [u8; 32]) -> Result<Self> {
        ensure!(public != [0; 32], "empty identity pin");
        Ok(Self {
            device: device_digest(device_id)?,
            public,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Transcript {
    pub binding: Binding,
    pub job_digest: [u8; 32],
    pub grant_digest: [u8; 32],
    pub source_identity: [u8; 32],
    pub target_identity: [u8; 32],
    pub source_ephemeral: [u8; 32],
    pub target_ephemeral: [u8; 32],
    pub max_file_bytes: u64,
    pub chunk_bytes: u32,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
impl Transcript {
    pub fn for_grant(
        g: &ValidatedGrant,
        source_identity: [u8; 32],
        target_identity: [u8; 32],
        source_ephemeral: [u8; 32],
        target_ephemeral: [u8; 32],
    ) -> Self {
        Self {
            binding: g.grant().binding.clone(),
            job_digest: g.grant().job_digest,
            grant_digest: g.digest(),
            source_identity,
            target_identity,
            source_ephemeral,
            target_ephemeral,
            max_file_bytes: g.job().bytes_total,
            chunk_bytes: g.grant().chunk_bytes,
            issued_at_ms: g.grant().issued_at_ms,
            expires_at_ms: g.grant().expires_at_ms,
        }
    }
    pub fn bytes(&self, role: Direction) -> Result<Vec<u8>> {
        self.binding.validate()?;
        ensure!(
            self.job_digest != [0; 32] && self.grant_digest != [0; 32],
            "uninitialized handshake job/grant digest"
        );
        ensure!(
            self.source_identity != [0; 32]
                && self.target_identity != [0; 32]
                && self.source_identity != self.target_identity,
            "invalid peer identities"
        );
        ensure!(
            self.max_file_bytes <= MAX_FILE_BYTES,
            "invalid handshake file quota"
        );
        ensure!(
            self.chunk_bytes > 0 && self.chunk_bytes as usize <= MAX_DATA,
            "invalid handshake chunk quota"
        );
        ensure!(
            self.expires_at_ms > self.issued_at_ms
                && self.expires_at_ms - self.issued_at_ms <= MAX_LEASE_MS,
            "invalid handshake lease"
        );
        let mut out = b"ferroc:fleet:auth:v2\0".to_vec();
        out.extend_from_slice(&AUTH_SUITE.to_be_bytes()); // suite: Ed25519/X25519/HKDF-SHA256/AES256-GCM
        out.push(role as u8);
        out.extend_from_slice(&self.binding.bytes());
        out.extend_from_slice(&self.job_digest);
        out.extend_from_slice(&self.grant_digest);
        for key in [
            self.source_identity,
            self.target_identity,
            self.source_ephemeral,
            self.target_ephemeral,
        ] {
            out.extend_from_slice(&key);
        }
        out.extend_from_slice(&self.max_file_bytes.to_be_bytes());
        out.extend_from_slice(&self.chunk_bytes.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(out)
    }
}

pub struct EphemeralKey(StaticSecret);
impl EphemeralKey {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(StaticSecret::from(*bytes))
    }
    pub fn public(&self) -> [u8; 32] {
        *PublicKey::from(&self.0).as_bytes()
    }
    #[cfg(test)]
    pub(super) fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }
    /// Consume the private key; pins + expected binding must originate from the
    /// trusted local grant, NOT from the peer's unverified fields.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate(
        self,
        t: &Transcript,
        role: Direction,
        expected: &ValidatedGrant,
        source_pin: &DevicePin,
        target_pin: &DevicePin,
        source_signature: &[u8; 64],
        target_signature: &[u8; 64],
        now_ms: u64,
    ) -> Result<AuthenticatedRecords> {
        ensure!(
            t.binding == expected.grant().binding
                && t.job_digest == expected.grant().job_digest
                && t.grant_digest == expected.digest()
                && t.max_file_bytes == expected.job().bytes_total
                && t.chunk_bytes == expected.grant().chunk_bytes
                && t.issued_at_ms == expected.grant().issued_at_ms
                && t.expires_at_ms == expected.grant().expires_at_ms,
            "unexpected handshake grant/context"
        );
        ensure!(
            source_pin.device == t.binding.source_device
                && target_pin.device == t.binding.target_device
                && source_pin.public == t.source_identity
                && target_pin.public == t.target_identity,
            "unapproved fleet identity"
        );
        let source_bytes = t.bytes(Direction::SourceToTarget)?;
        let target_bytes = t.bytes(Direction::TargetToSource)?;
        ensure!(
            now_ms >= t.issued_at_ms && now_ms < t.expires_at_ms,
            "handshake lease not live"
        );
        UnparsedPublicKey::new(&ED25519, source_pin.public)
            .verify(&source_bytes, source_signature)
            .map_err(|_| anyhow::anyhow!("source identity signature invalid"))?;
        UnparsedPublicKey::new(&ED25519, target_pin.public)
            .verify(&target_bytes, target_signature)
            .map_err(|_| anyhow::anyhow!("target identity signature invalid"))?;
        let (mine, peer, receive_direction) = match role {
            Direction::SourceToTarget => (
                t.source_ephemeral,
                t.target_ephemeral,
                Direction::TargetToSource,
            ),
            Direction::TargetToSource => (
                t.target_ephemeral,
                t.source_ephemeral,
                Direction::SourceToTarget,
            ),
        };
        ensure!(
            self.public() == mine,
            "ephemeral private key does not match role"
        );
        let shared = self.0.diffie_hellman(&PublicKey::from(peer));
        ensure!(shared.was_contributory(), "non-contributory X25519 peer");
        let salt = Sha256::digest(&source_bytes);
        let mut root = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
            .expand(b"ferroc:fleet:authenticated-root:v2", root.as_mut())
            .map_err(|_| anyhow::anyhow!("handshake key derivation failed"))?;
        Ok(AuthenticatedRecords {
            sealer: RecordSealer::new(&root, t.binding.clone(), role)?,
            opener: RecordOpener::new(&root, t.binding.clone(), receive_direction)?,
            max_file_bytes: t.max_file_bytes,
            chunk_bytes: t.chunk_bytes,
            issued_at_ms: t.issued_at_ms,
            expires_at_ms: t.expires_at_ms,
            last_ms: now_ms,
            grant: expected.clone(),
            faulted: false,
        })
    }
}
impl Default for EphemeralKey {
    fn default() -> Self {
        Self::generate()
    }
}

pub(crate) struct AuthenticatedRecords {
    sealer: RecordSealer,
    opener: RecordOpener,
    max_file_bytes: u64,
    chunk_bytes: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
    last_ms: u64,
    grant: ValidatedGrant,
    faulted: bool,
}

/// A fresh authenticated but invalid control faults this session: it must never
/// turn into an apparently acknowledged duplicate on retry.
pub enum PeerRecord {
    Data {
        header: super::protocol::Header,
        bytes: Zeroizing<Vec<u8>>,
    },
    Control {
        header: super::protocol::Header,
        message: ControlMessage,
    },
    Duplicate {
        header: super::protocol::Header,
    },
}
impl AuthenticatedRecords {
    pub(crate) fn is_faulted(&self) -> bool {
        self.faulted
    }
    pub fn seal_data(&mut self, offset: u64, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        self.seal(Kind::Data, offset, bytes, now_ms)
    }
    pub fn seal_control(&mut self, body: ControlBody, now_ms: u64) -> Result<Vec<u8>> {
        let msg = ControlMessage::new(&self.grant, body)?;
        let bytes = msg.encode(&self.grant)?;
        self.seal(msg.body.kind(), 0, &bytes, now_ms)
    }
    pub fn open_record(&mut self, bytes: &[u8], now_ms: u64) -> Result<PeerRecord> {
        match self.open(bytes, now_ms)? {
            Opened::Duplicate { header } => Ok(PeerRecord::Duplicate { header }),
            Opened::Fresh { header, plaintext } if header.kind == Kind::Data => {
                Ok(PeerRecord::Data {
                    header,
                    bytes: plaintext,
                })
            }
            Opened::Fresh { header, plaintext } => {
                match ControlMessage::decode(&header, &plaintext, &self.grant) {
                    Ok(message) => Ok(PeerRecord::Control { header, message }),
                    Err(error) => {
                        self.faulted = true;
                        Err(error)
                    }
                }
            }
        }
    }
    fn limits(&mut self, kind: Kind, offset: u64, len: usize, now_ms: u64) -> Result<()> {
        ensure!(!self.faulted, "fleet record session faulted");
        ensure!(now_ms >= self.last_ms, "fleet clock moved backwards");
        self.last_ms = now_ms;
        ensure!(
            now_ms >= self.issued_at_ms,
            "time precedes authenticated grant"
        );
        // Read-only receipts, ACK/status and cancellation may settle an already
        // admitted transaction after its deadline; new effects are forbidden.
        if kind.requires_live_grant() {
            ensure!(now_ms < self.expires_at_ms, "fleet mutation lease expired");
        }
        if kind == Kind::Data {
            ensure!(
                len <= self.chunk_bytes as usize
                    && offset
                        .checked_add(len as u64)
                        .is_some_and(|end| end <= self.max_file_bytes),
                "DATA exceeds authenticated quota"
            );
        }
        Ok(())
    }
    pub(crate) fn seal(
        &mut self,
        kind: Kind,
        offset: u64,
        data: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        self.limits(kind, offset, data.len(), now_ms)?;
        self.sealer.seal(kind, offset, data)
    }
    pub(crate) fn open(&mut self, bytes: &[u8], now_ms: u64) -> Result<Opened> {
        let frame = Frame::decode(bytes)?;
        self.limits(
            frame.header.kind,
            frame.header.offset,
            frame.header.plaintext_len as usize,
            now_ms,
        )?;
        self.opener.open(bytes)
    }
}
