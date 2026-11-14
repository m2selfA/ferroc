//! AEAD records for an ALREADY AUTHENTICATED shared secret. Not a handshake.
//! No clone/reset API: one sealer per binding + direction for its lifetime.
//! Retransmit saved ciphertext, never reseal mutated data with an old sequence.
use super::protocol::{Binding, Direction, Frame, HEADER_LEN, Header, Kind, MAX_RECORDS, TAG_LEN};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const REPLAY_WINDOW: usize = 128;
fn key(root: &[u8; 32], binding: &Binding, direction: Direction) -> Result<Zeroizing<[u8; 32]>> {
    binding.validate()?;
    ensure!(root != &[0; 32], "uninitialized fleet shared secret");
    let mut info = b"ferroc:fleet:record-key:v1\0".to_vec();
    info.extend_from_slice(&binding.bytes());
    info.push(direction as u8);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"ferroc:fleet:hkdf-salt:v1"), root)
        .expand(&info, out.as_mut())
        .map_err(|_| anyhow::anyhow!("fleet key derivation failed"))?;
    Ok(out)
}
fn nonce(sequence: u64) -> [u8; 12] {
    let mut n = [0; 12];
    n[4..].copy_from_slice(&sequence.to_be_bytes());
    n
}

pub struct RecordSealer {
    key: Zeroizing<[u8; 32]>,
    binding: Binding,
    direction: Direction,
    next_sequence: u64,
}
impl RecordSealer {
    /// Caller must verify device identities, authorize this context and ensure
    /// this key epoch has NEVER had another sealer in the same direction.
    pub(crate) fn new(root: &[u8; 32], binding: Binding, direction: Direction) -> Result<Self> {
        Ok(Self {
            key: key(root, &binding, direction)?,
            binding,
            direction,
            next_sequence: 0,
        })
    }
    pub fn seal(&mut self, kind: Kind, offset: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            plaintext.len() <= kind.max_payload(),
            "fleet payload too large"
        );
        let header = Header {
            kind,
            direction: self.direction,
            binding: self.binding.clone(),
            sequence: self.next_sequence,
            offset,
            plaintext_len: plaintext.len() as u32,
        };
        let aad = header.encode()?;
        // Burn the nonce before entering crypto. Even a crypto failure must
        // never expose a retry path that reuses a partly-consumed nonce.
        self.next_sequence += 1;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid fleet key"))?;
        let mut data = Zeroizing::new(plaintext.to_vec());
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce(header.sequence)),
                &aad,
                data.as_mut(),
            )
            .map_err(|_| anyhow::anyhow!("fleet record encryption failed"))?;
        let mut frame = Vec::with_capacity(HEADER_LEN + data.len() + TAG_LEN);
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&data);
        frame.extend_from_slice(&tag);
        Ok(frame)
    }
    pub fn remaining_records(&self) -> u64 {
        MAX_RECORDS - self.next_sequence
    }
}

#[derive(Clone, Copy)]
struct Seen {
    sequence: u64,
    digest: [u8; 32],
}
pub enum Opened {
    Fresh {
        header: Header,
        plaintext: Zeroizing<Vec<u8>>,
    },
    /// This exact, previously authenticated ciphertext was seen. Do not write
    /// or count it twice; the caller may repeat its acknowledgement.
    Duplicate { header: Header },
}
impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh { header, plaintext } => f
                .debug_struct("Fresh")
                .field("header", header)
                .field("plaintext_len", &plaintext.len())
                .finish(),
            Self::Duplicate { header } => {
                f.debug_struct("Duplicate").field("header", header).finish()
            }
        }
    }
}

pub struct RecordOpener {
    key: Zeroizing<[u8; 32]>,
    binding: Binding,
    direction: Direction,
    highest: Option<u64>,
    seen: [Option<Seen>; REPLAY_WINDOW],
}
impl RecordOpener {
    pub(crate) fn new(root: &[u8; 32], binding: Binding, direction: Direction) -> Result<Self> {
        Ok(Self {
            key: key(root, &binding, direction)?,
            binding,
            direction,
            highest: None,
            seen: [None; REPLAY_WINDOW],
        })
    }
    pub fn open(&mut self, bytes: &[u8]) -> Result<Opened> {
        let frame = Frame::decode(bytes)?;
        let h = &frame.header;
        ensure!(
            h.binding == self.binding && h.direction == self.direction,
            "fleet context mismatch"
        );
        if let Some(highest) = self.highest {
            ensure!(
                h.sequence >= highest.saturating_sub((REPLAY_WINDOW - 1) as u64),
                "stale fleet sequence"
            );
        }
        let slot = h.sequence as usize % REPLAY_WINDOW;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if let Some(seen) = self.seen[slot].filter(|s| s.sequence == h.sequence) {
            ensure!(
                bool::from(seen.digest.ct_eq(&digest)),
                "fleet sequence reused with different ciphertext"
            );
            return Ok(Opened::Duplicate {
                header: frame.header,
            });
        }
        let (encrypted, tag) = frame.ciphertext_and_tag.split_at(h.plaintext_len as usize);
        let mut plaintext = Zeroizing::new(encrypted.to_vec());
        Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid fleet key"))?
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce(h.sequence)),
                &bytes[..HEADER_LEN],
                plaintext.as_mut(),
                Tag::from_slice(tag),
            )
            .map_err(|_| anyhow::anyhow!("fleet record authentication failed"))?;
        // An unauthenticated high sequence must never advance/poison the window.
        self.highest = Some(self.highest.map_or(h.sequence, |high| high.max(h.sequence)));
        self.seen[slot] = Some(Seen {
            sequence: h.sequence,
            digest,
        });
        Ok(Opened::Fresh {
            header: frame.header,
            plaintext,
        })
    }
}
