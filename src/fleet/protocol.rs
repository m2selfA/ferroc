//! Fixed-width, bounded fleet/1 peer records. Never decode these on BRC /ws.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAGIC: &[u8; 8] = b"FRCFL001";
pub const VERSION: u16 = 1;
pub const BINDING_LEN: usize = 176;
pub const HEADER_LEN: usize = 216;
pub const TAG_LEN: usize = 16;
pub const MAX_DATA: usize = 256 * 1024;
pub const MAX_CONTROL: usize = 16 * 1024;
pub const MAX_RECORDS: u64 = 1 << 20;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_FRAME: usize = HEADER_LEN + MAX_DATA + TAG_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    SourceToTarget = 0,
    TargetToSource = 1,
}
impl TryFrom<u8> for Direction {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::SourceToTarget),
            1 => Ok(Self::TargetToSource),
            _ => bail!("unknown fleet direction"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Prepare = 1,
    Ready = 2,
    Data = 3,
    Ack = 4,
    Finish = 5,
    CommitAck = 6,
    Cancel = 7,
    StatusRequest = 8,
    Status = 9,
}
impl Kind {
    pub fn direction(self) -> Direction {
        match self {
            Self::Ready | Self::Ack | Self::CommitAck | Self::Status => Direction::TargetToSource,
            _ => Direction::SourceToTarget,
        }
    }
    /// Only these records may initiate/advance unpublished file effects.
    pub const fn requires_live_grant(self) -> bool {
        matches!(
            self,
            Self::Prepare | Self::Ready | Self::Data | Self::Finish
        )
    }
    pub fn max_payload(self) -> usize {
        if self == Self::Data {
            MAX_DATA
        } else {
            MAX_CONTROL
        }
    }
}
impl TryFrom<u8> for Kind {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::Prepare,
            2 => Self::Ready,
            3 => Self::Data,
            4 => Self::Ack,
            5 => Self::Finish,
            6 => Self::CommitAck,
            7 => Self::Cancel,
            8 => Self::StatusRequest,
            9 => Self::Status,
            _ => bail!("unknown fleet record kind"),
        })
    }
}

/// Identifiers are not authentication. The trusted control plane must supply
/// the expected binding; peer-authentication and lease checks are separate.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub fleet_id: Uuid,
    pub source_device: [u8; 32],
    pub target_device: [u8; 32],
    pub source_session: Uuid,
    pub target_session: Uuid,
    pub transfer_id: Uuid,
    pub file_id: Uuid,
    pub authorization_id: Uuid,
    pub key_epoch: Uuid,
}
impl Binding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.source_device != [0; 32] && self.target_device != [0; 32],
            "empty device digest"
        );
        ensure!(
            self.source_device != self.target_device,
            "source equals target"
        );
        for id in [
            self.fleet_id,
            self.source_session,
            self.target_session,
            self.transfer_id,
            self.file_id,
            self.authorization_id,
            self.key_epoch,
        ] {
            ensure!(!id.is_nil(), "nil fleet identifier");
        }
        Ok(())
    }
    pub fn bytes(&self) -> [u8; BINDING_LEN] {
        let mut out = [0; BINDING_LEN];
        let mut cursor = 0;
        for part in [
            self.fleet_id.as_bytes().as_slice(),
            &self.source_device,
            &self.target_device,
            self.source_session.as_bytes(),
            self.target_session.as_bytes(),
            self.transfer_id.as_bytes(),
            self.file_id.as_bytes(),
            self.authorization_id.as_bytes(),
            self.key_epoch.as_bytes(),
        ] {
            out[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        }
        out
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            fleet_id: Uuid::from_bytes(r.take()?),
            source_device: r.take()?,
            target_device: r.take()?,
            source_session: Uuid::from_bytes(r.take()?),
            target_session: Uuid::from_bytes(r.take()?),
            transfer_id: Uuid::from_bytes(r.take()?),
            file_id: Uuid::from_bytes(r.take()?),
            authorization_id: Uuid::from_bytes(r.take()?),
            key_epoch: Uuid::from_bytes(r.take()?),
        })
    }
}

/// Hash opaque existing device IDs rather than assuming they are UUID strings.
pub fn device_digest(id: &str) -> Result<[u8; 32]> {
    ensure!(
        !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control),
        "invalid device identifier"
    );
    let mut h = Sha256::new();
    h.update(b"ferroc:fleet:device-id:v1\0");
    h.update((id.len() as u16).to_be_bytes());
    h.update(id.as_bytes());
    Ok(h.finalize().into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub direction: Direction,
    pub binding: Binding,
    pub sequence: u64,
    pub offset: u64,
    pub plaintext_len: u32,
}
impl Header {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        ensure!(
            self.direction == self.kind.direction(),
            "wrong record direction"
        );
        ensure!(
            self.sequence < MAX_RECORDS,
            "fleet key record budget exhausted"
        );
        ensure!(
            self.plaintext_len as usize <= self.kind.max_payload(),
            "fleet payload too large"
        );
        if self.kind == Kind::Data {
            ensure!(
                self.plaintext_len > 0,
                "empty DATA record; use FINISH for empty files"
            );
            ensure!(
                self.offset
                    .checked_add(self.plaintext_len as u64)
                    .is_some_and(|end| end <= MAX_FILE_BYTES),
                "DATA range exceeds fleet file limit"
            );
        } else {
            ensure!(self.offset == 0, "offset only valid for DATA");
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<[u8; HEADER_LEN]> {
        self.validate()?;
        let mut out = [0; HEADER_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_be_bytes());
        out[10] = self.kind as u8;
        out[11] = self.direction as u8;
        // 12..14 reserved flags, always zero.
        out[14..16].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        out[16..20].copy_from_slice(&(self.plaintext_len + TAG_LEN as u32).to_be_bytes());
        out[20..196].copy_from_slice(&self.binding.bytes());
        out[196..204].copy_from_slice(&self.sequence.to_be_bytes());
        out[204..212].copy_from_slice(&self.offset.to_be_bytes());
        out[212..216].copy_from_slice(&self.plaintext_len.to_be_bytes());
        Ok(out)
    }
}

/// Borrowed ciphertext; the decoder never allocates based on untrusted lengths.
#[derive(Debug)]
pub struct Frame<'a> {
    pub header: Header,
    pub ciphertext_and_tag: &'a [u8],
}
impl<'a> Frame<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            (HEADER_LEN + TAG_LEN..=MAX_FRAME).contains(&bytes.len()),
            "invalid fleet frame length"
        );
        let mut r = Reader { bytes, cursor: 0 };
        ensure!(&r.take::<8>()? == MAGIC, "invalid fleet magic");
        ensure!(
            u16::from_be_bytes(r.take()?) == VERSION,
            "unsupported fleet version"
        );
        let kind = Kind::try_from(r.take::<1>()?[0])?;
        let direction = Direction::try_from(r.take::<1>()?[0])?;
        ensure!(r.take::<2>()? == [0; 2], "reserved fleet flags");
        ensure!(
            u16::from_be_bytes(r.take()?) as usize == HEADER_LEN,
            "invalid fleet header length"
        );
        let wire_len = u32::from_be_bytes(r.take()?) as usize;
        let binding = Binding::read(&mut r)?;
        let header = Header {
            kind,
            direction,
            binding,
            sequence: u64::from_be_bytes(r.take()?),
            offset: u64::from_be_bytes(r.take()?),
            plaintext_len: u32::from_be_bytes(r.take()?),
        };
        header.validate()?;
        ensure!(
            wire_len == header.plaintext_len as usize + TAG_LEN
                && bytes.len() - HEADER_LEN == wire_len,
            "fleet body length mismatch"
        );
        Ok(Self {
            header,
            ciphertext_and_tag: &bytes[HEADER_LEN..],
        })
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .cursor
            .checked_add(N)
            .context("fleet header overflow")?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .context("truncated fleet header")?;
        self.cursor = end;
        value
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid fleet field"))
    }
}
