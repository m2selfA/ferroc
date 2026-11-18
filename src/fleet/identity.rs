//! Explicitly approved local identity/pin persistence, not enrollment UI, TOFU,
//! revocation, a durable job journal or a filesystem sandbox. Root and parent
//! must be trusted local paths, never peer-selected or attacker-writable paths.
pub use super::identity_protection::Protection;
use super::{
    auth::{DevicePin, IdentityKey},
    protocol::device_digest,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const RECORD_MAGIC: &[u8] = b"ferroc:fleet:identity-store:v1\0";
const MAX_FILE: usize = 16 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);
impl Fingerprint {
    /// Exact 64 hexadecimal characters, from an independently verified source.
    pub fn parse_hex(text: &str) -> Result<Self> {
        ensure!(
            text.len() == 64 && text.is_ascii(),
            "invalid fleet fingerprint length"
        );
        let mut out = [0; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .context("invalid fleet fingerprint hex")?;
        }
        Ok(Self(out))
    }
    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("string format");
    }
    s
}
pub fn fingerprint(fleet: Uuid, device_id: &str, public: [u8; 32]) -> Result<Fingerprint> {
    ensure!(
        !fleet.is_nil() && public != [0; 32],
        "invalid identity fingerprint context"
    );
    let mut h = Sha256::new();
    h.update(b"ferroc:fleet:identity-fingerprint:v1\0");
    h.update(fleet.as_bytes());
    h.update(device_digest(device_id)?);
    h.update(public);
    Ok(Fingerprint(h.finalize().into()))
}
/// Not Deserialize; independently approved fingerprint is mandatory. This
/// verifies equality, not proof a human actually checked an external channel.
pub struct PeerApproval {
    fleet: Uuid,
    device: String,
    public: [u8; 32],
}
impl PeerApproval {
    pub fn verify(
        fleet: Uuid,
        device: &str,
        public: [u8; 32],
        expected: &Fingerprint,
    ) -> Result<Self> {
        ensure!(
            fingerprint(fleet, device, public)? == *expected,
            "peer fingerprint does not match explicit approval"
        );
        Ok(Self {
            fleet,
            device: device.into(),
            public,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinAdmission {
    Created,
    Existing,
}
/// Holds directory handle; does not repair permissions or regenerate anything.
/// Protection and scope must be supplied again on every open; neither is inferred
/// from an untrusted file. No implicit plaintext or backend downgrade.
pub struct IdentityStore {
    root: PathBuf,
    directory: File,
    protection: Protection,
    fleet: Uuid,
    device: String,
    device_hash: [u8; 32],
}
impl IdentityStore {
    pub fn create(root: &Path, protection: Protection, fleet: Uuid, device: &str) -> Result<Self> {
        validate_scope(root, fleet, device)?;
        make_directory(root)?;
        Self::open(root, protection, fleet, device)
    }
    pub fn open(root: &Path, protection: Protection, fleet: Uuid, device: &str) -> Result<Self> {
        validate_scope(root, fleet, device)?;
        let directory = open_private(root, true)?;
        Ok(Self {
            root: root.into(),
            directory,
            protection,
            fleet,
            device: device.into(),
            device_hash: device_digest(device)?,
        })
    }
    fn check_directory(&self) -> Result<()> {
        validate_private(&self.directory, true)?;
        let now = open_private(&self.root, true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let a = self.directory.metadata()?;
            let b = now.metadata()?;
            ensure!(
                a.dev() == b.dev() && a.ino() == b.ino(),
                "identity directory replaced"
            );
        }
        #[cfg(windows)]
        {
            super::identity_windows::same_file(&self.directory, &now)?;
        }
        Ok(())
    }
    fn context(&self, purpose: &[u8]) -> Vec<u8> {
        let mut c = RECORD_MAGIC.to_vec();
        c.extend_from_slice(self.fleet.as_bytes());
        c.extend_from_slice(&self.device_hash);
        c.extend_from_slice(purpose);
        c
    }
    fn read(&self, name: &str, context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.check_directory()?;
        let mut f = open_private(&self.root.join(name), false)?;
        ensure!(
            f.metadata()?.len() <= MAX_FILE as u64,
            "oversized protected identity record"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut f)
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_FILE,
            "protected record grew beyond bound"
        );
        self.check_directory()?;
        self.protection.open(context, &bytes)
    }
    fn write_new(&self, name: &str, context: &[u8], plain: &[u8]) -> Result<bool> {
        self.check_directory()?;
        let bytes = self.protection.seal(context, plain)?;
        ensure!(bytes.len() <= MAX_FILE, "oversized protected record output");
        let path = self
            .root
            .join(format!(".fleet-identity-{}.pending", Uuid::new_v4()));
        let mut file = new_private(&path)?;
        // Construct cleanup only AFTER successful create_new; never remove an
        // existing file we failed to create. Residue is encrypted, never PKCS8.
        let mut cleanup = Pending { path, owned: true };
        validate_private(&file, false)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        self.check_directory()?;
        let created = match fs::hard_link(&cleanup.path, self.root.join(name)) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => {
                return Err(e).context(
                    "identity/pin publication refused; existing destination is never replaced",
                );
            }
        };
        cleanup.remove().context("protected publication may exist; pending-link cleanup failed, explicitly reload before retry")?;
        #[cfg(unix)]
        self.directory
            .sync_all()
            .context("protected publication may exist; directory sync failed")?;
        Ok(created)
    }
    /// Explicit create; existing/corrupt data is never overwritten/regenerated.
    /// After a concurrent winner or uncertain publication, call load explicitly.
    pub fn create_identity(&self) -> Result<IdentityKey> {
        let (key, pkcs8) = IdentityKey::generate()?;
        let mut plain = Zeroizing::new(self.context(b"identity"));
        plain.extend_from_slice(&key.public());
        ensure!(pkcs8.len() <= 1024, "identity PKCS8 too large");
        plain.extend_from_slice(&(pkcs8.len() as u16).to_be_bytes());
        plain.extend_from_slice(&pkcs8);
        ensure!(
            self.write_new("identity.fid", &self.context(b"identity"), &plain)?,
            "identity already exists; explicitly load, never regenerate"
        );
        Ok(key)
    }
    pub fn load_identity(&self) -> Result<IdentityKey> {
        let context = self.context(b"identity");
        let plain = self.read("identity.fid", &context)?;
        ensure!(
            plain.starts_with(&context) && plain.len() >= context.len() + 34,
            "invalid protected identity context/layout"
        );
        let rest = &plain[context.len()..];
        let len = u16::from_be_bytes([rest[32], rest[33]]) as usize;
        ensure!(
            len <= 1024 && rest.len() == 34 + len,
            "invalid protected identity key length"
        );
        let key = IdentityKey::from_pkcs8(&rest[34..])?;
        ensure!(
            key.public() == rest[..32],
            "protected identity public/private mismatch"
        );
        Ok(key)
    }
    pub(super) fn issuance_scope(&self) -> (Uuid, &str) {
        (self.fleet, &self.device)
    }
    pub fn local_fingerprint(&self) -> Result<Fingerprint> {
        fingerprint(self.fleet, &self.device, self.load_identity()?.public())
    }
    fn pin_context(&self, device: &str) -> Result<(String, Vec<u8>)> {
        let hash = device_digest(device)?;
        let name = format!("pin-{}.fpin", hex(&hash));
        let mut c = self.context(b"pin");
        c.extend_from_slice(&hash);
        Ok((name, c))
    }
    fn read_pin_public(&self, device: &str) -> Result<[u8; 32]> {
        let (name, context) = self.pin_context(device)?;
        let plain = self.read(&name, &context)?;
        ensure!(
            plain.starts_with(&context) && plain.len() == context.len() + 32,
            "invalid protected pin context/layout"
        );
        let key = plain[context.len()..].try_into().expect("32byte pin");
        ensure!(key != [0; 32], "invalid empty pin");
        Ok(key)
    }
    pub fn load_pin(&self, device: &str) -> Result<DevicePin> {
        DevicePin::approved(device, self.read_pin_public(device)?)
    }
    pub fn pin_fingerprint(&self, device: &str) -> Result<Fingerprint> {
        fingerprint(self.fleet, device, self.read_pin_public(device)?)
    }
    pub fn approve_new_pin(&self, approval: PeerApproval) -> Result<PinAdmission> {
        ensure!(
            approval.fleet == self.fleet && approval.device != self.device,
            "wrong fleet/self pin approval"
        );
        let (name, context) = self.pin_context(&approval.device)?;
        let mut plain = Zeroizing::new(context.clone());
        plain.extend_from_slice(&approval.public);
        if self.write_new(&name, &context, &plain)? {
            Ok(PinAdmission::Created)
        } else {
            // Only the final atomic link reported AlreadyExists. Temp create,
            // encryption, permissions, IO or cleanup errors never become success.
            ensure!(
                self.read_pin_public(&approval.device)? == approval.public,
                "peer key conflict; explicit revoke/rotation workflow required"
            );
            Ok(PinAdmission::Existing)
        }
    }
}
struct Pending {
    path: PathBuf,
    owned: bool,
}
impl Pending {
    fn remove(&mut self) -> std::io::Result<()> {
        fs::remove_file(&self.path)?;
        self.owned = false;
        Ok(())
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if self.owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEntry {
    label: String,
    device: String,
    public: [u8; 32],
    added_ms: u64,
}
impl PeerEntry {
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn device(&self) -> &str {
        &self.device
    }
    pub(super) fn public_key(&self) -> [u8; 32] {
        self.public
    }
    pub fn added_ms(&self) -> u64 {
        self.added_ms
    }
    /// Recomputed on every read; never trusted from stored bytes.
    pub fn fingerprint(&self, fleet: Uuid) -> Result<Fingerprint> {
        fingerprint(fleet, &self.device, self.public)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAdmission {
    Created,
    Existing,
}
impl IdentityStore {
    fn peer_context(&self, hash: &[u8; 32]) -> Vec<u8> {
        let mut c = self.context(b"peer");
        c.extend_from_slice(hash);
        c
    }
    fn peer_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.root.join(format!("peer-{}.fpeer", hex(hash)))
    }
    fn read_peer(&self, hash: &[u8; 32]) -> Result<PeerEntry> {
        self.check_directory()?;
        let context = self.peer_context(hash);
        let mut f = open_private(&self.peer_path(hash), false)?;
        ensure!(
            f.metadata()?.len() <= MAX_FILE as u64,
            "oversized protected peer record"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut f)
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_FILE, "peer record grew beyond bound");
        self.check_directory()?;
        let plain = self.protection.open(&context, &bytes)?;
        ensure!(
            plain.starts_with(&context) && plain.len() >= context.len() + 4,
            "invalid protected peer context/layout"
        );
        let body = &plain[context.len()..];
        ensure!(
            body[0] == PEER_RECORD_VERSION,
            "unsupported peer record version"
        );
        let label_len = body[1] as usize;
        ensure!(
            label_len <= MAX_LABEL,
            "invalid protected peer label length"
        );
        ensure!(
            body.len() > 2 + label_len,
            "truncated protected peer record"
        );
        let label = std::str::from_utf8(&body[2..2 + label_len])?.to_owned();
        validate_label(&label)?;
        let dev_len = body[2 + label_len] as usize;
        ensure!(
            dev_len > 0 && body.len() == 3 + label_len + dev_len + 32 + 8,
            "invalid protected peer record length"
        );
        let device = std::str::from_utf8(&body[3 + label_len..3 + label_len + dev_len])?.to_owned();
        ensure!(
            device_digest(&device)? == *hash,
            "protected peer record device/filename mismatch"
        );
        ensure!(
            device != self.device,
            "protected peer record names this device"
        );
        let public: [u8; 32] = body[3 + label_len + dev_len..3 + label_len + dev_len + 32]
            .try_into()
            .expect("32 byte peer key");
        ensure!(public != [0; 32], "invalid empty peer key");
        let added_ms = u64::from_be_bytes(
            body[3 + label_len + dev_len + 32..]
                .try_into()
                .expect("8 byte timestamp"),
        );
        Ok(PeerEntry {
            label,
            device,
            public,
            added_ms,
        })
    }
    /// Explicit local enrolment of one peer key. `approval` already requires a
    /// caller-supplied expected fingerprint; there is no trust-on-first-use,
    /// automatic rotation, network lookup or grant issuance here.
    pub fn enroll_peer(
        &self,
        approval: PeerApproval,
        label: &str,
        now_ms: u64,
    ) -> Result<PeerAdmission> {
        ensure!(
            approval.fleet == self.fleet && approval.device != self.device,
            "wrong fleet/self peer approval"
        );
        validate_label(label)?;
        let existing = self.peers()?;
        let hash = device_digest(&approval.device)?;
        if let Some(found) = existing.iter().find(|p| p.device == approval.device) {
            ensure!(
                found.public == approval.public,
                "peer key conflict; explicit revoke/rotation workflow required"
            );
            ensure!(
                found.label == label,
                "peer already enrolled under another label"
            );
            return Ok(PeerAdmission::Existing);
        }
        ensure!(
            !existing.iter().any(|p| p.label == label),
            "peer label already used by another device"
        );
        ensure!(existing.len() < MAX_PEERS, "peer book capacity reached");
        let context = self.peer_context(&hash);
        let mut plain = Zeroizing::new(context.clone());
        plain.push(PEER_RECORD_VERSION);
        plain.push(label.len() as u8);
        plain.extend_from_slice(label.as_bytes());
        plain.push(approval.device.len() as u8);
        plain.extend_from_slice(approval.device.as_bytes());
        plain.extend_from_slice(&approval.public);
        plain.extend_from_slice(&now_ms.to_be_bytes());
        if self.write_new(&format!("peer-{}.fpeer", hex(&hash)), &context, &plain)? {
            // Two devices racing the same label can both pass the pre-check.
            // Re-read, and remove only the record this call just created.
            let after = self.read_roster()?;
            if after.iter().filter(|p| p.label == label).count() != 1 {
                let _ = fs::remove_file(self.peer_path(&hash));
                anyhow::bail!("peer label raced with another device; enrolment refused");
            }
            return Ok(PeerAdmission::Created);
        }
        let found = self.read_peer(&hash)?;
        ensure!(
            found.public == approval.public && found.label == label,
            "peer key/label conflict; explicit revoke/rotation workflow required"
        );
        Ok(PeerAdmission::Existing)
    }
    /// Read-only roster. Each record is re-decrypted and its device/key binding
    /// re-derived; the filename hash must match the device name it contains.
    pub fn peers(&self) -> Result<Vec<PeerEntry>> {
        let out = self.read_roster()?;
        for (index, peer) in out.iter().enumerate() {
            ensure!(
                out[index + 1..]
                    .iter()
                    .all(|other| other.label != peer.label),
                "duplicate peer label; roster refused rather than guessed"
            );
        }
        Ok(out)
    }
    fn read_roster(&self) -> Result<Vec<PeerEntry>> {
        self.check_directory()?;
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().unwrap_or_default();
            let Some(rest) = name.strip_prefix("peer-") else {
                continue;
            };
            let Some(digest) = rest.strip_suffix(".fpeer") else {
                continue;
            };
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "unexpected peer record name; refusing partial roster"
            );
            let mut hash = [0u8; 32];
            for (i, byte) in hash.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16)?;
            }
            out.push(self.read_peer(&hash)?);
            ensure!(out.len() <= MAX_PEERS, "peer book exceeds capacity bound");
        }
        out.sort_by(|a, b| a.device.cmp(&b.device));
        self.check_directory()?;
        Ok(out)
    }
    /// Explicit revocation of exactly the approved key; unknown or drifted key
    /// is refused and leaves the record in place.
    pub fn revoke_peer(&self, device: &str, expected: &Fingerprint) -> Result<bool> {
        let hash = device_digest(device)?;
        let found = self.read_peer(&hash)?;
        ensure!(
            found.fingerprint(self.fleet)? == *expected,
            "peer revoke fingerprint mismatch; record retained"
        );
        self.check_directory()?;
        fs::remove_file(self.peer_path(&hash))?;
        #[cfg(unix)]
        self.directory.sync_all()?;
        self.check_directory()?;
        Ok(true)
    }
    // Endpoint v2 binds the exact approved key, not just the device name.
    // Presence treats ONLY NotFound as absent; permission/IO errors fail closed.
    fn endpoint_present(&self, hash: &[u8; 32], slot: EndpointSlot) -> Result<bool> {
        match fs::symlink_metadata(self.endpoint_path(hash, slot)) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn endpoint_path(&self, hash: &[u8; 32], slot: EndpointSlot) -> PathBuf {
        self.root
            .join(format!("endpoint-{}-{}.fep", hex(hash), slot.as_str()))
    }
    fn read_endpoint(&self, hash: &[u8; 32], slot: EndpointSlot) -> Result<PeerEndpoint> {
        self.check_directory()?;
        let context = self.endpoint_context(hash, slot);
        let mut f = open_private(&self.endpoint_path(hash, slot), false)?;
        ensure!(
            f.metadata()?.len() <= MAX_FILE as u64,
            "oversized protected endpoint record"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut f)
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        self.check_directory()?;
        let plain = self.protection.open(&context, &bytes)?;
        ensure!(
            plain.starts_with(&context) && plain.len() > context.len() + 3,
            "invalid protected endpoint context/layout"
        );
        let body = &plain[context.len()..];
        ensure!(
            body[0] == ENDPOINT_RECORD_VERSION,
            "unsupported endpoint record version"
        );
        let dev_len = body[1] as usize;
        ensure!(
            dev_len > 0 && body.len() > 2 + dev_len + 2,
            "truncated endpoint record"
        );
        let device = std::str::from_utf8(&body[2..2 + dev_len])?.to_owned();
        ensure!(
            device_digest(&device)? == *hash,
            "endpoint record device/filename mismatch"
        );
        let key_offset = 2 + dev_len;
        ensure!(
            body.len() >= key_offset + 34,
            "truncated endpoint key binding"
        );
        let current = self.read_peer(hash)?.fingerprint(self.fleet)?;
        ensure!(
            body[key_offset..key_offset + 32] == current.0,
            "endpoint was approved for a different peer key"
        );
        let url_offset = key_offset + 32;
        let url_len = u16::from_be_bytes([body[url_offset], body[url_offset + 1]]) as usize;
        ensure!(
            url_len > 0 && url_len <= MAX_ENDPOINT_URL && body.len() == url_offset + 2 + url_len,
            "invalid endpoint URL length"
        );
        let url = std::str::from_utf8(&body[url_offset + 2..])?.to_owned();
        ensure!(
            !url.chars().any(char::is_control),
            "endpoint URL contains control characters"
        );
        // Reuse the one accepted transport policy; no second TLS rule set.
        crate::transport::relay_url(&url)?;
        Ok(PeerEndpoint { device, slot, url })
    }
    fn endpoint_context(&self, hash: &[u8; 32], slot: EndpointSlot) -> Vec<u8> {
        let mut c = self.context(b"endpoint");
        c.extend_from_slice(hash);
        c.push(slot as u8);
        c
    }
    /// Bind (or explicitly rotate) one endpoint slot for an ALREADY approved
    /// peer key. The caller must present the recomputed current fingerprint; a
    /// drifted key cannot inherit the old destination. Writing is atomic
    /// (private temp + sync + rename); a crash leaves old or new, never partial.
    pub fn set_peer_endpoint(
        &self,
        device: &str,
        slot: EndpointSlot,
        url: &str,
        expected: &Fingerprint,
    ) -> Result<EndpointAdmission> {
        let hash = device_digest(device)?;
        let peer = self.read_peer(&hash)?;
        ensure!(
            peer.fingerprint(self.fleet)? == *expected,
            "endpoint binding fingerprint mismatch; roster unchanged"
        );
        ensure!(
            !url.is_empty() && url.len() <= MAX_ENDPOINT_URL,
            "endpoint URL must be 1..=512 bytes"
        );
        ensure!(
            !url.chars().any(char::is_control),
            "endpoint URL contains control characters"
        );
        crate::transport::relay_url(url)?;
        let context = self.endpoint_context(&hash, slot);
        let mut plain = Zeroizing::new(context.clone());
        plain.push(ENDPOINT_RECORD_VERSION);
        plain.push(device.len() as u8);
        plain.extend_from_slice(device.as_bytes());
        plain.extend_from_slice(&expected.0);
        plain.extend_from_slice(&(url.len() as u16).to_be_bytes());
        plain.extend_from_slice(url.as_bytes());
        let existing = self.endpoints_for(device)?;
        let admission = if existing.iter().any(|e| e.slot == slot) {
            EndpointAdmission::Rotated
        } else {
            EndpointAdmission::Created
        };
        self.write_replace(
            &format!("endpoint-{}-{}.fep", hex(&hash), slot.as_str()),
            &context,
            &plain,
        )?;
        Ok(admission)
    }
    pub fn endpoints_for(&self, device: &str) -> Result<Vec<PeerEndpoint>> {
        let hash = device_digest(device)?;
        self.read_peer(&hash)?;
        let mut out = Vec::new();
        for slot in [EndpointSlot::Primary, EndpointSlot::Fallback] {
            if self.endpoint_present(&hash, slot)? {
                out.push(self.read_endpoint(&hash, slot)?);
            }
        }
        out.sort_by_key(|e| e.slot as u8);
        Ok(out)
    }
    pub fn clear_peer_endpoint(
        &self,
        device: &str,
        slot: EndpointSlot,
        expected: &Fingerprint,
    ) -> Result<bool> {
        let hash = device_digest(device)?;
        let peer = self.read_peer(&hash)?;
        ensure!(
            peer.fingerprint(self.fleet)? == *expected,
            "endpoint revoke fingerprint mismatch; record retained"
        );
        let path = self.endpoint_path(&hash, slot);
        ensure!(
            !self.endpoint_present(&hash, slot)? || self.read_endpoint(&hash, slot)?.slot == slot,
            "endpoint slot mismatch"
        );
        self.check_directory()?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        #[cfg(unix)]
        self.directory.sync_all()?;
        self.check_directory()?;
        Ok(true)
    }
    /// Atomic replace under the held private directory. Unlike write_new this
    /// may overwrite ONLY a file this same store previously wrote in that slot.
    fn write_replace(&self, name: &str, context: &[u8], plain: &[u8]) -> Result<()> {
        self.check_directory()?;
        let bytes = self.protection.seal(context, plain)?;
        ensure!(bytes.len() <= MAX_FILE, "oversized protected record output");
        let temp = self
            .root
            .join(format!(".fleet-endpoint-{}.pending", Uuid::new_v4()));
        let mut file = new_private(&temp)?;
        let mut cleanup = Pending {
            path: temp.clone(),
            owned: true,
        };
        validate_private(&file, false)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        self.check_directory()?;
        fs::rename(&temp, self.root.join(name))?;
        cleanup.owned = false;
        #[cfg(unix)]
        self.directory.sync_all()?;
        self.check_directory()?;
        Ok(())
    }
}
const MAX_LABEL: usize = 64;
const MAX_PEERS: usize = 64;
const PEER_RECORD_VERSION: u8 = 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointSlot {
    Primary,
    Fallback,
}
impl EndpointSlot {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Fallback => "fallback",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointAdmission {
    Created,
    Rotated,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEndpoint {
    device: String,
    slot: EndpointSlot,
    url: String,
}
impl PeerEndpoint {
    pub fn device(&self) -> &str {
        &self.device
    }
    pub fn slot(&self) -> EndpointSlot {
        self.slot
    }
    pub fn url(&self) -> &str {
        &self.url
    }
}
const MAX_ENDPOINT_URL: usize = 512;
const ENDPOINT_RECORD_VERSION: u8 = 2;
fn validate_label(label: &str) -> Result<()> {
    ensure!(
        !label.is_empty() && label.len() <= MAX_LABEL,
        "peer label must be 1..=64 bytes"
    );
    ensure!(
        label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
        "peer label allows only ASCII letters, digits, '-', '_' and '.'"
    );
    // A label is display-only, but leading/trailing dots invite confusion with
    // '.'/'..' path notation in logs and admin UI. Require alphanumeric ends.
    let first = label.as_bytes()[0];
    let last = *label.as_bytes().last().expect("non-empty label");
    ensure!(
        first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric(),
        "peer label must start and end with an ASCII letter or digit"
    );
    Ok(())
}
fn validate_scope(root: &Path, fleet: Uuid, device: &str) -> Result<()> {
    ensure!(
        root.is_absolute() && !fleet.is_nil(),
        "identity store requires absolute trusted directory and fleet ID"
    );
    ensure!(
        !root
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        "identity root traversal unsupported"
    );
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        ensure!(
            matches!(root.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_))),
            "identity store requires local disk path; UNC/device namespaces unsupported"
        );
    }
    device_digest(device)?;
    Ok(())
}
#[cfg(windows)]
pub(super) fn make_directory(path: &Path) -> Result<()> {
    super::identity_windows::create_directory(path)
}
#[cfg(unix)]
pub(super) fn make_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
pub(super) fn open_private(path: &Path, directory: bool) -> Result<File> {
    open_with_sharing(path, directory, false)
}
// ONLY a stage verifier shares DELETE; the live owner still denies it.
pub(super) fn open_stage(path: &Path) -> Result<File> {
    open_with_sharing(path, false, true)
}
pub(super) fn new_stage_private(path: &Path) -> Result<File> {
    #[cfg(windows)]
    {
        super::identity_windows::create_stage_file(path)
    }
    #[cfg(not(windows))]
    {
        new_private(path)
    }
}
fn open_with_sharing(path: &Path, directory: bool, _stage: bool) -> Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.share_mode(if _stage { 7 } else { 3 })
            .custom_flags(0x0020_0000 | if directory { 0x0200_0000 } else { 0 });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(
            libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if directory {
                    libc::O_DIRECTORY
                } else {
                    libc::O_NONBLOCK
                },
        );
    }
    let f = o.open(path)?;
    validate_private(&f, directory)?;
    Ok(f)
}
#[cfg(windows)]
pub(super) fn new_private(path: &Path) -> Result<File> {
    super::identity_windows::create_file(path)
}
#[cfg(unix)]
pub(super) fn new_private(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
pub(super) fn validate_private(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            m.file_attributes() & 0x400 == 0,
            "identity reparse point rejected"
        );
        super::identity_windows::check_security(file)?;
    }
    ensure!(
        if directory { m.is_dir() } else { m.is_file() },
        "protected path is not expected regular file/directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt; // SAFETY: geteuid takes no pointers or mutable memory.
        ensure!(
            m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o7777 == if directory { 0o700 } else { 0o600 },
            "identity owner/mode must be current user with exact0700/0600"
        );
    }
    Ok(())
}
#[cfg(test)]
#[path = "identity_endpoint_tests.rs"]
mod endpoint_tests;
#[cfg(test)]
#[path = "identity_peer_tests.rs"]
mod peer_tests;
#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
