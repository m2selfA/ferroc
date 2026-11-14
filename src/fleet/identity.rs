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
#[path = "identity_tests.rs"]
mod tests;
