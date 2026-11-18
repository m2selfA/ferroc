//! Public observation never seeds encoder state. Private continuation keeps
//! actual same-FD SHA state only for a consumed dual-proof Source owner.
use super::*;
use crate::fleet::{job::LeaseProfile, resume_condition::ResumeProposal};
use sha2::{Digest, Sha256};
use std::io::{Seek, SeekFrom};
#[derive(Debug)]
pub struct SourcePrefixObservation {
    condition_digest: [u8; 32],
    grant_digest: [u8; 32],
    bytes: u64,
    sha256: [u8; 32],
}
impl SourcePrefixObservation {
    pub fn condition_digest(&self) -> [u8; 32] {
        self.condition_digest
    }
    pub fn grant_digest(&self) -> [u8; 32] {
        self.grant_digest
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}
impl SourceFile<'_> {
    /// Rehash the approved proposal's prefix using this fresh SourceFile's actual
    /// original FD. Does NOT import hash state, advance logical offset, encode a
    /// frame, establish peer acceptance or authorize target stage adoption.
    /// After success the ordinary encoder still starts at byte0 and count0.
    /// This is a historical read sequence, not immutable content. Any failure
    /// closes the original FD/parent and permanently faults the encoder.
    pub fn observe_resume_prefix(
        &mut self,
        p: &ResumeProposal,
        max_prefix_bytes: u64,
    ) -> Result<SourcePrefixObservation> {
        self.prefix_with(p, max_prefix_bytes, false, |_, _| Ok(()))
    }
    #[cfg(test)]
    pub(in crate::fleet) fn test_prefix_with(
        &mut self,
        p: &ResumeProposal,
        max: u64,
        between: impl FnMut(u64, &mut Self) -> Result<()>,
    ) -> Result<SourcePrefixObservation> {
        self.prefix_with(p, max, false, between)
    }
    pub(super) fn restore_resume_prefix(&mut self, p: &ResumeProposal, max: u64) -> Result<()> {
        self.prefix_with(p, max, true, |_, _| Ok(())).map(|_| ())
    }
    fn prefix_with(
        &mut self,
        p: &ResumeProposal,
        max_prefix_bytes: u64,
        restore: bool,
        mut between: impl FnMut(u64, &mut Self) -> Result<()>,
    ) -> Result<SourcePrefixObservation> {
        let result = (|| {
            ensure!(
                max_prefix_bytes <= 1024 * 1024 * 1024 && p.prefix_bytes() <= max_prefix_bytes,
                "source prefix readback budget exceeded"
            );
            ensure!(
                self.encoder.bytes_encoded() == 0
                    && self.encoder.resumed_prefix_bytes().is_none()
                    && self.encoder.current_grant().lease_profile() == LeaseProfile::SingleOwner
                    && self.encoder.current_grant().digest() == p.expected_grant_digest(),
                "source prefix requires matching fresh SingleOwner grant"
            );
            let _life = self.runtime.fleet_source_guard()?;
            let gate = self.gate.clone();
            let _fs = gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            self.encoder.check_source_io()?;
            self.checks.set(OBJECT_CHECK_EVERY - 1);
            self.check_objects()?;
            self.encoder.check_source_io()?;
            self.file
                .as_mut()
                .context("source closed")?
                .seek(SeekFrom::Start(0))?;
            self.encoder.check_source_io()?;
            let mut hash = Sha256::new();
            let mut read = 0;
            let mut buffer = zeroize::Zeroizing::new([0u8; 65536]);
            while read < p.prefix_bytes() {
                self.encoder.check_source_io()?;
                self.checks.set(OBJECT_CHECK_EVERY - 1);
                self.check_objects()?;
                self.encoder.check_source_io()?;
                let n = (p.prefix_bytes() - read).min(buffer.len() as u64) as usize;
                let count = self
                    .file
                    .as_mut()
                    .context("source closed")?
                    .read(&mut buffer[..n])?;
                self.encoder.check_source_io()?;
                ensure!(count > 0, "source prefix truncated");
                hash.update(&buffer[..count]);
                read += count as u64;
                between(read, self)?;
                self.encoder.check_source_io()?;
                self.checks.set(OBJECT_CHECK_EVERY - 1);
                self.check_objects()?;
                self.encoder.check_source_io()?;
            }
            ensure!(
                <[u8; 32]>::from(hash.clone().finalize()) == p.prefix_sha256(),
                "source prefix differs from approved checkpoint"
            );
            if restore {
                self.encoder.restore_prefix(hash, read)?;
                self.resume_base = Some(Box::new(
                    crate::fleet::control::ResumeBase::from_condition(p),
                ));
            } else {
                self.file
                    .as_mut()
                    .context("source closed")?
                    .seek(SeekFrom::Start(0))?;
            }
            self.encoder.check_source_io()?;
            self.checks.set(OBJECT_CHECK_EVERY - 1);
            self.check_objects()?;
            self.encoder.check_source_io()?;
            Ok(SourcePrefixObservation {
                condition_digest: p.digest(),
                grant_digest: p.expected_grant_digest(),
                bytes: read,
                sha256: p.prefix_sha256(),
            })
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
}
