//! Real same-DB fence takeover of a recovered retained stage. Reopens the
//! ORIGINAL object, verifies identity/parent/length/prefix in the actual
//! Runtime fs_gate, then binds the allocation via the existing bind_reference.
//! Returns a real File only after every check; any failure leaves the
//! allocation unbound and full debt retained. NOT a publication permit, debt
//! release, automatic retry or network admission.
use crate::config::Policy;
use crate::fleet::control::ParentDurability;
use crate::fleet::fence::{FencedConnection, directory_id};
use crate::fleet::identity::{open_private, open_stage};
use crate::fleet::journal::{JobKey, Journal};
use crate::fleet::state::Phase;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
};
impl FencedConnection {
    /// Caller holds the real fs_gate EXTERNALLY (the admission path serializes
    /// this Runtime). Reopens and verifies the recovered named stage, then
    /// binds its object id. `expected_prefix` rehashes the declared prefix
    /// against the actual bytes before binding; length may exceed the prefix.
    /// Currently reachable only from tests; the FleetHost admission wiring is
    /// the NEXT increment. Kept strict-lint clean with an explicit allow.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn adopt_retained_stage(
        &mut self,
        key: &JobKey,
        revision: u64,
        policy: &Policy,
        fs_gate: Arc<Mutex<()>>,
        expected_prefix: Option<(&[u8; 32], u64)>,
    ) -> Result<(File, u64)> {
        let _gate = fs_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        let s = Journal::existing_fenced(&mut self.connection, &self.fence)?
            .get(key)?
            .context("adopt job missing")?;
        ensure!(
            s.owner() == self.fence.owner
                && s.revision() == revision
                && s.phase() == Phase::Interrupted
                && s.data_seal().is_none()
                && s.intent().is_none()
                && s.receipt().is_none(),
            "adopt requires same-DB recovered interrupted job"
        );
        let reference = s.stage().context("adopt stage missing")?;
        let a = reference.allocation().context("adopt allocation missing")?;
        ensure!(!a.is_anonymous(), "adopt requires named retained stage");
        ensure!(
            a.original_owner() != self.fence.owner
                && a.database_id() == Some(self.fence.database_id())
                && a.database_parent_id() == Some(self.fence.database_parent_id()?.as_str()),
            "adopt allocation domain mismatch"
        );
        let (dest, directory, parent_id) = super::allocation::parent(policy, &s)?;
        ensure!(
            dest.parent() == reference.path().parent() && parent_id == a.parent_id(),
            "reserved parent object changed"
        );
        let mut file = open_stage(reference.path())?;
        let object = super::allocation::stage_object_id(&file, false, false)?;
        ensure!(
            super::allocation::stage_path_matches(reference.path(), &object, false)?
                && directory_id(&open_private(reference.path().parent().unwrap(), true)?)?
                    == parent_id,
            "adopted stage/parent object changed"
        );
        let length = file.metadata()?.len();
        ensure!(length <= s.job().bytes_total, "adopted stage oversized");
        if let Some((sha, bytes)) = expected_prefix {
            ensure!(bytes <= length, "adopted stage shorter than prefix");
            file.seek(SeekFrom::Start(0))?;
            let mut h = Sha256::new();
            let mut buf = [0u8; 65536];
            let mut read = 0u64;
            while read < bytes {
                let n = (bytes - read).min(buf.len() as u64) as usize;
                file.read_exact(&mut buf[..n])?;
                h.update(&buf[..n]);
                read += n as u64;
            }
            ensure!(
                <[u8; 32]>::from(h.finalize()) == *sha,
                "adopted prefix mismatch"
            );
            file.seek(SeekFrom::Start(0))?;
        }
        let _ = directory;
        // Windows keeps durability Unsupported; Linux named parent sync below.
        #[cfg(unix)]
        let durability = {
            directory.sync_all()?;
            ParentDurability::Synced
        };
        #[cfg(not(unix))]
        let durability = ParentDurability::Unsupported;
        self.fence.check_connection(&self.connection)?;
        Journal::existing_fenced(&mut self.connection, &self.fence)?.rebind_recovered_reference(
            key,
            revision,
            &object,
            durability,
            a.original_owner(),
        )?;
        Ok((file, length))
    }
}
