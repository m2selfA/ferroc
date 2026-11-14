//! Bounded LOCAL Windows tree observation, not a snapshot or remote scan grant.
//! No writes, exclusion rules, pagination, apply, cleanup, network or restore.
use super::{
    manifest::{Manifest, ManifestLimits},
    sync_exec::CancelToken,
};
use crate::runtime::Runtime;
use anyhow::Result;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

pub const MAX_HASHED_BYTES: u64 = 1024 * 1024 * 1024;
#[derive(Clone, Copy, Debug)]
pub struct ScanLimits {
    pub manifest: ManifestLimits,
    pub max_depth: usize,
    pub max_hashed_bytes: u64,
}
impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            manifest: ManifestLimits::default(),
            max_depth: super::manifest::MAX_DEPTH,
            max_hashed_bytes: 64 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanConsistency {
    ReadSequence,
}
/// Actual local reads, but external writers are NOT excluded. Hashes describe a
/// sequence of reads; they are not cached permission to publish later.
/// ```compile_fail
/// fn no_apply(o:ferroc::fleet::manifest_scan::ManifestObservation){o.apply().unwrap();}
/// ```
#[derive(Debug)]
pub struct ManifestObservation {
    manifest: Manifest,
    bytes_hashed: u64,
    files_hashed: usize,
}
impl ManifestObservation {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn into_manifest(self) -> Manifest {
        self.manifest
    }
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed
    }
    pub fn files_hashed(&self) -> usize {
        self.files_hashed
    }
    pub fn consistency(&self) -> ScanConsistency {
        ScanConsistency::ReadSequence
    }
    pub fn namespace(&self) -> super::manifest::Namespace {
        super::manifest::Namespace::ExactUtf8Unqualified
    }
}

pub(crate) fn observe(
    runtime: &Runtime,
    gate: Arc<Mutex<()>>,
    root: &Path,
    limits: ScanLimits,
    cancel: &CancelToken,
) -> Result<ManifestObservation> {
    #[cfg(windows)]
    {
        observe_with(runtime, &gate, root, limits, cancel, |_| Ok(()))
    }
    #[cfg(not(windows))]
    {
        let _ = (runtime, gate, root, limits, cancel);
        anyhow::bail!("local manifest observation is a Windows-only candidate; no fallback")
    }
}

#[cfg(windows)]
// Event payloads are consumed only by native cfg(test) probes.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) enum ScanEvent<'a> {
    DirectoryRead(&'a Path),
    FileChunk(&'a Path, u64),
}

#[cfg(windows)]
pub(crate) fn observe_with(
    runtime: &Runtime,
    gate: &Mutex<()>,
    root: &Path,
    limits: ScanLimits,
    cancel: &CancelToken,
    hook: impl FnMut(ScanEvent<'_>) -> Result<()>,
) -> Result<ManifestObservation> {
    use super::source_file::{object_id, open_object};
    use anyhow::{Context, ensure};
    ensure!(!cancel.is_cancelled(), "manifest scan cancelled");
    ensure!(
        limits.max_depth > 0
            && limits.max_depth <= super::manifest::MAX_DEPTH
            && limits.max_hashed_bytes <= MAX_HASHED_BYTES,
        "scan limits outside hard ceilings"
    );
    // Validate both manifest ceilings before doing any directory enumeration.
    let _ = Manifest::new(Vec::new(), limits.manifest)?;
    super::fence::local_path(root)?;
    let _life = runtime.fleet_source_guard()?;
    let _fs = gate
        .lock()
        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
    ensure!(!cancel.is_cancelled(), "manifest scan cancelled");
    // Authorize before opening the original root chain, but do not discard its
    // spelling: canonicalization alone would hide an in-policy junction.
    let resolved = runtime
        .policy
        .resolve(root.to_str().context("non-UTF8 root")?)?;
    super::fence::local_path(&resolved)?;
    let ancestors: Vec<_> = root.ancestors().collect();
    ensure!(
        ancestors.len() <= super::manifest::MAX_DEPTH + 1,
        "scan root ancestor depth exceeded"
    );
    // Inspect the ORIGINAL spelling even when Policy canonicalization resolved
    // a junction. Keep every ancestor open so ordinary Windows renames cannot swap
    // a path component during the accepted scan. This is not a general sandbox.
    let mut anchors = Vec::with_capacity(ancestors.len());
    for path in ancestors.iter().rev() {
        let file = open_object(path, true)?;
        let id = object_id(&file, true)?;
        anchors.push((path.to_path_buf(), id, file));
    }
    ensure!(
        object_id(&open_object(&resolved, true)?, true)?
            == anchors.last().context("root anchor missing")?.1,
        "scan root changed"
    );
    let mut scanner = WindowsScan {
        runtime,
        limits,
        cancel,
        hook,
        entries: Vec::new(),
        paths: 0,
        names_seen: 0,
        bytes: 0,
        files: 0,
        seen: std::collections::BTreeSet::new(),
        buffer: vec![0u8; 65536].into_boxed_slice(),
    };
    scanner.walk(&resolved, "", 0)?;
    for (path, id, file) in &anchors {
        ensure!(
            object_id(file, true)? == *id && object_id(&open_object(path, true)?, true)? == *id,
            "scan ancestor changed"
        );
    }
    ensure!(!cancel.is_cancelled(), "manifest scan cancelled");
    let manifest = Manifest::new(std::mem::take(&mut scanner.entries), limits.manifest)?;
    Ok(ManifestObservation {
        manifest,
        bytes_hashed: scanner.bytes,
        files_hashed: scanner.files,
    })
}

#[cfg(windows)]
struct WindowsScan<'a, F> {
    runtime: &'a Runtime,
    limits: ScanLimits,
    cancel: &'a CancelToken,
    hook: F,
    entries: Vec<super::manifest::ManifestEntry>,
    paths: usize,
    names_seen: usize,
    bytes: u64,
    files: usize,
    seen: std::collections::BTreeSet<String>,
    buffer: Box<[u8]>,
}
#[cfg(windows)]
impl<F> Drop for WindowsScan<'_, F> {
    fn drop(&mut self) {
        self.buffer.fill(0);
    }
}
#[cfg(windows)]
impl<F: FnMut(ScanEvent<'_>) -> Result<()>> WindowsScan<'_, F> {
    fn check(&self) -> Result<()> {
        anyhow::ensure!(!self.cancel.is_cancelled(), "manifest scan cancelled");
        Ok(())
    }
    fn policy(&self, path: &Path) -> Result<()> {
        use anyhow::{Context, ensure};
        ensure!(
            self.runtime
                .policy
                .resolve(path.to_str().context("non-UTF8 scan path")?)?
                == path,
            "scan canonical path changed"
        );
        Ok(())
    }
    fn walk(&mut self, path: &Path, relative: &str, depth: usize) -> Result<()> {
        use super::{
            manifest::{EntryKind, ManifestEntry},
            source_file::{object_id, open_object},
        };
        use anyhow::{Context, ensure};
        self.check()?;
        self.policy(path)?;
        let directory = open_object(path, true)?;
        let id = object_id(&directory, true)?;
        ensure!(self.seen.insert(id.clone()), "duplicate scan object");
        let modified = directory.metadata()?.modified()?;
        let mut children = Vec::new();
        for entry in std::fs::read_dir(path)? {
            self.check()?;
            let entry = entry.context("enumerate scan directory")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 scan name refused"))?;
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            super::manifest::validate_path(&child)?;
            ensure!(depth < self.limits.max_depth, "scan depth exceeded");
            self.paths = self
                .paths
                .checked_add(child.len())
                .context("scan path byte overflow")?;
            ensure!(
                self.paths <= self.limits.manifest.max_total_path_bytes,
                "scan path byte limit exceeded"
            );
            // Entries already completed plus names queued in ancestor frames
            // are counted before allocating each queued child.
            self.names_seen = self
                .names_seen
                .checked_add(1)
                .context("scan entry count overflow")?;
            ensure!(
                self.names_seen <= self.limits.manifest.max_entries,
                "scan entry limit exceeded"
            );
            children.push((child, entry.path()));
        }
        (self.hook)(ScanEvent::DirectoryRead(path))?;
        children.sort_by(|a, b| a.0.cmp(&b.0));
        let mut initial_names: Vec<_> = children
            .iter()
            .map(|(_, p)| p.file_name().unwrap().to_os_string())
            .collect();
        initial_names.sort();
        for (child, child_path) in children {
            self.check()?;
            let metadata = std::fs::symlink_metadata(&child_path)?;
            if metadata.is_dir() {
                self.entries.push(ManifestEntry {
                    path: child.clone(),
                    kind: EntryKind::Directory,
                });
                self.walk(&child_path, &child, depth + 1)?;
            } else {
                let kind = self.hash(&child_path)?;
                self.entries.push(ManifestEntry { path: child, kind });
            }
        }
        self.check()?;
        // A second bounded name read detects simple additions/removals even if
        // directory timestamp updates are delayed. It is still not a snapshot.
        let mut final_names = Vec::new();
        for entry in std::fs::read_dir(path)? {
            self.check()?;
            ensure!(
                final_names.len() < initial_names.len(),
                "scan directory names changed"
            );
            final_names.push(entry?.file_name());
        }
        final_names.sort();
        ensure!(initial_names == final_names, "scan directory names changed");
        self.policy(path)?;
        ensure!(
            object_id(&directory, true)? == id
                && object_id(&open_object(path, true)?, true)? == id
                && directory.metadata()?.modified()? == modified,
            "scan directory changed"
        );
        Ok(())
    }
    fn hash(&mut self, path: &Path) -> Result<super::manifest::EntryKind> {
        use super::source_file::{object_id, open_object};
        use anyhow::{Context, ensure};
        use sha2::{Digest, Sha256};
        use std::io::Read;
        self.check()?;
        self.policy(path)?;
        let mut file = open_object(path, false)?;
        let id = object_id(&file, false)?;
        ensure!(self.seen.insert(id.clone()), "duplicate scan object");
        let before = file.metadata()?;
        let size = before.len();
        let modified = before.modified()?;
        ensure!(
            size <= super::protocol::MAX_FILE_BYTES,
            "scan file exceeds fleet ceiling"
        );
        let total = self
            .bytes
            .checked_add(size)
            .context("scan hash byte overflow")?;
        ensure!(
            total <= self.limits.max_hashed_bytes,
            "scan hash byte limit exceeded"
        );
        let mut sha = Sha256::new();
        let mut offset = 0;
        while offset < size {
            self.check()?;
            let want = ((size - offset).min(self.buffer.len() as u64)) as usize;
            let count = file.read(&mut self.buffer[..want])?;
            ensure!(count > 0, "scan file truncated during read");
            sha.update(&self.buffer[..count]);
            offset += count as u64;
            (self.hook)(ScanEvent::FileChunk(path, offset))?;
            self.check()?;
        }
        let after = file.metadata()?;
        ensure!(
            after.len() == size
                && after.modified()? == modified
                && object_id(&file, false)? == id
                && object_id(&open_object(path, false)?, false)? == id,
            "scan file changed during read"
        );
        self.policy(path)?;
        self.check()?;
        self.buffer.fill(0);
        let mtime = match modified.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => i128::try_from(duration.as_nanos()).context("scan mtime overflow")?,
            Err(error) => {
                -i128::try_from(error.duration().as_nanos()).context("scan mtime overflow")?
            }
        };
        let mtime_ns =
            i64::try_from(mtime).context("scan mtime outside signed nanosecond range")?;
        self.files += 1;
        self.bytes = total;
        Ok(super::manifest::EntryKind::File {
            size,
            mtime_ns,
            sha256: Some(sha.finalize().into()),
        })
    }
}

#[cfg(all(test, windows))]
#[path = "manifest_scan_tests.rs"]
mod tests;
