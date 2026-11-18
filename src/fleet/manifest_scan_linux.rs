//! Linux read-sequence scanner. O_PATH pins names without opening devices/FIFOs;
//! only validated regular files are reopened through procfs for read-only IO.
//! Directory FDs do not exclude rename or external writes. No snapshot/sandbox.
use super::{ManifestObservation, ScanLimits};
use crate::{
    fleet::{
        manifest::{EntryKind, Manifest, ManifestEntry},
        manifest_view::ScanRules,
        source_file::object_id,
        sync_exec::CancelToken,
    },
    runtime::Runtime,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{File, Metadata, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::Mutex,
};

struct Anchor {
    path: PathBuf,
    file: File,
    id: String,
}
fn component(path: &Path) -> Result<CString> {
    CString::new(
        path.file_name()
            .context("scan component missing")?
            .as_bytes(),
    )
    .context("scan component contains NUL")
}
fn open_at(parent: &File, path: &Path) -> Result<File> {
    let name = component(path)?;
    // SAFETY: retained parent FD and one live NUL-terminated component. O_PATH
    // does not open special objects; O_NOFOLLOW pins a symlink itself, which
    // object_id's plain-object validation rejects before any read/open for IO.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "scan openat failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn proc_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
fn stamp(metadata: &Metadata) -> Result<(u64, std::time::SystemTime, i64, i64)> {
    Ok((
        metadata.len(),
        metadata.modified()?,
        metadata.ctime(),
        metadata.ctime_nsec(),
    ))
}
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy)]
enum Event<'a> {
    DirectoryRead(&'a Path),
    FileChunk(&'a Path, u64),
}

pub(super) fn observe(
    runtime: &Runtime,
    gate: &Mutex<()>,
    root: &Path,
    limits: ScanLimits,
    cancel: &CancelToken,
    rules: &ScanRules,
) -> Result<ManifestObservation> {
    observe_with(runtime, gate, root, limits, cancel, rules, |_| Ok(()))
}
#[allow(clippy::too_many_arguments)]
fn observe_with(
    runtime: &Runtime,
    gate: &Mutex<()>,
    root: &Path,
    limits: ScanLimits,
    cancel: &CancelToken,
    rules: &ScanRules,
    hook: impl FnMut(Event<'_>) -> Result<()>,
) -> Result<ManifestObservation> {
    ensure!(!cancel.is_cancelled(), "manifest scan cancelled");
    ensure!(
        limits.max_depth > 0
            && limits.max_depth <= crate::fleet::manifest::MAX_DEPTH
            && limits.max_hashed_bytes <= super::MAX_HASHED_BYTES,
        "scan limits outside hard ceilings"
    );
    let _ = Manifest::new(Vec::new(), limits.manifest)?;
    crate::fleet::fence::local_path(root)?;
    let _life = runtime.fleet_source_guard()?;
    let _gate = gate
        .lock()
        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
    let root_text = root.to_str().context("non-UTF8 scan root")?;
    ensure!(
        runtime.policy.resolve(root_text)? == root,
        "scan root resolves elsewhere"
    );
    let ancestors: Vec<_> = root.ancestors().collect();
    ensure!(
        ancestors.len() <= crate::fleet::manifest::MAX_DEPTH + 1,
        "scan root ancestor depth exceeded"
    );
    let mut anchors: Vec<Anchor> = Vec::with_capacity(ancestors.len());
    for path in ancestors.into_iter().rev() {
        ensure!(!cancel.is_cancelled(), "manifest scan cancelled");
        let file = if let Some(previous) = anchors.last() {
            open_at(&previous.file, path)?
        } else {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
                .open(path)?
        };
        let id = object_id(&file, true)?;
        anchors.push(Anchor {
            path: path.to_owned(),
            file,
            id,
        });
    }
    let mut scanner = LinuxScan {
        runtime,
        root,
        limits,
        cancel,
        rules,
        hook,
        anchors,
        entries: Vec::new(),
        names: 0,
        paths: 0,
        bytes: 0,
        files: 0,
        seen: BTreeSet::new(),
        buffer: vec![0u8; 65536].into_boxed_slice(),
    };
    scanner.walk(root, "", 0)?;
    scanner.recheck(root)?;
    Ok(ManifestObservation {
        manifest: Manifest::new(std::mem::take(&mut scanner.entries), limits.manifest)?,
        bytes_hashed: scanner.bytes,
        files_hashed: scanner.files,
        rules_digest: rules.digest(),
    })
}
struct LinuxScan<'a, F> {
    runtime: &'a Runtime,
    root: &'a Path,
    limits: ScanLimits,
    cancel: &'a CancelToken,
    rules: &'a ScanRules,
    hook: F,
    anchors: Vec<Anchor>,
    entries: Vec<ManifestEntry>,
    names: usize,
    paths: usize,
    bytes: u64,
    files: usize,
    seen: BTreeSet<String>,
    buffer: Box<[u8]>,
}
impl<F> Drop for LinuxScan<'_, F> {
    fn drop(&mut self) {
        self.buffer.fill(0);
    }
}
impl<F: FnMut(Event<'_>) -> Result<()>> LinuxScan<'_, F> {
    fn recheck(&self, path: &Path) -> Result<()> {
        ensure!(!self.cancel.is_cancelled(), "manifest scan cancelled");
        for (index, anchor) in self.anchors.iter().enumerate() {
            let current = if index == 0 {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY,
                    )
                    .open(&anchor.path)?
            } else {
                open_at(&self.anchors[index - 1].file, &anchor.path)?
            };
            ensure!(
                object_id(&anchor.file, true)? == anchor.id
                    && object_id(&current, true)? == anchor.id,
                "scan ancestor changed"
            );
        }
        ensure!(
            self.runtime
                .policy
                .resolve(self.root.to_str().context("non-UTF8 root")?)?
                == self.root,
            "scan root resolves elsewhere"
        );
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
        self.recheck(path)?;
        let directory = self
            .anchors
            .last()
            .context("scan directory anchor absent")?
            .file
            .try_clone()?;
        let id = object_id(&directory, true)?;
        ensure!(self.seen.insert(id.clone()), "duplicate scan object");
        let before = stamp(&directory.metadata()?)?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(proc_path(&directory))? {
            ensure!(!self.cancel.is_cancelled(), "manifest scan cancelled");
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 scan name refused"))?;
            let child = if relative.is_empty() {
                name.clone()
            } else {
                format!("{relative}/{name}")
            };
            crate::fleet::manifest::validate_path(&child)?;
            ensure!(depth < self.limits.max_depth, "scan depth exceeded");
            self.names = self
                .names
                .checked_add(1)
                .context("scan entry count overflow")?;
            self.paths = self
                .paths
                .checked_add(child.len())
                .context("scan path byte overflow")?;
            ensure!(
                self.names <= self.limits.manifest.max_entries,
                "scan entry limit exceeded"
            );
            ensure!(
                self.paths <= self.limits.manifest.max_total_path_bytes,
                "scan path byte limit exceeded"
            );
            names.push((name, child));
        }
        names.sort();
        (self.hook)(Event::DirectoryRead(path))?;
        self.recheck(path)?;
        for (name, child) in &names {
            if self.rules.excludes(child) {
                continue;
            }
            self.recheck(path)?;
            let child_path = path.join(name);
            let descriptor = open_at(&directory, &child_path)?;
            let is_directory = descriptor.metadata()?.is_dir();
            let id = object_id(&descriptor, is_directory)?;
            if is_directory {
                self.entries.push(ManifestEntry {
                    path: child.clone(),
                    kind: EntryKind::Directory,
                });
                self.anchors.push(Anchor {
                    path: child_path.clone(),
                    file: descriptor,
                    id,
                });
                self.walk(&child_path, child, depth + 1)?;
                self.anchors.pop();
            } else {
                let kind = self.hash(&directory, &descriptor, &child_path)?;
                self.entries.push(ManifestEntry {
                    path: child.clone(),
                    kind,
                });
            }
        }
        self.recheck(path)?;
        let mut final_names = Vec::new();
        for entry in std::fs::read_dir(proc_path(&directory))? {
            ensure!(!self.cancel.is_cancelled(), "manifest scan cancelled");
            ensure!(
                final_names.len() < names.len(),
                "scan directory names changed"
            );
            final_names.push(entry?.file_name());
        }
        final_names.sort();
        let initial: Vec<_> = names
            .iter()
            .map(|(name, _)| std::ffi::OsString::from(name))
            .collect();
        ensure!(
            initial == final_names && stamp(&directory.metadata()?)? == before,
            "scan directory changed"
        );
        Ok(())
    }
    fn hash(&mut self, parent: &File, descriptor: &File, path: &Path) -> Result<EntryKind> {
        self.recheck(path)?;
        let id = object_id(descriptor, false)?;
        ensure!(self.seen.insert(id.clone()), "duplicate scan object");
        let before = descriptor.metadata()?;
        let size = before.len();
        ensure!(
            size <= crate::fleet::protocol::MAX_FILE_BYTES,
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
        // The O_PATH descriptor remains live through reopen and all read IO;
        // procfs is an explicit dependency, never an unchecked pathname fallback.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(proc_path(descriptor))?;
        ensure!(
            object_id(&file, false)? == id,
            "scan read descriptor changed"
        );
        let mut digest = Sha256::new();
        let mut offset = 0;
        while offset < size {
            self.recheck(path)?;
            let want = ((size - offset).min(self.buffer.len() as u64)) as usize;
            let count = file.read(&mut self.buffer[..want])?;
            ensure!(count > 0, "scan file truncated during read");
            digest.update(&self.buffer[..count]);
            offset += count as u64;
            (self.hook)(Event::FileChunk(path, offset))?;
            self.recheck(path)?;
        }
        ensure!(
            stamp(&file.metadata()?)? == stamp(&before)?
                && object_id(&file, false)? == id
                && object_id(&open_at(parent, path)?, false)? == id,
            "scan file changed during read"
        );
        self.recheck(path)?;
        self.buffer.fill(0);
        let mtime = match before.modified()?.duration_since(std::time::UNIX_EPOCH) {
            Ok(v) => i128::try_from(v.as_nanos()).context("scan mtime overflow")?,
            Err(v) => -i128::try_from(v.duration().as_nanos()).context("scan mtime overflow")?,
        };
        self.files += 1;
        self.bytes = total;
        Ok(EntryKind::File {
            size,
            mtime_ns: i64::try_from(mtime).context("scan mtime outside signed range")?,
            sha256: Some(digest.finalize().into()),
        })
    }
}
#[cfg(test)]
#[path = "manifest_scan_linux_tests.rs"]
mod tests;
