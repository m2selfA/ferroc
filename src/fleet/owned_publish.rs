//! Windows-only LOCAL publication attempt, not final commit/receipt/P1.
use super::*;
use std::path::Path;
use std::{
    ffi::c_void,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr::null_mut,
};
#[path = "target_receipt.rs"]
mod target_receipt;
pub use target_receipt::{FinishedCandidate, ReceiptedCandidate};
#[repr(C)]
struct RenameInfo {
    flags: u32,
    root: *mut c_void,
    length: u32,
    name: [u16; 1],
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetFileInformationByHandle(
        h: *mut c_void,
        class: i32,
        info: *const c_void,
        length: u32,
    ) -> i32;
}
// NO source-path operation or fallback. Destination comes from actual policy +
// pinned parent. RootDirectory-relative Win32 form failed os87 in native probe.
fn rename_exact(file: &File, destination: &Path) -> Result<()> {
    ensure!(
        destination.is_absolute(),
        "native destination must be absolute"
    );
    let mut name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    ensure!(!name.contains(&0), "native destination contains NUL");
    let bytes = u32::try_from(name.len().checked_mul(2).context("native name overflow")?)?;
    name.push(0);
    let offset = std::mem::offset_of!(RenameInfo, name);
    let size = (offset + name.len() * 2).max(std::mem::size_of::<RenameInfo>());
    let length = u32::try_from(size)?;
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let p = storage.as_mut_ptr().cast::<RenameInfo>();
    // SAFETY: pointer-aligned zeroed buffer covers fixed layout and UTF16 name;
    // File retained throughout synchronous call. flags=0 NEVER replaces target.
    unsafe {
        (*p).flags = 0;
        (*p).root = null_mut();
        (*p).length = bytes;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            p.cast::<u8>().add(offset).cast::<u16>(),
            name.len(),
        );
        if SetFileInformationByHandle(file.as_raw_handle(), 3, p.cast(), length) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}
/// Same live owner AFTER a native no-replace rename. v7 stays CommitUnknown,
/// stage reservation retained; this is NOT a receipt or durable commit ACK.
/// File and parent guard drop BEFORE releasing the host operation. No recovery.
/// ```compile_fail
/// fn cannot_rebuild(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::host::receiver::RenamedCandidate::from(s);}
/// ```
/// ```compile_fail
/// fn cannot_publish_again(r:ferroc::fleet::host::receiver::RenamedCandidate<'_,'_>){r.attempt_local_publication().unwrap();}
/// ```
/// ```compile_fail
/// fn cannot_extract(r:ferroc::fleet::host::receiver::RenamedCandidate<'_,'_>){let _=r.inner;}
/// ```
/// ```compile_fail
/// fn cannot_deserialize(){let _=serde_json::from_str::<ferroc::fleet::host::receiver::RenamedCandidate<'_,'_>>("{}");}
/// ```
pub struct RenamedCandidate<'h, 'r> {
    _parent: File,
    inner: CommitCandidate<'h, 'r>,
}
impl RenamedCandidate<'_, '_> {
    #[cfg(test)]
    pub(in super::super) fn test_expire(&mut self) {
        self.inner.test_expire();
    }
    #[cfg(test)]
    pub(in super::super) fn test_move(&self, p: &Path) -> Result<()> {
        self.inner.test_move_owned(p)
    }
    pub fn snapshot(&self) -> &Snapshot {
        self.inner.snapshot()
    }
    pub fn observe(&mut self) -> Result<ReadbackObservation> {
        self.inner.observe()
    }
    pub fn revoke(&mut self) {
        self.inner.revoke()
    }
    pub fn renew(
        &mut self,
        g: ValidatedGrant,
        k: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<()> {
        self.inner.renew(g, k, t, a, b)
    }
}
impl<'h, 'r> CommitCandidate<'h, 'r> {
    #[cfg(test)]
    pub(in super::super) fn test_move_owned(&self, destination: &Path) -> Result<()> {
        rename_exact(&self.inner.inner.file, destination)
    }

    /// Consume current live owner; freshly hash under Runtime gate, durably mark
    /// v7 unknown BEFORE syscall, rename original File only, then recheck lease,
    /// object/revision/parent. Unsupported APIs/filesystems FAIL, never fallback.
    /// Errors CAN follow rename/SQL COMMIT. Never retry/adopt/delete/emit ACK.
    /// No claim against external/mmap writes or power loss. Not a final receipt.
    pub fn attempt_local_publication(self) -> Result<RenamedCandidate<'h, 'r>> {
        self.rename_between(|_| Ok(()), |_| Ok(()), |_, _| Ok(()))
    }
    pub(in super::super) fn rename_between(
        mut self,
        after_marker: impl FnOnce(&mut Self) -> Result<()>,
        after_rename: impl FnOnce(&mut Self) -> Result<()>,
        mut between: impl FnMut(u64, &mut Self) -> Result<()>,
    ) -> Result<RenamedCandidate<'h, 'r>> {
        let result = (|| {
            ensure!(
                !self.inner.inner.faulted
                    && self.inner.inner.ranges.complete()
                    && self.snapshot().phase() == Phase::Committing
                    && !self.snapshot().is_publication_attempt(),
                "invalid live publication candidate"
            );
            let host = self.inner.inner.operation.host;
            let _gate = host
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            let key = JobKey::from_job(self.snapshot().job());
            let check = |this: &Self| {
                no_wait(host, |db| {
                    let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .get(&key)?
                        .context("publication job missing")?;
                    this.inner.inner.current_snapshot(db, &s)
                })
            };
            let _initial = check(&self)?;
            self.inner.inner.records.receive_admission()?;
            let total = self.snapshot().job().bytes_total;
            let mut hash = Sha256::new();
            let mut offset = 0u64;
            let mut buffer = [0u8; 65536];
            self.inner.inner.file.seek(SeekFrom::Start(0))?;
            loop {
                let _parent = check(&self)?;
                self.inner.inner.records.receive_admission()?;
                ensure!(
                    self.inner.inner.file.metadata()?.len() == total,
                    "publication size changed"
                );
                let n = self.inner.inner.file.read(&mut buffer)?;
                self.inner.inner.records.receive_admission()?;
                if n == 0 {
                    break;
                }
                offset = offset
                    .checked_add(n as u64)
                    .context("publication read overflow")?;
                ensure!(offset <= total, "publication exceeds task");
                hash.update(&buffer[..n]);
                between(offset, &mut self)?;
            }
            let actual: [u8; 32] = hash.finalize().into();
            ensure!(
                offset == total && actual == self.snapshot().job().sha256,
                "publication Runtime-gate SHA256 mismatch"
            );
            self.inner.inner.file.sync_all()?;
            ensure!(
                self.inner.inner.file.metadata()?.len() == total,
                "publication final size changed"
            );
            no_wait(host, |db| {
                let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .get(&key)?
                    .context("publication job missing")?;
                let _parent = self.inner.inner.current_snapshot(db, &s)?;
                self.inner.inner.records.receive_admission()?;
                self.inner.inner.snapshot =
                    Journal::existing_fenced(&mut db.connection, &db.fence)?
                        .mark_publication_attempt(&key, s.revision())?;
                self.inner.inner.records.receive_admission()?;
                Ok(())
            })?;
            after_marker(&mut self)?;
            // No DB waits while gate owned. Once this mutex is acquired,
            // cancellation queues BEHIND the native attempt, not through it.
            let parent = no_wait(host, |db| {
                let s = Journal::existing_fenced(&mut db.connection, &db.fence)?
                    .get(&key)?
                    .context("publication job missing")?;
                let parent = self.inner.inner.current_snapshot(db, &s)?;
                self.inner.inner.records.receive_admission()?;
                let (dest, guard, _) =
                    crate::fleet::allocation::parent(&host.attachment.runtime.policy, &s)?;
                ensure!(
                    self.inner.inner.file.metadata()?.len() == total,
                    "publication final size changed"
                );
                rename_exact(&self.inner.inner.file, &dest)?;
                self.inner.inner.published = true;
                self.inner.inner.records.receive_admission()?;
                let _again = self.inner.inner.current_snapshot(db, &s)?;
                drop(guard);
                Ok(parent)
            })?;
            after_rename(&mut self)?;
            let _parent = check(&self)?;
            ensure!(
                self.inner.inner.file.metadata()?.len() == total,
                "publication final size changed"
            );
            self.inner.inner.records.receive_admission()?;
            Ok(parent)
        })();
        match result {
            Ok(parent) => Ok(RenamedCandidate {
                _parent: parent,
                inner: self,
            }),
            Err(e) => {
                self.inner.revoke();
                Err(e)
            }
        }
    }
}
