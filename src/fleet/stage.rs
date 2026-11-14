//! Local, network-free stage primitive. No overwrite, no mkdir, no journal.
//! Directory policy is NOT an OS sandbox. Source consistency and signed digest
//! admission belong to the future service; this primitive cannot prove them.
use super::{
    protocol::MAX_FILE_BYTES,
    ranges::{Admission, ReceiveRanges},
};
use crate::config::Policy;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tempfile::NamedTempFile;

#[cfg(test)]
#[path = "stage_tests.rs"]
mod tests;

const MAX_ACTIVE: usize = 4;
#[derive(Debug)]
struct Budget {
    limit: u64,
    reserved: u64,
    active: usize,
    max_active: usize,
    retained: Vec<RetainedStage>,
    recovery_closed: bool,
}
/// Residual stage ownership recorded after cleanup could not be confirmed.
/// Paths are local diagnostic data, never credentials or peer-selected inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedStage {
    pub path: PathBuf,
    pub bytes: u64,
}
/// Logical byte/active-stage quota, NOT physical free-space reservation.
/// Failed cleanup retains charges (including an active slot) until the owned
/// path is confirmed absent. Detected object-identity loss permanently quarantines
/// this entire component budget: path absence then cannot prove original cleanup.
/// Retained entries are bounded by max_active.
#[derive(Clone, Debug)]
pub struct StageBudget(Arc<Mutex<Budget>>);
impl StageBudget {
    pub fn new(limit: u64, max_active: usize) -> Result<Self> {
        ensure!(
            limit <= MAX_FILE_BYTES * MAX_ACTIVE as u64 && (1..=MAX_ACTIVE).contains(&max_active),
            "invalid fleet stage budget"
        );
        Ok(Self(Arc::new(Mutex::new(Budget {
            limit,
            reserved: 0,
            active: 0,
            max_active,
            retained: Vec::new(),
            recovery_closed: false,
        }))))
    }
    /// A reconstructed or ownership-lost budget can report debt but cannot
    /// authorize reception or release obligations by merely observing absence.
    /// ```compile_fail
    /// use ferroc::fleet::stage::StageBudget;
    /// fn cannot_seed_from_untrusted_paths() {
    ///     StageBudget::reconstruct_quarantined(10,1,&[]).unwrap();
    /// }
    /// ```
    pub fn is_quarantined(&self) -> Result<bool> {
        Ok(self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("stage budget poisoned"))?
            .recovery_closed)
    }
    pub(super) fn reconstruct_quarantined(
        limit: u64,
        max_active: usize,
        charges: &[(PathBuf, u64)],
    ) -> Result<Self> {
        let budget = Self::new(limit, max_active)?;
        let mut total = 0u64;
        ensure!(
            charges.len() <= max_active,
            "recovery active-slot quota exceeded"
        );
        for (_, bytes) in charges {
            ensure!(*bytes <= MAX_FILE_BYTES, "recovery file quota invalid");
            total = total
                .checked_add(*bytes)
                .context("recovery quota overflow")?;
        }
        ensure!(total <= limit, "recovery byte quota exceeded");
        {
            let mut b = budget
                .0
                .lock()
                .map_err(|_| anyhow::anyhow!("stage budget poisoned"))?;
            b.reserved = total;
            b.active = charges.len();
            b.recovery_closed = true;
        }
        Ok(budget)
    }
    fn reserve(&self, bytes: u64) -> Result<Reservation> {
        let mut b = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("stage budget poisoned"))?;
        ensure!(
            !b.recovery_closed,
            "reconstructed stage budget is quarantined"
        );
        ensure!(
            bytes <= MAX_FILE_BYTES && b.active < b.max_active && bytes <= b.limit - b.reserved,
            "fleet stage budget exhausted"
        );
        b.reserved += bytes;
        b.active += 1;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
            stage_path: None,
            ownership_uncertain: Arc::new(AtomicBool::new(false)),
        })
    }
    /// List current-process failed-cleanup residuals only; this does not list
    /// recovered logical obligations (see RecoveryInventory). Never deletes
    /// paths or releases their charges.
    pub fn retained(&self) -> Result<Vec<RetainedStage>> {
        let b = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("stage budget poisoned"))?;
        Ok(b.retained.clone())
    }
    /// Release ONLY registered residual paths now confirmed absent. This does
    /// not delete anything and cannot accept arbitrary peer-provided paths.
    /// Before removing a residual, the owner must ensure it is still their file.
    pub fn reconcile_removed(&self) -> Result<usize> {
        let mut b = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("stage budget poisoned"))?;
        ensure!(
            !b.recovery_closed,
            "quarantined obligations require separate ownership reconciliation"
        );
        let mut removed = 0;
        let mut i = 0;
        while i < b.retained.len() {
            if confirmed_absent(&b.retained[i].path) {
                let entry = b.retained.swap_remove(i);
                b.reserved -= entry.bytes;
                b.active -= 1;
                removed += 1;
            } else {
                i += 1;
            }
        }
        Ok(removed)
    }
    pub fn usage(&self) -> Result<(u64, usize)> {
        let b = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("stage budget poisoned"))?;
        Ok((b.reserved, b.active))
    }
}
struct Reservation {
    budget: StageBudget,
    bytes: u64,
    stage_path: Option<PathBuf>,
    ownership_uncertain: Arc<AtomicBool>,
}
fn confirmed_absent(path: &Path) -> bool {
    matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut b = self
            .budget
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(path) = &self.stage_path
            && (self.ownership_uncertain.load(Ordering::SeqCst) || !confirmed_absent(path))
        {
            // Keep both charges: cleanup error, unreadable path, a residual
            // hardlink, or unknown state must never admit replacement work.
            b.retained.push(RetainedStage {
                path: path.clone(),
                bytes: self.bytes,
            });
            return;
        }
        b.reserved -= self.bytes;
        b.active -= 1;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParentSync {
    Synced,
    Unsupported,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Publication {
    /// File data sync + no-clobber publication succeeded. Not a journal receipt
    /// and not proof of crash durability on platforms without parent sync.
    Published {
        size: u64,
        sha256: [u8; 32],
        parent_sync: ParentSync,
    },
    /// A publication was attempted. Never turn this into a safe-to-retry failure.
    Uncertain {
        size: u64,
        sha256: [u8; 32],
        reason: &'static str,
    },
}

/// Ownership-preserving rejection before native publication. Nothing is
/// automatically cancelled/deleted: the caller must settle journal state first.
/// Dropping this error still runs normal best-effort StageFile cleanup; retain it
/// or recover its stage when the caller needs durable reconciliation.
pub struct StageRejected<T> {
    stage: Box<T>,
    error: anyhow::Error,
}
impl<T> StageRejected<T> {
    fn new(stage: T, error: anyhow::Error) -> Self {
        Self {
            stage: Box::new(stage),
            error,
        }
    }
    pub fn reason(&self) -> &anyhow::Error {
        &self.error
    }
    pub fn into_parts(self) -> (T, anyhow::Error) {
        (*self.stage, self.error)
    }
}
impl<T> std::fmt::Debug for StageRejected<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageRejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<T> std::fmt::Display for StageRejected<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}
impl<T> std::error::Error for StageRejected<T> {}
/// Readback observation, not a reusable lease/authorization or a filesystem
/// sandbox. No write_chunk API is exposed. Same-user external mutations remain
/// outside Policy's guarantee; size is rechecked at publication admission.
/// ```compile_fail
/// use ferroc::fleet::stage::VerifiedStage;
/// fn cannot_modify(mut verified: VerifiedStage) {
///     verified.write_chunk(0, b"unverified change").unwrap();
/// }
/// ```
pub struct VerifiedStage {
    stage: StageFile,
    size: u64,
    sha256: [u8; 32],
}
impl std::fmt::Debug for VerifiedStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedStage")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
impl VerifiedStage {
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn into_stage(self) -> StageFile {
        self.stage
    }
    /// Trusted LOCAL admission callback runs exactly once under the actual fs
    /// gate after policy/absence/size checks. It must bind job/revision/owner and
    /// check the real lease immediately before returning (including after SQL
    /// fsync). Its success is the admission boundary: later cancellation cannot
    /// promise rollback. Never reenter fs_gate or infer owner death here.
    /// Callback errors retain stage+reservation. After native publication is
    /// attempted, only Published/Uncertain is returned, never safe-to-retry Err.
    pub fn publish_with(
        self,
        admit: impl FnOnce() -> Result<()>,
    ) -> std::result::Result<Publication, StageRejected<Self>> {
        self.publish_checked(|| Ok(()), admit)
    }
    /// Rehash the actual stage under its real fs_gate before final admission.
    /// check runs before/after each64KiB read and after sync; it must NOT acquire
    /// DB or reenter fs_gate. This is a COMPONENT API, not host commit wiring:
    /// future host integration must solve journal cancellation/intent lock order.
    /// admit must not mutate the stage; cooperative Runtime writes are excluded
    /// until no-clobber. Hostile same-user IO is not an OS sandbox guarantee.
    pub fn publish_checked(
        mut self,
        mut check: impl FnMut() -> Result<()>,
        admit: impl FnOnce() -> Result<()>,
    ) -> std::result::Result<Publication, StageRejected<Self>> {
        let gate = Arc::clone(&self.stage.fs_gate);
        let _guard = match gate.lock() {
            Ok(g) => g,
            Err(_) => {
                return Err(StageRejected::new(
                    self,
                    anyhow::anyhow!("filesystem gate poisoned"),
                ));
            }
        };
        let preflight = (|| -> Result<PathBuf> {
            ensure!(
                !self.stage.faulted
                    && !self
                        .stage
                        ._reservation
                        .ownership_uncertain
                        .load(Ordering::SeqCst),
                "stage fault/ownership quarantined"
            );
            ensure!(
                self.stage.stage.as_file().metadata()?.len() == self.size,
                "verified stage size changed"
            );
            ensure!(
                self.stage.policy.allow_transfers
                    && self.stage.policy.resolve(&self.stage.input)? == self.stage.destination,
                "fleet destination policy changed"
            );
            check()?;
            self.stage.check_identity()?;
            let file = self.stage.stage.as_file_mut();
            file.seek(SeekFrom::Start(0))?;
            let (actual, read) = digest_reader(&mut file.take(self.size + 1), &mut check)?;
            ensure!(
                read == self.size && actual == self.sha256,
                "verified stage content changed before publication"
            );
            self.stage.stage.as_file().sync_all()?;
            self.stage.check_identity()?;
            check()?;
            absent(&self.stage.destination)?;
            let parent = self
                .stage
                .destination
                .parent()
                .context("destination has no parent")?
                .to_path_buf();
            admit()?;
            Ok(parent)
        })();
        let parent = match preflight {
            Ok(p) => p,
            Err(e) => return Err(StageRejected::new(self, e)),
        };
        // Gate remains owned until the no-clobber attempt/cleanup/parent sync.
        Ok(self.stage.publish_admitted(self.size, self.sha256, parent))
    }
}

// NamedTempFile alone unlinks by NAME, even after the path has been replaced.
// Keep identity-aware, non-blocking cleanup in this field, before Reservation.
struct GuardedTempFile {
    file: Option<NamedTempFile>,
    gate: Arc<Mutex<()>>,
    budget: StageBudget,
    lost: Arc<AtomicBool>,
}
fn check_file_identity(file: &NamedTempFile) -> Result<()> {
    let meta = fs::symlink_metadata(file.path())?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "stage path is not a regular file"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            meta.file_attributes() & 0x400 == 0,
            "stage path is a reparse point"
        );
    }
    let current = fs::File::open(file.path())?;
    #[cfg(windows)]
    super::identity_windows::same_file(file.as_file(), &current)
        .context("stage path identity changed")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = file.as_file().metadata()?;
        let b = current.metadata()?;
        ensure!(
            (a.dev(), a.ino()) == (b.dev(), b.ino()),
            "stage path object replaced"
        );
    }
    Ok(())
}
impl GuardedTempFile {
    fn new(
        file: NamedTempFile,
        gate: Arc<Mutex<()>>,
        budget: StageBudget,
        lost: Arc<AtomicBool>,
    ) -> Self {
        Self {
            file: Some(file),
            gate,
            budget,
            lost,
        }
    }
    fn as_file(&self) -> &fs::File {
        self.file.as_ref().expect("live stage").as_file()
    }
    fn as_file_mut(&mut self) -> &mut fs::File {
        self.file.as_mut().expect("live stage").as_file_mut()
    }
    fn path(&self) -> &Path {
        self.file.as_ref().expect("live stage").path()
    }
    fn disable_cleanup(&mut self, disabled: bool) {
        self.file
            .as_mut()
            .expect("live stage")
            .disable_cleanup(disabled)
    }
    fn quarantine(&self) {
        self.lost.store(true, Ordering::SeqCst);
        self.budget
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recovery_closed = true;
    }
    // Only the owning Stage's already-gated explicit close/publication uses
    // these consuming escapes. Taking the File leaves None, so Drop cannot
    // reenter that gate.
    fn close(mut self) -> std::io::Result<()> {
        self.file.take().expect("live stage").close()
    }
    fn persist_noclobber(
        mut self,
        destination: &Path,
    ) -> std::result::Result<fs::File, tempfile::PersistError> {
        self.file
            .take()
            .expect("live stage")
            .persist_noclobber(destination)
    }
}
impl Drop for GuardedTempFile {
    fn drop(&mut self) {
        let Some(mut file) = self.file.take() else {
            return;
        };
        // Never wait/reenter a gate in a destructor. The poisoned guard is
        // usable for cleanup only; its poison is never cleared for admission.
        let gate = self.gate.clone();
        let guard = match gate.try_lock() {
            Ok(g) => Some(g),
            Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        if self.lost.load(Ordering::SeqCst)
            || guard.is_none()
            || check_file_identity(&file).is_err()
        {
            self.quarantine();
            file.disable_cleanup(true);
        }
        drop(file); // Any unlink occurs while the same actual gate is retained.
    }
}

/// Unchecked legacy publication is absent from non-test builds.
/// ```compile_fail
/// fn cannot_skip_admission(stage: ferroc::fleet::stage::StageFile) {
///     stage.publish([0; 32]).unwrap();
/// }
/// ```
pub struct StageFile {
    // Rust drops fields in declaration order. The owned tempfile MUST precede
    // _reservation: try cleanup first, inspect the residual path and account
    // it last. cancel/publish also consume/drop the tempfile before that check.
    stage: GuardedTempFile,
    policy: Policy,
    input: String,
    destination: PathBuf,
    fs_gate: Arc<Mutex<()>>,
    ranges: ReceiveRanges,
    faulted: bool,
    _reservation: Reservation,
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => anyhow::bail!("fleet destination already exists; overwrite unsupported"),
    }
}
fn digest_reader(
    reader: &mut impl Read,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<([u8; 32], u64)> {
    let mut hasher = Sha256::new();
    let mut bytes = [0u8; 64 * 1024];
    let mut total = 0;
    loop {
        check()?;
        let n = reader.read(&mut bytes)?;
        check()?;
        if n == 0 {
            break;
        }
        hasher.update(&bytes[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize().into(), total))
}
impl StageFile {
    fn check_identity(&mut self) -> Result<()> {
        let result = check_file_identity(self.stage.file.as_ref().expect("live stage"));
        if result.is_err() {
            self.stage.quarantine();
            self.stage.disable_cleanup(true);
            self.faulted = true;
        }
        result
    }
    /// Caller must pass Runtime's actual shared fs_gate during integration.
    /// Destination parent must already exist; this method never creates trees.
    pub fn prepare(
        policy: Policy,
        input: &str,
        total: u64,
        budget: &StageBudget,
        fs_gate: Arc<Mutex<()>>,
    ) -> Result<Self> {
        ensure!(policy.allow_transfers, "transfers disabled by local policy");
        let mut reservation = budget.reserve(total)?;
        let destination;
        let stage;
        {
            let _guard = fs_gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            destination = policy.resolve(input)?;
            ensure!(
                !destination
                    .file_name()
                    .context("missing destination filename")?
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .starts_with(".ferroc-fleet-"),
                "reserved fleet stage namespace"
            );
            absent(&destination)?;
            let parent = destination.parent().context("destination has no parent")?;
            ensure!(parent.is_dir(), "destination parent must exist");
            stage = tempfile::Builder::new()
                .prefix(".ferroc-fleet-")
                .tempfile_in(parent)?;
        }
        reservation.stage_path = Some(stage.path().to_path_buf());
        let stage = GuardedTempFile::new(
            stage,
            fs_gate.clone(),
            budget.clone(),
            reservation.ownership_uncertain.clone(),
        );
        Ok(Self {
            stage,
            policy,
            input: input.to_owned(),
            destination,
            fs_gate,
            ranges: ReceiveRanges::new(total)?,
            faulted: false,
            _reservation: reservation,
        })
    }
    pub fn write_chunk(&mut self, offset: u64, data: &[u8]) -> Result<Admission> {
        self.write_using(offset, data, |f, offset, data| {
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(data)
        })
    }
    fn write_using(
        &mut self,
        offset: u64,
        data: &[u8],
        write: impl FnOnce(&mut fs::File, u64, &[u8]) -> std::io::Result<()>,
    ) -> Result<Admission> {
        let result = (|| {
            ensure!(!self.faulted, "stage is faulted");
            ensure!(
                data.len() <= super::protocol::MAX_DATA,
                "fleet chunk too large"
            );
            let digest: [u8; 32] = Sha256::digest(data).into();
            let admission = self.ranges.validate(offset, data.len() as u32, &digest)?;
            if admission == Admission::New {
                let f = self.stage.as_file_mut();
                write(f, offset, data)?;
                self.ranges
                    .record_written(offset, data.len() as u32, digest)?;
            }
            Ok(admission)
        })();
        // Once IO or validation fails, never resume a stage whose partial write
        // might have been marked seen by an upstream authenticated record layer.
        if result.is_err() {
            self.faulted = true;
        }
        result
    }
    #[cfg(test)]
    pub(super) fn inject_partial_storage_full(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<Admission> {
        self.write_using(offset, data, |f, offset, data| {
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(&data[..data.len() / 2])?;
            Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "injected partial-write StorageFull",
            ))
        })
    }
    #[cfg(test)]
    pub(super) fn stage_path(&self) -> &Path {
        self.stage.path()
    }
    pub fn bytes_received(&self) -> u64 {
        self.ranges.received()
    }
    /// Explicit cleanup confirmation. Drop is only a best-effort fallback and
    /// MUST NOT be used as proof for the protocol's cancelled state.
    pub fn cancel(mut self) -> Result<()> {
        let gate = self.fs_gate.clone();
        // Explicit owned-object cleanup may drain a poisoned gate; never clear
        // its poison or restore admission. Identity is still mandatory below.
        let _guard = gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure!(
            !self._reservation.ownership_uncertain.load(Ordering::SeqCst),
            "stage ownership lost; no deletion or quota release"
        );
        self.check_identity()?;
        let path = self.stage.path().to_path_buf();
        self.stage.close().with_context(|| {
            format!(
                "fleet stage cleanup failed; residual path: {}",
                path.display()
            )
        })
    }
    /// Chunk-bounded cancellation/lease observation before/after every read and
    /// after sync_all. Checks cannot interrupt a blocked OS read/sync syscall.
    /// All errors return the owned stage without deleting it or releasing quota.
    pub fn verify_with(
        mut self,
        expected_sha256: [u8; 32],
        mut check: impl FnMut() -> Result<()>,
    ) -> std::result::Result<VerifiedStage, StageRejected<Self>> {
        let result = (|| -> Result<(u64, [u8; 32])> {
            check()?;
            ensure!(
                !self.faulted && self.ranges.complete(),
                "incomplete or faulted fleet stage"
            );
            let total = self.ranges.total();
            let file = self.stage.as_file_mut();
            file.seek(SeekFrom::Start(0))?;
            let (actual, read) = digest_reader(&mut file.take(total + 1), &mut check)?;
            ensure!(
                read == total
                    && actual == expected_sha256
                    && self.stage.as_file().metadata()?.len() == total,
                "fleet readback SHA256 or size mismatch"
            );
            self.stage.as_file().sync_all()?;
            check()?;
            Ok((total, actual))
        })();
        match result {
            Ok((size, sha256)) => Ok(VerifiedStage {
                stage: self,
                size,
                sha256,
            }),
            Err(e) => Err(StageRejected::new(self, e)),
        }
    }
    /// Historical unchecked component probe only. Operational receivers must
    /// use verify_with + publish_with with real lease/job/journal admission.
    #[cfg(test)]
    pub fn publish(self, expected_sha256: [u8; 32]) -> Result<Publication> {
        self.verify_with(expected_sha256, || Ok(()))
            .map_err(|e| e.into_parts().1)?
            .publish_with(|| Ok(()))
            .map_err(|e| e.into_parts().1)
    }
    fn publish_admitted(self, total: u64, actual: [u8; 32], parent: PathBuf) -> Publication {
        let old_stage = self.stage.path().to_path_buf();
        // Once persist has been called, fail conservatively. tempfile guarantees
        // no overwrite, not universal all-platform rename/unlink atomicity.
        let _published = match self.stage.persist_noclobber(&self.destination) {
            Ok(file) => file,
            Err(_) => {
                return Publication::Uncertain {
                    size: total,
                    sha256: actual,
                    reason: "no-clobber publication error; reconcile destination",
                };
            }
        };
        if !matches!(fs::symlink_metadata(&old_stage), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            return Publication::Uncertain {
                size: total,
                sha256: actual,
                reason: "temporary link cleanup not confirmed",
            };
        }
        #[cfg(unix)]
        let parent_sync = {
            if fs::File::open(&parent).and_then(|f| f.sync_all()).is_err() {
                return Publication::Uncertain {
                    size: total,
                    sha256: actual,
                    reason: "parent directory sync failed after publication",
                };
            }
            ParentSync::Synced
        };
        #[cfg(not(unix))]
        let parent_sync = {
            let _ = parent;
            ParentSync::Unsupported
        };
        Publication::Published {
            size: total,
            sha256: actual,
            parent_sync,
        }
    }
}
