//! Candidate P1 source-file IO over the existing leased encoder, not transport.
//! Only Runtime constructs it; there is no arbitrary path/gate/handle import.
//! Source files need not have private database ACLs. Plain single-link files and
//! ordinary parents are required; symlink/reparse/special files are refused.
use super::{
    auth::{EphemeralKey, Transcript},
    job::ValidatedGrant,
    lease::LeasedRecords,
    source::{AwaitingCommit, SourceEncoder},
};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[path = "source_prefix.rs"]
mod source_prefix;
pub use source_prefix::SourcePrefixObservation;

/// Real source handle and one bounded plaintext chunk per call. Returned DATA is
/// encoded, NOT sent/acknowledged. Caller must bound queues and preserve exact
/// ciphertext for retransmission. No file export, snapshot restore, clone or seek API.
/// Actual prefix hash plus NEW encoded suffix must match the approved total/SHA.
/// Checks serialize this Runtime, not external processes or mapped writers.
/// FINISH binds the encoded stream, NOT a later snapshot of the source file.
/// Renewal is explicit and only at an acknowledged boundary; this candidate has
/// no transport, reconnect or source-journal API. Explicit local continuation
/// consumes a dual-proof Source lease and actually rehashes its original FD;
/// its prefix is historical, not newly encoded or stable current file bytes.
/// ```compile_fail
/// fn no_clone(s:ferroc::fleet::source_file::SourceFile<'_>){let _=s.clone();}
/// ```
/// ```compile_fail
/// fn no_file(s:ferroc::fleet::source_file::SourceFile<'_>){let _=s.file;}
/// ```
/// ```compile_fail
/// fn no_restore(s:ferroc::fleet::journal::Snapshot){let _=ferroc::fleet::source_file::SourceFile::from(s);}
/// ```
/// ```compile_fail
/// fn no_path_override(r:&ferroc::runtime::Runtime,l:ferroc::fleet::lease::LeasedRecords){let _=r.open_fleet_source(l,"/other/file");}
/// ```
/// ```compile_fail
/// fn no_after_finish(mut s:ferroc::fleet::source_file::SourceFile<'_>){let _=s.finish();let _=s.next_record();}
/// ```
/// ```compile_fail
/// use ferroc::{runtime::Runtime,config::Policy,fleet::{lease::LeasedRecords,source_file::SourceFile}};
/// fn no_outlive(p:Policy,l:LeasedRecords)->SourceFile<'static>{let r=Runtime::new(p);r.open_fleet_source(l).unwrap()}
/// ```
pub struct SourceFile<'r> {
    runtime: &'r Runtime,
    gate: Arc<Mutex<()>>,
    file: Option<File>,
    parent: Option<File>,
    path: PathBuf,
    file_id: String,
    parent_id: String,
    encoder: SourceEncoder,
    // Heap metadata only. SHA state still comes exclusively from original-FD IO.
    resume_base: Option<Box<super::control::ResumeBase>>,
    /// Chunks seen since the last periodic pathname/parent re-check.
    checks: std::cell::Cell<u64>,
}
fn plain(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        if directory { m.is_dir() } else { m.is_file() },
        "source object is not plain file/directory"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            m.file_attributes() & 0x400 == 0,
            "source reparse object refused"
        );
    }
    Ok(())
}
pub(super) fn open_object(path: &Path, directory: bool) -> Result<File> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        !m.file_type().is_symlink() && if directory { m.is_dir() } else { m.is_file() },
        "source links/special objects refused"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .share_mode(3)
            .custom_flags(0x0020_0000 | if directory { 0x0200_0000 } else { 0 });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            libc::O_NOFOLLOW | libc::O_NONBLOCK | if directory { libc::O_DIRECTORY } else { 0 },
        );
    }
    let file = options.open(path)?;
    plain(&file, directory)?;
    Ok(file)
}
/// Pathname/parent re-checks are periodic; `finish` still re-verifies both.
const OBJECT_CHECK_EVERY: u64 = 32;
pub(super) fn object_id(file: &File, directory: bool) -> Result<String> {
    plain(file, directory)?;
    #[cfg(windows)]
    {
        if directory {
            super::identity_windows::directory_file_id(file)
        } else {
            super::identity_windows::single_link_file_id(file)
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        ensure!(
            directory || m.nlink() == 1,
            "source requires single-link file"
        );
        Ok(format!("unix-{:016x}-{:016x}", m.dev(), m.ino()))
    }
}
impl<'r> SourceFile<'r> {
    pub(crate) fn open_resume(
        runtime: &'r Runtime,
        owner: super::resume_lease::ResumeLease,
        gate: Arc<Mutex<()>>,
        max_prefix_bytes: u64,
    ) -> Result<Self> {
        let (condition, records) = owner.into_source()?;
        let mut source = Self::open(runtime, records, gate)?;
        source.restore_resume_prefix(&condition, max_prefix_bytes)?;
        Ok(source)
    }

    pub(crate) fn open(
        runtime: &'r Runtime,
        records: LeasedRecords,
        gate: Arc<Mutex<()>>,
    ) -> Result<Self> {
        let _life = runtime.fleet_source_guard()?;
        let _fs = gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        let mut encoder = SourceEncoder::new(records)?;
        encoder.check_source_io()?;
        let original = Path::new(&encoder.job().source_path);
        ensure!(
            !fs::symlink_metadata(original)?.file_type().is_symlink(),
            "source symlink refused"
        );
        let path = runtime.policy.resolve(&encoder.job().source_path)?;
        super::fence::local_path(&path)?;
        let parent = open_object(path.parent().context("source parent missing")?, true)?;
        let file = open_object(&path, false)?;
        let file_id = object_id(&file, false)?;
        let parent_id = object_id(&parent, true)?;
        let mut this = Self {
            runtime,
            gate: gate.clone(),
            file: Some(file),
            parent: Some(parent),
            path,
            file_id,
            checks: std::cell::Cell::new(0),
            parent_id,
            encoder,
            resume_base: None,
        };
        this.check_objects()?;
        // Opening/metadata IO may itself cross lease expiry. Keep one gate.
        this.encoder.check_source_io()?;
        Ok(this)
    }
    fn check_objects(&self) -> Result<()> {
        let resolved = self
            .runtime
            .policy
            .resolve(&self.encoder.job().source_path)?;
        ensure!(resolved == self.path, "source canonical path changed");
        ensure!(
            !fs::symlink_metadata(&self.encoder.job().source_path)?
                .file_type()
                .is_symlink(),
            "source symlink appeared"
        );
        let file = self.file.as_ref().context("source reader closed/faulted")?;
        ensure!(
            object_id(file, false)? == self.file_id
                && file.metadata()?.len() == self.encoder.job().bytes_total,
            "source file identity/size changed"
        );
        // Re-opening the pathname and the parent on every 64 KiB chunk cost far
        // more than the read itself. Path substitution cannot affect bytes we
        // already hold open, and the final finish() re-checks the pathname and
        // parent before it accepts the stream, so the per-chunk check is a
        // periodic one instead of a per-chunk one.
        let seen = self.checks.get().wrapping_add(1);
        self.checks.set(seen);
        if !seen.is_multiple_of(OBJECT_CHECK_EVERY) {
            return Ok(());
        }
        ensure!(
            object_id(&open_object(&self.path, false)?, false)? == self.file_id,
            "source pathname substituted"
        );
        ensure!(
            object_id(self.parent.as_ref().context("source parent closed")?, true)?
                == self.parent_id
                && object_id(
                    &open_object(self.path.parent().context("source parent missing")?, true)?,
                    true
                )? == self.parent_id,
            "source parent substituted"
        );
        Ok(())
    }
    pub(super) fn resume_base(&self) -> Option<&super::control::ResumeBase> {
        self.resume_base.as_deref()
    }
    pub(super) fn flow_total(&self) -> u64 {
        self.encoder.job().bytes_total
    }
    /// Binding the encoder is currently sealing under.
    pub(super) fn current_binding(&self) -> super::protocol::Binding {
        self.encoder.current_binding()
    }
    pub(super) fn flow_chunk_limit(&self) -> usize {
        self.encoder.io_chunk_bytes()
    }
    pub(super) fn flow_faulted(&self) -> bool {
        self.encoder.flow_faulted()
    }
    pub(super) fn flow_check(&mut self) -> Result<()> {
        let result = (|| {
            let _life = self.runtime.fleet_source_guard()?;
            let _fs = self
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            self.encoder.check_source_io()?;
            self.check_objects()?;
            self.encoder.check_source_io()
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
    /// Seal a flow control body under the CURRENT epoch. Used by the renewal
    /// handshake, which must travel before the rotation it describes.
    pub(super) fn seal_flow_control(
        &mut self,
        body: super::control::ControlBody,
    ) -> Result<Vec<u8>> {
        self.encoder.seal_flow_control(body)
    }
    pub(super) fn flow_control(&mut self, bytes: &[u8]) -> Result<super::auth::PeerRecord> {
        let result = self.flow_control_inner(bytes);
        if self.encoder.flow_faulted() {
            self.revoke();
        }
        result
    }
    fn flow_control_inner(&mut self, bytes: &[u8]) -> Result<super::auth::PeerRecord> {
        let _life = match self.runtime.fleet_source_guard() {
            Ok(g) => g,
            Err(e) => {
                self.encoder.revoke();
                return Err(e);
            }
        };
        let _fs = match self.gate.lock() {
            Ok(g) => g,
            Err(_) => {
                self.encoder.revoke();
                anyhow::bail!("filesystem gate poisoned");
            }
        };
        if let Err(e) = self
            .encoder
            .check_source_io()
            .and_then(|_| self.check_objects())
        {
            self.encoder.revoke();
            return Err(e);
        }
        self.encoder.open_flow_control(bytes)
    }
    /// Rotation keeps the read cursor, encoded count/hash and original total
    /// deadline. It only succeeds while the live owner still checks out; a
    /// rejected renewal leaves the previous session usable.
    pub fn renew(
        &mut self,
        g: ValidatedGrant,
        k: EphemeralKey,
        t: &Transcript,
        a: &[u8; 64],
        b: &[u8; 64],
    ) -> Result<()> {
        ensure!(
            self.resume_base.is_none(),
            "resume source does not rotate its approved base"
        );
        if let Err(e) = self.renew_prepare() {
            self.revoke();
            return Err(e);
        }
        // Renewal rejection (stale/expired/param change) preserves the old
        // session; do not revoke a still-valid lease on a peer-side refusal.
        self.encoder.renew(g, k, t, a, b)
    }
    fn renew_prepare(&mut self) -> Result<()> {
        let _life = self.runtime.fleet_source_guard()?;
        let _fs = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.encoder.check_source_io()?;
        self.check_objects()?;
        self.encoder.check_source_io()
    }
    pub fn bytes_encoded(&self) -> u64 {
        self.encoder.bytes_encoded()
    }
    /// Historical same-FD prefix read, NOT newly encoded/sent/received bytes.
    pub fn resumed_prefix_bytes(&self) -> Option<u64> {
        self.encoder.resumed_prefix_bytes()
    }
    pub fn next_data_offset(&self) -> u64 {
        self.encoder.next_data_offset()
    }
    pub fn revoke(&mut self) {
        self.encoder.revoke();
        drop(self.file.take());
        drop(self.parent.take());
    }
    #[cfg(test)]
    pub(super) fn test_expire(&mut self) {
        self.encoder.test_expire();
    }
    /// Reads at most min(granted chunk,64KiB); None is EOF, not final completion.
    /// Any error permanently closes this file owner; no automatic retry/resume.
    pub fn next_record(&mut self) -> Result<Option<Vec<u8>>> {
        let result = self.read_one();
        if result.is_err() {
            self.revoke();
        }
        result
    }
    fn read_one(&mut self) -> Result<Option<Vec<u8>>> {
        let _life = self.runtime.fleet_source_guard()?;
        let _fs = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.encoder.check_source_io()?;
        self.check_objects()?;
        self.encoder.check_source_io()?;
        let remaining = self.encoder.job().bytes_total - self.encoder.next_data_offset();
        if remaining == 0 {
            return Ok(None);
        }
        // Honour the granted chunk size (already bounded by MAX_DATA when the
        // grant was validated). A fixed 64 KiB cap here silently defeated a
        // larger grant and multiplied the per-chunk object checks and journal
        // reads, which is what limited large-transfer throughput.
        let n = remaining.min(self.encoder.io_chunk_bytes() as u64) as usize;
        let mut data = zeroize::Zeroizing::new(vec![0; n]);
        let mut done = 0;
        while done < n {
            self.encoder.check_source_io()?;
            let count = self
                .file
                .as_mut()
                .context("source closed")?
                .read(&mut data[done..])?;
            self.encoder.check_source_io()?;
            self.check_objects()?;
            ensure!(count > 0, "source truncated during read");
            done += count;
        }
        let record = self.encoder.encode_next(&data)?;
        self.check_objects()?;
        self.encoder.check_source_io()?;
        Ok(Some(record))
    }
    /// Releases source FD only after forced final name/parent/object/lease checks
    /// and complete actual-prefix/encoded-suffix SHA. AwaitingCommit still waits for peer
    /// statement; it is neither source journal completion nor current target truth.
    pub fn finish(mut self) -> Result<AwaitingCommit> {
        let _life = self.runtime.fleet_source_guard()?;
        let _fs = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.encoder.check_source_io()?;
        self.checks.set(OBJECT_CHECK_EVERY - 1);
        self.check_objects()?;
        self.encoder.check_source_io()?;
        let pending = self.encoder.finish()?;
        drop(self.file.take());
        drop(self.parent.take());
        Ok(pending)
    }
}
