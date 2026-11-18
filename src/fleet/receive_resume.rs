//! Explicit LOCAL target continuation using the SAME retained object and full debt.
//! No SourceFile cursor, wire resume/READY, retry, deletion or new allocation.
use super::*;
use crate::fleet::{
    allocation, fence::directory_id, identity::validate_private, journal::Journal,
    resume_condition::ResumeProposal, resume_lease::ResumeLease,
};
use std::time::Duration;

/// Native same-object reopen, not a source-path reopen. The caller validates
/// private/regular/single-link and exact identity before/after, under its gate.
fn reopen_writer(original: &File) -> Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ReOpenFile(original: RawHandle, access: u32, share: u32, flags: u32) -> RawHandle;
        }
        // Microsoft ReOpenFile forbids FILE_ATTRIBUTE_* here; flags MUST be0.
        // Original open_stage reader shares7. Writer owns DELETE but shares3.
        let raw = unsafe { ReOpenFile(original.as_raw_handle(), 0xc001_0000, 3, 0) };
        if raw == (-1isize as RawHandle) || raw.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("retained object writable reopen failed");
        }
        Ok(unsafe { File::from_raw_handle(raw) })
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
        // procfs magic-link reopening preserves the original held regular FD.
        // NO pathname fallback, O_CREAT or truncate. /proc availability required.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", original.as_raw_fd()))
            .context("retained original FD writable reopen failed")
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = original;
        anyhow::bail!("retained writer unsupported on this platform")
    }
}
fn current(
    db: &mut FencedConnection,
    host: &FleetHost<'_>,
    old: &Snapshot,
    file: &File,
    parent: &File,
    records: &mut LeasedRecords,
) -> Result<()> {
    records.receive_admission()?;
    let now = Journal::existing_fenced(&mut db.connection, &db.fence)?
        .get(&JobKey::from_job(old.job()))?
        .context("recovery row missing")?;
    ensure!(
        now.owner() == old.owner()
            && now.revision() == old.revision()
            && now.phase() == Phase::Interrupted
            && now.stage() == old.stage()
            && now.retained_stage() == old.retained_stage()
            && now.job() == old.job(),
        "recovery row changed during admission"
    );
    let r = old.stage().context("recovery stage missing")?;
    let a = r.allocation().context("recovery allocation missing")?;
    let (_, observed_parent, id) = allocation::parent(&host.attachment.runtime.policy, old)?;
    ensure!(
        id == a.parent_id()
            && directory_id(parent)? == id
            && directory_id(&observed_parent)? == id
            && Some(file_id(file)?.as_str()) == a.file_id()
            && allocation::stage_path_matches(
                r.path(),
                a.file_id().context("recovery file id missing")?,
                false
            )?,
        "recovery original object/parent changed"
    );
    validate_private(file, false)?;
    records.receive_admission()?;
    Ok(())
}
impl<'r> FleetHost<'r> {
    /// Consume a trusted-LOCAL caller's dual-signed fresh target lease. Ordinary
    /// admission stays shut; pause/close/Runtime stop cannot be bypassed. This is
    /// NOT SourceFile/SourceWindow or network restart-resume. Existing READY/ACK
    /// is intentionally unavailable until a resume-base wire contract exists.
    /// Full debt remains, including after errors following a committed migration.
    pub fn admit_retained_receiver<'h>(
        &'h self,
        key: &JobKey,
        revision: u64,
        owner: ResumeLease,
        max_prefix_bytes: u64,
    ) -> Result<HostReceiver<'h, 'r>> {
        let operation = self.enter_recovery()?;
        let (condition, mut records) = owner.into_target()?;
        ensure!(
            max_prefix_bytes <= 1u64 << 30 && condition.prefix_bytes() <= max_prefix_bytes,
            "recovery prefix exceeds bounded budget"
        );
        let mut guard = self
            .database
            .lock()
            .map_err(|_| anyhow::anyhow!("host database poisoned"))?;
        let db = guard.as_mut().context("host database closed")?;
        let previous: i64 = db
            .connection
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))?;
        ensure!(
            (0..=i32::MAX as i64).contains(&previous),
            "invalid busy timeout"
        );
        db.connection.busy_timeout(Duration::ZERO)?;
        let result = (|| {
            let _gate = self
                .gate
                .lock()
                .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
            records.receive_admission()?;
            let old = Journal::existing_fenced(&mut db.connection, &db.fence)?
                .get(key)?
                .context("recovery job missing")?;
            ensure!(
                old.owner() == db.fence.owner
                    && old.revision() == revision
                    && old.phase() == Phase::Interrupted
                    && old.data_seal().is_none()
                    && old.intent().is_none()
                    && old.receipt().is_none()
                    && old.migration_origin().is_none(),
                "recovery needs exact recovered precommit row"
            );
            let retained = old
                .retained_stage()
                .context("recovery retained opt-in missing")?;
            let cp = retained
                .checkpoint()
                .context("recovery persisted checkpoint missing")?;
            let expected = ResumeProposal::build(old.job(), cp, records.grant())?;
            ensure!(
                expected.canonical_bytes() == condition.canonical_bytes()
                    && expected.digest() == condition.digest(),
                "recovery condition differs from current checkpoint"
            );
            let r = old.stage().context("recovery stage debt missing")?;
            let a = r.allocation().context("recovery allocation missing")?;
            ensure!(
                !a.is_anonymous()
                    && a.original_owner() != db.fence.owner
                    && retained.original_owner() == a.original_owner()
                    && a.database_id() == Some(db.fence.database_id())
                    && a.database_parent_id() == Some(db.fence.database_parent_id()?.as_str()),
                "recovery stopped-origin/domain mismatch"
            );
            let (_, parent, id) = allocation::parent(&self.attachment.runtime.policy, &old)?;
            ensure!(id == a.parent_id(), "recovery parent mismatch");
            // No standalone adopt/rebind here: migration must see STOPPED origin.
            let original = open_stage(r.path())?;
            current(db, self, &old, &original, &parent, &mut records)?;
            let mut file = reopen_writer(&original)?;
            current(db, self, &old, &file, &parent, &mut records)?;
            let length = file.metadata()?.len();
            ensure!(
                condition.prefix_bytes() <= length && length <= old.job().bytes_total,
                "recovery stage length invalid"
            );
            let mut hash = Sha256::new();
            let mut buffer = zeroize::Zeroizing::new([0u8; 65536]);
            let mut offset = 0;
            file.seek(SeekFrom::Start(0))?;
            while offset < condition.prefix_bytes() {
                current(db, self, &old, &file, &parent, &mut records)?;
                ensure!(
                    file.metadata()?.len() == length,
                    "recovery stage length changed"
                );
                let n = (condition.prefix_bytes() - offset).min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..n])?;
                hash.update(&buffer[..n]);
                offset += n as u64;
                current(db, self, &old, &file, &parent, &mut records)?;
            }
            ensure!(
                <[u8; 32]>::from(hash.finalize()) == condition.prefix_sha256(),
                "recovery prefix mismatch"
            );
            current(db, self, &old, &file, &parent, &mut records)?;
            ensure!(
                file.metadata()?.len() == length,
                "recovery stage length changed"
            );
            let now = records.receive_admission()?;
            let next = records.grant().clone();
            let (_, migrated) = Journal::existing_fenced(&mut db.connection, &db.fence)?
                .migrate_retained_reference(key, revision, &next, &condition, now)?;
            records.receive_admission()?;
            let new_key = JobKey::from_job(next.job());
            let snapshot = Journal::existing_fenced(&mut db.connection, &db.fence)?
                .begin_migrated_receive(&new_key, migrated.revision(), &next, &condition)?;
            let _parent = check_stage(db, &snapshot, &file, self, false)?;
            records.receive_admission()?;
            let ranges = ReceiveRanges::with_verified_prefix(
                next.job().bytes_total,
                condition.prefix_bytes(),
            )?;
            Ok((file, snapshot, ranges))
        })();
        let restored = db
            .connection
            .busy_timeout(Duration::from_millis(previous as u64));
        let (file, snapshot, ranges) = match (result, restored) {
            (result, Ok(())) => result?,
            (_, Err(_)) => {
                anyhow::bail!("recovery busy timeout restoration failed; inspect persisted debt")
            }
        };
        Ok(HostReceiver {
            file,
            records,
            ranges,
            resume_base: Some(Box::new(crate::fleet::control::ResumeBase::from_condition(
                &condition,
            ))),
            snapshot,
            faulted: false,
            published: false,
            flow_window: None,
            flow_ready: None,
            flow_ack: None,
            renewal: None,
            unsynced: 0,
            persisted: condition.prefix_bytes(),
            operation,
        })
    }
}
