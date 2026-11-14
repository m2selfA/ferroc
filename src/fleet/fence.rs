//! Cooperative, local, native owner fencing for the SAME SQLite database.
//! No PID/deadline guesses, lock heartbeat, extra database, daemon or network.
//! DB/parent paths must already be private/trusted. This is not an OS sandbox
//! against malicious same-user path replacement or non-cooperating SQL writers.
use super::{
    identity::{new_private, open_private, validate_private},
    journal::Journal,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

/// A non-cloneable factory for an exclusive OS lock. Connections retain the
/// private guard internally; dropping this factory cannot unlock a live DB.
/// Acquisition requires an existing private regular DB with exactly one link.
/// Sidecar creation may leave an empty marker on failure; never unlink it.
/// ```compile_fail
/// fn no_lock_duplication(f: ferroc::fleet::fence::OwnerFence) {
///     let _ = f.clone();
/// }
/// ```
pub struct OwnerFence {
    domain: Arc<FenceDomain>,
}
pub(super) struct FenceDomain {
    // Last field owns the lock so directory/DB handle cleanup happens first.
    database: File,
    directory: File,
    path: PathBuf,
    marker: PathBuf,
    key: String,
    pub(super) owner: Uuid,
    lock: File,
}
/// Connection opened only AFTER its owner lock was acquired. No raw connection
/// escape: the host must adopt this opening order for the shared DB. This does
/// not wrap a pre-existing Connection by trusting its filename alone.
/// ```compile_fail
/// use ferroc::fleet::fence::{OwnerFence,FencedConnection};
/// fn cannot_export_raw(db:FencedConnection)->rusqlite::Connection {
///     db.connection
/// }
/// ```
/// ```no_run
/// use ferroc::fleet::fence::{OwnerFence,FencedConnection};
/// fn fenced_database(path:&std::path::Path)->anyhow::Result<FencedConnection> {
///     // The returned DB retains the lock even after this temporary factory drops.
///     OwnerFence::acquire(path)?.open_connection()
/// }
/// ```
pub struct FencedConnection {
    // DB must close before the last retained domain lock can be released.
    pub(super) connection: Connection,
    pub(super) fence: Arc<FenceDomain>,
}
impl FencedConnection {
    /// Bounded, read-only recovery observation. The returned budget is ALWAYS
    /// quarantined; this is not a live admission permit or a cleanup capability.
    /// Caller supplies trusted local directories and Runtime's actual fs_gate.
    /// Existing journal schema is required; no schema creation/recovery here.
    pub fn inventory(
        &mut self,
        policy: &crate::config::Policy,
        roots: &[PathBuf],
        fs_gate: Arc<std::sync::Mutex<()>>,
        limits: super::inventory::InventoryLimits,
    ) -> Result<super::inventory::RecoveryInventory> {
        limits.validate()?;
        let _guard = fs_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
        self.fence.check_connection(&self.connection)?;
        let rows = Journal::inventory_rows(&mut self.connection, &self.fence)?;
        let report = super::inventory::inspect(policy, roots, &rows, &self.fence, limits)?;
        self.fence.check_connection(&self.connection)?;
        Ok(report)
    }
    pub fn journal(&mut self) -> Result<Journal<'_>> {
        Journal::attach_fenced(&mut self.connection, &self.fence)
    }
}
pub(super) fn local_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .to_str()
                .is_some_and(|s| s.len() <= 4096 && !s.chars().any(char::is_control)),
        "fence requires bounded absolute local UTF8 path"
    );
    ensure!(
        !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        "fence path traversal unsupported"
    );
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        ensure!(
            matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_))),
            "fence UNC/device namespace unsupported"
        );
        ensure!(
            !path
                .components()
                .any(|c| matches!(c,Component::Normal(n) if n.to_string_lossy().contains(':'))),
            "fence alternate stream unsupported"
        );
    }
    Ok(())
}
pub(super) fn file_id(file: &File) -> Result<String> {
    validate_private(file, false)?;
    #[cfg(windows)]
    {
        super::identity_windows::single_link_file_id(file)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        ensure!(
            m.nlink() == 1,
            "fence database/marker must have exactly one link"
        );
        Ok(format!("unix-{:016x}-{:016x}", m.dev(), m.ino()))
    }
}
pub(super) fn directory_id(file: &File) -> Result<String> {
    validate_private(file, true)?;
    #[cfg(windows)]
    {
        super::identity_windows::directory_file_id(file)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        Ok(format!("unix-{:016x}-{:016x}", m.dev(), m.ino()))
    }
}
fn same_directory(a: &File, b: &File) -> Result<()> {
    #[cfg(windows)]
    {
        super::identity_windows::same_file(a, b)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = a.metadata()?;
        let b = b.metadata()?;
        ensure!(
            (a.dev(), a.ino()) == (b.dev(), b.ino()),
            "fence parent directory replaced"
        );
    }
    Ok(())
}
fn open_marker(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(3).custom_flags(0x0020_0000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match new_private(path) {
            Ok(f) => f,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                options.open(path)?
            }
            Err(e) => return Err(e),
        },
        Err(e) => return Err(e.into()),
    };
    file_id(&file)?;
    ensure!(
        file.metadata()?.len() == 0,
        "fence marker must be empty and never truncated"
    );
    Ok(file)
}
impl OwnerFence {
    pub fn acquire(path: &Path) -> Result<Self> {
        local_path(path)?;
        // Reject a reparse/symlink final component BEFORE canonicalization.
        let database = open_private(path, false)?;
        let key = file_id(&database)?;
        let path = fs::canonicalize(path)?;
        local_path(&path)?;
        let parent = path.parent().context("fence DB has no parent")?;
        let directory = open_private(parent, true)?;
        ensure!(
            file_id(&open_private(&path, false)?)? == key,
            "fence DB changed during opening"
        );
        let hash = Sha256::digest(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let marker = parent.join(format!(".ferroc-fleet-owner-{hash}.lock"));
        let lock = open_marker(&marker)?;
        lock.try_lock()
            .context("native owner fence busy or unsupported")?;
        let fence = FenceDomain {
            database,
            directory,
            path,
            marker,
            key,
            owner: Uuid::new_v4(),
            lock,
        };
        fence.check_paths()?;
        Ok(Self {
            domain: Arc::new(fence),
        })
    }
    pub fn owner(&self) -> Uuid {
        self.domain.owner
    }
    /// Open the same existing DB under the already acquired lock. Connection
    /// internally retains that guard until after SQLite closes. No CREATE,
    /// permission repair, raw-handle escape or second database. WAL/FULL setup
    /// is performed while fenced, before any journal schema or recovery work.
    pub fn open_connection(&self) -> Result<FencedConnection> {
        self.domain.check_paths()?;
        let connection = Connection::open_with_flags(
            &self.domain.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;")?;
        self.domain.check_connection(&connection)?;
        Ok(FencedConnection {
            connection,
            fence: Arc::clone(&self.domain),
        })
    }
}
impl FenceDomain {
    pub(super) fn database_parent_id(&self) -> Result<String> {
        directory_id(&self.directory)
    }
    pub(super) fn database_id(&self) -> &str {
        &self.key
    }
    pub(super) fn control_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.path.clone(), self.marker.clone()];
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut name = self.path.as_os_str().to_os_string();
            name.push(suffix);
            paths.push(PathBuf::from(name));
        }
        paths
    }
    fn check_paths(&self) -> Result<()> {
        validate_private(&self.directory, true)?;
        let parent = open_private(self.path.parent().context("missing fence parent")?, true)?;
        same_directory(&self.directory, &parent)?;
        ensure!(
            file_id(&self.database)? == self.key
                && file_id(&open_private(&self.path, false)?)? == self.key,
            "fenced database replaced/aliased"
        );
        ensure!(
            self.lock.metadata()?.len() == 0
                && file_id(&self.lock)? == file_id(&open_private(&self.marker, false)?)?,
            "fence marker replaced/changed"
        );
        Ok(())
    }
    pub(super) fn check_connection(&self, connection: &Connection) -> Result<()> {
        self.check_paths()?;
        let name: String = connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |r| r.get(0),
        )?;
        ensure!(!name.is_empty(), "fence cannot bind memory database");
        let path = fs::canonicalize(name)?;
        ensure!(
            path == self.path && file_id(&open_private(&path, false)?)? == self.key,
            "fence/SQLite database domain mismatch"
        );
        Ok(())
    }
}
#[cfg(test)]
#[path = "fence_tests.rs"]
mod tests;
