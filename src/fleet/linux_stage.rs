//! Explicit Linux anonymous-stage backend. No Runtime/grant/journal bypass API.
//! Requires O_TMPFILE and mounted /proc/self/fd; no path-rename or AT_EMPTY_PATH
//! fallback. Last FD drop reclaims UNLINKED bytes, never persistent journal debt.
#[cfg(test)]
#[path = "linux_replace_tests.rs"]
mod replace_tests;
use anyhow::{Context, Result, ensure};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
};
pub(super) fn object_id(file: &File, published: bool) -> Result<String> {
    super::identity::validate_private(file, false)?;
    let m = file.metadata()?;
    ensure!(
        m.nlink() == u64::from(published),
        "anonymous stage link count changed"
    );
    Ok(format!("unix-{:016x}-{:016x}", m.dev(), m.ino()))
}
pub(super) fn create(parent: &File) -> Result<File> {
    super::identity::validate_private(parent, true)?;
    // SAFETY: constant relative name, borrowed directory FD; success owned once.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(
        fd >= 0,
        "Linux O_TMPFILE stage unavailable: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { File::from_raw_fd(fd) };
    object_id(&file, false)?;
    Ok(file)
}
/// One NUL-terminated relative component; reject separators and dot names.
fn component(name: &std::ffi::OsStr) -> Result<CString> {
    let bytes = name.as_bytes();
    ensure!(
        !bytes.is_empty() && !bytes.contains(&b'/') && bytes != b"." && bytes != b"..",
        "invalid target filename"
    );
    CString::new(bytes).context("target filename contains NUL")
}
/// Crash-visible reserved name derived from the job digest. It is NOT persisted
/// separately: the job row already carries the job, so the same digest reproduces
/// the only name this job may create. Determinism also means a retry hits EEXIST
/// instead of silently adopting a leftover name. Never removed automatically.
pub(super) fn replace_temporary(job_digest: &[u8; 32]) -> std::ffi::OsString {
    let mut name = String::from(".ferroc-fleet-repl-");
    for byte in &job_digest[..16] {
        name.push_str(&format!("{byte:02x}"));
    }
    std::ffi::OsString::from(name)
}
/// Replace an existing destination from the SAME anonymous File: link once under
/// the reserved name, then rename over the destination (atomic). Requires the
/// caller's in-gate pre-image check; no retry, no adoption, no cleanup on failure.
pub(super) fn replace(
    file: &File,
    parent: &File,
    name: &std::ffi::OsStr,
    temporary: &std::ffi::OsStr,
) -> Result<()> {
    let id = object_id(file, false)?;
    super::identity::validate_private(parent, true)?;
    let name = component(name)?;
    let temporary = component(temporary)?;
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    // SAFETY: documented procfs-FD dereference, live retained descriptor and
    // pinned directory, one NUL-terminated component, no user source symlink.
    let rc = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            parent.as_raw_fd(),
            temporary.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("Linux reserved replacement link failed; destination untouched");
    }
    ensure!(object_id(file, true)? == id, "linked original File changed");
    // SAFETY: both names are single components inside the same pinned directory
    // descriptor; the destination is replaced atomically by the kernel.
    let rc = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            temporary.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context(
            "Linux replacement rename failed; reserved temporary may remain and the destination is unchanged",
        );
    }
    parent
        .sync_all()
        .context("Linux parent fsync failed after replacement; effects exist")?;
    Ok(())
}
/// Link the SAME anonymous File once into the pinned parent. No retry/fallback.
pub(super) fn publish(file: &File, parent: &File, name: &std::ffi::OsStr) -> Result<()> {
    let id = object_id(file, false)?;
    super::identity::validate_private(parent, true)?;
    let name = component(name)?;
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    // SAFETY: documented procfs-FD dereference, live retained descriptor and
    // pinned directory, one NUL-terminated component, no user source symlink.
    let rc = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("Linux original-FD publication failed; effects may exist");
    }
    ensure!(
        object_id(file, true)? == id,
        "published original File changed"
    );
    parent
        .sync_all()
        .context("Linux parent fsync failed after publication; effects exist")?;
    Ok(())
}
