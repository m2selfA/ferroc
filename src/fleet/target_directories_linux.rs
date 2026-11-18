//! Linux local-only parent preparation. Directory FDs bind objects but do NOT
//! exclude rename. A failed post-mkdir observation can leave a directory under
//! the moved original parent. No rollback, cleanup, chmod or durable-root claim.
use super::{TargetParents, validate_scope};
use crate::{
    config::Policy,
    fleet::{identity::validate_private, source_file::object_id},
};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

struct Anchor {
    path: PathBuf,
    file: File,
    id: String,
    private: bool,
}
impl Anchor {
    fn new(path: &Path, file: File, private: bool) -> Result<Self> {
        if private {
            validate_private(&file, true)?;
        }
        Ok(Self {
            path: path.to_owned(),
            id: object_id(&file, true)?,
            file,
            private,
        })
    }
}

fn component(path: &Path) -> Result<CString> {
    CString::new(
        path.file_name()
            .context("missing directory component")?
            .as_bytes(),
    )
    .context("directory component contains NUL")
}

fn open_at(parent: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: a retained directory FD and one live component. The descriptor
    // is owned exactly once on success; final symlinks are never followed.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn recheck(
    policy: &Policy,
    root: &Path,
    destination: &Path,
    anchors: &[Anchor],
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    for (index, anchor) in anchors.iter().enumerate() {
        check()?;
        let observed = if index == 0 {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&anchor.path)?
        } else {
            open_at(&anchors[index - 1].file, &component(&anchor.path)?)?
        };
        ensure!(
            object_id(&anchor.file, true)? == anchor.id && object_id(&observed, true)? == anchor.id,
            "target parent chain changed; directories may remain"
        );
        if anchor.private {
            validate_private(&anchor.file, true)?;
            validate_private(&observed, true)?;
        }
    }
    ensure!(
        policy.resolve(root.to_str().context("non-UTF8 root")?)? == root,
        "target root resolves elsewhere"
    );
    let resolved = policy.resolve(destination.to_str().context("non-UTF8 destination")?)?;
    ensure!(
        resolved.starts_with(root) && resolved != root,
        "target destination resolves outside approved root"
    );
    check()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CreatePoint {
    Before,
    After,
}

pub(crate) fn prepare(
    policy: &Policy,
    root: &Path,
    destination: &Path,
    check: impl FnMut() -> Result<()>,
) -> Result<TargetParents> {
    prepare_with(policy, root, destination, check, |_, _| Ok(()))
}

fn prepare_with(
    policy: &Policy,
    root: &Path,
    destination: &Path,
    mut check: impl FnMut() -> Result<()>,
    mut hook: impl FnMut(CreatePoint, &Path) -> Result<()>,
) -> Result<TargetParents> {
    let parents = validate_scope(root, destination)?;
    check()?;
    ensure!(
        policy.resolve(root.to_str().context("non-UTF8 root")?)? == root,
        "target root resolves elsewhere"
    );
    let ancestors: Vec<_> = root.ancestors().collect();
    ensure!(
        ancestors.len() <= crate::fleet::manifest::MAX_DEPTH + 1,
        "target root depth exceeded"
    );
    let mut anchors: Vec<Anchor> = Vec::with_capacity(ancestors.len() + parents.len());
    for path in ancestors.into_iter().rev() {
        check()?;
        let file = if let Some(previous) = anchors.last() {
            open_at(&previous.file, &component(path)?)?
        } else {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?
        };
        anchors.push(Anchor::new(path, file, path == root)?);
    }
    recheck(policy, root, destination, &anchors, &mut check)?;
    let mut created = 0;
    for path in parents {
        recheck(policy, root, destination, &anchors, &mut check)?;
        let name = component(&path)?;
        let parent = &anchors.last().context("target root absent")?.file;
        let directory = match open_at(parent, &name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                hook(CreatePoint::Before, &path)?;
                recheck(policy, root, destination, &anchors, &mut check)?;
                // SAFETY: the checked parent FD and one bounded component;
                // mode is private at creation and EEXIST is deliberately an error.
                let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
                if rc != 0 {
                    return Err(io::Error::last_os_error())
                        .context("target private mkdirat failed; directories may remain");
                }
                created += 1;
                hook(CreatePoint::After, &path)?;
                recheck(policy, root, destination, &anchors, &mut check)?;
                open_at(parent, &name)?
            }
            Err(error) => return Err(error).context("target parent observation failed"),
        };
        anchors.push(Anchor::new(&path, directory, true)?);
        recheck(policy, root, destination, &anchors, &mut check)?;
    }
    recheck(policy, root, destination, &anchors, &mut check)?;
    Ok(TargetParents {
        _anchors: anchors.into_iter().map(|anchor| anchor.file).collect(),
        created,
    })
}

#[cfg(test)]
#[path = "target_directories_linux_tests.rs"]
mod tests;
