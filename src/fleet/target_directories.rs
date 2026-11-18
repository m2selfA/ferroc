//! Explicit LOCAL target-parent creation, not directory mirroring. The caller
//! must hold the real Runtime registry -> fs_gate and a live Target lease.
//! Only missing ancestors of the exact approved destination may be created,
//! below an existing locally approved private root. No delete/rollback, file
//! creation, grant, DB or publication capability. Failed/cancelled operations
//! can leave private directories; subsequent file admission must revalidate.
use super::{fence::local_path, manifest::MAX_DEPTH, target_preflight::portable_component};
use anyhow::{Context, Result, ensure};
use std::path::{Component, Path, PathBuf};

pub(crate) fn validate_scope(root: &Path, destination: &Path) -> Result<Vec<PathBuf>> {
    local_path(root)?;
    local_path(destination)?;
    let relative = destination
        .strip_prefix(root)
        .context("destination outside approved parent-creation root")?;
    let components: Vec<_> = relative.components().collect();
    ensure!(
        !components.is_empty() && components.len() <= MAX_DEPTH,
        "invalid target parent depth"
    );
    for part in &components {
        let Component::Normal(name) = part else {
            anyhow::bail!("non-normal target component");
        };
        portable_component(name.to_str().context("non-UTF8 target component")?)?;
    }
    let mut current = root.to_path_buf();
    let mut parents = Vec::with_capacity(components.len() - 1);
    for part in &components[..components.len() - 1] {
        current.push(part.as_os_str());
        parents.push(current.clone());
    }
    Ok(parents)
}

/// Retain original ancestor/parent objects through the target pump. Windows
/// handles deny ordinary rename/delete; Linux FDs do not. Neither excludes
/// same-user external writes/mmap or claims a sandbox or directory durability.
#[cfg(any(windows, target_os = "linux"))]
pub(crate) struct TargetParents {
    _anchors: Vec<std::fs::File>,
    pub(crate) created: usize,
}

#[cfg(windows)]
pub(crate) fn prepare(
    policy: &crate::config::Policy,
    root: &Path,
    destination: &Path,
    check: impl FnMut() -> Result<()>,
) -> Result<TargetParents> {
    prepare_with(policy, root, destination, check, |_| Ok(()))
}

#[cfg(windows)]
fn prepare_with(
    policy: &crate::config::Policy,
    root: &Path,
    destination: &Path,
    mut check: impl FnMut() -> Result<()>,
    mut before_create: impl FnMut(&Path) -> Result<()>,
) -> Result<TargetParents> {
    use super::{
        identity::{make_directory, open_private},
        source_file::{object_id, open_object},
    };
    use std::fs;
    let parents = validate_scope(root, destination)?;
    check()?;
    let resolved_root = policy.resolve(root.to_str().context("non-UTF8 root")?)?;
    let resolved_dest = policy.resolve(destination.to_str().context("non-UTF8 destination")?)?;
    ensure!(
        resolved_dest.starts_with(&resolved_root) && resolved_dest != resolved_root,
        "target resolves outside approved root"
    );
    let ancestors: Vec<_> = root.ancestors().collect();
    ensure!(
        ancestors.len() <= MAX_DEPTH + 1,
        "target root depth exceeded"
    );
    let mut anchors = Vec::with_capacity(ancestors.len() + parents.len());
    // Retain original spelling all the way to the root; canonicalize alone
    // would hide an intervening reparse point.
    for path in ancestors.iter().rev() {
        check()?;
        anchors.push(open_object(path, true)?);
    }
    let private_root = open_private(root, true)?;
    ensure!(
        object_id(&private_root, true)? == object_id(&open_private(&resolved_root, true)?, true)?,
        "target root resolves elsewhere"
    );
    anchors.push(private_root);
    let mut created = 0;
    for path in parents {
        check()?;
        let was_missing = match fs::symlink_metadata(&path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error).context("target parent observation failed"),
        };
        if was_missing {
            before_create(&path)?;
            check()?;
            // CREATE_NEW-style directory creation with private DACL AT creation;
            // a concurrent creator is an error, never adopted as our creation.
            make_directory(&path)
                .context("target private directory creation failed; directories may remain")?;
            created += 1;
            check()?;
        }
        let directory = open_private(&path, true)?;
        let resolved = policy.resolve(path.to_str().context("non-UTF8 target parent")?)?;
        ensure!(
            resolved.starts_with(&resolved_root),
            "target parent escaped root"
        );
        ensure!(
            object_id(&directory, true)? == object_id(&open_private(&resolved, true)?, true)?,
            "target parent resolves elsewhere"
        );
        anchors.push(directory);
        check()?;
    }
    check()?;
    Ok(TargetParents {
        _anchors: anchors,
        created,
    })
}

#[cfg(all(test, windows))]
#[path = "target_directories_tests.rs"]
mod tests;

#[cfg(target_os = "linux")]
#[path = "target_directories_linux.rs"]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::prepare;
