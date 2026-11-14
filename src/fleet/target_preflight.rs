//! Windows-only LOCAL preflight observation for an existing add-only SyncPlan.
//! Reads names, parents and absence ONLY: it never creates a directory or file,
//! never publishes, overwrites or deletes, issues no grant and takes no DB lock.
//! NOT publication permission; the publisher must re-observe under its own gate.
//! Name rule is a deliberately NARROW ASCII profile, not a Windows-equivalence proof.
use super::{
    fence::{directory_id, local_path},
    identity::open_private,
    manifest::MAX_PATH_BYTES,
    source_file::{object_id, open_object},
    sync_exec::CancelToken,
    sync_plan::{MAX_PLAN_FILES, SyncPlan},
};
use crate::runtime::Runtime;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const MAX_COMPONENT_BYTES: usize = 255;
/// Marker for a parent that the plan declares but that does not exist yet.
/// It is NOT an object id and must never be treated as one.
const PLANNED_PARENT_ID: &str = "planned-directory";
const RESERVED_DEVICES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Clone, Copy, Debug)]
pub struct PreflightLimits {
    pub max_files: usize,
    /// Opt-in: treat the plan's declared-but-absent directories as admissible.
    /// Default false keeps the strict existing-private-parent requirement. Even
    /// when true, preflight still creates NOTHING.
    pub allow_planned_directories: bool,
}
impl Default for PreflightLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_PLAN_FILES,
            allow_planned_directories: false,
        }
    }
}
impl PreflightLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            self.max_files > 0 && self.max_files <= MAX_PLAN_FILES,
            "preflight limits outside hard ceilings"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreflightProfile {
    AsciiPortableOnly,
}

/// One observed destination. Both the parent object ID and the absence result
/// are observations at preflight time; neither survives into publication.
#[derive(Debug)]
pub struct PreflightEntry {
    path: String,
    destination: PathBuf,
    parent_id: String,
    bytes: u64,
}
impl PreflightEntry {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn destination(&self) -> &Path {
        &self.destination
    }
    pub fn parent_id(&self) -> &str {
        &self.parent_id
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// One directory the plan declares and the target does not have yet. Declared
/// intent only: preflight does not create it, and no handle can be pinned for it.
#[derive(Debug)]
pub struct PlannedDirectory {
    path: String,
    destination: PathBuf,
}
impl PlannedDirectory {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

/// Read-only result for one ordered plan. It has NO publish/apply/create method
/// and cannot be turned into a grant or a writable stage.
/// ```compile_fail
/// fn no_publish(p:ferroc::fleet::target_preflight::TargetPreflight){p.publish().unwrap();}
/// ```
/// ```compile_fail
/// fn no_apply(p:ferroc::fleet::target_preflight::TargetPreflight){p.apply().unwrap();}
/// ```
/// ```compile_fail
/// let _:ferroc::fleet::target_preflight::TargetPreflight=serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug)]
pub struct TargetPreflight {
    entries: Vec<PreflightEntry>,
    directories: Vec<PlannedDirectory>,
    root_id: String,
    plan_digest: [u8; 32],
    bytes: u64,
}
impl TargetPreflight {
    pub fn entries(&self) -> &[PreflightEntry] {
        &self.entries
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Sum of planned source sizes; NOT traffic, received bytes or durability.
    pub fn planned_bytes(&self) -> u64 {
        self.bytes
    }
    /// Ancestor-first directories the receiver must still create. Empty unless
    /// the caller opted into `allow_planned_directories`.
    pub fn planned_directories(&self) -> &[PlannedDirectory] {
        &self.directories
    }
    pub fn root_id(&self) -> &str {
        &self.root_id
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
    pub fn profile(&self) -> PreflightProfile {
        PreflightProfile::AsciiPortableOnly
    }
    /// Bind this observation to the exact ordered plan it was taken from.
    pub fn matches(&self, plan: &SyncPlan) -> Result<()> {
        ensure!(
            self.plan_digest == plan_digest(plan)?,
            "target preflight belongs to another plan"
        );
        Ok(())
    }
}

fn plan_digest(plan: &SyncPlan) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"ferroc:fleet:target-preflight:v1\0");
    for file in plan.files() {
        h.update((file.path.len() as u16).to_be_bytes());
        h.update(file.path.as_bytes());
        h.update(file.bytes.to_be_bytes());
        h.update(file.sha256);
        h.update(file.job_digest()?);
    }
    Ok(h.finalize().into())
}

/// Declared narrow profile. Anything outside it is refused rather than folded,
/// so this never claims Unicode/8.3 equivalence for names it did not accept.
fn portable_component(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= MAX_COMPONENT_BYTES,
        "target component length outside portable profile"
    );
    ensure!(
        name.is_ascii(),
        "non-ASCII target name outside this preflight's portable profile"
    );
    ensure!(
        !name.bytes().any(|b| b < 0x20 || b == 0x7f),
        "control character in target name"
    );
    ensure!(
        !name.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*']),
        "reserved character in target name"
    );
    ensure!(
        !name.ends_with(' ') && !name.ends_with('.'),
        "target name ends with space or period"
    );
    ensure!(
        !name.to_ascii_lowercase().starts_with(".ferroc-fleet-"),
        "reserved fleet stage namespace"
    );
    let base = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    ensure!(
        !RESERVED_DEVICES.contains(&base.as_str()),
        "reserved Windows device name"
    );
    Ok(())
}

pub(crate) fn preflight(
    runtime: &Runtime,
    gate: Arc<Mutex<()>>,
    root: &Path,
    plan: &SyncPlan,
    limits: PreflightLimits,
    cancel: &CancelToken,
) -> Result<TargetPreflight> {
    #[cfg(windows)]
    {
        preflight_with(runtime, &gate, root, plan, limits, cancel, |_| Ok(()))
    }
    #[cfg(not(windows))]
    {
        let _ = (runtime, gate, root, plan, limits, cancel);
        anyhow::bail!("target preflight is a Windows-only candidate; no fallback")
    }
}

#[cfg(windows)]
// Event payloads are consumed only by native cfg(test) probes.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) struct PreflightEvent<'a> {
    pub(crate) destination: &'a Path,
    pub(crate) relative: &'a str,
}

#[cfg(windows)]
pub(crate) fn preflight_with(
    runtime: &Runtime,
    gate: &Mutex<()>,
    root: &Path,
    plan: &SyncPlan,
    limits: PreflightLimits,
    cancel: &CancelToken,
    mut hook: impl FnMut(PreflightEvent<'_>) -> Result<()>,
) -> Result<TargetPreflight> {
    ensure!(!cancel.is_cancelled(), "target preflight cancelled");
    limits.validate()?;
    ensure!(
        plan.files().len() <= limits.max_files,
        "target preflight file limit exceeded"
    );
    let root_text = root.to_str().context("non-UTF8 target root")?;
    local_path(root)?;
    let _life = runtime.fleet_source_guard()?;
    let _fs = gate
        .lock()
        .map_err(|_| anyhow::anyhow!("filesystem gate poisoned"))?;
    ensure!(!cancel.is_cancelled(), "target preflight cancelled");
    // Authorize first, but keep the ORIGINAL spelling: canonicalization alone
    // would hide an in-policy junction between root and destination.
    let resolved_root = runtime.policy.resolve(root_text)?;
    local_path(&resolved_root)?;
    let ancestors: Vec<_> = root.ancestors().collect();
    ensure!(
        ancestors.len() <= super::manifest::MAX_DEPTH + 1,
        "target preflight root depth exceeded"
    );
    let mut anchors = Vec::with_capacity(ancestors.len());
    for path in ancestors.iter().rev() {
        let file = open_object(path, true)?;
        let id = object_id(&file, true)?;
        anchors.push((path.to_path_buf(), id, file));
    }
    let root_id = anchors
        .last()
        .context("target preflight root anchor missing")?
        .1
        .clone();
    ensure!(
        object_id(&open_object(&resolved_root, true)?, true)? == root_id,
        "target preflight root changed"
    );
    let resolved_plan = plan_digest(plan)?;
    let mut entries = Vec::with_capacity(plan.files().len());
    let mut parents: BTreeMap<String, (PathBuf, String, File)> = BTreeMap::new();
    let mut declared: BTreeMap<String, String> = BTreeMap::new();
    // Observed existing directories: relative -> (resolved path, object id).
    let mut existing: BTreeMap<String, (PathBuf, String)> = BTreeMap::new();
    // Directory declarations live in their OWN namespace: a planned directory is
    // legitimately an ancestor of planned files. Only real file/directory clashes
    // are rejected, in both directions.
    let mut declared_dirs: BTreeMap<String, String> = BTreeMap::new();
    let mut dir_ancestors: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Declared-but-absent directories, ancestor-first. Never created here.
    let mut planned_dirs: Vec<PlannedDirectory> = Vec::new();
    let mut planned: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut bytes = 0u64;
    if limits.allow_planned_directories {
        for relative in plan.directories() {
            ensure!(!cancel.is_cancelled(), "target preflight cancelled");
            let components: Vec<&str> = relative.split('/').collect();
            ensure!(
                components.len() <= super::manifest::MAX_DEPTH,
                "target preflight depth exceeded"
            );
            for component in &components {
                portable_component(component)?;
            }
            let lower = relative.to_ascii_lowercase();
            if let Some(previous) = declared_dirs.insert(lower.clone(), relative.clone()) {
                ensure!(
                    previous == *relative,
                    "planned targets collide ignoring ASCII case: {previous} vs {relative}"
                );
                anyhow::bail!("duplicate planned target {relative}");
            }
            let mut prefix = String::new();
            for component in &components[..components.len() - 1] {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                dir_ancestors.insert(prefix.to_ascii_lowercase());
            }
            let input = Path::new(root_text).join(relative);
            let resolved = runtime
                .policy
                .resolve(input.to_str().context("non-UTF8 planned directory")?)?;
            local_path(&resolved)?;
            ensure!(
                resolved.starts_with(&resolved_root) && resolved != resolved_root,
                "resolved planned directory escaped the target root"
            );
            match fs::symlink_metadata(&input) {
                Ok(_) => {
                    let original = open_private(&input, true).with_context(|| {
                        format!("planned directory {relative} is not a private plain directory")
                    })?;
                    let dir = open_private(&resolved, true)?;
                    let id = directory_id(&dir)?;
                    ensure!(
                        directory_id(&original)? == id,
                        "planned directory {relative} resolves elsewhere"
                    );
                    existing.insert(relative.clone(), (resolved, id));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if let Some((parent, _)) = relative.rsplit_once('/') {
                        ensure!(
                            existing.contains_key(parent) || planned.contains_key(parent),
                            "planned directory {relative} has no declared or existing parent"
                        );
                    }
                    planned.insert(relative.clone(), resolved.clone());
                    planned_dirs.push(PlannedDirectory {
                        path: relative.clone(),
                        destination: resolved,
                    });
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("target preflight directory {relative}"));
                }
            }
        }
    }
    for file in plan.files() {
        ensure!(!cancel.is_cancelled(), "target preflight cancelled");
        let job = file.job();
        job.validate()?;
        ensure!(!job.overwrite, "target preflight refuses an overwrite plan");
        ensure!(
            job.bytes_total == file.bytes && job.sha256 == file.sha256,
            "plan job and planned summary disagree"
        );
        let relative = file.path.as_str();
        ensure!(
            relative.len() <= MAX_PATH_BYTES,
            "target preflight path length exceeded"
        );
        let expected = Path::new(root_text).join(relative);
        ensure!(
            expected == Path::new(job.destination_path.as_str()),
            "planned destination does not match target root and relative path"
        );
        let components: Vec<&str> = relative.split('/').collect();
        ensure!(
            components.len() <= super::manifest::MAX_DEPTH,
            "target preflight depth exceeded"
        );
        for component in &components {
            portable_component(component)?;
        }
        let lower = relative.to_ascii_lowercase();
        if let Some(previous) = declared.insert(lower.clone(), relative.to_string()) {
            ensure!(
                previous == relative,
                "planned targets collide ignoring ASCII case: {previous} vs {relative}"
            );
            anyhow::bail!("duplicate planned target {relative}");
        }
        ensure!(
            !declared_dirs.contains_key(&lower),
            "planned file {relative} is also a planned directory"
        );
        ensure!(
            !dir_ancestors.contains(&lower),
            "planned file {relative} is also an ancestor directory"
        );
        // A planned file may not also be another planned file's ancestor.
        let mut prefix = String::new();
        for component in &components[..components.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            ensure!(
                !declared.contains_key(&prefix.to_ascii_lowercase()),
                "planned target {prefix} is also a directory of {relative}"
            );
        }
        let parent_relative = components[..components.len() - 1].join("/");
        let original = Path::new(job.destination_path.as_str());
        let from_plan = planned.get(&parent_relative).cloned();
        let original_dir = match &from_plan {
            None => Some(
                open_private(
                    original.parent().context("destination parent missing")?,
                    true,
                )
                .with_context(|| {
                    format!("target preflight requires an existing private parent for {relative}")
                })?,
            ),
            // Declared-but-absent parent: no directory exists to open yet.
            Some(_) => None,
        };
        let resolved = runtime.policy.resolve(job.destination_path.as_str())?;
        local_path(&resolved)?;
        ensure!(
            resolved.starts_with(&resolved_root) && resolved != resolved_root,
            "resolved destination escaped the target root"
        );
        let resolved_parent = resolved
            .parent()
            .context("resolved destination parent missing")?
            .to_path_buf();
        let (id, dir) = match (&from_plan, &original_dir) {
            (None, Some(original_dir)) => {
                let dir = open_private(&resolved_parent, true).with_context(|| {
                    format!("target preflight requires an existing private parent for {relative}")
                })?;
                let id = directory_id(&dir)?;
                ensure!(
                    directory_id(original_dir)? == id,
                    "destination parent resolves to a different directory"
                );
                (id, Some(dir))
            }
            (Some(expected), None) => {
                ensure!(
                    *expected == resolved_parent,
                    "planned parent resolves elsewhere for {relative}"
                );
                // Still absent: no handle can be retained, and the receiver must
                // re-observe the parent after creating it.
                (PLANNED_PARENT_ID.to_string(), None)
            }
            (None, None) | (Some(_), Some(_)) => {
                anyhow::bail!("planned parent state is inconsistent")
            }
        };
        match fs::symlink_metadata(&resolved) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("target preflight destination {relative}"));
            }
            Ok(_) => anyhow::bail!("target preflight found an existing destination: {relative}"),
        }
        bytes = bytes
            .checked_add(file.bytes)
            .context("target preflight byte overflow")?;
        let key = resolved_parent.to_string_lossy().into_owned();
        // Retaining the private parent handle denies ordinary rename/delete for
        // the rest of THIS observation only; it is not a publication reservation.
        if let Some(dir) = dir {
            parents
                .entry(key)
                .or_insert((resolved_parent.clone(), id.clone(), dir));
        }
        entries.push(PreflightEntry {
            path: relative.to_string(),
            destination: resolved,
            parent_id: id,
            bytes: file.bytes,
        });
        let destination: &Path = &entries
            .last()
            .context("preflight entry missing")?
            .destination;
        hook(PreflightEvent {
            destination,
            relative,
        })?;
        ensure!(!cancel.is_cancelled(), "target preflight cancelled");
    }
    for (path, id, file) in &anchors {
        ensure!(
            object_id(file, true)? == *id && object_id(&open_object(path, true)?, true)? == *id,
            "target preflight ancestor changed"
        );
    }
    for (path, id, _) in parents.values() {
        ensure!(
            directory_id(&open_private(path, true)?)? == *id,
            "target preflight parent directory changed"
        );
    }
    ensure!(!cancel.is_cancelled(), "target preflight cancelled");
    Ok(TargetPreflight {
        entries,
        directories: planned_dirs,
        root_id,
        plan_digest: resolved_plan,
        bytes,
    })
}

#[cfg(all(test, windows))]
#[path = "target_preflight_tests.rs"]
mod tests;
