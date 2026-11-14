//! Bounded logical manifests and pure dry-run directory differences.
//!
//! NO filesystem scan, native name equivalence, IO authorization, apply, delete,
//! overwrite, network or restart capability. Metadata/digests are caller claims,
//! not measurements. Exact UTF-8 keys are NOT proof of distinct Windows objects.
use super::protocol::MAX_FILE_BYTES;
use anyhow::{Result, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_TOTAL_PATH_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DEPTH: usize = 128;
#[derive(Clone, Copy, Debug)]
pub struct ManifestLimits {
    pub max_entries: usize,
    pub max_total_path_bytes: usize,
}
impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_ENTRIES,
            max_total_path_bytes: MAX_TOTAL_PATH_BYTES,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum EntryKind {
    Directory,
    File {
        size: u64,
        mtime_ns: i64,
        sha256: Option<[u8; 32]>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub kind: EntryKind,
}
/// Validated canonical relative-path metadata, not a scanned filesystem.
/// Empty root is implicit; every non-root parent needs a Directory entry.
/// Nothing case-folds, Unicode-normalizes, aliases, truncates or repairs names.
/// ```
/// use ferroc::fleet::manifest::{Manifest,ManifestLimits,Comparison,diff};
/// let m=Manifest::new(vec![],ManifestLimits::default()).unwrap();
/// assert!(diff(&m,&m,Comparison::default()).unwrap().is_dry_run());
/// ```
/// ```compile_fail
/// let _:ferroc::fleet::manifest::Manifest=serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct Manifest {
    entries: BTreeMap<String, EntryKind>,
    path_bytes: usize,
}
impl Manifest {
    pub fn new(entries: Vec<ManifestEntry>, limits: ManifestLimits) -> Result<Self> {
        ensure!(
            limits.max_entries > 0
                && limits.max_entries <= MAX_ENTRIES
                && limits.max_total_path_bytes > 0
                && limits.max_total_path_bytes <= MAX_TOTAL_PATH_BYTES,
            "manifest limits outside hard ceilings"
        );
        ensure!(
            entries.len() <= limits.max_entries,
            "manifest entry limit exceeded"
        );
        let mut map = BTreeMap::new();
        let mut path_bytes = 0usize;
        for entry in entries {
            validate_path(&entry.path)?;
            path_bytes = path_bytes
                .checked_add(entry.path.len())
                .ok_or_else(|| anyhow::anyhow!("manifest path byte count overflow"))?;
            ensure!(
                path_bytes <= limits.max_total_path_bytes,
                "manifest aggregate path bytes exceeded"
            );
            if let EntryKind::File { size, .. } = entry.kind {
                ensure!(
                    size <= MAX_FILE_BYTES,
                    "manifest file exceeds fleet hard ceiling"
                );
            }
            ensure!(
                !map.contains_key(&entry.path),
                "duplicate logical manifest path"
            );
            map.insert(entry.path, entry.kind);
        }
        for path in map.keys() {
            for (index, _) in path.match_indices('/') {
                ensure!(
                    matches!(map.get(&path[..index]), Some(EntryKind::Directory)),
                    "manifest parent missing or not a directory: {}",
                    &path[..index]
                );
            }
        }
        Ok(Self {
            entries: map,
            path_bytes,
        })
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn path_bytes(&self) -> usize {
        self.path_bytes
    }
    pub fn entries(&self) -> impl Iterator<Item = (&str, &EntryKind)> {
        self.entries.iter().map(|(p, k)| (p.as_str(), k))
    }
}
pub(super) fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES,
        "manifest relative path length outside limit"
    );
    ensure!(!path.starts_with('/') && !path.ends_with('/') && !path.contains(['\\',':']) && !path.chars().any(|c|c.is_control() || matches!(c,'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')),"manifest path must use canonical relative UTF8/slash spelling");
    let mut depth = 0usize;
    for part in path.split('/') {
        depth += 1;
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.to_ascii_lowercase().starts_with(".ferroc-fleet-"),
            "ambiguous or reserved manifest path component"
        );
    }
    ensure!(depth <= MAX_DEPTH, "manifest depth exceeded");
    Ok(())
}
/// Checksum is the default. Quick is explicitly heuristic, NOT content proof:
/// equal size+mtime may hide a modification. ANY mtime difference triggers copy,
/// including a backdated source (never use source.mtime > target.mtime).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Comparison {
    #[default]
    Checksum,
    Quick,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Namespace {
    ExactUtf8Unqualified,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryType {
    Directory,
    File,
}
impl EntryKind {
    fn entry_type(&self) -> EntryType {
        match self {
            Self::Directory => EntryType::Directory,
            Self::File { .. } => EntryType::File,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CopyReason {
    MissingTarget,
    SizeChanged,
    ChecksumChanged,
    MtimeChanged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CopyTarget {
    Absent,
    ExistingFile,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum Difference {
    CopyWholeFile {
        bytes: u64,
        reason: CopyReason,
        target: CopyTarget,
    },
    EnsureDirectory,
    TypeConflict {
        source: EntryType,
        target: EntryType,
    },
    BlockedByAncestor {
        ancestor: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PathDifference {
    pub path: String,
    pub difference: Difference,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetainedTarget {
    pub path: String,
    pub kind: EntryType,
}
/// Descriptive dry-run only. Existing-file copy means a whole-file change is
/// needed, NOT authorization to overwrite it with the current no-clobber engine.
/// A later execution layer must re-observe, qualify native names/identities,
/// authorize each file, enforce its policy and handle races/failure atomically.
/// ```compile_fail
/// fn no_apply(p:ferroc::fleet::manifest::DiffPlan){p.apply().unwrap();}
/// ```
/// ```compile_fail
/// fn no_delete(p:ferroc::fleet::manifest::DiffPlan){p.delete_extra_targets().unwrap();}
/// ```
/// ```compile_fail
/// let _:ferroc::fleet::manifest::DiffPlan=serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiffPlan {
    comparison: Comparison,
    namespace: Namespace,
    dry_run: bool,
    changes: Vec<PathDifference>,
    retained_target_only: Vec<RetainedTarget>,
    unchanged_files: usize,
    matching_directories: usize,
    file_bytes_selected: u64,
}
impl DiffPlan {
    pub fn comparison(&self) -> Comparison {
        self.comparison
    }
    pub fn namespace(&self) -> Namespace {
        self.namespace
    }
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }
    pub fn changes(&self) -> &[PathDifference] {
        &self.changes
    }
    pub fn retained_target_only(&self) -> &[RetainedTarget] {
        &self.retained_target_only
    }
    pub fn unchanged_files(&self) -> usize {
        self.unchanged_files
    }
    pub fn matching_directories(&self) -> usize {
        self.matching_directories
    }
    /// Selected source file sizes, NOT traffic, encoded, received or durable bytes.
    pub fn file_bytes_selected(&self) -> u64 {
        self.file_bytes_selected
    }
}
fn required_digest<'a>(
    digest: &'a Option<[u8; 32]>,
    side: &str,
    path: &str,
) -> Result<&'a [u8; 32]> {
    digest
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("{side} checksum required for logical path {path}"))
}
/// Deterministic lexical output, with parents before children. A type conflict
/// blocks the source directory's descendants, never emits contradictory copies.
/// No deletion is ever produced; even target-only subtrees remain descriptive.
/// Missing digests NEVER silently fall back to Quick. Target-only files and
/// length-mismatched targets do not need hashing because they cannot be skipped
/// on a supposed content equality. Needed source copies still require a source
/// digest in Checksum mode; conflict/blocked paths do not require irrelevant IO.
/// Caller input allocations are already made: these bounds are NOT a parser or
/// transport allocation cap, and are not filesystem snapshot consistency proof.
pub fn diff(source: &Manifest, target: &Manifest, comparison: Comparison) -> Result<DiffPlan> {
    let mut out = DiffPlan {
        comparison,
        namespace: Namespace::ExactUtf8Unqualified,
        dry_run: true,
        changes: vec![],
        retained_target_only: vec![],
        unchanged_files: 0,
        matching_directories: 0,
        file_bytes_selected: 0,
    };
    let mut blocked = BTreeSet::new();
    for (path, entry) in &source.entries {
        let parent_conflict = path
            .match_indices('/')
            .find_map(|(i, _)| blocked.get(&path[..i]).cloned());
        let action = if let Some(ancestor) = parent_conflict {
            Some(Difference::BlockedByAncestor { ancestor })
        } else {
            match (entry, target.entries.get(path)) {
                (EntryKind::Directory, Some(EntryKind::Directory)) => {
                    out.matching_directories += 1;
                    None
                }
                (EntryKind::Directory, None) => Some(Difference::EnsureDirectory),
                (EntryKind::Directory, Some(other)) => {
                    blocked.insert(path.clone());
                    Some(Difference::TypeConflict {
                        source: EntryType::Directory,
                        target: other.entry_type(),
                    })
                }
                (EntryKind::File { .. }, Some(EntryKind::Directory)) => {
                    Some(Difference::TypeConflict {
                        source: EntryType::File,
                        target: EntryType::Directory,
                    })
                }
                (EntryKind::File { size, sha256, .. }, None) => {
                    if comparison == Comparison::Checksum {
                        required_digest(sha256, "source", path)?;
                    }
                    Some(Difference::CopyWholeFile {
                        bytes: *size,
                        reason: CopyReason::MissingTarget,
                        target: CopyTarget::Absent,
                    })
                }
                (
                    EntryKind::File {
                        size,
                        mtime_ns,
                        sha256,
                    },
                    Some(EntryKind::File {
                        size: t_size,
                        mtime_ns: t_mtime,
                        sha256: t_sha,
                    }),
                ) => {
                    if comparison == Comparison::Checksum {
                        required_digest(sha256, "source", path)?;
                    }
                    let reason = if size != t_size {
                        Some(CopyReason::SizeChanged)
                    } else {
                        match comparison {
                            Comparison::Quick => {
                                (mtime_ns != t_mtime).then_some(CopyReason::MtimeChanged)
                            }
                            Comparison::Checksum => (required_digest(sha256, "source", path)?
                                != required_digest(t_sha, "target", path)?)
                            .then_some(CopyReason::ChecksumChanged),
                        }
                    };
                    if let Some(reason) = reason {
                        Some(Difference::CopyWholeFile {
                            bytes: *size,
                            reason,
                            target: CopyTarget::ExistingFile,
                        })
                    } else {
                        out.unchanged_files += 1;
                        None
                    }
                }
            }
        };
        if let Some(difference) = action {
            if let Difference::CopyWholeFile { bytes, .. } = &difference {
                out.file_bytes_selected = out
                    .file_bytes_selected
                    .checked_add(*bytes)
                    .ok_or_else(|| anyhow::anyhow!("selected byte sum overflow"))?;
            }
            out.changes.push(PathDifference {
                path: path.clone(),
                difference,
            });
        }
    }
    for (path, entry) in &target.entries {
        if !source.entries.contains_key(path) {
            out.retained_target_only.push(RetainedTarget {
                path: path.clone(),
                kind: entry.entry_type(),
            });
        }
    }
    Ok(out)
}
#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
