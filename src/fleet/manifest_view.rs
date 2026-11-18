//! Bounded exact-subtree rules and session-authenticated metadata pages.
//! Pages are not filesystem snapshots, authorization, or restart tokens.
use super::manifest::{Manifest, ManifestEntry, ManifestLimits, validate_path};
use anyhow::{Result, ensure};
use rand_core::{OsRng, RngCore};
use ring::hmac;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAX_RULES: usize = 128;
pub const MAX_RULE_BYTES: usize = 16 * 1024;
pub const MAX_PAGE_ENTRIES: usize = 1000;
pub const MAX_PAGE_BYTES: usize = 1024 * 1024;

/// Exact UTF8 root-relative paths; excludes that name AND its descendants.
/// No glob, case folding, Unicode normalization, negation or gitignore grammar.
#[derive(Clone, Debug, Default)]
pub struct ScanRules {
    paths: Vec<String>,
}
impl ScanRules {
    pub fn new(mut paths: Vec<String>) -> Result<Self> {
        ensure!(paths.len() <= MAX_RULES, "too many subtree exclusion rules");
        let mut bytes = 0usize;
        for path in &paths {
            validate_path(path)?;
            // Reject glob-looking input rather than silently imply glob support.
            ensure!(
                !path.contains(['*', '?', '[', ']']),
                "exclusions are exact subtree paths, not globs"
            );
            bytes = bytes
                .checked_add(path.len())
                .ok_or_else(|| anyhow::anyhow!("rule size overflow"))?;
            ensure!(
                bytes <= MAX_RULE_BYTES,
                "exclusion rule byte limit exceeded"
            );
        }
        paths.sort();
        ensure!(
            !paths.windows(2).any(|p| p[0] == p[1]),
            "duplicate exclusion path"
        );
        Ok(Self { paths })
    }
    pub fn paths(&self) -> &[String] {
        &self.paths
    }
    pub fn excludes(&self, path: &str) -> bool {
        self.paths.iter().any(|p| {
            path == p
                || path
                    .strip_prefix(p)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ferroc/exact-subtree-rules/v1\0");
        h.update((self.paths.len() as u64).to_be_bytes());
        for path in &self.paths {
            h.update((path.len() as u64).to_be_bytes());
            h.update(path.as_bytes());
        }
        h.finalize().into()
    }
    /// Pure metadata filtering, never a filesystem read or permission.
    pub fn filter(&self, manifest: &Manifest) -> Result<Manifest> {
        Manifest::new(
            manifest
                .entries()
                .filter(|(p, _)| !self.excludes(p))
                .map(|(p, k)| ManifestEntry {
                    path: p.into(),
                    kind: k.clone(),
                })
                .collect(),
            ManifestLimits::default(),
        )
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PageLimits {
    pub max_entries: usize,
    pub max_json_bytes: usize,
}
impl Default for PageLimits {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_json_bytes: 256 * 1024,
        }
    }
}
impl PageLimits {
    pub(crate) fn validate(self) -> Result<()> {
        ensure!(
            (1..=MAX_PAGE_ENTRIES).contains(&self.max_entries)
                && (512..=MAX_PAGE_BYTES).contains(&self.max_json_bytes),
            "page limits outside hard ceilings"
        );
        Ok(())
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestPage {
    pub scan_id: Uuid,
    pub rules_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub consistency: &'static str,
    pub namespace: super::manifest::Namespace,
    pub offset: usize,
    pub total_entries: usize,
    pub entries: Vec<ManifestEntry>,
    pub next_cursor: Option<String>,
}
/// Retains a whole bounded in-memory manifest. Only emitted page JSON is capped;
/// this is NOT a streaming scan/global memory bound or persistent scan service.
/// Cursor MACs are local capabilities for reading this immutable owner only.
pub struct ManifestPages {
    id: Uuid,
    rules: [u8; 32],
    digest: [u8; 32],
    entries: Vec<ManifestEntry>,
    consistency: &'static str,
    limits: PageLimits,
    key: hmac::Key,
}
impl ManifestPages {
    pub fn new(manifest: Manifest, rules: &ScanRules, limits: PageLimits) -> Result<Self> {
        Self::build(
            rules.filter(&manifest)?,
            rules.digest(),
            limits,
            "callerSuppliedMetadata",
        )
    }
    pub fn observed(
        observation: super::manifest_scan::ManifestObservation,
        limits: PageLimits,
    ) -> Result<Self> {
        let rules = observation.rules_digest();
        Self::build(observation.into_manifest(), rules, limits, "readSequence")
    }
    fn build(
        manifest: Manifest,
        rules: [u8; 32],
        limits: PageLimits,
        consistency: &'static str,
    ) -> Result<Self> {
        limits.validate()?;
        let mut h = Sha256::new();
        h.update(b"ferroc/manifest-records/v1\0");
        let mut entries = Vec::with_capacity(manifest.len());
        for (path, kind) in manifest.entries() {
            let entry = ManifestEntry {
                path: path.into(),
                kind: kind.clone(),
            };
            let bytes = serde_json::to_vec(&entry)?;
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
            entries.push(entry);
        }
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *secret);
        Ok(Self {
            id: Uuid::new_v4(),
            rules,
            digest: h.finalize().into(),
            entries,
            consistency,
            limits,
            key: hmac::Key::new(hmac::HMAC_SHA256, &*secret),
        })
    }
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn rules_digest(&self) -> [u8; 32] {
        self.rules
    }
    fn binding(&self, offset: u64) -> Vec<u8> {
        let mut out = b"ferroc/manifest-cursor/v1\0".to_vec();
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.rules);
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&(self.limits.max_entries as u64).to_be_bytes());
        out.extend_from_slice(&(self.limits.max_json_bytes as u64).to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out
    }
    fn cursor(&self, offset: usize) -> String {
        let offset = offset as u64;
        let mut bytes = offset.to_be_bytes().to_vec();
        bytes.extend_from_slice(hmac::sign(&self.key, &self.binding(offset)).as_ref());
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn offset(&self, cursor: Option<&str>) -> Result<usize> {
        let Some(cursor) = cursor else {
            return Ok(0);
        };
        ensure!(
            cursor.len() == 80 && cursor.is_ascii(),
            "invalid manifest cursor length"
        );
        let mut bytes = [0u8; 40];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&cursor[2 * i..2 * i + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid manifest cursor encoding"))?;
        }
        let offset = u64::from_be_bytes(bytes[..8].try_into()?);
        hmac::verify(&self.key, &self.binding(offset), &bytes[8..])
            .map_err(|_| anyhow::anyhow!("manifest cursor authentication failed"))?;
        let offset = usize::try_from(offset)?;
        ensure!(
            offset < self.entries.len(),
            "manifest cursor outside result"
        );
        Ok(offset)
    }
    pub fn page(&self, cursor: Option<&str>) -> Result<ManifestPage> {
        let start = self.offset(cursor)?;
        let mut page = ManifestPage {
            scan_id: self.id,
            rules_digest: self.rules,
            manifest_digest: self.digest,
            consistency: self.consistency,
            namespace: super::manifest::Namespace::ExactUtf8Unqualified,
            offset: start,
            total_entries: self.entries.len(),
            entries: vec![],
            next_cursor: Some(self.cursor(start)),
        };
        let mut bytes = serde_json::to_vec(&page)?.len();
        for item in self.entries[start..].iter().take(self.limits.max_entries) {
            let added = serde_json::to_vec(item)?.len() + usize::from(!page.entries.is_empty());
            if bytes + added > self.limits.max_json_bytes {
                break;
            }
            bytes += added;
            page.entries.push(item.clone());
        }
        ensure!(
            start == self.entries.len() || !page.entries.is_empty(),
            "one manifest entry exceeds page byte budget"
        );
        let end = start + page.entries.len();
        page.next_cursor = (end < self.entries.len()).then(|| self.cursor(end));
        ensure!(
            serde_json::to_vec(&page)?.len() <= self.limits.max_json_bytes,
            "manifest page envelope exceeds byte budget"
        );
        Ok(page)
    }
}
#[cfg(test)]
#[path = "manifest_view_tests.rs"]
mod tests;
