//! Bounded receiver coverage accounting. This does NOT perform filesystem IO.
use super::protocol::{MAX_DATA, MAX_FILE_BYTES};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

pub const WINDOW: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Chunk {
    len: u32,
    digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    New,
    Duplicate,
}
#[derive(Debug)]
pub struct ReceiveRanges {
    total: u64,
    contiguous: u64,
    pending: BTreeMap<u64, Chunk>,
}
impl ReceiveRanges {
    pub fn new(total: u64) -> Result<Self> {
        ensure!(total <= MAX_FILE_BYTES, "file exceeds fleet limit");
        Ok(Self {
            total,
            contiguous: 0,
            pending: BTreeMap::new(),
        })
    }
    /// Validate BEFORE disk IO. Old records already below the contiguous prefix
    /// must be deduplicated by the authenticated record opener, not rewritten.
    pub fn validate(&self, offset: u64, len: u32, digest: &[u8; 32]) -> Result<Admission> {
        ensure!(
            len > 0 && len as usize <= MAX_DATA,
            "invalid DATA range length"
        );
        let end = offset.checked_add(len as u64);
        ensure!(
            end.is_some_and(|e| e <= self.total),
            "DATA outside declared file"
        );
        ensure!(
            offset >= self.contiguous,
            "DATA below committed coverage prefix"
        );
        ensure!(
            offset - self.contiguous <= (MAX_DATA * WINDOW) as u64,
            "DATA exceeds receive window"
        );
        if let Some(c) = self.pending.get(&offset) {
            ensure!(
                c.len == len && c.digest == *digest,
                "conflicting duplicate DATA"
            );
            return Ok(Admission::Duplicate);
        }
        let end = end.expect("range checked");
        if let Some((&start, c)) = self.pending.range(..offset).next_back() {
            ensure!(start + c.len as u64 <= offset, "overlapping DATA");
        }
        if let Some((&start, _)) = self.pending.range(offset..).next() {
            ensure!(end <= start, "overlapping DATA");
        }
        // The missing prefix must always be admissible so a full out-of-order
        // window cannot deadlock itself. No memory is added when it drains.
        ensure!(
            offset == self.contiguous || self.pending.len() < WINDOW,
            "receive window full"
        );
        Ok(Admission::New)
    }
    /// Call only AFTER the stage write succeeds, under the same per-file lock
    /// used by validate/write. ACK means stage coverage, NOT durable commit.
    pub fn record_written(&mut self, offset: u64, len: u32, digest: [u8; 32]) -> Result<Admission> {
        let result = self.validate(offset, len, &digest)?;
        if result == Admission::Duplicate {
            return Ok(result);
        }
        if offset == self.contiguous {
            self.contiguous += len as u64;
        } else {
            self.pending.insert(offset, Chunk { len, digest });
        }
        while let Some(c) = self.pending.remove(&self.contiguous) {
            self.contiguous += c.len as u64;
        }
        Ok(Admission::New)
    }
    pub fn total(&self) -> u64 {
        self.total
    }
    pub fn contiguous(&self) -> u64 {
        self.contiguous
    }
    pub fn received(&self) -> u64 {
        self.contiguous + self.pending.values().map(|c| c.len as u64).sum::<u64>()
    }
    pub fn complete(&self) -> bool {
        self.contiguous == self.total && self.pending.is_empty()
    }
    pub fn pending_ranges(&self) -> usize {
        self.pending.len()
    }
}
