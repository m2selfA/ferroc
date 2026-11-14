use super::*;
use crate::fleet::{
    control::{ParentDurability, Receipt},
    manifest::{Comparison, EntryKind, Manifest, ManifestEntry, ManifestLimits, diff},
    sync_plan::{SyncTemplate, plan_add_only},
};
use uuid::Uuid;
fn plan(files: &[(&str, u64)]) -> SyncPlan {
    let entries: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(i, (p, s))| ManifestEntry {
            path: (*p).into(),
            kind: EntryKind::File {
                size: *s,
                mtime_ns: 5,
                sha256: Some([(i + 1) as u8; 32]),
            },
        })
        .collect();
    let source = Manifest::new(entries, ManifestLimits::default()).unwrap();
    let target = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    let d = diff(&source, &target, Comparison::Checksum).unwrap();
    plan_add_only(
        &source,
        &d,
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: [2; 32],
            target_device: [3; 32],
            transfer_id: Uuid::from_bytes([4; 16]),
            source_root: "C:/src",
            target_root: "C:/dst",
            deadline_ms: 60_000,
            idempotency_prefix: "sync-1",
            chunk_bytes: 65536,
        },
    )
    .unwrap()
}
fn receipt(size: u64, tag: u8) -> Receipt {
    Receipt {
        receipt_id: Uuid::from_bytes([tag; 16]),
        size,
        sha256: [tag; 32],
        parent_durability: ParentDurability::Unsupported,
    }
}
#[test]
fn starts_in_plan_order_and_allows_one_flight_at_a_time() {
    let plan = plan(&[("a.bin", 3), ("b.bin", 5)]);
    let mut run = RunLedger::new(&plan);
    assert_eq!(run.len(), 2);
    assert_eq!(run.settled_bytes(), 0);
    assert!(
        run.entries()
            .iter()
            .all(|e| e.state() == FileState::Pending)
    );
    assert_eq!(run.start_next().unwrap(), Some("a.bin"));
    assert_eq!(run.active_path(), Some("a.bin"));
    assert!(run.start_next().is_err());
}
#[test]
fn settle_requires_exact_size_and_advances_order() {
    let plan = plan(&[("a.bin", 3), ("b.bin", 5)]);
    let mut run = RunLedger::new(&plan);
    run.start_next().unwrap();
    assert!(run.settle(&receipt(4, 1)).is_err());
    assert_eq!(run.active_path(), Some("a.bin"));
    run.settle(&receipt(3, 1)).unwrap();
    assert_eq!(run.settled_count(), 1);
    assert_eq!(run.settled_bytes(), 3);
    assert_eq!(run.active_path(), None);
    assert_eq!(run.start_next().unwrap(), Some("b.bin"));
    run.settle(&receipt(5, 2)).unwrap();
    assert_eq!(run.settled_bytes(), 8);
    assert_eq!(run.start_next().unwrap(), None);
}
#[test]
fn settle_without_flight_or_twice_is_refused() {
    let plan = plan(&[("a.bin", 3)]);
    let mut run = RunLedger::new(&plan);
    assert!(run.settle(&receipt(3, 1)).is_err());
    run.start_next().unwrap();
    run.settle(&receipt(3, 1)).unwrap();
    assert!(run.settle(&receipt(3, 1)).is_err());
    assert_eq!(run.settled_count(), 1);
}
#[test]
fn failure_blocks_the_run_and_keeps_history() {
    let plan = plan(&[("a.bin", 3), ("b.bin", 5), ("c.bin", 7)]);
    let mut run = RunLedger::new(&plan);
    run.start_next().unwrap();
    run.settle(&receipt(3, 1)).unwrap();
    run.start_next().unwrap();
    run.fail("peer reported failure").unwrap();
    assert!(run.is_blocked());
    assert_eq!(run.failed_count(), 1);
    assert_eq!(run.settled_bytes(), 3);
    assert_eq!(run.failure().unwrap().path, "b.bin");
    assert!(run.start_next().is_err());
    assert!(run.settle(&receipt(5, 2)).is_err());
    // No revival path exists in this ledger.
    assert!(run.start_next().is_err());
    assert_eq!(run.settled_count(), 1);
}
#[test]
fn fail_requires_a_flight_and_a_reason() {
    let plan = plan(&[("a.bin", 3)]);
    let mut run = RunLedger::new(&plan);
    assert!(run.fail("x").is_err());
    run.start_next().unwrap();
    assert!(run.fail("").is_err());
    assert!(!run.is_blocked());
    run.fail("local IO error").unwrap();
    assert!(run.is_blocked());
}
#[test]
fn empty_plan_and_zero_byte_file_are_representable() {
    let empty = plan(&[]);
    let mut run = RunLedger::new(&empty);
    assert!(run.is_empty());
    assert_eq!(run.start_next().unwrap(), None);

    let zero = plan(&[("empty.bin", 0), ("one.bin", 1)]);
    let mut run = RunLedger::new(&zero);
    assert_eq!(run.start_next().unwrap(), Some("empty.bin"));
    run.settle(&receipt(0, 1)).unwrap();
    assert_eq!(run.settled_bytes(), 0);
    assert_eq!(run.settled_count(), 1);
    assert_eq!(run.start_next().unwrap(), Some("one.bin"));
    run.settle(&receipt(1, 2)).unwrap();
    assert_eq!(run.settled_bytes(), 1);
}
#[test]
fn status_reports_running_complete_and_settled_bytes() {
    let plan = plan(&[("a.bin", 3), ("b.bin", 5)]);
    let mut run = RunLedger::new(&plan);
    let status = run.status();
    assert_eq!(status.state, RunState::Running);
    assert_eq!(status.planned, 2);
    assert_eq!(status.settled, 0);
    run.start_next().unwrap();
    assert_eq!(run.status().state, RunState::Running);
    run.settle(&receipt(3, 1)).unwrap();
    assert_eq!(run.status().settled, 1);
    assert_eq!(run.status().settled_bytes, 3);
    run.start_next().unwrap();
    run.settle(&receipt(5, 2)).unwrap();
    let status = run.status();
    assert_eq!(status.state, RunState::Complete);
    assert_eq!(status.settled, 2);
    assert_eq!(status.settled_bytes, 8);
}
#[test]
fn cancel_without_flight_stops_future_work() {
    let plan = plan(&[("a.bin", 3), ("b.bin", 5)]);
    let mut run = RunLedger::new(&plan);
    run.cancel("operator stop").unwrap();
    assert!(run.is_cancelled());
    assert_eq!(run.cancelled_reason(), Some("operator stop"));
    assert_eq!(run.status().state, RunState::Cancelled);
    assert!(run.start_next().is_err());
    assert!(run.settle(&receipt(3, 1)).is_err());
    assert!(run.fail("late").is_err());
    // Idempotent refusal: a second cancel does not overwrite the reason.
    assert!(run.cancel("again").is_err());
    assert_eq!(run.cancelled_reason(), Some("operator stop"));
}
#[test]
fn cancel_with_flight_marks_it_cancelled_and_keeps_prior_settlement() {
    let plan = plan(&[("a.bin", 3), ("b.bin", 5)]);
    let mut run = RunLedger::new(&plan);
    run.start_next().unwrap();
    run.settle(&receipt(3, 1)).unwrap();
    run.start_next().unwrap();
    run.cancel("operator stop").unwrap();
    assert_eq!(run.active_path(), None);
    assert_eq!(run.entries()[1].state(), FileState::Cancelled);
    assert_eq!(run.status().cancelled, 1);
    assert_eq!(run.status().settled, 1);
    assert_eq!(run.settled_bytes(), 3);
    // The cancelled file has no receipt and cannot be settled later.
    assert_eq!(run.entries()[1].receipt(), None);
    assert!(run.settle(&receipt(5, 2)).is_err());
}
#[test]
fn cancel_is_refused_after_failure_or_completion() {
    let failed_plan = plan(&[("a.bin", 3)]);
    let mut run = RunLedger::new(&failed_plan);
    run.start_next().unwrap();
    run.fail("io").unwrap();
    assert!(run.cancel("operator stop").is_err());
    assert_eq!(run.status().state, RunState::Blocked);

    let complete_plan = plan(&[("a.bin", 3)]);
    let mut run = RunLedger::new(&complete_plan);
    run.start_next().unwrap();
    run.settle(&receipt(3, 1)).unwrap();
    assert!(run.cancel("too late").is_err());
    assert_eq!(run.status().state, RunState::Complete);
}

#[test]
fn receipts_are_retained_per_file_and_never_rewritten() {
    let plan = plan(&[("a.bin", 3), ("b.bin", 5)]);
    let mut run = RunLedger::new(&plan);
    run.start_next().unwrap();
    let first = receipt(3, 1);
    run.settle(&first).unwrap();
    assert_eq!(run.entries()[0].receipt(), Some(&first));
    run.start_next().unwrap();
    run.settle(&receipt(5, 2)).unwrap();
    assert_eq!(run.entries()[0].receipt(), Some(&first));
}
