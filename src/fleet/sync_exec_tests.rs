use super::*;
use crate::fleet::{
    control::ParentDurability,
    manifest::{Comparison, EntryKind, Manifest, ManifestEntry, ManifestLimits, diff},
    sync_plan::{SyncTemplate, plan_add_only},
    sync_run::{FileState, RunState},
};
use std::sync::atomic::AtomicUsize;
use uuid::Uuid;

fn plan(root: &str, count: usize) -> SyncPlan {
    let source = Manifest::new(
        (0..count)
            .map(|i| ManifestEntry {
                path: format!("{i}.bin"),
                kind: EntryKind::File {
                    size: 3,
                    mtime_ns: 1,
                    sha256: Some([(i + 1) as u8; 32]),
                },
            })
            .collect(),
        ManifestLimits::default(),
    )
    .unwrap();
    let target = Manifest::new(vec![], ManifestLimits::default()).unwrap();
    plan_add_only(
        &source,
        &diff(&source, &target, Comparison::Checksum).unwrap(),
        &SyncTemplate {
            fleet_id: Uuid::from_bytes([1; 16]),
            source_device: [2; 32],
            target_device: [3; 32],
            transfer_id: Uuid::from_bytes([4; 16]),
            source_root: root,
            target_root: "C:/target",
            deadline_ms: 60000,
            idempotency_prefix: "driver-boundary",
            chunk_bytes: 65536,
        },
    )
    .unwrap()
}
fn receipt() -> Receipt {
    Receipt {
        receipt_id: Uuid::from_bytes([5; 16]),
        size: 3,
        sha256: [1; 32],
        parent_durability: ParentDurability::Unsupported,
    }
}

#[tokio::test]
async fn driver_rejects_other_job_before_preparation_or_mutation() {
    let original = plan("C:/source", 1);
    let other = plan("C:/different", 1);
    let mut ledger = RunLedger::new(&original);
    let mut called = 0;
    let token = CancelToken::new();
    let result = run_plan(&other, &mut ledger, &token, |_| {
        called += 1;
        async { anyhow::bail!("must not prepare a mismatched plan") }
    })
    .await;
    assert!(
        result.is_err(),
        "different job must be rejected before start"
    );
    assert_eq!(called, 0);
    assert_eq!(ledger.entries()[0].state(), FileState::Pending);
    assert!(ledger.failure().is_none());
}

#[tokio::test]
async fn driver_continues_at_pending_index_and_preserves_prior_receipt() {
    let plan = plan("C:/source", 2);
    let mut ledger = RunLedger::new(&plan);
    ledger.start_next().unwrap();
    let first = receipt();
    ledger.settle(&first).unwrap();
    let mut indices = Vec::new();
    let token = CancelToken::new();
    let status = run_plan(&plan, &mut ledger, &token, |i| {
        indices.push(i);
        async { anyhow::bail!("controlled preparation refusal") }
    })
    .await
    .unwrap();
    assert_eq!(indices, vec![1], "do not restart closure index at zero");
    assert_eq!(status.state, RunState::Blocked);
    assert_eq!(status.settled_bytes, 3);
    assert_eq!(ledger.entries()[0].receipt(), Some(&first));
    assert_eq!(ledger.failure().unwrap().path, "1.bin");
    assert!(ledger.start_next().is_err());
}

struct OnDrop(Arc<AtomicUsize>);
impl Drop for OnDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[tokio::test]
async fn driver_cancel_during_pending_prepare_drops_it_and_is_terminal() {
    let plan = plan("C:/source", 2);
    let mut ledger = RunLedger::new(&plan);
    let token = CancelToken::new();
    let drops = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut tx = Some(tx);
    let stop = async {
        rx.await.unwrap();
        token.cancel();
    };
    let drive = run_plan(&plan, &mut ledger, &token, |_| {
        let tx = tx.take().unwrap();
        let drops = drops.clone();
        async move {
            let _guard = OnDrop(drops);
            tx.send(()).unwrap();
            std::future::pending::<Result<PreparedFile<'_>>>().await
        }
    });
    let (result, ()) =
        tokio::time::timeout(Duration::from_secs(1), async { tokio::join!(drive, stop) })
            .await
            .expect("cancellation must also interrupt preparation, not wait forever");
    assert_eq!(result.unwrap().state, RunState::Cancelled);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.entries()[0].state(), FileState::Cancelled);
    assert_eq!(ledger.entries()[1].state(), FileState::Pending);
    assert!(ledger.start_next().is_err());
}

#[tokio::test]
async fn driver_completed_or_empty_plan_stays_complete_even_with_stop_token() {
    for count in [0, 1] {
        let plan = plan("C:/source", count);
        let mut ledger = RunLedger::new(&plan);
        if count == 1 {
            ledger.start_next().unwrap();
            ledger.settle(&receipt()).unwrap();
        }
        let token = CancelToken::new();
        token.cancel();
        let status = run_plan(&plan, &mut ledger, &token, |_| async {
            panic!("complete ledger must prepare nothing")
        })
        .await
        .unwrap();
        assert_eq!(status.state, RunState::Complete);
        assert!(!ledger.is_cancelled());
    }
}

#[tokio::test]
async fn driver_refuses_external_active_owner_without_cancelling_it() {
    let plan = plan("C:/source", 1);
    let mut ledger = RunLedger::new(&plan);
    ledger.start_next().unwrap();
    let token = CancelToken::new();
    token.cancel();
    assert!(
        run_plan(&plan, &mut ledger, &token, |_| async {
            panic!("must not adopt an already active owner")
        })
        .await
        .is_err()
    );
    assert_eq!(ledger.entries()[0].state(), FileState::InFlight);
    assert!(!ledger.is_cancelled());
}

#[tokio::test]
async fn driver_refuses_failed_or_cancelled_ledger_without_reviving_it() {
    for cancelled in [false, true] {
        let plan = plan("C:/source", 1);
        let mut ledger = RunLedger::new(&plan);
        ledger.start_next().unwrap();
        if cancelled {
            ledger.cancel("original stop").unwrap();
        } else {
            ledger.fail("original IO error").unwrap();
        }
        let before = ledger.status();
        let token = CancelToken::new();
        assert!(
            run_plan(&plan, &mut ledger, &token, |_| async {
                panic!("terminal ledger cannot prepare another file")
            })
            .await
            .is_err()
        );
        assert_eq!(ledger.status(), before);
    }
}

#[test]
fn ledger_same_size_wrong_sha_cannot_settle() {
    let plan = plan("C:/source", 1);
    let mut ledger = RunLedger::new(&plan);
    ledger.start_next().unwrap();
    let mut wrong = receipt();
    wrong.sha256 = [9; 32];
    assert!(
        ledger.settle(&wrong).is_err(),
        "size alone is not file identity"
    );
    assert_eq!(ledger.active_path(), Some("0.bin"));
    assert_eq!(ledger.settled_bytes(), 0);
    assert!(ledger.entries()[0].receipt().is_none());
    ledger.settle(&receipt()).unwrap();
    assert_eq!(ledger.status().state, RunState::Complete);
}
