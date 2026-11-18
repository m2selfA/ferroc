//! Task ownership tests. Cryptographic fixtures are PUBLIC, not peer enrollment.
use super::*;
use crate::fleet::{
    job::LeaseProfile,
    source::{PeerCommitObservation, SourceEncoder},
    transfer_tasks::{TaskFailure, TaskPhase, TransferTasks},
};
use std::sync::atomic::{AtomicBool, Ordering};

fn single(root: &Path) -> ValidatedGrant {
    let g = grant(root, b"abc");
    g.grant()
        .clone()
        .validate_for_profile(g.job().clone(), LeaseProfile::SingleOwner)
        .unwrap()
}
/// Authenticated peer CLAIM, deliberately no target IO. Tests must not turn it
/// into a local target settlement or private-IO attestation.
fn peer_claim(g: &ValidatedGrant) -> PeerCommitObservation {
    let mut source = SourceEncoder::new(records(g, Direction::SourceToTarget)).unwrap();
    let mut target = records(g, Direction::TargetToSource);
    source.encode_next(b"abc").unwrap();
    let mut waiting = source.finish().unwrap();
    let receipt = crate::fleet::control::Receipt {
        receipt_id: Uuid::new_v4(),
        size: 3,
        sha256: Sha256::digest(b"abc").into(),
        parent_durability: crate::fleet::control::ParentDurability::Unsupported,
    };
    let frame = target
        .seal_control(crate::fleet::control::ControlBody::CommitAck(receipt))
        .unwrap();
    waiting.observe_final(&frame).unwrap();
    waiting.peer_observation().unwrap().clone()
}
async fn terminal(tasks: &TransferTasks, id: Uuid) -> crate::fleet::transfer_tasks::TaskSnapshot {
    tokio::time::timeout(Duration::from_secs(5), tasks.wait(id))
        .await
        .unwrap()
        .unwrap()
}
#[test]
fn task_capacity_is_explicitly_bounded() {
    assert!(TransferTasks::new(0).is_err());
    assert!(TransferTasks::new(129).is_err());
    assert!(TransferTasks::new(128).is_ok());
}
#[tokio::test]
async fn task_queue_cancel_never_invokes_worker_or_confirms_remote_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(1).unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let flag = ran.clone();
    let id = tasks
        .launch(single(root.path()), Duration::from_secs(2), move |_| {
            flag.store(true, Ordering::SeqCst);
            std::future::pending::<Result<PeerCommitObservation>>()
        })
        .unwrap();
    assert_eq!(tasks.get(id).unwrap().phase, TaskPhase::Queued);
    assert!(tasks.forget_finished(id).is_err());
    assert!(tasks.request_cancel(id).unwrap());
    assert!(!tasks.request_cancel(id).unwrap());
    let done = terminal(&tasks, id).await;
    assert_eq!(done.phase, TaskPhase::Interrupted);
    assert_eq!(done.failure, Some(TaskFailure::LocalStop));
    assert!(!done.remote_cleanup_confirmed);
    assert!(done.peer_reported_coverage_bytes.is_none());
    assert!(!ran.load(Ordering::SeqCst));
    tasks.forget_finished(id).unwrap();
    assert!(tasks.get(id).is_err());
}
#[tokio::test]
async fn task_capacity_and_duplicate_refuse_before_calling_factory() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(1).unwrap();
    let g = single(a.path());
    let id = tasks
        .launch(g.clone(), Duration::from_secs(2), |_| {
            std::future::pending()
        })
        .unwrap();
    let duplicate = tasks.launch(
        g,
        Duration::from_secs(2),
        |_| -> std::future::Ready<Result<PeerCommitObservation>> { panic!("factory must not run") },
    );
    assert!(
        duplicate
            .unwrap_err()
            .to_string()
            .contains("already registered")
    );
    let capacity = tasks.launch(
        single(b.path()),
        Duration::from_secs(2),
        |_| -> std::future::Ready<Result<PeerCommitObservation>> { panic!("factory must not run") },
    );
    assert!(capacity.unwrap_err().to_string().contains("capacity"));
    tasks.request_cancel(id).unwrap();
    terminal(&tasks, id).await;
    assert!(
        tasks
            .launch(single(b.path()), Duration::from_secs(2), |_| {
                std::future::pending()
            })
            .is_err()
    );
    tasks.forget_finished(id).unwrap();
    let next = tasks
        .launch(single(b.path()), Duration::from_secs(2), |_| {
            std::future::pending()
        })
        .unwrap();
    tasks.shutdown().await.unwrap();
    assert_eq!(terminal(&tasks, next).await.phase, TaskPhase::Interrupted);
}
#[tokio::test]
async fn task_observer_timeout_does_not_cancel_and_clone_shares_the_same_id() {
    let root = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(1).unwrap();
    let g = single(root.path());
    let observed = peer_claim(&g);
    let receipt = observed.receipt().clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let id = tasks
        .launch(
            g,
            Duration::from_secs(3),
            |_| async move { rx.await.unwrap() },
        )
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), tasks.wait(id))
            .await
            .is_err()
    );
    let clone = tasks.clone();
    assert!(!clone.get(id).unwrap().phase.is_terminal());
    tx.send(Ok(observed)).unwrap();
    let result = terminal(&clone, id).await;
    assert_eq!(result.phase, TaskPhase::PeerReportedCompleted);
    assert_eq!(result.peer_reported_committed_bytes, Some(3));
    assert_eq!(result.peer_observation.unwrap().receipt(), &receipt);
    assert!(result.encoded_bytes.is_none());
    assert!(!tasks.request_cancel(id).unwrap());
    assert!(!clone.get(id).unwrap().remote_cleanup_confirmed);
}
struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[tokio::test]
async fn task_cancel_drops_owned_worker_before_terminal_status_and_shutdown_drains() {
    let root = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(1).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let flag = dropped.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let id = tasks
        .launch(
            single(root.path()),
            Duration::from_secs(3),
            |_| async move {
                let _drop = DropFlag(flag);
                tx.send(()).unwrap();
                std::future::pending::<Result<PeerCommitObservation>>().await
            },
        )
        .unwrap();
    rx.await.unwrap();
    assert!(tasks.request_cancel(id).unwrap());
    let (a, b) = tokio::join!(tasks.shutdown(), tasks.shutdown());
    a.unwrap();
    b.unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(tasks.get(id).unwrap().phase, TaskPhase::Interrupted);
    assert!(
        tasks
            .launch(single(root.path()), Duration::from_secs(1), |_| {
                std::future::pending()
            })
            .is_err()
    );
}
#[tokio::test]
async fn task_wrong_job_receipt_is_not_accepted_and_worker_errors_are_redacted() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(2).unwrap();
    let observation = peer_claim(&single(b.path()));
    let id = tasks
        .launch(single(a.path()), Duration::from_secs(2), |_| {
            std::future::ready(Ok(observation))
        })
        .unwrap();
    let bad = terminal(&tasks, id).await;
    assert_eq!(bad.failure, Some(TaskFailure::ReceiptMismatch));
    assert!(bad.peer_observation.is_none());
    let id = tasks
        .launch(single(b.path()), Duration::from_secs(2), |_| {
            std::future::ready(Err(anyhow::anyhow!("PUBLIC_SENSITIVE_TEST_TOKEN")))
        })
        .unwrap();
    let bad = terminal(&tasks, id).await;
    assert_eq!(bad.failure, Some(TaskFailure::WorkerFailed));
    assert!(
        !serde_json::to_string(&bad)
            .unwrap()
            .contains("PUBLIC_SENSITIVE_TEST_TOKEN")
    );
}
#[tokio::test]
async fn task_worker_panic_and_budget_expiry_do_not_strand_drain() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(2).unwrap();
    let id = tasks
        .launch(
            single(a.path()),
            Duration::from_secs(1),
            |_| -> std::future::Ready<Result<PeerCommitObservation>> {
                panic!("PUBLIC test worker panic")
            },
        )
        .unwrap();
    assert_eq!(
        terminal(&tasks, id).await.failure,
        Some(TaskFailure::WorkerDropped)
    );
    let id = tasks
        .launch(single(b.path()), Duration::from_millis(1), |_| {
            std::future::pending()
        })
        .unwrap();
    assert_eq!(
        terminal(&tasks, id).await.failure,
        Some(TaskFailure::TaskDeadline)
    );
    tokio::time::timeout(Duration::from_secs(2), tasks.shutdown())
        .await
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn task_rejects_unknown_ids_rotating_profile_and_invalid_budget() {
    let root = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(1).unwrap();
    let id = Uuid::new_v4();
    assert!(tasks.get(id).is_err());
    assert!(tasks.request_cancel(id).is_err());
    assert!(tasks.wait(id).await.is_err());
    assert!(
        tasks
            .launch(grant(root.path(), b"abc"), Duration::from_secs(1), |_| {
                std::future::pending()
            })
            .is_err()
    );
    for budget in [Duration::ZERO, Duration::from_secs(301)] {
        assert!(
            tasks
                .launch(single(root.path()), budget, |_| std::future::pending())
                .is_err()
        );
    }
}
/// Real source + real Windows target + TCP/WS relay, owned by a background task.
/// PUBLIC cfg(test) issuance; not operational registration or a second host.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn task_real_relay_worker_settles_and_polling_accepts_the_same_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x39; 131_073];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let raw = grant(&root, &data);
    let g = raw
        .grant()
        .clone()
        .validate_for_profile(raw.job().clone(), LeaseProfile::SingleOwner)
        .unwrap();
    let fleet = Arc::new(FleetRelay::new());
    let initialization = std::time::Instant::now();
    let (url, _relay, server_task) = server(&root, Some(fleet.clone())).await;
    let init_ms = initialization.elapsed().as_millis();
    // Do not spend the route TTL on Relay::new/password initialization.
    // The original 30s route and25s worker budget are unchanged.
    let tickets = fleet
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let events = Arc::new(std::sync::Mutex::new(vec![format!(
        "server_init_ms={init_ms};route_ttl_ms=30000;approved_after_server_ready=true"
    )]));
    let trace = events.clone();
    let failure_job = g.job().clone();
    let tasks = TransferTasks::new(1).unwrap();
    let work_grant = g.clone();
    let work_root = root.clone();
    let local_receipt = Arc::new(std::sync::Mutex::new(None));
    let slot = local_receipt.clone();
    let id = tasks
        .launch(g, Duration::from_secs(25), move |_| {
            Box::pin(async move {
                let work = async {
                    trace.lock().unwrap().push("worker_start".into());
                    let source_rt =
                        Runtime::new(Policy::new(vec![work_root.join("source")], false)?);
                    let target_rt =
                        Runtime::new(Policy::new(vec![work_root.join("target")], false)?);
                    let host = target_rt.open_fleet_host(
                        &work_root.join("target/host.db"),
                        InventoryLimits::default(),
                    )?;
                    host.resume()?;
                    let window = SourceWindow::new(
                        source_rt
                            .open_fleet_source(records(&work_grant, Direction::SourceToTarget))?,
                        8,
                    )?;
                    let receiver =
                        host.admit_receiver(records(&work_grant, Direction::TargetToSource))?;
                    let a = link(
                        &url,
                        tickets.source.expose_secret(),
                        &work_grant,
                        Direction::SourceToTarget,
                    )
                    .await?;
                    let b = link(
                        &url,
                        tickets.target.expose_secret(),
                        &work_grant,
                        Direction::TargetToSource,
                    )
                    .await?;
                    let (source_result, target_result) = tokio::join!(
                        run_source(window, a),
                        crate::fleet::relay_io::run_target(receiver, b)
                    );
                    trace.lock().unwrap().push(format!(
                        "source_result={:?}",
                        source_result
                            .as_ref()
                            .map(|v| v.receipt())
                            .map_err(|e| format!("{e:#}"))
                    ));
                    trace
                        .lock()
                        .unwrap()
                        .push(format!("target_result={target_result:?}"));
                    if source_result.is_err() || target_result.is_err() {
                        trace.lock().unwrap().push(format!(
                            "inventory_after_pumps={:?}",
                            host.inventory().map(|v| v.recorded_usage())
                        ));
                    }
                    let observation = source_result?;
                    let receipt = target_result?;
                    ensure!(observation.receipt() == &receipt, "two receipts differ");
                    ensure!(
                        host.inventory()?.recorded_usage() == (0, 0),
                        "stage debt retained"
                    );
                    host.close()?;
                    *slot.lock().unwrap() = Some(receipt);
                    source_rt.shutdown().await;
                    target_rt.shutdown().await;
                    Ok(observation)
                }
                .await;
                if let Err(error) = &work {
                    trace.lock().unwrap().push(
                        format!("worker_error={error:#}")
                            .chars()
                            .take(4096)
                            .collect(),
                    );
                }
                work
            })
        })
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(25), tasks.wait(id))
        .await
        .unwrap()
        .unwrap();
    // Test-only evidence; no credentials and no production error logging.
    let evidence =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/fleet-p1/task-native");
    std::fs::create_dir_all(&evidence).unwrap();
    serde_json::to_writer(
        new_private(&evidence.join(format!("{}.json", result.id))).unwrap(),
        &serde_json::json!({"job":failure_job,"task":result,"events":*events.lock().unwrap(),"localReceipt":*local_receipt.lock().unwrap()}),
    ).unwrap();
    if result.phase != TaskPhase::PeerReportedCompleted {
        serde_json::to_writer(
            new_private(&root.join("task-failure.json")).unwrap(),
            &serde_json::json!({"job":failure_job,"task":result,"events":*events.lock().unwrap(),"localReceipt":*local_receipt.lock().unwrap()}),
        ).unwrap();
        let path = temp.keep();
        panic!(
            "task failure {:?}; retained={}; events={:?}",
            result.failure,
            path.display(),
            events.lock().unwrap()
        );
    }
    assert_eq!(result.phase, TaskPhase::PeerReportedCompleted);
    assert_eq!(result.peer_reported_committed_bytes, Some(131_073));
    assert_eq!(
        result.peer_observation.as_ref().unwrap().receipt(),
        local_receipt.lock().unwrap().as_ref().unwrap()
    );
    assert_eq!(std::fs::read(root.join("target/output.bin")).unwrap(), data);
    assert!(!tasks.request_cancel(id).unwrap());
    tasks.shutdown().await.unwrap();
    server_task.abort();
    let _ = server_task.await;
}
#[test]
fn task_route_is_send_sync_and_retirement_clone_is_independent() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Route>();
    let temp = tempfile::tempdir().unwrap();
    let g = grant(temp.path(), b"abc");
    let next = crate::fleet::renewal::successor(&g, &[0x46; 32], 1, 200, 30000).unwrap();
    let mut route = Route::from_grant(&g);
    route.advance(&next).unwrap();
    let copy = route.clone();
    {
        let mut state = copy.retirement.lock().unwrap();
        state.binding = None;
        state.switched = 3;
    }
    let original = route.retirement.lock().unwrap();
    assert_eq!(original.binding.as_ref(), Some(&g.grant().binding));
    assert_eq!(original.switched, 0);
}
#[tokio::test]
async fn task_ready_peer_observation_survives_late_local_cancel_request() {
    let root = tempfile::tempdir().unwrap();
    let tasks = TransferTasks::new(1).unwrap();
    let g = single(root.path());
    let observation = peer_claim(&g);
    let (started, ready) = tokio::sync::oneshot::channel();
    let (send, receive) = tokio::sync::oneshot::channel();
    let id = tasks
        .launch(g, Duration::from_secs(3), |_| async move {
            started.send(()).unwrap();
            receive.await.unwrap()
        })
        .unwrap();
    ready.await.unwrap();
    assert!(tasks.request_cancel(id).unwrap());
    send.send(Ok(observation)).unwrap();
    let done = terminal(&tasks, id).await;
    assert_eq!(done.phase, TaskPhase::PeerReportedCompleted);
    assert!(done.peer_observation.is_some());
    assert!(!tasks.request_cancel(id).unwrap());
}
