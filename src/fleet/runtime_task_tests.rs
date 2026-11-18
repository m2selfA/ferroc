//! Runtime attachment/lifecycle, PUBLIC test issuance, no production enrollment.
use super::*;
use crate::fleet::{
    job::LeaseProfile,
    source::PeerCommitObservation,
    transfer_tasks::{TaskPhase, TransferTasks},
};

fn single(root: &Path) -> ValidatedGrant {
    let g = grant(root, b"abc");
    g.grant()
        .clone()
        .validate_for_profile(g.job().clone(), LeaseProfile::SingleOwner)
        .unwrap()
}
fn runtime(root: &Path) -> Arc<Runtime> {
    Arc::new(Runtime::new(
        Policy::new(vec![root.to_path_buf()], false).unwrap(),
    ))
}
async fn start_pending(tasks: &TransferTasks, g: ValidatedGrant) -> Uuid {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let id = tasks
        .launch(g, Duration::from_secs(30), move |_| async move {
            let _ = tx.send(());
            std::future::pending::<Result<PeerCommitObservation>>().await
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    id
}
async fn done(tasks: &TransferTasks, id: Uuid) -> crate::fleet::transfer_tasks::TaskSnapshot {
    tokio::time::timeout(Duration::from_secs(5), tasks.wait(id))
        .await
        .unwrap()
        .unwrap()
}
#[tokio::test]
async fn runtime_task_attachment_is_local_explicit_once_and_policy_gated() {
    let root = tempfile::tempdir().unwrap();
    let rt = runtime(root.path());
    assert!(rt.fleet_tasks().unwrap().is_none());
    assert!(rt.open_fleet_tasks(0).is_err());
    assert!(rt.fleet_tasks().unwrap().is_none());
    let tasks = rt.open_fleet_tasks(1).unwrap();
    assert!(rt.open_fleet_tasks(2).is_err());
    let id = tasks
        .launch(single(root.path()), Duration::from_secs(5), |_| async {
            anyhow::bail!("PUBLIC TEST error")
        })
        .unwrap();
    let result = done(&tasks, id).await;
    assert_eq!(result.phase, TaskPhase::Failed);
    assert_eq!(rt.fleet_tasks().unwrap().unwrap().get(id).unwrap().id, id);
    assert!(!crate::runtime::tools().iter().any(|t| matches!(
        t.name.as_str(),
        "send_file" | "sync_dir" | "transfer_get" | "transfer_cancel"
    )));
    let mut policy = Policy::new(vec![root.path().to_path_buf()], false).unwrap();
    policy.allow_transfers = false;
    let disabled = Runtime::new(policy);
    assert!(disabled.open_fleet_tasks(1).is_err());
    assert!(disabled.fleet_tasks().unwrap().is_none());
    rt.shutdown_fleet_host().await.unwrap();
}
#[tokio::test]
async fn runtime_task_shutdown_interrupts_owned_work_and_closes_retained_clones() {
    let root = tempfile::tempdir().unwrap();
    let rt = runtime(root.path());
    let tasks = rt.open_fleet_tasks(2).unwrap();
    let id = start_pending(&tasks, single(root.path())).await;
    rt.shutdown_fleet_host().await.unwrap();
    let observed = tasks.get(id).unwrap();
    // Assertion before fallback is deliberately deferred: old implementations
    // fail without leaving a never-ending worker behind in the red control.
    let another = tempfile::tempdir().unwrap();
    let refused = tasks.launch(single(another.path()), Duration::from_secs(5), |_| {
        std::future::pending()
    });
    if let Ok(extra) = refused.as_ref() {
        tasks.request_cancel(*extra).unwrap();
    }
    tasks.shutdown().await.unwrap();
    assert_eq!(observed.phase, TaskPhase::Interrupted);
    assert!(!observed.remote_cleanup_confirmed);
    assert!(refused.unwrap_err().to_string().contains("stopped"));
    assert!(rt.open_fleet_tasks(1).is_err());
    assert_eq!(
        rt.fleet_tasks().unwrap().unwrap().get(id).unwrap().phase,
        TaskPhase::Interrupted
    );
    rt.shutdown_fleet_host().await.unwrap();
}
#[tokio::test]
async fn runtime_task_full_shutdown_uses_the_same_task_lifecycle() {
    let root = tempfile::tempdir().unwrap();
    let rt = runtime(root.path());
    let tasks = rt.open_fleet_tasks(1).unwrap();
    let id = start_pending(&tasks, single(root.path())).await;
    rt.shutdown().await;
    let observed = tasks.get(id).unwrap();
    tasks.shutdown().await.unwrap();
    assert_eq!(observed.phase, TaskPhase::Interrupted);
    assert!(rt.open_fleet_tasks(1).is_err());
}
#[tokio::test]
async fn runtime_task_shutdown_does_not_own_another_runtime_or_detached_table() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let ra = runtime(a.path());
    let rb = runtime(b.path());
    let ta = ra.open_fleet_tasks(1).unwrap();
    let tb = rb.open_fleet_tasks(1).unwrap();
    let separate = TransferTasks::new(1).unwrap();
    let ia = start_pending(&ta, single(a.path())).await;
    let ib = start_pending(&tb, single(b.path())).await;
    let ic = start_pending(&separate, single(c.path())).await;
    ra.shutdown_fleet_host().await.unwrap();
    let a_before = ta.get(ia).unwrap();
    let b_before = tb.get(ib).unwrap();
    let c_before = separate.get(ic).unwrap();
    ta.shutdown().await.unwrap();
    rb.shutdown_fleet_host().await.unwrap();
    tb.shutdown().await.unwrap();
    separate.shutdown().await.unwrap();
    assert_eq!(a_before.phase, TaskPhase::Interrupted);
    assert_eq!(b_before.phase, TaskPhase::Running);
    assert_eq!(c_before.phase, TaskPhase::Running);
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_task_shutdown_drops_idle_receiver_before_waiting_for_host() {
    let root = tempfile::tempdir().unwrap();
    make_directory(&root.path().join("target")).unwrap();
    let db = root.path().join("target/host.db");
    drop(new_private(&db).unwrap());
    let rt = runtime(&root.path().join("target"));
    let tasks = rt.open_fleet_tasks(1).unwrap();
    let g = single(root.path());
    let worker_grant = g.clone();
    let owner = rt.clone();
    let worker_db = db.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let failure = Arc::new(std::sync::Mutex::new(String::new()));
    let report_failure = failure.clone();
    let id = tasks
        .launch(g, Duration::from_secs(30), move |_| async move {
            let work = async {
                let host = owner.open_fleet_host(&worker_db, InventoryLimits::default())?;
                host.resume()?;
                let receiver =
                    host.admit_receiver(records(&worker_grant, Direction::TargetToSource))?;
                let _ = tx.send(host.status()?.in_flight);
                let result = std::future::pending::<Result<PeerCommitObservation>>().await;
                drop(receiver);
                host.close()?;
                result
            }
            .await;
            if let Err(error) = &work {
                *report_failure.lock().unwrap() = format!("{error:#}");
            }
            work
        })
        .unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap();
    let in_flight = match admitted {
        Ok(count) => count,
        Err(_) => {
            let result = done(&tasks, id).await;
            panic!(
                "Native fixture failed before shutdown: task={:?}; raw={}",
                result.failure,
                failure.lock().unwrap()
            );
        }
    };
    assert_eq!(in_flight, 1);
    let stopped = tokio::time::timeout(Duration::from_secs(5), rt.shutdown_fleet_host()).await;
    let without_external_cancel = matches!(stopped, Ok(Ok(())));
    // Always release the red control's real host owner before an assertion,
    // including a spawn_blocking drain whose observing future timed out.
    let _ = tasks.request_cancel(id);
    let terminal = done(&tasks, id).await;
    rt.shutdown_fleet_host().await.unwrap();
    let recovery = runtime(&root.path().join("target"));
    let inspect = recovery
        .open_fleet_host(&db, InventoryLimits::default())
        .unwrap();
    assert_eq!(inspect.inventory().unwrap().recorded_usage(), (3, 1));
    assert!(!root.path().join("target/output.bin").exists());
    inspect.close().unwrap();
    drop(inspect);
    assert!(
        without_external_cancel,
        "Runtime waited for host before cancelling its owned receiver task"
    );
    assert_eq!(terminal.phase, TaskPhase::Interrupted);
    assert!(!terminal.remote_cleanup_confirmed);
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_task_aborted_shutdown_observer_keeps_both_admissions_closed_but_not_external_fence()
 {
    let root = tempfile::tempdir().unwrap();
    make_directory(&root.path().join("target")).unwrap();
    let db = root.path().join("target/host.db");
    drop(new_private(&db).unwrap());
    let rt = runtime(&root.path().join("target"));
    let tasks = rt.open_fleet_tasks(1).unwrap();
    let g = single(root.path());
    let host = rt.open_fleet_host(&db, InventoryLimits::default()).unwrap();
    host.resume().unwrap();
    let receiver = host
        .admit_receiver(records(&g, Direction::TargetToSource))
        .unwrap();
    let id = start_pending(&tasks, g.clone()).await;
    let owner = rt.clone();
    let stopping = tokio::spawn(async move { owner.shutdown_fleet_host().await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while host.status().unwrap().mode != crate::fleet::host::HostMode::Closing {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let observer_waited_for_external_owner = !stopping.is_finished();
    stopping.abort();
    let _ = stopping.await;
    let terminal = done(&tasks, id).await;
    let closed = tasks
        .launch(g, Duration::from_secs(5), |_| std::future::pending())
        .unwrap_err()
        .to_string();
    assert!(closed.contains("stopped"));
    assert!(host.resume().is_err());
    assert_eq!(host.status().unwrap().in_flight, 1);
    assert!(crate::fleet::fence::OwnerFence::acquire(&db).is_err());
    drop(receiver);
    host.close().unwrap();
    drop(host);
    rt.shutdown_fleet_host().await.unwrap();
    let fence = crate::fleet::fence::OwnerFence::acquire(&db).unwrap();
    drop(fence);
    assert!(observer_waited_for_external_owner);
    assert_eq!(terminal.phase, TaskPhase::Interrupted);
    assert!(!terminal.remote_cleanup_confirmed);
}
#[tokio::test]
async fn runtime_task_attachment_stop_race_never_reopens_table() {
    let root = tempfile::tempdir().unwrap();
    let g = single(root.path());
    for _ in 0..16 {
        let rt = runtime(root.path());
        let (attached, stopped) = tokio::join!(
            async {
                tokio::task::yield_now().await;
                rt.open_fleet_tasks(1)
            },
            rt.shutdown_fleet_host()
        );
        stopped.unwrap();
        if let Ok(table) = attached {
            assert!(
                table
                    .launch(g.clone(), Duration::from_secs(5), |_| std::future::pending(
                    ))
                    .unwrap_err()
                    .to_string()
                    .contains("stopped")
            );
        }
        assert!(rt.open_fleet_tasks(1).is_err());
    }
}
#[tokio::test]
async fn runtime_task_queue_cancel_drops_factory_captures_before_terminal_snapshot() {
    // A PUBLIC test-only blocking Drop lets another OS thread inspect the
    // ordering deterministically, not by racing a tiny notification window.
    struct Witness {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl Drop for Witness {
        fn drop(&mut self) {
            let _ = self.entered.send(());
            let _ = self.release.recv_timeout(Duration::from_secs(5));
        }
    }
    let root = tempfile::tempdir().unwrap();
    let rt = runtime(root.path());
    let tasks = rt.open_fleet_tasks(1).unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let witness = Witness {
        entered: entered_tx,
        release: release_rx,
    };
    let id = tasks
        .launch(single(root.path()), Duration::from_secs(10), move |_| {
            let _owned_capture = witness;
            std::future::pending::<Result<PeerCommitObservation>>()
        })
        .unwrap();
    tasks.request_cancel(id).unwrap();
    let table = tasks.clone();
    let observer = std::thread::spawn(move || {
        let entered = entered_rx.recv_timeout(Duration::from_secs(5));
        let phase = table.get(id).unwrap().phase;
        let _ = release_tx.send(());
        (entered.is_ok(), phase)
    });
    let terminal = done(&tasks, id).await;
    let (entered, during_capture_drop) = observer.join().unwrap();
    rt.shutdown_fleet_host().await.unwrap();
    assert!(entered);
    assert!(
        !during_capture_drop.is_terminal(),
        "terminal snapshot became visible while the owned factory capture was still alive"
    );
    assert_eq!(terminal.phase, TaskPhase::Interrupted);
}
#[test]
fn runtime_task_never_polled_executor_drop_releases_capture_before_worker_dropped() {
    use std::sync::atomic::{AtomicBool, Ordering};
    type Watch = Arc<std::sync::Mutex<Option<(TransferTasks, Uuid)>>>;
    struct Capture {
        watch: Watch,
        released: Arc<AtomicBool>,
        terminal_too_early: Arc<AtomicBool>,
    }
    impl Drop for Capture {
        fn drop(&mut self) {
            if let Some((table, id)) = self.watch.lock().unwrap().as_ref() {
                self.terminal_too_early.store(
                    table.get(*id).unwrap().phase.is_terminal(),
                    Ordering::SeqCst,
                );
            }
            self.released.store(true, Ordering::SeqCst);
        }
    }
    let root = tempfile::tempdir().unwrap();
    let owner = runtime(root.path());
    let tasks = owner.open_fleet_tasks(1).unwrap();
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let watch: Watch = Arc::new(std::sync::Mutex::new(None));
    let released = Arc::new(AtomicBool::new(false));
    let early = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let called = entered.clone();
    let capture = Capture {
        watch: watch.clone(),
        released: released.clone(),
        terminal_too_early: early.clone(),
    };
    let id = {
        let _entered = engine.enter();
        tasks
            .launch(single(root.path()), Duration::from_secs(10), move |_| {
                called.store(true, Ordering::SeqCst);
                let _capture = capture;
                std::future::pending::<Result<PeerCommitObservation>>()
            })
            .unwrap()
    };
    *watch.lock().unwrap() = Some((tasks.clone(), id));
    drop(engine); // No block_on/poll ever ran this worker.
    assert!(!entered.load(Ordering::SeqCst));
    assert!(released.load(Ordering::SeqCst));
    assert!(!early.load(Ordering::SeqCst));
    let result = tasks.get(id).unwrap();
    assert_eq!(result.phase, TaskPhase::Failed);
    assert_eq!(
        result.failure,
        Some(crate::fleet::transfer_tasks::TaskFailure::WorkerDropped)
    );
    let observer = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    observer.block_on(async {
        assert_eq!(done(&tasks, id).await.id, id);
        owner.shutdown_fleet_host().await.unwrap();
    });
}
