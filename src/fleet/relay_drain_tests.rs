use super::*;
use futures_util::FutureExt;

#[tokio::test]
async fn empty_eof_is_immediate_and_permanently_cuts_new_admission() {
    let gate = ForwardGate::new();
    gate.begin_drain();
    assert!(gate.admit(0).is_none() && gate.admit(1).is_none());
    assert!(gate.drained(0).now_or_never().unwrap().is_ok());
    assert!(gate.drained(1).now_or_never().unwrap().is_ok());
    gate.begin_drain();
    assert!(gate.admit(0).is_none());
}
#[tokio::test]
async fn a_direction_drains_without_waiting_for_unrelated_owners() {
    let gate = ForwardGate::new();
    let first = gate.admit(0).unwrap();
    let second = gate.admit(1).unwrap();
    gate.begin_drain();
    assert!(gate.drained(0).now_or_never().is_none());
    assert!(gate.drained(1).now_or_never().is_none());
    drop(first);
    assert!(gate.drained(0).now_or_never().unwrap().is_ok());
    assert!(gate.drained(1).now_or_never().is_none());
    drop(second);
    assert!(gate.drained(1).now_or_never().unwrap().is_ok());
}
#[tokio::test]
async fn cancelling_blocked_enqueue_and_dropping_queue_release_both_owners() {
    let gate = ForwardGate::new();
    let (tx, rx) = mpsc::channel(1);
    tx.send(ForwardFrame {
        bytes: Bytes::from_static(b"first"),
        permit: gate.admit(0).unwrap(),
    })
    .await
    .ok()
    .unwrap();
    let mut blocked = Box::pin(tx.send(ForwardFrame {
        bytes: Bytes::from_static(b"second"),
        permit: gate.admit(0).unwrap(),
    }));
    assert!(blocked.as_mut().now_or_never().is_none());
    gate.begin_drain();
    drop(blocked);
    assert!(gate.drained(0).now_or_never().is_none());
    drop(rx);
    assert!(gate.drained(0).now_or_never().unwrap().is_ok());
}
#[tokio::test]
async fn dequeue_keeps_the_inflight_write_counted_until_its_owner_drops() {
    let gate = ForwardGate::new();
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(ForwardFrame {
        bytes: Bytes::from_static(b"pending write"),
        permit: gate.admit(0).unwrap(),
    })
    .await
    .ok()
    .unwrap();
    let frame = rx.recv().await.unwrap();
    gate.begin_drain();
    drop(rx);
    assert!(gate.drained(0).now_or_never().is_none());
    drop(frame);
    assert!(gate.drained(0).now_or_never().unwrap().is_ok());
}
#[tokio::test]
async fn aborting_an_unpolled_write_task_drops_its_captured_owner() {
    let gate = ForwardGate::new();
    let frame = ForwardFrame {
        bytes: Bytes::from_static(b"captured"),
        permit: gate.admit(1).unwrap(),
    };
    let task = tokio::spawn(async move {
        let _frame = frame;
        std::future::pending::<()>().await;
    });
    gate.begin_drain();
    assert!(gate.drained(1).now_or_never().is_none());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(gate.drained(1).now_or_never().unwrap().is_ok());
}
#[test]
fn concurrent_eof_cut_never_skips_accepted_owners_or_reopens_admission() {
    for _ in 0..16 {
        let gate = Arc::new(ForwardGate::new());
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();
        for role in (0..8).map(|i| i % 2) {
            let g = gate.clone();
            let b = barrier.clone();
            workers.push(std::thread::spawn(move || {
                b.wait();
                g.admit(role)
            }));
        }
        barrier.wait();
        gate.begin_drain();
        let owners: Vec<_> = workers
            .into_iter()
            .filter_map(|thread| thread.join().unwrap())
            .collect();
        for role in 0..2 {
            assert!(gate.admit(role).is_none());
            let accepted = owners.iter().any(|owner| owner.role == role);
            assert_eq!(gate.drained(role).now_or_never().is_none(), accepted);
        }
        drop(owners);
        assert!(gate.drained(0).now_or_never().unwrap().is_ok());
        assert!(gate.drained(1).now_or_never().unwrap().is_ok());
    }
}
#[tokio::test]
async fn all_drain_waiters_are_notified_when_the_last_owner_finishes() {
    let gate = Arc::new(ForwardGate::new());
    let first = gate.admit(0).unwrap();
    let last = gate.admit(0).unwrap();
    gate.begin_drain();
    let mut waiters = Vec::new();
    for _ in 0..2 {
        let g = gate.clone();
        waiters.push(tokio::spawn(async move { g.drained(0).await }));
    }
    tokio::task::yield_now().await;
    drop(first);
    tokio::task::yield_now().await;
    assert!(waiters.iter().all(|waiter| !waiter.is_finished()));
    drop(last);
    for waiter in waiters {
        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
