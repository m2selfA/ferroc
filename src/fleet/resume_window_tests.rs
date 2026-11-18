//! Candidate LOCAL records window; no stock agent or process/network resume.
use super::*;
use crate::fleet::{
    control::{Ack, ControlBody, Ready, ResumeBase, ResumeReady},
    source_window::{ProgressOutcome, SourceWindow, WindowRecord},
};
macro_rules! setup {
    ($f:ident,$h:ident,$r:ident,$w:ident,$recv:ident,$base:ident,$different:expr) => {
        std::fs::write(&$f.old.source_path, &$f.data).unwrap();
        let proof = $f.proof.take().unwrap();
        let $h = recovered(&$f, proof);
        let old = $h.get(&$f.key).unwrap().unwrap();
        let (source, target) = owner_pair_variant(&$f, &$f.cp, $different);
        let $base = ResumeBase::from_condition(target.condition());
        $h.resume_retained_recovery().unwrap();
        let mut $recv = $h
            .admit_retained_receiver(&$f.key, old.revision(), target, $f.data.len() as u64)
            .unwrap();
        let $r = crate::runtime::Runtime::new(
            crate::config::Policy::new(vec![$f.path.parent().unwrap().to_path_buf()], false)
                .unwrap(),
        );
        let source = $r
            .open_fleet_resume_source(source, $f.data.len() as u64)
            .unwrap();
        let mut $w = SourceWindow::resuming(source, 2).unwrap();
        assert_eq!($w.next_record().unwrap(), WindowRecord::WaitingForReady);
    };
}
fn take(w: &mut SourceWindow<'_>) -> (u64, Vec<u8>) {
    match w.next_record().unwrap() {
        WindowRecord::Data { offset, ciphertext } => (offset, ciphertext.to_vec()),
        other => panic!("expected DATA: {other:?}"),
    }
}
#[test]
fn restored_window_requires_exact_base_before_any_suffix_and_preserves_counter_meaning() {
    let mut f = stopped(&vec![7; 131073], 101);
    setup!(f, h, r, w, recv, base, false);
    assert_eq!(base.prefix_bytes, 101);
    assert_eq!(w.next_record().unwrap(), WindowRecord::WaitingForReady);
    assert_eq!(w.bytes_encoded(), 0);
    assert_eq!(w.bytes_peer_reported_contiguous(), 0);
    let ready = recv.resume_ready_record(2).unwrap().to_vec();
    assert_eq!(ready, recv.resume_ready_record(2).unwrap());
    assert_eq!(w.observe_control(&ready).unwrap(), ProgressOutcome::Ready);
    assert_eq!(
        w.observe_control(&ready).unwrap(),
        ProgressOutcome::Duplicate
    );
    assert_eq!(w.bytes_peer_reported_contiguous(), 101);
    assert!(!w.at_renewal_boundary());
    assert!(w.begin_renewal(Uuid::new_v4(), Uuid::new_v4(), 1).is_err());
    assert!(!w.is_faulted());
    let (offset, a) = take(&mut w);
    assert_eq!(offset, 101);
    let (offset2, b) = take(&mut w);
    assert_eq!(offset2, 101 + 65536);
    assert_eq!(w.pending_records(), 2);
    assert_eq!(w.bytes_encoded(), 130972);
    assert_eq!(w.next_record().unwrap(), WindowRecord::Backpressured);
    assert_eq!(w.retry_record(offset).unwrap(), a);
    recv.write_record(&a).unwrap();
    let ack = recv.resume_ack_record().unwrap().to_vec();
    assert_eq!(ack, recv.resume_ack_record().unwrap());
    w.observe_control(&ack).unwrap();
    assert_eq!(w.bytes_peer_reported_contiguous(), 65637);
    assert_eq!(w.pending_records(), 1);
    assert!(w.retry_record(offset).is_err());
    recv.write_record(&b).unwrap();
    w.observe_control(recv.resume_ack_record().unwrap())
        .unwrap();
    assert_eq!(w.bytes_peer_reported_contiguous(), 131073);
    assert_eq!(w.bytes_encoded(), 130972);
    let p = w.finish().unwrap();
    let sealed = recv.seal_finish(p.finish_record()).unwrap();
    assert_eq!(std::fs::read(&f.stage).unwrap(), f.data);
    assert!(sealed.snapshot().receipt().is_none());
    drop(sealed);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
    h.close().unwrap();
}
#[test]
fn zero_full_partial_and_large_prefix_window_finishes_only_after_logical_ack() {
    for (data, prefix) in [
        (vec![], 0),
        (b"abcdefgh".to_vec(), 0),
        (b"abcdefgh".to_vec(), 3),
        (b"abcdefgh".to_vec(), 8),
        (vec![9; 8 * 1024 * 1024], 65536),
    ] {
        let mut f = stopped(&data, prefix);
        setup!(f, h, r, w, recv, _base, false);
        w.observe_control(recv.resume_ready_record(2).unwrap())
            .unwrap();
        loop {
            match w.next_record().unwrap() {
                WindowRecord::Data { offset, ciphertext } => {
                    assert!(offset >= prefix as u64);
                    let frame = ciphertext.to_vec();
                    recv.write_record(&frame).unwrap();
                    w.observe_control(recv.resume_ack_record().unwrap())
                        .unwrap();
                }
                WindowRecord::Exhausted => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(w.bytes_encoded(), (data.len() - prefix) as u64);
        assert_eq!(w.bytes_peer_reported_contiguous(), data.len() as u64);
        let pending = w.finish().unwrap();
        #[cfg(windows)]
        let mut pending = pending;
        let sealed = recv.seal_finish(pending.finish_record()).unwrap();
        #[cfg(windows)]
        {
            let finished = sealed
                .prepare_commit()
                .unwrap()
                .attempt_local_publication()
                .unwrap()
                .record_target_observation()
                .unwrap()
                .settle_local()
                .unwrap();
            pending.observe_final(finished.local_commit_ack()).unwrap();
            assert_eq!(
                pending.peer_observation().unwrap().receipt(),
                finished.receipt()
            );
            assert_eq!(std::fs::read(&f.old.destination_path).unwrap(), data);
            assert_eq!(h.inventory().unwrap().recorded_usage(), (0, 0));
            drop(finished);
        }
        #[cfg(target_os = "linux")]
        {
            assert!(pending.peer_observation().is_none());
            assert_eq!(std::fs::read(&f.stage).unwrap(), data);
            assert!(!std::path::Path::new(&f.old.destination_path).exists());
            assert_eq!(
                h.inventory().unwrap().recorded_usage(),
                (data.len() as u64, 1)
            );
            drop(sealed);
        }
        assert_eq!(schema(&f.path), 13);
        assert_eq!(h.status().unwrap().in_flight, 0);
        h.close().unwrap();
    }
}
#[test]
fn same_new_grant_and_keys_but_two_valid_different_revision_proofs_refuse_ready() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, _base, true);
    let ready = recv.resume_ready_record(2).unwrap().to_vec();
    assert!(w.observe_control(&ready).is_err());
    assert!(w.is_faulted());
    assert_eq!(w.bytes_encoded(), 0);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    assert!(!std::path::Path::new(&f.old.destination_path).exists());
    drop(recv);
    h.close().unwrap();
}
#[test]
fn authenticated_wrong_digest_sha_or_prefix_closes_source_without_reading_suffix() {
    for field in 0..3 {
        let mut f = stopped(b"abcdefgh", 3);
        setup!(f, h, r, w, recv, base, false);
        let mut bad = base;
        match field {
            0 => bad.condition_digest[0] ^= 1,
            1 => bad.prefix_sha256[0] ^= 1,
            _ => bad.prefix_bytes += 1,
        }
        let frame = recv
            .test_seal_flow_control(ControlBody::ResumeReady(ResumeReady {
                base: bad,
                chunk_bytes: 65536,
                window_chunks: 2,
            }))
            .unwrap();
        assert!(w.observe_control(&frame).is_err());
        assert!(w.is_faulted());
        assert_eq!(w.bytes_encoded(), 0);
        assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
        drop(recv);
        h.close().unwrap();
    }
}
#[test]
fn legacy_ready_cannot_downgrade_restored_source_even_zero_prefix() {
    for prefix in [0, 3] {
        let mut f = stopped(b"abcdefgh", prefix);
        setup!(f, h, r, w, recv, _base, false);
        let old = recv
            .test_seal_flow_control(ControlBody::Ready(Ready {
                chunk_bytes: 65536,
                window_chunks: 2,
            }))
            .unwrap();
        assert!(w.observe_control(&old).is_err());
        assert!(w.is_faulted());
        assert_eq!(w.bytes_encoded(), 0);
        drop(recv);
        h.close().unwrap();
    }
}
#[test]
fn corrupt_aead_does_not_poison_valid_ready_but_second_authenticated_ready_does() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, base, false);
    let ready = recv.resume_ready_record(2).unwrap().to_vec();
    let mut broken = ready.clone();
    let last = broken.len() - 1;
    broken[last] ^= 1;
    assert!(w.observe_control(&broken).is_err());
    assert!(!w.is_faulted());
    w.observe_control(&ready).unwrap();
    let second = recv
        .test_seal_flow_control(ControlBody::ResumeReady(ResumeReady {
            base,
            chunk_bytes: 65536,
            window_chunks: 2,
        }))
        .unwrap();
    assert!(w.observe_control(&second).is_err());
    assert!(w.is_faulted());
    drop(recv);
    h.close().unwrap();
}
#[test]
fn selective_ack_does_not_free_original_ciphertext_and_logical_boundary_does() {
    let mut f = stopped(&vec![3; 131073], 3);
    setup!(f, h, r, w, recv, _base, false);
    w.observe_control(recv.resume_ready_record(2).unwrap())
        .unwrap();
    let (offset, a) = take(&mut w);
    let (_, b) = take(&mut w);
    let selective = recv
        .test_seal_flow_control(ControlBody::Ack(Ack {
            contiguous: 3,
            received: f.data.len() as u64,
        }))
        .unwrap();
    w.observe_control(&selective).unwrap();
    assert_eq!(w.pending_records(), 2);
    assert_eq!(w.retry_record(offset).unwrap(), a);
    recv.write_record(&a).unwrap();
    recv.write_record(&b).unwrap();
    w.observe_control(recv.resume_ack_record().unwrap())
        .unwrap();
    assert_eq!(w.pending_records(), 0);
    drop(recv);
    h.close().unwrap();
}
#[test]
fn ack_under_base_inside_chunk_or_beyond_logical_encoded_faults_without_releasing_debt() {
    for case in 0..3 {
        let mut f = stopped(&vec![3; 131073], 3);
        setup!(f, h, r, w, recv, _base, false);
        w.observe_control(recv.resume_ready_record(2).unwrap())
            .unwrap();
        let _ = take(&mut w);
        let (c, received) = match case {
            0 => (0, 0),
            1 => (4, 4),
            _ => (65540, 65540),
        };
        let ack = recv
            .test_seal_flow_control(ControlBody::Ack(Ack {
                contiguous: c,
                received,
            }))
            .unwrap();
        assert!(w.observe_control(&ack).is_err());
        assert!(w.is_faulted());
        assert_eq!(h.inventory().unwrap().recorded_usage(), (131073, 1));
        drop(recv);
        h.close().unwrap();
    }
}
#[test]
fn source_expiry_refuses_new_resume_ready_and_keeps_target_debt() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, _base, false);
    let ready = recv.resume_ready_record(2).unwrap().to_vec();
    w.test_expire();
    assert!(w.observe_control(&ready).is_err());
    assert!(w.is_faulted());
    assert_eq!(w.bytes_encoded(), 0);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn target_requires_resume_ready_before_resume_ack_and_never_falls_back() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, _base, false);
    assert!(recv.resume_ack_record().is_err());
    drop(w);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn fresh_target_cannot_emit_resume_control() {
    let (_t, path, r) = fixture();
    let h = r
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (_source, mut receiver) = open(&h, &path, b"abcdefgh");
    assert!(receiver.resume_ready_record(2).is_err());
    drop(receiver);
    h.close().unwrap();
}
#[test]
fn resume_ready_has_direction_liveness_and_strict_window_limits() {
    use crate::fleet::protocol::Kind;
    assert_eq!(Kind::try_from(14).unwrap(), Kind::ResumeReady);
    assert!(Kind::try_from(15).is_err());
    assert_eq!(Kind::ResumeReady.direction(), Direction::TargetToSource);
    assert!(Kind::ResumeReady.requires_live_grant());
    assert_eq!(
        std::mem::size_of::<Option<Box<ResumeBase>>>(),
        std::mem::size_of::<usize>()
    );
    for which in 0..4 {
        let mut f = stopped(b"abcdefgh", 3);
        setup!(f, h, r, w, recv, base, false);
        let mut rd = ResumeReady {
            base,
            chunk_bytes: 65536,
            window_chunks: 2,
        };
        match which {
            0 => rd.chunk_bytes = 1,
            1 => rd.window_chunks = 0,
            2 => rd.window_chunks = 9,
            _ => rd.base.prefix_bytes = 9,
        }
        assert!(
            recv.test_seal_flow_control(ControlBody::ResumeReady(rd))
                .is_err()
        );
        drop(w);
        drop(recv);
        h.close().unwrap();
    }
}

#[test]
fn wal_writer_allows_readonly_resume_ready_without_claiming_target_completion() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, _base, false);
    let writer = rusqlite::Connection::open(&f.path).unwrap();
    let mode: String = writer
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
    writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let start = std::time::Instant::now();
    let ready = recv.resume_ready_record(2).map(|v| v.to_vec());
    let elapsed = start.elapsed();
    writer.execute_batch("ROLLBACK").unwrap();
    let ready = ready.unwrap();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "readonly WAL admission elapsed {elapsed:?}"
    );
    w.observe_control(&ready).unwrap();
    assert_eq!(w.bytes_encoded(), 0);
    assert!(recv.snapshot().receipt().is_none());
    assert!(!std::path::Path::new(&f.old.destination_path).exists());
    drop(w);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn delete_journal_exclusive_writer_refuses_resume_ready_fast_and_restores_timeout() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, _base, false);
    let previous: i64 = {
        let mut guard = h.database.lock().unwrap();
        let db = guard.as_mut().unwrap();
        db.connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        db.connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap()
    };
    let writer = rusqlite::Connection::open(&f.path).unwrap();
    let mode: String = writer
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "delete");
    writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let start = std::time::Instant::now();
    let result = recv.resume_ready_record(2).map(|v| v.to_vec());
    let elapsed = start.elapsed();
    writer.execute_batch("ROLLBACK").unwrap();
    assert!(result.is_err());
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "nonwaiting SQL read elapsed {elapsed:?}"
    );
    {
        let guard = h.database.lock().unwrap();
        let db = guard.as_ref().unwrap();
        let after: i64 = db
            .connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(after, previous);
    }
    assert_eq!(w.bytes_encoded(), 0);
    drop(w);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn held_host_database_mutex_refuses_resume_ready_without_wait_or_releasing_debt() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, _base, false);
    let guard = h.database.lock().unwrap();
    let start = std::time::Instant::now();
    let result = recv.resume_ready_record(2).map(|v| v.to_vec());
    let elapsed = start.elapsed();
    drop(guard);
    assert!(result.is_err());
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "no-wait DB mutex elapsed {elapsed:?}"
    );
    assert_eq!(w.bytes_encoded(), 0);
    drop(w);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn source_runtime_shutdown_invalidates_idle_resume_window_not_target_obligation() {
    let mut f = stopped(b"abcdefgh", 3);
    setup!(f, h, r, w, recv, _base, false);
    let ready = recv.resume_ready_record(2).unwrap().to_vec();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(r.shutdown());
    assert!(w.observe_control(&ready).is_err());
    assert!(w.is_faulted());
    assert_eq!(w.bytes_encoded(), 0);
    drop(recv);
    assert_eq!(h.inventory().unwrap().recorded_usage(), (8, 1));
    h.close().unwrap();
}
#[test]
fn resume_ready_dto_rejects_unknown_fields_and_short_fixed_hashes() {
    let good = ResumeReady {
        base: ResumeBase {
            condition_digest: [3; 32],
            prefix_bytes: 0,
            prefix_sha256: [4; 32],
        },
        chunk_bytes: 65536,
        window_chunks: 2,
    };
    let value = serde_json::to_value(&good).unwrap();
    assert_eq!(
        serde_json::from_value::<ResumeReady>(value.clone()).unwrap(),
        good
    );
    let mut unknown = value.clone();
    unknown["grant"] = serde_json::json!("not authorized by a READY");
    assert!(serde_json::from_value::<ResumeReady>(unknown).is_err());
    let mut nested = value.clone();
    nested["base"]["path"] = serde_json::json!("not an IO capability");
    assert!(serde_json::from_value::<ResumeReady>(nested).is_err());
    let mut short = value;
    short["base"]["conditionDigest"] = serde_json::json!([1]);
    assert!(serde_json::from_value::<ResumeReady>(short).is_err());
}
