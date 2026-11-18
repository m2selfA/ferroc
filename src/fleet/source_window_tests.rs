use super::*;
#[test]
fn fresh_window_refuses_authenticated_resume_ready_even_zero_base() {
    use sha2::Digest;
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.bin");
    let target = temp.path().join("target.bin");
    std::fs::write(&source, b"abc").unwrap();
    let mut o = Offer::paths(
        b"abc",
        0,
        source.to_str().unwrap().to_owned(),
        target.to_str().unwrap().to_owned(),
    );
    o.g =
        o.g.grant()
            .clone()
            .validate_for_profile(
                o.g.job().clone(),
                crate::fleet::job::LeaseProfile::SingleOwner,
            )
            .unwrap();
    let (s, mut p) = pair300(o);
    let r = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![temp.path().to_path_buf()], false).unwrap(),
    );
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 2).unwrap();
    let frame = p
        .seal_control(ControlBody::ResumeReady(
            crate::fleet::control::ResumeReady {
                base: crate::fleet::control::ResumeBase {
                    condition_digest: [1; 32],
                    prefix_bytes: 0,
                    prefix_sha256: sha2::Sha256::digest([]).into(),
                },
                chunk_bytes: 65536,
                window_chunks: 2,
            },
        ))
        .unwrap();
    assert!(w.observe_control(&frame).is_err());
    assert!(w.is_faulted());
    assert_eq!(w.bytes_encoded(), 0);
}
#[test]
fn explicit_resume_window_never_promotes_fresh_source_to_resume_mode() {
    let (_t, r, s, _p) = file_source_fixture(b"abc");
    assert!(SourceWindow::resuming(r.open_fleet_source(s).unwrap(), 2).is_err());
}

#[path = "source_renewal_tests.rs"]
mod renewal_tests;
use crate::fleet::{
    control::Ready,
    ranges::WINDOW,
    source_window::{ProgressOutcome, SourceWindow, WindowRecord},
};
fn ready(peer: &mut LeasedRecords, window: u8) -> Vec<u8> {
    peer.seal_control(ControlBody::Ready(Ready {
        chunk_bytes: 65536,
        window_chunks: window,
    }))
    .unwrap()
}
fn ack(peer: &mut LeasedRecords, c: u64, r: u64) -> Vec<u8> {
    peer.seal_control(ControlBody::Ack(Ack {
        contiguous: c,
        received: r,
    }))
    .unwrap()
}
// Wider skew window so a later public renew(now) sees the successor as
// certainly live. PUBLIC TEST issuance; not an operational enrollment path.
fn pair300(o: Offer) -> (LeasedRecords, LeasedRecords) {
    let sample = ClockSample::now();
    let anchor = || TrustedTimeAnchor::approved_window(sample, 300, 300).unwrap();
    let s =
        o.s.authenticate_leased(
            &o.t,
            Direction::SourceToTarget,
            &o.g,
            &o.sp,
            &o.tp,
            &o.a,
            &o.b,
            anchor(),
        )
        .unwrap();
    let p =
        o.r.authenticate_leased(
            &o.t,
            Direction::TargetToSource,
            &o.g,
            &o.sp,
            &o.tp,
            &o.a,
            &o.b,
            anchor(),
        )
        .unwrap();
    (s, p)
}
fn renewable_fixture(
    data: &[u8],
) -> (
    tempfile::TempDir,
    crate::runtime::Runtime,
    LeasedRecords,
    LeasedRecords,
    String,
    String,
) {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("source.bin");
    std::fs::write(&path, data).unwrap();
    let source = path.to_str().unwrap().to_string();
    let destination = t.path().join("dest.bin").to_str().unwrap().to_string();
    let (s, p) = pair300(Offer::paths(data, 0, source.clone(), destination.clone()));
    let runtime = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![t.path().to_path_buf()], false).unwrap(),
    );
    (t, runtime, s, p, source, destination)
}
fn take(s: &mut SourceWindow<'_>) -> (u64, Vec<u8>) {
    match s.next_record().unwrap() {
        WindowRecord::Data { offset, ciphertext } => (offset, ciphertext.to_vec()),
        x => panic!("DATA expected: {x:?}"),
    }
}
#[test]
fn waits_ready_then_bounded_window_and_exact_retries() {
    let data = vec![0x71; 3 * 65536];
    let (_t, r, s, mut p) = file_source_fixture(&data);
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 2).unwrap();
    assert_eq!(w.next_record().unwrap(), WindowRecord::WaitingForReady);
    assert_eq!(w.bytes_encoded(), 0);
    let rd = ready(&mut p, 8);
    assert_eq!(w.observe_control(&rd).unwrap(), ProgressOutcome::Ready);
    assert_eq!(w.observe_control(&rd).unwrap(), ProgressOutcome::Duplicate);
    let (o, a) = take(&mut w);
    let (_, b) = take(&mut w);
    assert_eq!(o, 0);
    assert_eq!(w.pending_records(), 2);
    assert_eq!(w.pending_ciphertext_bytes(), 2 * (65536 + 232));
    assert!(w.pending_ciphertext_bytes() <= w.ciphertext_capacity_bytes());
    assert_eq!(w.next_record().unwrap(), WindowRecord::Backpressured);
    assert_eq!(w.bytes_encoded(), 131072);
    assert_eq!(w.retry_record(0).unwrap(), a);
    p.open_record(&a).unwrap();
    p.open_record(&b).unwrap();
    w.observe_control(&ack(&mut p, 65536, 65536)).unwrap();
    assert_eq!(w.pending_records(), 1);
    assert!(w.retry_record(0).is_err());
    let (offset, c) = take(&mut w);
    assert_eq!(offset, 131072);
    p.open_record(&c).unwrap();
    w.observe_control(&ack(&mut p, data.len() as u64, data.len() as u64))
        .unwrap();
    assert_eq!(w.pending_records(), 0);
    assert_eq!(w.next_record().unwrap(), WindowRecord::Exhausted);
    let mut end = w.finish().unwrap();
    p.open_record(end.finish_record()).unwrap();
    assert_eq!(end.status(), SourceCommitStatus::AwaitingAck);
    let f = p
        .seal_control(ControlBody::CommitAck(receipt(&data)))
        .unwrap();
    assert_eq!(end.observe_final(&f).unwrap(), FinalAckOutcome::Accepted);
}
#[test]
fn maximum_chunk_real_file_keeps_eight_original_ciphertexts_within_exact_capacity() {
    let chunk = crate::fleet::protocol::MAX_DATA;
    let data = vec![0x71; 8 * chunk + 1];
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source.bin");
    std::fs::write(&source, &data).unwrap();
    let offer = Offer::paths_with_chunk(
        &data,
        0,
        source.to_str().unwrap().into(),
        temp.path().join("dest.bin").to_str().unwrap().into(),
        chunk as u32,
    );
    let (s, mut peer) = pair300(offer);
    let runtime = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![temp.path().to_owned()], false).unwrap(),
    );
    let mut window = SourceWindow::new(runtime.open_fleet_source(s).unwrap(), 8).unwrap();
    assert_eq!(window.next_record().unwrap(), WindowRecord::WaitingForReady);
    let rd = peer
        .seal_control(ControlBody::Ready(Ready {
            chunk_bytes: chunk as u32,
            window_chunks: 8,
        }))
        .unwrap();
    window.observe_control(&rd).unwrap();
    for index in 0..8 {
        let (offset, ciphertext) = take(&mut window);
        assert_eq!(offset, (index * chunk) as u64);
        assert_eq!(ciphertext.len(), chunk + 232);
        match peer.open_record(&ciphertext).unwrap() {
            PeerRecord::Data { header, bytes } => {
                assert_eq!(header.offset, offset);
                assert_eq!(bytes.len(), chunk);
                assert!(bytes.iter().all(|byte| *byte == 0x71));
            }
            _ => panic!("DATA expected"),
        }
    }
    assert_eq!(window.pending_records(), 8);
    assert_eq!(window.pending_ciphertext_bytes(), 8 * (chunk + 232));
    assert_eq!(
        window.pending_ciphertext_bytes(),
        window.ciphertext_capacity_bytes()
    );
    assert_eq!(window.next_record().unwrap(), WindowRecord::Backpressured);
    assert_eq!(window.bytes_encoded(), (8 * chunk) as u64);
    let retry = window.retry_record(0).unwrap().to_vec();
    assert_eq!(window.retry_record(0).unwrap(), retry);
    window
        .observe_control(&ack(&mut peer, (8 * chunk) as u64, (8 * chunk) as u64))
        .unwrap();
    assert_eq!(window.pending_records(), 0);
    let (_, tail) = take(&mut window);
    peer.open_record(&tail).unwrap();
    window
        .observe_control(&ack(&mut peer, data.len() as u64, data.len() as u64))
        .unwrap();
    assert_eq!(window.next_record().unwrap(), WindowRecord::Exhausted);
    let mut end = window.finish().unwrap();
    peer.open_record(end.finish_record()).unwrap();
    let final_ack = peer
        .seal_control(ControlBody::CommitAck(receipt(&data)))
        .unwrap();
    assert_eq!(
        end.observe_final(&final_ack).unwrap(),
        FinalAckOutcome::Accepted
    );
}

#[test]
fn remote_smaller_window_wins() {
    let (_t, r, s, mut p) = file_source_fixture(&vec![2; 131072]);
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 8).unwrap();
    w.observe_control(&ready(&mut p, 1)).unwrap();
    take(&mut w);
    assert_eq!(w.next_record().unwrap(), WindowRecord::Backpressured);
}
#[test]
fn no_selective_credit_or_status_completed_shortcut() {
    let data = vec![1; 131072];
    let (_t, r, s, mut p) = file_source_fixture(&data);
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    w.observe_control(&ready(&mut p, 1)).unwrap();
    take(&mut w);
    w.observe_control(&ack(&mut p, 0, 65536)).unwrap();
    assert_eq!(w.next_record().unwrap(), WindowRecord::Backpressured);
    assert_eq!(w.pending_records(), 1);
    let f = p
        .seal_control(ControlBody::Status(Status {
            phase: Phase::Completed,
            bytes_received: 131072,
            bytes_committed: 131072,
            cleanup: Cleanup::Confirmed,
            receipt: Some(receipt(&data)),
            error: None,
        }))
        .unwrap();
    assert_eq!(w.observe_control(&f).unwrap(), ProgressOutcome::Status);
    assert_eq!(w.pending_records(), 1);
    assert!(w.finish().is_err());
}
#[test]
fn ack_before_ready_faults_and_closes_file() {
    let (t, r, s, mut p) = file_source_fixture(b"abc");
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 2).unwrap();
    assert!(w.observe_control(&ack(&mut p, 0, 0)).is_err());
    assert!(w.is_faulted());
    assert!(w.next_record().is_err());
    std::fs::rename(t.path().join("source.bin"), t.path().join("closed.bin")).unwrap();
}
#[test]
fn midchunk_and_beyond_encoded_ack_fail_closed() {
    for (c, n) in [(1, 1), (65537, 65537)] {
        let (_t, r, s, mut p) = file_source_fixture(&vec![1; 131072]);
        let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 2).unwrap();
        w.observe_control(&ready(&mut p, 2)).unwrap();
        take(&mut w);
        assert!(w.observe_control(&ack(&mut p, c, n)).is_err());
        assert!(w.is_faulted());
        assert_eq!(w.pending_records(), 0);
    }
}
#[test]
fn stale_ack_reordering_does_not_rewind_but_fresh_regression_faults() {
    let (_t, r, s, mut p) = file_source_fixture(&vec![1; 131072]);
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 2).unwrap();
    w.observe_control(&ready(&mut p, 2)).unwrap();
    take(&mut w);
    take(&mut w);
    let old = ack(&mut p, 65536, 65536);
    let new = ack(&mut p, 131072, 131072);
    w.observe_control(&new).unwrap();
    assert_eq!(w.observe_control(&old).unwrap(), ProgressOutcome::Stale);
    assert_eq!(w.bytes_peer_reported_contiguous(), 131072);
    assert!(w.observe_control(&ack(&mut p, 65536, 65536)).is_err());
    assert!(w.is_faulted());
}
#[test]
fn tampered_control_does_not_release_or_poison_then_valid_succeeds() {
    let (_t, r, s, mut p) = file_source_fixture(b"abc");
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    let f = ready(&mut p, 1);
    let mut bad = f.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(w.observe_control(&bad).is_err());
    assert!(!w.is_faulted());
    assert_eq!(w.bytes_encoded(), 0);
    w.observe_control(&f).unwrap();
    take(&mut w);
    let f = ack(&mut p, 3, 3);
    let mut bad = f.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(w.observe_control(&bad).is_err());
    assert_eq!(w.pending_records(), 1);
    w.observe_control(&f).unwrap();
    assert_eq!(w.pending_records(), 0);
}
#[test]
fn fresh_second_ready_and_early_commit_ack_are_not_progress() {
    for final_ack in [false, true] {
        let (_t, r, s, mut p) = file_source_fixture(b"abc");
        let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 2).unwrap();
        w.observe_control(&ready(&mut p, 2)).unwrap();
        let f = if final_ack {
            p.seal_control(ControlBody::CommitAck(receipt(b"abc")))
                .unwrap()
        } else {
            ready(&mut p, 2)
        };
        assert!(w.observe_control(&f).is_err());
        assert!(w.is_faulted());
    }
}
#[test]
fn empty_requires_ready_and_then_separate_final_ack() {
    let (_t, r, s, mut p) = file_source_fixture(b"");
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    assert_eq!(w.next_record().unwrap(), WindowRecord::WaitingForReady);
    w.observe_control(&ready(&mut p, 1)).unwrap();
    assert_eq!(w.next_record().unwrap(), WindowRecord::Exhausted);
    let end = w.finish().unwrap();
    assert_eq!(end.status(), SourceCommitStatus::AwaitingAck);
}
#[test]
fn full_window_cannot_finish_without_contiguous_ack() {
    let (_t, r, s, mut p) = file_source_fixture(b"abc");
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    w.observe_control(&ready(&mut p, 1)).unwrap();
    take(&mut w);
    assert!(w.finish().is_err());
}
#[test]
fn used_source_and_invalid_window_rejected() {
    for n in [0, WINDOW as u8 + 1] {
        let (_t, r, s, _p) = file_source_fixture(b"abc");
        assert!(SourceWindow::new(r.open_fleet_source(s).unwrap(), n).is_err());
    }
    let (_t, r, s, _p) = file_source_fixture(b"abc");
    let mut f = r.open_fleet_source(s).unwrap();
    f.next_record().unwrap();
    assert!(SourceWindow::new(f, 1).is_err());
}
#[test]
fn revoke_and_runtime_shutdown_deny_waiting_or_retry() {
    let (_t, r, s, mut p) = file_source_fixture(b"abc");
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    w.observe_control(&ready(&mut p, 1)).unwrap();
    take(&mut w);
    w.revoke();
    assert!(w.retry_record(0).is_err());
    assert_eq!(w.pending_records(), 0);
    let (_t, r, s, _p) = file_source_fixture(b"abc");
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(r.shutdown());
    assert!(w.next_record().is_err());
    assert!(w.is_faulted());
}
#[test]
fn changed_source_fails_even_while_window_full() {
    let (t, r, s, mut p) = file_source_fixture(&vec![1; 131072]);
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    w.observe_control(&ready(&mut p, 1)).unwrap();
    take(&mut w);
    std::fs::OpenOptions::new()
        .write(true)
        .open(t.path().join("source.bin"))
        .unwrap()
        .set_len(1)
        .unwrap();
    assert!(w.next_record().is_err());
    assert!(w.is_faulted());
}
#[test]
fn flow_expiry_while_waiting_or_full_denies_data_control_and_retry() {
    for full in [false, true] {
        let (_t, r, s, mut p) = file_source_fixture(b"abc");
        let mut file = r.open_fleet_source(s).unwrap();
        if !full {
            file.test_expire();
        }
        if !full {
            assert!(SourceWindow::new(file, 1).is_err());
            continue;
        }
        let mut w = SourceWindow::new(file, 1).unwrap();
        w.observe_control(&ready(&mut p, 1)).unwrap();
        take(&mut w);
        // Test-only fence is private to this source component, never a bare-time API.
        w.test_expire();
        assert!(w.observe_control(&ack(&mut p, 3, 3)).is_err());
        assert!(w.retry_record(0).is_err());
        assert_eq!(w.pending_records(), 0);
    }
}
#[test]
fn flow_wrong_key_control_cannot_unlock_ready() {
    let (_t, r, s, _p) = file_source_fixture(b"abc");
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 1).unwrap();
    let (_other, mut wrong) = Offer::new(b"abc", 0).pair();
    assert!(w.observe_control(&ready(&mut wrong, 1)).is_err());
    assert!(!w.is_faulted());
    assert_eq!(w.next_record().unwrap(), WindowRecord::WaitingForReady);
}
#[cfg(windows)]
fn native_window(data: &[u8], out_of_order: bool) {
    use crate::{
        config::Policy,
        fleet::{
            identity::{make_directory, new_private},
            inventory::InventoryLimits,
        },
        runtime::Runtime,
    };
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("private");
    make_directory(&root).unwrap();
    let db = root.join("relay.db");
    drop(new_private(&db).unwrap());
    let src = root.join("source.bin");
    std::fs::write(&src, data).unwrap();
    let rt = Runtime::new(Policy::new(vec![root.clone()], false).unwrap());
    let host = rt.open_fleet_host(&db, InventoryLimits::default()).unwrap();
    host.resume().unwrap();
    let (s, p) = Offer::paths(
        data,
        0,
        src.to_str().unwrap().into(),
        root.join("target.bin").to_str().unwrap().into(),
    )
    .pair();
    let mut w = SourceWindow::new(rt.open_fleet_source(s).unwrap(), 2).unwrap();
    let mut target = host.admit_receiver(p).unwrap();
    let rd = target.ready_record(2).unwrap().to_vec();
    assert_eq!(target.ready_record(2).unwrap(), rd);
    w.observe_control(&rd).unwrap();
    let mut max_pending = 0;
    let start = Instant::now();
    loop {
        let mut frames = Vec::new();
        loop {
            match w.next_record().unwrap() {
                WindowRecord::Data { offset, ciphertext } => {
                    frames.push((offset, ciphertext.to_vec()))
                }
                WindowRecord::Backpressured | WindowRecord::Exhausted => break,
                x => panic!("{x:?}"),
            }
        }
        if frames.is_empty() {
            break;
        }
        max_pending = max_pending.max(w.pending_records());
        if out_of_order {
            frames.reverse();
        }
        for (_, f) in frames {
            target.write_record(&f).unwrap();
            let a = target.ack_record().unwrap().to_vec();
            assert_eq!(target.ack_record().unwrap(), a);
            w.observe_control(&a).unwrap();
        }
    }
    let mut end = w.finish().unwrap();
    assert_eq!(end.status(), SourceCommitStatus::AwaitingAck);
    let target = target
        .seal_finish(end.finish_record())
        .unwrap()
        .prepare_commit()
        .unwrap()
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    assert_eq!(
        end.observe_final(target.local_commit_ack()).unwrap(),
        FinalAckOutcome::Accepted
    );
    assert_eq!(std::fs::read(root.join("target.bin")).unwrap(), data);
    println!(
        "WINDOW_NATIVE bytes={} max_pending={} window=2 elapsed_ms={} localSourceFile+HostV9+ACK/notNetwork",
        data.len(),
        max_pending,
        start.elapsed().as_millis()
    );
    drop(target);
    host.close().unwrap();
}
#[cfg(windows)]
#[test]
fn native_window_zero_one_cross_chunk_and_out_of_order() {
    for d in [vec![], vec![2], vec![3; 131073]] {
        native_window(&d, true);
    }
}
#[cfg(windows)]
#[test]
fn native_window_eight_mib_true_target_and_final_ack() {
    native_window(&vec![0x39; 8 * 1024 * 1024], false);
}

#[test]
#[ignore = "release-only real128MiB source/window/peer records, not network or Host128MiB settlement"]
fn flow_window_128_mib_bounded_stream() {
    use std::io::Write;
    let (t, r, _old_s, _old_p) = file_source_fixture(b"");
    let path = t.path().join("source.bin");
    let chunk = vec![0x5a; 65536];
    let size = 128 * 1024 * 1024u64;
    let mut file = std::fs::File::create(&path).unwrap();
    let mut hash = Sha256::new();
    for _ in 0..size / 65536 {
        file.write_all(&chunk).unwrap();
        hash.update(&chunk);
    }
    file.sync_all().unwrap();
    drop(file);
    let digest: [u8; 32] = hash.finalize().into();
    let mut o = Offer::paths(
        b"",
        0,
        path.to_str().unwrap().into(),
        t.path().join("target.bin").to_str().unwrap().into(),
    );
    let mut job = o.g.job().clone();
    job.bytes_total = size;
    job.sha256 = digest;
    let mut grant = o.g.grant().clone();
    grant.job_digest = job.digest().unwrap();
    o.g = grant.validate_for(job).unwrap();
    let sk = IdentityKey::from_test_seed([0x11; 32]);
    let tk = IdentityKey::from_test_seed([0x22; 32]);
    o.t = Transcript::for_grant(&o.g, sk.public(), tk.public(), o.s.public(), o.r.public());
    o.a = sk.sign(&o.t, Direction::SourceToTarget).unwrap();
    o.b = tk.sign(&o.t, Direction::TargetToSource).unwrap();
    let (s, mut peer) = o.pair();
    let mut w = SourceWindow::new(r.open_fleet_source(s).unwrap(), 8).unwrap();
    w.observe_control(&ready(&mut peer, 8)).unwrap();
    let start = std::time::Instant::now();
    let mut received = 0u64;
    let mut hash = Sha256::new();
    let mut records = 0usize;
    let mut peak = 0usize;
    loop {
        for _ in 0..8 {
            match w.next_record().unwrap() {
                WindowRecord::Data { offset, ciphertext } => {
                    assert_eq!(offset, received);
                    match peer.open_record(ciphertext).unwrap() {
                        PeerRecord::Data { bytes, .. } => {
                            received += bytes.len() as u64;
                            hash.update(&bytes);
                        }
                        _ => panic!("DATA expected"),
                    };
                    records += 1;
                }
                WindowRecord::Exhausted => break,
                x => panic!("unexpected {x:?}"),
            }
        }
        peak = peak.max(w.pending_ciphertext_bytes());
        assert!(peak <= 8 * (65536 + 232));
        if w.pending_records() == 0 {
            break;
        }
        assert_eq!(w.next_record().unwrap(), WindowRecord::Backpressured);
        w.observe_control(&ack(&mut peer, received, received))
            .unwrap();
    }
    assert_eq!(received, size);
    assert_eq!(<[u8; 32]>::from(hash.finalize()), digest);
    assert_eq!(records, 2048);
    assert_eq!(peak, 526144);
    let mut end = w.finish().unwrap();
    peer.open_record(end.finish_record()).unwrap();
    let final_ack = peer
        .seal_control(ControlBody::CommitAck(Receipt {
            receipt_id: Uuid::new_v4(),
            size,
            sha256: digest,
            parent_durability: ParentDurability::Unsupported,
        }))
        .unwrap();
    assert_eq!(
        end.observe_final(&final_ack).unwrap(),
        FinalAckOutcome::Accepted
    );
    println!(
        "WINDOW_SCALE bytes={size} records={records} max_pending=8 max_ciphertext_bytes={peak} elapsed_ms={} realFile+authenticatedFlow/notNetwork/notHost128MiB",
        start.elapsed().as_millis()
    );
}
