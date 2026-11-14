//! Control-v2 tests; child of the shared fixture module, not a network probe.
use super::super::{
    auth::PeerRecord,
    control::{
        Ack, Cancel, CancelReason, Cleanup, ControlBody, ControlMessage, Empty, ErrorCode, Finish,
        ParentDurability, Ready, Receipt, Status,
    },
    job::{AdmissionKind, IdempotencyLedger, MAX_JOBS, MAX_PATH_BYTES},
};
use super::*;
fn offer_for(spec: JobSpec) -> Offer {
    let mut o = Offer::new();
    o.grant = grant(spec);
    o.t = Transcript::for_grant(
        &o.grant,
        o.t.source_identity,
        o.t.target_identity,
        o.t.source_ephemeral,
        o.t.target_ephemeral,
    );
    o.resign();
    o
}
fn bodies(g: &ValidatedGrant) -> Vec<ControlBody> {
    vec![
        ControlBody::Prepare(Empty {}),
        ControlBody::Ready(Ready {
            chunk_bytes: g.grant().chunk_bytes,
            window_chunks: WINDOW as u8,
        }),
        ControlBody::Ack(Ack {
            contiguous: 0,
            received: 0,
        }),
        ControlBody::Finish(Finish {
            size: g.job().bytes_total,
            sha256: g.job().sha256,
        }),
        ControlBody::CommitAck(receipt(g)),
        ControlBody::Cancel(Cancel {
            reason: CancelReason::Operator,
        }),
        ControlBody::StatusRequest(Empty {}),
        ControlBody::Status(Status {
            phase: Phase::Preparing,
            bytes_received: 0,
            bytes_committed: 0,
            cleanup: Cleanup::NotRequired,
            receipt: None,
            error: None,
        }),
    ]
}
fn receipt(g: &ValidatedGrant) -> Receipt {
    Receipt {
        receipt_id: Uuid::from_bytes([9; 16]),
        size: g.job().bytes_total,
        sha256: g.job().sha256,
        parent_durability: ParentDurability::Unsupported,
    }
}
fn header(g: &ValidatedGrant, kind: Kind, len: usize) -> Header {
    Header {
        kind,
        direction: kind.direction(),
        binding: g.grant().binding.clone(),
        sequence: 0,
        offset: 0,
        plaintext_len: len as u32,
    }
}
fn encode(g: &ValidatedGrant, body: ControlBody) -> Vec<u8> {
    ControlMessage::new(g, body).unwrap().encode(g).unwrap()
}
fn parsed(g: &ValidatedGrant, kind: Kind, bytes: &[u8]) -> anyhow::Result<ControlMessage> {
    ControlMessage::decode(&header(g, kind, bytes.len()), bytes, g)
}
fn received(session: &mut AuthenticatedRecords, frame: &[u8], now: u64) -> ControlBody {
    match session.open_record(frame, now).unwrap() {
        PeerRecord::Control { message, .. } => message.body,
        _ => panic!("expected typed control"),
    }
}

#[test]
fn independent_node_canonical_job_grant_and_suite2_vectors() {
    let v: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/fleet-p0-control-vectors.json"
    ))
    .unwrap();
    let j = job();
    let g = grant(j.clone());
    assert_eq!(hex(&j.request_bytes().unwrap()), v["request_hex"]);
    assert_eq!(
        hex(&j.parameter_digest().unwrap()),
        v["parameter_digest_hex"]
    );
    assert_eq!(hex(&j.canonical_bytes().unwrap()), v["job_hex"]);
    assert_eq!(hex(&j.digest().unwrap()), v["job_digest_hex"]);
    assert_eq!(hex(&g.grant().canonical_bytes().unwrap()), v["grant_hex"]);
    assert_eq!(hex(&g.digest()), v["grant_digest_hex"]);
    assert_eq!(
        Offer::new()
            .t
            .bytes(Direction::SourceToTarget)
            .unwrap()
            .len(),
        420
    );
}
#[test]
fn every_semantic_request_dimension_changes_parameter_and_job_digests() {
    let baseline = job();
    let pd = baseline.parameter_digest().unwrap();
    let jd = baseline.digest().unwrap();
    for i in 0..9 {
        let mut j = baseline.clone();
        match i {
            0 => j.fleet_id = Uuid::new_v4(),
            1 => j.source_device[0] ^= 1,
            2 => j.target_device[0] ^= 1,
            3 => j.source_path.push('x'),
            4 => j.destination_path.push('x'),
            5 => j.bytes_total -= 1,
            6 => j.sha256[0] ^= 1,
            7 => j.deadline_ms += 1,
            _ => j.source_path = j.source_path.replace('α', "a"),
        }
        assert_ne!(j.parameter_digest().unwrap(), pd, "parameter dimension {i}");
        assert_ne!(j.digest().unwrap(), jd);
    }
    for i in 0..3 {
        let mut j = baseline.clone();
        match i {
            0 => j.transfer_id = Uuid::new_v4(),
            1 => j.file_id = Uuid::new_v4(),
            _ => j.idempotency_key.push('x'),
        }
        assert_eq!(j.parameter_digest().unwrap(), pd);
        assert_ne!(j.digest().unwrap(), jd);
    }
}
#[test]
fn job_validation_rejects_ambiguous_paths_sizes_flags_and_keys() {
    for p in [
        "relative",
        "C:relative",
        "C:\\a:stream",
        "//server/share/file",
        "\\\\?\\C:\\a",
        "/a/../b",
        "/a/./b",
        "/a//b",
        "/a/",
        "/",
        "/a/.FERROC-FLEET-temp",
        "/a/\0b",
        "/a/\nb",
    ] {
        let mut j = job();
        j.destination_path = p.into();
        assert!(j.validate().is_err(), "accepted {p:?}");
    }
    for p in ["C:\\safe\\file.bin", "/safe/α.bin"] {
        let mut j = job();
        j.source_path = p.into();
        j.validate().unwrap();
    }
    let mut j = job();
    j.source_path = format!("/{}", "a".repeat(MAX_PATH_BYTES));
    assert!(j.validate().is_err());
    for i in 0..8 {
        let mut j = job();
        match i {
            0 => j.version += 1,
            1 => j.transfer_id = Uuid::nil(),
            2 => j.bytes_total = MAX_FILE_BYTES + 1,
            3 => j.overwrite = true,
            4 => j.deadline_ms = 0,
            5 => j.idempotency_key.clear(),
            6 => j.idempotency_key = "x".repeat(129),
            _ => j.idempotency_key = "bad key".into(),
        };
        assert!(j.validate().is_err());
    }
}
#[test]
fn bounded_idempotency_retains_original_ids_and_checks_conflicts_before_capacity() {
    let mut ledger = IdempotencyLedger::new(1).unwrap();
    let j = job();
    assert!(ledger.is_empty());
    assert_eq!(
        ledger.admit(j.clone(), 200).unwrap().kind,
        AdmissionKind::Created
    );
    let mut retry = j.clone();
    retry.transfer_id = Uuid::new_v4();
    retry.file_id = Uuid::new_v4();
    let known = ledger.admit(retry, 9999).unwrap();
    assert_eq!(known.kind, AdmissionKind::Existing);
    assert_eq!(known.job, j);
    let mut changed = j.clone();
    changed.destination_path.push('x');
    assert!(
        ledger
            .admit(changed, 200)
            .err()
            .unwrap()
            .to_string()
            .contains("different parameters")
    );
    let mut distinct = j.clone();
    distinct.idempotency_key.push('2');
    assert!(
        ledger
            .admit(distinct, 200)
            .err()
            .unwrap()
            .to_string()
            .contains("ledger full")
    );
    assert_eq!(ledger.len(), 1);
    assert!(IdempotencyLedger::new(0).is_err());
    assert!(IdempotencyLedger::new(MAX_JOBS + 1).is_err());
    let mut empty = IdempotencyLedger::new(1).unwrap();
    assert!(empty.admit(j.clone(), j.deadline_ms).is_err());
    assert!(empty.is_empty());
}
#[test]
fn idempotency_all_changed_parameters_are_conflicts_not_new_work() {
    let j = job();
    let mut ledger = IdempotencyLedger::new(3).unwrap();
    ledger.admit(j.clone(), 200).unwrap();
    for i in 0..6 {
        let mut k = j.clone();
        match i {
            0 => k.source_path.push('x'),
            1 => k.destination_path.push('x'),
            2 => k.bytes_total += 1,
            3 => k.sha256[0] ^= 1,
            4 => k.deadline_ms += 1,
            _ => k.target_device[0] ^= 1,
        };
        assert!(ledger.admit(k, 201).is_err());
        assert_eq!(ledger.len(), 1);
    }
}
#[test]
fn grants_reject_wrong_job_binding_digest_and_lease() {
    let j = job();
    let original = grant(j.clone());
    for i in 0..9 {
        let mut g = original.grant().clone();
        match i {
            0 => g.binding.file_id = Uuid::new_v4(),
            1 => g.binding.source_device[0] ^= 1,
            2 => g.job_digest[0] ^= 1,
            3 => g.chunk_bytes = 0,
            4 => g.chunk_bytes = MAX_DATA as u32 + 1,
            5 => g.expires_at_ms = g.issued_at_ms,
            6 => g.expires_at_ms = g.issued_at_ms + MAX_LEASE_MS + 1,
            7 => g.expires_at_ms = j.deadline_ms + 1,
            _ => g.binding.authorization_id = Uuid::nil(),
        };
        assert!(
            g.validate_for(j.clone()).is_err(),
            "accepted grant mutation {i}"
        );
    }
}
#[test]
fn session_rotation_changes_grant_not_stable_job_identity() {
    let original = grant(job());
    let mut raw = original.grant().clone();
    raw.binding.source_session = Uuid::new_v4();
    raw.binding.target_session = Uuid::new_v4();
    raw.binding.key_epoch = Uuid::new_v4();
    raw.binding.authorization_id = Uuid::new_v4();
    let rotated = raw.validate_for(job()).unwrap();
    assert_eq!(
        rotated.job().digest().unwrap(),
        original.job().digest().unwrap()
    );
    assert_ne!(rotated.digest(), original.digest());
    let bytes = encode(&original, ControlBody::Prepare(Empty {}));
    assert!(parsed(&rotated, Kind::Prepare, &bytes).is_err());
}
#[test]
fn both_peer_signatures_cannot_replace_locally_expected_job_or_grant() {
    for digest in 0..2 {
        let mut o = Offer::new();
        if digest == 0 {
            o.t.job_digest[0] ^= 1;
        } else {
            o.t.grant_digest[0] ^= 1;
        }
        // Re-sign WITHOUT local grant re-approval: both signatures are genuine.
        o.a = IdentityKey::from_test_seed([0x11; 32])
            .sign(&o.t, Direction::SourceToTarget)
            .unwrap();
        o.b = IdentityKey::from_test_seed([0x22; 32])
            .sign(&o.t, Direction::TargetToSource)
            .unwrap();
        assert!(o.source_session(200).is_err());
    }
}
#[test]
fn legacy_suite1_signatures_are_rejected_without_downgrade() {
    let old = vector();
    let mut o = Offer::new();
    for (out, key) in [
        (&mut o.a, "source_signature_hex"),
        (&mut o.b, "target_signature_hex"),
    ] {
        let s = old[key].as_str().unwrap();
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    assert!(o.source_session(200).is_err());
}
#[test]
fn all_eight_control_bodies_roundtrip_and_reject_unknown_fields_at_each_level() {
    let g = grant(job());
    for body in bodies(&g) {
        let kind = body.kind();
        let bytes = encode(&g, body.clone());
        assert_eq!(parsed(&g, kind, &bytes).unwrap().body, body);
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        for level in 0..3 {
            let mut v = value.clone();
            let map = match level {
                0 => v.as_object_mut().unwrap(),
                1 => v["body"].as_object_mut().unwrap(),
                _ => v["body"]["payload"].as_object_mut().unwrap(),
            };
            map.insert("unexpected".into(), json!(true));
            assert!(
                parsed(&g, kind, &serde_json::to_vec(&v).unwrap()).is_err(),
                "unknown field level {level}"
            );
        }
    }
}
#[test]
fn control_rejects_wrong_version_digest_kind_duplicate_truncation_and_overflow() {
    let g = grant(job());
    let bytes = encode(&g, ControlBody::Prepare(Empty {}));
    for len in 0..bytes.len() {
        assert!(parsed(&g, Kind::Prepare, &bytes[..len]).is_err());
    }
    for field in ["version", "jobDigest", "grantDigest"] {
        let mut v: Value = serde_json::from_slice(&bytes).unwrap();
        if field == "version" {
            v[field] = json!(2)
        } else {
            v[field][0] = json!(255)
        }
        assert!(parsed(&g, Kind::Prepare, &serde_json::to_vec(&v).unwrap()).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(b'!');
    assert!(parsed(&g, Kind::Prepare, &extra).is_err());
    let duplicate = format!(
        "{{\"version\":1,{}",
        &String::from_utf8(bytes.clone()).unwrap()[1..]
    );
    assert!(parsed(&g, Kind::Prepare, duplicate.as_bytes()).is_err());
    assert!(parsed(&g, Kind::Cancel, &bytes).is_err());
    assert!(parsed(&g, Kind::Data, &bytes).is_err());
    assert!(parsed(&g, Kind::Prepare, &vec![b' '; MAX_CONTROL + 1]).is_err());
    let ack = encode(
        &g,
        ControlBody::Ack(Ack {
            contiguous: 0,
            received: 0,
        }),
    );
    let s = String::from_utf8(ack)
        .unwrap()
        .replace("\"received\":0", "\"received\":18446744073709551616");
    assert!(parsed(&g, Kind::Ack, s.as_bytes()).is_err());
}
#[test]
fn ready_ack_and_final_digest_limits_are_enforced() {
    let mut j = job();
    j.bytes_total = MAX_FILE_BYTES;
    let g = grant(j);
    for body in [
        ControlBody::Ready(Ready {
            chunk_bytes: 0,
            window_chunks: 1,
        }),
        ControlBody::Ready(Ready {
            chunk_bytes: MAX_DATA as u32,
            window_chunks: 0,
        }),
        ControlBody::Ready(Ready {
            chunk_bytes: MAX_DATA as u32,
            window_chunks: WINDOW as u8 + 1,
        }),
        ControlBody::Ack(Ack {
            contiguous: 1,
            received: 0,
        }),
        ControlBody::Ack(Ack {
            contiguous: 0,
            received: (MAX_DATA * WINDOW) as u64 + 1,
        }),
        ControlBody::Ack(Ack {
            contiguous: 0,
            received: MAX_FILE_BYTES + 1,
        }),
        ControlBody::Finish(Finish {
            size: 0,
            sha256: g.job().sha256,
        }),
    ] {
        assert!(ControlMessage::new(&g, body).is_err());
    }
    let mut r = receipt(&g);
    r.sha256[0] ^= 1;
    assert!(ControlMessage::new(&g, ControlBody::CommitAck(r)).is_err());
    let mut r = receipt(&g);
    r.receipt_id = Uuid::nil();
    assert!(ControlMessage::new(&g, ControlBody::CommitAck(r)).is_err());
}
#[test]
fn status_never_confuses_received_committed_uncertain_and_cancelled() {
    let g = grant(job());
    let total = g.job().bytes_total;
    let complete = Status {
        phase: Phase::Completed,
        bytes_received: total,
        bytes_committed: total,
        cleanup: Cleanup::NotRequired,
        receipt: Some(receipt(&g)),
        error: None,
    };
    ControlMessage::new(&g, ControlBody::Status(complete.clone())).unwrap();
    for i in 0..7 {
        let mut s = complete.clone();
        match i {
            0 => s.receipt = None,
            1 => s.bytes_received -= 1,
            2 => s.bytes_committed -= 1,
            3 => s.cleanup = Cleanup::Retained,
            4 => s.error = Some(ErrorCode::Io),
            5 => s.receipt.as_mut().unwrap().sha256[0] ^= 1,
            _ => s.phase = Phase::CommitUnknown,
        };
        assert!(ControlMessage::new(&g, ControlBody::Status(s)).is_err());
    }
    for cleanup in [Cleanup::NotRequired, Cleanup::Pending, Cleanup::Retained] {
        let s = Status {
            phase: Phase::Cancelled,
            bytes_received: 0,
            bytes_committed: 0,
            cleanup,
            receipt: None,
            error: None,
        };
        assert!(ControlMessage::new(&g, ControlBody::Status(s)).is_err());
    }
    let s = Status {
        phase: Phase::CommitUnknown,
        bytes_received: total,
        bytes_committed: 0,
        cleanup: Cleanup::Retained,
        receipt: None,
        error: Some(ErrorCode::CommitUncertain),
    };
    ControlMessage::new(&g, ControlBody::Status(s)).unwrap();
}
#[test]
fn authenticated_invalid_control_faults_session_instead_of_becoming_duplicate() {
    let (mut a, mut b) = Offer::new().sessions();
    let bad = a.seal(Kind::Prepare, 0, b"{}", 201).unwrap();
    assert!(b.open_record(&bad, 201).is_err());
    assert!(b.open_record(&bad, 202).is_err());
    let good = a.seal_control(ControlBody::Prepare(Empty {}), 203).unwrap();
    assert!(b.open_record(&good, 203).is_err());
}
#[test]
fn unauthenticated_control_corruption_does_not_poison_semantic_validation() {
    let (mut a, mut b) = Offer::new().sessions();
    let good = a.seal_control(ControlBody::Prepare(Empty {}), 201).unwrap();
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(b.open_record(&bad, 201).is_err());
    assert!(matches!(
        b.open_record(&good, 202).unwrap(),
        PeerRecord::Control { .. }
    ));
    assert!(matches!(
        b.open_record(&good, 203).unwrap(),
        PeerRecord::Duplicate { .. }
    ));
}
#[test]
fn typed_lease_expiry_blocks_effects_but_allows_cancel_and_receipt_settlement() {
    let g = grant(job());
    let (mut a, mut b) = Offer::new().sessions();
    assert!(
        a.seal_control(ControlBody::Prepare(Empty {}), 1000)
            .is_err()
    );
    assert!(a.seal_data(0, b"a", 1000).is_err());
    let cancel = a
        .seal_control(
            ControlBody::Cancel(Cancel {
                reason: CancelReason::DeadlineExpired,
            }),
            1001,
        )
        .unwrap();
    assert!(matches!(
        received(&mut b, &cancel, 1001),
        ControlBody::Cancel(_)
    ));
    let commit = b
        .seal_control(ControlBody::CommitAck(receipt(&g)), 1002)
        .unwrap();
    assert!(matches!(
        received(&mut a, &commit, 1002),
        ControlBody::CommitAck(_)
    ));
    assert!(
        a.seal_control(ControlBody::StatusRequest(Empty {}), 999)
            .is_err()
    );
}
#[test]
fn typed_peer_records_and_real_local_stage_roundtrip_not_network_or_journal() {
    for size in [0, 3, MAX_DATA + 1] {
        let root = tempfile::tempdir().unwrap();
        let bytes = vec![0x5a; size];
        let mut spec = job();
        spec.bytes_total = size as u64;
        spec.sha256 = sha(&bytes);
        spec.source_path = root.path().join("source.bin").to_str().unwrap().into();
        spec.destination_path = root.path().join("target.bin").to_str().unwrap().into();
        let o = offer_for(spec);
        let g = o.grant.clone();
        let (mut a, mut b) = o.sessions();
        let frame = a.seal_control(ControlBody::Prepare(Empty {}), 201).unwrap();
        assert!(matches!(
            received(&mut b, &frame, 201),
            ControlBody::Prepare(_)
        ));
        let budget = StageBudget::new((MAX_DATA + 1) as u64, 1).unwrap();
        let mut stage = StageFile::prepare(
            policy(&root),
            &g.job().destination_path,
            size as u64,
            &budget,
            Arc::new(Mutex::new(())),
        )
        .unwrap();
        let frame = b
            .seal_control(
                ControlBody::Ready(Ready {
                    chunk_bytes: g.grant().chunk_bytes,
                    window_chunks: WINDOW as u8,
                }),
                202,
            )
            .unwrap();
        assert!(matches!(
            received(&mut a, &frame, 202),
            ControlBody::Ready(_)
        ));
        for (i, data) in bytes.chunks(MAX_DATA).enumerate() {
            let frame = a.seal_data((i * MAX_DATA) as u64, data, 203).unwrap();
            match b.open_record(&frame, 203).unwrap() {
                PeerRecord::Data { header, bytes } => {
                    let admission = stage.write_chunk(header.offset, &bytes).unwrap();
                    assert!(matches!(admission, Admission::New));
                }
                _ => panic!("expected DATA"),
            }
        }
        let ack = b
            .seal_control(
                ControlBody::Ack(Ack {
                    contiguous: size as u64,
                    received: size as u64,
                }),
                204,
            )
            .unwrap();
        assert!(matches!(received(&mut a, &ack, 204), ControlBody::Ack(_)));
        assert!(!root.path().join("target.bin").exists());
        let finish = a
            .seal_control(
                ControlBody::Finish(Finish {
                    size: size as u64,
                    sha256: g.job().sha256,
                }),
                205,
            )
            .unwrap();
        assert!(matches!(
            received(&mut b, &finish, 205),
            ControlBody::Finish(_)
        ));
        let publication = stage.publish(g.job().sha256).unwrap();
        let parent = match publication {
            Publication::Published { parent_sync, .. } => match parent_sync {
                ParentSync::Synced => ParentDurability::Synced,
                ParentSync::Unsupported => ParentDurability::Unsupported,
            },
            _ => panic!("unexpected publication uncertainty"),
        };
        // Fixture receipt, NOT durably journaled: this is not a service ACK.
        let mut r = receipt(&g);
        r.parent_durability = parent;
        let commit = b.seal_control(ControlBody::CommitAck(r), 206).unwrap();
        assert!(matches!(
            received(&mut a, &commit, 206),
            ControlBody::CommitAck(_)
        ));
        assert_eq!(fs::read(root.path().join("target.bin")).unwrap(), bytes);
        assert_eq!(budget.usage().unwrap(), (0, 0));
        assert_eq!(stage_links(&root), 0);
    }
}
