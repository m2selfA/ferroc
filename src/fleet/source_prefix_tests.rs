use super::*;
use crate::fleet::{journal::PrefixCheckpoint, resume_condition::ResumeProposal};
use serde_json::json;
pub(super) fn fixture(
    data: &[u8],
    prefix: u64,
) -> (
    tempfile::TempDir,
    crate::runtime::Runtime,
    LeasedRecords,
    LeasedRecords,
    ResumeProposal,
) {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("source.bin");
    std::fs::write(&path, data).unwrap();
    let mut offer = Offer::paths(
        data,
        0,
        path.to_str().unwrap().into(),
        t.path().join("target.bin").to_str().unwrap().into(),
    );
    offer.g = offer
        .g
        .grant()
        .clone()
        .validate_for_profile(
            offer.g.job().clone(),
            crate::fleet::job::LeaseProfile::SingleOwner,
        )
        .unwrap();
    let mut old = offer.g.job().clone();
    old.transfer_id = Uuid::from_u128(901);
    old.file_id = Uuid::from_u128(902);
    old.idempotency_key = "old-prefix-job".into();
    let mut old_b = offer.g.grant().binding.clone();
    old_b.transfer_id = old.transfer_id;
    old_b.file_id = old.file_id;
    old_b.source_session = Uuid::from_u128(903);
    old_b.target_session = Uuid::from_u128(904);
    old_b.authorization_id = Uuid::from_u128(905);
    old_b.key_epoch = Uuid::from_u128(906);
    let cp:PrefixCheckpoint=serde_json::from_value(json!({"version":1,"bytes":prefix,"sha256":<[u8;32]>::from(Sha256::digest(&data[..prefix as usize])),"job_digest":old.digest().unwrap(),"grant_digest":([9u8;32]),"binding":old_b,"revision":3})).unwrap();
    let proposal = ResumeProposal::build(&old, &cp, &offer.g).unwrap();
    let (s, p) = offer.pair();
    let r = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![t.path().to_path_buf()], false).unwrap(),
    );
    (t, r, s, p, proposal)
}
#[cfg(target_os = "linux")]
#[test]
fn finish_rejects_replaced_source_path_after_complete_read() {
    let (t, r, s, _peer, _p) = fixture(b"abcdefgh", 3);
    let mut source = r.open_fleet_source(s).unwrap();
    assert!(source.next_record().unwrap().is_some());
    std::fs::rename(t.path().join("source.bin"), t.path().join("original.bin")).unwrap();
    std::fs::write(t.path().join("source.bin"), b"XXXXXXXX").unwrap();
    assert!(
        source.finish().is_err(),
        "source finish accepted replaced pathname after complete original-FD read"
    );
    assert_eq!(
        std::fs::read(t.path().join("original.bin")).unwrap(),
        b"abcdefgh"
    );
    assert_eq!(
        std::fs::read(t.path().join("source.bin")).unwrap(),
        b"XXXXXXXX"
    );
}

#[test]
fn fresh_prefix_hash_leaves_actual_stream_and_encoded_count_at_zero() {
    let (_t, r, s, mut peer, p) = fixture(b"abcdefgh", 3);
    let mut source = r.open_fleet_source(s).unwrap();
    let observed = source.observe_resume_prefix(&p, 8).unwrap();
    assert_eq!(observed.bytes(), 3);
    assert_eq!(observed.sha256(), <[u8; 32]>::from(Sha256::digest(b"abc")));
    assert_eq!(observed.condition_digest(), p.digest());
    assert_eq!(source.bytes_encoded(), 0);
    match peer
        .open_record(&source.next_record().unwrap().unwrap())
        .unwrap()
    {
        PeerRecord::Data { header, bytes } => {
            assert_eq!(header.offset, 0);
            assert_eq!(bytes.as_slice(), b"abcdefgh")
        }
        _ => panic!("DATA expected"),
    };
    source.finish().unwrap();
}
#[test]
fn same_size_prefix_mutation_is_rejected_and_owner_cannot_continue() {
    let (t, r, s, _peer, p) = fixture(b"abcdefgh", 3);
    std::fs::write(t.path().join("source.bin"), b"xyzdefgh").unwrap();
    let mut source = r.open_fleet_source(s).unwrap();
    assert!(source.observe_resume_prefix(&p, 8).is_err());
    assert!(source.next_record().is_err());
}
#[test]
fn expiry_during_read_faults_original_source() {
    let (_t, r, s, _peer, p) = fixture(&vec![7; 131073], 131073);
    let mut source = r.open_fleet_source(s).unwrap();
    assert!(
        source
            .test_prefix_with(&p, 200000, |_, this| {
                this.test_expire();
                Ok(())
            })
            .is_err()
    );
    assert!(source.next_record().is_err());
}
#[test]
fn truncation_during_read_faults_and_returns_no_observation() {
    let (t, r, s, _peer, p) = fixture(&vec![7; 131073], 131073);
    let mut source = r.open_fleet_source(s).unwrap();
    assert!(
        source
            .test_prefix_with(&p, 200000, |_, _| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(t.path().join("source.bin"))?
                    .set_len(1)?;
                Ok(())
            })
            .is_err()
    );
    assert!(source.next_record().is_err());
}
#[test]
fn budget_and_prior_encoding_are_not_resume_initialization() {
    for prior in [false, true] {
        let (_t, r, s, _peer, p) = fixture(b"abcdefgh", 3);
        let mut source = r.open_fleet_source(s).unwrap();
        if prior {
            source.next_record().unwrap();
        }
        assert!(
            source
                .observe_resume_prefix(&p, if prior { 8 } else { 2 })
                .is_err()
        );
        assert!(source.next_record().is_err());
    }
}
#[test]
fn read_sequence_does_not_claim_external_prefix_stability() {
    use std::io::{Seek, SeekFrom, Write};
    let (t, r, s, _peer, p) = fixture(b"abcdefgh", 3);
    let mut source = r.open_fleet_source(s).unwrap();
    let observed = source
        .test_prefix_with(&p, 8, |_, _| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(t.path().join("source.bin"))?;
            f.seek(SeekFrom::Start(0))?;
            f.write_all(b"xyz")?;
            Ok(())
        })
        .unwrap();
    assert_eq!(observed.sha256(), <[u8; 32]>::from(Sha256::digest(b"abc")));
    assert_eq!(
        std::fs::read(t.path().join("source.bin")).unwrap(),
        b"xyzdefgh"
    );
}
