//! These are real fenced SQLite METADATA tests, not resumed writer/IO claims.
#[test]
#[ignore = "explicit archived schema12 CLI required: FERROC_MIGRATION_OLD_READER"]
fn actual_schema12_reader_accepts12_rejects13_without_changing_rows_or_stage() {
    use std::process::Command;
    let image = PathBuf::from(
        std::env::var_os("FERROC_MIGRATION_OLD_READER").expect("actual old12 image required"),
    );
    let image_hash = Sha256::digest(std::fs::read(&image).unwrap());
    let mut f = round(b"abc", 1, 1);
    let owner = f.old.owner();
    let path = f.path.clone();
    let root = path.parent().unwrap().to_path_buf();
    let command = || {
        Command::new(&image)
            .arg("--allow-dir")
            .arg(&root)
            .arg("fleet-inventory")
            .arg("--db")
            .arg(&path)
            .arg("--root")
            .arg(&root)
            .output()
            .unwrap()
    };
    drop(f.db);
    let canary = command();
    assert!(
        canary.status.success(),
        "old-reader schema12 canary failed: {}",
        String::from_utf8_lossy(&canary.stderr)
    );
    f.db = OwnerFence::acquire(&path)
        .unwrap()
        .open_connection()
        .unwrap();
    f.db.journal()
        .unwrap()
        .recover_stopped_owner(owner)
        .unwrap();
    f.old =
        f.db.journal()
            .unwrap()
            .get(&JobKey::from_job(f.old.job()))
            .unwrap()
            .unwrap();
    let (_, new) = f.migrate().unwrap();
    let stage = new.stage().unwrap().path().to_path_buf();
    let rows: Vec<(String, String)> =
        f.db.connection
            .prepare("SELECT k,body FROM ferroc_fleet_jobs_v1 ORDER BY k")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
    let bytes = std::fs::read(&stage).unwrap();
    drop(f.db);
    let refused = command();
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("unsupported/ambiguous fleet journal schema version")
    );
    f.db = OwnerFence::acquire(&path)
        .unwrap()
        .open_connection()
        .unwrap();
    assert_eq!(f.schema(), 13);
    let after: Vec<(String, String)> =
        f.db.connection
            .prepare("SELECT k,body FROM ferroc_fleet_jobs_v1 ORDER BY k")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
    assert_eq!(rows, after);
    assert_eq!(std::fs::read(&stage).unwrap(), bytes);
    assert_eq!(f.usage(), (3, 1));
    println!(
        "OLD_READER_SCHEMA13_REJECTED image_sha256={image_hash:x} canary12=accepted rows_stage_debt_unchanged=true"
    );
}

use super::*;
use crate::fleet::{
    fence::{FencedConnection, OwnerFence},
    job::LeaseProfile,
    resume_condition::ResumeProposal,
};
use std::sync::Arc;
struct Round {
    db: FencedConnection,
    old: Snapshot,
    next: ValidatedGrant,
    condition: ResumeProposal,
    path: PathBuf,
    runtime: crate::runtime::Runtime,
    _temp: tempfile::TempDir,
}
fn round(data: &[u8], prefix: usize, tail: usize) -> Round {
    let (temp, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (mut source, mut receiver) = open(&host, &path, data);
    let owner = receiver.snapshot().owner();
    let key = JobKey::from_job(receiver.snapshot().job());
    receiver.enable_retained_checkpoints().unwrap();
    if prefix != 0 {
        receiver
            .write_record(&source.seal_data(0, &data[..prefix]).unwrap())
            .unwrap();
    }
    receiver.capture_retained_checkpoint().unwrap();
    if tail != 0 {
        receiver
            .write_record(
                &source
                    .seal_data(prefix as u64, &data[prefix..prefix + tail])
                    .unwrap(),
            )
            .unwrap();
    }
    drop(receiver);
    drop(source);
    host.close().unwrap();
    drop(host);
    let mut db = OwnerFence::acquire(&path)
        .unwrap()
        .open_connection()
        .unwrap();
    db.journal().unwrap().recover_stopped_owner(owner).unwrap();
    let old = db.journal().unwrap().get(&key).unwrap().unwrap();
    let mut job = old.job().clone();
    job.transfer_id = Uuid::new_v4();
    job.file_id = Uuid::new_v4();
    job.idempotency_key = "metadata-migration-fresh".into();
    let mut g = Offer::new(&path, data, 1).g.grant().clone();
    g.binding.transfer_id = job.transfer_id;
    g.binding.file_id = job.file_id;
    g.binding.source_session = Uuid::new_v4();
    g.binding.target_session = Uuid::new_v4();
    g.binding.authorization_id = Uuid::new_v4();
    g.binding.key_epoch = Uuid::new_v4();
    g.job_digest = job.digest().unwrap();
    let next = g
        .validate_for_profile(job, LeaseProfile::SingleOwner)
        .unwrap();
    let condition = ResumeProposal::build(
        old.job(),
        old.retained_stage().unwrap().checkpoint().unwrap(),
        &next,
    )
    .unwrap();
    Round {
        db,
        old,
        next,
        condition,
        path,
        runtime,
        _temp: temp,
    }
}
impl Round {
    fn migrate(&mut self) -> anyhow::Result<(Snapshot, Snapshot)> {
        self.db.journal()?.migrate_retained_reference(
            &JobKey::from_job(self.old.job()),
            self.old.revision(),
            &self.next,
            &self.condition,
            self.next.grant().issued_at_ms,
        )
    }
    fn old_bytes(&mut self) -> Vec<u8> {
        serde_json::to_vec(
            &self
                .db
                .journal()
                .unwrap()
                .get(&JobKey::from_job(self.old.job()))
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }
    fn schema(&self) -> i64 {
        self.db
            .connection
            .query_row("SELECT version FROM ferroc_fleet_meta", [], |r| r.get(0))
            .unwrap()
    }
    fn usage(&mut self) -> (u64, usize) {
        self.db
            .inventory(
                &self.runtime.policy,
                &[self.path.parent().unwrap().to_path_buf()],
                Arc::default(),
                InventoryLimits::default(),
            )
            .unwrap()
            .recorded_usage()
    }
    fn assert_rolled_back(&mut self, before: &[u8]) {
        assert_eq!(self.schema(), 12);
        assert_eq!(self.old_bytes(), before);
        assert!(
            self.db
                .journal()
                .unwrap()
                .get(&JobKey::from_job(self.next.job()))
                .unwrap()
                .is_none()
        );
        assert_eq!(self.usage(), (self.old.job().bytes_total, 1));
    }
}
#[test]
fn one_transaction_moves_one_allocation_but_never_restores_received_coverage() {
    let mut f = round(b"abcdefgh", 3, 1);
    assert_eq!(f.usage(), (8, 1));
    let path = f.old.stage().unwrap().path().to_path_buf();
    let old_bytes = std::fs::read(&path).unwrap();
    let (old, new) = f.migrate().unwrap();
    assert_eq!(f.schema(), 13);
    assert!(old.is_migrated_origin());
    assert!(old.stage().is_none());
    assert_eq!(old.received(), 4);
    assert_eq!(new.phase(), Phase::Interrupted);
    assert_eq!(new.received(), 0);
    assert!(new.retained_stage().unwrap().checkpoint().is_none());
    assert_eq!(old.migration_origin(), f.old.stage());
    assert_eq!(new.migration_origin(), f.old.stage());
    assert_eq!(new.stage().unwrap().path(), path);
    assert_ne!(
        new.stage().unwrap().allocation().unwrap().original_owner(),
        f.old
            .stage()
            .unwrap()
            .allocation()
            .unwrap()
            .original_owner()
    );
    assert_eq!(f.usage(), (8, 1));
    assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
    assert!(!Path::new(new.job().destination_path.as_str()).exists());
}
#[test]
fn zero_byte_debt_keeps_one_slot() {
    let mut f = round(b"", 0, 0);
    f.migrate().unwrap();
    assert_eq!(f.usage(), (0, 1));
}
#[test]
fn failure_at_old_cas_rolls_back_schema_and_both_rows() {
    let mut f = round(b"abc", 1, 1);
    let before = f.old_bytes();
    f.db.connection.execute_batch("CREATE TRIGGER fail_old BEFORE UPDATE ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'fixture old CAS'); END;").unwrap();
    assert!(
        f.migrate()
            .unwrap_err()
            .to_string()
            .contains("fixture old CAS")
    );
    f.assert_rolled_back(&before);
}
#[test]
fn failure_at_new_insert_rolls_back_old_history_and_schema() {
    let mut f = round(b"abc", 1, 1);
    let before = f.old_bytes();
    f.db.connection.execute_batch("CREATE TRIGGER fail_new BEFORE INSERT ON ferroc_fleet_jobs_v1 BEGIN SELECT RAISE(ABORT,'fixture new INSERT'); END;").unwrap();
    assert!(
        f.migrate()
            .unwrap_err()
            .to_string()
            .contains("fixture new INSERT")
    );
    f.assert_rolled_back(&before);
}
#[test]
fn deferred_commit_failure_rolls_back_both_rows_and_schema() {
    let mut f = round(b"abc", 1, 1);
    let before = f.old_bytes();
    f.db.connection.execute_batch("PRAGMA foreign_keys=ON;CREATE TABLE guard_parent(x INTEGER PRIMARY KEY);CREATE TABLE guard_child(x INTEGER REFERENCES guard_parent(x) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_commit AFTER INSERT ON ferroc_fleet_jobs_v1 BEGIN INSERT INTO guard_child(x) VALUES(1);END;").unwrap();
    assert!(f.migrate().unwrap_err().to_string().contains("FOREIGN KEY"));
    f.assert_rolled_back(&before);
}
#[test]
fn new_key_collision_does_not_move_old_debt() {
    let mut f = round(b"abc", 1, 1);
    f.db.journal()
        .unwrap()
        .admit(f.next.job().clone(), 200)
        .unwrap();
    let before = f.old_bytes();
    assert!(f.migrate().unwrap_err().to_string().contains("UNIQUE"));
    assert_eq!(f.old_bytes(), before);
    assert_eq!(f.schema(), 12);
    assert_eq!(f.usage(), (3, 1));
}
#[test]
fn new_idempotency_collision_does_not_move_old_debt() {
    let mut f = round(b"abc", 1, 1);
    let mut occupied = f.next.job().clone();
    occupied.transfer_id = Uuid::new_v4();
    occupied.file_id = Uuid::new_v4();
    f.db.journal().unwrap().admit(occupied, 200).unwrap();
    let before = f.old_bytes();
    assert!(f.migrate().unwrap_err().to_string().contains("UNIQUE"));
    f.assert_rolled_back(&before);
}
#[test]
fn stale_revision_and_invalid_new_time_are_rejected() {
    let mut f = round(b"abc", 1, 1);
    let before = f.old_bytes();
    let key = JobKey::from_job(f.old.job());
    assert!(
        f.db.journal()
            .unwrap()
            .migrate_retained_reference(&key, f.old.revision() + 1, &f.next, &f.condition, 200)
            .is_err()
    );
    assert!(
        f.db.journal()
            .unwrap()
            .migrate_retained_reference(
                &key,
                f.old.revision(),
                &f.next,
                &f.condition,
                f.next.grant().expires_at_ms
            )
            .is_err()
    );
    f.assert_rolled_back(&before);
}
#[test]
fn old_history_is_not_replayable_cancellable_or_absence_releasable() {
    let mut f = round(b"abc", 1, 1);
    let (old, new) = f.migrate().unwrap();
    let key = JobKey::from_job(old.job());
    let before = f.old_bytes();
    assert!(f.migrate().is_err());
    assert!(
        f.db.journal()
            .unwrap()
            .cancel(&key, old.revision())
            .is_err()
    );
    assert!(
        f.db.journal()
            .unwrap()
            .confirm_removed(&key, old.revision())
            .is_err()
    );
    assert_eq!(f.old_bytes(), before);
    assert_eq!(
        f.db.journal()
            .unwrap()
            .get(&JobKey::from_job(new.job()))
            .unwrap()
            .unwrap()
            .received(),
        0
    );
    assert_eq!(f.usage(), (3, 1));
}
#[test]
fn missing_peer_fails_both_inventory_and_history_read() {
    let mut f = round(b"abc", 1, 1);
    let (_, new) = f.migrate().unwrap();
    f.db.connection
        .execute(
            "DELETE FROM ferroc_fleet_jobs_v1 WHERE k=?1",
            [JobKey::from_job(new.job()).id()],
        )
        .unwrap();
    assert!(
        f.db.journal()
            .unwrap()
            .get(&JobKey::from_job(f.old.job()))
            .is_err()
    );
    assert!(
        f.db.inventory(
            &f.runtime.policy,
            &[f.path.parent().unwrap().to_path_buf()],
            Arc::default(),
            InventoryLimits::default()
        )
        .is_err()
    );
}
#[test]
fn schema_downgrade_refuses_both_rows() {
    let mut f = round(b"abc", 1, 1);
    let (_, new) = f.migrate().unwrap();
    f.db.connection
        .execute("UPDATE ferroc_fleet_meta SET version=12", [])
        .unwrap();
    for job in [f.old.job(), new.job()] {
        assert!(f.db.journal().unwrap().get(&JobKey::from_job(job)).is_err());
    }
}
#[test]
fn restart_skips_immutable_origin_and_recovers_only_successor_without_coverage() {
    let mut f = round(b"abc", 1, 1);
    let (old, new) = f.migrate().unwrap();
    let old_serialized = f.old_bytes();
    let owner = new.owner();
    let path = f.path.clone();
    drop(f.db);
    f.db = OwnerFence::acquire(&path)
        .unwrap()
        .open_connection()
        .unwrap();
    let rows =
        f.db.journal()
            .unwrap()
            .recover_stopped_owner(owner)
            .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].job(), new.job());
    assert_eq!(rows[0].received(), 0);
    assert_eq!(
        f.db.journal()
            .unwrap()
            .get(&JobKey::from_job(old.job()))
            .unwrap()
            .unwrap()
            .revision(),
        old.revision()
    );
    assert_eq!(f.old_bytes(), old_serialized);
    assert_eq!(f.usage(), (3, 1));
}
#[test]
fn original_checkpoint_flow_and_settlement_do_not_downgrade_schema13() {
    let (_t, path, runtime) = fixture();
    let host = runtime
        .open_fleet_host(&path, InventoryLimits::default())
        .unwrap();
    let (mut source, mut receiver) = open(&host, &path, b"abc");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("UPDATE ferroc_fleet_meta SET version=13", [])
        .unwrap();
    receiver.enable_retained_checkpoints().unwrap();
    receiver
        .write_record(&source.seal_data(0, b"abc").unwrap())
        .unwrap();
    receiver.capture_retained_checkpoint().unwrap();
    let finish = source
        .seal_control(crate::fleet::control::ControlBody::Finish(
            crate::fleet::control::Finish {
                size: 3,
                sha256: Sha256::digest(b"abc").into(),
            },
        ))
        .unwrap();
    let sealed = receiver.seal_finish(&finish).unwrap();
    let candidate = sealed.prepare_commit().unwrap();
    #[cfg(windows)]
    let terminal = candidate
        .attempt_local_publication()
        .unwrap()
        .record_target_observation()
        .unwrap()
        .settle_local()
        .unwrap();
    #[cfg(not(windows))]
    let terminal = candidate;
    assert_eq!(
        c.query_row("SELECT version FROM ferroc_fleet_meta", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        13
    );
    drop(terminal);
    host.close().unwrap();
}
