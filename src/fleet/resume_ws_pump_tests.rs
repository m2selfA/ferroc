//! One PROCESS, real TCP/WS/relay and original Files; not stock agent restart.
use super::*;
use crate::{
    fleet::{
        job::ValidatedGrant,
        relay_channel::FleetRelay,
        relay_io::{FleetLink, run_source, run_target},
        source_window::SourceWindow,
        state::Phase,
    },
    network::Network,
    relay::{Relay, hash},
};
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
struct RelayGuard(tokio::task::JoinHandle<()>);
impl Drop for RelayGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn links(root: &Path, g: &ValidatedGrant) -> (FleetLink, FleetLink, RelayGuard) {
    let dir = root.join("resume-ws-relay");
    crate::fleet::identity::make_directory(&dir).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let relay = Relay::new(
        &dir.join("relay.db"),
        &url,
        "PUBLIC TEST admin password only",
    )
    .unwrap();
    for (id, token) in [
        ("source-A", "TEST-source-token"),
        ("target-B", "TEST-target-token"),
    ] {
        let h = hash(token);
        relay
            .store
            .put(
                "device",
                id,
                &serde_json::json!({"tokenHash":h,"paused":false}),
                120,
            )
            .unwrap();
        relay
            .store
            .put("device_token", &h, &serde_json::json!({"deviceId":id}), 120)
            .unwrap();
    }
    let registry = Arc::new(FleetRelay::new());
    let router = relay.router_with_fleet(registry.clone());
    let server = RelayGuard(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap()
    }));
    // Route TTL starts AFTER store/listener initialization; original budgets unchanged.
    let t = registry
        .approve_local(g, "source-A", "target-B", Duration::from_secs(30))
        .unwrap();
    let source = FleetLink::connect(
        &Network::direct(),
        &url,
        "TEST-source-token",
        t.source.expose_secret(),
        g,
        Direction::SourceToTarget,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    let target = FleetLink::connect(
        &Network::direct(),
        &url,
        "TEST-target-token",
        t.target.expose_secret(),
        g,
        Direction::TargetToSource,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    (source, target, server)
}
macro_rules! run_pair {
    ($w:ident,$recv:ident,$f:ident,$grant:ident) => {{
        let (sl, tl, _relay) = links($f._temp.path(), &$grant).await;
        tokio::time::timeout(Duration::from_secs(45), async {
            tokio::join!(
                Box::pin(run_source($w, sl)),
                Box::pin(run_target($recv, tl))
            )
        })
        .await
        .unwrap()
    }};
}
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_resumed_pumps_tcp_ws_reach_authenticated_receipt_sql_and_file() {
    let mut rows = Vec::new();
    for (data, prefix) in [
        (vec![], 0),
        (b"abcdefgh".to_vec(), 0),
        (b"abcdefgh".to_vec(), 8),
        (vec![0x61; 131073], 101),
        (vec![0x63; 8 * 1024 * 1024], 65536),
    ] {
        let mut f = stopped(&data, prefix);
        std::fs::write(&f.old.source_path, &data).unwrap();
        let proof = f.proof.take().unwrap();
        let host = recovered(&f, proof);
        let old = host.get(&f.key).unwrap().unwrap();
        let (source, target) = owner_pair(&f, &f.cp);
        let grant = target.grant().clone();
        let key = JobKey::from_job(grant.job());
        host.resume_retained_recovery().unwrap();
        let recv = host
            .admit_retained_receiver(&f.key, old.revision(), target, data.len() as u64)
            .unwrap();
        let rt = crate::runtime::Runtime::new(
            crate::config::Policy::new(vec![f.path.parent().unwrap().to_path_buf()], false)
                .unwrap(),
        );
        let source = rt
            .open_fleet_resume_source(source, data.len() as u64)
            .unwrap();
        let w = SourceWindow::resuming(source, 8).unwrap();
        let (source, target) = run_pair!(w, recv, f, grant);
        let target = target.unwrap_or_else(|e| panic!("target pump failed: {e:#}"));
        let source = source.unwrap_or_else(|e| panic!("source pump failed: {e:#}"));
        let row = host.get(&key).unwrap().unwrap();
        assert_eq!(source.receipt(), &target);
        assert_eq!(row.receipt(), Some(&target));
        assert_eq!(row.phase(), Phase::Completed);
        assert_eq!(row.received(), data.len() as u64);
        assert!(row.stage().is_none());
        assert!(!f.stage.exists());
        assert_eq!(std::fs::read(&f.old.source_path).unwrap(), data);
        let target_bytes = std::fs::read(&f.old.destination_path).unwrap();
        assert_eq!(target_bytes, data);
        assert_eq!(host.inventory().unwrap().recorded_usage(), (0, 0));
        assert_eq!(schema(&f.path), 13);
        assert_eq!(host.status().unwrap().in_flight, 0);
        rows.push(serde_json::json!({"bytes":data.len(),"prefixBytes":prefix,"jobDigest":grant.job().digest().unwrap(),"sourceReceipt":source.receipt(),"targetReceipt":target,"sqlReceipt":row.receipt(),"targetSha256":<[u8;32]>::from(Sha256::digest(&target_bytes)),"schema":13,"liveDebt":[0,0]}));
        host.close().unwrap();
    }
    if let Ok(path) = std::env::var("FERROC_RESUME_WS_RECEIPTS") {
        std::fs::write(path, serde_json::to_vec_pretty(&serde_json::json!({"scope":"PUBLIC-fixture single-process real TCP/WS; NOT stock restart","cases":rows})).unwrap()).unwrap();
    }
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_resumed_pump_reaches_finish_but_named_publish_retains_full_debt() {
    for (data, prefix) in [
        (vec![], 0),
        (b"abcdefgh".to_vec(), 3),
        (vec![0x61; 131073], 101),
        (vec![0x63; 8 * 1024 * 1024], 65536),
    ] {
        let mut f = stopped(&data, prefix);
        std::fs::write(&f.old.source_path, &data).unwrap();
        let proof = f.proof.take().unwrap();
        let host = recovered(&f, proof);
        let old = host.get(&f.key).unwrap().unwrap();
        let (source, target) = owner_pair(&f, &f.cp);
        let grant = target.grant().clone();
        let key = JobKey::from_job(grant.job());
        host.resume_retained_recovery().unwrap();
        let recv = host
            .admit_retained_receiver(&f.key, old.revision(), target, data.len() as u64)
            .unwrap();
        let rt = crate::runtime::Runtime::new(
            crate::config::Policy::new(vec![f.path.parent().unwrap().to_path_buf()], false)
                .unwrap(),
        );
        let file = rt
            .open_fleet_resume_source(source, data.len() as u64)
            .unwrap();
        let w = SourceWindow::resuming(file, 8).unwrap();
        let (source, target) = run_pair!(w, recv, f, grant);
        let error = target.unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("Linux publication requires the explicit anonymous owner"),
            "{error:#}"
        );
        assert!(source.is_err());
        let row = host.get(&key).unwrap().unwrap();
        assert!(row.data_seal().is_some());
        assert!(row.intent().is_some());
        assert!(row.receipt().is_none());
        assert_ne!(row.phase(), Phase::Completed);
        assert_eq!(std::fs::read(&f.stage).unwrap(), data);
        assert!(!Path::new(&f.old.destination_path).exists());
        assert_eq!(
            host.inventory().unwrap().recorded_usage(),
            (data.len() as u64, 1)
        );
        assert_eq!(schema(&f.path), 13);
        assert_eq!(host.status().unwrap().in_flight, 0);
        host.close().unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn different_but_both_valid_proof_bases_are_rejected_over_ws_before_suffix() {
    let mut f = stopped(b"abcdefgh", 3);
    std::fs::write(&f.old.source_path, &f.data).unwrap();
    let proof = f.proof.take().unwrap();
    let host = recovered(&f, proof);
    let row = host.get(&f.key).unwrap().unwrap();
    let (source, target) = owner_pair_variant(&f, &f.cp, true);
    let grant = target.grant().clone();
    let key = JobKey::from_job(grant.job());
    host.resume_retained_recovery().unwrap();
    let recv = host
        .admit_retained_receiver(&f.key, row.revision(), target, 8)
        .unwrap();
    let stage_before = std::fs::read(&f.stage).unwrap();
    let row_before = host.get(&key).unwrap().unwrap();
    let rt = crate::runtime::Runtime::new(
        crate::config::Policy::new(vec![f.path.parent().unwrap().to_path_buf()], false).unwrap(),
    );
    let file = rt.open_fleet_resume_source(source, 8).unwrap();
    let w = SourceWindow::resuming(file, 8).unwrap();
    let (source, target) = run_pair!(w, recv, f, grant);
    let error = source.unwrap_err();
    assert!(
        format!("{error:#}").contains("resume READY differs from local BOTH-proof base"),
        "{error:#}"
    );
    assert!(target.is_err());
    assert_eq!(std::fs::read(&f.stage).unwrap(), stage_before);
    let after = host.get(&key).unwrap().unwrap();
    assert_eq!(after.revision(), row_before.revision());
    assert_eq!(after.received(), row_before.received());
    assert_eq!(after.phase(), row_before.phase());
    assert!(after.receipt().is_none());
    assert!(after.data_seal().is_none());
    assert!(!Path::new(&f.old.destination_path).exists());
    assert_eq!(host.inventory().unwrap().recorded_usage(), (8, 1));
    assert_eq!(host.status().unwrap().in_flight, 0);
    host.close().unwrap();
}
