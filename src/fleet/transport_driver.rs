//! Agent-side bridge from an already authenticated lease owner to the EXISTING
//! source/target pumps. It adds no wire message, crypto or path authority: the
//! owner, its one-shot ticket and its approved grant are the only inputs.
//!
//! Ordering that must not change: the ticket is consumed into the real link
//! first; only then may records move into a window/receiver. On the target the
//! receiver future is dropped before `host.close()`. Nothing here publishes by
//! itself: the target pump performs the existing v9 settlement and the source
//! pump only reports an authenticated peer statement.
use super::control::Receipt;
#[cfg(any(windows, target_os = "linux"))]
use super::{host::FleetHost, inventory::InventoryLimits, relay_io::run_target_with_renewal};
use super::{
    relay_io::{FleetLink, NoRenewal, run_source_with_renewal},
    setup_config::TransferPlan,
    setup_lease::SetupLease,
    source::PeerCommitObservation,
};
use crate::runtime::Runtime;
#[cfg(any(windows, target_os = "linux"))]
use anyhow::Context;
use anyhow::{Result, ensure};
#[cfg(any(windows, target_os = "linux"))]
use std::path::PathBuf;
use std::{sync::Arc, time::Duration};

/// Local outcome of one provisioned round. Never a claim about the peer's disk.
pub(crate) enum TransferOutcome {
    SourceObserved(Box<PeerCommitObservation>),
    #[cfg(any(windows, target_os = "linux"))]
    TargetSettled(Receipt),
}

/// One bounded JSON line with descriptive completion metadata only. Source
/// observations remain peer statements; neither role's log grants authority or
/// proves current file bytes. No paths, tickets, tokens or private keys appear.
fn log_completion(evidence: &str, job_digest: [u8; 32], receipt: &Receipt) {
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "fleetTransferCompletion",
            "version": 1,
            "evidence": evidence,
            "jobDigest": job_digest,
            "receipt": receipt,
        })
    );
}

/// Plain local copy of the approved transfer settings (no secret material).
pub(crate) struct TransferPlanSnapshot {
    role: super::protocol::Direction,
    window_chunks: u8,
    linux_anonymous_stage: bool,
    retained_checkpoint_bytes: Option<u64>,
    #[cfg(any(windows, target_os = "linux"))]
    host_db: Option<PathBuf>,
    #[cfg(any(windows, target_os = "linux"))]
    create_parents_below: Option<PathBuf>,
}

impl TransferPlanSnapshot {
    pub(crate) fn from_plan(plan: &TransferPlan, role: super::protocol::Direction) -> Self {
        Self {
            role,
            window_chunks: plan.window_chunks(),
            linux_anonymous_stage: plan.linux_anonymous_stage(),
            retained_checkpoint_bytes: plan.retained_checkpoint_bytes(),
            #[cfg(any(windows, target_os = "linux"))]
            host_db: plan.host_db().map(|p| p.to_path_buf()),
            #[cfg(any(windows, target_os = "linux"))]
            create_parents_below: plan.create_parents_below().map(|p| p.to_path_buf()),
        }
    }
}

async fn wait_stop(stop: &mut tokio::sync::watch::Receiver<bool>) {
    if *stop.borrow() {
        return;
    }
    let _ = stop.changed().await;
}

/// Consume this owner's ticket into the real link, then drive the matching pump.
/// `token` is the connection's own device token; it is never logged.
/// SOURCE-only entry used by the local MCP task surface. Same ticket/owner
/// handoff and the same pump; the target path stays with the automatic mode.
pub(crate) async fn run_leased_source(
    runtime: Arc<Runtime>,
    owner: SetupLease,
    token: String,
    plan: TransferPlanSnapshot,
    budget: Duration,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<PeerCommitObservation> {
    ensure!(
        plan.role == super::protocol::Direction::SourceToTarget,
        "MCP task entry only drives source rounds"
    );
    match run_leased_transfer(runtime, owner, token, plan, budget, stop).await? {
        TransferOutcome::SourceObserved(observed) => Ok(*observed),
        #[cfg(any(windows, target_os = "linux"))]
        TransferOutcome::TargetSettled(_) => {
            anyhow::bail!("source entry produced a target outcome")
        }
    }
}

fn log_resume_admission(role: &str, job_digest: [u8; 32], condition_digest: [u8; 32], prefix: u64) {
    eprintln!(
        "{}",
        serde_json::json!({"event":"fleetTransferResumeAdmission","version":1,"role":role,
        "jobDigest":job_digest,"conditionDigest":condition_digest,"verifiedPrefixBytes":prefix})
    );
}
/// Explicit stock restart path. A fresh BOTH-proof owner is consumed once;
/// stopped-owner selection is LOCAL and never supplied by a relay message.
pub(crate) async fn run_resumed_transfer(
    runtime: Arc<Runtime>,
    mut owner: super::setup_resume::ResumeSetupLease,
    token: String,
    plan: TransferPlanSnapshot,
    recovery: super::setup_config::RecoveryPlan,
    budget: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<TransferOutcome> {
    ensure!(owner.role() == plan.role, "resume transfer role mismatch");
    ensure!(
        !budget.is_zero() && budget <= Duration::from_secs(300),
        "invalid resume transfer budget"
    );
    let job_digest = owner.grant().grant().job_digest;
    let condition_digest = owner
        .condition()
        .context("resume condition missing")?
        .digest();
    let prefix = owner
        .condition()
        .context("resume condition missing")?
        .prefix_bytes();
    let link = owner
        .connect_link(&runtime.policy.network, &token, budget)
        .await?;
    let mut none = NoRenewal;
    match plan.role {
        super::protocol::Direction::SourceToTarget => {
            let window = owner.into_recovery_source_window(
                &runtime,
                plan.window_chunks,
                recovery.max_prefix_bytes,
            )?;
            ensure!(
                window.bytes_encoded() == 0,
                "recovery must not encode before READY"
            );
            log_resume_admission("source", job_digest, condition_digest, prefix);
            let observed = tokio::select! {
                _=wait_stop(&mut stop)=>anyhow::bail!("resume source cancelled; effects may exist"),
                result=Box::pin(run_source_with_renewal(window,link,&mut none))=>result?,
            };
            log_completion("peerReportedCompleted", job_digest, observed.receipt());
            Ok(TransferOutcome::SourceObserved(Box::new(observed)))
        }
        #[cfg(any(windows, target_os = "linux"))]
        super::protocol::Direction::TargetToSource => {
            let db = plan
                .host_db
                .as_deref()
                .context("resume target requires local host database")?;
            let host = runtime.open_fleet_host(db, InventoryLimits::default())?;
            host.resume_retained_recovery()?;
            let result = tokio::select! {
                _=wait_stop(&mut stop)=>Err(anyhow::anyhow!("resume target cancelled; effects may exist")),
                result=async {
                    let receiver=owner.into_recovery_receiver(&host,&recovery)?;
                    ensure!(receiver.resumed_prefix()==Some(prefix),"admitted resume prefix differs");
                    log_resume_admission("target",job_digest,condition_digest,prefix);
                    Box::pin(run_target_with_renewal(receiver,link,&mut none)).await
                }=>result,
            };
            let closed = host.close();
            let receipt = result?;
            closed.context("resume target host close")?;
            log_completion("targetSettledLocally", job_digest, &receipt);
            Ok(TransferOutcome::TargetSettled(receipt))
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        super::protocol::Direction::TargetToSource => anyhow::bail!("resume target unsupported"),
    }
}

pub(crate) async fn run_leased_transfer(
    runtime: Arc<Runtime>,
    mut owner: SetupLease,
    token: String,
    plan: TransferPlanSnapshot,
    budget: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<TransferOutcome> {
    ensure!(
        owner.role() == plan.role,
        "transfer plan role differs from leased role"
    );
    ensure!(
        !budget.is_zero() && budget <= Duration::from_secs(300),
        "invalid transfer budget"
    );
    let job_digest = owner.grant().grant().job_digest;
    let network = runtime.policy.network.clone();
    let link: FleetLink = owner.connect_link(&network, &token, budget).await?;
    let mut none = NoRenewal;
    match plan.role {
        super::protocol::Direction::SourceToTarget => {
            let window = owner.into_source_window(&runtime, plan.window_chunks)?;
            let observed = tokio::select! {
                _ = wait_stop(&mut stop) => anyhow::bail!("transfer cancelled before source completion"),
                result = run_source_with_renewal(window, link, &mut none) => result?,
            };
            log_completion("peerReportedCompleted", job_digest, observed.receipt());
            Ok(TransferOutcome::SourceObserved(Box::new(observed)))
        }
        #[cfg(any(windows, target_os = "linux"))]
        super::protocol::Direction::TargetToSource => {
            let db = plan
                .host_db
                .as_deref()
                .context("target transfer needs a local host database")?;
            // Explicit local approval only. Hold the private ancestor guards
            // through receiver admission/publishing; an error leaves directories
            // in place and never changes journal debt.
            #[cfg(any(windows, target_os = "linux"))]
            let _parents = match plan.create_parents_below.as_deref() {
                Some(root) => {
                    let parents = owner.prepare_target_parents(root)?;
                    eprintln!(
                        "target private parent directories created={}",
                        parents.created
                    );
                    Some(parents)
                }
                None => None,
            };
            let host: FleetHost<'_> = runtime.open_fleet_host(db, InventoryLimits::default())?;
            let report = host.inventory()?;
            eprintln!(
                "target host inventory: complete={} usage={:?} entries={} findings={:?}",
                report.complete(),
                report.recorded_usage(),
                report.entries_seen(),
                report.findings()
            );
            host.resume().context("target host resume")?;
            let result = tokio::select! {
                _ = wait_stop(&mut stop) => Err(anyhow::anyhow!("transfer cancelled before target settlement")),
                result = async {
                    #[cfg(windows)]
                    let receiver = {
                        ensure!(!plan.linux_anonymous_stage, "Linux anonymous mode unavailable on Windows");
                        owner.into_receiver(&host)?
                    };
                    #[cfg(target_os = "linux")]
                    let receiver = {
                        ensure!(plan.linux_anonymous_stage, "Linux anonymous mode requires explicit approval");
                        owner.into_linux_anonymous_receiver(&host)?
                    };
                    if let Some(interval) = plan.retained_checkpoint_bytes {
                        Box::pin(super::relay_io::run_target_with_checkpoints(receiver, link, interval)).await
                    } else {
                        Box::pin(run_target_with_renewal(receiver, link, &mut none)).await
                    }
                } => result,
            };
            // The receiver future (and its stage operation) is dropped by the
            // select before this close, so close cannot await this task.
            let closed = host.close();
            let receipt = result?;
            closed.context("target host close after settlement")?;
            log_completion("targetSettledLocally", job_digest, &receipt);
            Ok(TransferOutcome::TargetSettled(receipt))
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        super::protocol::Direction::TargetToSource => {
            anyhow::bail!("target fleet transfer requires Windows host primitives")
        }
    }
}
