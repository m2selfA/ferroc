//! Candidate single-file executor for one planned transfer. Runs the EXISTING
//! source window and target receiver pumps against caller-built links, then
//! requires both sides to report the SAME receipt. No retry, reconnect, journal,
//! operational issuance or two-host orchestration. The candidate driver owns
//! sequential scheduling only; callers still construct all authorized owners.
use super::{
    control::Receipt,
    host::receiver::HostReceiver,
    relay_io::{FleetLink, run_source, run_target},
    source_window::SourceWindow,
    sync_plan::SyncPlan,
    sync_run::{RunLedger, RunStatus},
};
#[cfg(test)]
#[path = "sync_exec_tests.rs"]
mod tests;

use anyhow::{Result, ensure};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

/// Cooperative stop flag checked on a 5 ms timer. Scheduler delay and blocking
/// IO are not bounded by this timer; it is not a hard cancellation deadline.
#[derive(Clone, Debug, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}
impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
    async fn wait(&self) {
        while !self.is_cancelled() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecOutcome {
    Settled(Receipt),
    Cancelled,
}

/// Both pumps run concurrently on the caller's runtime. A successful return means
/// the local target settled AND the source authenticated that same receipt; it is
/// still not delivery proof for any other observer.
/// ```compile_fail
/// // Both peers and both links are required; there is no one-sided entry point.
/// fn no_half(file:ferroc::fleet::source_window::SourceWindow<'static>,l:ferroc::fleet::relay_io::FleetLink,r:ferroc::fleet::host::receiver::HostReceiver<'static,'static>){let _=ferroc::fleet::sync_exec::execute_file(file,l,r);}
/// ```
/// ```compile_fail
/// // A receipt is not a resend token: the executor exposes no retry handle.
/// fn no_retry(r:ferroc::fleet::control::Receipt){r.resend();}
/// ```
/// Cancellation drops BOTH pumps instead of waiting for them: the target keeps
/// its stage and full debt if not yet settled; the source keeps its file.
/// No receipt is returned for cancellation. A target that already settled may
/// retain its historical receipt and zero debt; cancellation cannot undo it.
/// A chunk already being written may still land; this is not a drain or rollback.
/// ```compile_fail
/// fn no_receipt_kind(o:ferroc::fleet::sync_exec::ExecOutcome){let _:ferroc::fleet::control::Receipt=o;}
/// ```
pub async fn execute_file_cancellable(
    window: SourceWindow<'_>,
    source: FleetLink,
    receiver: HostReceiver<'_, '_>,
    target: FleetLink,
    token: &CancelToken,
) -> Result<ExecOutcome> {
    if token.is_cancelled() {
        return Ok(ExecOutcome::Cancelled);
    }
    tokio::select! {
        biased;
        _ = token.wait() => Ok(ExecOutcome::Cancelled),
        result = execute_file(window, source, receiver, target) => {
            result.map(ExecOutcome::Settled)
        }
    }
}
/// Everything one planned file needs, built by the caller (links, admission and
/// records all stay caller-owned). `run_plan` never constructs them itself.
pub struct PreparedFile<'a> {
    pub window: SourceWindow<'a>,
    pub source: FleetLink,
    pub receiver: HostReceiver<'a, 'a>,
    pub target: FleetLink,
}

/// Sequential driver for one additive plan: start the next file, prepare it,
/// execute (cancellable), then settle or fail. Ordering and one-in-flight come
/// from the ledger. A prepare/execute failure fails the ledger and stops; a
/// cancellation cancels it. Returns the final local status, never a claim about
/// the peer.
/// ```compile_fail
/// fn no_skip(plan:&ferroc::fleet::sync_plan::SyncPlan,l:&mut ferroc::fleet::sync_run::RunLedger){let _=ferroc::fleet::sync_exec::run_plan(plan,l,3);}
/// ```
pub async fn run_plan<'a, F, Fut>(
    plan: &SyncPlan,
    ledger: &mut RunLedger,
    token: &CancelToken,
    mut prepare: F,
) -> Result<RunStatus>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Result<PreparedFile<'a>>>,
{
    ledger.validate_plan(plan)?;
    while let Some(index) = ledger.driver_next_index()? {
        if token.is_cancelled() {
            ledger.cancel("operator cancelled between files")?;
            return Ok(ledger.status());
        }
        let Some(path) = ledger.start_next()?.map(str::to_string) else {
            break;
        };
        // Box per-file futures: their state includes both pumps, and the driver is
        // itself polled from a caller future. Without this the nested state can
        // exceed a default 2 MiB test-thread stack.
        let preparation = Box::pin(prepare(index));
        let prepared = match tokio::select! {
            biased;
            _ = token.wait() => {
                ledger.cancel("operator cancelled during preparation")?;
                return Ok(ledger.status());
            }
            result = preparation => result,
        } {
            Ok(prepared) => prepared,
            Err(e) => {
                ledger.fail(&format!("{path}: {e:#}"))?;
                return Ok(ledger.status());
            }
        };
        // Check the actual admitted target, not a caller-supplied identity claim.
        // Preparation may already have created a stage; dropping it retains debt.
        if prepared.receiver.snapshot().job() != plan.files()[index].job() {
            drop(prepared);
            ledger.fail(&format!("{path}: prepared target job differs from plan"))?;
            return Ok(ledger.status());
        }
        match Box::pin(execute_file_cancellable(
            prepared.window,
            prepared.source,
            prepared.receiver,
            prepared.target,
            token,
        ))
        .await
        {
            Ok(ExecOutcome::Settled(receipt)) => {
                if let Err(e) = ledger.settle(&receipt) {
                    // A local target may already be settled: this blocks only the
                    // run ledger and does not roll back its file or receipt.
                    ledger.fail(&format!("{path}: receipt rejected: {e:#}"))?;
                    return Ok(ledger.status());
                }
            }
            Ok(ExecOutcome::Cancelled) => {
                ledger.cancel("operator cancelled during transfer")?;
                return Ok(ledger.status());
            }
            Err(e) => {
                ledger.fail(&format!("{path}: {e:#}"))?;
                return Ok(ledger.status());
            }
        }
    }
    Ok(ledger.status())
}
pub async fn execute_file(
    window: SourceWindow<'_>,
    source: FleetLink,
    receiver: HostReceiver<'_, '_>,
    target: FleetLink,
) -> Result<Receipt> {
    let (source_outcome, target_outcome) =
        tokio::join!(run_source(window, source), run_target(receiver, target));
    let observation = source_outcome?;
    let receipt = target_outcome?;
    ensure!(
        observation.receipt() == &receipt,
        "source-observed receipt differs from the local target receipt"
    );
    Ok(receipt)
}
