use crate::{
    config::{Policy, integer, string},
    process::{Processes, pid},
    protocol::{ToolDefinition, ToolResult},
    search::Searches,
};
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub struct Runtime {
    pub policy: Policy,
    pub processes: Processes,
    pub searches: Searches,
    transfers: crate::transfer::Transfers,
    history: Mutex<VecDeque<Value>>,
    started: Instant,
    // Serialize filesystem mutations, preventing edits from racing other calls in this process.
    fs_gate: Arc<Mutex<()>>,
    #[cfg(feature = "fleet-core")]
    fleet_hosts: Arc<Mutex<crate::fleet::host::HostRegistration>>,
}
impl Runtime {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            processes: Processes::default(),
            searches: Searches::default(),
            transfers: crate::transfer::Transfers::default(),
            history: Mutex::new(VecDeque::new()),
            started: Instant::now(),
            fs_gate: Arc::new(Mutex::new(())),
            #[cfg(feature = "fleet-core")]
            fleet_hosts: Arc::new(Mutex::new(crate::fleet::host::HostRegistration::default())),
        }
    }
    /// Candidate P1 source IO. Reads ONLY the path bound to a fresh Source lease.
    /// Not a network/CLI/MCP entry point, scanner, durable sender or resume API.
    #[cfg(feature = "fleet-core")]
    pub fn open_fleet_source(
        &self,
        records: crate::fleet::lease::LeasedRecords,
    ) -> Result<crate::fleet::source_file::SourceFile<'_>> {
        crate::fleet::source_file::SourceFile::open(self, records, self.fs_gate.clone())
    }
    /// Windows-only LOCAL bounded tree read under this Runtime's current policy.
    /// No remote manifest authority, snapshot, publication or network capability.
    #[cfg(feature = "fleet-core")]
    pub fn scan_fleet_manifest(
        &self,
        root: &std::path::Path,
        limits: crate::fleet::manifest_scan::ScanLimits,
        cancel: &crate::fleet::sync_exec::CancelToken,
    ) -> Result<crate::fleet::manifest_scan::ManifestObservation> {
        crate::fleet::manifest_scan::observe(self, self.fs_gate.clone(), root, limits, cancel)
    }
    /// Windows-only LOCAL read-only preflight of an add-only plan destinations.
    /// Never creates a directory/file and never publishes; not a grant/reservation.
    #[cfg(feature = "fleet-core")]
    pub fn preflight_fleet_target(
        &self,
        root: &std::path::Path,
        plan: &crate::fleet::sync_plan::SyncPlan,
        limits: crate::fleet::target_preflight::PreflightLimits,
        cancel: &crate::fleet::sync_exec::CancelToken,
    ) -> Result<crate::fleet::target_preflight::TargetPreflight> {
        crate::fleet::target_preflight::preflight(
            self,
            self.fs_gate.clone(),
            root,
            plan,
            limits,
            cancel,
        )
    }
    #[cfg(all(test, windows, feature = "fleet-core"))]
    pub(crate) fn preflight_fleet_target_for_test(
        &self,
        root: &std::path::Path,
        plan: &crate::fleet::sync_plan::SyncPlan,
        limits: crate::fleet::target_preflight::PreflightLimits,
        cancel: &crate::fleet::sync_exec::CancelToken,
        hook: impl FnMut(crate::fleet::target_preflight::PreflightEvent<'_>) -> Result<()>,
    ) -> Result<crate::fleet::target_preflight::TargetPreflight> {
        crate::fleet::target_preflight::preflight_with(
            self,
            &self.fs_gate,
            root,
            plan,
            limits,
            cancel,
            hook,
        )
    }
    #[cfg(all(test, windows, feature = "fleet-core"))]
    pub(crate) fn scan_fleet_manifest_for_test(
        &self,
        root: &std::path::Path,
        limits: crate::fleet::manifest_scan::ScanLimits,
        cancel: &crate::fleet::sync_exec::CancelToken,
        hook: impl FnMut(crate::fleet::manifest_scan::ScanEvent<'_>) -> Result<()>,
    ) -> Result<crate::fleet::manifest_scan::ManifestObservation> {
        crate::fleet::manifest_scan::observe_with(self, &self.fs_gate, root, limits, cancel, hook)
    }
    // Same registry -> filesystem-gate order as host construction. Holding this
    // guard through one synchronous source operation makes shutdown wait for
    // that accepted operation, not idle SourceFile owners. No DB lock is taken.
    #[cfg(feature = "fleet-core")]
    pub(crate) fn fleet_source_guard(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, crate::fleet::host::HostRegistration>> {
        let state = self
            .fleet_hosts
            .lock()
            .map_err(|_| anyhow::anyhow!("Runtime fleet registration poisoned"))?;
        ensure!(!state.stopped, "Runtime fleet lifecycle stopped");
        ensure!(self.policy.allow_transfers, "transfers disabled");
        Ok(state)
    }
    /// Explicit experimental LOCAL host attachment, default paused. No CLI/MCP
    /// entrypoint invokes this. The borrow pins this Runtime/policy lifetime and
    /// the host reuses the actual filesystem gate; callers cannot substitute one.
    #[cfg(feature = "fleet-core")]
    pub fn open_fleet_host(
        &self,
        path: &std::path::Path,
        limits: crate::fleet::inventory::InventoryLimits,
    ) -> Result<crate::fleet::host::FleetHost<'_>> {
        crate::fleet::host::FleetHost::open(self, path, self.fs_gate.clone(), limits)
    }
    #[cfg(feature = "fleet-core")]
    pub(crate) fn fleet_host_claim(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, crate::fleet::host::HostRegistration>> {
        let state = self
            .fleet_hosts
            .lock()
            .map_err(|_| anyhow::anyhow!("Runtime fleet registration poisoned"))?;
        ensure!(!state.stopped, "Runtime fleet lifecycle stopped");
        ensure!(!state.attached, "Runtime already has a fleet host");
        Ok(state)
    }
    #[cfg(feature = "fleet-core")]
    pub(crate) fn fleet_host_detach(&self) {
        let mut state = self
            .fleet_hosts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.attached = false;
        state.control = std::sync::Weak::new();
    }
    /// Terminally stop host admission and drain accepted operations, including
    /// a construction accepted before shutdown. Does not delete data or close
    /// an externally held host DB: close()/Drop keeps that explicit ownership.
    /// Runtime::shutdown invokes this too and fails fast on a failed drain.
    #[cfg(feature = "fleet-core")]
    pub async fn shutdown_fleet_host(&self) -> Result<()> {
        let registry = self.fleet_hosts.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let control = {
                let mut state = registry
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Runtime fleet registration poisoned"))?;
                state.stopped = true;
                state.control.upgrade()
            };
            if let Some(control) = control {
                control.stop_and_drain()?;
            }
            Ok(())
        })
        .await?
    }

    pub async fn call(&self, tool: &str, args: Value) -> ToolResult {
        if tool.len() > 128 {
            return ToolResult::error("tool name exceeds 128 bytes");
        }
        let result = self.dispatch(tool, args).await;
        let error = result.is_err();
        let mut history = self.history.lock().expect("history lock");
        if history.len() == 1000 {
            history.pop_front();
        }
        history.push_back(json!({"toolName":tool,"isError":error,"unixMs":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()}));
        match result {
            Ok(v) => ToolResult::json(v),
            Err(e) => ToolResult::error(e),
        }
    }
    async fn dispatch(&self, tool: &str, args: Value) -> Result<Value> {
        ensure!(args.is_object(), "tool arguments must be an object");
        match tool {
            "get_config" => Ok(self.policy.describe()),
            "set_config_value" => bail!(
                "security policy is local-only; restart ferroc with explicit CLI options (remote mutation disabled)"
            ),
            "get_usage_stats" => Ok(
                json!({"retainedCalls":self.history.lock().expect("history lock").len(),"uptimeSeconds":self.started.elapsed().as_secs(),"telemetryEnabled":false}),
            ),
            "get_recent_tool_calls" => {
                ensure!(
                    args.get("since").is_none(),
                    "since filtering is not implemented; use toolName and maxResults"
                );
                let n = integer(&args, "maxResults", 50, 1, 1000)? as usize;
                let tool = args
                    .get("toolName")
                    .map(|_| string(&args, "toolName"))
                    .transpose()?;
                let h = self.history.lock().expect("history lock");
                Ok(json!(
                    h.iter()
                        .rev()
                        .filter(|v| tool.is_none_or(|t| v["toolName"] == t))
                        .take(n)
                        .collect::<Vec<_>>()
                ))
            }
            "start_process" => {
                ensure!(
                    self.policy.allow_shell,
                    "shell disabled; trusted operators must opt in with --allow-shell (not sandboxed)"
                );
                self.processes.start(&args, &self.policy.roots[0]).await
            }
            "read_process_output" => self.processes.read(pid(&args)?, &args).await,
            "interact_with_process" => self.processes.interact(pid(&args)?, &args).await,
            "force_terminate" | "kill_process" => self.processes.kill(pid(&args)?).await,
            "list_sessions" | "list_processes" => self.processes.list().await,
            "prepare_file_transfer" | "send_file_transfer" | "receive_file_transfer" => {
                self.transfers
                    .call(&self.policy, tool, args, self.fs_gate.clone())
                    .await
            }
            "start_search" => self.searches.start(self.policy.clone(), args),
            "get_more_search_results" => self.searches.results(&args),
            "stop_search" => self.searches.stop(&args),
            "list_searches" => Ok(self.searches.list()),
            "read_file"
            | "read_multiple_files"
            | "write_file"
            | "edit_block"
            | "create_directory"
            | "move_file"
            | "list_directory"
            | "get_file_info" => {
                let policy = self.policy.clone();
                let tool = tool.to_owned();
                let gate = self.fs_gate.clone();
                tokio::task::spawn_blocking(move || {
                    let _lock = gate.lock().expect("filesystem gate");
                    crate::files::call(&policy, &tool, &args)
                })
                .await?
            }
            _ => bail!("unknown or not implemented tool: {tool}"),
        }
    }
    #[cfg(all(test, feature = "fleet-core"))]
    pub(crate) fn test_fleet_registration(
        &self,
    ) -> Arc<Mutex<crate::fleet::host::HostRegistration>> {
        self.fleet_hosts.clone()
    }
    #[cfg(test)]
    pub(crate) fn test_fs_gate(&self) -> Arc<Mutex<()>> {
        self.fs_gate.clone()
    }
    pub async fn shutdown(&self) {
        #[cfg(feature = "fleet-core")]
        self.shutdown_fleet_host()
            .await
            .expect("fleet host shutdown failed; cannot report drained");
        self.transfers.shutdown();
        self.searches.shutdown();
        self.processes.shutdown().await;
    }
}

fn prop(t: &str) -> Value {
    json!({"type":t})
}
fn def(name: &str, description: &str, properties: Value, required: &[&str]) -> ToolDefinition {
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema: json!({"type":"object","properties":properties,"required":required}),
    }
}
pub fn tools() -> Vec<ToolDefinition> {
    let s = prop("string");
    let n = prop("integer");
    let b = prop("boolean");
    vec![
        def(
            "get_config",
            "Inspect immutable local policy. No telemetry.",
            json!({}),
            &[],
        ),
        def(
            "get_usage_stats",
            "Inspect in-memory counters (retained history only).",
            json!({}),
            &[],
        ),
        def(
            "get_recent_tool_calls",
            "Recent call metadata only; no arguments or outputs retained.",
            json!({"maxResults":n,"toolName":s}),
            &[],
        ),
        def(
            "read_file",
            "Read local UTF-8 text up to 8 MiB. Absolute path required. Offset is zero-based; negative offset is tail. No URL/PDF/Office support.",
            json!({"path":s,"offset":n,"length":n,"isUrl":b}),
            &["path"],
        ),
        def(
            "read_multiple_files",
            "Read at most 32 local UTF-8 files, aggregate 8 MiB limit.",
            json!({"paths":{"type":"array","items":s,"maxItems":32}}),
            &["paths"],
        ),
        def(
            "write_file",
            "Write UTF-8 text; mode rewrite or append. Parent directory must exist.",
            json!({"path":s,"content":s,"mode":{"type":"string","enum":["rewrite","append"]}}),
            &["path", "content"],
        ),
        def(
            "edit_block",
            "Exact text replacement only. Match count must equal expected_replacements or file is unchanged. No fuzzy matching or Office formats.",
            json!({"file_path":s,"old_string":s,"new_string":s,"expected_replacements":n}),
            &["file_path", "old_string", "new_string"],
        ),
        def(
            "create_directory",
            "Create allowed directory and parents.",
            json!({"path":s}),
            &["path"],
        ),
        def(
            "move_file",
            "Rename within allowed roots; refuses overwrite. Not cross-volume copy.",
            json!({"source":s,"destination":s}),
            &["source", "destination"],
        ),
        def(
            "list_directory",
            "List allowed tree, depth 1..10, no symlink traversal, at most 10000 entries.",
            json!({"path":s,"depth":n}),
            &["path"],
        ),
        def(
            "get_file_info",
            "Basic file metadata only, no document introspection.",
            json!({"path":s}),
            &["path"],
        ),
        def(
            "start_process",
            "Start shell process only when operator enabled --allow-shell. Shell has full OS user permissions, NOT restricted by allowedDirectories. timeout_ms (0..30000) is observation time, NOT a kill deadline. Pipes, not PTY; output bounded to 1 MiB.",
            json!({"command":s,"timeout_ms":n,"shell":s}),
            &["command", "timeout_ms"],
        ),
        def(
            "read_process_output",
            "Read agent-owned process output. offset=0 consumes unread snapshot; nonzero offset is line snapshot/tail. timeout_ms only waits. No prompt detection.",
            json!({"pid":n,"timeout_ms":n,"offset":n,"length":n}),
            &["pid"],
        ),
        def(
            "interact_with_process",
            "Send input plus newline to an agent-owned process stdin (pipes, not PTY).",
            json!({"pid":n,"input":s,"timeout_ms":n}),
            &["pid", "input"],
        ),
        def(
            "force_terminate",
            "Kill live agent-owned shell tree. Does not target arbitrary host PIDs.",
            json!({"pid":n}),
            &["pid"],
        ),
        def(
            "kill_process",
            "Kill live agent-owned shell tree only, NOT arbitrary host processes.",
            json!({"pid":n}),
            &["pid"],
        ),
        def(
            "list_sessions",
            "List retained agent-owned process sessions only.",
            json!({}),
            &[],
        ),
        def(
            "list_processes",
            "List agent-owned process sessions only, NOT all OS processes.",
            json!({}),
            &[],
        ),
        def(
            "prepare_file_transfer",
            "Prepare an in-memory one-use X25519 receive key (60..7200s). Enabled by default; local --no-transfers disables it.",
            json!({"ttlSeconds":n}),
            &[],
        ),
        def(
            "send_file_transfer",
            "Encrypt a regular file (max 99 MB) as BRCX1 and upload ciphertext to tmpfiles.org; enabled by default; local --no-transfers disables it. No provider deletion guarantee; provider sees size/timing.",
            json!({"sourcePath":s,"recipientPublicKey":s,"expireSeconds":n}),
            &["sourcePath", "recipientPublicKey"],
        ),
        def(
            "receive_file_transfer",
            "Receive BRCX1 from validated tmpfiles.org HTTPS only. Verify AES-GCM/size/SHA256 before atomic destination commit; successful receive consumes in-memory key. No sender-identity authentication. Enabled by default; local --no-transfers disables it.",
            json!({"receiveId":s,"transferToken":s,"destinationPath":s,"overwrite":b}),
            &["receiveId", "transferToken", "destinationPath"],
        ),
        def(
            "start_search",
            "Start bounded background filename regex or UTF-8 content search. No symlink traversal. Read status/errors/truncation with get_more_search_results. 64 retained sessions maximum.",
            json!({"path":s,"pattern":s,"searchType":{"type":"string","enum":["files","content"]},"filePattern":s,"ignoreCase":b,"literalSearch":b,"includeHidden":b,"maxResults":n,"contextLines":n,"timeout_ms":n,"earlyTermination":b}),
            &["path", "pattern"],
        ),
        def(
            "get_more_search_results",
            "Read search snapshot with offset/length. Negative offset reads tail.",
            json!({"sessionId":s,"offset":n,"length":n}),
            &["sessionId"],
        ),
        def(
            "stop_search",
            "Request cooperative cancellation; done may become true later.",
            json!({"sessionId":s}),
            &["sessionId"],
        ),
        def(
            "list_searches",
            "List retained search session status.",
            json!({}),
            &[],
        ),
    ]
}
