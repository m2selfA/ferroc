# Windows agent explicit-proxy increment

## Identity and boundary

One local outbound policy for agent pairing HTTP, persistent ws/wss, encrypted uploads and encrypted downloads. No proxy daemon, relay replacement, GUI, tray, PAC/WPAD or NTLM/Kerberos was introduced. The existing optional native relay and unchanged BRC relay remain separate routes.

- Release: `target/release/ferroc.exe`, SHA-256 `a5fff3a8acd63cb8568f3e8dc72914fc1a8cc477189135479bf4d20c34030cb8`.
- Preview version remains 0.1.0. This executable was built before the initial Git commit and remains hash-addressed; committing the repository is not a rebuilt or published release.
- Historical icon binary `3e459bbf664344c6fd2bd8fb7c80ae9c381669b1b4c96b520e90b12d7e2e9691`, its source and receipts are preserved separately in `artifacts/before-agent-proxy/`.

## Static-confirmed contract

`src/network.rs` owns redacted proxy/CA state; `src/main.rs` selects it once for agent; `src/config.rs` exposes only `outboundNetwork` metadata. `src/transport.rs` uses it for pairing and WebSocket upgrade; `src/transfer.rs` uses it for all provider requests. The retained `pair()` library wrapper selects the standard environment policy.

- Explicit schemes: HTTP, HTTPS, SOCKS5 with local DNS, SOCKS5h with proxy DNS. URL auth supports HTTP Basic / SOCKS user-password, not integrated OS authentication.
- Precedence: CLI `--proxy` > nonempty `FERROC_PROXY` > reqwest standard environment matching. `--no-proxy` conflicts with CLI `--proxy` and bypasses all environment routing. Explicit proxy ignores standard `NO_PROXY`; failure never falls back to direct. Environment mode is a configuration label, not a per-request route attestation.
- HTTP requests and WS share locked reqwest0.12.28's connector. WS is ws->http / wss->https HTTP/1.1 Upgrade, then status/Upgrade/Connection/Sec-WebSocket-Accept and unsolicited extension/subprotocol checks before tungstenite client-role framing. There is no raw proxy-bypassing `connect_async` on the agent path.
- 5s connector and15s total WS-upgrade budgets; no HTTP request timeout is retained on the upgraded socket. Existing welcome/heartbeat/send budgets remain independent.
- Bundled WebPKI + platform roots remain enabled. Optional PEM roots trust BOTH proxy and target TLS, with certificate and hostname validation retained; OS trust is not modified.
- No raw proxy URL/user/password is logged, serialized into device credentials or returned to remote callers. Connector errors are classified without untrusted raw causes. CLI/env remain OS-visible; they are not secret vaults or zeroized-memory guarantees.

## Locally verified

- `scripts/verify.ps1 -Release`: fmt, locked strict all-target/all-feature clippy, **54 passed +1ignored** default Rust tests, release build and Windows resource validation. All7 embedded icon payloads and all7 group mappings match the canonical assets.
- Full default compile/harness hashes are frozen in `artifacts/agent-proxy/full-suite-source.json`. `first-full-agent_proxy.rs` preserves that exact scenario set. Later hostname/environment scenario strengthening is separately logged against the same release executable, not retroactively attributed to the first full run.
- Recording loopback HTTP/HTTPS/SOCKS fixtures use synthetic public auth and a public test CA/key. Negative cases cover wrong proxy auth, unreachable proxy for both fresh pairing and token-authenticated WS (zero requests at a directly reachable origin), malformed configuration/conflicting flags, untrusted proxy or relay CA, wrong hostname, invalid/duplicate WS accept, unsolicited extensions/subprotocol, redirect/407 distinction, credential non-persistence and log redaction.
- Stalled upgrade stops at the15s deadline. A frame appended to101 headers is preserved; a later frame after16s still arrives, proving handshake timeout is not a connection lifetime.
- Production transfer handlers roundtrip100000 bytes through the authenticated HTTP proxy, including landing-page resolution. Test-only provider override uses127.0.0.2 mapped by the fixture to the actual127.0.0.1 listener; a direct HTTP probe fails first. Exact3 proxy connections /3 provider requests, no Proxy-Authorization at provider, rejected auth causes zero provider requests, key retained and no output file; corrected route can retry and consume key on successful commit. This is component/fixture evidence, not a public-provider transfer.

- Same-release selected suite: **12 passed**. Evidence is separated:5 agent-proxy test functions execute the recorded release;2 agent handshake negatives +1 lifetime test link Rust test-profile Network code;1 native relay+agent OS-process roundtrip executes the release and1 SQLite test links Rust Store code;2 transfer-default CLI test functions execute the release. The combined log is `artifacts/native-release-roundtrip.log`.
- Release proxy matrix:6 authenticated scenarios (HTTP->HTTP, HTTP CONNECT->TLS, HTTPS CONNECT->TLS, HTTPS proxy->HTTP, SOCKS5->TLS with localhost resolved locally, SOCKS5h->TLS with unresolvable relay.invalid passed to proxy). Each completes real child-agent pairing and get_config RPC; origin rejects leaked Proxy-Authorization, output rejects username/password and Basic-encoded credentials.
-8 environment/precedence scenarios pass: HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY=* /CIDR/domain, force-direct, CLI overriding invalid FERROC_PROXY and NO_PROXY. The IPv4/IPv6 address-type check on SOCKS5 uses an actual hostname, not an IP literal as a false DNS proof. A later release-only control also checks unreachable proxy for both pairing and WS without relaxing the original assertions.
- Same release vs unchanged pinned Node relay: **7 groups +14 canonical OAuth/MCP checks passed**, cleanup verified. The separately invoked original-Node BRCX1 oracle: **1 passed**, original source blob `d541a49af6a0c3371e1d6726a6b80de84d3e3997`, mocked filesystem/provider only. Node retains its experimental TypeScript-transform warning; no test warning was hidden or interpreted as algorithm failure.
- Final source/binary/harness receipts are regenerated after these logs, not copied from the historical3e459 build.

## Failure evidence and corrections

1. `focused-first.log` preserved two failing assertions, not accepted as a pass. The NO_PROXY wildcard incorrectly routed IP targets through the proxy. Locked hyper-util0.1.21 source proves IP matching bypasses the domain wildcard branch; the local environment-only bypass-all guard fixes it. CIDR/domain/wildcard/direct/explicit-override controls remain strict.
2. The initial407 test did not save stderr and could only establish a failed expectation, not the original OS transport cause. A subsequent isolated probe recorded407. The fixture now drains its bounded request body before closing so authentication refusal is not mixed with early-close transport effects. No direct fallback or credential overwrite was permitted in either case.
3. `transfer-metric-control.log`:3 provider requests used2 keep-alive proxy connections. This was a test-metric error, not a missing transfer request. The fixture now closes each non-upgrade HTTP hop and strips proxy auth before forwarding; provider explicitly rejects leaked proxy-auth headers. `transfer-metric-fixed.log` and `transfer-no-direct-route.log` show exact3/3 and successful crypto roundtrip. TLS tunnels are still counted as connections, never misrepresented as observable inner HTTP requests.
4. Strict clippy found a large Proxy enum variant and a test `.err().expect()` pattern. Both were corrected, not suppressed. Failure logs remain archived; `artifacts/agent-proxy/clippy-final.log` is clean.

## Independent review: blocked observation, NOT approval

Two final advisor calls returned Not done yet. Both reported no test records and treated their own or already-terminal Fabric jobs as pending, despite the source/diff/log/hash evidence read immediately beforehand. The second call still cited the obsolete failed replacement even though the current `tests/agent_proxy.rs` has the unreachable-pairing/WS control and its terminal log records zero direct-origin requests. Advisor's test_result surface returned only85characters and did not establish visibility into the persisted Fabric shell evidence. Raw outputs are preserved in `artifacts/agent-proxy/advisor-first-review.log` and `advisor-second-review.log`.

These statements conflict with the actual on-disk implementation, terminal exit0 results and revalidated receipts; they are not accepted as proof of a missing implementation or failed test. All concrete checks requested by the review were either rechecked (source, route consistency, protocol/NO_PROXY/auth/malformed/unreachable cases, regressions, hashes) or retained as explicit unverified scope (all-protocol release-provider/WAN transfers). No production fixture override was added to erase that boundary.

**No independent advisor approval is claimed.** The implementation and local evidence are delivered as a development preview; independent-review closeout remains blocked on restoring its evidence observation, tracked separately. This is not a security-audited/production-qualified release. Repeating unchanged tests or relaxing assertions to satisfy stale telemetry is not a valid remedy.

## Unverified / not claimed

Real configured LAN/WAN proxy, public relay TLS/deployment, real tmpfiles.org upload/download, 99MB HTTP transfer, SaaS connector sessions, PAC/integrated authentication, Linux/macOS native execution and production load remain unverified. Existing99MB tests are local crypto in Rust test profile, not release-binary/WAN throughput evidence. Loopback TLS uses explicit per-client fixture trust, not a real production certificate chain or modified OS CA store.

Fixtures terminate their listeners/tasks/child processes; temporary pair credentials remain separate from user homes. No registry, persistent proxy/environment defaults, Windows CA store, user credentials or existing relay service is intentionally changed. Final source/binary/whole-addition patch/harness/certificate closure passed, including no residual ferroc processes. Negative controls reject historical-binary reuse, proxy receipt binary mismatch and altered evidence hashes. Advisor observation/review status is tracked separately below.
