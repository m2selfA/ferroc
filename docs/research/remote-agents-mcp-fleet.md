# remote-agents-mcp fleet 互传：源码研究

## 结论和证据等级

研究对象为 [47-ronn/remote-agents-mcp](https://github.com/47-ronn/remote-agents-mcp)，固定提交 **`18a7317d4c0bd0d39890bb752989f6e1cdce20a7`**（提交日期 2026-11-10）。workspace 声明版本 `0.1.49`，许可证 MIT。以下上游链接均固定到此提交，而不是浮动 main。

- **static-confirmed**：通过 GitHub MCP `get_repository_tree`、`list_commits`、`get_file_contents` 检查源码。20 份原文快照逐一用 `git hash-object --no-filters` 对照 MCP 返回的 Git blob SHA-1，一致；快照和清单保存在本地忽略的 `artifacts/research/remote-agents-mcp/`。
- **locally-verified / isolated component**：原样包含其 `sync.rs`，用与 `types.rs` 字段一致、去除 serde 的 `ManifestEntry` 镜像编译隔离探针。6 个上游单测及 3 个对照测试全部通过。哈希字段是合成比较输入；没有执行上游文件散列或网络传输。
- **not-run**：完整上游程序、真实公网 NAT、直连中断转中继、代理、吞吐及生产数据集。源码中的测试和注释不是本次执行证据。
- ferroc 对照基线为 **`02e5842c7876b52bef9b80d234772d429a9d182c`**。本文不代表 ferroc 已实现 fleet 功能；建议见 [实现规划](../design/fleet-transfers.md)。

来源边界：[Cargo.toml](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/Cargo.toml#L14-L18) 的 `repository` 字段指向另一个地址，不能据此把本次所读代码归属给 Anthropic。实际读取来源是上述 owner/repo/commit。[LICENSE](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/LICENSE) 要求复制实质代码时保留版权与许可；实施时若复用代码须更新 ferroc NOTICE/许可副本。本次不引入上游产品代码。

## 1. 功能声明与真实实现

| 能力 | 源码实际行为 | 证据 |
|---|---|---|
| `send_file` A→B | `agent_id` 选源主机 A，`dest_id` 选 B，立即返回 transfer id；B 必须允许写入 | [工具定义](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/mcp_server.rs#L221-L254)、[代理源发送](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/connection.rs#L983-L1112) |
| 流式单文件 | 先读整份源文件计算 SHA-256，再按片读取；不是整文件载入内存。非末片最多 32 个在途，最后一片等待此前 ACK 后发送，并携带整文件 SHA | [stream_file](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/transfer.rs#L215-L287) |
| 目录同步 | 双方生成 manifest，求差异，只重传新增/变化的**整份文件**；不是 rsync 滚动校验或文件内部块级 delta | [diff_manifests](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/sync.rs#L28-L84)、[run_sync_agent](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/connection.rs#L1465-L1575) |
| size+mtime | `size 不同 OR 源 mtime > 目标 mtime`，并非 `mtime !=`。目标拷贝后保留写入时间，用“更新于”避免重复同步，但可能漏回溯修改 | 同上 `sync.rs` |
| SHA 比较 | `checksum:true` 比较两个 manifest 的 SHA；任一缺少 SHA 则重传 | 同上 `sync.rs` |
| 直连/回落 | WS 信令交换候选地址及 nonce；STUN 和局域网候选打洞；成功后尝试 QUIC，QUIC 建链失败退自研可靠 UDP ARQ，UDP 不可用则 WS relay | [UDP transport](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/udp_transport.rs#L100-L279)、[三层选择](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/udp_transport.rs#L295-L405) |
| SHA 终验 | 接收端在 eof 时读回目标文件计算 SHA，对比发送方提供值；不是每个数据片都独立 SHA 终验 | [receive_chunk_raw](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/transfer.rs#L148-L205) |
| `transfer_get` | 到**源主机**查询进程内 registry：queued/running/done/failed，bytes/total，files_done/files_total，via/error；目录 bytes 在文件完成时累计 | [store](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/transfer.rs#L35-L113)、[结构](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/shared/src/types.rs#L282-L342) |

默认分片 256 KiB，单文件窗口 32；目录最多并行 4 文件。这是源码配置，不是建议照抄的性能结论。[配置](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/config.rs#L348-L358)、[目录引擎](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/transfer.rs#L304-L372)。

## 2. 调用链闭合

```text
MCP send_file(agent_id=A, dest_id=B)
  → SendFileTo 路由到 A
  → connection::begin_send_file / relay_controller::begin_send_file
  → TransferStore.start + 后台任务
  → transfer::stream_file
  → send_file_slice
      direct: 加密 raw → FileData → UDP/QUIC channel
      relay: FileRecv(base64) → 加密 command → WS relay
  → B 的 raw 接收 / executor FileRecv
  → mode/path 检查 → receive_chunk_raw → 按 offset 写入 → eof SHA
  → 应用 ACK → A 更新进度 → transfer_get(A)
```

两种源宿主分别有 sender 编排代码，不等于两套文件算法。[controller sender](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/relay_controller.rs#L791-L879)、[agent sender](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/connection.rs#L892-L967)、[接收权限及查询](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/executor/mod.rs#L352-L419)、[raw 接收模式检查](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/executor/mod.rs#L572-L599)。

## 3. 应借鉴与应改进的边界

### 借鉴

控制面与字节通道分开；MCP 返回 id 而不等待大文件；有界在途窗口；最后一片作为完整性屏障；目录差异逻辑纯函数化；排除规则同时作用于双方；删除默认关闭，且在文件发送完成后进行。

目录 walker 不跟随 symlink，排除规则可以剪枝，远端路径用 `/` 连接，避免 Windows 源把反斜杠目录结构写到 Unix 单个文件名中。[walker](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/files.rs#L114-L176)、[跨平台连接](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/connection.rs#L1114-L1134)。

### 不直接照搬

1. **散列失败不保全旧文件。** 接收端 `.truncate(false)` 打开最终路径，按 offset 写，eof `set_len` 后才检查 SHA。失败时旧内容可能已被覆盖。这不是“SHA 检测缺失”，而是“检测存在但提交不具失败原子性”。
2. **传输路径改变配额语义。** relay/base64 接收默认限 100 MiB，raw UDP 接收不受此上限；目录 sender 直连时还会解除本地 relay cap。ferroc 应按协商配额统一管理所有路径，超限在写入前拒绝。
3. **回落不等于可靠续传。** 当前片直连发送失败/不可用时可选 relay；一旦 `via_udp=true`，应用 ACK 等待超时会返回失败，而不是自动重发当前片到 relay。QUIC/UDP 失连下的可靠续传不能从 README 推出。
4. **QUIC 证书不是机器身份锚。** `AcceptAny` 连 TLS 签名检查都直接接受；该实现依赖 nonce 和房间 Cipher。共享房间 AEAD 不能自动等同逐机器身份认证。ferroc 不照搬此 verifier。[QUIC](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/shared/src/quic.rs#L1-L145)、[Cipher](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/shared/src/crypto.rs#L1-L85)。
5. **进度不等于持久化提交。** registry 是内存 HashMap；所读实现没有持久化恢复或完成项 TTL。代理目录路径的 dry-run 也走 `store.done`，后者把 bytes 置为 total，不能据此声称已传/已落盘。[dry-run](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/connection.rs#L1440-L1454)、[计划早退](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/src/connection.rs#L1491-L1508)。
6. **不要拿局域网或注释吞吐当公网证据。** 它包含 [集成测试源码](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/mcp-server/tests/transfer_e2e.rs) 和 QUIC loopback 测试；本次未运行这些测试。STUN 是 Google/Cloudflare 列表，且测试可用环境变量跳过，[见实现](https://github.com/47-ronn/remote-agents-mcp/blob/18a7317d4c0bd0d39890bb752989f6e1cdce20a7/crates/shared/src/udp.rs#L640-L664)。

## 4. 本地隔离对照结果

探针用 `rustc --edition=2021 --test` 直接包含固定原文 `sync.rs`，不修改上游函数；仅镜像四字段输入类型，不测试 serde。日志为本地 `artifacts/research/remote-agents-mcp/isolated-sync-probe.log`。9 测试通过，初版自建探针的缺少 `fn` 语法错误已修正并重编译后才采纳结果。

| 输入：两个条目均 size=4 | quick 结果 | checksum 结果 |
|---|---|---|
| 源 mtime=100 / 目标=200，哈希字段不同 | 跳过（本地实测） | 重传（本地实测） |
| 源 mtime=300 / 目标=200，哈希字段相同 | 重传（本地实测） | 跳过（本地实测） |

这验证了**比较函数行为**，不是原生程序、实际文件 SHA、网络互通或接收失败保全测试。后者必须在 ferroc 实施阶段独立验证。
