# ferroc fleet 内机器互传实现规划

> **状态：用户要求停止 Advisor 咨询并继续实现；P0 原语保留既有证据，P1 已开始源文件 IO 候选，网络通道尚未接入，未提交/未推送。** 起始默认沿用本设计，工具名仍不是已可调用接口。新增候选格式及明确缺口见 [P0 core](fleet-p0-core.md)。
>
> 基线：ferroc `02e5842`；参考源码、固定提交与证据分层见 [研究报告](../research/remote-agents-mcp-fleet.md)。不计划与 remote-agents-mcp wire 兼容。

## 1. 推荐方案

**一套 fleet 引擎、同一个原生 relay 进程/HTTP 端口；先实现安全的 relay 流式通道，再做目录增量，最后加入认证 QUIC 直连优先。** 最终 `auto` 策略先尝试直连，失败回落 relay；开发阶段 relay-first 不应被标成最终直连能力。

保留现有 tmpfiles.org/BRCX1 三工具和默认开启行为，不把其 99 MB 整文件加密上传接口改名为 fleet 互传。新 fleet 功能先本地显式开启，`--no-transfers` 必须一并禁止 fleet；旧 stdio 25 工具、原 Node relay 互通、代理、GUI drain 和 tag-only CI 不回归。

首版 fleet 定义为**同一 ferroc 原生 relay 管理实例中获准配对的设备集合**。当前不是多租户系统：OAuth client 不等于用户/租户，也没有已验证的逐用户设备 ACL。跨 relay、跨管理域、互联网任意地址互传不纳入首版。

## 2. 现状与缺口

| 已有实现 | 可复用 | 不可直接假定 |
|---|---|---|
| `src/relay.rs`：设备配对、OAuth MCP、paused/revoked、连接 generation、32 长度 outbound 队列 | 管理域、凭据校验、连接替换与审计 | fleet 路由、用户级 ACL、字节中继均不存在 |
| `src/protocol.rs` / `src/transport.rs`：v1 call/result，单帧 1 MiB；agent 最多 4 RPC，调用最长 120s | 日常工具保持原协议 | 不能把大文件装进 RPC；当前 relay 明确拒绝 binary/未知 agent frame |
| `src/transfer.rs`：99,000,000 字节限额、X25519/HKDF/AES-GCM、tmpfiles.org | 算法、测试经验；临时文件→sync→原子提交原则 | 现有格式整文件缓冲、没有发送者身份认证，不能直接做无限流式 fleet |
| `src/config.rs`：allowed roots、ADS/父级路径校验 | 两端本地不可远程放宽的路径政策 | 当前路径政策明确不是防本机竞态沙箱 |
| `src/network.rs`：统一 HTTP/WS 代理及凭据脱敏 | fleet WSS 必须走同一 Network | HTTP/SOCKS CONNECT 不自动提供 QUIC UDP 支持 |
| `src/store.rs`：relay SQLite KV/TTL/audit | relay job/grant/receipt 元数据 | agent Runtime 当前无持久化 job journal；若新增要明确是本地存储文件，不是已有能力 |

精确入口：[relay](../../src/relay.rs#L74-L138)、[v1](../../src/protocol.rs#L1-L5)、[旧传输原子提交](../../src/transfer.rs#L450-L489)、[路径政策](../../src/config.rs#L10-L105)。

## 3. 控制面与传输面

```text
MCP client ── OAuth /mcp ── 原生 relay：fleet coordinator + existing SQLite
                                  │                     │
                          source A /fleet/ws     destination B /fleet/ws
                                  └── 加密有界字节转发 ────┘
                                  ╰══ 认证 QUIC 直连 ════╯
```

建议增加同源 **`/fleet/ws`**（控制+数据）及只描述协议版本的能力发现端点，仍复用原 relay 进程、HTTP 端口、device bearer 和 Network。不新建独立传输服务、TURN daemon 或对象存储。额外 WS 连接用于隔离 fleet 扩展，避免给已有 `/ws` 注入会被旧实现拒绝的二进制帧；不提升全局 BRC `VERSION=1`。

`/fleet/ws` 有独立 `fleet/1` 握手、会话 generation、设备配对 epoch 和额度协商。无此端点/无本地 fleet 授权时，报告 `FLEET_UNSUPPORTED`，不发送新帧到旧 BRC socket。旧 25 工具照常；只在启用 fleet 的原生 relay MCP 注册 fleet 工具，离线时仍保留查询工具和清晰错误。

两端身份取自鉴权 socket，不信任客户端填写的 from-device。coordinator 校验 source≠target、同管理域、两端配对/在线/未暂停、两端能力和本地准入；随后发短期、绑定双方设备/会话/transfer/权限的授权。agent 再独立检查读写根目录与本地额度。dry-run 只授予双方 manifest 读取，不以规划为理由获取目标写权限；apply 才请求写入授权。relay 端 client 权限不应被伪称现有用户 ACL。

控制队列与 bulk 队列分开，有界且控制优先；reserve 心跳/撤销通路，数据拥塞不能挤占旧 RPC 或心跳。relay 默认不落整份文件，只转发有界密文；源/目标负责 stage，relay 现有 SQLite 存状态、额度与收据。

## 4. 建议 MCP 合同

fleet 工具属于**coordinator 层**，不冒充 agent 25 工具或 text `read_file`。字段采用 ferroc 的 camelCase。起始实现仅原生 relay MCP；GUI 本机 HTTP/stdio 在后续有 FleetContext 时再接入同一服务。

| 工具 | 必要输入与约束 | 返回语义 |
|---|---|---|
| `send_file` | `sourceDeviceId`, `targetDeviceId`, `sourcePath`, `destinationPath`, `idempotencyKey`；两设备必须显式填写。`overwrite` 默认 false | `{transferId,state:"queued"}`，不表示文件已发送成功 |
| `sync_dir` | 同上两个设备与目录；`compare:"checksum"|"size_mtime"` 默认 checksum，`dryRun` 默认 true；apply 提供前次 `planId`；`exclude` 同时作用双方；`delete` 默认 false | dry-run 返回可分页计划、`wouldTransferBytes`、manifest/规则指纹与 `planId`；不是 completed/已写入字节 |
| `transfer_get` | `transferId`；校验请求的管理域和调用权限 | 阶段、双方、计数、实际路径历史、错误、收据及 `stale`；不依赖调用者记住源主机路由 |
| `transfer_cancel` | `transferId`，幂等；不放宽原调用权限 | 先返回 `cancel_requested`，目标确认 stage 已停止且清理后才为 cancelled；若已提交则返回已提交 |

`idempotencyKey` 绑定整个参数摘要，不同参数重用必须拒绝；不能把一次 MCP 超时当作任务已取消或再次创建的许可。apply 重新验证 plan 的文件身份/目的地前置条件；陈旧计划拒绝并要求重新规划，不静默覆盖。

`transfer_get` 建议字段：`phase`, `sourceDeviceId`, `targetDeviceId`, `bytesTotal`（扫描时 null，不等于零字节）, `bytesSent`, `bytesReceived`, `bytesCommitted`, `filesPlanned`, `filesCommitted`, `filesSkipped`, `currentFile`, `activeTransport`, `transportHistory`, `fallbackReason`, `updatedAt`, `stale`, `errorCode`, `commitReceipt`。重传不重复累计逻辑进度；计划量、网络量、stage 接收量和最终提交量分开。

## 5. 文件事务与 wire 不变量

建议状态：`queued → preparing → transferring → verifying → committing → completed`；目录增加 `scanning/planning/planned`。旁路为 `cancel_requested/cancelled/failed/interrupted/commit_unknown`。`planned` 没有传输副作用；`commit_unknown` 不是可盲重试的 failed。

1. 协议先固定版本、长度前缀、最大帧及黄金字节向量。`PREPARE/READY/DATA/ACK/FINISH/COMMIT_ACK/CANCEL/STATUS` 均绑定管理域、双方设备、当前会话 epoch、transferId、fileId；DATA 有 offset、真实长度、seq。禁止整数溢出、越界、错误身份、冲突重叠、未覆盖完就 EOF；重复相同片可幂等 ACK。
2. 在**目标目录同一文件系统**独占创建随机 stage，不直接打开最终路径覆盖。统一全文件大小/总 stage 配额/并发/保留磁盘余量；不能因 relay→QUIC 切换就取消限额。失败及取消清理 stage，旧文件不动。
3. 分片读写与 SHA 使用有界缓冲，不整文件 Vec、不逐片打开路径。网络 ACK 只表示 stage 接收，不等同持久提交。`FINISH` 须验证完整范围、长度及经过身份保护的发送方 SHA-256；目标读回 SHA 后 sync 文件，重新检查 policy/目标前置条件，再原子 no-clobber 或受控替换；复用 Runtime 的 fs_gate，仅在最终检查/提交短临界区持有，不跨网络等待持锁。它只协调本进程工具，不声称解决外部同权限进程竞态；按平台能力处理父目录持久化。
4. 单文件 SHA 不等于认证；元数据和终验 digest 必须纳入认证消息。复用 X25519/HKDF/AES-GCM 算法，不复用 BRCX1 一次性收件格式。引入设备身份签名/固定公钥，绑定临时密钥交换；派生每方向/每文件的密钥，定义 seq nonce 唯一性和上限。重发发送**原封不动的已缓存密文**，不对变动内容复用 nonce。
5. QUIC 使用经验证、固定身份绑定的双向证书/公钥认证，不用 AcceptAny；首次身份固定、密钥轮换与操作员核对流程须在 P0 定义。可信 relay 初次分发的身份目录不自动抗恶意 relay 替换；未做带外核对/固定身份前不宣称零信任。
6. 只有接收端持久化提交收据后发出的 `COMMIT_ACK` 才令任务 completed。rename 成功但 ACK/日志回复丢失时，进入 commit_unknown，按 transferId 查询目标收据/散列，不重新覆盖。journal 先记录 committing；重启恢复需核实文件与收据，不能把 DB 与文件 rename 假设成同一事务。
7. 并发改写的源不是一致性快照。检查打开文件身份、大小、mtime 与实际读取长度，变化则失败；这仍不证明任意外部写入下的一致性。严格备份需要业务停写、不可变输入或可选快照/私有副本，并为副本计入磁盘预算。

数据块经 relay 时只转发密文，但 native relay 是 MCP 终点，会看到工具参数、路径、设备、大小和时序。不能把数据块加密写成“relay 完全看不到元数据/零信任控制面”。

## 6. 可靠切路与代理

最终路线为 **QUIC 优先 → relay**；不复制自研可靠 UDP ARQ，可靠传输交给 Quinn。UDP 用于候选探测/打洞，文件走认证 QUIC stream。参考项目声明 `quinn="0.11"` 范围，不等于某个 patch 已被 ferroc 编译或通过 glibc 验证。

- 提供 `auto / relay_only / direct_only` 三策略，用后两项做独立控制实验。auto 有明确建链预算，失败理由可见，不用固定 sleep 猜测已连通。不能承诺对称 NAT/CGNAT 一定打通。
- 同 LAN 收集合法候选；公网使用操作员配置的现有 STUN，或在**同一 relay 进程**增加可选 UDP 反射能力，不部署额外 daemon。没有 STUN/未开放 UDP 时仍可用 relay。不能从 TCP/WS 对端端口猜 UDP 映射。公网 STUN 的可达性与隐私应单独记录。候选个数/探测速率/总时长有上限，默认拒绝 loopback、广播、多播、云元数据及未授权链路地址，LAN 范围服从本地政策；loopback 仅显式测试模式开放。不自动改防火墙/UPnP，不把授权 peer 当成任意 UDP 扫描入口。
- 网络断流后的自动切路必须靠应用 ACK、接收范围及幂等片实现，确认缺失范围后重发；不能仅重新发整个工具调用。v1 最小版本可 fail safely，不支持同任务无损切路时必须标为 relay-only/无续传；最终 auto 验收须覆盖半途 QUIC 断开。
- QUIC socket/流和控制握手分别设 deadline；区分建链预算、无进展 idle timeout、任务总 deadline。流控等待不是自动认定断链；失败切换不重置总 deadline。
- **显式代理不绕过。** fleet WSS 使用现有 Network。用户设 `--proxy` 时，默认 relay_only；只有本地明确允许直连才尝试 UDP/QUIC，界面显示该策略。普通 HTTP/SOCKS CONNECT 不作为 QUIC UDP 代理；不实现未验证的 SOCKS UDP ASSOCIATE。

## 7. sync_dir 的安全语义

首版是**单向新增/更新，整份变化文件重传**，不做双向合并、块级 rsync delta、ACL/xattr/硬链接/稀疏布局等价保证。manifest 要表达普通文件和目录，支持空目录；symlink、junction/reparse、特殊设备文件默认拒绝或显式列为不支持，不能默默穿越。

- 默认 `checksum`，准确比较内容但多一次磁盘散列成本；显式 `size_mtime` 才使用快速模式。快速模式建议 `size 不同 OR 规范化后的 mtime 不等`，并在成功提交后尽力保留源 mtime。双方协商时间精度、无法保存时间的降级行为；即使 size+mtime 相同也不能保证内容未变。所有**实际传输**仍 SHA 终验。
- 用 `/` 相对路径表示树，拒绝绝对/父级/ADS/NUL/设备命名空间和目标平台非法名字；不使用源系统的 Path.join 构造目标绝对路径。源/目标各自校验根。Windows 大小写、名称别名、Unicode/非 UTF-8 文件名冲突必须显式报告，不有损转换；不假设所有文件系统具有相同规范化行为。
- manifest 分页，页有条目数和字节上限，绑定 scanId/规则指纹/cursor；大树索引可落现有 SQLite 技术栈，不在内存累积无限 HashMap。扫描错误不能等同空目录，扫描前后变化须使计划失效或标为非快照。
- 计划包含双方 manifest 摘要、目标已有文件前置条件、排除规则、总文件数/字节/额度。apply 前检测目标并发修改；未知文件绝不当成“允许覆盖”。目录同步只保证**逐文件原子性**，失败时已提交文件仍存在；不是整棵树原子回滚。
- `delete=false` 作为安全默认。最小版本可以返回 `DELETE_UNSUPPORTED`；后续实现要求显式授权、可审核的删除清单/planId、目标再次核验，排除项永远不删，先传输全部成功再执行删除。优先隔离/回收而非永久删除；回收不可用时不静默转永久删除。

## 8. 生命周期与记录

以 agent 进程持有的 `FleetService` 管理 job，不挂在单次 120s RPC future 或 MCP 客户端连接上；MCP 断开不等于取消。复用 relay SQLite 存 coordinator 记录，agent 新增本地 journal 文件以保存 stage/提交元数据；不能说 agent 已有此存储。密钥仅保存在受控内存，不把凭据写入 journal。

首个版本不承诺进程重启断点续传：重启后明确 interrupted，并根据 journal 安全回收 stage/解决 commit_unknown。支持同进程路由恢复与跨进程持久续传是不同能力。完成项有 TTL、活跃项有上限；查询显示状态新鲜度，源离线不伪造完成。

暂停阻止新任务，既有任务如何排空必须与既有 GUI drain 语义一致；取消用独立显式接口。撤销设备应取消该授权并通知两端；直连 control-plane 失联时用短期授权租约到期 fail closed，不承诺网络隔离下立即撤销。commit 竞态以接收端提交点/收据为准。GUI 退出显示长任务并执行明确的等待/取消流程，不能为新 fleet 功能破坏原 HTTP 已接收操作的排空规则。

## 9. 建议模块与集成改动

| 文件/模块 | 规划改动 |
|---|---|
| `src/fleet/protocol.rs`（新增） | fleet/1 消息、能力、长度/额度、状态和黄金向量 |
| `src/fleet/service.rs`, `journal.rs`（新增） | 一套任务生命周期、幂等、查询/取消、授权与收据 |
| `src/fleet/receiver.rs`, `sender.rs`（新增） | 有界流、stage、SHA、提交及范围 ACK |
| `src/fleet/sync.rs`, `manifest.rs`（新增） | 纯 diff、分页扫描、计划/排除与目标冲突 |
| `src/fleet/relay.rs`, `peer.rs`（新增） | 同进程 router 扩展、fleet WS 转发、候选/认证 QUIC；按成熟度启用 |
| `src/relay.rs`, `store.rs`, `relay_auth.rs` | 复用认证并注册 fleet coordinator；不伪造多租户；审计参数摘要不写凭据 |
| `src/runtime.rs`, `transport.rs`, `config.rs`, `network.rs` | 持有可选 FleetContext、启动/关闭及本地政策/代理；旧工具与 `/ws` 继续独立 |
| `src/gui_service.rs`, `gui_windows.rs`, `http_mcp.rs`, `stdio.rs` | 后续复用同一 FleetService/Context，显示真实任务和route；无 fleet 上下文不冒充功能可用 |
| `Cargo.toml/lock`, `.github/workflows/ci.yml`, `tests/fleet_*` | 实施时才添加已核验依赖及本地/标签测试；Windows/Linux 产物明确编入所需 QUIC 能力；不添加分支/PR触发 |

模块是职责建议，不要求预先生成空壳或多个 daemon。跨平台安全文件提交需要审查 OS 句柄/符号链接竞态；若达不到沙箱强度，保留现有“本机同权限进程可竞态”的威胁边界。

## 10. 分阶段与验收门槛

| 阶段 | 交付 | 必须通过才进入下一阶段 |
|---|---|---|
| P0 协议与安全契约 | 固定消息/状态/身份与nonce、限额、逐文件事务、兼容策略；独立评审 | 黄金向量、恶意帧、跨设备/跨管理域、重放、超限、commit/cancel/ACK丢失测试设计闭合；身份与首配信任模型签收 |
| P1 relay-only 单文件 | 4个 MCP 工具的单文件部分，同进程 relay 新WS端点，SHA+原子提交+进度/取消 | 真实relay+A+B三进程；0B/1B/跨片/大于99MB/至少1GiB流式；内存随窗口而非文件大小增长；hash失败、磁盘满、断线不破坏旧文件；最终ACK丢失可查明 |
| P2 目录增量 | 分页manifest、dry-run/apply、checksum及quick、空目录、排除/冲突 | 首次全量、第二次零变化、单文件变化只重传该文件；同大小同mtime/回溯mtime的对照；1→嵌套树→10万文件；Windows↔Linux名称/mtime/链接负例。删除可继续禁用 |
| P3 direct QUIC + fallback | 候选/STUN、认证、策略/路径计数、同任务切路 | 强制relay/强制QUIC/auto独立探针；LAN→不同NAT→UDP封锁→对称NAT回落；半途断QUIC不重复提交；代理不直连、撤销/租约、丢包/延迟/idle/总deadline控制实验 |
| P4 GUI与交付 | GUI/HTTP/stdio共享入口和观测；当前两平台tag产物 | 旧25工具、Node互通、默认传输/禁用传输、GUI drain/托盘不回归；Windows/Linux真实二进制映射与hash收据；Linux ELF+实际glibc2.17门禁；独立源码/依赖复核 |

### 当前门禁核对：实现存在不等于资格签收

| 项目 | 已有证据 / 缺口 | 下一步边界 |
|---|---|---|
| P0 原语工程 | 双签/控制/本机续租/保护身份/fenced journal/清点/活跃 v9 结算/发送端 ACK 观察已有本地回归 | 不再当作全部未实现；工程通过不等于运行资格 |
| 历史独立源码复核 | 未取得有效独立签收；用户明确停止 Advisor 咨询 | 不再作为开发依赖，不伪称签收、不改插件权限；继续按实际代码和测试推进 |
| 当前平台资格 52 | 本机 WSL stub 报未安装，Docker/Podman CLI 缺失；没有本轮 Linux 原生证明 | 等待可用且明确授权的执行面，不擅选 SSH 或安装服务 |
| P1 源 IO / 流控 / 真实传输 | 已接入同 relay 候选 route 与 IO pump，真实 relay/Source/Target 三测试进程初验通过；仍无生产 MCP/CLI 入口 | 显式 router_with_fleet，固定公开测试签发，不能冒充运营注册、两机或 Linux/生产验收 |
| 获准并行纯 manifest/diff | 默认 checksum、quick 任意 mtime 差异、冲突子树阻断、目标额外项保留；10万内存条目验证 | 仅 dry-run 描述，不证明实际文件树、名称等价或 IO |
| P2 扫描与 apply | Windows本机有界扫描候选已实现：Policy/Runtime内真实目录与64KiB哈希，ReadSequence不是快照。另有只读目标预检：父目录须已存在且私有、解析后仍在目标根内、ASCII可移植名称剖面、目标缺失，并按有序计划摘要绑定；不建目录/不建文件/不覆盖。运营每文件授权和更新事务仍未完成 | 无远程扫描授权/分页/排除；预检不是发布许可或快照，无删除/apply，见[fleet-manifest-scan](fleet-manifest-scan.md)与[fleet-target-preflight](fleet-target-preflight.md) |


大数据最终门槛：逐步增加至可供使用的实际生产目录/EMPIAR 数据，不预设本机已拥有某数据集。记录数据集来源、完整 manifest/端点 SHA、二进制SHA↔commit、明确强制路线与实际路线字节、峰值内存、磁盘/网络指标和失败恢复日志；分节点/二进制/数据集独立存档。合成小测试和回环 QUIC 不能代替真实公网/生产级验收。

## 11. 下一步建议与仍待签收的选择

先做 **P0 审阅 + P1 relay-only 单文件**，不要先调 NAT 或做 GUI进度条。可并行细化纯 manifest/diff 测试，但共享 wire/身份/事务合同先冻结。现有 tag-only CI 首次执行和既有 GUI 真人验收仍是原来的独立事项，不能被本研究标成通过。

建议初始选择：原生 relay 同管理域限定；fleet 本地 opt-in；checksum 默认；dry-run 默认；删除默认禁用；显式代理默认不 UDP 绕行；无进程重启续传承诺。用户已批准以这些起始默认推进；具体 wire、身份、授权和事务合同仍须完成 P0 独立复核后冻结，不意味着现已上线。

研究阶段已完成源码与隔离算法对照；default-off `fleet-core` 已有控制体/双签、受保护身份/pin、本机续租、fenced SQLite journal/幂等、清点恢复及 v9 本地结算/发送端 ACK 观察的工程验证。它们仍未独立签收；源文件读取、有界流控和同relay候选网络生命周期已经接入组件，但不等于运营注册、签发或两机部署。**P0 整体验收、生产入口、全程序网络测试和有效独立签收不能由这些组件替代。** 历史独立签收和真实平台资格仍未获得；用户已明确停止 Advisor 咨询，复核根不再阻塞开发。源 IO/流控/relay+A+B 按原 P1 路线继续实现，不再不断新增 P0 前置条件；当前源 IO 见[候选合同](fleet-source-io.md)。

按本节允许的并行路线，新增纯逻辑 `manifest::diff`：checksum 默认；quick 使用 size 或任何 mtime 差异，不再只比较源端更新；额外目标只保留，文件/目录冲突阻断子树。结果仅是整文件变化的 dry-run 描述，没有扫描/apply/覆盖/删除权限；ExactUtf8Unqualified 不证明 Windows 名称或文件对象互不冲突。10万条内存清单实验不能替代 P2 的实际10万文件树、跨平台命名或网络同步验收；P0/P1/P2 均未因此签收。
