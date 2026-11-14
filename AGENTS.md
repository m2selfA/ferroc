# ferroc — repository guide

ferroc = Ferrum + Commander，Better Remote Commander 的原生 Rust 重写预览。

## 技术栈与运行
- Rust 2024；CLI：Tokio/axum/SQLite；Windows GUI：crates.io `windui = 0.32.0`。
- `cargo build --locked --release`；CLI 本机 MCP：`ferroc stdio`。
- `cargo build --locked --release --features gui --bin ferroc-gui`。
- GUI 本机 MCP 是认证的 loopback HTTP；可选出站 relay 共用一个 Runtime，不新增中间服务。

## 代码与验证
- `src/runtime.rs`：工具执行；`src/transport.rs`：relay 协议；`src/stdio.rs`：MCP。
- `src/http_mcp.rs` / `src/gui_service.rs`：本机 HTTP 与生命周期。
- `src/gui_windows.rs`：Windows 主窗口、resident 宿主、托盘；`src/bin/ferroc-gui.rs`：可选入口。
- `cargo fmt --all -- --check`。
- `cargo clippy --locked --all-features --all-targets -- -D warnings`。
- `cargo test --locked --all-features --all-targets`。
- 显式原生/SDK 探针、图标和来源审计命令见 `docs/verification/windows-gui-preview.md`。
- Node 只用于可选上游/SDK 对照测试，不是程序运行时依赖。
- CI 只允许 tag push 触发；仅 Windows/Linux x86_64，Linux须通过 glibc 2.17 ABI和真实容器门禁；见 `docs/releasing.md`。
- CI 验证器：`python -B -m unittest discover -s scripts/tests -v`；不得仅凭目标后缀宣称 glibc 兼容。

## 必须保留的边界
- WindUI 必须使用发布 registry crate，不改 Git 依赖、patch 或全局依赖缓存。
- shell 默认关闭，传输默认开启；目录策略不是当前用户权限的沙箱。
- 暂停/退出阻止新接收，已接收 HTTP 操作可能继续产生副作用；退出须等待排空。
- 托盘状态泵依附 resident 宿主，不能依赖已隐藏或已销毁窗口的 WM_PAINT。
- 不记录认证口令/代理凭据；规划文件、`artifacts/` 和 `target/` 仅留本地，不入库。
- 上游溯源快照必须保持原字节；不要为格式检查改写它们。
- 仅在用户要求时提交；不自动 push。提交说明不能把代码提交视为发布或独立签收。

## Fleet 开发边界
- `fleet-core` 默认关闭，编入候选 P0 组件、本地 host、纯 manifest/diff 及 P1 源文件 IO/认证有界流控；不是运行时 fleet 开关，没有新增 MCP/CLI 工具；默认 router 不挂载 `/fleet/ws`，仅显式 `Relay::router_with_fleet` 在同进程/Store/listener 增加候选路由。
- P0 双签使用 suite 2（420 字节，绑定 job/grant 摘要）；旧 suite 1 向量只作历史 oracle，不允许降级。结构化 grant 校验不等于可信签发/目录权限；`job.rs` 原内存账本不承担崩溃恢复；新增持久元数据另走 `journal.rs`，尚未接入网络接收。`Runtime::open_fleet_host` 是默认暂停的本地候选 API，使用实际 fs_gate/同库 fence，不导出裸 File 或绕过租约的 stage 句柄。每 Runtime 仅一个附件；暂停拒绝新准入，close 等已接纳与排队操作排空后关闭 DB/fence。Runtime.shutdown 也停止/排空 host，但外持 DB/fence 仍由 close/Drop 释放，不能暗中免债；幂等重放不自动创建重试。`stop_creators` 终止/排空并关闭 DB/fence 后才签发一次性本机停止凭证；新 host 的 `recover_creators` 仍须不同 owner、相同 DB/父目录对象，只恢复 journal，不免债、不恢复接收。直接同 owner 免债仍禁止；缺失结算仍需独立本机审批与重新观测，现存对象不处理。`admit_receiver(LeasedRecords)` 是本地 DATA 写入候选：只用当前 CREATE_NEW 句柄，Target 双签租约逐 IO 检查；写前原子落盘 v4 意图，旧 reader 须拒开。File 先 Drop 后解除 host drain 计数；失败/到期/撤销/Drop 均不删除或免债。覆盖只在内存，v4 仍禁持久 verified/commit/重启续传；FINISH 读取序列观测不是提交许可。关闭 host 前须让 receiver Drop，不能同线程带着闲置 receiver 等 close。
- v5 `seal_finish` 消费 DATA writer，封存记录只是历史描述；v6 `SealedReceiver::reserve_commit` 在真实 Runtime gate 内重新完整哈希并持久化 intent，返回 Snapshot 不是发布许可。整段哈希不持 DB，gate 内只允许非阻塞 DB/SQL 准入；竞争须失败保留负债，不等 DB 锁，不放宽旧 DB→gate 清点路径。临时 SQLite busy_timeout=0 必须恢复，既有 schema 读取不能调用会重设5s并开启写事务的 attach。v6 verified 只描述该 Runtime 串行临界段的读回事件，不保证之后字节不变，也不防外部进程/mmap/shell。取消赢在 intent 前则不提交；intent 后只能 unknown，不清除 intent/负债。重启不发布/续传，v6 无 receipt/完成/免债路径。`prepare_commit` 返回的 `CommitCandidate` 保留原 File/活跃租约/同一个 host Operation，不从 Snapshot/JSON/重启重建，也不可克隆、解包或写 DATA；创建候选仍为 v6，不是缓存发布许可。观察仍不是稳定内容许可，续租只换活跃记录，不重写历史 intent_binding；到期/撤销/取消不能被新 grant 复活。Drop 只关句柄和排空计数，不删文件/免债；同线程 await close/stop 前须先 Drop 候选。新 publish 接入必须再次完整哈希并验证最终权限，不能拿旧 Snapshot 或候选创建时的 SHA 直接发布。
- Windows `attempt_local_publication` 消费活跃 v6 候选：整段 gate 内再哈希，先原子 v7/CommitUnknown，再 `SetFileInformationByHandle(FileRenameInfo,flags=0)` 改原 File，返回持同一 File/租约/Operation/父目录 guard 的 RenamedCandidate。不关闭原句柄再按源路径 rename，不调用旧 NamedTempFile publisher，不自动 fallback/retry。只有新分配 stage 创建时预留 DELETE，原持有者仍 share=3；专用 stage 验证读 share=7，身份/DB/fence/目录 open_private 仍 share=3，ACL/单链接检查不变。持有 gate 并以 no_wait 接入 DB 的 commit/rename/观察收据路径，禁止 db.journal()/attach 重设 busy_timeout5s，必须 existing_fenced+0超时并恢复。7 只允许 Unknown、保留原stage债务与历史绑定、无 receipt/完成/免债；即使 syscall 已改名后检查失败也不删目标。重启/新 grant 不重建 RenamedCandidate，观察/续租是活跃对象校验，不是对外部/mmap/断电的保证；仅原生Windows组件证据，P1仍关闭。
- Windows `RenamedCandidate::record_target_observation` 只消费本轮活跃原 File/租约，真实 gate 内再做完整 SHA/逐64KiB租约与对象检查，同库原子写 v8，返回 ReceiptedCandidate。TargetObservationReceipt 是单独历史观察元数据，不是 control::Receipt/COMMIT_ACK/完成/免债。v8 仍 Unknown 且 stage 债务完整保留（含0字节slot）；绑定 intent/size/SHA/原FD/父目录/会话与当次grant，不冒充最新续租授权或当前字节状态。父目录耐久性明确 Unsupported。SQL失败保留v7；SQL已提交后到期/取消/截短/替身可报错但v8观察已存在，不能当回滚/自动重试。恢复只读历史，不从Snapshot/观察/新grant重建live owner。失败消费的 owner 先撤销并关闭 File，再结束 Operation；不保留可重试能力，drain 归零不是债务免除。两个SQL窗口须分别测：mark前有writer则事务失败快退，mark后晚到保留writer不阻塞只读final检查/rename；收据提交确实需要写事务时必须0等待。既有DB→gate观察路径不扩大为新Gate→DB等待许可。
- Windows v9 `ReceiptedCandidate::settle_local` 必须再次持真实 gate 全量哈希、逐64KiB/SQL前后检查当前 File/parent/租约。只允许本轮活跃 owner：同库原子写 Completed/control Receipt，将原 StageReference 转为 settlement_origin 历史，移除 live stage 字节/slot；不得从历史、存在的目标或新grant结算。SQL未提交失败保留v8全债；SQL已提交后的错误可能已存在v9历史结算，不当回滚/删除/再签发。ACK必须在同一gate内、最终检查后一次编码，FinishedCandidate仅返回缓存帧；重复复制不是新证明，不能从Snapshot/Receipt重建。历史origin不是live文件位置/配额，重启Completed仍转Unknown且禁止metadata publication重放；最终收据和父目录Unsupported都只描述历史事件，不防外部/mmap/断电，不是网络P1。Finished持原File/parent直至Drop后才解除Operation，close/stop前须先Drop。
- `source::SourceEncoder` 是纯记录组件，不读 source 文件、不发送网络或维护持久 sender 状态。只接初始epoch且未尝试过加/解密的 Source LeasedRecords；编码器自持顺序字节计数与完整SHA，完整匹配才消费成 AwaitingCommit、一次编码缓存FINISH。计数名必须 bytes_encoded，不当已发送/收到。续租保留计数/SHA/总期限，FINISH后无DATA/renew或重建入口。只在现存epoch/时钟连续性内认证CommitAck后记录 PeerReportedCompleted；ACK/STATUS Completed/无关Duplicate均不完成。精确已接受帧只在原128重放窗口内幂等，不绕过窗口/时钟；新密文第二最终帧即使同Receipt也关闭consumer，旧历史不擦除。AEAD损坏不污染后续合法帧；已认证语义坏帧/时钟失连续必须反映fault。Source观察只是对端声明，不推断私有IO、因果时刻、当前文件、source持久完成或重启能力；合法对端甚至可预计算虚假ACK，原生v9只验证本地诚实实现路径，不当remote-attestation。
- `Runtime::scan_fleet_manifest` 仅Windows本机只读候选：复用Policy及registry→fs_gate，无SQLite/网络/签发，其他平台显式拒绝。保留原始祖先/目录句柄，拒绝reparse/多硬链接/非UTF8/保留名；全局预算含祖先队列，默认64MiB、硬上限1GiB哈希、64KiB块。错误/取消不返回部分manifest、不写/删除。结果是ReadSequence+ExactUtf8Unqualified；同Runtime串行化不防外部/mmap，恢复mtime的已读前缀改写已实测可绕过前后元数据检测，不能叫快照/最新SHA/目标名称资格。扫描错误不当空目录，无分页/排除/apply/更新覆盖能力；Runtime shutdown等已接纳同步扫描，5ms token不构成硬实时界限。
- `Runtime::preflight_fleet_target` 仅Windows本机只读候选，不建目录/文件、不覆盖、不删除、不取DB/fence、不签发grant。复用Policy与registry→fs_gate，保留原始祖先与父目录私有句柄并比对对象ID；要求父目录已存在（缺失整轮拒绝，不隐式mkdir）、解析后仍在给定目标根内、目标当前缺失（仅NotFound算缺失）。名称采用声明式窄ASCII剖面（保留设备名/尾随空格或点/保留字符/非ASCII/`.ferroc-fleet-`均拒绝而非折叠），并按ASCII忽略大小写检测计划内碰撞；不声称Unicode或8.3等价。结果携带有序(path,bytes,sha,job)摘要绑定，不能套用到另一计划；它不是发布许可、不是预留、不是快照，检查后仍可被并发创建。父句柄只在本次观测期间拒绝普通改名/删除，且只覆盖直接父目录。`PreflightLimits::allow_planned_directories` 默认 false；显式开启后只把计划自身声明的目录当作可缺失，且每个缺失目录须其父已存在或已在本计划更早声明，返回 `planned_directories()` 供接收方创建，仍不创建任何目录，也不给出真实对象ID（占位符 `planned-directory`）。目录声明实为文件、或计划文件同时是声明目录/目录祖先，整轮拒绝。
- `manifest` 是原计划允许并行的纯逻辑目录差异组件，不扫描/触盘/发送或执行计划。默认checksum且缺所需SHA失败，不降级quick；quick仅启发式，使用size或任意mtime不等（包括回溯），同size/mtime仍可能漏改动。精确UTF8键不lowercase/Unicode归并，Namespace::ExactUtf8Unqualified不证明Windows/实际FS名称或对象等价；原生资格/路径重观测/每文件授权和原子更新仍须后续完成。目标额外项只保留，无删除/apply；ExistingFile变化不是当前no-clobber publisher的覆盖许可。目录/文件冲突阻断子树但不误伤近似前缀。10万条内存metadata测试不是实际10万文件树/P2/网络验收；输入构造在验证前，不冒充解析器/网络分配上界。
- 用户已明确停止 Advisor 咨询；它不再是开发前置，不得继续调用、要求激活复核根或改插件来绕行。历史独立签收缺失仍如实保留。按原计划推进 P1 候选实现，但 Linux、两机和生产验收未完成，不宣称运行资格；relay+A+B 已有公开 cfg(test) 固定密钥/合成时间签发的三测试进程探针，不是运营注册或完整 agent；见 `docs/design/fleet-relay-channel.md`。
- `Runtime::open_fleet_source` 只接 fresh Source 租约并读取 job.source_path，普通源文件不套私有 DB ACL，仍拒绝 symlink/reparse/特殊对象及多硬链接。绑定原只读 File/父目录对象，真实 registry→fs_gate 顺序，无 SQLite 锁；单次最多 min(grant,64KiB)，IO前后检查租约/对象，明文缓存擦除。错误/revoke立即关闭源 File/parent 并关闭本轮能力；shutdown等待已进入同步操作，不等闲置 owner，后者下一次操作必须失败或Drop。完整编码流 SHA 才生成FINISH，不证明后来源文件字节仍相同；无持久 sender/续传/transport window，初版 SourceFile 尚无续租API。不能拿回传Vec数量当全局内存上界。
- P1 `SourceWindow` 只包装未编码 SourceFile：READY 前/窗口满不读内容，最多 WINDOW=8 个 Box 原密文；只有认证单调连续片边界 ACK 释放，selective received/STATUS/早到 final 不放行，旧序 ACK 不回退，新序回退失败关闭；FINISH 须排空，随后仍需最终 ACK。待确认密文上限 8*(64KiB+232)=526144B，不含调用者/网络复制、明文/编码暂存和队列元数据。Target READY/覆盖 ACK 只经活跃原 receiver/current对象/租约检查，缓存同字节；复用 gate→DB try/no_wait+existing_fenced，禁止 journal() 重设超时。flow启用后不续租，失败保留stage/债务；不把ACK当磁盘证明。
- `relay_channel` 只接显式本地 route approval，不等于可信签发/时钟/pin/文件授权；原设备 tokenHash/paused/revoked 与一次性 header ticket 必须同时有效，原生 protocol=1、拒Origin/query/重复认证头。16pair/32socket、每向8消息、64累计授权摘要（不淘汰重放记录），TTL是本机路由期限不是租约。全部消息有frame/message/write buffer上界，Reader/Writer/monitor整循环固定future；source单send副本并行收控制，最多8控制后poll同send并yield，避免丢帧/饿死deadline。仍初始epoch/no自动重连续传；断链不能删除stage/免债/回滚v9。Target final ACK送达未知必须如实报错，成功返回本地收据不证明Source接受。三测试进程与两机/运营/生产严格分开，HTTP代理新路由对照不等于TLS/SOCKS全矩阵。原生TCP/WS探针仅cfg(test)用bounded256事件观察满8队列/实际sink Pending/actor退出，不调原5s预算、不重建send future。opaque压力流不走SourceWindow，不冒充v9；独立v9后ACK失败另走真实SourceFile/window/Host.get/Inventory，Source错误与Target历史Completed分层。run_target_after_settle是私有同实现观察接缝，公共调用无操作回调，禁止由此开放File/DB/fence、恢复或新回调API。
- `sync_exec::run_plan` 先绑定计划有序JobSpec，再按台账pending索引逐文件 start→prepare(调用方闭包)→执行→settle/fail；准备可取消，实际Target job不符即失败且保留债务，不接管已有在飞owner、不复活终态；不建链不签发不持久化；每文件的准备与执行future必须装箱，否则嵌套状态可超过默认2MiB测试线程栈（实测0xC00000FD，装箱后默认栈通过）。
- `sync_exec::execute_file_cancellable` 的取消是**丢弃两端泵**：目标未结算时保留stage与全额债务、源保留文件，不向调用方返回收据，也不回滚或排空；若Target已先结算，历史v9收据/零债务可能存在，取消不能撤回；取消延迟受5ms轮询与既有阻塞IO约束，正在写的那一块可能已落地。它不等于优雅关闭或交付撤回。
- `sync_run` 取消是终态：`cancel(reason)` 在已失败或已完成时拒绝；在飞文件标为 Cancelled 且不结算、不回滚、不放债，调用方必须丢弃自己的泵；`status()` 只汇总本地台账与已接受收据尺寸，`Complete` 不等于交付或持久化证明。
- `sync_exec::execute_file` 只是单文件执行器：并发驱动既有源窗口与目标接收泵，两端都成功且源端认证观察到的收据与本地目标收据完全相等才算成功；它不创建链路/不批准路由/不签发/不排序/不重试/不重连/不持久化。顺序与单飞由 `sync_run::RunLedger` 持有，调用方负责准入与链接构造。
- `sync_run::RunLedger` 是内存台账：严格按计划顺序、同时最多一个在飞、只接受size与SHA均匹配计划文件的收据（不是文件路径或当前落盘证明）；任一失败即整轮阻断且已结算收据/字节保留，本对象内无重试与复活路径。它不发送/不持久化/不调度/不证明对端落盘，`settled_bytes` 只是已接受收据尺寸之和，不是流量或编码字节；未来执行器必须保持同一单飞顺序。
- `sync_grant` 只为一份 `sync_plan` 生成结构批次：每文件一条 no-clobber `ValidatedGrant`，会话非nil且两端不同，种子非零且不同，chunk 1..=65536，issued+lease 不得超过该 job 固定期限；授权与 epoch 按种子+索引摘要派生且每批唯一，同输入同 digest 便于重放审计。它不签名、不导入可信时间、不做本地策略批准、不发网、不调度、不落盘；消费方仍须验pin/签名/策略/准入后才能传。
- `sync_plan` 是纯计划器：只接收既有 `DiffPlan`+源清单，仅支持 checksum 与“目标缺失”的整文件新增；任何更新(已有目标)、类型冲突或阻塞子树都使整份计划失败，目标独有项只计数不删除，缺失目录只计数待接收方创建。逐文件键用 `prefix:digest16(path)`（job 键仅允许 ASCII 字母数字与 `._:-`），`JobSpec::validate` 复用唯一路径合同；计划不扫描/不触盘/不发网/不签发/不调度，不是执行许可。
- 续租是显式调用，不是定时器或签发服务：`SourceWindow` 仅在 READY 且无缓存密文、连续覆盖等于已编码前缀时允许；`SourceFile` 轮换前在同gate重验对象；flow 接收器保留窗口与已收区间、丢弃旧epoch控制密文并在下次控制调用重封装。注册表 `advance_local` 只接受同一 pair 的稳定身份、相同job摘要、不增大chunk、授权与epoch同时轮换且不复用，历史有界1024；推进后旧binding不可路由。续租被拒保留旧会话且不延长总期限；无法认证的帧（含旧epoch）拒绝但不毒化会话，认证通过但语义倒退才失败关闭。组件/本地 stage/源 IO/流控探针不可冒充三进程互传；三测试进程也不可冒充两机、QUIC/NAT 或生产数据验收。
- 公共会话必须走 `authenticate_leased` / `LeasedRecords`，不得把 peer 时间当可信 anchor 或开放裸 u64 now。续租不重锚定/延长总期限；回拨或双时钟分歧超 2s 关闭时间连续性；最多 1024 epoch，无旧密钥保留/自动重启恢复。
- 身份/pin 持久化走 `IdentityStore`：Windows CurrentUser DPAPI 或显式外部包装密钥，禁止明文降级、自动 TOFU、损坏重生或覆盖旧密钥。根/父目录是可信本地路径，ACL/mode 只验证不修复；不能把 Unix0600 当 OS 加密或把旧密文回滚当已防御。
- Journal 借用现有 SQLite 连接，要求 file-backed/FULL/正常日志模式；计数不是覆盖证据，intent 不是发布许可。旧 owner 必须外部 fence 后才恢复，提交后保持 unknown/历史收据，不能自动续传或删除持久路径；未知引用阻断新 stage 登记，不等于运行时配额重建已完成。
- Journal 正常入口必须经 `OwnerFence::acquire` → `open_connection` → `journal`，原裸 attach/连接导出仅 cfg(test)。锁固定 sidecar，不锁主 DB、不删除/截断 marker、不猜 PID/超时死亡。连接内部保留私有 guard，SQLite 先关闭后放锁；只支持已存在、私有、单链接本地数据库，既有宿主须采用先锁后开同库顺序，不能把 PRAGMA 文件名当旧连接文件身份的证明。Windows 探针通过不代表 Linux/网络文件系统资格。
- 旧 StageFile 组件 API 是 `verify_with` / `VerifiedStage::publish_with`，不是本地 HostReceiver 的发布路径，HostReceiver 仍禁直接发布；Windows 活跃 CommitCandidate 另有 v7 一次本地原句柄发布尝试，状态只到 Unknown，不等于旧组件 publisher 或最终收据。接入前须实测读回后同尺寸内容修改及最终 SHA 稳定性，不能只凭长度/共享 gate 认定内容不可变；同时验证取消可见性与 DB→fs_gate 锁序。旧无准入 `publish` 仅 cfg(test)。读回检查无法打断 OS 阻塞 syscall；最终回调须在真实 fs_gate 内绑定 job/revision/fence，并在 SQL fsync 后重查租约。StageRejected 被持有时保留 stage/配额；丢弃错误仍会触发尽力清理，不能当取消确认。
- 规模探针用 `scripts/measure-fleet-p0.ps1`，默认 release **测试二进制**；逐数据量独立日志/自有工作区，失败须确认 stage 回收。旧生产 exe 不由该探针替换。

## 当前状态与下一步
GUI 是预览。工程回归、原生生命周期和 SDK 组件探针已通过；真实托盘鼠标/复制配置验收及有效独立复核仍未完成。详见上述验证报告，勿把组件测试等同于 GUI release 的真实操作路径。
