# Windows GUI / HTTP MCP preview

## 当前结论

已构建可运行的 GUI **预览**，不是完整人工交互/独立安全签收。以下路径均相对仓库根目录；不新增 Node runtime、独立 relay 或 Windows 服务，也不改变 CLI 本机 MCP 的 stdio 入口。

- GUI：`target/release/ferroc-gui.exe`，SHA-256 `68b1b8f4fdd7bc75926412f89c075133e2cf5f7e7f581f1cb06cd93dabb9dba0`。
- 构建：`cargo build --locked --release --features gui --bin ferroc-gui`。
- 上述二进制构建于基线 `546e2d3` 后的本地 GUI 工作区。GUI 源码增量由后续 Git 提交记录；维护提交不重建该二进制，也不把提交等同于 release tag、逐提交可复现构建或完整验收。
- 原 CLI release 未覆盖，仍为 `a5fff3a8acd63cb8568f3e8dc72914fc1a8cc477189135479bf4d20c34030cb8`。这不是新 GUI 的测试二进制。

## Registry 来源

使用 crates.io `windui = 0.32.0`，关闭默认 features，仅 Windows/gui feature 引入。没有 Git dependency、`[patch]` 或 dependency 源码修改。

- registry source：`registry+https://github.com/rust-lang/crates.io-index`。
- 实际缓存 `.crate` SHA-256：`464c6095750e6d24823007f877d63eaab32594e83dea4fca4d49c6331ca54fe5`，与 Cargo.lock 一致。
- 发布包 `.cargo_vcs_info.json`：`78a088c90bcf8d8367bb97f347814aef2994ccb2`。先前 Git HEAD `206c37e19a3428dcef600d0b4f55d7439a719233` 仅为研究历史，不能替代 registry 证据。
- 包声明 MIT OR Apache-2.0；MIT 选项原文保存在 `docs/licenses/windui-LICENSE-MIT`。

## 结构与隐藏窗口问题

`gui_service.rs` 负责一个后台 Runtime、loopback HTTP 和可选出站 relay；`gui_windows.rs` 只负责 WindUI 窗口/托盘与输入模型。`http_mcp.rs` 复用现有 MCP/Runtime。

已发布 crate 的普通窗口 `WM_TIMER` 只请求重绘，隐藏窗口不产生正常 `WM_PAINT`，托盘提示/退出意图可能滞留。普通 `App.channel` 也不是无条件替代品：隐藏 channel drain 仅在 resident 模式启用。

隔离 Win32 对照创建自己的隐藏窗口，`RedrawWindow(RDW_INTERNALPAINT)` 返回成功但没有 WM_PAINT；窗口与 class 均销毁。否决强制重绘方案，没有将其加入产品。

最终使用公开 resident API：

- 应用宿主每250ms刷新状态和落地托盘/退出意图，不依赖主窗口是否存在。
- 单例窗口可关闭/重建，输入与控制器模型不随窗口销毁。
- 子窗每100ms读取真实 `WindowState.minimized`，通过公开 `HotkeyCtx::default().close_window(key)` 声明延迟关闭意图。registry 的 `core::EventCtx` 没有这个方法；不伪造 API，也不直接调用私有 native handle。
- 托盘显示/隐藏、再次启动唤起、暂停/停止/排空退出均走公开 API；child window 单独设置同一 IconSource。

## 验证与证据层级

| 项目 | 结果与边界 |
|---|---|
| 全 feature / all targets | 62 passed，3项显式 ignored；不是声称ignored也已默认执行 |
| 当前CLI / 原版relay | 当前debug CLI `2959aee41d5c4f15893d38075862c3e4c21d16c42049087d9d562337ebf2ace7`通过7组互操作和原样14项OAuth/MCP；fixture与进程清理通过，不把旧CLI release当当前源码 |
| 严格 clippy / fmt | `-D warnings` 和 fmt check 通过；无新增lint豁免 |
| 显式原生 Windows 回归 | ignored测试单独运行通过：实际 SW_MINIMIZE/IsIconic→生产单例关闭观察器→零窗口托盘意图消费→重建保留输入→零窗口退出；根节拍与产品同为250ms |
| MCP SDK oracle | SDK1.30.0 实测 initialize/initialized、精确25工具、文件写读、默认shell拒绝、无认证401和DELETE；是 GUI-controller **组件测试二进制**，不是 GUI release 的复制按钮路径 |
| 最终 GUI release 离屏渲染 | 1.5×截图输出正常，进程exit0；源码禁止此模式启动监听，退出后0 GUI进程/0测试端口监听。离屏截图不等于真实窗口鼠标验收 |
| PE 图标 | 最终exe7尺寸payload及7组映射核验；Windows GUI subsystem2；窗口/托盘图标路由有源码与原生构造证据，不冒充逐个Shell像素读回 |
| 旧真实窗口 | registry/debug二进制`8cc4a052...`曾显示真实1.5DPI窗口，匿名HTTP401；这是历史二进制，不能冒充最终release |
| 真实悬停/右键/复制配置 | **live-blocked**：Cua background像素输入UIA busy，按工具允许前台重试后被同连接截图归属拒绝；命名会话也有transport归属失配。没有通过其他输入通道绕过该边界 |
| 独立 advisor | 初始/恢复未取得有效答复，120s/240s超时；最终 final-check 也在240s后超时（任务`9bf24645-1cf7-4f11-b483-a847153bf5fa`）。没有有效审阅结论，不声称独立批准；不自动重复同一路径 |

全量测试、native和SDK日志分别保存在 `artifacts/gui-tests-final.log`、`gui-resident-native-final.log`、`gui-sdk-component-postaudit.log`；SDK JSON 明确记录 kind、实际测试二进制hash和版本。release渲染、PE与source manifest为不同收据，不能混用。

源码审计 `scripts/audit-gui.ps1` 覆盖 tracked **和 untracked** 文件，生成并反向检查完整patch、逐文件SHA、固定二进制hash、GUI子系统及registry归档/实际缓存源码字节一致性；旧 unborn whole-addition脚本不适用于已提交仓库。实际registry缓存218个发布文件逐字节匹配，额外缓存文件仅允许Cargo标记；错误CLI/单字节篡改GUI副本均被固定hash拒绝，canonical未改动且未执行篡改副本。生成记录：`artifacts/gui-build-provenance.json` 与 `artifacts/gui-review.patch`。默认对比 `HEAD`，零差异工作区仍校验源码、二进制和依赖；需要审计已提交增量时指定 `-BaseRef HEAD^`。这些本机原始凭证、构建产物、规划笔记均不入库；仓库保留可复验脚本与此结论报告。

## 安全与操作边界

默认仅loopback，随机256-bit bearer，Host/Origin/重复头/会话/版本验证；最大64会话、30分钟TTL、4已接收调用、16 body readers、5秒body期限、1MiB消息上限。GET SSE返回405，JSON HTTP可用。没有公网OAuth接入或负载生产资格声明。

暂停/关闭只阻止新调用；已接收HTTP操作即使客户端断开或session DELETE也可能完成并改变状态。四个真实filesystem-gate写操作的受控对照验证排空，不能解释为事务回滚。可选relay保留原协议的连接/超时语义；共享Runtime下，relay重连的进程清理也会影响本地后台进程会话，未承诺路由间完全隔离。shell默认关闭，显式启用后是完整用户权限，不是目录沙箱。

复制配置含口令，只交给可信客户端；不会出现在状态/tooltip/普通日志。剪贴板桥接QA在未复制前超时，没有持久化口令，也没有验证完整复制/恢复路径。

旧QA进程405456已强制清理并归档，归档hash严格复核；这是受控测试拆除，**不是**优雅退出证据。原生fixture验证了独立的零窗口退出。所有原始失败日志与修正保留，包括metadata未启用gui、错误checksum文件假设、上下文API误读、SDK pnpm解析位置、两项大Err和toast借用lint。

## 重现

```powershell
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --features gui --bin ferroc-gui resident_native -- --ignored --nocapture --test-threads=1
cargo test --locked --features gui --test gui_service sdk_oracle -- --ignored --nocapture
cargo build --locked --release --features gui --bin ferroc-gui
.\scripts\verify-windows-resources.ps1 -Exe target/release/ferroc-gui.exe
$guiHash = (Get-FileHash target/release/ferroc-gui.exe -Algorithm SHA256).Hash
./scripts/audit-gui.ps1 -ExpectedSha256 $guiHash
```

SDK oracle需已有独立 `better-remote-commander/packages/relay` 的Node依赖；仅测试使用，GUI运行不需要Node。原生测试需要交互式Windows桌面，操作的仅是自己进程的独立窗口，不访问Cua私有状态。

## 后续验收

修复桌面工具的合法同连接capture/input会话后，或由操作员实际测试：右键菜单、hover状态随pause/resume变化、复制配置接入真实GUI release、再次启动唤醒。随后取得有效独立diff/证据复核；在此之前保持preview，不宣布完整GUI验收完成。
