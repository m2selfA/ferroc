# ferroc

**Ferrum（铁）+ Commander**。Better Remote Commander 的原生 Rust 重写，当前交付 **agent + 原生 relay/OAuth/管理台预览版**，不是全功能等价替代品。

```text
本地 MCP 客户端 ──stdio──> ferroc ──> 文件 / 进程 / 搜索
远程 MCP 客户端 ──OAuth/HTTPS──> ferroc relay ──WebSocket──> ferroc agent
                               或现有 BRC relay（兼容路线）
```

Rust 运行时不需要 Node.js。已有 BRC relay 可继续复用；也可用同一个 `ferroc` 二进制替换它，不需要叠加新的中间服务。原生 relay 使用 axum + SQLite；浏览器管理页由 Rust 直接提供。

## 项目图标

![ferroc icon](assets/icons/128.png)

Agnes 生成的明亮橙金 `F` + 青绿命令箭头。透明母图 [`assets/ferroc.png`](assets/ferroc.png)、Windows 七尺寸 [`assets/ferroc.ico`](assets/ferroc.ico)、独立 16–512px PNG 位于 `assets/icons/`。原图、提示词、来源与输出哈希位于 `assets/branding/`；`assets/generate-icons.ps1` 可离线重新导出。Windows 构建继续通过 `build.rs` 嵌入；浏览器管理页复用同一图标，不新增服务。可选 Windows GUI 预览复用同一资产作为程序资源、窗口与托盘图标；真实交互与验证边界见 [GUI 验证记录](docs/verification/windows-gui-preview.md)。

## 构建与运行

```powershell
cd .\ferroc
cargo build --locked --release
.\target\release\ferroc.exe --help
.\target\release\ferroc.exe --allow-dir E:\work stdio
.\target\release\ferroc.exe --allow-dir E:\work agent --relay https://relay.example.com --name MyPC
```

首次连接会在 **stderr** 显示验证地址和配对码；手动到现有 relay 批准。凭据独立存于 `~/.ferroc/device.json`，不读取、不覆盖 `~/.brc`。Windows 凭据写入前收紧 ACL；Unix 使用 0600。用 `--home` 指定独立目录。

文件根目录默认仅当前工作目录。多次 `--allow-dir` 可配置多个根。**shell 默认关闭**；受信任操作员可加 `--allow-shell`。启用后 shell 拥有当前用户的完整 OS 权限，目录策略不是沙箱。

```json
{
  "mcpServers": {
    "ferroc": {
      "command": "C:\\tools\\ferroc\\ferroc.exe",
      "args": ["--allow-dir", "E:\\work", "stdio"]
    }
  }
}
```

其他入口：`ferroc tools` 输出真实工具 schema；`ferroc call get_config` 单次调用。进程/搜索/传输接收会话须在长驻的 stdio 或 agent 中使用；单次 `call` 退出会清理进程。

## Windows GUI（WindUI 预览）

```powershell
cargo build --locked --release --features gui --bin ferroc-gui
.\target\release\ferroc-gui.exe --allow-dir E:\work --start
# 仅托盘启动：追加 --start-hidden；不加 --start 则等待手动启动。
```

依赖使用 crates.io **`windui = 0.32.0`**，无 Git dependency 或本地 patch。GUI 本机 MCP 为 **Streamable HTTP**（默认 `http://127.0.0.1:3211/mcp`），CLI 本机 MCP 仍为 `ferroc stdio`。`ferroc agent` 则是连接 relay 的出站 WebSocket 入口，不与 stdio 混淆。

- 授权目录、监听地址、可选 relay、代理/直连设置；关闭或最小化后驻留托盘。resident 模式释放窗口并可重建，输入模型保留；再次运行也可唤起窗口。
- 托盘提供显示/隐藏、启动/停止、暂停 HTTP 新请求、排空后退出；tooltip 显示 HTTP/中继状态。已接收操作不因暂停、客户端断开或退出请求而假装取消。
- 启动后点“复制 MCP 配置”，交给支持 HTTP/认证头的可信 MCP 客户端。配置含**本次随机口令**；重启后失效，不会出现在普通状态、日志或 tooltip。
- 仅允许 loopback 监听；校验认证、Host、Origin、会话、版本与消息大小。GET SSE 返回 405，JSON HTTP 客户端可用；不是公网 OAuth MCP 服务。
- 本机 HTTP 和可选远程 relay 共用一个 Runtime，不启动 Node 或额外 relay。shell 默认关闭，传输默认开启；`--no-transfers` 可关闭。界面目录策略不是 OS 沙箱。

当前原生 Windows 回归已覆盖最小化→零窗口→重建→退出，以及无窗口时托盘意图消费；这不等于鼠标悬停 tooltip 的 Shell 读回。桌面工具的跨调用截图归属问题仍阻塞完整鼠标/复制操作验收，独立 advisor 也未取得有效签收，详见验证记录。

## Agent 显式代理

配对 HTTP、持续 WebSocket 和加密文件上传/下载共用同一出站策略，不增加代理服务。

```powershell
.\target\release\ferroc.exe agent --relay https://relay.example.com --proxy http://192.168.1.200:10808
.\target\release\ferroc.exe agent --relay https://relay.example.com --proxy socks5h://192.168.1.200:10808
# 强制直连，忽略全部代理环境变量
.\target\release\ferroc.exe agent --relay https://relay.example.com --no-proxy
```

支持 `http://`、`https://`、`socks5://`（本地 DNS）、`socks5h://`（代理端 DNS）；SOCKS URL 须显式写端口。支持 URL 用户名/密码认证，特殊字符需 URL 编码。认证信息建议通过受控的 `FERROC_PROXY` 环境变量注入，不放入 OS 可见的命令行参数；环境变量本身不是加密密钥库。

优先级：`--proxy` > `FERROC_PROXY` > 标准 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` 与 `NO_PROXY` 匹配。`--no-proxy` 与 `--proxy` 冲突，并覆盖所有环境变量。显式代理会强制覆盖 `NO_PROXY`，失败不会悄悄改为直连；若需要按目的地址绕行，使用标准环境变量模式。未指定时只显示 `environment`，不声称每个请求都已走代理。

启动 stderr 和 agent 的 `get_config.outboundNetwork` 显示脱敏策略；不展示用户名/密码，也不写入设备凭据。`--ca-cert company-ca.pem` 或 `FERROC_CA_CERT` 可增加 PEM CA，适用于代理和目标 TLS；仍验证证书与主机名，不修改系统证书库。没有 PAC/WPAD、NTLM/Kerberos；可选 GUI 预览提供代理输入和强制直连开关，配置在下次启动 Agent 时生效。

验证边界及日志见 [代理验证报告](docs/verification/windows-agent-proxy.md)。

## 原生 relay（可选替换路线）

```powershell
$env:FERROC_ADMIN_PASSWORD = '<至少 16 字符的独立强密码>'
.\target\release\ferroc.exe relay --bind 127.0.0.1:3210 --public-url http://127.0.0.1:3210 --db E:\private\ferroc-relay.sqlite
# 管理页：http://127.0.0.1:3210/admin，用户名 admin
# Agent 改用 --relay http://127.0.0.1:3210；远程 MCP 地址 /mcp
```

数据库目录须由操作员设置私有 ACL。非 loopback 的公开地址必须是 HTTPS；TLS 由已有反向代理终结。本次没有安装服务、修改现有 relay 或导入 Node 数据库。原生实现为单管理员、JSON HTTP MCP 预览，不包含 SSE、多租户或无缝数据库迁移。

## 实现范围

25 个已注册工具：本地 UTF-8 文件读写、精确编辑、目录操作、受控进程会话、可取消后台搜索、配置只读和内存调用记录。

- WebSocket protocol v1、设备配对、token header、heartbeat、重连、并发上限、重复请求 ID 拒绝。
- stdio MCP：initialize、ping、tools/list、tools/call；newline JSON-RPC，单连接顺序执行。
- 原生 relay：OAuth discovery/DCR/PKCE S256、code 单次兑换、refresh rotation、撤销，远程 MCP，设备管理和元数据审计。`list_devices` 是 relay 额外工具，因此远程共 26 个工具。
- 三个加密传输工具已原生实现，**默认开启**；本地可用 `--no-transfers` 禁用，原 `--allow-transfers` 保留兼容。启动不会自动上传，只有显式调用收发工具才访问 provider。采用上游 BRCX1 格式，把密文放到 tmpfiles.org，不新增传输服务。provider 可见文件大小/时间；不是发送者身份认证协议。接收密钥仅在当前 agent/stdio 内存中有效，成功后单次消费。真实公网 provider 尚未验证，本轮未上传任何私有数据。
- `set_config_value` 不暴露：安全策略只能由本地 CLI 修改。
- `list_processes` / `kill_process` **仅 agent 自己创建的会话**，不枚举/终止任意 OS 进程。
- Windows CLI 与可选 GUI 均嵌入产品信息和七尺寸图标；GUI/托盘为预览，暂无自启动或服务安装器。

完整差异见 [COMPATIBILITY](docs/COMPATIBILITY.md)，安全边界见 [SECURITY](SECURITY.md)。

## Fleet 互传（开发中，尚无可调用网络入口）

默认关闭的 `fleet-core` 已有 P0 候选协议/双签授权/单调租约、保护身份与显式 pin、同库 fence/journal、持久预约、Target DATA/FINISH 和 Windows v9 活跃对象本地结算。最终 ACK 在真实 gate 内一次编码并缓存；重启记录不能重建活跃文件、恢复发布或自动免债。SourceEncoder 是纯记录组件，PeerReportedCompleted 只表示认证对端声明，不是远端私有 IO 证明。

**P1 已开始接入源文件 IO**：`Runtime::open_fleet_source(LeasedRecords)` 只读获批 job 的源路径，绑定 Runtime 目录策略/关停状态、原文件和父目录句柄。每次至多 min(授权片长,64KiB)，读取前后检查对象与租约，计数仍是 bytes_encoded，不是已发送。失败撤销并关闭本轮读取能力，完整编码流 SHA 匹配后才产生 FINISH；它不重新证明后来的源文件快照。没有源端持久 journal 或重启续传；SourceFile 本身不维护传输窗口，调用者仍须限制密文队列。

用户已明确停止 Advisor 咨询，该路径不再作为开发依赖；历史独立签收缺失没有被改写为通过。真实源文件→认证 DATA→本地 Target v9→最终 ACK 是本机 IO 验证，不等于 relay+A+B 三进程、两机或 Linux 验收。现有生产 CLI/GUI、25 工具、`/ws`、BRCX1 和 tag-only CI 不变；默认 router 没有 `/fleet/ws`。显式 library API `Relay::router_with_fleet` 可在同一 relay/listener/Store 挂载候选通道，要求原设备 Bearer 与绑定 grant/角色的一次性 header 票据；不新增服务或 fleet MCP/CLI 工具。真实三测试进程已执行，仍不等于两机、生产 agent 或运营签发验收。

纯 manifest/diff 仍仅提供默认 checksum 的 dry-run，quick 比较任意 mtime 差异，目标额外项保留；该纯组件无触盘/apply/覆盖/删除权限，精确 UTF8 键不证明原生名称等价。新增独立 Windows 本机候选 `Runtime::scan_fleet_manifest` 在当前目录策略和生命周期内有界读取真实树，64KiB 分块哈希；错误不返回部分清单。结果只是 ReadSequence，不防外部已读前缀改写，不是文件系统快照/远程扫描授权/目录同步完成，见[扫描合同](docs/design/fleet-manifest-scan.md)。另有只读目标预检 `Runtime::preflight_fleet_target`：要求每个目标父目录已存在且为私有普通目录、解析后仍在该目标根内、目标名称落在声明式 ASCII 可移植剖面内、目标当前缺失，并把有序 `(path, bytes, sha, job)` 绑定为计划摘要；任一不满足整轮拒绝，绝不建目录/建文件/覆盖。它不授予发布许可，也不构成快照。默认要求父目录全部已存在；显式开启 `allow_planned_directories` 后才接受计划自身声明的目录，缺失者按祖先优先返回给接收方创建，预检本身仍不建目录，见[目标准入合同](docs/design/fleet-target-preflight.md)。P1 已加入 `SourceWindow`：认证 READY 后读取，最多 8 片原密文缓存，只有认证连续覆盖 ACK 释放；乱序旧 ACK 不回退，FINISH 必须排空。Target 活跃 receiver 生成缓存 READY/ACK，竞争时非阻塞 DB 准入，进度不是最终结算。`FleetLink`/IO pump 已复用 Network 的代理/TLS 升级路径，接入同 relay 二进制通道和 Windows v9；已通过独立 relay+Source+Target 测试进程与显式 HTTP 代理对照；另有真实 TCP/WS 队列饱和后5s超时、恢复读完整DATA/SHA、拥塞中撤销，以及实际v9后ACK原生发送失败仍保留本地结算而Source不完成的探针。后者用私有观察接缝触发真实断链，不是生产恢复/投递保证；详见[原生背压合同](docs/design/fleet-backpressure.md)与[续租合同](docs/design/fleet-renewal.md)。下一步是受控任务入口、可信运营签发/进度/取消及真实两机验证，之后才做 P2 目录执行与 P3 QUIC/NAT。

`cargo test --locked --features fleet-core --lib fleet::` 运行候选组件。`scripts/measure-fleet-p0.ps1` 的历史合成 stage 探针不替换 CLI/GUI，也不是新源 IO 或网络吞吐量证明。详见[总体设计](docs/design/fleet-transfers.md)、[P0 历史合同](docs/design/fleet-p0-core.md)、[P1 源 IO 合同](docs/design/fleet-source-io.md)、[有界流控合同](docs/design/fleet-flow-control.md)、[同 relay 通道合同](docs/design/fleet-relay-channel.md)和[研究来源](docs/research/remote-agents-mcp-fleet.md)。

## 验证

```powershell
.\scripts\verify.ps1 -Release
# 可选：原版 relay 对照测试；Node 仅用于测试，不属于 ferroc runtime。
node scripts/upstream-e2e.mjs ../better-remote-commander ./target/release/ferroc.exe
```

上游对照须位于固定提交 `cbe511702dd0147650353c29ac6ab1decd8afda1`，先按其 lockfile 构建 shared/relay。测试临时监听 loopback，执行后关闭。报告在 `artifacts/`，不含 token/password。

本机 Windows 代理支持基线构建通过 54 项默认 Rust 测试及单独执行的原版 Node 双向密码互操作测试；同一 release 二进制通过原生 relay + agent 回环，以及原版 relay 的 7 组互操作 + 14 项 OAuth/MCP 检查。99 MB 验证仅为本地密码回环，不是公网传输。原生基线见 [历史报告](docs/verification/windows-native-preview.md)，加密协议见 [历史传输报告](docs/verification/windows-transfer-preview.md)，默认开启策略见 [历史默认策略报告](docs/verification/windows-transfer-defaults.md)，图标来源与历史构建见 [图标报告](docs/verification/windows-bright-icon.md)，当前代理、Windows 资源与同一二进制回归见 [当前报告](docs/verification/windows-agent-proxy.md)；**不等于**公网 TLS、Claude/ChatGPT 实际连接或 Linux/macOS 已验证。CI 仅由 tag push 触发，当前仅构建 Windows/Linux x86_64；Linux 设有 glibc 2.17 的 ABI 与实际运行门禁。首次 tag 构建完成前，不把配置和本机测试视为 GitHub 构建成功。

工程测试与独立签收分开：当前本地验证已通过；advisor 两次观测失配，未取得有效的独立审阅认可。完整分歧和后续阻塞见当前报告，不能称为安全审计或生产资格。

GUI 增量另通过 62 项全 feature 回归、显式原生窗口和 HTTP MCP SDK 测试；其二进制哈希、真实托盘交互缺口和独立复核超时见 [GUI 验证记录](docs/verification/windows-gui-preview.md)。提交代码不代表发布或完整验收。

## Tag 构建与下载

常规提交和 PR **不触发 CI**；仅 push tag 构建 Windows x86_64（CLI + GUI）和 Linux x86_64（CLI，glibc 2.17 兼容门禁）。两平台检查通过后生成带 `SHA256SUMS` 的 GitHub 预览 Release；不产出 macOS/ARM/musl 版。

版本 tag 由操作员显式创建，不会随提交自动生成。触发方法、固定工具版本、glibc ABI/真实容器验证及尚待首次 tag 执行的边界见 [发布说明](docs/releasing.md)。

## 溯源

GitHub MCP 审阅源码：[shahidx0x/better-remote-commander](https://github.com/shahidx0x/better-remote-commander/tree/cbe511702dd0147650353c29ac6ab1decd8afda1)。参考 fork：`m2selfA/better-remote-commander`。`ferroc` 是独立 Rust 项目，不把 Node 上游文件作为运行时依赖。

MIT；保留 BRC 与 Desktop Commander 署名，见 [LICENSE](LICENSE)、[NOTICE](NOTICE)。
