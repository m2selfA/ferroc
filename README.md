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

Agnes 生成的明亮橙金 `F` + 青绿命令箭头。透明母图 [`assets/ferroc.png`](assets/ferroc.png)、Windows 七尺寸 [`assets/ferroc.ico`](assets/ferroc.ico)、独立 16–512px PNG 位于 `assets/icons/`。原图、提示词、来源与输出哈希位于 `assets/branding/`；`assets/generate-icons.ps1` 可离线重新导出。Windows 构建继续通过 `build.rs` 嵌入；浏览器管理页复用同一图标，不新增服务。当前无原生 GUI/任务栏窗口/托盘；未来实现可共用 `ferroc::icons`，不代表这些界面已实现或验证。

## 构建与运行

```powershell
cd E:\inter\Documents\Repos\ferroc
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
      "command": "E:\\inter\\Documents\\Repos\\ferroc\\target\\release\\ferroc.exe",
      "args": ["--allow-dir", "E:\\work", "stdio"]
    }
  }
}
```

其他入口：`ferroc tools` 输出真实工具 schema；`ferroc call get_config` 单次调用。进程/搜索/传输接收会话须在长驻的 stdio 或 agent 中使用；单次 `call` 退出会清理进程。

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

启动 stderr 和 agent 的 `get_config.outboundNetwork` 显示脱敏策略；不展示用户名/密码，也不写入设备凭据。`--ca-cert company-ca.pem` 或 `FERROC_CA_CERT` 可增加 PEM CA，适用于代理和目标 TLS；仍验证证书与主机名，不修改系统证书库。没有 PAC/WPAD、NTLM/Kerberos、GUI 设置页或托盘。

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
- Windows 控制台程序嵌入产品信息和七尺寸图标；当前没有 GUI/托盘/自启动安装器。

完整差异见 [COMPATIBILITY](docs/COMPATIBILITY.md)，安全边界见 [SECURITY](SECURITY.md)。

## 验证

```powershell
.\scripts\verify.ps1 -Release
# 可选：原版 relay 对照测试；Node 仅用于测试，不属于 ferroc runtime。
node scripts/upstream-e2e.mjs E:\inter\Documents\Repos\better-remote-commander .\target\release\ferroc.exe
```

上游对照须位于固定提交 `cbe511702dd0147650353c29ac6ab1decd8afda1`，先按其 lockfile 构建 shared/relay。测试临时监听 loopback，执行后关闭。报告在 `artifacts/`，不含 token/password。

本机 Windows 当前代理支持构建通过 54 项默认 Rust 测试及单独执行的原版 Node 双向密码互操作测试；同一 release 二进制通过原生 relay + agent 回环，以及原版 relay 的 7 组互操作 + 14 项 OAuth/MCP 检查。99 MB 验证仅为本地密码回环，不是公网传输。原生基线见 [历史报告](docs/verification/windows-native-preview.md)，加密协议见 [历史传输报告](docs/verification/windows-transfer-preview.md)，默认开启策略见 [历史默认策略报告](docs/verification/windows-transfer-defaults.md)，图标来源与历史构建见 [图标报告](docs/verification/windows-bright-icon.md)，当前代理、Windows 资源与同一二进制回归见 [当前报告](docs/verification/windows-agent-proxy.md)；**不等于**公网 TLS、Claude/ChatGPT 实际连接或 Linux/macOS 已验证。CI 配置覆盖三平台，但尚未在 GitHub 执行。

工程测试与独立签收分开：当前本地验证已通过；advisor 两次观测失配，未取得有效的独立审阅认可。完整分歧和后续阻塞见当前报告，不能称为安全审计或生产资格。

## 溯源

GitHub MCP 审阅源码：[shahidx0x/better-remote-commander](https://github.com/shahidx0x/better-remote-commander/tree/cbe511702dd0147650353c29ac6ab1decd8afda1)。参考 fork：`m2selfA/better-remote-commander`。`ferroc` 是独立 Rust 项目，不把 Node 上游文件作为运行时依赖。

MIT；保留 BRC 与 Desktop Commander 署名，见 [LICENSE](LICENSE)、[NOTICE](NOTICE)。
