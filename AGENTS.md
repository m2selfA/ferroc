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

## 必须保留的边界
- WindUI 必须使用发布 registry crate，不改 Git 依赖、patch 或全局依赖缓存。
- shell 默认关闭，传输默认开启；目录策略不是当前用户权限的沙箱。
- 暂停/退出阻止新接收，已接收 HTTP 操作可能继续产生副作用；退出须等待排空。
- 托盘状态泵依附 resident 宿主，不能依赖已隐藏或已销毁窗口的 WM_PAINT。
- 不记录认证口令/代理凭据；规划文件、`artifacts/` 和 `target/` 仅留本地，不入库。
- 上游溯源快照必须保持原字节；不要为格式检查改写它们。
- 仅在用户要求时提交；不自动 push。提交说明不能把代码提交视为发布或独立签收。

## 当前状态与下一步
GUI 是预览。工程回归、原生生命周期和 SDK 组件探针已通过；真实托盘鼠标/复制配置验收及有效独立复核仍未完成。详见上述验证报告，勿把组件测试等同于 GUI release 的真实操作路径。
