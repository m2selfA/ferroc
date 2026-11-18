use anyhow::{Context, Result};
use clap::Parser;
use ferroc::gui_service::{GuiControl, GuiOptions, GuiService, GuiSnapshot, Phase};
use std::{path::PathBuf, time::Duration};
use windui::prelude::*;

const BG: u32 = 0xF4F7FA;
const FG: u32 = 0x233044;
const MUTED: u32 = 0x66758A;
const ORANGE: u32 = 0xED8A27;

#[derive(Parser)]
#[command(
    version,
    about = "ferroc Windows GUI · WindUI + local Streamable HTTP MCP"
)]
struct Args {
    #[arg(long, default_value = ".")]
    allow_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:3211")]
    bind: std::net::SocketAddr,
    #[arg(long)]
    allow_shell: bool,
    #[arg(long)]
    no_transfers: bool,
    #[arg(long, env = "FERROC_RELAY")]
    relay: Option<String>,
    #[arg(long, hide_env_values = true, conflicts_with = "no_proxy")]
    proxy: Option<String>,
    #[arg(long)]
    no_proxy: bool,
    #[arg(long, env = "FERROC_CA_CERT", hide_env_values = true)]
    ca_cert: Option<PathBuf>,
    /// Local fleet approval file. With transfer.mcp=true, exposes four task tools
    /// over the GUI HTTP MCP endpoint. Requires a configured relay.
    #[cfg(feature = "fleet-core")]
    #[arg(long, env = "FERROC_FLEET_SETUP", hide_env_values = true)]
    fleet_setup: Option<PathBuf>,
    #[arg(long, env = "FERROC_HOME")]
    home: Option<PathBuf>,
    #[arg(long, default_value = "ferroc")]
    name: String,
    /// Start after the primary GUI enters its event loop; otherwise start manually.
    #[arg(long)]
    start: bool,
    #[arg(long)]
    start_hidden: bool,
    /// Offscreen rendering only: no listener or relay is started by this mode.
    #[arg(long)]
    screenshot: Option<PathBuf>,
    #[arg(long, default_value_t = 1.0)]
    scale: f32,
}
#[derive(Clone, Copy)]
struct Inputs {
    root: Signal<String>,
    bind: Signal<String>,
    relay: Signal<String>,
    proxy: Signal<String>,
    direct: Signal<bool>,
}
fn start(control: &GuiControl, input: Inputs, defaults: &GuiOptions) -> Result<()> {
    let mut options = defaults.clone();
    options.root = PathBuf::from(input.root.get());
    options.bind = input
        .bind
        .get()
        .parse()
        .context("监听地址应为127.0.0.1:端口或[::1]:端口")?;
    options.no_proxy = input.direct.get();
    options.proxy = if options.no_proxy {
        None
    } else {
        let p = input.proxy.get();
        (!p.trim().is_empty()).then_some(p)
    };
    options.relay = {
        let url = input.relay.get();
        (!url.trim().is_empty()).then_some(url)
    };
    control.start(options)
}
fn status(snapshot: &GuiSnapshot) -> String {
    match snapshot.phase {
        Phase::Stopped => "HTTP MCP · 未启动".into(),
        Phase::Starting => "HTTP MCP · 启动中".into(),
        Phase::Stopping => "正在排空已接收调用…".into(),
        Phase::Failed => "需要处理配置或监听错误".into(),
        Phase::Exited => "已停止".into(),
        Phase::Running => {
            let h = snapshot.http.as_ref().expect("running HTTP");
            if h.paused {
                "HTTP MCP · 已暂停新请求".into()
            } else {
                format!(
                    "HTTP MCP · 监听中  /  {}个会话  /  {}个处理中",
                    h.sessions, h.active
                )
            }
        }
    }
}
fn tooltip(snapshot: &GuiSnapshot) -> String {
    let relay = if snapshot.relay == "在线" {
        "中继在线"
    } else if snapshot.relay.starts_with("等待批准") {
        "中继配对中"
    } else if snapshot.relay.starts_with("已断开") {
        "中继重连中"
    } else {
        "中继未连接"
    };
    format!("ferroc | {} | {relay}", status(snapshot))
        .chars()
        .take(120)
        .collect()
}
fn label(text: &str) -> Element {
    Element::label(text)
        .font_size(12.0)
        .fg(Color::hex(MUTED))
        .width_match()
        .height(20)
}
fn icon_at(px: u32) -> WindowIcon {
    let bytes: &[u8] = match px {
        0..=16 => include_bytes!("../assets/icons/16.png"),
        17..=20 => include_bytes!("../assets/icons/20.png"),
        21..=24 => include_bytes!("../assets/icons/24.png"),
        25..=32 => include_bytes!("../assets/icons/32.png"),
        33..=40 => include_bytes!("../assets/icons/40.png"),
        41..=48 => include_bytes!("../assets/icons/48.png"),
        49..=64 => include_bytes!("../assets/icons/64.png"),
        65..=128 => include_bytes!("../assets/icons/128.png"),
        _ => include_bytes!("../assets/icons/256.png"),
    };
    WindowIcon::from_image(&Image::from_bytes(bytes).expect("embedded PNG")).expect("embedded icon")
}
const MAIN_WINDOW: &str = "ferroc-main";
const STATUS_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone)]
struct View {
    control: GuiControl,
    defaults: GuiOptions,
    input: Inputs,
    heading: Signal<String>,
    endpoint: Signal<String>,
    detail: Signal<String>,
    network: Signal<String>,
    relay_status: Signal<String>,
    start_text: Signal<String>,
    pause_text: Signal<String>,
}

fn main_window(view: View) -> WindowRequest {
    Window::new("ferroc Agent", 680, 720)
        .single(MAIN_WINDOW)
        .icon(IconSource::sized(icon_at))
        .frameless(true)
        .min_size(620, 560)
        .bg(Color::hex(BG))
        // Published WindUI puts child-window timers on that window, but the
        // resident host consumes close_window's application queue independently
        // of painting. This covers native Win+Down/system-menu minimization too.
        .on_interval(Duration::from_millis(100), |ctx| {
            if ctx.window_state().minimized {
                // EventCtx lacks close_window in registry 0.32.0. The public
                // HotkeyCtx declares the same deferred, keyed application intent
                // without accessing native handles or running OS calls here.
                windui::event::HotkeyCtx::default().close_window(MAIN_WINDOW);
            }
        })
        .content(move || build_ui(view))
}

fn build_ui(view: View) -> Element {
    let View {
        control,
        defaults,
        input,
        heading,
        endpoint,
        detail,
        network,
        relay_status,
        start_text,
        pause_text,
    } = view;
    let title = Element::row()
        .height(40)
        .width_match()
        .window_drag()
        .bg(Color::hex(BG))
        .child(
            Element::label("  ferroc")
                .font_size(15.0)
                .fg(Color::hex(FG))
                .weight(1.0),
        )
        .child(Element::window_button(WindowButtonKind::Minimize).fg(Color::hex(MUTED)))
        .child(Element::window_button(WindowButtonKind::Close).fg(Color::hex(MUTED)));
    let hero = Element::row()
        .width_match()
        .spacing(16)
        .align(Align::Center)
        .child(
            Element::image_bytes(include_bytes!("../assets/icons/64.png"))
                .width(60)
                .height(60),
        )
        .child(
            Element::col()
                .spacing(6)
                .weight(1.0)
                .child(
                    Element::label("你的桌面，轻量连接")
                        .font_size(24.0)
                        .fg(Color::hex(FG))
                        .width_match()
                        .height(32),
                )
                .child(
                    Element::label_signal(heading)
                        .font_size(13.0)
                        .fg(Color::hex(MUTED))
                        .width_match()
                        .height(24),
                ),
        );
    let endpoint_card = Element::col()
        .width_match()
        .padding(16)
        .spacing(7)
        .bg(Color::WHITE)
        .corner(12.0)
        .child(label("LOCAL MCP · Streamable HTTP"))
        .child(
            Element::label_signal(endpoint)
                .font_size(18.0)
                .fg(Color::hex(FG))
                .width_match()
                .height(28),
        )
        .child(
            Element::label(if defaults.allow_shell {
                "Shell 已明确启用 · 目录策略不是沙箱"
            } else {
                "Shell 默认关闭 · 口令认证 · 仅本机监听"
            })
            .font_size(12.0)
            .fg(Color::hex(MUTED))
            .width_match()
            .height(20),
        );
    let settings = Element::col()
        .width_match()
        .padding(16)
        .spacing(7)
        .bg(Color::WHITE)
        .corner(12.0)
        .child(label("授权目录"))
        .child(
            Element::text_input(input.root, "授权目录；也可将文件夹拖入窗口")
                .width_match()
                .height(34),
        )
        .child(
            Element::row()
                .width_match()
                .spacing(12)
                .child(
                    Element::col()
                        .weight(1.0)
                        .spacing(4)
                        .child(label("HTTP 监听地址"))
                        .child(
                            Element::text_input(input.bind, "127.0.0.1:3211")
                                .width_match()
                                .height(34),
                        ),
                )
                .child(
                    Element::col()
                        .weight(1.0)
                        .spacing(4)
                        .child(label("中继 URL（可选，留空仅提供本机 MCP）"))
                        .child(
                            Element::text_input(input.relay, "留空不启用中继")
                                .width_match()
                                .height(34),
                        ),
                ),
        )
        .child(label(
            "出站代理（HTTP / HTTPS / SOCKS5 / SOCKS5h；内容隐藏防止泄漏凭据）",
        ))
        .child(
            Element::row()
                .width_match()
                .spacing(10)
                .align(Align::Center)
                .child(
                    Element::text_input(input.proxy, "留空沿用环境代理")
                        .password()
                        .weight(1.0)
                        .height(34),
                )
                .child(Element::checkbox("强制直连", input.direct)),
        )
        .child(
            Element::label("配置修改仅在下次启动生效；目录策略不是用户级安全沙箱。")
                .font_size(11.0)
                .fg(Color::hex(MUTED))
                .width_match()
                .height(20),
        );
    let c = control.clone();
    let d = defaults.clone();
    let start_button = Element::button(start_text)
        .width(135)
        .height(38)
        .bg(Color::hex(ORANGE))
        .fg(Color::WHITE)
        .corner(8.0)
        .on_click(move |ctx| {
            let result = if c.snapshot().has_runtime {
                c.stop()
            } else {
                start(&c, input, &d)
            };
            if let Err(error) = result {
                ctx.toast(error.to_string());
            }
        });
    let c = control.clone();
    let pause_button = Element::button(pause_text)
        .width(100)
        .height(38)
        .on_click(move |_| {
            let paused = c.snapshot().http.as_ref().is_some_and(|h| h.paused);
            c.pause(!paused);
        });
    let c = control.clone();
    let copy_button = Element::button("复制 MCP 配置")
        .width(135)
        .height(38)
        .on_click(move |ctx| {
            if let Some(config) = c.client_config() {
                ctx.clipboard_set(&config);
                ctx.toast_ok("配置含本次口令，请只交给受信任的MCP客户端。");
            } else {
                ctx.toast("请先启动；停止或重启后旧口令失效。");
            }
        });
    let c = control.clone();
    let exit_button = Element::button("退出")
        .width(72)
        .height(38)
        .on_click(move |_| {
            let _ = c.quit();
        });
    let buttons = Element::row()
        .width_match()
        .spacing(10)
        .child(start_button)
        .child(pause_button)
        .child(copy_button)
        .child(Element::row().weight(1.0))
        .child(exit_button);
    let content = Element::col()
        .width_match()
        .padding(20)
        .spacing(12)
        .bg(Color::hex(BG))
        .child(hero)
        .child(endpoint_card)
        .child(settings)
        .child(
            Element::col()
                .width_match()
                .spacing(3)
                .child(
                    Element::label_signal(network)
                        .font_size(11.0)
                        .fg(Color::hex(MUTED))
                        .width_match(),
                )
                .child(
                    Element::label_signal(relay_status)
                        .font_size(12.0)
                        .fg(Color::hex(FG))
                        .width_match(),
                )
                .child(
                    Element::label_signal(detail)
                        .font_size(11.0)
                        .fg(Color::hex(MUTED))
                        .width_match(),
                ),
        );
    let body = Element::col()
        .fill()
        .bg(Color::hex(BG))
        .child(Element::scroll().width_match().weight(1.0).child(content))
        .child(Element::col().width_match().padding(20).child(buttons));
    Element::col()
        .fill()
        .on_drop_files(move |ctx, paths| {
            if let Some(path) = paths.first() {
                if path.is_dir() {
                    input.root.set(path.display().to_string());
                    ctx.toast("目录已填入，下次启动生效。");
                } else {
                    ctx.toast("请拖入文件夹，而不是文件。");
                }
            }
        })
        .bg(Color::hex(BG))
        .child(title)
        .child(body.weight(1.0))
}

pub fn run() -> Result<()> {
    let args = Args::parse();
    let home = args
        .home
        .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(".ferroc")))
        .context("无法确定home，请指定--home")?;
    let defaults = GuiOptions {
        root: args.allow_dir.clone(),
        bind: args.bind,
        allow_shell: args.allow_shell,
        allow_transfers: !args.no_transfers,
        proxy: args.proxy.clone(),
        no_proxy: args.no_proxy,
        ca_cert: args.ca_cert,
        relay: args.relay.clone(),
        home,
        name: args.name,
        #[cfg(feature = "fleet-core")]
        fleet_setup: args.fleet_setup.clone(),
    };
    let input = Inputs {
        root: signal(args.allow_dir.display().to_string()),
        bind: signal(args.bind.to_string()),
        relay: signal(args.relay.unwrap_or_default()),
        proxy: signal(args.proxy.unwrap_or_default()),
        direct: signal(args.no_proxy),
    };
    let heading = signal(String::from("HTTP MCP · 未启动"));
    let endpoint = signal(String::from("启动后显示本机地址"));
    let detail = signal(String::from("默认仅本机可访问；关闭或最小化会收进托盘。"));
    let network = signal(String::from("代理：尚未启动"));
    let relay_status = signal(String::from("中继：未启用"));
    let start_text = signal(String::from("启动 Agent"));
    let pause_text = signal(String::from("暂停 HTTP"));
    let menu_running = signal(false);
    let menu_paused = signal(false);
    let service = GuiService::new()?;
    let control = service.control();
    let view = View {
        control: control.clone(),
        defaults: defaults.clone(),
        input,
        heading,
        endpoint,
        detail,
        network,
        relay_status,
        start_text,
        pause_text,
    };
    // Keep the status/exit pump on WindUI's resident application host, never on
    // a hidden primary window whose WM_PAINT is suppressed by Windows.
    let mut app = App::resident("ferroc Agent")
        .icon(IconSource::sized(icon_at))
        .theme(Theme::default());
    let tray = {
        let c = control.clone();
        let d = defaults.clone();
        let failed_view = view.clone();
        let start_item = TrayMenuItem::item("启动 Agent", move |ctx| {
            if start(&c, input, &d).is_err() {
                ctx.open_window(main_window(failed_view.clone()));
                ctx.notify("ferroc", "无法启动；检查目录、监听地址或代理。")
            }
        });
        let c = control.clone();
        let stop_item = TrayMenuItem::item("停止 Agent（等待已接收调用）", move |_| {
            let _ = c.stop();
        })
        .enabled(menu_running);
        let c = control.clone();
        let pause_item = TrayMenuItem::check("暂停 HTTP 新请求", menu_paused, move |_| {
            c.pause(!menu_paused.get());
        })
        .enabled(menu_running);
        let c = control.clone();
        let quit_item = TrayMenuItem::item("退出（排空后关闭）", move |_| {
            let _ = c.quit();
        });
        let icon = icon_at(32);
        let left = view.clone();
        let double = view.clone();
        let show = view.clone();
        Tray::new()
            .tooltip("ferroc | HTTP MCP未启动")
            .icon_rgba(icon.width(), icon.height(), icon.rgba())
            .on_left_click(move |ctx| ctx.open_window(main_window(left.clone())))
            .on_double_click(move |ctx| ctx.open_window(main_window(double.clone())))
            .menu(vec![
                TrayMenuItem::item("显示主窗口", move |ctx| {
                    ctx.open_window(main_window(show.clone()));
                }),
                TrayMenuItem::item("隐藏到托盘", |ctx| ctx.close_window(MAIN_WINDOW)),
                TrayMenuItem::separator(),
                start_item,
                stop_item,
                pause_item,
                TrayMenuItem::separator(),
                quit_item,
            ])
    };
    let second_view = view.clone();
    let show = app.channel::<()>(move |ctx, ()| {
        ctx.open_window(main_window(second_view.clone()));
    });
    app = app
        .tray(tray)
        .single_instance("ferroc.agent.gui.v1", move |_| {
            let _ = show.send(());
        });
    let tray_handle = app.tray_handle();
    let mut previous: Option<GuiSnapshot> = None;
    let mut bootstrap = args.start && args.screenshot.is_none();
    let c = control.clone();
    let d = defaults;
    app = app.on_interval(STATUS_INTERVAL, move |_ctx| {
        if bootstrap {
            bootstrap = false;
            if start(&c, input, &d).is_err() {
                tray_handle.notify("ferroc", "自动启动失败，请打开主窗口检查配置。");
            }
        }
        let snapshot = c.snapshot();
        if snapshot.phase == Phase::Exited {
            tray_handle.quit();
            return;
        }
        if previous.as_ref() != Some(&snapshot) {
            heading.set(status(&snapshot));
            endpoint.set(
                snapshot
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| "启动后显示本机地址".into()),
            );
            network.set(format!("代理：{}", snapshot.network));
            let relay_text = format!("中继：{}", snapshot.relay);
            #[cfg(feature = "fleet-core")]
            let relay_text = match &snapshot.fleet_tasks {
                Some(tasks) => format!(
                    "{relay_text} · 本机任务：{}待完成 / {}对端报告完成 / {}中断 / {}失败",
                    tasks.pending, tasks.peer_reported_completed, tasks.interrupted, tasks.failed,
                ),
                None => relay_text,
            };
            relay_status.set(relay_text);
            detail.set(snapshot.detail.clone());
            start_text.set(
                if snapshot.has_runtime {
                    "停止 Agent"
                } else {
                    "启动 Agent"
                }
                .into(),
            );
            let paused = snapshot.http.as_ref().is_some_and(|h| h.paused);
            pause_text.set(if paused { "恢复 HTTP" } else { "暂停 HTTP" }.into());
            menu_running.set(snapshot.has_runtime);
            menu_paused.set(paused);
            tray_handle.set_tooltip(tooltip(&snapshot));
            previous = Some(snapshot);
        }
    });
    app = app.screenshot_window(main_window(view.clone()));
    if !args.start_hidden {
        app = app.start_window(main_window(view));
    }
    app.screenshot_from_args().run_resident();
    service.finish()
}
#[cfg(test)]
#[path = "gui_windows_tests.rs"]
mod tests;

pub fn show_startup_error(message: &str) {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(
            window: *mut core::ffi::c_void,
            text: *const u16,
            caption: *const u16,
            flags: u32,
        ) -> i32;
    }
    let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "ferroc · 启动失败".encode_utf16().chain(Some(0)).collect();
    // Startup only, before entering (or after leaving) WindUI's message loop.
    unsafe {
        MessageBoxW(core::ptr::null_mut(), text.as_ptr(), title.as_ptr(), 0x10);
    }
}
