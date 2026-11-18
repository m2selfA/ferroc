//! Explicit desktop test. Executes production window construction with the
//! registry WindUI event loop; no Cua state/input ownership is accessed.
use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

// Test-only OS control targets a unique window in THIS test process. Native
// minimization exercises WM_SIZE/WindowState, not a synthetic signal substitute.
fn minimize_own_window(title: &str) -> bool {
    type Hwnd = *mut core::ffi::c_void;
    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(class: *const u16, title: *const u16) -> Hwnd;
        fn GetWindowThreadProcessId(hwnd: Hwnd, pid: *mut u32) -> u32;
        fn ShowWindow(hwnd: Hwnd, command: i32) -> i32;
        fn IsIconic(hwnd: Hwnd) -> i32;
    }
    let title: Vec<u16> = title.encode_utf16().chain(Some(0)).collect();
    // No arbitrary handles, external processes, input injection, or subclassing.
    unsafe {
        let hwnd = FindWindowW(core::ptr::null(), title.as_ptr());
        if hwnd.is_null() {
            return false;
        }
        let mut pid = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != std::process::id() {
            return false;
        }
        ShowWindow(hwnd, 6); // SW_MINIMIZE: native system minimization route.
        IsIconic(hwnd) != 0
    }
}
fn native_window(view: View, title: &str) -> WindowRequest {
    let mut request = main_window(view);
    request.title = title.into();
    // No focus stealing or visible test panel on the user's desktop.
    request.position = Some((-20000, -20000));
    request
}

#[test]
#[ignore = "requires interactive Windows desktop; run explicitly, alone"]
fn resident_native_minimize_reopen_tooltip_queue_and_zero_window_exit() {
    let root = tempfile::tempdir().expect("fixture directory");
    let service = GuiService::new().expect("controller");
    let control = service.control();
    let defaults = GuiOptions {
        root: root.path().into(),
        bind: "127.0.0.1:0".parse().unwrap(),
        allow_shell: false,
        allow_transfers: false,
        proxy: None,
        no_proxy: true,
        ca_cert: None,
        relay: None,
        home: root.path().join("home"),
        name: "native probe".into(),
        #[cfg(feature = "fleet-core")]
        fleet_setup: None,
    };
    let input = Inputs {
        root: signal(root.path().display().to_string()),
        bind: signal(defaults.bind.to_string()),
        relay: signal(String::new()),
        proxy: signal(String::new()),
        direct: signal(true),
    };
    let view = View {
        control,
        defaults,
        input,
        heading: signal("native probe".into()),
        endpoint: signal("not listening in UI test".into()),
        detail: signal("probe".into()),
        network: signal("direct".into()),
        relay_status: signal("disabled".into()),
        start_text: signal("启动 Agent".into()),
        pause_text: signal("暂停 HTTP".into()),
    };
    let title = format!("ferroc native probe {}", std::process::id());
    let failures = Rc::new(RefCell::new(Vec::<String>::new()));
    let observed = Rc::new(RefCell::new(Vec::<&'static str>::new()));
    let done = Rc::new(Cell::new(false));
    let errors = failures.clone();
    let receipts = observed.clone();
    let complete = done.clone();
    let mut app = App::resident("ferroc native verification")
        .icon(IconSource::sized(icon_at))
        .tray(
            Tray::new()
                .tooltip("ferroc verification")
                .icon_rgba(32, 32, icon_at(32).rgba()),
        )
        .start_window(native_window(view.clone(), &title));
    let tray = app.tray_handle();
    let mut stage = 0;
    let mut ticks = 0;
    let app = app.on_interval(STATUS_INTERVAL, move |ctx| {
        ticks += 1;
        if ticks > 80 {
            errors
                .borrow_mut()
                .push(format!("native stage {stage} exceeded deadline"));
            tray.quit();
            return;
        }
        match stage {
            0 if window_open(MAIN_WINDOW) => {
                input.root.set("retained editable configuration".into());
                tray.set_tooltip("ferroc | visible probe");
                stage = 1;
            }
            1 => {
                if !tray.pending_ops().is_empty() {
                    errors
                        .borrow_mut()
                        .push("visible tray effects stalled".into());
                    tray.quit();
                    return;
                }
                receipts
                    .borrow_mut()
                    .push("visible tooltip intent consumed");
                if !minimize_own_window(&title) {
                    errors
                        .borrow_mut()
                        .push("own native window did not minimize".into());
                    tray.quit();
                    return;
                }
                receipts
                    .borrow_mut()
                    .push("native IsIconic after SW_MINIMIZE");
                stage = 2;
            }
            2 if !window_open(MAIN_WINDOW) => {
                receipts
                    .borrow_mut()
                    .push("production minimized-window observer closed singleton");
                tray.set_tooltip("ferroc | zero-window state");
                stage = 3;
            }
            3 => {
                if !tray.pending_ops().is_empty() {
                    errors
                        .borrow_mut()
                        .push("zero-window tray effects stalled".into());
                    tray.quit();
                    return;
                }
                receipts
                    .borrow_mut()
                    .push("zero-window tooltip intent consumed");
                ctx.open_window(native_window(view.clone(), &title));
                stage = 4;
            }
            4 if window_open(MAIN_WINDOW) => {
                if input.root.get() != "retained editable configuration" {
                    errors
                        .borrow_mut()
                        .push("recreated window lost input model".into());
                    tray.quit();
                    return;
                }
                receipts
                    .borrow_mut()
                    .push("singleton reopened with retained input model");
                windui::event::HotkeyCtx::default().close_window(MAIN_WINDOW);
                stage = 5;
            }
            5 if !window_open(MAIN_WINDOW) => {
                receipts.borrow_mut().push("zero-window quit intent");
                complete.set(true);
                tray.quit();
                stage = 6;
            }
            _ => {}
        }
    });
    let ok = app.run_resident();
    service.finish().expect("controller clean shutdown");
    assert!(ok, "native WindUI startup failed");
    assert!(failures.borrow().is_empty(), "{:?}", failures.borrow());
    assert!(done.get(), "native sequence incomplete");
    assert!(
        !window_open(MAIN_WINDOW),
        "window registration must be removed"
    );
    println!(
        "Native WindUI receipts (not shell tooltip readback): {:?}",
        observed.borrow()
    );
}
