#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
#[path = "../gui_windows.rs"]
mod gui_windows;

#[cfg(windows)]
fn main() {
    if let Err(error) = gui_windows::run() {
        // No secrets are included in top-level diagnostics. Windows builds have
        // no console; retain the actionable startup message in a native dialog.
        gui_windows::show_startup_error(&error.to_string());
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!(
        "ferroc-gui is currently a Windows-only frontend; use ferroc stdio on this platform."
    );
    std::process::exit(1);
}
