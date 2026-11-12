//! One Agnes-derived identity for executable resources, browser UI and future desktop surfaces.
//! This module supplies bytes only: it does not implement a native window or tray lifecycle.
pub const PNG: &[u8] = include_bytes!("../assets/ferroc.png");
pub const ICO: &[u8] = include_bytes!("../assets/ferroc.ico");
pub const PNG_32: &[u8] = include_bytes!("../assets/icons/32.png");
