#![cfg(not(feature = "fleet-core"))]
use std::process::Command;
#[test]
fn default_binary_does_not_advertise_or_accept_fleet_setup() {
    let help = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(
        !text
            .lines()
            .any(|line| line.trim_start().starts_with("fleet "))
    );
    let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args(["fleet", "--help"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
        .args(["fleet-dir", "--help"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        !text
            .lines()
            .any(|line| line.trim_start().starts_with("fleet-dir "))
    );
    for subcommand in ["relay", "agent"] {
        let out = Command::new(env!("CARGO_BIN_EXE_ferroc"))
            .args([subcommand, "--help"])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains("--fleet-setup"));
    }
}
