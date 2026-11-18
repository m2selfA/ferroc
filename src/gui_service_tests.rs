use super::*;
use std::path::PathBuf;

fn options() -> GuiOptions {
    GuiOptions {
        root: std::env::temp_dir(),
        bind: "127.0.0.1:0".parse().unwrap(),
        allow_shell: false,
        allow_transfers: true,
        proxy: None,
        no_proxy: true,
        ca_cert: None,
        relay: None,
        home: std::env::temp_dir(),
        name: "gui-test".into(),
        fleet_setup: None,
    }
}

fn refuse(options: GuiOptions) -> String {
    let state = Arc::new(Mutex::new(State {
        phase: Phase::Stopped,
        detail: String::new(),
        endpoint: None,
        token: None,
        network: String::new(),
        relay: String::new(),
        http: None,
        fleet_runtime: std::sync::Weak::new(),
    }));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // `start` is async and binds a listener; the two fleet guards run BEFORE any
    // of that, so a refusal can be asserted without opening a socket or a relay.
    match runtime.block_on(start(options, state)) {
        Ok(_) => panic!("fleet configuration without a relay must be refused"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn fleet_setup_without_relay_is_refused_instead_of_silently_unused() {
    let mut o = options();
    o.fleet_setup = Some(PathBuf::from("setup.json"));
    let text = refuse(o);
    assert!(text.contains("fleet setup需要同时配置中继地址"), "{text}");
}

#[test]
fn fleet_setup_cannot_be_combined_with_disabled_transfers() {
    let mut o = options();
    o.fleet_setup = Some(PathBuf::from("setup.json"));
    o.relay = Some("https://relay.example".into());
    o.allow_transfers = false;
    let text = refuse(o);
    assert!(text.contains("--no-transfers"), "{text}");
}
