fn main() {
    println!("cargo:rerun-if-changed=assets/ferroc.ico");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/ferroc.ico")
            .set("ProductName", "ferroc")
            .set("FileDescription", "ferroc - Ferrum + Commander")
            .set("InternalName", "ferroc");
        res.compile()
            .expect("Windows SDK resource compiler required");
    }
}
