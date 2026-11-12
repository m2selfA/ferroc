#[cfg(windows)]
#[test]
fn policy_accepts_its_own_canonical_paths() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("probe.txt");
    std::fs::write(&file, "probe").unwrap();
    let p = ferroc::config::Policy::new(vec![dir.path().to_owned()], false).unwrap();
    let canonical = std::fs::canonicalize(&file).unwrap();
    let result = p.resolve(canonical.to_str().unwrap());
    assert!(
        result.is_ok(),
        "canonical path {canonical:?} rejected: {result:?}"
    );
}
