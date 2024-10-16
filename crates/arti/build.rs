fn main() {
    // When we test our cfg machinery, in crates/arti/src/cfg.rs, we need to know
    // which cargo features are enabled - not just in the arti crate, but in the dependencies.
    // Indeed, we want to test with precisely the features we intend.
    // However, cargo feature unification can mean that features are enabled in dependencies,
    // even if *we* (arti) don't request them - especially if we run with --workspace.
    //
    // This `--cfg` is passed by maint/test-all-crates, when we test each crate individually.
    // That tells our test cases in cfg.rs that they can check that a feature is
    // actually unsupported.
    //
    // (We don't want this to be a normal cargo feature because then it would be enabled
    // with --workspace --all-features, defeating the point.)
    println!(r#"cargo:rustc-check-cfg=cfg(arti_features_precise)"#);
}
