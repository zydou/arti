fn main() {
    // TODO ns-vote remove this when we actually have this feature
    println!(
        r#"
cargo::rustc-check-cfg=cfg(feature, values("ns-vote"))
"#
    );
}
