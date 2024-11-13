fn main() {
    // get the enabled cargo features
    let features = std::env::vars()
        .filter_map(|(env_name, val)| feature_name(env_name, val))
        // arti crates all use lowercase feature names with '-'
        .map(|feature| feature.replace('_', "-").to_lowercase())
        .collect::<Vec<_>>()
        .join(",");
    println!("cargo:rustc-env=BUILD_FEATURES={features}");

    let opt_level = std::env::var("OPT_LEVEL").unwrap();
    println!("cargo:rustc-env=BUILD_OPT_LEVEL={opt_level}");

    let profile = std::env::var("PROFILE").unwrap();
    println!("cargo:rustc-env=BUILD_PROFILE={profile}");

    let debug = std::env::var("DEBUG").unwrap();
    println!("cargo:rustc-env=BUILD_DEBUG={debug}");

    let target = std::env::var("TARGET").unwrap();
    println!("cargo:rustc-env=BUILD_TARGET={target}");

    let host = std::env::var("HOST").unwrap();
    println!("cargo:rustc-env=BUILD_HOST={host}");

    let rustc = std::env::var("RUSTC").unwrap();
    let rustc_version = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .unwrap()
        .stdout;
    let rustc_version = String::from_utf8(rustc_version).unwrap();
    println!("cargo:rustc-env=BUILD_RUSTC_VERSION={rustc_version}");
}

/// Returns `Some` if `name` begins with "CARGO_FEATURE_" and `val` is "1". Used when obtaining a
/// list of enabled features.
fn feature_name(name: String, val: String) -> Option<String> {
    let feature = name.strip_prefix("CARGO_FEATURE_")?;
    if val != "1" {
        return None;
    }
    Some(feature.to_string())
}
