#![doc = include_str!("../README.md")]

#[test]
fn cli_tests() {
    let t = trycmd::TestCases::new();
    let dir = tempfile::TempDir::new().unwrap();
    t.env("HOME", dir.path().to_str().unwrap());

    cfg_if::cfg_if! {
        if #[cfg(feature = "onion-service-service")] {
            t.case("tests/testcases/hss/*.toml");
            t.case("tests/testcases/hss/*.md");
        } else {
            // This is not yet implemented, see #1487
            t.skip("tests/testcases/hss-feature-missing/*.toml");
            t.skip("tests/testcases/hss-feature-missing/*.md");
        }
    }

    t.case("README.md");

    // Run the tests.
    //
    // Note: the TestCases must be dropped *before* the tempdir
    // (otherwise HOME will get cleaned up before the tests have had a chance to run!)
    drop(t);
}
