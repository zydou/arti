#![doc = include_str!("../README.md")]

/// The value to set the `COLUMNS` environment variable to.
///
/// Set to a large value to suppress line wrapping.
///
/// See <https://github.com/assert-rs/snapbox/issues/361>
const COLUMNS: usize = 1000;

#[test]
fn cli_tests() {
    let t = trycmd::TestCases::new();
    let dir = tempfile::TempDir::new().unwrap();
    t.env("HOME", dir.path().to_str().unwrap())
        .env("COLUMNS", COLUMNS.to_string());

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

    cfg_if::cfg_if! {
        if #[cfg(feature = "hsc")] {
            t.case("tests/testcases/hsc/*.toml");
            t.case("tests/testcases/hsc/*.md");
        } else {
            // This is not yet implemented, see #1487
            t.skip("tests/testcases/hsc-feature-missing/*.toml");
            t.skip("tests/testcases/hsc-feature-missing/*.md");
        }
    }

    t.case("README.md");

    // Run the tests.
    //
    // Note: the TestCases must be dropped *before* the tempdir
    // (otherwise HOME will get cleaned up before the tests have had a chance to run!)
    drop(t);
}
