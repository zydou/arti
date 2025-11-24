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
            cfg_if::cfg_if! {
                if #[cfg(feature = "onion-service-cli-extra")] {
                    t.case("tests/testcases/hss-extra/*.toml");
                } else {
                    t.case("tests/testcases/hss/*.toml");
                }
            }
            t.case("tests/testcases/hss/*.md");
        } else {
            // This is not yet implemented, see #1487
            t.skip("tests/testcases/hss-feature-missing/*.toml");
            t.skip("tests/testcases/hss-feature-missing/*.md");
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "hsc")] {
            cfg_if::cfg_if! {
                if #[cfg(feature = "onion-service-cli-extra")] {
                    t.case("tests/testcases/hsc-extra/*.toml");
                } else {
                    t.case("tests/testcases/hsc/*.toml");
                }
            }
            t.case("tests/testcases/hsc-common/*.toml");
            t.case("tests/testcases/hsc-common/*.md");
        } else {
            // This is not yet implemented, see #1487
            t.skip("tests/testcases/hsc-feature-missing/*.toml");
            t.skip("tests/testcases/hsc-feature-missing/*.md");
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "onion-service-cli-extra")] {
            t.case("tests/testcases/keys/*.toml");
            t.case("tests/testcases/keys/*.md");
        } else {
            // This is not yet implemented, see #1487
            t.skip("tests/testcases/keys-feature-missing/*.toml");
            t.skip("tests/testcases/keys-feature-missing/*.md");
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "onion-service-cli-extra")] {
            t.case("tests/testcases/keys-raw/*.toml");
            t.case("tests/testcases/keys-raw/*.md");
        } else {
            // This is not yet implemented, see #1487
            t.skip("tests/testcases/keys-raw-feature-missing/*.toml");
            t.skip("tests/testcases/keys-raw-feature-missing/*.md");
        }
    }

    t.case("README.md");

    // Run the tests.
    //
    // NOTE: the TestCases must be dropped *before* the tempdir
    // (otherwise HOME will get cleaned up before the tests have had a chance to run!)
    drop(t);
}
