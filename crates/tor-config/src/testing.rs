//! Helpers for testing configuration.

/// Assert that the specified error is the specified `kind` of
/// [`ConfigBuildError`](crate::ConfigBuildError).
#[macro_export]
macro_rules! assert_config_error {
    ($err:expr, $kind:tt, $expect_problem:expr) => {
        match $err {
            $crate::ConfigBuildError::$kind { problem, .. } => {
                assert_eq!(problem, $expect_problem);
            }
            _ => {
                panic!("unexpected error {:?}", $err);
            }
        }
    };
}
