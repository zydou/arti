//! Test helpers.

/// Check that we can parse `key_spec.arti_path()` back into a `KeySpecifier` that is equal to
/// `key_spec`.
#[macro_export]
macro_rules! assert_key_specifier_rountrip {
    ($key_spec_ty:ty, $key_spec:expr) => {{
        assert_eq!(
            $key_spec,
            <$key_spec_ty>::try_from(&$crate::KeyPath::Arti($key_spec.arti_path().unwrap())).unwrap()
        );
    }};
}
