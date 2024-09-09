//! Test helpers.

// @@ begin test lint list maintained by maint/add_warning @@
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::dbg_macro)]
#![allow(clippy::mixed_attributes_style)]
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::unchecked_duration_subtraction)]
#![allow(clippy::useless_vec)]
#![allow(clippy::needless_pass_by_value)]
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

use std::fmt::Debug;

use crate::{ArtiPath, KeyPath, KeySpecifier};

/// Check that `spec` produces the [`ArtiPath`] from `path`, and that `path` parses to `spec`
///
/// # Panics
///
/// Panics if `path` isn't valid as an `ArtiPath` or any of the checks fail.
pub fn check_key_specifier<S, E>(spec: &S, path: &str)
where
    S: KeySpecifier + Debug + PartialEq,
    S: for<'p> TryFrom<&'p KeyPath, Error = E>,
    E: Debug,
{
    let apath = ArtiPath::new(path.to_string()).unwrap();
    assert_eq!(spec.arti_path().unwrap(), apath);
    assert_eq!(&S::try_from(&KeyPath::Arti(apath)).unwrap(), spec, "{path}");
}

/// OpenSSH keys used for testing.
#[cfg(test)]
pub(crate) mod ssh_keys {
    /// An Ed25519 keypair
    pub(crate) const OPENSSH_ED25519: &str = include_str!("../testdata/ed25519_openssh.private");

    /// An Ed25519 public key
    pub(crate) const OPENSSH_ED25519_PUB: &str = include_str!("../testdata/ed25519_openssh.public");

    /// An Ed25519 keypair that fails to parse.
    pub(crate) const OPENSSH_ED25519_BAD: &str =
        include_str!("../testdata/ed25519_openssh_bad.private");

    /// An Ed25519 public key that fails to parse.
    pub(crate) const OPENSSH_ED25519_PUB_BAD: &str =
        include_str!("../testdata/ed25519_openssh_bad.public");

    /// An expanded Ed25519 keypair.
    pub(crate) const OPENSSH_EXP_ED25519: &str =
        include_str!("../testdata/ed25519_expanded_openssh.private");

    /// A public key using the ed25519-expanded@spec.torproject.org algorithm.
    ///
    /// Not valid because Ed25519 public keys can't be "expanded".
    pub(crate) const OPENSSH_EXP_ED25519_PUB: &str =
        include_str!("../testdata/ed25519_expanded_openssh.public");

    /// An expanded Ed25519 keypair that fails to parse.
    pub(crate) const OPENSSH_EXP_ED25519_BAD: &str =
        include_str!("../testdata/ed25519_expanded_openssh_bad.private");

    /// A DSA keypair.
    pub(crate) const OPENSSH_DSA: &str = include_str!("../testdata/dsa_openssh.private");

    /// A X25519 keypair.
    pub(crate) const OPENSSH_X25519: &str = include_str!("../testdata/x25519_openssh.private");

    /// A X25519 public key.
    pub(crate) const OPENSSH_X25519_PUB: &str = include_str!("../testdata/x25519_openssh.public");

    /// An invalid keypair using the pangolin@torproject.org algorithm.
    pub(crate) const OPENSSH_X25519_UNKNOWN_ALGORITHM: &str =
        include_str!("../testdata/x25519_openssh_unknown_algorithm.private");

    /// An invalid public key using the armadillo@torproject.org algorithm.
    pub(crate) const OPENSSH_X25519_PUB_UNKNOWN_ALGORITHM: &str =
        include_str!("../testdata/x25519_openssh_unknown_algorithm.public");
}

/// A module exporting a key specifier used for testing.
#[cfg(test)]
mod specifier {
    use crate::{ArtiPath, ArtiPathUnavailableError, CTorPath, KeySpecifier};

    /// A key specifier path.
    pub(crate) const TEST_SPECIFIER_PATH: &str = "parent1/parent2/parent3/test-specifier";

    /// A [`KeySpecifier`] with a fixed [`ArtiPath`] prefix and custom suffix.
    ///
    /// The inner String is the suffix of its `ArtiPath`.
    #[derive(Default)]
    pub(crate) struct TestSpecifier(String);

    impl TestSpecifier {
        /// Create a new [`TestSpecifier`].
        pub(crate) fn new(prefix: impl AsRef<str>) -> Self {
            Self(prefix.as_ref().into())
        }

        /// Return the prefix of the [`ArtiPath`] of this specifier.
        pub(crate) fn path_prefix() -> &'static str {
            TEST_SPECIFIER_PATH
        }
    }

    impl KeySpecifier for TestSpecifier {
        fn arti_path(&self) -> Result<ArtiPath, ArtiPathUnavailableError> {
            Ok(ArtiPath::new(format!("{TEST_SPECIFIER_PATH}{}", self.0))
                .map_err(|e| tor_error::internal!("{e}"))?)
        }

        fn ctor_path(&self) -> Option<CTorPath> {
            None
        }

        fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>> {
            None
        }
    }
}

#[cfg(test)]
pub(crate) use specifier::*;
