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
