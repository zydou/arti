//! [`ArtiPath`] and its associated helpers.

use std::str::FromStr;

use derive_deftly::{define_derive_deftly, Deftly};
use derive_more::{Deref, Display, Into};
use serde::{Deserialize, Serialize};
use tor_persist::slug::{self, BadSlug};

use crate::{ArtiPathRange, ArtiPathSyntaxError, KeySpecifierComponent};

// TODO: this is only used for ArtiPaths (we should consider turning this
// intro a regular impl ArtiPath {} and removing the macro).
define_derive_deftly! {
    /// Implement `new()`, `TryFrom<String>` in terms of `validate_str`, and `as_ref<str>`
    //
    // TODO maybe this is generally useful?  Or maybe we should find a crate?
    ValidatedString for struct, expect items:

    impl $ttype {
        #[doc = concat!("Create a new [`", stringify!($tname), "`].")]
        ///
        /// This function returns an error if `inner` is not in the right syntax.
        pub fn new(inner: String) -> Result<Self, ArtiPathSyntaxError> {
            Self::validate_str(&inner)?;
            Ok(Self(inner))
        }
    }

    impl TryFrom<String> for $ttype {
        type Error = ArtiPathSyntaxError;

        fn try_from(s: String) -> Result<Self, ArtiPathSyntaxError> {
            Self::new(s)
        }
    }

    impl FromStr for $ttype {
        type Err = ArtiPathSyntaxError;

        fn from_str(s: &str) -> Result<Self, ArtiPathSyntaxError> {
            Self::validate_str(s)?;
            Ok(Self(s.to_owned()))
        }
    }

    impl AsRef<str> for $ttype {
        fn as_ref(&self) -> &str {
            &self.0.as_str()
        }
    }
}

/// A unique identifier for a particular instance of a key.
///
/// In an [`ArtiNativeKeystore`](crate::ArtiNativeKeystore), this also represents the path of the
/// key relative to the root of the keystore, minus the file extension.
///
/// An `ArtiPath` is a nonempty sequence of [`Slug`](tor_persist::slug::Slug)s, separated by `/`.  Path
/// components may contain lowercase ASCII alphanumerics, and  `-` or `_`.
/// See [slug] for the full syntactic requirements.
/// Consequently, leading or trailing or duplicated / are forbidden.
///
/// The last component of the path may optionally contain the encoded (string) representation
/// of one or more
/// [`KeySpecifierComponent`]
/// s representing the denotators of the key.
/// They are separated from the rest of the component, and from each other,
/// by [`DENOTATOR_SEP`] characters.
/// Denotators are encoded using their
/// [`KeySpecifierComponent::to_slug`]
/// implementation.
/// The denotators **must** come after all the other fields.
/// Denotator strings are validated in the same way as [`Slug`](tor-persist::slug::Slug)s.
///
/// For example, the last component of the path `"foo/bar/bax+denotator_example+1"`
/// is `"bax+denotator_example+1"`.
/// Its denotators are `"denotator_example"` and `"1"` (encoded as strings).
///
/// NOTE: There is a 1:1 mapping between a value that implements `KeySpecifier` and its
/// corresponding `ArtiPath`. A `KeySpecifier` can be converted to an `ArtiPath`, but the reverse
/// conversion is not supported.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Deref, Into, Display)] //
#[derive(Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[derive(Deftly)]
#[derive_deftly(ValidatedString)]
pub struct ArtiPath(String);

/// A separator for `ArtiPath`s.
pub(crate) const PATH_SEP: char = '/';

/// A separator for that marks the beginning of the keys denotators
/// within an [`ArtiPath`].
///
/// This separator can only appear within the last component of an [`ArtiPath`],
/// and the substring that follows it is assumed to be the string representation
/// of the denotators of the path.
pub const DENOTATOR_SEP: char = '+';

impl ArtiPath {
    /// Validate the underlying representation of an `ArtiPath`
    fn validate_str(inner: &str) -> Result<(), ArtiPathSyntaxError> {
        // Validate the denotators, if there are any.
        let path = if let Some((main_part, denotators)) = inner.split_once(DENOTATOR_SEP) {
            for d in denotators.split(DENOTATOR_SEP) {
                let () = slug::check_syntax(d)?;
            }

            main_part
        } else {
            inner
        };

        if let Some(e) = path
            .split(PATH_SEP)
            .map(|s| {
                if s.is_empty() {
                    Err(BadSlug::EmptySlugNotAllowed.into())
                } else {
                    Ok(slug::check_syntax(s)?)
                }
            })
            .find(|e| e.is_err())
        {
            return e;
        }

        Ok(())
    }

    /// Return the substring corresponding to the specified `range`.
    ///
    /// Returns `None` if `range` is not within the bounds of this `ArtiPath`.
    ///
    /// ### Example
    /// ```
    /// # use tor_keymgr::{ArtiPath, ArtiPathRange, ArtiPathSyntaxError};
    /// # fn demo() -> Result<(), ArtiPathSyntaxError> {
    /// let path = ArtiPath::new("foo_bar_bax_1".into())?;
    ///
    /// let range = ArtiPathRange::from(2..5);
    /// assert_eq!(path.substring(&range), Some("o_b"));
    ///
    /// let range = ArtiPathRange::from(22..50);
    /// assert_eq!(path.substring(&range), None);
    /// # Ok(())
    /// # }
    /// #
    /// # demo().unwrap();
    /// ```
    pub fn substring(&self, range: &ArtiPathRange) -> Option<&str> {
        self.0.get(range.0.clone())
    }

    /// Create an `ArtiPath` from an `ArtiPath` and a list of denotators.
    ///
    /// If `cert_denotators` is empty, returns the specified `path` as-is.
    /// Otherwise, returns an `ArtiPath` that consists of the specified `path`
    /// followed by a [`DENOTATOR_SEP`] character and the specified denotators
    /// (the denotators are encoded as described in the [`ArtiPath`] docs).
    ///
    /// Returns an error if any of the specified denotators are not valid `Slug`s.
    //
    /// ### Example
    /// ```nocompile
    /// # // `nocompile` because this function is not pub
    /// # use tor_keymgr::{
    /// #    ArtiPath, ArtiPathRange, ArtiPathSyntaxError, KeySpecifierComponent,
    /// #    KeySpecifierComponentViaDisplayFromStr,
    /// # };
    /// # use derive_more::{Display, FromStr};
    /// # #[derive(Display, FromStr)]
    /// # struct Denotator(String);
    /// # impl KeySpecifierComponentViaDisplayFromStr for Denotator {}
    /// # fn demo() -> Result<(), ArtiPathSyntaxError> {
    /// let path = ArtiPath::new("my_key_path".into())?;
    /// let denotators = [
    ///    &Denotator("foo".to_string()) as &dyn KeySpecifierComponent,
    ///    &Denotator("bar".to_string()) as &dyn KeySpecifierComponent,
    /// ];
    ///
    /// let expected_path = ArtiPath::new("my_key_path+foo+bar".into())?;
    ///
    /// assert_eq!(
    ///    ArtiPath::from_path_and_denotators(path.clone(), &denotators[..])?,
    ///    expected_path
    /// );
    ///
    /// assert_eq!(
    ///    ArtiPath::from_path_and_denotators(path.clone(), &[])?,
    ///    path
    /// );
    /// # Ok(())
    /// # }
    /// #
    /// # demo().unwrap();
    /// ```
    pub(crate) fn from_path_and_denotators(
        path: ArtiPath,
        cert_denotators: &[&dyn KeySpecifierComponent],
    ) -> Result<ArtiPath, ArtiPathSyntaxError> {
        if cert_denotators.is_empty() {
            return Ok(path);
        }

        let path: String = [Ok(path.0)]
            .into_iter()
            .chain(
                cert_denotators
                    .iter()
                    .map(|s| s.to_slug().map(|s| s.to_string())),
            )
            .collect::<Result<Vec<_>, _>>()?
            .join(&DENOTATOR_SEP.to_string());

        ArtiPath::new(path)
    }
}

#[cfg(test)]
mod tests {
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
    use super::*;

    use derive_more::{Display, FromStr};

    use crate::KeySpecifierComponentViaDisplayFromStr;

    #[derive(Display, FromStr)]
    struct Denotator(String);

    impl KeySpecifierComponentViaDisplayFromStr for Denotator {}

    #[test]
    fn arti_path_from_path_and_denotators() {
        let path = ArtiPath::new("my_key_path".into()).unwrap();
        let denotators = [
            &Denotator("foo".to_string()) as &dyn KeySpecifierComponent,
            &Denotator("bar".to_string()) as &dyn KeySpecifierComponent,
            &Denotator("baz".to_string()) as &dyn KeySpecifierComponent,
        ];

        let expected_path = ArtiPath::new("my_key_path+foo+bar+baz".into()).unwrap();

        assert_eq!(
            ArtiPath::from_path_and_denotators(path.clone(), &denotators[..]).unwrap(),
            expected_path
        );

        assert_eq!(
            ArtiPath::from_path_and_denotators(path.clone(), &[]).unwrap(),
            path
        );
    }
}
