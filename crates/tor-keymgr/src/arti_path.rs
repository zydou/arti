//! [`ArtiPath`] and its associated helpers.

use std::str::FromStr;

use derive_deftly::{Deftly, define_derive_deftly};
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    use derive_more::{Display, FromStr};
    use itertools::chain;

    use crate::KeySpecifierComponentViaDisplayFromStr;

    impl PartialEq for ArtiPathSyntaxError {
        fn eq(&self, other: &Self) -> bool {
            use ArtiPathSyntaxError::*;

            match (self, other) {
                (Slug(err1), Slug(err2)) => err1 == err2,
                _ => false,
            }
        }
    }

    macro_rules! assert_ok {
        ($ty:ident, $inner:expr) => {{
            let path = $ty::new($inner.to_string());
            let path_fromstr: Result<$ty, _> = $ty::try_from($inner.to_string());
            let path_tryfrom: Result<$ty, _> = $inner.to_string().try_into();
            assert!(path.is_ok(), "{} should be valid", $inner);
            assert_eq!(path.as_ref().unwrap().to_string(), *$inner);
            assert_eq!(path, path_fromstr);
            assert_eq!(path, path_tryfrom);
        }};
    }

    fn assert_err(path: &str, error_kind: ArtiPathSyntaxError) {
        let path_anew = ArtiPath::new(path.to_string());
        let path_fromstr = ArtiPath::try_from(path.to_string());
        let path_tryfrom: Result<ArtiPath, _> = path.to_string().try_into();
        assert!(path_anew.is_err(), "{} should be invalid", path);
        let actual_err = path_anew.as_ref().unwrap_err();
        assert_eq!(actual_err, &error_kind);
        assert_eq!(path_anew, path_fromstr);
        assert_eq!(path_anew, path_tryfrom);
    }

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

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn arti_path_validation() {
        const VALID_ARTI_PATH_COMPONENTS: &[&str] = &["my-hs-client-2", "hs_client"];
        const VALID_ARTI_PATHS: &[&str] = &[
            "path/to/client+subvalue+fish",
            "_hs_client",
            "hs_client-",
            "hs_client_",
            "_",
        ];

        const BAD_FIRST_CHAR_ARTI_PATHS: &[&str] = &["-hs_client", "-"];

        const DISALLOWED_CHAR_ARTI_PATHS: &[(&str, char)] = &[
            ("client?", '?'),
            ("no spaces please", ' '),
            ("client٣¾", '٣'),
            ("clientß", 'ß'),
        ];

        const EMPTY_PATH_COMPONENT: &[&str] =
            &["/////", "/alice/bob", "alice//bob", "alice/bob/", "/"];

        for path in chain!(VALID_ARTI_PATH_COMPONENTS, VALID_ARTI_PATHS) {
            assert_ok!(ArtiPath, path);
        }

        for (path, bad_char) in DISALLOWED_CHAR_ARTI_PATHS {
            assert_err(
                path,
                ArtiPathSyntaxError::Slug(BadSlug::BadCharacter(*bad_char)),
            );
        }

        for path in BAD_FIRST_CHAR_ARTI_PATHS {
            assert_err(
                path,
                ArtiPathSyntaxError::Slug(BadSlug::BadFirstCharacter(path.chars().next().unwrap())),
            );
        }

        for path in EMPTY_PATH_COMPONENT {
            assert_err(
                path,
                ArtiPathSyntaxError::Slug(BadSlug::EmptySlugNotAllowed),
            );
        }

        const SEP: char = PATH_SEP;
        // This is a valid ArtiPath, but not a valid Slug
        let path = format!("a{SEP}client{SEP}key+private");
        assert_ok!(ArtiPath, path);

        const PATH_WITH_TRAVERSAL: &str = "alice/../bob";
        assert_err(
            PATH_WITH_TRAVERSAL,
            ArtiPathSyntaxError::Slug(BadSlug::BadCharacter('.')),
        );

        const REL_PATH: &str = "./bob";
        assert_err(
            REL_PATH,
            ArtiPathSyntaxError::Slug(BadSlug::BadCharacter('.')),
        );

        const EMPTY_DENOTATOR: &str = "c++";
        assert_err(
            EMPTY_DENOTATOR,
            ArtiPathSyntaxError::Slug(BadSlug::EmptySlugNotAllowed),
        );
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn arti_path_with_denotator() {
        const VALID_ARTI_DENOTATORS: &[&str] = &[
            "foo",
            "one_two_three-f0ur",
            "1-2-3-",
            "1-2-3_",
            "1-2-3",
            "_1-2-3",
            "1-2-3",
        ];

        const BAD_OUTER_CHAR_DENOTATORS: &[&str] = &["-1-2-3"];

        for denotator in VALID_ARTI_DENOTATORS {
            let path = format!("foo/bar/qux+{denotator}");
            assert_ok!(ArtiPath, path);
        }

        for denotator in BAD_OUTER_CHAR_DENOTATORS {
            let path = format!("foo/bar/qux+{denotator}");

            assert_err(
                &path,
                ArtiPathSyntaxError::Slug(BadSlug::BadFirstCharacter(
                    denotator.chars().next().unwrap(),
                )),
            );
        }

        // An ArtiPath with multiple denotators
        let path = format!(
            "foo/bar/qux+{}+{}+foo",
            VALID_ARTI_DENOTATORS[0], VALID_ARTI_DENOTATORS[1]
        );
        assert_ok!(ArtiPath, path);

        // An invalid ArtiPath with multiple valid denotators and
        // an empty (invalid) denotator
        let path = format!(
            "foo/bar/qux+{}+{}+foo+",
            VALID_ARTI_DENOTATORS[0], VALID_ARTI_DENOTATORS[1]
        );
        assert_err(
            &path,
            ArtiPathSyntaxError::Slug(BadSlug::EmptySlugNotAllowed),
        );
    }

    #[test]
    fn substring() {
        const KEY_PATH: &str = "hello";
        let path = ArtiPath::new(KEY_PATH.to_string()).unwrap();

        assert_eq!(path.substring(&(0..1).into()).unwrap(), "h");
        assert_eq!(path.substring(&(2..KEY_PATH.len()).into()).unwrap(), "llo");
        assert_eq!(
            path.substring(&(0..KEY_PATH.len()).into()).unwrap(),
            "hello"
        );
        assert_eq!(path.substring(&(0..KEY_PATH.len() + 1).into()), None);
        assert_eq!(path.substring(&(0..0).into()).unwrap(), "");
    }
}
