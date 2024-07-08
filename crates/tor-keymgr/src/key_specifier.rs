//! The [`KeySpecifier`] trait and its implementations.

use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::ops::Range;
use std::result::Result as StdResult;
use std::str::FromStr;

use arrayvec::ArrayVec;
use derive_more::{Deref, DerefMut, Display, From, Into};
use thiserror::Error;
use tor_error::{internal, into_internal, Bug};
use tor_hscrypto::pk::{HsId, HsIdParseError, HSID_ONION_SUFFIX};
use tor_hscrypto::time::TimePeriod;
use tor_persist::slug::Slug;

use crate::{ArtiPath, ArtiPathSyntaxError};

// #[doc(hidden)] applied at crate toplevel
#[macro_use]
pub mod derive;

/// The identifier of a key.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, From, Display)]
#[non_exhaustive]
pub enum KeyPath {
    /// An Arti key path.
    Arti(ArtiPath),
    /// A C-Tor key path.
    CTor(CTorPath),
}

/// A range specifying a substring of a [`KeyPath`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, From)]
pub struct KeyPathRange(pub(crate) Range<usize>);

impl KeyPath {
    /// Check whether this `KeyPath` matches the specified [`KeyPathPattern`].
    ///
    /// If the `KeyPath` matches the pattern, this returns the ranges that match its dynamic parts.
    ///
    /// ### Example
    /// ```
    /// # use tor_keymgr::{ArtiPath, KeyPath, KeyPathPattern, ArtiPathSyntaxError};
    /// # fn demo() -> Result<(), ArtiPathSyntaxError> {
    /// let path = KeyPath::Arti(ArtiPath::new("foo_bar_baz_1".into())?);
    /// let pattern = KeyPathPattern::Arti("*_bar_baz_*".into());
    /// let matches = path.matches(&pattern).unwrap();
    ///
    /// let path = path.arti().unwrap();
    /// assert_eq!(matches.len(), 2);
    /// assert_eq!(path.substring(&matches[0]), Some("foo"));
    /// assert_eq!(path.substring(&matches[1]), Some("1"));
    /// # Ok(())
    /// # }
    /// #
    /// # demo().unwrap();
    /// ```
    pub fn matches(&self, pat: &KeyPathPattern) -> Option<Vec<KeyPathRange>> {
        use KeyPathPattern::*;

        let (pattern, path): (&str, &str) = match (self, pat) {
            (KeyPath::Arti(p), Arti(pat)) => (pat.as_ref(), p.as_ref()),
            (KeyPath::CTor(p), CTor(pat)) => (pat.as_ref(), p.as_ref()),
            _ => return None,
        };

        glob_match::glob_match_with_captures(pattern, path)
            .map(|res| res.into_iter().map(|r| r.into()).collect())
    }

    // TODO: rewrite these getters using derive_adhoc if KeyPath grows more variants.

    /// Return the underlying [`ArtiPath`], if this is a `KeyPath::Arti`.
    pub fn arti(&self) -> Option<&ArtiPath> {
        match self {
            KeyPath::Arti(ref arti) => Some(arti),
            KeyPath::CTor(_) => None,
        }
    }

    /// Return the underlying [`CTorPath`], if this is a `KeyPath::CTor`.
    pub fn ctor(&self) -> Option<&CTorPath> {
        match self {
            KeyPath::Arti(_) => None,
            KeyPath::CTor(ref ctor) => Some(ctor),
        }
    }
}

/// A pattern specifying some or all of a kind of key
///
/// Generally implemented on `SomeKeySpecifierPattern` by
/// applying
/// [`#[derive_deftly(KeySpecifier)`](crate::derive_deftly_template_KeySpecifier)
/// to `SomeKeySpecifier`.
pub trait KeySpecifierPattern {
    /// Obtain a pattern template that matches all keys of this type.
    fn new_any() -> Self
    where
        Self: Sized;

    /// Get a [`KeyPathPattern`] that can match the [`ArtiPath`]s
    /// of some or all the keys of this type.
    fn arti_pattern(&self) -> Result<KeyPathPattern, Bug>;
}

/// An error while attempting to extract information about a key given its path
///
/// For example, from a [`KeyPathInfoExtractor`].
///
/// See also `crate::keystore::arti::MalformedPathError`,
/// which occurs at a lower level.
///
// Note: Currently, all KeyPathErrors (except Unrecognized and Bug) are only returned from
// functions that parse ArtiPaths and/or ArtiPath denotators, so their context contains an
// `ArtiPath` rather than a `KeyPath` (i.e. PatternNotMatched, InvalidArtiPath,
// InvalidKeyPathComponent value can only happen if we're dealing with an ArtiPath).
//
// For now this is alright, but we might want to rethink this error enum (for example, a better
// idea might be to create an ArtiPathError { path: ArtiPath, kind: ArtiPathErrorKind } error type
// and move PatternNotMatched, InvalidArtiPath, InvalidKeyPathComponentValue to the new
// ArtiPathErrorKind enum.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum KeyPathError {
    /// The path did not match the expected pattern.
    #[error("Path does not match expected pattern")]
    PatternNotMatched(ArtiPath),

    /// The path is not recognized.
    ///
    /// Returned by [`KeyMgr::describe`](crate::KeyMgr::describe) when none of its
    /// [`KeyPathInfoExtractor`]s is able to parse the specified [`KeyPath`].
    #[error("Unrecognized path: {0}")]
    Unrecognized(KeyPath),

    /// Found an invalid [`ArtiPath`], which is syntactically invalid on its face
    #[error("ArtiPath {path} is invalid")]
    InvalidArtiPath {
        /// What was wrong with the value
        #[source]
        error: ArtiPathSyntaxError,
        /// The offending `ArtiPath`.
        path: ArtiPath,
    },

    /// An invalid key path component value string was encountered
    ///
    /// When attempting to interpret a key path, one of the elements in the path
    /// contained a string value which wasn't a legitimate representation of the
    /// type of data expected there for this kind of key.
    ///
    /// (But the key path is in the proper character set.)
    #[error("invalid string value for element of key path")]
    InvalidKeyPathComponentValue {
        /// What was wrong with the value
        #[source]
        error: InvalidKeyPathComponentValue,
        /// The name of the "key" (what data we were extracting)
        ///
        /// Should be valid Rust identifier syntax.
        key: String,
        /// The `ArtiPath` of the key.
        path: ArtiPath,
        /// The substring of the `ArtiPath` that couldn't be parsed.
        value: Slug,
    },

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// Error to be returned by `KeySpecifierComponent::from_slug` implementations
///
/// Currently this error contains little information,
/// but the context and value are provided in
/// [`KeyPathError::InvalidKeyPathComponentValue`].
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum InvalidKeyPathComponentValue {
    /// Found an invalid slug.
    ///
    /// The inner string should be a description of what is wrong with the slug.
    /// It should not say that the keystore was corrupted,
    /// (keystore corruption errors are reported using higher level
    /// [`KeystoreCorruptionError`s](crate::KeystoreCorruptionError)),
    /// or where the information came from (the context is encoded in the
    /// enclosing [`KeyPathError::InvalidKeyPathComponentValue`] error).
    #[error("{0}")]
    Slug(String),

    /// An internal error.
    ///
    /// The [`KeySpecifierComponentViaDisplayFromStr`] trait maps any errors returned by the
    /// [`FromStr`] implementation of the implementing type to this variant.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// Information about a [`KeyPath`].
///
/// The information is extracted from the [`KeyPath`] itself
/// (_not_ from the key data) by a [`KeyPathInfoExtractor`].
//
// TODO  maybe the getters should be combined with the builder, or something?
#[derive(Debug, Clone, PartialEq, derive_builder::Builder, amplify::Getters)]
pub struct KeyPathInfo {
    /// A human-readable summary string describing what the [`KeyPath`] is for.
    ///
    /// This should *not* recapitulate information in the `extra_info`.
    summary: String,
    /// The key role, ie its official name in the Tor Protocols.
    ///
    /// This should usually start with `KS_`.
    //
    // TODO (#1195): see the comment for #[deftly(role)] in derive.rs
    role: String,
    /// Additional information, in the form of key-value pairs.
    ///
    /// This will contain human-readable information that describes the individual
    /// components of a KeyPath. For example, for the [`ArtiPath`]
    /// `hs/foo/KS_hs_id.expanded_ed25519_private`, the extra information could
    /// be `("kind", "service)`, `("nickname", "foo")`, etc.
    #[builder(default, setter(custom))]
    extra_info: BTreeMap<String, String>,
}

impl KeyPathInfo {
    /// Start to build a [`KeyPathInfo`]: return a fresh [`KeyPathInfoBuilder`]
    pub fn builder() -> KeyPathInfoBuilder {
        KeyPathInfoBuilder::default()
    }
}

impl KeyPathInfoBuilder {
    /// Initialize the additional information of this builder with the specified values.
    ///
    /// Erases the preexisting `extra_info`.
    pub fn set_all_extra_info(
        &mut self,
        all_extra_info: impl Iterator<Item = (String, String)>,
    ) -> &mut Self {
        self.extra_info = Some(all_extra_info.collect());
        self
    }

    /// Append the specified key-value pair to the `extra_info`.
    ///
    /// The preexisting `extra_info` is preserved.
    pub fn extra_info(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        let extra_info = self.extra_info.get_or_insert(Default::default());
        extra_info.insert(key.into(), value.into());
        self
    }
}

/// A trait for extracting info out of a [`KeyPath`]s.
///
/// This trait is used by [`KeyMgr::describe`](crate::KeyMgr::describe)
/// to extract information out of [`KeyPath`]s.
pub trait KeyPathInfoExtractor: Send + Sync {
    /// Describe the specified `path`.
    fn describe(&self, path: &KeyPath) -> StdResult<KeyPathInfo, KeyPathError>;
}

/// Register a [`KeyPathInfoExtractor`] for use with [`KeyMgr`](crate::KeyMgr).
#[macro_export]
macro_rules! register_key_info_extractor {
    ($kv:expr) => {{
        $crate::inventory::submit!(&$kv as &dyn $crate::KeyPathInfoExtractor);
    }};
}

/// A pattern that can be used to match [`ArtiPath`]s or [`CTorPath`]s.
///
/// Create a new `KeyPathPattern`.
///
/// ## Syntax
///
/// NOTE: this table is copied verbatim from the [`glob-match`] docs.
///
/// | Syntax  | Meaning                                                                                                                                                                                             |
/// | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
/// | `?`     | Matches any single character.                                                                                                                                                                       |
/// | `*`     | Matches zero or more characters, except for path separators (e.g. `/`).                                                                                                                             |
/// | `**`    | Matches zero or more characters, including path separators. Must match a complete path segment (i.e. followed by a `/` or the end of the pattern).                                                  |
/// | `[ab]`  | Matches one of the characters contained in the brackets. Character ranges, e.g. `[a-z]` are also supported. Use `[!ab]` or `[^ab]` to match any character _except_ those contained in the brackets. |
/// | `{a,b}` | Matches one of the patterns contained in the braces. Any of the wildcard characters can be used in the sub-patterns. Braces may be nested up to 10 levels deep.                                     |
/// | `!`     | When at the start of the glob, this negates the result. Multiple `!` characters negate the glob multiple times.                                                                                     |
/// | `\`     | A backslash character may be used to escape any of the above special characters.                                                                                                                    |
///
/// [`glob-match`]: https://crates.io/crates/glob-match
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyPathPattern {
    /// A pattern for matching [`ArtiPath`]s.
    Arti(String),
    /// A pattern for matching [`CTorPath`]s.
    CTor(String),
}

/// The path of a key in the C Tor key store.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Deref, DerefMut, Into, Display)]
pub struct CTorPath(String);

/// The "specifier" of a key, which identifies an instance of a key.
///
/// [`KeySpecifier::arti_path()`] should uniquely identify an instance of a key.
pub trait KeySpecifier {
    /// The location of the key in the Arti key store.
    ///
    /// This also acts as a unique identifier for a specific key instance.
    fn arti_path(&self) -> StdResult<ArtiPath, ArtiPathUnavailableError>;

    /// The location of the key in the C Tor key store (if supported).
    ///
    /// This function should return `None` for keys that are recognized by Arti's key stores, but
    /// not by C Tor's key store (such as `HsClientIntroAuthKeypair`).
    fn ctor_path(&self) -> Option<CTorPath>;
}

/// A trait for serializing and deserializing specific types of [`Slug`]s.
///
/// A `KeySpecifierComponent` is a specific kind of `Slug`. A `KeySpecifierComponent` is
/// always a valid `Slug`, but may have a more restricted charset, or more specific
/// validation rules. A `Slug` is not always a valid `KeySpecifierComponent`
/// instance.
///
/// If you are deriving [`DefaultKeySpecifier`](crate::derive_deftly_template_KeySpecifier) for a
/// struct, all of its fields must implement this trait.
///
/// If you are implementing [`KeySpecifier`] and [`KeyPathInfoExtractor`] manually rather than by
/// deriving `DefaultKeySpecifier`, you do not need to implement this trait.
pub trait KeySpecifierComponent {
    /// Return the [`Slug`] representation of this type.
    fn to_slug(&self) -> Result<Slug, Bug>;
    /// Try to convert `s` into an object of this type.
    fn from_slug(s: &Slug) -> StdResult<Self, InvalidKeyPathComponentValue>
    where
        Self: Sized;
    /// Display the value in a human-meaningful representation
    ///
    /// The output should be a single line (without trailing full stop).
    fn fmt_pretty(&self, f: &mut fmt::Formatter) -> fmt::Result;
}

/// An error returned by a [`KeySpecifier`].
///
/// The putative `KeySpecifier` might be simply invalid,
/// or it might be being used in an inappropriate context.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum ArtiPathUnavailableError {
    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),

    /// An error returned by a [`KeySpecifier`] that does not have an [`ArtiPath`].
    ///
    /// This is returned, for example, by [`CTorPath`]'s [`KeySpecifier::arti_path`]
    /// implementation.
    #[error("ArtiPath unavailable")]
    ArtiPathUnavailable,
}

impl KeySpecifier for ArtiPath {
    fn arti_path(&self) -> StdResult<ArtiPath, ArtiPathUnavailableError> {
        Ok(self.clone())
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        None
    }
}

impl KeySpecifier for CTorPath {
    fn arti_path(&self) -> StdResult<ArtiPath, ArtiPathUnavailableError> {
        Err(ArtiPathUnavailableError::ArtiPathUnavailable)
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        Some(self.clone())
    }
}

impl KeySpecifier for KeyPath {
    fn arti_path(&self) -> StdResult<ArtiPath, ArtiPathUnavailableError> {
        match self {
            KeyPath::Arti(p) => p.arti_path(),
            KeyPath::CTor(p) => p.arti_path(),
        }
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        match self {
            KeyPath::Arti(p) => p.ctor_path(),
            KeyPath::CTor(p) => p.ctor_path(),
        }
    }
}

impl KeySpecifierComponent for TimePeriod {
    fn to_slug(&self) -> Result<Slug, Bug> {
        Slug::new(format!(
            "{}_{}_{}",
            self.interval_num(),
            self.length(),
            self.epoch_offset_in_sec()
        ))
        .map_err(into_internal!("TP formatting went wrong"))
    }

    fn from_slug(s: &Slug) -> StdResult<Self, InvalidKeyPathComponentValue>
    where
        Self: Sized,
    {
        let s = s.to_string();
        #[allow(clippy::redundant_closure)] // the closure makes things slightly more readable
        let err_ctx = |e: &str| InvalidKeyPathComponentValue::Slug(e.to_string());
        let parts = s.split('_').collect::<ArrayVec<&str, 3>>();
        let [interval, len, offset]: [&str; 3] = parts
            .into_inner()
            .map_err(|_| err_ctx("invalid number of subcomponents"))?;

        let length = len.parse().map_err(|_| err_ctx("invalid length"))?;
        let interval_num = interval
            .parse()
            .map_err(|_| err_ctx("invalid interval_num"))?;
        let offset_in_sec = offset
            .parse()
            .map_err(|_| err_ctx("invalid offset_in_sec"))?;

        Ok(TimePeriod::from_parts(length, interval_num, offset_in_sec))
    }

    fn fmt_pretty(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO should this be the Display impl for TimePeriod?
        write!(f, "#{} ", self.interval_num())?;
        match self.range() {
            Ok(r) => {
                use humantime::format_rfc3339_seconds as f3339;
                let mins = self.length().as_minutes();
                write!(f, "{}..+{}:{:02}", f3339(r.start), mins / 60, mins % 60)
            }
            Err(_) => write!(f, "overflow! {self:?}"),
        }
    }
}

/// Implement [`KeySpecifierComponent`] in terms of [`Display`] and [`FromStr`] (helper trait)
///
/// The default [`from_slug`](KeySpecifierComponent::from_slug) implementation maps any errors
/// returned from [`FromStr`] to [`InvalidKeyPathComponentValue::Bug`].
/// Key specifier components that cannot readily be parsed from a string should have a bespoke
/// [`from_slug`](KeySpecifierComponent::from_slug) implementation, and
/// return more descriptive errors through [`InvalidKeyPathComponentValue::Slug`].
pub trait KeySpecifierComponentViaDisplayFromStr: Display + FromStr {}
impl<T: KeySpecifierComponentViaDisplayFromStr + ?Sized> KeySpecifierComponent for T {
    fn to_slug(&self) -> Result<Slug, Bug> {
        self.to_string()
            .try_into()
            .map_err(into_internal!("Display generated bad Slug"))
    }
    fn from_slug(s: &Slug) -> Result<Self, InvalidKeyPathComponentValue>
    where
        Self: Sized,
    {
        s.as_str()
            .parse()
            .map_err(|_| internal!("slug cannot be parsed as component").into())
    }
    fn fmt_pretty(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl KeySpecifierComponent for HsId {
    fn to_slug(&self) -> StdResult<Slug, Bug> {
        // We can't implement KeySpecifierComponentViaDisplayFromStr for HsId,
        // because its Display impl contains the `.onion` suffix, and Slugs can't
        // contain `.`.
        let hsid = self.to_string();
        let hsid_slug = hsid
            .strip_suffix(HSID_ONION_SUFFIX)
            .ok_or_else(|| internal!("HsId Display impl missing .onion suffix?!"))?;
        hsid_slug
            .to_owned()
            .try_into()
            .map_err(into_internal!("Display generated bad Slug"))
    }

    fn from_slug(s: &Slug) -> StdResult<Self, InvalidKeyPathComponentValue>
    where
        Self: Sized,
    {
        // Note: HsId::from_str expects the string to have a .onion suffix,
        // but the string representation of our slug doesn't have it
        // (because we manually strip it away, see to_slug()).
        //
        // We have to manually add it for this to work.
        //
        // TODO: HsId should have some facilities for converting base32 HsIds (sans suffix)
        // to and from string.
        let onion = format!("{}{HSID_ONION_SUFFIX}", s.as_str());

        onion
            .parse()
            .map_err(|e: HsIdParseError| InvalidKeyPathComponentValue::Slug(e.to_string()))
    }

    fn fmt_pretty(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

/// Wrapper for `KeySpecifierComponent` that `Displays` via `fmt_pretty`
struct KeySpecifierComponentPrettyHelper<'c>(&'c dyn KeySpecifierComponent);

impl Display for KeySpecifierComponentPrettyHelper<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        KeySpecifierComponent::fmt_pretty(self.0, f)
    }
}

#[cfg(test)]
mod test {
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

    use crate::arti_path::PATH_SEP;
    use crate::test_utils::check_key_specifier;
    use derive_deftly::Deftly;
    use humantime::parse_rfc3339;
    use itertools::{chain, Itertools};
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;
    use std::time::Duration;
    use tor_persist::slug::BadSlug;

    // TODO I think this could be a function?
    macro_rules! assert_err {
        ($ty:ident, $inner:expr, $error_kind:pat) => {{
            let path = $ty::new($inner.to_string());
            let path_fromstr: Result<$ty, _> = $ty::try_from($inner.to_string());
            let path_tryfrom: Result<$ty, _> = $inner.to_string().try_into();
            assert!(path.is_err(), "{} should be invalid", $inner);
            assert!(
                matches!(path.as_ref().unwrap_err(), $error_kind),
                "wrong error type for {}: {path:?}",
                $inner
            );
            assert_eq!(path, path_fromstr);
            assert_eq!(path, path_tryfrom);
        }};
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

    impl KeySpecifierComponentViaDisplayFromStr for usize {}
    impl KeySpecifierComponentViaDisplayFromStr for String {}

    // This impl probably shouldn't be made non-test, since it produces longer paths
    // than is necessary.  `t`/`f` would be better representation.  But it's fine for tests.
    impl KeySpecifierComponentViaDisplayFromStr for bool {}

    // TODO many of these tests should be in arti_path.rs

    fn test_time_period() -> TimePeriod {
        TimePeriod::new(
            Duration::from_secs(86400),
            parse_rfc3339("2020-09-15T00:00:00Z").unwrap(),
            Duration::from_secs(3600),
        )
        .unwrap()
    }

    #[test]
    fn pretty_time_period() {
        let tp = test_time_period();
        assert_eq!(
            KeySpecifierComponentPrettyHelper(&tp).to_string(),
            "#18519 2020-09-14T01:00:00Z..+24:00",
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

        const DISALLOWED_CHAR_ARTI_PATHS: &[&str] =
            &["client?", "no spaces please", "client٣¾", "clientß"];

        const EMPTY_PATH_COMPONENT: &[&str] =
            &["/////", "/alice/bob", "alice//bob", "alice/bob/", "/"];

        for path in chain!(VALID_ARTI_PATH_COMPONENTS, VALID_ARTI_PATHS) {
            assert_ok!(ArtiPath, path);
        }

        for path in DISALLOWED_CHAR_ARTI_PATHS {
            assert_err!(
                ArtiPath,
                path,
                ArtiPathSyntaxError::Slug(BadSlug::BadCharacter(_))
            );
        }

        for path in BAD_FIRST_CHAR_ARTI_PATHS {
            assert_err!(
                ArtiPath,
                path,
                ArtiPathSyntaxError::Slug(BadSlug::BadFirstCharacter(_))
            );
        }

        for path in EMPTY_PATH_COMPONENT {
            assert_err!(
                ArtiPath,
                path,
                ArtiPathSyntaxError::Slug(BadSlug::EmptySlugNotAllowed)
            );
        }

        const SEP: char = PATH_SEP;
        // This is a valid ArtiPath, but not a valid Slug
        let path = format!("a{SEP}client{SEP}key+private");
        assert_ok!(ArtiPath, &path);

        const PATH_WITH_TRAVERSAL: &str = "alice/../bob";
        assert_err!(
            ArtiPath,
            PATH_WITH_TRAVERSAL,
            ArtiPathSyntaxError::Slug(BadSlug::BadCharacter('.'))
        );

        const REL_PATH: &str = "./bob";
        assert_err!(
            ArtiPath,
            REL_PATH,
            ArtiPathSyntaxError::Slug(BadSlug::BadCharacter('.'))
        );

        const EMPTY_DENOTATOR: &str = "c++";
        assert_err!(
            ArtiPath,
            EMPTY_DENOTATOR,
            ArtiPathSyntaxError::Slug(BadSlug::EmptySlugNotAllowed)
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

            assert_err!(
                ArtiPath,
                path,
                ArtiPathSyntaxError::Slug(BadSlug::BadFirstCharacter(_))
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
        assert_err!(
            ArtiPath,
            path,
            ArtiPathSyntaxError::Slug(BadSlug::EmptySlugNotAllowed)
        );
    }

    #[test]
    fn serde() {
        // TODO: clone-and-hack with tor_hsservice::::nickname::test::serde
        // perhaps there should be some utility in tor-basic-utils for testing
        // validated string newtypes, or something
        #[derive(Serialize, Deserialize, Debug)]
        struct T {
            n: Slug,
        }
        let j = serde_json::from_str(r#"{ "n": "x" }"#).unwrap();
        let t: T = serde_json::from_value(j).unwrap();
        assert_eq!(&t.n.to_string(), "x");

        assert_eq!(&serde_json::to_string(&t).unwrap(), r#"{"n":"x"}"#);

        let j = serde_json::from_str(r#"{ "n": "!" }"#).unwrap();
        let e = serde_json::from_value::<T>(j).unwrap_err();
        assert!(
            e.to_string()
                .contains("character '!' (U+0021) is not allowed"),
            "wrong msg {e:?}"
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

    #[test]
    fn define_key_specifier_with_fields_and_denotator() {
        let tp = test_time_period();

        #[derive(Deftly, Debug, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "encabulator")]
        #[deftly(role = "marzlevane")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            // The remaining fields
            kind: String,
            base: String,
            casing: String,
            #[deftly(denotator)]
            count: usize,
            #[deftly(denotator)]
            tp: TimePeriod,
        }

        let key_spec = TestSpecifier {
            kind: "hydrocoptic".into(),
            base: "waneshaft".into(),
            casing: "logarithmic".into(),
            count: 6,
            tp,
        };

        check_key_specifier(
            &key_spec,
            "encabulator/hydrocoptic/waneshaft/logarithmic/marzlevane+6+18519_1440_3600",
        );

        let info = TestSpecifierInfoExtractor
            .describe(&KeyPath::Arti(key_spec.arti_path().unwrap()))
            .unwrap();

        assert_eq!(
            format!("{info:#?}"),
            r##"
KeyPathInfo {
    summary: "test key",
    role: "marzlevane",
    extra_info: {
        "base": "waneshaft",
        "casing": "logarithmic",
        "count": "6",
        "kind": "hydrocoptic",
        "tp": "#18519 2020-09-14T01:00:00Z..+24:00",
    },
}
            "##
            .trim()
        );
    }

    #[test]
    fn define_key_specifier_no_fields() {
        #[derive(Deftly, Debug, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "encabulator")]
        #[deftly(role = "marzlevane")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {}

        let key_spec = TestSpecifier {};

        check_key_specifier(&key_spec, "encabulator/marzlevane");

        assert_eq!(
            TestSpecifierPattern {}.arti_pattern().unwrap(),
            KeyPathPattern::Arti("encabulator/marzlevane".into())
        );
    }

    #[test]
    fn define_key_specifier_with_denotator() {
        #[derive(Deftly, Debug, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "encabulator")]
        #[deftly(role = "marzlevane")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            #[deftly(denotator)]
            count: usize,
        }

        let key_spec = TestSpecifier { count: 6 };

        check_key_specifier(&key_spec, "encabulator/marzlevane+6");

        assert_eq!(
            TestSpecifierPattern { count: None }.arti_pattern().unwrap(),
            KeyPathPattern::Arti("encabulator/marzlevane+*".into())
        );
    }

    #[test]
    fn define_key_specifier_with_fields() {
        #[derive(Deftly, Debug, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "encabulator")]
        #[deftly(role = "fan")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            casing: String,
            /// A doc comment.
            bearings: String,
        }

        let key_spec = TestSpecifier {
            casing: "logarithmic".into(),
            bearings: "spurving".into(),
        };

        check_key_specifier(&key_spec, "encabulator/logarithmic/spurving/fan");

        assert_eq!(
            TestSpecifierPattern {
                casing: Some("logarithmic".into()),
                bearings: Some("prefabulating".into()),
            }
            .arti_pattern()
            .unwrap(),
            KeyPathPattern::Arti("encabulator/logarithmic/prefabulating/fan".into())
        );

        assert_eq!(key_spec.ctor_path(), None);
    }

    #[test]
    fn define_key_specifier_with_multiple_denotators() {
        #[derive(Deftly, Debug, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "encabulator")]
        #[deftly(role = "fan")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            casing: String,
            /// A doc comment.
            bearings: String,

            #[deftly(denotator)]
            count: usize,

            #[deftly(denotator)]
            length: usize,

            #[deftly(denotator)]
            kind: String,
        }

        let key_spec = TestSpecifier {
            casing: "logarithmic".into(),
            bearings: "spurving".into(),
            count: 8,
            length: 2000,
            kind: "lunar".into(),
        };

        check_key_specifier(
            &key_spec,
            "encabulator/logarithmic/spurving/fan+8+2000+lunar",
        );

        assert_eq!(
            TestSpecifierPattern {
                casing: Some("logarithmic".into()),
                bearings: Some("prefabulating".into()),
                ..TestSpecifierPattern::new_any()
            }
            .arti_pattern()
            .unwrap(),
            KeyPathPattern::Arti("encabulator/logarithmic/prefabulating/fan+*+*+*".into())
        );
    }

    #[test]
    fn define_key_specifier_role_field() {
        #[derive(Deftly, Debug, Eq, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "prefix")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            #[deftly(role)]
            role: String,
            i: usize,
            #[deftly(denotator)]
            den: bool,
        }

        check_key_specifier(
            &TestSpecifier {
                i: 1,
                role: "role".to_string(),
                den: true,
            },
            "prefix/1/role+true",
        );
    }

    #[test]
    fn define_key_specifier_ctor_path() {
        #[derive(Deftly, Debug, Eq, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "p")]
        #[deftly(role = "r")]
        #[deftly(ctor_path = "Self::ctp")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            i: usize,
        }

        impl TestSpecifier {
            fn ctp(&self) -> CTorPath {
                // TODO this ought to use CTorPath's public constructor
                // but it doesn't have one
                CTorPath(self.i.to_string())
            }
        }

        let spec = TestSpecifier { i: 42 };

        check_key_specifier(&spec, "p/42/r");

        assert_eq!(spec.ctor_path(), Some(CTorPath("42".into())),);
    }

    #[test]
    fn define_key_specifier_fixed_path_component() {
        #[derive(Deftly, Debug, Eq, PartialEq)]
        #[derive_deftly(KeySpecifier)]
        #[deftly(prefix = "prefix")]
        #[deftly(role = "role")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            x: usize,
            #[deftly(fixed_path_component = "fixed")]
            z: bool,
        }

        check_key_specifier(&TestSpecifier { x: 1, z: true }, "prefix/1/fixed/true/role");
    }

    #[test]
    fn encode_time_period() {
        let period = TimePeriod::from_parts(1, 2, 3);
        let encoded_period = period.to_slug().unwrap();

        assert_eq!(encoded_period.to_string(), "2_1_3");
        assert_eq!(period, TimePeriod::from_slug(&encoded_period).unwrap());

        assert!(TimePeriod::from_slug(&Slug::new("invalid_tp".to_string()).unwrap()).is_err());
        assert!(TimePeriod::from_slug(&Slug::new("2_1_3_4".to_string()).unwrap()).is_err());
    }

    #[test]
    fn encode_hsid() {
        let b32 = "eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad";
        let onion = format!("{b32}.onion");
        let hsid = HsId::from_str(&onion).unwrap();
        let hsid_slug = hsid.to_slug().unwrap();

        assert_eq!(hsid_slug.to_string(), b32);
        assert_eq!(hsid, HsId::from_slug(&hsid_slug).unwrap());
    }

    #[test]
    fn key_info_builder() {
        // A helper to check the extra_info of a `KeyPathInfo`
        macro_rules! assert_extra_info_eq {
            ($key_info:expr, [$(($k:expr, $v:expr),)*]) => {{
                assert_eq!(
                    $key_info.extra_info.into_iter().collect_vec(),
                    vec![
                        $(($k.into(), $v.into()),)*
                    ]
                );
            }}
        }
        let extra_info = vec![("nickname".into(), "bar".into())];

        let key_info = KeyPathInfo::builder()
            .summary("test summary".into())
            .role("KS_vote".to_string())
            .set_all_extra_info(extra_info.clone().into_iter())
            .build()
            .unwrap();

        assert_eq!(key_info.extra_info.into_iter().collect_vec(), extra_info);

        let key_info = KeyPathInfo::builder()
            .summary("test summary".into())
            .role("KS_vote".to_string())
            .set_all_extra_info(extra_info.clone().into_iter())
            .extra_info("type", "service")
            .extra_info("time period", "100")
            .build()
            .unwrap();

        assert_extra_info_eq!(
            key_info,
            [
                ("nickname", "bar"),
                ("time period", "100"),
                ("type", "service"),
            ]
        );

        let key_info = KeyPathInfo::builder()
            .summary("test summary".into())
            .role("KS_vote".to_string())
            .extra_info("type", "service")
            .extra_info("time period", "100")
            .set_all_extra_info(extra_info.clone().into_iter())
            .build()
            .unwrap();

        assert_extra_info_eq!(key_info, [("nickname", "bar"),]);

        let key_info = KeyPathInfo::builder()
            .summary("test summary".into())
            .role("KS_vote".to_string())
            .extra_info("type", "service")
            .extra_info("time period", "100")
            .build()
            .unwrap();

        assert_extra_info_eq!(key_info, [("time period", "100"), ("type", "service"),]);
    }
}
