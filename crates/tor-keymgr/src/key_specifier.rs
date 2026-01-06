//! The [`KeySpecifier`] trait and its implementations.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Display};
use std::ops::Range;
use std::result::Result as StdResult;
use std::str::FromStr;

use derive_more::From;
use safelog::DisplayRedacted as _;
use thiserror::Error;
use tor_error::{Bug, internal, into_internal};
use tor_hscrypto::pk::{HSID_ONION_SUFFIX, HsId, HsIdParseError};
use tor_hscrypto::time::TimePeriod;
use tor_persist::hsnickname::HsNickname;
use tor_persist::slug::Slug;

use crate::{ArtiPath, ArtiPathSyntaxError};

// #[doc(hidden)] applied at crate toplevel
#[macro_use]
pub mod derive;

/// The identifier of a key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, From, derive_more::Display)]
#[non_exhaustive]
pub enum KeyPath {
    /// An Arti key path.
    Arti(ArtiPath),
    /// A C-Tor key path.
    CTor(CTorPath),
}

/// A range specifying a substring of a [`KeyPath`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, From)]
pub struct ArtiPathRange(pub(crate) Range<usize>);

impl ArtiPath {
    /// Check whether this `ArtiPath` matches the specified [`KeyPathPattern`].
    ///
    /// If the `ArtiPath` matches the pattern, this returns the ranges that match its dynamic parts.
    ///
    /// ### Example
    /// ```
    /// # use tor_keymgr::{ArtiPath, KeyPath, KeyPathPattern, ArtiPathSyntaxError};
    /// # fn demo() -> Result<(), ArtiPathSyntaxError> {
    /// let path = ArtiPath::new("foo_bar_baz_1".into())?;
    /// let pattern = KeyPathPattern::Arti("*_bar_baz_*".into());
    /// let matches = path.matches(&pattern).unwrap();
    ///
    /// assert_eq!(matches.len(), 2);
    /// assert_eq!(path.substring(&matches[0]), Some("foo"));
    /// assert_eq!(path.substring(&matches[1]), Some("1"));
    /// # Ok(())
    /// # }
    /// #
    /// # demo().unwrap();
    /// ```
    pub fn matches(&self, pat: &KeyPathPattern) -> Option<Vec<ArtiPathRange>> {
        use KeyPathPattern::*;

        let pattern: &str = match pat {
            Arti(pat) => pat.as_ref(),
            _ => return None,
        };

        glob_match::glob_match_with_captures(pattern, self.as_ref())
            .map(|res| res.into_iter().map(|r| r.into()).collect())
    }
}

impl KeyPath {
    /// Check whether this `KeyPath` matches the specified [`KeyPathPattern`].
    ///
    /// Returns `true` if the `KeyPath` matches the pattern.
    ///
    /// ### Example
    /// ```
    /// # use tor_keymgr::{ArtiPath, KeyPath, KeyPathPattern, ArtiPathSyntaxError};
    /// # fn demo() -> Result<(), ArtiPathSyntaxError> {
    /// let path = KeyPath::Arti(ArtiPath::new("foo_bar_baz_1".into())?);
    /// let pattern = KeyPathPattern::Arti("*_bar_baz_*".into());
    /// assert!(path.matches(&pattern));
    /// # Ok(())
    /// # }
    /// #
    /// # demo().unwrap();
    /// ```
    pub fn matches(&self, pat: &KeyPathPattern) -> bool {
        use KeyPathPattern::*;

        match (self, pat) {
            (KeyPath::Arti(p), Arti(_)) => p.matches(pat).is_some(),
            (KeyPath::CTor(p), CTor(pat)) if p == pat => true,
            _ => false,
        }
    }

    // TODO: rewrite these getters using derive_adhoc if KeyPath grows more variants.

    /// Return the underlying [`ArtiPath`], if this is a `KeyPath::Arti`.
    pub fn arti(&self) -> Option<&ArtiPath> {
        match self {
            KeyPath::Arti(arti) => Some(arti),
            KeyPath::CTor(_) => None,
        }
    }

    /// Return the underlying [`CTorPath`], if this is a `KeyPath::CTor`.
    pub fn ctor(&self) -> Option<&CTorPath> {
        match self {
            KeyPath::Arti(_) => None,
            KeyPath::CTor(ctor) => Some(ctor),
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
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum KeyPathError {
    /// An error while trying to extract information from an [`ArtiPath`].
    #[error("{err}")]
    Arti {
        /// The path that caused the error.
        path: ArtiPath,
        /// The underlying error
        err: ArtiPathError,
    },

    /// An error while trying to extract information from an [`CTorPath`].
    #[error("{err}")]
    CTor {
        /// The path that caused the error.
        path: CTorPath,
        /// The underlying error
        err: CTorPathError,
    },

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// An error while attempting to extract information from an [`ArtiPath`].
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ArtiPathError {
    /// The path did not match the expected pattern.
    #[error("Path does not match expected pattern")]
    PatternNotMatched,

    /// Found an invalid [`ArtiPath`], which is syntactically invalid on its face
    #[error("ArtiPath is invalid")]
    InvalidArtiPath(ArtiPathSyntaxError),

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
        /// The substring of the `ArtiPath` that couldn't be parsed.
        value: Slug,
    },

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// An error while attempting to convert a [`CTorPath`]
/// to its corresponding key specifier type.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CTorPathError {
    /// Attempted to convert a C Tor path to a mismatched specifier kind.
    #[error("C Tor path cannot be converted to {0}")]
    KeySpecifierMismatch(String),

    /// Attempted to convert a C Tor path to a key specifier
    /// that does not have a C Tor path.
    #[error("Key specifier {0} does not have a C Tor path")]
    MissingCTorPath(String),
}

/// Error to be returned by `KeySpecifierComponent::from_slug` implementations
///
/// Currently this error contains little information,
/// but the context and value are provided in
/// [`ArtiPathError::InvalidKeyPathComponentValue`].
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
    /// enclosing [`ArtiPathError::InvalidKeyPathComponentValue`] error).
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
    CTor(CTorPath),
}

/// The path of a key in the C Tor key store.
#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::Display)] //
#[non_exhaustive]
pub enum CTorPath {
    /// A client descriptor encryption key, to be looked up in ClientOnionAuthDir.
    ///
    /// Represents an entry in C Tor's `ClientOnionAuthDir`.
    ///
    /// We can't statically know exactly *which* entry has the key for this `HsId`
    /// (we'd need to read and parse each file from `ClientOnionAuthDir` to find out).
    //
    // TODO: Perhaps we should redact this sometimes.
    #[display("HsClientDescEncKeypair({})", hs_id.display_unredacted())]
    HsClientDescEncKeypair {
        /// The hidden service this restricted discovery keypair is for.
        hs_id: HsId,
    },
    /// C Tor's `HiddenServiceDirectory/hs_ed25519_public_key`.
    #[display("hs_ed25519_public_key")]
    HsIdPublicKey {
        /// The nickname of the service,
        nickname: HsNickname,
    },
    /// C Tor's `HiddenServiceDirectory/hs_ed25519_secret_key`.
    #[display("hs_ed25519_secret_key")]
    HsIdKeypair {
        /// The nickname of the service,
        nickname: HsNickname,
    },
}

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

    /// If this is the specifier for a public key, the specifier for
    /// the corresponding (secret) keypair from which it can be derived
    fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>>;
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

    fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>> {
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

    fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>> {
        None
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

    fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>> {
        None
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
        use itertools::Itertools;

        let s = s.to_string();
        #[allow(clippy::redundant_closure)] // the closure makes things slightly more readable
        let err_ctx = |e: &str| InvalidKeyPathComponentValue::Slug(e.to_string());
        let (interval, len, offset) = s
            .split('_')
            .collect_tuple()
            .ok_or_else(|| err_ctx("invalid number of subcomponents"))?;

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
        Display::fmt(&self, f)
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
impl<T: KeySpecifierComponentViaDisplayFromStr> KeySpecifierComponent for T {
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

impl KeySpecifierComponentViaDisplayFromStr for HsNickname {}

impl KeySpecifierComponent for HsId {
    fn to_slug(&self) -> StdResult<Slug, Bug> {
        // We can't implement KeySpecifierComponentViaDisplayFromStr for HsId,
        // because its Display impl contains the `.onion` suffix, and Slugs can't
        // contain `.`.
        let hsid = self.display_unredacted().to_string();
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
        Display::fmt(&self.display_redacted(), f)
    }
}

/// Wrapper for `KeySpecifierComponent` that `Displays` via `fmt_pretty`
struct KeySpecifierComponentPrettyHelper<'c>(&'c dyn KeySpecifierComponent);

impl Display for KeySpecifierComponentPrettyHelper<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        KeySpecifierComponent::fmt_pretty(self.0, f)
    }
}

/// The "specifier" of a key certificate, which identifies an instance of a cert,
/// as well as its signing and subject keys.
///
/// Certificates can only be fetched from Arti key stores
/// (we will not support loading certs from C Tor's key directory)
pub trait KeyCertificateSpecifier {
    /// The denotators of the certificate.
    ///
    /// Used by `KeyMgr` to derive the `ArtiPath` of the certificate.
    /// The `ArtiPath` of a certificate is obtained
    /// by concatenating the `ArtiPath` of the subject key with the
    /// denotators provided by this function,
    /// with a `+` between the `ArtiPath` of the subject key and
    /// the denotators (the `+` is omitted if there are no denotators).
    fn cert_denotators(&self) -> Vec<&dyn KeySpecifierComponent>;
    /// The key specifier of the signing key.
    ///
    /// Returns `None` if the signing key should not be retrieved from the keystore.
    ///
    /// Note: a return value of `None` means the signing key will be provided
    /// as an argument to the `KeyMgr` accessor this `KeyCertificateSpecifier`
    /// will be used with.
    fn signing_key_specifier(&self) -> Option<&dyn KeySpecifier>;
    /// The key specifier of the subject key.
    fn subject_key_specifier(&self) -> &dyn KeySpecifier;
}

/// A trait for converting key specifiers to and from [`CTorPath`].
///
/// Important: this trait should not be implemented by hand.
/// It is auto-implemented for types that derive [`KeySpecifier`].
pub trait CTorKeySpecifier: KeySpecifier + Sized {
    /// The location of the key in the C Tor key store (if supported).
    ///
    /// See [`KeySpecifier::ctor_path`].
    fn ctor_path(&self) -> Option<CTorPath>;

    /// Try to convert `path` to a specifier of this kind.
    ///
    /// Returns an error if the `CTorPath` is not the path of a key of this type,
    /// or if this type does not have a `CTorPath`.
    fn from_ctor_path(path: CTorPath) -> Result<Self, CTorPathError>;
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    use crate::test_utils::check_key_specifier;
    use derive_deftly::Deftly;
    use humantime::parse_rfc3339;
    use itertools::Itertools;
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;
    use std::time::Duration;

    impl KeySpecifierComponentViaDisplayFromStr for usize {}
    impl KeySpecifierComponentViaDisplayFromStr for String {}

    // This impl probably shouldn't be made non-test, since it produces longer paths
    // than is necessary.  `t`/`f` would be better representation.  But it's fine for tests.
    impl KeySpecifierComponentViaDisplayFromStr for bool {}

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

        let ctor_path = CTorPath::HsIdPublicKey {
            nickname: HsNickname::from_str("foo").unwrap(),
        };

        assert_eq!(
            TestSpecifier::from_ctor_path(ctor_path).unwrap_err(),
            CTorPathError::MissingCTorPath("TestSpecifier".into()),
        );
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
        #[deftly(ctor_path = "HsIdPublicKey")]
        #[deftly(summary = "test key")]
        struct TestSpecifier {
            nickname: HsNickname,
        }

        let spec = TestSpecifier {
            nickname: HsNickname::from_str("42").unwrap(),
        };

        check_key_specifier(&spec, "p/42/r");

        let ctor_path = KeySpecifier::ctor_path(&spec);

        assert_eq!(
            ctor_path,
            Some(CTorPath::HsIdPublicKey {
                nickname: HsNickname::from_str("42").unwrap(),
            }),
        );

        assert_eq!(
            TestSpecifier::from_ctor_path(ctor_path.unwrap()).unwrap(),
            spec,
        );

        /// An .onion address to put for test client CTorPaths.
        const HSID: &str = "yc6v7oeksrbech4ctv53di7rfjuikjagkyfrwu3yclzkfyv5haay6mqd.onion";
        let wrong_paths = &[
            CTorPath::HsClientDescEncKeypair {
                hs_id: HsId::from_str(HSID).unwrap(),
            },
            CTorPath::HsIdKeypair {
                nickname: HsNickname::from_str("42").unwrap(),
            },
        ];

        for path in wrong_paths {
            assert_eq!(
                TestSpecifier::from_ctor_path(path.clone()).unwrap_err(),
                CTorPathError::KeySpecifierMismatch("TestSpecifier".into()),
            );
        }
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
