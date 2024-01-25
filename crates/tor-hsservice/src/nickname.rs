//! `HsNickname` module itself is private, but `HsNickname` etc. are re-exported

use std::str::FromStr;

use derive_more::{Display, From, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use tor_keymgr::KeySpecifierComponentViaDisplayFromStr;
use tor_persist::slug::{BadSlug, Slug};

/// Nickname (local identifier) for a Tor hidden service
///
/// Used to look up this services's
/// keys, state, configuration, etc,
/// and distinguish them from other services.
///
/// An `HsNickname` is a non-empty [`Slug`].
/// See [slug](tor_persist::slug) for the syntactic requirements.
//
// NOTE: if at some point we decide HsNickname should have a more restrictive syntax/charset than
// Slug, we should remember to also update `KeySpecifierComponent::from_component` (it
// should return an error if the specified string is a valid Slug, but not a valid
// HsNickname).
#[derive(
    Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Display, From, Into, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct HsNickname(Slug);

impl FromStr for HsNickname {
    type Err = BadSlug;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Slug::try_from(s.to_string()).map(HsNickname)
    }
}

impl KeySpecifierComponentViaDisplayFromStr for HsNickname {}

/// Local nickname for Tor Hidden Service (`.onion` service) was syntactically invalid
#[derive(Clone, Debug, Hash, Eq, PartialEq, Error)]
#[non_exhaustive]
#[error("Invalid syntax for hidden service nickname")]
pub struct InvalidNickname {}

impl HsNickname {
    /// Create a new `HsNickname` from a `String`
    ///
    /// Returns an error if the syntax is not valid
    fn new(s: String) -> Result<HsNickname, InvalidNickname> {
        // Slugs can be empty, but HS nicknames cannot.
        if s.is_empty() {
            return Err(InvalidNickname {});
        }

        Ok(Self(s.try_into().map_err(|_| InvalidNickname {})?))
    }
}

impl From<HsNickname> for String {
    fn from(nick: HsNickname) -> String {
        nick.0.into()
    }
}

impl TryFrom<String> for HsNickname {
    type Error = InvalidNickname;
    fn try_from(s: String) -> Result<HsNickname, InvalidNickname> {
        Self::new(s)
    }
}

impl AsRef<str> for HsNickname {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn mk() {
        assert_eq!(HsNickname::new("".into()), Err(InvalidNickname {}));
        assert_eq!(HsNickname::new("-a".into()).unwrap().to_string(), "-a");
        assert_eq!(HsNickname::new("b.".into()), Err(InvalidNickname {}));
        assert_eq!(HsNickname::new("_c".into()).unwrap().to_string(), "_c");
        assert_eq!(&HsNickname::new("x".into()).unwrap().to_string(), "x");
    }

    #[test]
    fn serde() {
        // TODO: clone-and-hack with tor_keymgr::::key_specifier::test::serde
        #[derive(Serialize, Deserialize, Debug)]
        struct T {
            n: HsNickname,
        }
        let j = serde_json::from_str(r#"{ "n": "x" }"#).unwrap();
        let t: T = serde_json::from_value(j).unwrap();
        assert_eq!(&t.n.to_string(), "x");

        assert_eq!(&serde_json::to_string(&t).unwrap(), r#"{"n":"x"}"#);

        let j = serde_json::from_str(r#"{ "n": "!" }"#).unwrap();
        let e = serde_json::from_value::<T>(j).unwrap_err();
        assert!(e.to_string().contains("Invalid syntax"), "wrong msg {e:?}");
    }
}
