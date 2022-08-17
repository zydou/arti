//! Miscellaneous types used in configuration
//!
//! This module contains types that need to be shared across various crates
//! and layers, but which don't depend on specific elements of the Tor system.

use std::borrow::Cow;

use educe::Educe;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, IntoStaticStr};

/// Padding enablement - rough amount of padding requested
///
/// Padding is cover traffic, used to help mitigate traffic analysis,
/// obscure traffic patterns, and impede router-level data collection.
///
/// This same enum is used to control padding at various levels of the Tor system.
/// (TODO: actually we don't do circuit padding yet.)
//
// This slightly-odd interleaving of derives and attributes stops rustfmt doing a daft thing
#[derive(Clone, Copy, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)] // we will add variants very rarely if ever
#[derive(Serialize, Deserialize)]
#[serde(try_from = "PaddingLevelSerde", into = "PaddingLevelSerde")]
#[derive(Display, EnumString, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[derive(Educe)]
#[educe(Default)]
pub enum PaddingLevel {
    /// Disable padding completely
    None,
    /// Reduced padding (eg for mobile)
    Reduced,
    /// Normal padding (the default)
    #[educe(Default)]
    Normal,
}

/// How we (de) serialize a [`PaddingLevel`]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PaddingLevelSerde {
    /// String (in snake case)
    ///
    /// We always serialize this way
    String(Cow<'static, str>),
    /// bool
    Bool(bool),
}

impl From<PaddingLevel> for PaddingLevelSerde {
    fn from(pl: PaddingLevel) -> PaddingLevelSerde {
        PaddingLevelSerde::String(<&str>::from(&pl).into())
    }
}

/// Padding level configuration is invalid
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[error("Invalid padding level")]
struct InvalidPaddingLevel {}

impl TryFrom<PaddingLevelSerde> for PaddingLevel {
    type Error = InvalidPaddingLevel;

    fn try_from(pls: PaddingLevelSerde) -> Result<PaddingLevel, Self::Error> {
        Ok(match pls {
            PaddingLevelSerde::String(s) => {
                s.as_ref().try_into().map_err(|_| InvalidPaddingLevel {})?
            }
            PaddingLevelSerde::Bool(false) => PaddingLevel::None,
            PaddingLevelSerde::Bool(true) => PaddingLevel::Normal,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    struct TestConfigFile {
        #[serde(default)]
        padding: PaddingLevel,
    }

    #[test]
    fn padding_level() {
        use PaddingLevel as PL;

        let chk = |pl, s| {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            assert_eq!(pl, tc.padding, "{:?}", s);
        };

        chk(PL::None, r#"padding = "none""#);
        chk(PL::None, r#"padding = false"#);
        chk(PL::Reduced, r#"padding = "reduced""#);
        chk(PL::Normal, r#"padding = "normal""#);
        chk(PL::Normal, r#"padding = true"#);
        chk(PL::Normal, "");

        let chk_e = |s| {
            let tc: Result<TestConfigFile, _> = toml::from_str(s);
            let _ = tc.expect_err(s);
        };

        chk_e(r#"padding = 1"#);
        chk_e(r#"padding = "unknown""#);
        chk_e(r#"padding = "Normal""#);
    }
}
