//! Implement parsing for the `pow-params` line within the `HsDescInner` layer

#[cfg_attr(not(feature = "hs-pow-v1"), path = "pow/v1_stub.rs")]
pub mod v1;

use crate::doc::hsdesc::inner::HsInnerKwd;
use crate::parse::tokenize::Item;
use crate::{NetdocErrorKind as EK, Result};
use std::collections::HashSet;
use std::mem::Discriminant;
use v1::PowParamsV1;

/// A list of parsed `pow-params` lines, at most one per scheme
///
#[derive(Debug, Clone)]
pub struct PowParamSet(Vec<PowParams>);

impl PowParamSet {
    /// Reference all parameters as a slice in arbitrary order
    pub(super) fn slice(&self) -> &[PowParams] {
        &self.0
    }

    /// Parse a slice of `pow-params` items
    ///
    /// Unrecognized schemes are ignored. Duplicate schemes result in an error.
    ///
    pub(super) fn from_items(items: &[Item<'_, HsInnerKwd>]) -> Result<Self> {
        // Parse each one individually,
        // verifing each time we don't have a duplicated enum discriminant.
        let mut inner = Vec::new();
        let mut schemes_seen: HashSet<Discriminant<PowParams>> = HashSet::new();
        for item in items {
            if let Some(parsed) = PowParams::try_from_item(item)? {
                if schemes_seen.insert(std::mem::discriminant(&parsed)) {
                    // Parsed params with a scheme we haven't seen before
                    inner.push(parsed);
                } else {
                    return Err(EK::DuplicateToken
                        .with_msg(item.kwd_str().to_owned())
                        .at_pos(item.pos()));
                }
            }
        }
        Ok(Self(inner))
    }
}

/// The contents of a `pow-params` line with any recognized scheme.
///
/// These use a text format defined by:
/// <https://spec.torproject.org/rend-spec/hsdesc-encrypt.html#second-layer-plaintext>
///
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PowParams {
    /// Parameters for the `v1` scheme
    V1(PowParamsV1),
}

impl PowParams {
    /// Parse a single `pow-params` line from an `Item`
    ///
    /// If the scheme is recognized, returns a PowParams or a parse error.
    /// If the scheme is unknown, returns None.
    /// If the scheme field is missing entirely, returns a parse error.
    fn try_from_item(item: &Item<'_, HsInnerKwd>) -> Result<Option<Self>> {
        let scheme = item.required_arg(0)?;
        if scheme == "v1" {
            Ok(Some(PowParams::V1(PowParamsV1::from_item(item)?)))
        } else {
            Ok(None)
        }
    }
}
