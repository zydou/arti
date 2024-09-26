//! Implement parsing for the `pow-params` line within the `HsDescInner` layer

use crate::doc::hsdesc::inner::HsInnerKwd;
use crate::parse::tokenize::Item;
use crate::types::misc::{Iso8601TimeNoSp, B64};
use crate::{NetdocErrorKind as EK, Result};
use std::collections::HashSet;
use std::mem::Discriminant;
use std::time::SystemTime;

/// A list of parsed `pow-params` lines, at most one per scheme
///
#[derive(Debug, Clone)]
pub struct HsPowParamSet(Vec<HsPowParams>);

impl HsPowParamSet {
    /// Reference all parameters as a slice in arbitrary order
    pub(super) fn slice(&self) -> &[HsPowParams] {
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
        let mut schemes_seen: HashSet<Discriminant<HsPowParams>> = HashSet::new();
        for item in items {
            if let Some(parsed) = HsPowParams::from_item(item)? {
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

/// The contents of a `pow-params` line with any known scheme
///
/// These use a text format defined by:
/// <https://spec.torproject.org/rend-spec/hsdesc-encrypt.html#second-layer-plaintext>
///
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HsPowParams {
    /// Parameters for the `v1` scheme
    V1(HsPowParamsV1),
}

impl HsPowParams {
    /// Parse a single `pow-params` line from an `Item`
    ///
    /// If the scheme is recognized, returns an HsPowParams or a parse error.
    /// If the scheme is unknown, returns None.
    /// If the scheme field is missing entirely, returns a parse error.
    fn from_item(item: &Item<'_, HsInnerKwd>) -> Result<Option<Self>> {
        let scheme = item.required_arg(0)?;
        if scheme == "v1" {
            Ok(Some(HsPowParams::V1(HsPowParamsV1::from_item(item)?)))
        } else {
            Ok(None)
        }
    }
}

/// The contents of a `pow-params v1` line
#[derive(Debug, Clone, derive_more::Constructor, amplify::Getters)]
pub struct HsPowParamsV1 {
    /// Current random seed, valid until the declared expiration time
    #[getter(as_ref)]
    seed: [u8; 32],
    /// Current suggested effort, or zero if this is available but not recommended
    #[getter(as_copy)]
    suggested_effort: u32,
    /// Declared time when this seed expires
    #[getter(as_copy)]
    expires: SystemTime,
}

impl HsPowParamsV1 {
    /// Parse a single `pow-params v1` line from an `Item`
    fn from_item(item: &Item<'_, HsInnerKwd>) -> Result<Self> {
        let seed = item.required_arg(1)?.parse::<B64>()?.into_array()?;
        let suggested_effort = item.required_arg(2)?.parse::<u32>()?;
        let expires = item.required_arg(3)?.parse::<Iso8601TimeNoSp>()?.into();
        Ok(Self {
            seed,
            suggested_effort,
            expires,
        })
    }
}
