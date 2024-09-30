//! Implement parsing for the `pow-params v1` scheme

use crate::doc::hsdesc::inner::HsInnerKwd;
use crate::parse::tokenize::Item;
use crate::types::misc::{Iso8601TimeNoSp, B64};
use crate::Result;
use std::time::SystemTime;
use tor_hscrypto::pow::v1::{Effort, Seed};

/// The contents of a `pow-params v1` line
///
/// These parameters are defined in the specifications for the `v1` proof of work scheme:
/// <https://spec.torproject.org/hspow-spec/v1-equix.html#parameter-descriptor>
///
/// In addition to the scheme identifier itself, this type of
/// `pow-params` line includes a 32-byte seed with its own expiration
/// timestamp, and a suggested effort value that clients may use for
/// their initial request.
#[derive(Debug, Clone, derive_more::Constructor, amplify::Getters)]
pub struct HsPowParamsV1 {
    /// Current random seed, valid until the declared expiration time
    #[getter(as_ref)]
    seed: Seed,
    /// Current suggested effort, or zero if this is available but not recommended
    #[getter(as_copy)]
    suggested_effort: Effort,
    /// Declared time when this seed expires
    #[getter(as_copy)]
    expires: SystemTime,
}

impl HsPowParamsV1 {
    /// Parse a single `pow-params v1` line from an `Item`
    pub(super) fn from_item(item: &Item<'_, HsInnerKwd>) -> Result<Self> {
        let seed = item.required_arg(1)?.parse::<B64>()?.into_array()?.into();
        let suggested_effort = item.required_arg(2)?.parse::<u32>()?.into();
        let expires = item.required_arg(3)?.parse::<Iso8601TimeNoSp>()?.into();
        Ok(Self {
            seed,
            suggested_effort,
            expires,
        })
    }
}
