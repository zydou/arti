//! Implement parsing for the `pow-params v1` scheme

use crate::doc::hsdesc::inner::HsInnerKwd;
use crate::parse::{keyword::Keyword, tokenize::Item};
use crate::types::misc::{Iso8601TimeNoSp, B64};
use crate::{NetdocErrorKind, Result};
use std::time::SystemTime;
use tor_checkable::timed::TimerangeBound;
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
pub struct PowParamsV1 {
    /// Time limited [`Seed`]
    #[getter(as_ref)]
    seed: TimerangeBound<Seed>,
    /// Last known suggested [`Effort`]
    ///
    /// This can be [`Effort::zero()`] if the puzzle is available but the
    /// service doesn't recommend using it for an initial connection attempt.
    #[getter(as_copy)]
    suggested_effort: Effort,
}

impl PowParamsV1 {
    /// Parse a single `pow-params v1` line from an `Item`
    pub(super) fn from_item(item: &Item<'_, HsInnerKwd>) -> Result<Self> {
        if item.has_obj() {
            return Err(NetdocErrorKind::UnexpectedObject
                .with_msg(item.kwd().to_str())
                .at_pos(item.pos()));
        }
        let seed = item.required_arg(1)?.parse::<B64>()?.into_array()?.into();
        let suggested_effort = item.required_arg(2)?.parse::<u32>()?.into();
        let expires: SystemTime = item.required_arg(3)?.parse::<Iso8601TimeNoSp>()?.into();
        Ok(Self {
            seed: TimerangeBound::new(seed, ..expires),
            suggested_effort,
        })
    }
}
