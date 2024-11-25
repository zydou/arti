//! Stub; `v1` proof of work scheme has been disabled at compile time

use crate::doc::hsdesc::inner::HsInnerKwd;
use crate::parse::tokenize::Item;
use crate::Result;

/// Marker for a `pow-params v1` line which was not parsed
///
/// If are missing the `hs-pow-full` crate feature, we will not parse
/// `pow-params v1` but we will remember that one exists. Clients will see
/// that a pow scheme is available which might work if the software were
/// compiled differently.
///
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PowParamsV1;

impl PowParamsV1 {
    /// Accept any Item as a 'PowParamsV1' without actually parsing it
    ///
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn from_item(_item: &Item<'_, HsInnerKwd>) -> Result<Self> {
        Ok(Self)
    }
}
