//! Memory tracker, core and low-level API

// TODO XXXX

use crate::internal_prelude::*;

/// Maximum amount we'll "cache" locally in a [`Participation`]
///
/// ie maximum value of `Participation.cache`.
//
// TODO is this a good amount? should it be configurable?
pub(crate) const MAX_CACHE: Qty = Qty(16384);
