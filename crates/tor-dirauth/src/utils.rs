//! Miscellaneous utilities

use crate::internal_prelude::*;

/// What `RangeInclusive::map` ought to be
///
/// Open-coding this at the call site would risk accidental change of the range type,
/// changing inclusiveness, etc.  This function has the same range type as argument and return.
pub(crate) fn map_range<T, U>(
    r: &RangeInclusive<T>,
    mut f: impl FnMut(&T) -> U,
) -> RangeInclusive<U> {
    f(r.start())..=f(r.end())
}
