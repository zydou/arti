//! Quantity bookkeeping
//!
//! Newtypes which wrap up a `Qty` (an amount of memory),
//! and which assure proper accounting.
//!
//! Methods are provided for the specific transactions which are correct,
//! in the accounting scheme in [`tracker`](super).
//! So these types embody the data structure (fields and invariants) from `tracker`.
//!
//! # Panics
//!
//! In tests, these types panic if they are dropped when nonzero,
//! if that's against the rules.

use super::*;

define_derive_deftly! {
    /// Implement [`BookkeptQty`] and its supertraits
    ///
    /// By default, dropping when nonzero is forbidden.
    /// `#[deftly(allow_nonzero_drop)]` suppresses this drop bomb.
    BookkeptQty =

    impl BookkeepableQty for $ttype {
        const ZERO: $ttype = $ttype { raw: Qty(0) };

        fn as_raw(&self) -> Qty {
            self.raw
        }
    }

    impl<Rhs: BookkeepableQty> PartialEq<Rhs> for $ttype {
        fn eq(&self, other: &Rhs) -> bool {
            self.as_raw().eq(&other.as_raw())
        }
    }
    impl<Rhs: BookkeepableQty> PartialOrd<Rhs> for $ttype {
        fn partial_cmp(&self, other: &Rhs) -> Option<Ordering> {
            self.as_raw().partial_cmp(&other.as_raw())
        }
    }

    impl DefaultExtTake for $ttype {}

    impl BookkeptQty for $ttype {
        fn from_raw(q: Qty) -> Self {
            $ttype { raw: q }
        }
        fn into_raw(mut self) -> Qty {
            mem::replace(&mut self.raw, Qty(0))
        }
    }

    assert_not_impl_any!($ttype: Clone, Into<Qty>, From<Qty>);

  ${if not(tmeta(allow_nonzero_drop)) {
    #[cfg(test)]
    impl Drop for $ttype {
        fn drop(&mut self) {
            // We don't check for unwinding.
            // We shouldn't drop a nonzero one of these even if we're panicking.
            // If we do, it'll be a double panic => abort.
            assert_eq!(self.raw, Qty(0));
        }
    }
  }}
}

/// Memory quantities that can work with bookkept quantities
///
/// This trait doesn't imply any invariants;
/// it merely provides read-only access to the underlying value,
/// and ways to make a zero.
///
/// Used by the derived `PartialEq` and `PartialOrd` impls on bookkept quantities.
///
/// Implemented by hand for `Qty`.
///
/// Implemented for bookkept types, along with `BookkeptQty`, by
/// [`#[derive_deftly(BookKept)]`](derive_deftly_template_BookkeptQty).
pub(super) trait BookkeepableQty: Default {
    /// Zero (default value)
    const ZERO: Self;

    /// Inspect as a raw untracked Qty
    fn as_raw(&self) -> Qty;
}

/// Bookkept memory quantities
///
/// Each bookkept quantity implements this trait,
/// and has a single field `raw` of type `Qty`.
///
/// Should be Implemented by
/// [`#[derive_deftly(BookKept)]`](derive_deftly_template_BookkeptQty)
/// and for raw `Qty`.
///
/// # CORRECTNESS
///
/// All accesses to `raw`, or calls to `from_raw` or `into_raw`,
/// should be made from transaction functions,
/// which modify one or more bookkept quantities together,
/// preserving the invariants.
///
/// `raw` may be accessed mutably by such functions, but a bookkept quantity type
/// should be constructed only with `from_raw` and should not be moved out of.
trait BookkeptQty: BookkeepableQty + DefaultExtTake {
    /// Make a new bookkept quantity one from a raw untracked Qty
    ///
    fn from_raw(q: Qty) -> Self;

    /// Unwrap into a raw untracked Qty
    fn into_raw(self) -> Qty;
}

impl BookkeepableQty for Qty {
    const ZERO: Qty = Qty(0);

    fn as_raw(&self) -> Qty {
        *self
    }
}

/// Total used, [`TotalQtyNotifier`].`total_used`, found in [`State`].`total_used`.
///
/// Can be "poisoned", preventing further claims.
//
// Poisoned is indicated by We setting to `MAX`.
#[derive(Default, Debug, Deftly, derive_more::Display)]
#[derive_deftly(BookkeptQty)]
#[deftly(allow_nonzero_drop)] // Dropped only when the whole tracker is dropped
pub(super) struct TotalQty {
    /// See [`BookkeptQty`]
    raw: Qty,
}

/// Qty used by a participant, found in [`PRecord`].`used`.
///
/// The tracker data structure has one of these for each Participant.
///
/// This is the total amount `claim`ed, plus the caches in each `Participation`.
#[derive(Default, Debug, Deftly, derive_more::Display)]
#[derive_deftly(BookkeptQty)]
pub(super) struct ParticipQty {
    /// See [`BookkeptQty`]
    raw: Qty,
}

/// "Cached" claim, on behalf of a Participant
///
/// Found in [`Participation`].`cache`,
/// and accounted to the Participant (ie, included in `ParticipQty`).
///
/// Also used as a temporary variable in `claim()` and `release()` functions.
/// When we return to the participant, outside the tracker, we
/// essentially throw this away, since we don't give the caller any representation
/// to store.  The participant is supposed to track this separately somehow.
#[derive(Default, Debug, Deftly, derive_more::Display)]
#[derive_deftly(BookkeptQty)]
#[must_use]
pub(super) struct ClaimedQty {
    /// See [`BookkeptQty`]
    raw: Qty,
}

impl TotalQty {
    /// Claim a quantity, increasing the tracked amounts
    ///
    /// This module doesn't know anything about the memory quota,
    /// so this doesn't do the quota check.
    ///
    /// The only caller is [`Participation::claim`].
    pub(super) fn claim(&mut self, p_used: &mut ParticipQty, want: Qty) -> Option<ClaimedQty> {
        // If poisoned, this add will fail (unless want is 0)
        let new_self = self.raw.checked_add(*want)?;
        let new_p_used = p_used.raw.checked_add(*want)?;
        // commit
        self.raw = Qty(new_self);
        p_used.raw = Qty(new_p_used);
        Some(ClaimedQty::from_raw(want))
    }

    /// Release a quantity, decreasing the tracked amounts
    ///
    /// (Handles underflow by saturating; returning an error is not going to be useful.)
    pub(super) fn release(&mut self, p_used: &mut ParticipQty, have: ClaimedQty) {
        let have = have.into_raw();
        *p_used.raw = p_used.raw.saturating_sub(*have);

        if self.raw != Qty::MAX {
            // Don't unpoison
            *self.raw = self.raw.saturating_sub(*have);
        }
    }

    /// Declare this poisoned, and prevent further claims
    pub(super) fn set_poisoned(&mut self) {
        self.raw = Qty::MAX;
    }
}

impl ClaimedQty {
    /// Split a `ClaimedQty` into two `ClaimedQty`s
    pub(super) fn split_off(&mut self, want: Qty) -> Option<ClaimedQty> {
        let new_self = self.raw.checked_sub(*want)?;
        // commit
        *self.raw = new_self;
        Some(ClaimedQty::from_raw(want))
    }

    /// Merge two `ClaimedQty`s
    ///
    /// (Handles overflow by saturating; returning an error is not going to be useful.)
    pub(super) fn merge_into(&mut self, have: ClaimedQty) {
        let have = have.into_raw();
        *self.raw = self.raw.saturating_add(*have);
    }

    /// Obtain result for the participant, after having successfully recorded the amount claimed
    ///
    /// # CORRECTNESS
    ///
    /// This must be called only on a successful return path from [`Participation::claim`].
    #[allow(clippy::unnecessary_wraps)] // returns Result; proves it's used on success path
    pub(super) fn claim_return_to_participant(self) -> crate::Result<()> {
        let _: Qty = self.into_raw();
        Ok(())
    }

    /// When the participant indicates a release, enrol the amount in our bookkeping scheme
    ///
    /// Handles the quantity argument to [`Participation::release`].
    ///
    /// # CORRECTNESS
    ///
    /// This must be called only on entry to [`Participation::release`].
    pub(super) fn release_got_from_participant(got: Qty) -> Self {
        ClaimedQty::from_raw(got)
    }

    /// Dispose of a quantity that was claimed by a now-destroyed participant
    ///
    /// # CORRECTNESS
    ///
    /// The `ParticipQty` this was claimed from must also have been destroyed.
    ///
    /// So,
    /// [`ParticipQty::for_participant_teardown`] and the corresponding
    /// [`release`](TotalQty::release)
    /// must have been called earlier - possibly, much earlier.
    pub(super) fn dispose_participant_destroyed(mut self) {
        let _: Qty = mem::take(&mut self).into_raw();
    }
}

impl ParticipQty {
    /// Prepare to destroy the `ParticipQty` in a participant that's being destroyed
    ///
    /// When the records of a participant that is being torn down are being destroyed,
    /// we must remove our records of the memory that it allocated.
    ///
    /// This function is for that situation.
    /// The returned `ClaimedQty` should then be passed to `release`.
    ///
    /// # CORRECTNESS
    ///
    /// The data structure where this `ParticipQty` resides
    /// must be turn down (after we return).
    ///
    /// The `ClaimedQty` must be passed to [`TotalQty::release`],
    /// passing the4 same `p_used`.
    //
    // We could provide this as a single transaction function, rather than requiring
    // two calls.  But the main code doesn't have a `TotalQty`, only a ,
    // so we'd need to add an additional passthrough method to `TotalQtyNotifier`,
    // which doesn't seem worth it given that there's only one call site for this fn.
    pub(super) fn for_participant_teardown(&self) -> ClaimedQty {
        // We imagine that the Participant said it was releasing everything
        ClaimedQty::from_raw(self.as_raw())
    }
}
