//! Deferred drop handling.
//!
//! We sometimes have `Arc<dyn Participant>`s we have obtained but don't want to drop yet
//!
//! See the top-level docs for context.
//!
//! When we drop the `Arc`, the refcount might become zero.
//! Then the inner type would be dropped.
//! The inner type is allowed to call back into us (for example, it may drop an `Account`).
//! We must therefore not drop a caller's `Participant` with our own state lock held.
//!
//! This module has a helper type for assuring that we do defer drops.
//
// There are no separate tests for this module.  Drop bombs are hard to test for,
// and the rest of the code is just wrappers.

use super::*;

/// `MutexGuard<State>` but also a list of `Arc<dyn Partcipant>` to drop when we unlock
#[derive(Debug, Default)]
pub(super) struct GuardWithDeferredDrop<'m> {
    /// The mutex guard
    ///
    /// Always `Some`; just an `Option` so we can move out during drop
    guard: Option<MutexGuard<'m, State>>,

    /// The participants we've acquired and which we want to drop later
    deferred_drop: DeferredDrop,
}

/// Participants we've acquired and which we want to drop later, convenience alias
pub(super) type DeferredDrop = Vec<drop_reentrancy::ProtectedArc<dyn IsParticipant>>;

impl<'m> GuardWithDeferredDrop<'m> {
    /// Prepare for handling deferred drops
    pub(super) fn new(guard: MutexGuard<'m, State>) -> Self {
        GuardWithDeferredDrop {
            guard: Some(guard),
            deferred_drop: vec![],
        }
    }

    /// Obtain mutable borrows of the two components
    pub(super) fn deref_mut_both(&mut self) -> (&mut State, &mut DeferredDrop) {
        (
            self.guard.as_mut().expect("deref_mut after drop"),
            &mut self.deferred_drop,
        )
    }
}

impl Deref for GuardWithDeferredDrop<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.guard.as_ref().expect("deref after drop")
    }
}
impl DerefMut for GuardWithDeferredDrop<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.deref_mut_both().0
    }
}

// We use ProtectedArc.  In tests, that has a drop bomb which requires us to
// call `.promise_dropping_is_ok()`, on pain of panicking.  So we must do that here.
//
// Outside tests, the normal drop order would be precisely correct:
// the guard field comes first, so the compiler would drop it before the Arcs.
// So we could make this `#[cfg(test)]` (and add some comments above about field order).
// However, we prefer to use the same code, so that the correctness of
// *production* GuardWithDeferredDrop is assured by the `ProtectedArc`.
impl Drop for GuardWithDeferredDrop<'_> {
    fn drop(&mut self) {
        let guard = self.guard.take().expect("dropping twice!");
        drop::<MutexGuard<_>>(guard);
        // we just unlocked the guard, so drops that re-enter our code are fine
        for p in self.deferred_drop.drain(..) {
            p.promise_dropping_is_ok();
        }
    }
}
