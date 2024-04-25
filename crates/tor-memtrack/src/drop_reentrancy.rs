//! Newtype which helps assure lack of drop entrance hazards
//!
//! Provides a drop bomb which will help tests detect latent bugs.
//!
//! We want this because there are places where we handle an Arc containing
//! a user-provided trait object, but where we want to prevent invoking
//! the user's Drop impl since that may lead to reentrancy.
//!
//! See the section on "Reentrancy" in the docs for `mtracker::State`.
//!
//! Outside tests, the types in this module are equivalent to `std::sync`'s.
//! So, we never panic in a drop in production.
//! Dropping in the wrong place might lead to a deadlock
//! (due to mutex reentrancy)
//! but this is far from certain:
//! probably, while we're running, the caller has another live reference,
//! so the drop of the underlying type won't happen now anyway.
//!
//! In any case, drop bombs mustn't be used in production.
//! Not only can they escalate the severity of problems,
//! where the program might blunder on,
//! but also
//! because Rust upstream are seriously considering
//! [turning them into aborts](https://github.com/rust-lang/rfcs/pull/3288)!
//
// There are no separate tests for this module.  Drop bombs are hard to test for.
// However, in an ad-hoc test, the bomb has been shown to be able to explode,
// if a `ProtectedArc` is dropped.

use crate::internal_prelude::*;

/// A `Weak<P>`, but upgradeable only to a `ProtectedArc`, not a raw `Arc`.
#[derive(Debug)]
pub(crate) struct ProtectedWeak<P: ?Sized>(Weak<P>);

/// An `Arc`, but containing a type which should only be dropped in certain places
///
/// In non `#[cfg(test)]` builds, this is just `Arc<P>`.
///
/// When testing, it has a drop bomb.  You must call `.promise_dropping_is_ok`.
/// It will panic if it's simply dropped.
#[derive(Debug, Deref, DerefMut)]
pub(crate) struct ProtectedArc<P: ?Sized> {
    /// The actual explosive (might be armed or disarmed)
    bomb: DropBomb,

    /// The underlying `Arc`
    #[deref(forward)]
    #[deref_mut(forward)]
    arc: Arc<P>,
}

impl<P: ?Sized> ProtectedWeak<P> {
    /// Make a new `ProtectedWeak`
    pub(crate) fn new(p: Weak<P>) -> Self {
        ProtectedWeak(p)
    }

    /// Upgrade a `ProtectedWeak` to a `ProtectedArc`, if it's not been garbage collected
    pub(crate) fn upgrade(&self) -> Option<ProtectedArc<P>> {
        Some(ProtectedArc::new(self.0.upgrade()?))
    }

    /// Convert back into an unprotected `Weak`.
    ///
    /// # CORRECTNESS
    ///
    /// You must arrange that the drop reentrancy requirements aren't violated
    /// by `Arc`s made from the returned `Weak`.
    pub(crate) fn unprotect(self) -> Weak<P> {
        self.0
    }
}

impl<P: ?Sized> ProtectedArc<P> {
    /// Make a new `ProtectedArc` from a raw `Arc`
    ///
    /// # CORRECTNESS
    ///
    /// Presumably the `Arc` came from an uncontrolled external source, such as user code.
    pub(crate) fn new(arc: Arc<P>) -> Self {
        let bomb = DropBomb::new_armed();
        ProtectedArc { arc, bomb }
    }

    /// Obtain a `ProtectedWeak` from a `&ProtectedArc`
    //
    // If this were a more general-purpose library, we'd avoid this and other methods on `self`.
    pub(crate) fn downgrade(&self) -> ProtectedWeak<P> {
        ProtectedWeak(Arc::downgrade(&self.arc))
    }

    /// Convert back into an unprotected `Arc`
    ///
    /// # CORRECTNESS
    ///
    /// If the return value is dropped, the location must be suitable for that.
    /// Or, maybe the returned value is going to calling code in the external user,
    /// (which, therefore, wouldn't pose a reentrancy hazard).
    pub(crate) fn promise_dropping_is_ok(mut self) -> Arc<P> {
        self.bomb.disarm();
        self.arc
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::let_and_return)] // TODO this lint is annoying and we should disable it

    use super::*;

    struct Payload;

    #[test]
    fn fine() {
        let arc = Arc::new(Payload);
        let prot = ProtectedArc::new(arc);
        let arc = prot.promise_dropping_is_ok();
        drop(arc);
    }

    #[test]
    fn bad() {
        let arc = Arc::new(Payload);
        let mut prot = ProtectedArc::new(arc);
        let h = prot.bomb.make_simulated();
        drop(prot);
        h.expect_exploded();
    }
}
