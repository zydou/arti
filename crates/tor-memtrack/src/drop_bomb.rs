//! Drop bombs, for assurance of postconditions when types are dropped
//!
//! Provides two drop bomb types: [`DropBomb`] and [`DropBombCondition`].
//!
//! These help assure that our algorithms are correct,
//! by detecting when types that contain the bomb are dropped inappropriately.
//!
//! # No-op outside `#[cfg(test)]`
//!
//! When used outside test code, these types are unit ZSTs,
//! and are completely inert.
//! They won't cause panics or detect bugs, in production.
//!
//! # Panics (in tests), and simulation
//!
//! These types work by panicking in drop, when a bug is detected.
//! This will then cause a test failure.
//! Such panics are described as "explodes (panics)" in the documentation.
//!
//! There are also simulated drop bombs, whose explosions do not actually panic.
//! Instead, they record that a panic would have occurred,
//! and print a message to stderr.
//! The constructors provide a handle to allow the caller to enquire about explosions.
//! This allows for testing a containing type's drop bomb logic.
//!
//! Certain misuses result in actual panics, even with simulated bombs.
//! This is described as "panics (actually)".
//!
//! # Choosing a bomb
//!
//! [`DropBomb`] is for assuring the runtime context or appropriate timing of drops
//! (and could be used for implementing general conditions).
//!
//! [`DropBombCondition`] is for assuring the properties of a value that is being dropped.

use crate::internal_prelude::*;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

//---------- macros used in this module, and supporting trait ----------

define_derive_deftly! {
    /// Helper for common impls on bombs
    ///
    ///  * Provides `fn new_armed`
    ///  * Provides `fn new_simulated`
    ///  * Implements `Drop`, using `TestableDrop::drop_impl`
    BombImpls =

    impl $ttype {
        /// Create a new drop bomb, which must be properly disposed of
        pub(crate) const fn new_armed() -> Self {
            let status = Status::ARMED_IN_TESTS;
            $ttype { status }
        }
    }

    #[cfg(test)]
    impl $ttype {
        /// Create a simulated drop bomb
        pub(crate) fn new_simulated() -> (Self, SimulationHandle) {
            let handle = SimulationHandle::new();
            let status = S::ArmedSimulated(handle.clone());
            ($ttype { status }, handle)
        }

        /// Turn an existing armed drop bomb into a simulated one
        ///
        /// This is useful for writing test cases, without having to make a `new_simulated`
        /// constructor for whatever type contains the drop bomb.
        /// Instead, construct it normally, and then reach in and call this on the bomb.
        ///
        /// # Panics
        ///
        /// `self` must be armed.  Otherwise, (actually) panics.
        pub(crate) fn make_simulated(&mut self) -> SimulationHandle {
            let handle = SimulationHandle::new();
            let new_status = S::ArmedSimulated(handle.clone());
            let old_status = mem::replace(&mut self.status, new_status);
            assert!(matches!(old_status, S::Armed));
            handle
        }

        /// Implemnetation of `Drop::drop`, split out for testability.
        ///
        /// Calls `drop_status`, and replaces `self.status` with `S::Disarmed`,
        /// so that `self` can be actually dropped (if we didn't panic).
        fn drop_impl(&mut self) {
            // Do the replacement first, so that if drop_status unwinds, we don't panic in panic.
            let status = mem::replace(&mut self.status, S::Disarmed);
            <$ttype as DropStatus>::drop_status(status);
        }
    }


    #[cfg(test)]
    impl Drop for $ttype {
        fn drop(&mut self) {
            // We don't check for unwinding.
            // We shouldn't drop a nonzero one of these even if we're panicking.
            // If we do, it'll be a double panic => abort.
            self.drop_impl();
        }
    }
}

/// Core of `Drop`, that can be called separately, for testing
///
/// To use: implement this, and derive deftly
/// [`BombImpls`](derive_deftly_template_BombImpls).
trait DropStatus {
    /// Handles dropping of a `Self` with this `status` field value
    fn drop_status(status: Status);
}

//---------- public types ----------

/// Drop bomb: for assuring that drops happen only when expected
///
/// Obtained from [`DropBomb::new_armed()`].
///
/// # Explosions
///
/// Explodes (panicking) if dropped,
/// unless [`.disarm()`](DropBomb::disarm) is called first.
#[derive(Deftly, Debug)]
#[derive_deftly(BombImpls)]
pub(crate) struct DropBomb {
    /// What state are we in
    status: Status,
}

/// Drop condition: for ensuring that a condition is true, on drop
///
/// Obtained from [`DropBombCondition::new_armed()`].
///
/// Instead of dropping this, you must call
/// `drop_bomb_disarm_assert!`
/// (or its internal function `disarm_assert()`.
// rustdoc can't manage to make a link to this crate-private macro or cfg-test item.
///
/// It will often be necessary to add `#[allow(dead_code)]`
/// on the `DropBombCondition` field of a containing type,
/// since outside tests, the `Drop` impl will usually be configured out,
/// and that's the only place this field is actually read.
///
/// # Panics
///
/// Panics (actually) if it is simply dropped.
#[derive(Deftly, Debug)]
#[derive_deftly(BombImpls)]
pub(crate) struct DropBombCondition {
    /// What state are we in
    #[allow(dead_code)] // not read outside tests
    status: Status,
}

/// Handle onto a simulated [`DropBomb`] or [`DropCondition`]
///
/// Can be used to tell whether the bomb "exploded"
/// (ie, whether `drop` would have panicked, if this had been a non-simulated bomb).
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct SimulationHandle {
    exploded: Arc<AtomicBool>,
}

/// Unit token indicating that a simulated drop bomb did explode, and would have panicked
#[cfg(test)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct SimulationExploded;

//---------- internal types ----------

/// State of some kind of drop bomb
///
/// This type is inert; the caller is responsible for exploding or panicking.
#[derive(Debug)]
enum Status {
    /// This bomb is disarmed and will not panic.
    ///
    /// This is always the case outside `#[cfg(test)]`
    Disarmed,

    /// This bomb is armed.  It will (or may) panic on drop.
    #[cfg(test)]
    Armed,

    /// This bomb is armed, but we're running in simulation.
    #[cfg(test)]
    ArmedSimulated(SimulationHandle),
}

use Status as S;

//---------- DropBomb impls ----------

impl DropBomb {
    /// Disarm this bomb.
    ///
    /// It will no longer explode (panic) when dropped.
    pub(crate) fn disarm(&mut self) {
        self.status = S::Disarmed;
    }
}

#[cfg(test)]
impl DropStatus for DropBomb {
    fn drop_status(status: Status) {
        match status {
            S::Disarmed => {}
            S::Armed => panic!("DropBomb dropped without a previous call to .disarm()"),
            S::ArmedSimulated(handle) => handle.set_exploded(),
        }
    }
}

//---------- DropCondition impls ----------

/// Check the condition, and disarm the bomb
///
/// If `CONDITION` is true, disarms the bomb; otherwise, explodes (panics).
///
/// # Syntax
///
/// ```
/// drop_bomb_disarm_assert!(BOMB, CONDITION);
/// drop_bomb_disarm_assert!(BOMB, CONDITION, "FORMAT", FORMAT_ARGS..);
/// ```
///
/// where
///
///  * `BOMB: &mut DropCondition` (or something that derefs to that).
///  * `CONDITION: bool`
///
/// # Example
///
/// ```
/// # struct S { drop_bomb: DropCondition };
/// # impl S { fn f(&mut self) {
/// drop_bomb_disarm_assert!(self.drop_bomb, self.raw, Qty(0));
/// # } }
/// ```
///
/// # Explodes
///
/// Explodes unless the condition is satisfied.
//
// This macro has this long name because we can't do scoping of macro-rules macros.
#[cfg(test)] // Should not be used outside tests, since the drop impls should be conditional
macro_rules! drop_bomb_disarm_assert {
    { $bomb:expr, $condition:expr $(,)? } => {
        $bomb.disarm_assert(
            || $condition,
            format_args!(concat!("condition = ", stringify!($condition))),
        )
    };
    { $bomb:expr, $condition:expr, $fmt:literal $($rest:tt)* } => {
        $bomb.disarm_assert(
            || $condition,
            format_args!(concat!("condition = ", stringify!($condition), ": ", $fmt),
                         $($rest)*),
        )
    };
}

impl DropBombCondition {
    /// Check a condition, and disarm the bomb
    ///
    /// If `call()` returns true, disarms the bomb; otherwise, explodes (panics).
    ///
    /// # Explodes
    ///
    /// Explodes unless the condition is satisfied.
    #[inline]
    #[cfg(test)] // Should not be used outside tests, since the drop impls should be conditional
    pub(crate) fn disarm_assert(&mut self, call: impl FnOnce() -> bool, msg: fmt::Arguments) {
        match mem::replace(&mut self.status, S::Disarmed) {
            S::Disarmed => {
                // outside cfg(test), this is the usual path.
                // placate the compiler: we ignore all our arguments
                let _ = call;
                let _ = msg;

                #[cfg(test)]
                panic!("disarm_assert called more than once!");
            }
            #[cfg(test)]
            S::Armed => {
                if !call() {
                    panic!("drop condition violated: dropped, but condition is false: {msg}");
                }
            }
            #[cfg(test)]
            #[allow(clippy::print_stderr)]
            S::ArmedSimulated(handle) => {
                if !call() {
                    eprintln!("drop condition violated in simulation: {msg}");
                    handle.set_exploded();
                }
            }
        }
    }
}

/// Ideally, if you use this, your struct's other default values meet your drop condition!
impl Default for DropBombCondition {
    fn default() -> DropBombCondition {
        Self::new_armed()
    }
}

#[cfg(test)]
impl DropStatus for DropBombCondition {
    fn drop_status(status: Status) {
        assert!(matches!(status, S::Disarmed));
    }
}

//---------- SimulationHandle impls ----------

#[cfg(test)]
impl SimulationHandle {
    /// Determine whether a drop bomb would have been triggered
    ///
    /// If the corresponding [`DropBomb]` or [`DropCondition`]
    /// would have panicked (if we weren't simulating),
    /// returns `Err`.
    ///
    /// # Panics
    ///
    /// The corresponding `DropBomb` or `DropCondition` must have been dropped.
    /// Otherwise, calling `outcome` will (actually) panic.
    pub(crate) fn outcome(mut self) -> Result<(), SimulationExploded> {
        let panicked = Arc::into_inner(mem::take(&mut self.exploded))
            .expect("bomb has not yet been dropped")
            .into_inner();
        if panicked {
            Err(SimulationExploded)
        } else {
            Ok(())
        }
    }

    /// Require that this bomb did *not* explode
    ///
    /// # Panics
    ///
    /// Panics if corresponding `DropBomb` hasn't yet been dropped,
    /// or if it exploded when it was dropped.
    pub(crate) fn expect_ok(self) {
        let () = self.outcome().expect("bomb unexpectedly exploded");
    }

    /// Require that this bomb *did* explode
    ///
    /// # Panics
    ///
    /// Panics if corresponding `DropBomb` hasn't yet been dropped,
    /// or if it did *not* explode when it was dropped.
    pub(crate) fn expect_exploded(self) {
        let SimulationExploded = self
            .outcome()
            .expect_err("bomb unexpectedly didn't explode");
    }

    /// Return a new handle with no explosion recorded
    fn new() -> Self {
        SimulationHandle {
            exploded: Default::default(),
        }
    }

    /// Return a clone of this handle
    //
    // Deliberately not a public Clone impl
    fn clone(&self) -> Self {
        SimulationHandle {
            exploded: self.exploded.clone(),
        }
    }

    /// Mark this simulated bomb as having exploded
    fn set_exploded(&self) {
        self.exploded.store(true, Ordering::Release);
    }
}

//---------- internal impls ----------

impl Status {
    /// Armed, in tests
    #[cfg(test)]
    const ARMED_IN_TESTS: Status = S::Armed;

    /// "Armed", outside tests, is in fact not armed
    #[cfg(not(test))]
    const ARMED_IN_TESTS: Status = S::Disarmed;
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
    use std::any::Any;
    use std::panic::catch_unwind;

    #[test]
    fn bomb_disarmed() {
        let mut b = DropBomb::new_armed();
        b.disarm();
        drop(b);
    }

    #[test]
    fn bomb_panic() {
        let mut b = DropBomb::new_armed();
        let _: Box<dyn Any> = catch_unwind(AssertUnwindSafe(|| b.drop_impl())).unwrap_err();
    }

    #[test]
    fn bomb_sim_disarmed() {
        let (mut b, h) = DropBomb::new_simulated();
        b.disarm();
        drop(b);
        h.expect_ok();
    }

    #[test]
    fn bomb_sim_explosion() {
        let (b, h) = DropBomb::new_simulated();
        drop(b);
        h.expect_exploded();
    }

    #[test]
    fn bomb_make_sim_explosion() {
        let mut b = DropBomb::new_armed();
        let h = b.make_simulated();
        drop(b);
        h.expect_exploded();
    }

    struct HasBomb {
        on_drop: Result<(), ()>,
        bomb: DropBombCondition,
    }

    impl Drop for HasBomb {
        fn drop(&mut self) {
            drop_bomb_disarm_assert!(self.bomb, self.on_drop.is_ok());
        }
    }

    #[test]
    fn cond_ok() {
        let hb = HasBomb {
            on_drop: Ok(()),
            bomb: DropBombCondition::new_armed(),
        };
        drop(hb);
    }

    #[test]
    fn cond_sim_explosion() {
        let (bomb, h) = DropBombCondition::new_simulated();
        let hb = HasBomb {
            on_drop: Err(()),
            bomb,
        };
        drop(hb);
        h.expect_exploded();
    }

    #[test]
    fn cond_explosion_panic() {
        // make an actual panic
        let mut bomb = DropBombCondition::new_armed();
        let _: Box<dyn Any> = catch_unwind(AssertUnwindSafe(|| {
            bomb.disarm_assert(|| false, format_args!("testing"));
        }))
        .unwrap_err();
    }

    #[test]
    fn cond_forgot_drop_impl() {
        // pretend that we put a DropBombCondition on this,
        // but we forgot to impl Drop and call drop_bomb_disarm_assert
        struct ForgotDropImpl {
            bomb: DropBombCondition,
        }
        let fdi = ForgotDropImpl {
            bomb: DropBombCondition::new_armed(),
        };
        // pretend that fdi is being dropped
        let mut bomb = fdi.bomb; // move out

        let _: Box<dyn Any> = catch_unwind(AssertUnwindSafe(|| bomb.drop_impl())).unwrap_err();
    }
}
