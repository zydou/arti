//! `HasMemoryCost` and typed memory cost tracking

use crate::internal_prelude::*;

/// Types whose memory usage is known (and stable)
///
/// ### Important guarantees
///
/// Implementors of this trait must uphold the guarantees in the API of
/// [`memory_cost`](HasMemoryCost::memory_cost).
///
/// If these guarantees are violated, memory tracking may go wrong,
/// with seriously bad implications for the whole program,
/// including possible complete denial of service.
///
/// (Nevertheless, memory safety will not be compromised,
/// so trait this is not `unsafe`.)
pub trait HasMemoryCost {
    /// Returns the memory cost of `self`, in bytes
    ///
    /// ### Return value must be stable
    ///
    /// It is vital that the return value does not change, for any particular `self`,
    /// unless `self` is mutated through `&mut self` or similar.
    /// Otherwise, memory accounting may go awry.
    ///
    /// If `self` has interior mutability. the changing internal state
    /// must not change the memory cost.
    ///
    /// ### Panics - forbidden
    ///
    /// This method must not panic.
    /// Otherwise, memory accounting may go awry.
    fn memory_cost(&self, _: EnabledToken) -> usize;
}

/// A [`Participation`] for use only for tracking the memory use of objects of type `T`
///
/// Wrapping a `Participation` in a `TypedParticipation`
/// helps prevent accidentally passing wrongly calculated costs
/// to `claim` and `release`.
#[derive(Deref, Educe)]
#[educe(Clone)]
#[educe(Debug(named_field = false))]
pub struct TypedParticipation<T> {
    /// The actual participation
    #[deref]
    raw: Participation,
    /// Marker
    #[educe(Debug(ignore))]
    marker: PhantomData<fn(T)>,
}

/// Memory cost obtained from a `T`
#[derive(Educe, derive_more::Display)]
#[educe(Copy, Clone)]
#[educe(Debug(named_field = false))]
#[display("{raw}")]
pub struct TypedMemoryCost<T> {
    /// The actual cost in bytes
    raw: usize,
    /// Marker
    #[educe(Debug(ignore))]
    marker: PhantomData<fn(T)>,
}

/// Types that can return a memory cost known to be the cost of some value of type `T`
///
/// [`TypedParticipation::claim`] and
/// [`release`](TypedParticipation::release)
/// take arguments implementing this trait.
///
/// Implemented by:
///
///   * `T: HasMemoryCost` (the usual case)
///   * `HasTypedMemoryCost<T>` (memory cost, calculated earlier, from a `T`)
///
/// ### Guarantees
///
/// This trait has the same guarantees as `HasMemoryCost`.
/// Normally, it will not be necessary to add an implementation.
// We could seal this trait, but we would need to use a special variant of Sealed,
// since we wouldn't want to `impl<T: HasMemoryCost> Sealed for T`
// for a normal Sealed trait also used elsewhere.
// The bug of implementing this trait for other types seems unlikely,
// and we don't think there's a significant API stability hazard.
pub trait HasTypedMemoryCost<T>: Sized {
    /// The cost, as a `TypedMemoryCost<T>` rather than a raw `usize`
    fn typed_memory_cost(&self, _: EnabledToken) -> TypedMemoryCost<T>;
}

impl<T: HasMemoryCost> HasTypedMemoryCost<T> for T {
    fn typed_memory_cost(&self, enabled: EnabledToken) -> TypedMemoryCost<T> {
        TypedMemoryCost::from_raw(self.memory_cost(enabled))
    }
}
impl<T> HasTypedMemoryCost<T> for TypedMemoryCost<T> {
    fn typed_memory_cost(&self, _: EnabledToken) -> TypedMemoryCost<T> {
        *self
    }
}

impl<T> TypedParticipation<T> {
    /// Wrap a [`Participation`], ensuring that future calls claim and release only `T`
    pub fn new(raw: Participation) -> Self {
        TypedParticipation {
            raw,
            marker: PhantomData,
        }
    }

    /// Record increase in memory use, of a `T: HasMemoryCost` or a `TypedMemoryCost<T>`
    pub fn claim(&mut self, t: &impl HasTypedMemoryCost<T>) -> Result<(), Error> {
        let Some(enabled) = EnabledToken::new_if_compiled_in() else {
            return Ok(());
        };
        self.raw.claim(t.typed_memory_cost(enabled).raw)
    }
    /// Record decrease in memory use, of a `T: HasMemoryCost` or a `TypedMemoryCost<T>`
    pub fn release(&mut self, t: &impl HasTypedMemoryCost<T>) {
        let Some(enabled) = EnabledToken::new_if_compiled_in() else {
            return;
        };
        self.raw.release(t.typed_memory_cost(enabled).raw);
    }

    /// Claiming wrapper for a closure
    ///
    /// Claims the memory, iff `call` succeeds.
    ///
    /// Specifically:
    /// Claims memory for `item`.   If that fails, returns the error.
    /// If the claim succeeded, calls `call`.
    /// If it fails or panics, the memory is released, undoing the claim,
    /// and the error is returned (or the panic propagated).
    ///
    /// In these error cases, `item` will typically be dropped by `call`,
    /// it is not convenient for `call` to do otherwise.
    pub fn try_claim<C, F, E, R>(&mut self, item: C, call: F) -> Result<Result<R, E>, Error>
    where
        C: HasTypedMemoryCost<T>,
        F: FnOnce(C) -> Result<R, E>,
    {
        let Some(enabled) = EnabledToken::new_if_compiled_in() else {
            return Ok(call(item));
        };

        let cost = item.typed_memory_cost(enabled);
        self.claim(&cost)?;
        // Unwind safety:
        //  - "`F` may not be safely transferred across an unwind boundary"
        //    but we don't; it is moved into the closure and
        //   it can't obwerve its own panic
        //  - "`C` may not be safely transferred across an unwind boundary"
        //   Once again, item is moved into call, and never seen again.
        match catch_unwind(AssertUnwindSafe(move || call(item))) {
            Err(panic_payload) => {
                self.release(&cost);
                std::panic::resume_unwind(panic_payload)
            }
            Ok(Err(caller_error)) => {
                self.release(&cost);
                Ok(Err(caller_error))
            }
            Ok(Ok(y)) => Ok(Ok(y)),
        }
    }

    /// Mutably access the inner `Participation`
    ///
    /// This bypasses the type check.
    /// It is up to you to make sure that the `claim` and `release` calls
    /// are only made with properly calculated costs.
    pub fn as_raw(&mut self) -> &mut Participation {
        &mut self.raw
    }

    /// Unwrap, and obtain the inner `Participation`
    pub fn into_raw(self) -> Participation {
        self.raw
    }
}

impl<T> From<Participation> for TypedParticipation<T> {
    fn from(untyped: Participation) -> TypedParticipation<T> {
        TypedParticipation::new(untyped)
    }
}

impl<T> TypedMemoryCost<T> {
    /// Convert a raw number of bytes into a type-tagged memory cost
    pub fn from_raw(raw: usize) -> Self {
        TypedMemoryCost {
            raw,
            marker: PhantomData,
        }
    }

    /// Convert a type-tagged memory cost into a raw number of bytes
    pub fn into_raw(self) -> usize {
        self.raw
    }
}

#[cfg(all(test, feature = "memquota"))]
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
    #![allow(clippy::arithmetic_side_effects)] // don't mind potential panicking ops in tests

    use super::*;
    use crate::mtracker::test::*;
    use crate::mtracker::*;
    use tor_rtmock::MockRuntime;

    // We don't really need to test the correctness, since this is just type wrappers.
    // But we should at least demonstrate that the API is usable.

    #[derive(Debug)]
    struct DummyParticipant;
    impl IsParticipant for DummyParticipant {
        fn get_oldest(&self, _: EnabledToken) -> Option<CoarseInstant> {
            None
        }
        fn reclaim(self: Arc<Self>, _: EnabledToken) -> ReclaimFuture {
            panic!()
        }
    }

    struct Costed;
    impl HasMemoryCost for Costed {
        fn memory_cost(&self, _: EnabledToken) -> usize {
            // We nearly exceed the limit with one allocation.
            //
            // This proves that claim does claim, or we'd underflow on release,
            // and that release does release, not claim, or we'd reclaim and crash.
            TEST_DEFAULT_LIMIT - mbytes(1)
        }
    }

    #[test]
    fn api() {
        MockRuntime::test_with_various(|rt| async move {
            let trk = mk_tracker(&rt);
            let acct = trk.new_account(None).unwrap();
            let particip = Arc::new(DummyParticipant);
            let partn = acct
                .register_participant(Arc::downgrade(&particip) as _)
                .unwrap();
            let mut partn: TypedParticipation<Costed> = partn.into();

            partn.claim(&Costed).unwrap();
            partn.release(&Costed);

            let cost = Costed.typed_memory_cost(EnabledToken::new());
            partn.claim(&cost).unwrap();
            partn.release(&cost);

            // claim, then release due to error
            partn
                .try_claim(Costed, |_: Costed| Err::<Void, _>(()))
                .unwrap()
                .unwrap_err();

            // claim, then release due to panic
            catch_unwind(AssertUnwindSafe(|| {
                let didnt_panic =
                    partn.try_claim(Costed, |_: Costed| -> Result<Void, Void> { panic!() });
                panic!("{:?}", didnt_panic);
            }))
            .unwrap_err();

            // claim OK, then explicitly release later
            let did_claim = partn
                .try_claim(Costed, |c: Costed| Ok::<Costed, Void>(c))
                .unwrap()
                .void_unwrap();
            // Check that we did claim at least something!
            assert!(trk.used_current_approx().unwrap() > 0);

            partn.release(&did_claim);

            drop(acct);
            drop(particip);
            drop(trk);
            partn
                .try_claim(Costed, |_| -> Result<Void, Void> { panic!() })
                .unwrap_err();

            rt.advance_until_stalled().await;
        });
    }
}
