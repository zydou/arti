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
    fn memory_cost(&self) -> usize;
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
#[display(fmt = "{raw}")]
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
    fn typed_memory_cost(&self) -> TypedMemoryCost<T>;
}

impl<T: HasMemoryCost> HasTypedMemoryCost<T> for T {
    fn typed_memory_cost(&self) -> TypedMemoryCost<T> {
        TypedMemoryCost::from_raw(self.memory_cost())
    }
}
impl<T> HasTypedMemoryCost<T> for TypedMemoryCost<T> {
    fn typed_memory_cost(&self) -> TypedMemoryCost<T> {
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
        self.raw.claim(t.typed_memory_cost().raw)
    }
    /// Record decrease in memory use, of a `T: HasMemoryCost` or a `TypedMemoryCost<T>`
    pub fn release(&mut self, t: &impl HasTypedMemoryCost<T>) {
        self.raw.release(t.typed_memory_cost().raw);
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
