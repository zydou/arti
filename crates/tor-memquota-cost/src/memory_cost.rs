//! `HasMemoryCost` and typed memory cost tracking

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
    fn memory_cost(&self, _: crate::EnabledToken) -> usize;
}
