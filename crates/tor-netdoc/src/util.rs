//! Misc helper functions and types for use in parsing network documents

pub(crate) mod intern;
pub(crate) mod str;

pub mod batching_split_before;

/// A Private module for declaring a "sealed" trait.
pub(crate) mod private {
    /// A non-exported trait, used to prevent others from implementing a trait.
    ///
    /// For more information on this pattern, see [the Rust API
    /// guidelines](https://rust-lang.github.io/api-guidelines/future-proofing.html#c-sealed).
    pub trait Sealed {}
}
