//! Misc helper functions and types for use in parsing network documents

pub(crate) mod str;

pub mod batching_split_before;

use std::iter::Peekable;

/// An iterator with a `.peek()` method
///
/// We make this a trait to avoid entangling all the types with `Peekable`.
/// Ideally we would do this with `Itertools::PeekingNext`
/// but that was not implemented for `&mut PeekingNext`
/// when we wrote this code,
/// and we need that because we use a lot of `&mut NetdocReader`.
/// <https://github.com/rust-itertools/itertools/issues/678>
///
/// TODO: As of itertools 0.11.0, `PeekingNext` _is_ implemented for
/// `&'a mut I where I: PeekingNext`, so we can remove this type some time.
///
/// # **UNSTABLE**
///
/// This type is UNSTABLE and not part of the semver guarantees.
/// You'll only see it if you ran rustdoc with `--document-private-items`.
// This is needed because this is a trait bound for batching_split_before.
#[doc(hidden)]
pub trait PeekableIterator: Iterator {
    /// Inspect the next item, if there is one
    fn peek(&mut self) -> Option<&Self::Item>;
}

impl<I: Iterator> PeekableIterator for Peekable<I> {
    fn peek(&mut self) -> Option<&Self::Item> {
        self.peek()
    }
}

impl<I: PeekableIterator> PeekableIterator for &mut I {
    fn peek(&mut self) -> Option<&Self::Item> {
        <I as PeekableIterator>::peek(*self)
    }
}

/// A Private module for declaring a "sealed" trait.
pub(crate) mod private {
    /// A non-exported trait, used to prevent others from implementing a trait.
    ///
    /// For more information on this pattern, see [the Rust API
    /// guidelines](https://rust-lang.github.io/api-guidelines/future-proofing.html#c-sealed).
    #[expect(dead_code, unreachable_pub)] // TODO keep this Sealed trait in case we want it again?
    pub trait Sealed {}
}
