//! Miscellaneous utility functions/macros/types.

use std::fmt::Display;

/// Formats an iterator as an object whose display implementation is a `separator`-separated string
/// of items from `iter`.
// TODO: This can be replaced with `std::fmt::from_fn()` once stabilised and within our MSRV.
pub(crate) fn iter_join(
    separator: &str,
    iter: impl Iterator<Item: Display> + Clone,
) -> impl Display {
    struct Fmt<'a, I: Iterator<Item: Display> + Clone> {
        /// Separates items in `iter`.
        separator: &'a str,
        /// Iterator to join.
        iter: I,
    }
    impl<'a, I: Iterator<Item: Display> + Clone> Display for Fmt<'a, I> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Self { separator, iter } = self;
            let mut iter = iter.clone();
            if let Some(first) = iter.next() {
                write!(f, "{first}")?;
            }
            for x in iter {
                write!(f, "{separator}{x}")?;
            }
            Ok(())
        }
    }
    Fmt { separator, iter }
}
