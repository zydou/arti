//! Structural keyword recognition helpers

use super::*;

/// Predicate for testing whether a keyword is a structural one that we should stop at
///
/// This helper type allows us to compose predicates in curried form with `|`.
#[derive(Debug, Copy, Clone, derive_more::Deref)]
#[allow(clippy::exhaustive_structs)]
pub struct StopAt<P: StopPredicate>(pub P);

/// Raw predicate, usually a closure, that can appear within `StopAt`.
///
/// Implemented for suitable closures, and also for booleans.
pub trait StopPredicate: Copy {
    /// Is this keyword a structural one meaning we should stop parsing here?
    ///
    /// Precisely what the semantics are depends on the context.
    /// Typically, matched keywords will cause processing to continue
    /// in a subsequent document section, or in an outer (containing) document.
    fn stop_at(&self, kw: KeywordRef<'_>) -> bool;
}
impl<F: Copy + Fn(KeywordRef<'_>) -> bool> StopPredicate for F {
    fn stop_at(&self, kw: KeywordRef<'_>) -> bool {
        self(kw)
    }
}
impl StopPredicate for bool {
    fn stop_at(&self, _kw: KeywordRef<'_>) -> bool {
        *self
    }
}

/// "Type alias" for `StopAt<impl Fn(KeywordRef<'_>) -> Option<Stop>>`
///
/// This has to be a macro because the `impl` is a different type at each call site;
/// even TAIT wouldn't help with thaat.
#[macro_export]
macro_rules! stop_at { {} => {
    $crate::parse2::internal_prelude::StopAt<
        impl $crate::parse2::internal_prelude::StopPredicate
    >
} }

impl StopAt<bool> {
    /// Returns predicate flagging precisely the intro keywords for a parseable document
    pub fn doc_intro<D: NetdocParseable>() -> stop_at!() {
        StopAt(D::is_intro_item_keyword)
    }
}

/// Helper type: return value from `StopAt | StopAt`
#[derive(Debug, Copy, Clone)]
pub struct BitOrOutput<A, B>(A, B);

impl<A: StopPredicate, B: StopPredicate> std::ops::BitOr<StopAt<B>> for StopAt<A> {
    type Output = StopAt<BitOrOutput<A, B>>;
    fn bitor(self, rhs: StopAt<B>) -> Self::Output {
        StopAt(BitOrOutput(self.0, rhs.0))
    }
}

impl<A: StopPredicate, B: StopPredicate> StopPredicate for BitOrOutput<A, B> {
    fn stop_at(&self, kw: KeywordRef<'_>) -> bool {
        self.0.stop_at(kw) || self.1.stop_at(kw)
    }
}
