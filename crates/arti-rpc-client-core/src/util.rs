//! Helper utilities
//!

// TODO RPC: Consider replacing this with a derive-deftly template.
//
/// Define an `impl From<fromty> for toty`` that wraps its input as
/// `toty::variant(Arc::new(e))``
macro_rules! define_from_for_arc {
    { $fromty:ty => $toty:ty [$variant:ident] } => {
        impl From<$fromty> for $toty {
            fn from(e: $fromty) -> $toty {
                Self::$variant(std::sync::Arc::new(e))
            }
        }
    };
}
pub(crate) use define_from_for_arc;
