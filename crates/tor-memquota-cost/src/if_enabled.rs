//! Helper type for disabling memory tracking when not wanted

/// Token indicating that memory quota tracking is enabled, at both compile and runtime
///
/// If support is compiled in this is a unit.
///
/// If the `memquota` cargo feature is not enabled, this type is uninhabited.
/// Scattering values of this type around in relevant data structures
/// and parameters lists
/// allows the compiler to eliminate the unwanted code.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EnabledToken {
    /// Make non-exhaustive even within the crate
    _hidden: (),

    /// Uninhabited if the feature isn't enabled.
    #[cfg(not(feature = "memquota"))]
    _forbid: void::Void,
}

impl Eq for EnabledToken {}

impl EnabledToken {
    /// Obtain an `EnabledToken` (only available if tracking is compiled in)
    #[allow(clippy::new_without_default)] // a conditional Default impl would be rather odd
    #[cfg(feature = "memquota")]
    pub const fn new() -> Self {
        EnabledToken { _hidden: () }
    }

    /// Obtain an `EnabledToken` if memory-tracking is compiled in, or `None` otherwise
    #[allow(clippy::unnecessary_wraps)] // Will be None if compiled out
    #[allow(unreachable_code)]
    pub const fn new_if_compiled_in() -> Option<Self> {
        Some(EnabledToken {
            _hidden: (),

            #[cfg(not(feature = "memquota"))]
            _forbid: return None,
        })
    }
}
