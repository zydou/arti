//! Facility for error-hinting

use super::ErrorHint;
use std::error::Error as StdError;

/// non-public module, to implement a "sealed" trait.
mod seal {
    /// Trait to seal the "Hintable" trait
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}

/// An error that can provide additional information about how to solve itself.
pub trait HintableError: seal::Sealed {
    /// Return a hint object explaining how to solve this error, if we have one.
    ///
    /// Most errors won't have obvious hints, but some do.  For the ones that
    /// do, we can return an [`ErrorHint`].
    ///
    /// Right now, `ErrorHint` is completely opaque: the only supported option
    /// is to format it for human consumption.
    fn hint(&self) -> Option<ErrorHint<'_>>;
}

impl seal::Sealed for super::Error {}
impl HintableError for super::Error {
    fn hint(&self) -> Option<ErrorHint<'_>> {
        best_hint(self)
    }
}
#[cfg(feature = "anyhow")]
impl seal::Sealed for anyhow::Error {}
#[cfg(feature = "anyhow")]
impl HintableError for anyhow::Error {
    fn hint(&self) -> Option<ErrorHint<'_>> {
        best_hint(self.as_ref())
    }
}

// TODO: We could also define HintableError for &dyn StdError if we wanted.

/// Return the best hint possible from `err`, by looking for the first error in
/// the chain defined by `err` and its sources that provides a value for
/// HintableErrorImpl::hint.
fn best_hint<'a>(mut err: &'a (dyn StdError + 'static)) -> Option<ErrorHint<'a>> {
    loop {
        if let Some(hint) =
            downcast_to_hintable_impl(err).and_then(HintableErrorImpl::hint_specific)
        {
            return Some(hint);
        }
        err = err.source()?;
    }
}

/// Trait for an error that can provide a hint _directly_.
///
/// Not defined for errors whose sources may provide a hint.
trait HintableErrorImpl: seal::Sealed {
    /// If possible, provide a hint for how to solve this error.
    ///
    /// (This should not check the source of this error or any other error;
    /// recursing is the job of [`best_hint`].  This is the method that
    /// should be implemented for an error type that might have a hint about how
    /// to solve that error in particular.)
    fn hint_specific(&self) -> Option<ErrorHint<'_>>;
}

impl HintableErrorImpl for fs_mistrust::Error {
    fn hint_specific(&self) -> Option<ErrorHint<'_>> {
        match self {
            fs_mistrust::Error::BadPermission(filename, bits, badbits) => Some(ErrorHint {
                inner: super::ErrorHintInner::BadPermission {
                    filename,
                    bits: *bits,
                    badbits: *badbits,
                },
            }),
            _ => None,
        }
    }
}

/// Declare one or more error types as having hints.
///
/// This macro implements Sealed for those types, and makes them participate
/// in `downcast_to_hintable_impl`.
macro_rules! hintable_impl {
    { $( $e:ty )+, $(,)? } =>
    {
        $(
            impl seal::Sealed for $e {}
        )+

        /// If possible, downcast this `StdError` to one of the implementations
        /// of `HintableErrorImpl`.
        fn downcast_to_hintable_impl<'a> (e: &'a (dyn StdError + 'static)) -> Option<&'a dyn HintableErrorImpl> {
            $(
                if let Some(hintable) =  e.downcast_ref::<$e>() {
                    return Some(hintable);
                }
            )+
            None
        }
    }
}

hintable_impl! {
    fs_mistrust::Error,
}
