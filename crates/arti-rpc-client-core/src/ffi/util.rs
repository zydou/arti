//! Helpers for working with FFI.

use std::ffi::{c_char, CStr};

use super::{err::IntoFfiError, FfiStatus};

/// Try to convert a const ptr to a string, but return an error if the pointer
/// is NULL or not UTF8.
///
/// # Safety
///
/// See [`CStr::from_ptr`].  All those restrictions apply, except that we tolerate a NULL pointer.
pub(super) unsafe fn ptr_to_str<'a>(p: *const c_char) -> Result<&'a str, PtrToStrError> {
    if p.is_null() {
        return Err(PtrToStrError::NullPointer);
    }

    // Safety: We require that the safety properties of CStr::from_ptr hold.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| PtrToStrError::BadUtf8)
}

/// An error from [`ptr_to_str`].
#[derive(Clone, Debug, thiserror::Error)]
pub(super) enum PtrToStrError {
    /// Tried to convert a NULL pointer to a string.
    #[error("Provided string was NULL.")]
    NullPointer,

    /// Tried to convert a non-UTF string.
    #[error("Provided string was not UTF-8")]
    BadUtf8,
}

impl IntoFfiError for PtrToStrError {
    fn status(&self) -> FfiStatus {
        FfiStatus::InvalidInput
    }
}
