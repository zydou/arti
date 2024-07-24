//! Helpers for working with FFI.

use std::ffi::{c_char, CStr};

use super::{
    err::{IntoFfiError, NullPointer},
    FfiStatus,
};

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

/// Convert `ptr` into a reference, or return a null pointer exception.
///
/// # Safety
///
/// If `ptr` is not null, it must be a valid pointer to an instance of `T`.
/// The underlying T must not be modified for so long as this reference exists.
///
/// (These are the same as the rules for `const *`s passed into the arti RPC lib.)
pub(super) unsafe fn ptr_as_ref<'a, T>(ptr: *const T) -> Result<&'a T, NullPointer> {
    // Safety: we require that ptr, if set, is valid.
    unsafe { ptr.as_ref() }.ok_or(NullPointer)
}

/// Helper for output parameters represented as `*mut *mut T`.
///
/// This is for an API which, from a C POV, returns an output via a parameter of type
/// `Foo **foo_out`.  If
///
/// The outer `foo_out` pointer may be NULL; if so, the caller wants to discard any values.
///
/// If `foo_out` is not NULL, then `*foo_out` is always set to NULL when an `OutPtr`
/// is constructed, so that even if the FFI code panics, the inner pointer will be initialized to
/// _something_.
pub(super) struct OutPtr<'a, T>(Option<&'a mut *mut T>);

impl<'a, T> OutPtr<'a, T> {
    /// Construct `Self` from a possibly NULL pointer; initialize `*ptr` to NULL if possible.
    ///
    /// # Safety
    ///
    /// The outer pointer, if set, must be valid, and must not alias any other pointers.
    ///
    /// See also the requirements on `pointer::as_mut()`.
    pub(super) unsafe fn from_ptr(ptr: *mut *mut T) -> Self {
        let ptr: Option<&'a mut *mut T> = unsafe { ptr.as_mut() };
        match ptr {
            Some(p) => {
                *p = std::ptr::null_mut();
                OutPtr(Some(p))
            }
            None => OutPtr(None),
        }
    }

    /// As [`Self::from_ptr`], but return an error if the pointer is NULL.
    ///
    /// This is appropriate in cases where it makes no sense to call the FFI function
    /// if you are going to throw away the output immediately.
    ///
    /// # Safety
    ///
    /// See [Self::from_ptr].
    pub(super) unsafe fn from_ptr_nonnull(ptr: *mut *mut T) -> Result<Self, NullPointer> {
        // Safety: We require that the pointer be valid for use with from_ptr.
        let r = unsafe { Self::from_ptr(ptr) };
        if r.0.is_none() {
            Err(NullPointer)
        } else {
            Ok(r)
        }
    }

    /// Consume this OutPtr and the provided value.
    ///
    /// If the OutPtr is null, `value` is discarded.  Otherwise it is written into the OutPtr.
    pub(super) fn write_value(self, value: T) {
        // Note that all the unsafety happened when we constructed a &mut from the pointer.
        //
        // Note also that this method consumes `self`.  That's because we want to avoid multiple
        // writes to the same OutPtr: If we did that, we would sometimes have to free a previous
        // value.
        if let Some(ptr) = self.0 {
            *ptr = Box::into_raw(Box::new(value));
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    unsafe fn outptr_user(ptr: *mut *mut i8, set_to_val: Option<i8>) {
        let ptr = unsafe { OutPtr::from_ptr(ptr) };

        if let Some(v) = set_to_val {
            ptr.write_value(v);
        }
    }

    #[test]
    fn outptr() {
        let mut ptr_to_int: *mut i8 = 7 as _; // This is a junk dangling pointer.  It will get overwritten.

        // Case 1: Don't set to anything.
        unsafe { outptr_user(&mut ptr_to_int as _, None) };
        assert!(ptr_to_int.is_null());

        // Cases 2, 3: Provide a null pointer for the output pointer.
        ptr_to_int = 7 as _; // make it junk again.
        unsafe { outptr_user(std::ptr::null_mut(), None) };
        assert_eq!(ptr_to_int, 7 as _); // we didn't pass this in, so it wasn't set.
        unsafe { outptr_user(std::ptr::null_mut(), Some(5)) };
        assert_eq!(ptr_to_int, 7 as _); // we didn't pass this in, so it wasn't set.

        // Case 4: Actually set something.
        unsafe { outptr_user(&mut ptr_to_int as _, Some(123)) };
        assert!(!ptr_to_int.is_null());
        let boxed = unsafe { Box::from_raw(ptr_to_int) };
        assert_eq!(*boxed, 123);
    }

    unsafe fn outptr_user_nn(ptr: *mut *mut i8, set_to_val: Option<i8>) -> Result<(), NullPointer> {
        let ptr = unsafe { OutPtr::from_ptr_nonnull(ptr) }?;

        if let Some(v) = set_to_val {
            ptr.write_value(v);
        }
        Ok(())
    }

    #[test]
    fn outptr_nonnull() {
        let mut ptr_to_int: *mut i8 = 7 as _; // This is a junk dangling pointer.  It will get overwritten.

        // Case 1: Don't set to anything.
        let r = unsafe { outptr_user_nn(&mut ptr_to_int as _, None) };
        assert!(r.is_ok());
        assert!(ptr_to_int.is_null());

        // Cases 2, 3: Provide a null pointer for the output pointer.
        ptr_to_int = 7 as _; // make it junk again.
        let r = unsafe { outptr_user_nn(std::ptr::null_mut(), None) };
        assert!(r.is_err());
        assert_eq!(ptr_to_int, 7 as _); // we didn't pass this in, so it wasn't set.
        let r = unsafe { outptr_user_nn(std::ptr::null_mut(), Some(5)) };
        assert!(r.is_err());
        assert_eq!(ptr_to_int, 7 as _); // we didn't pass this in, so it wasn't set.

        // Case 4: Actually set something.
        let r = unsafe { outptr_user_nn(&mut ptr_to_int as _, Some(123)) };
        assert!(r.is_ok());
        assert!(!ptr_to_int.is_null());
        let boxed = unsafe { Box::from_raw(ptr_to_int) };
        assert_eq!(*boxed, 123);
    }
}
