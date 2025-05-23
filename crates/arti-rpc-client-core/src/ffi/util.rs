//! Helpers for working with FFI.

use std::mem::MaybeUninit;

/// Helper for output parameters represented as `*mut T`.
///
/// This is for an API which, from a C POV, returns an output via a parameter of type
/// `Foo *foo_out` .  When an `OutPtr` is constructed, `foo_out` is necessarily non-null;
///
/// If `foo_out` is not NULL, then `*foo_out` is always initialized when an `OutPtr`
/// is constructed, so that even if the FFI code panics, the inner pointer will be initialized to
/// _something_.
pub(super) struct OutVal<'a, T>(&'a mut T);

/// Alias for an `OutVal` representing a `*mut *mut T`.
pub(super) type OutPtr<'a, T> = OutVal<'a, *mut T>;

impl<'a, T> OutVal<'a, T> {
    /// Construct `Option<Self>` from a possibly NULL pointer; initialize `*ptr` to `initial_value` if possible.
    ///
    /// # Safety
    ///
    /// The outer pointer, if set, must be valid, and must not alias any other pointers.
    ///
    /// See also the requirements on `pointer::as_mut()`.
    ///
    /// # No panics!
    ///
    /// This method can be invoked in cases where panicking is not allowed (such as
    /// in a FFI method, outside of `handle_errors()` or `catch_panic()`.)
    //
    // (I have tested this using the `no-panic` crate.  But `no-panic` is not suitable
    // for use in production, since it breaks when run in debug mode.)
    pub(super) unsafe fn from_opt_ptr(ptr: *mut T, initial_value: T) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            // TODO: Use `.as_mut_uninit` once it is stable.
            //
            // SAFETY: See documentation for [`<*mut *mut T>::as_uninit_mut`]
            // at https://doc.rust-lang.org/std/primitive.pointer.html#method.as_uninit_mut :
            // This is the same code.
            let ptr: &mut MaybeUninit<T> = unsafe { &mut *(ptr as *mut MaybeUninit<T>) };
            let ptr: &mut T = ptr.write(initial_value);
            Some(OutVal(ptr))
        }
    }

    /// Consume this `OutVal` and the provided value, writing the value into the outval.
    pub(super) fn write_value(self, value: T) {
        // Note that all the unsafety happened when we constructed a &mut from the pointer.
        //
        // Note also that this method consumes `self`.  That's because we want to avoid multiple
        // writes to the same OutVal: If we did that, we would sometimes have to free a previous
        // value.
        *self.0 = value;
    }
}

impl<'a, T> OutVal<'a, *mut T> {
    /// Consume this `OutPtr` and the provided value, writing the value into the outptr.
    pub(super) fn write_value_boxed(self, value: T) {
        self.write_value(Box::into_raw(Box::new(value)));
    }
}

/// Implement OptOutPtrExt and OptOutValExt.
///
/// This is a separate module so we can seal these traits.
mod out_ptr_ext {
    use super::OutVal;

    /// Trait to prevent implementation of OptOutPtrExt outside this module.
    trait Sealed {}

    /// Extension trait on `Option<OutPtr<T>>`
    #[allow(private_bounds)]
    pub(in crate::ffi) trait OptOutPtrExt<T>: Sealed {
        /// Consume this `Option<OutPtr<T>>` and the provided value.
        ///
        /// If this is Some, write the value into the outptr.
        ///
        /// Otherwise, discard the value.
        fn write_boxed_value_if_ptr_set(self, value: T);
    }
    /// Extension trait on `Option<OutVal<T>>`
    #[allow(private_bounds)]
    pub(in crate::ffi) trait OptOutValExt<T>: Sealed {
        /// Consume this `Option<OutVal<T>>` and the provided value.
        ///
        /// If this is Some, write the value into the outptr.
        ///
        /// Otherwise, discard the value.
        fn write_value_if_ptr_set(self, value: T);
    }
    impl<'a, T> Sealed for Option<OutVal<'a, T>> {}
    impl<'a, T> OptOutPtrExt<T> for Option<OutVal<'a, *mut T>> {
        fn write_boxed_value_if_ptr_set(self, value: T) {
            if let Some(outptr) = self {
                outptr.write_value_boxed(value);
            }
        }
    }
    impl<'a, T> OptOutValExt<T> for Option<OutVal<'a, T>> {
        fn write_value_if_ptr_set(self, value: T) {
            if let Some(outptr) = self {
                outptr.write_value(value);
            }
        }
    }
}
pub(super) use out_ptr_ext::{OptOutPtrExt, OptOutValExt};

/// Helper for output parameters represented as `*mut ArtiRpcRawSocket`.
///
/// Implements the case where these parameters take ownership the associated socket.
#[derive(derive_more::From)]
pub(super) struct OutSocketOwned<'a>(OutVal<'a, ArtiRpcRawSocket>);

#[cfg(not(windows))]
use std::os::fd::IntoRawFd as IntoRawSocketTrait;
#[cfg(windows)]
use std::os::windows::io::IntoRawSocket as IntoRawSocketTrait;

impl<'a> OutSocketOwned<'a> {
    /// Take ownership of the provided socket,
    /// consume it,
    /// and store its associated `ArtiRpcRawSocket` into `self`.
    pub(super) fn write_socket<T: IntoRawSocketTrait>(self, socket: T) {
        #[cfg(windows)]
        let sock = socket.into_raw_socket();

        #[cfg(not(windows))]
        let sock = socket.into_raw_fd();

        self.0.write_value(ArtiRpcRawSocket(sock));
    }
}

/// Implement the body of an FFI function.
///
/// This macro handles the calling convention of an FFI function.
/// Proper use of this macro will ensure that the FFI function behaves as documented,
/// as regards pointer handling, ownership, lifetimes, and error handling.
/// It also catches panics, making sure that we don't unwind into the FFI caller.
/// I.e. it ensures that correct callers will not experience UB.
///
/// This variant is for functions that
/// don't pass back an `ArtiRpcError` via an out parameter.
/// See [`ffi_body_with_err!`] for that.
///
/// This macro is meant to be invoked as follows:
///
/// ```ignore
///     ffi_body_raw!(
///         {
///             [CONVERSIONS]
///         } in {
///             [BODY]
///         } on invalid {
///             [VALUE_ON_BAD_INPUT]
///         }
///     )
/// ```
///
/// For example:
///
/// ```ignore
/// pub extern "C" fn arti_rpc_cook_meal(
///     recipe: *const Recipe,
///     special_ingredients: *const Ingredients,
///     n_guests: usize,
///     dietary_constraints: *const c_char,
///     food_out: *mut *mut DeliciousMeal,
/// ) -> usize {
///     ffi_body_raw!(
///         { // [CONVERSIONS]
///             let recipe: Option<&Recipe> [in_ptr_opt];
///             let ingredients: Option<&Ingredients> [in_ptr_opt];
///             let dietary_constraints: Option<&str> [in_str_opt];
///             let food_out: OutPtr<DeliciousMeal> [out_ptr_opt];
///         } in {
///             // [BODY]
///             let Some(recipe) = recipe else { return 0 };
///             let delicious_meal = prepare_meal(
///                 recipe, ingredients, dietary_constraints, n_guests
///             );
///             food_out.write_value_if_nonnull(delicious_meal);
///             n_guests
///         } on invalid {
///             // [VALUE_ON_BAD_INPUT]
///             0
///         }
///     )
/// }
/// ```
///
/// The first part (`CONVERSIONS`) defines a set of conversions to be done on the function inputs.
/// These are documented below.
/// Each conversion performs an unsafe operation,
/// making certain assumptions about an input variable,
/// in order to produce an output of the specified type.
/// Conversions can reject input values.
/// If they do, the function will return;
/// see discussion of `[VALUE_ON_BAD_INPUT]`
///
/// Pointer parameters to the outer function *must not be ignored*.
/// Every raw pointer parameter must be processed by this macro.
/// (For raw pointer arguments that are not,
/// no guarantees are made by the macro,
/// and the overall function will probably be unsound.
/// There is no checking that every pointer parameter is properly used,
/// other than Rust's usual detection of unused variables.)
///
/// The second part (`BODY`) is the body of the function.
/// The body is *outside* `unsafe`, and
/// it should generally be possible to write this body without using unsafe code.
/// The result of this block is the returned value of the function.
///
/// The third part (`VALUE_ON_BAD_INPUT`) is an expression to be returned
/// as the result of the function if any input pointer has a rejected value.
/// You may omit the entire `on invalid { ... }` part of the macro's input
/// when all of the conversions are infallible.
/// (This is checked statically.)
///
/// ## Supported conversions
///
/// All conversions take the following format:
///
/// `let NAME : TYPE [METHOD] ;`
///
/// The `NAME` must match one of the inputs to the function.
///
/// The `TYPE` must match the actual type that the input will be converted to.
/// (These types are generally easy to use ergonomically from safe rust.)
///
/// The `METHOD` is an identifier explaining how the input is to be converted.
///
/// The following methods are recognized:
///
/// | method               | input type      | converted to       | can reject input? |
/// |----------------------|-----------------|--------------------|-------------------|
/// | `in_ptr_opt`         | `*const T`      | `Option<&T>`       | N                 |
/// | `in_str_opt`         | `*const c_char` | `Option<&str>`     | Y                 |
/// | `in_ptr_consume_opt` | `*mut T`        | `Option<Box<T>>`   | N                 |
/// | `out_ptr_opt`        | `*mut *mut T`   | `Option<OutPtr<T>>`| N                 |
/// | `out_val_opt`        | `*mut T`        | `Option<OutVal<T>>`| N                 |
/// | `out_socket_owned_opt` | *mut ArtiRpcRawSocket` | `Option<OutSocketOwned>`| N   |
/// | `in_mut_ptr_opt`     | (NO!)           | (Do not add!)      | (NO!)             |
///
/// > (Note: Other conversion methods are logically possible, but have not been added yet,
/// > since they would not yet be used in this crate.)
/// >
/// > (Note: There is **deliberately** no in_mut_ptr_opt, or anything similar:
/// > while we're okay with returning objects via `OutPtr`/`OutVal`,
/// > we do not want to expose APIs that take a non-sharable object via `&mut T``,
/// > since other languages have no way to enforce Rust's requirement
/// > that no other `&mut` references exits.)
///
/// ## Safety
///
/// The `in_ptr_opt` method
/// has the safety requirements of
/// [`<*const T>::as_ref`](https://doc.rust-lang.org/std/primitive.pointer.html#method.as_ref).
/// Informally, this means:
/// * If the pointer is not null, it must point
///   to a valid aligned dereferenceable instance of `T`.
/// * The underlying `T` must not be freed or modified for so long as the function is running.
///
/// The `in_str_opt` method, when its input is non-NULL,
/// has the safety requirements of [`CStr::from_ptr`](std::ffi::CStr::from_ptr).
/// Informally, this means:
///  * If the pointer is not null, it must point to a nul-terminated string.
///  * The string must not be freed or modified for so long as the function is running.
///
/// Additionally, the `[in_str_opt]` method
/// will detect invalid any string that is not UTF-8.
///
/// The `in_ptr_consume_opt` method, when its input is non-NULL,
/// has the safety requirements of [`Box::from_raw`].
/// Informally, this is satisfied when:
///  * If the pointer is not null, it should be
///    the result of an earlier a call to `Box<T>::into_raw`.
///    (Note that using either `out_ptr_*` method
///    will output pointers that can later be consumed in this way.)
///
/// The `out_val_opt` method
/// has the safety requirements of
/// [`<*mut T>::as_uninit_mut`](https://doc.rust-lang.org/std/primitive.pointer.html#method.as_uninit_mut).
/// Informally, this means:
///   * If the pointer (call it "out") is non-NULL, then `*out` must point to aligned
///     "dereferenceable" (q.v.) memory holding a possibly uninitialized "T".
///
/// The `out_ptr_opt` method
/// has the safety requirements of
/// [`<*mut *mut T>::as_uninit_mut`](https://doc.rust-lang.org/std/primitive.pointer.html#method.as_uninit_mut).
/// Informally, this means:
///   * If the pointer (call it "out") is non-NULL, then `*out` must point to aligned
///     "dereferenceable" (q.v.) memory holding a possibly uninitialized "*mut T".
///
/// (Note that immediately upon conversion, if `out` is non-NULL,
/// `*out` is set to NULL.  See documentation for `OptPtr`.)
///
/// The return value of `BODY` becomes the return value of the C FFI function.
/// It is the macro user's responsibility to ensure
/// that it conforms to the published API.
/// For example, if the return value is a raw pointer,
/// the macro user must ensure it's suitably dereferenceable,
/// that its lifetime is documented,
/// and only null when the API says that's allowed.
//
// Design notes:
// - I am keeping the conversions separate from the body below, since we don't want to catch
//   InvalidInput from the body.
// - The "on invalid" value must be specified explicitly if it can happen,
//   since in general we should force the caller to think about it.
//   Getting a 0 or -1 wrong here can have nasty results.
// - The conversion syntax deliberately includes the type of the converted argument,
//   on the theory that it makes the functions more readable.
// - The conversion code deliberately shadows the original parameter with the
//   converted parameter.
macro_rules! ffi_body_raw {
    {
        {
            $(
                let $name:ident : $type:ty [$how:ident]
            );*
            $(;)?
        } in {
            $($body:tt)+
        } on invalid {
            $err:expr
        }
    } => {
        crate::ffi::err::abort_on_panic(|| {
            // run conversions and check for invalid input exceptions.
            crate::ffi::util::ffi_initialize!{
                {
                    $( let $name : $type [$how]; )*
                } else with _ignore_err : crate::ffi::err::InvalidInput {
                    #[allow(clippy::unused_unit)]
                    return $err;
                }
            };

            $($body)+

            },
        )
    };

    {
        {
            $(
                let $name:ident : $type:ty [$how:ident]
            );*
            $(;)?
        } in {
            $($body:tt)+
        }
    } => {
        crate::ffi::err::abort_on_panic(|| {
            // run conversions and check for invalid input exceptions.
            crate::ffi::util::ffi_initialize!{
                {
                    $( let $name : $type [$how]; )*
                } else with impossible_error : void::Void {
                    void::unreachable(impossible_error);
                }
            };

            $($body)+

            },
        )
    };

}
pub(super) use ffi_body_raw;

/// Implement the body of an FFI function that returns an ArtiRpcStatus.
///
/// This macro is meant to be invoked as follows:
/// ```text
/// ffi_body_with_err!(
///         {
///             [CONVERSIONS]
///             err [ERRNAME] : OutPtr<ArtiRpcError>;
///         } in {
///             [BODY]
///         }
/// })```
///
/// For example:
///
/// ```ignore
/// pub extern "C" fn arti_rpc_wombat_feed(
///     wombat: *const Wombat,
///     wombat_chow: *const Meal,
///     error_out: *mut *mut ArtiRpcError
/// ) -> ArtiRpcStatus {
///     ffi_body_with_err!(
///         {
///             let wombat: Option<&Wombat> [in_ptr_opt];
///             let wombat_chow: Option<&Meal> [in_ptr_opt];
///             err error_out: Option<OutPtr<ArtiRpcError>>;
///         } in {
///             let wombat = wombat.ok_or(InvalidInput::NullPointer)?
///             let wombat_chow = wombat_chow.ok_or(InvalidInput::NullPointer)?
///             wombat.please_enjoy(wombat_chow)?;
///         }
///     )
/// }
/// ```
///
/// The resulting function has the same kinds
/// of conversions as would [`ffi_body_raw!`].
///
/// The differences are:
///   * Instead of returning a value, the body can only give errors with `?`.
///   * The function must return ArtiRpcStatus.
///   * Any errors that occur during the conversions or the body
///     are converted into an ArtiRpcError,
///     and given to the user via `error_out` if it is non-NULL.
///     A corresponding ArtiRpcStatus is returned.
///
/// ## Safety
///
/// The safety requirements are the same as for `ffi_body_raw`, except that:
///
/// The safety requirements for the `err` conversion
/// are the same as those for `out_ptr_opt` (q.v.).
///
/// `ffi_body_with_err` then additionally ensures conformance of
/// the return value with the API's error handling rules.
macro_rules! ffi_body_with_err {
    {
        {
            $(
                let $name:ident : $type:ty [$how:ident];
            )*
            err $err_out:ident : $err_type:ty $(;)?
        } in {
            $($body:tt)+
        }
    } => {{
        use void::ResultVoidExt as _;
        let $err_out: $err_type =
            unsafe { crate::ffi::util::arg_conversion::out_ptr_opt($err_out) }
            .void_unwrap();

        crate::ffi::err::handle_errors($err_out,
            || {
                crate::ffi::util::ffi_initialize!{
                    {
                        $( let $name : $type [$how]; )*
                    } else with err: crate::ffi::err::ArtiRpcError {
                        return Err(crate::ffi::err::ArtiRpcError::from(err));
                    }
                };

                let () = { $($body)+ };

                Ok(())
            }
        )
    }}
}
pub(super) use ffi_body_with_err;

/// Implement a set of conversions, trying each one.
///
/// (It's important that this cannot exit early,
/// since some conversions have side effects: notably, the ones that create an OutPtr
/// can initialize that pointer to NULL, and we want to do that unconditionally.
///
/// If any conversion fails, run `return ($on_invalid)(error)`
/// _after_ every conversion has succeeded or failed.
///
/// The syntax is:
///
/// ```ignore
/// ffi_initialize!{
///    { [CONVERSIONS] }
///    else with [ERR_IDENT] { [ERR_BODY] }
/// }
/// ```
///
/// The `[CONVERSIONS]` have the same syntax and behavior as in [`ffi_body_raw!`].
/// After every conversion has been tried, if one or more of them failed,
/// then the `[ERR_BODY]` code is run,
/// with `[ERR_IDENT]` bound to an instance of `InvalidInput`.
macro_rules! ffi_initialize {
    {
        {
            $( let $name:ident : $type:ty [$how:ident] ; )*
        } else with $err_id:ident: $err_type:ty {
            $($on_invalid:tt)*
        }
    } => {
        // General approach
        //
        // First, we process each `$name` into `Result<$type>`, without doing any early exits.
        // This ensures that we process every `$name`, even if some of the processing fails.
        //
        // Then we convert each `Result<X>` into just `X`
        // (with an IEFE that returns a `Result<(X,...)>` - one `Result` with a big tuple.
        // We rebinding the `$name`'s to the values from the tuple.
        #[allow(unused_parens)]
        let ($($name,)*) : ($($type,)*) = {
            $(
                let $name : Result<$type, _>
                   = unsafe { crate::ffi::util::arg_conversion::$how($name) };
            )*

            #[allow(clippy::needless_question_mark)]
            // Note that the question marks here exit from _this_ closure.
            match (|| -> Result<_,$err_type> {
                Ok(($($name?,)*))
            })() {
                Ok(v) => v,
                Err($err_id) => {
                    $($on_invalid)*
                }
            }
        };
    };
}

/// Functions to implement argument conversion.
///
/// Each of these functions corresponds to a conversion mode used in `ffi_initialize!`.
///
/// Every function has all of these properties:
///
/// - It returns  `Err(InvalidInput)` if the conversion fails,
///   and `Ok($ty)` if the conversion succeeds.
///   (Infallible conversions always return `Ok`.)
///
/// Nothing outside of the `ffi_initialize!` macro should actually invoke these functions!
#[allow(clippy::unnecessary_wraps)]
pub(super) mod arg_conversion {
    use super::{OutPtr, OutSocketOwned, OutVal};
    use crate::ffi::{err::InvalidInput, ArtiRpcRawSocket};
    use std::ffi::{c_char, CStr};
    use void::Void;

    /// Try to convert a const pointer to an optional reference.
    ///
    /// A null pointer is allowed, and converted to `None`.
    ///
    /// # Safety
    ///
    /// As for [`<*const T>::as_ref`](https://doc.rust-lang.org/std/primitive.pointer.html#method.as_ref).
    pub(in crate::ffi) unsafe fn in_ptr_opt<'a, T>(input: *const T) -> Result<Option<&'a T>, Void> {
        Ok(unsafe { input.as_ref() })
    }

    /// Try to convert a `const char *` to a `&str`.
    ///
    /// A null pointer is allowed, and converted to `None`.
    /// Non-UTF-8 inputs will give an error.
    ///
    /// # Safety
    ///
    /// As for [`CStr::from_ptr`](std::ffi::CStr::from_ptr).
    pub(in crate::ffi) unsafe fn in_str_opt<'a>(
        input: *const c_char,
    ) -> Result<Option<&'a str>, InvalidInput> {
        if input.is_null() {
            return Ok(None);
        }

        // Safety: We require that the safety properties of CStr::from_ptr hold.
        unsafe { CStr::from_ptr(input) }
            .to_str()
            .map(Some)
            .map_err(|_| InvalidInput::BadUtf8)
    }

    /// Try to convert a mutable pointer to a `Option<Box<T>>`.
    ///
    /// A null pointer is allowed, and converted to `None`.
    ///
    /// # Safety
    ///
    /// As for  [`Box::from_raw`].
    pub(in crate::ffi) unsafe fn in_ptr_consume_opt<T>(
        input: *mut T,
    ) -> Result<Option<Box<T>>, Void> {
        Ok(if input.is_null() {
            None
        } else {
            Some(unsafe { Box::from_raw(input) })
        })
    }

    /// Try to convert a mutable pointer-to-pointer into an `Option<OutPtr<T>>`.
    ///
    /// A null pointer is allowed, and converted into None.
    ///
    /// Whatever the target of the original pointer (`input: *mut *mut T`), if `input` is non-null.
    /// then `*input` is initialized to NULL.
    ///
    /// It is safe for `*input` to be uninitialized.
    ///
    /// # Safety
    ///
    /// As for
    /// [`<*mut *mut T>::as_uninit_mut`](https://doc.rust-lang.org/std/primitive.pointer.html#method.as_uninit_mut).
    pub(in crate::ffi) unsafe fn out_ptr_opt<'a, T>(
        input: *mut *mut T,
    ) -> Result<Option<OutPtr<'a, T>>, Void> {
        Ok(unsafe { crate::ffi::util::OutPtr::from_opt_ptr(input, std::ptr::null_mut()) })
    }

    /// Try to convert a mutable pointer-to-value into an `Option<OutVal<T>>`.
    ///
    /// A null pointer is allowed, and converted into None.
    ///
    /// Whatever the target of the original pointer (`input: *mut T`), if `input` is non-null.
    /// then `*input` is initialized to T::default().
    ///
    /// It is safe for `*input` to be uninitialized.
    ///
    /// # Safety
    ///
    /// As for
    /// [`<*mut T>::as_uninit_mut`](https://doc.rust-lang.org/std/primitive.pointer.html#method.as_uninit_mut).
    pub(in crate::ffi) unsafe fn out_val_opt<'a, T>(
        input: *mut T,
    ) -> Result<Option<OutVal<'a, T>>, Void>
    where
        T: Default,
    {
        Ok(unsafe { crate::ffi::util::OutVal::from_opt_ptr(input, T::default()) })
    }

    /// Try to convert a mutable pointer-to-socket into an `Option<OutSocketOwned>`.
    ///
    /// A null pointer is allowed, and converted into None.
    ///
    /// Whatever the target of the original pointer, if `input` is non-null,
    /// then `*input` is initialized to -1 or `INVALID_SOCKET`.
    ///
    /// It is safe for `*input` to be uninitialized.
    ///
    /// # Safety
    ///
    /// As for
    /// [`<* mut ArtiRpcRawSocket>::as_uninit_mut`](https://doc.rust-lang.org/std/primitive.pointer.html#method.as_uninit_mut).
    ///
    /// Additionally, if the resulting `ArtiRpcRawSocket` is used to send an fd/`SOCKET` to the
    /// application, then the application becomes the owner of that socket, and is responsible for
    /// making sure it is eventually closed.
    pub(in crate::ffi) unsafe fn out_socket_owned_opt<'a>(
        input: *mut ArtiRpcRawSocket,
    ) -> Result<Option<OutSocketOwned<'a>>, Void> {
        let optval: Option<OutVal<'a, ArtiRpcRawSocket>> =
            unsafe { crate::ffi::util::OutVal::from_opt_ptr(input, ArtiRpcRawSocket::default()) };

        Ok(optval.map(OutSocketOwned::from))
    }
}

pub(super) use ffi_initialize;

use super::ArtiRpcRawSocket;

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
        let ptr = unsafe { OutPtr::from_opt_ptr(ptr, std::ptr::null_mut()) };

        if let Some(v) = set_to_val {
            ptr.write_boxed_value_if_ptr_set(v);
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
}
