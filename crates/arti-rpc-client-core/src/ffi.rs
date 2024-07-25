//! Exposed C APIs for arti-rpc-client-core.
//!
//! See top-level documentation in header file for C conventions that affect the safety of these functions.
//! (These include things like "all input pointers must be valid" and so on.)

pub mod err;
mod util;

use err::{catch_panic, handle_errors, ArtiError, FfiStatus};
use std::ffi::c_char;
use util::{ptr_as_ref, OutPtr};

use crate::{util::Utf8CStr, RpcConnBuilder};

/// A status code returned by an Arti RPC function.
///
/// On success, a function will return `ARTI_SUCCESS (0)`.
/// On failure, a function will return some other status code.
pub type ArtiStatus = u32;

/// An open connection to Arti over an a RPC protocol.
///
/// This is a thread-safe type: you may safely use it from multiple threads at once.
///
/// Once you are no longer going to use this connection at all, you must free
/// it with [`arti_rpc_conn_free`]
pub type ArtiRpcConn = crate::RpcConn;

/// An owned string, returned by this library.
///
/// This string must be released with `arti_rpc_str_free`.
/// You can inspect it with `arti_rpc_str_get`, but you may not modify it.
/// The string is guaranteed to be UTF-8 and NUL-terminated.
pub type ArtiRpcStr = Utf8CStr;

/// Try to open a new connection to an Arti instance.
///
/// The location of the instance and the method to connect to it are described in
/// `connection_string`.
///
/// On success, return `ARTI_STATUS_SUCCESS` and set `*rpc_conn_out` to a new ArtiRpcConn.
/// Otherwise return some other status code, set `*rpc_conn_out` to NULL, and set
/// `*error_out` (if provided) to a newly allocated error object.
///
/// # Safety
///
/// Standard safety warnings apply; see library header.
#[no_mangle]
pub unsafe extern "C" fn arti_connect(
    connection_string: *const c_char,
    rpc_conn_out: *mut *mut ArtiRpcConn,
    error_out: *mut *mut ArtiError,
) -> ArtiStatus {
    // Safety: we globally require that error_out is a valid pointer.
    let err_out = unsafe { OutPtr::from_opt_ptr(error_out) };

    handle_errors(err_out, || {
        // Safety: We globally require that `rpc_conn_out` is a valid pointer.
        let rpc_conn_out = unsafe { OutPtr::from_ptr_nonnull(rpc_conn_out) }?;

        // Safety: We globally require that all strings are valid according to CStr::from_ptr.
        let s = unsafe { util::ptr_to_str(connection_string) }?;
        let builder = RpcConnBuilder::from_connect_string(s)?;

        let conn = builder.connect()?;

        rpc_conn_out.write_value_if_nonnull(conn);

        Ok(())
    })
}

/// Run an RPC request over `rpc_conn` and wait for a successful response.
///
/// The message `msg` should be a valid RPC request in JSON format.
/// If you omit its `id` field, one will be generated: this is typically the best way to use this function.
///
/// On success, return `ARTI_SUCCESS` and set `*response_out` to a newly allocated string
/// containing the Json response to your request (including `id` and `response` fields).
///
/// Otherwise return some other status code,  set `*response_out` to NULL,
/// and set `*error_out` (if provided) to a newly allocated error object.
///
/// (If response_out is set to NULL, then any successful response will be ignored.)
///
/// # Safety
///
/// The caller must not modify the length of `*response_out`.
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_execute(
    rpc_conn: *const ArtiRpcConn,
    msg: *const c_char,
    response_out: *mut *mut ArtiRpcStr,
    error_out: *mut *mut ArtiError,
) -> ArtiStatus {
    // Safety: we globally require that error_out is a valid pointer.
    let err_out = unsafe { OutPtr::from_opt_ptr(error_out) };

    handle_errors(err_out, || {
        // Safety: we require that rpc_conn is a valid pointer.
        let rpc_conn = unsafe { ptr_as_ref(rpc_conn) }?;
        // Safety: we require that response_out is a valid pointer.
        let response_out = unsafe { OutPtr::from_opt_ptr(response_out) };

        // Safety: We globally require that the constraints of CStr::from_ptr apply.
        let msg = unsafe { util::ptr_to_str(msg) }?;

        let success = rpc_conn.execute(msg)??;

        response_out.write_value_if_nonnull(Utf8CStr::from(success));

        Ok(())
    })
}

/// Free a string returned by the Arti RPC API.
///
/// # Safety
///
/// The string must not have been modified since it was returned.
///
/// After you have called this function, it is not safe to use the provided pointer from any thread.
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_str_free(string: *mut ArtiRpcStr) {
    catch_panic(
        || {
            if !string.is_null() {
                // Safety: We require that `string` is a pointer returned by a function in our API.
                //
                // The functions in this API only return owned strings via CString::into_raw.
                let owned = unsafe { Box::from_raw(string) };
                drop(owned);
            }
        },
        || {},
    );
}

/// Return a const pointer to the underlying nul-terminated string from an `ArtiRpcStr`.
///
/// The resulting string is guaranteed to be valid UTF-8.
///
/// (Returns NULL if the input is NULL.)
///
/// # Safety
///
/// Standard safety warnings apply; see library header.
///
/// The resulting string is valid only for as long as the input `string` is not freed.
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_str_get(string: *const ArtiRpcStr) -> *const c_char {
    let Ok(str) = (unsafe { ptr_as_ref(string) }) else {
        return std::ptr::null();
    };

    str.as_ptr()
}

/// Close and free an open Arti RPC connection.
///
/// # Safety
///
/// After you have called this function, it is not safe to use the provided pointer from any thread.
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_conn_free(rpc_conn: *mut ArtiRpcConn) {
    catch_panic(
        || {
            if !rpc_conn.is_null() {
                // Safety: We require that this input to this function be a valid pointer
                // returned from this library, which uses Box::into_raw.
                let owned = unsafe { Box::from_raw(rpc_conn) };
                drop(owned);
            }
        },
        || {},
    );
}
