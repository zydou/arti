//! Exposed C APIs for arti-rpc-client-core.
//!
//! See top-level documentation in header file for C conventions that affect the safety of these functions.
//! (These include things like "all input pointers must be valid" and so on.)

pub mod err;
mod util;

use err::{ArtiRpcError, InvalidInput};
use std::ffi::c_char;
use util::{ffi_body_raw, ffi_body_with_err, OptOutPtrExt as _, OutPtr};

use crate::{util::Utf8CString, RpcConnBuilder};

/// A status code returned by an Arti RPC function.
///
/// On success, a function will return `ARTI_SUCCESS (0)`.
/// On failure, a function will return some other status code.
pub type ArtiRpcStatus = u32;

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
pub type ArtiRpcStr = Utf8CString;

/// Try to open a new connection to an Arti instance.
///
/// The location of the instance and the method to connect to it are described in
/// `connection_string`.
///
/// (TODO RPC: Document the format of this string better!)
///
/// On success, return `ARTI_RPC_STATUS_SUCCESS` and set `*rpc_conn_out` to a new ArtiRpcConn.
/// Otherwise return some other status code, set `*rpc_conn_out` to NULL, and set
/// `*error_out` (if provided) to a newly allocated error object.
///
///
/// # Ownership
///
/// The caller is responsible for making sure that `*rpc_conn_out` and `*error_out`,
/// if set, are eventually freed.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_connect(
    connection_string: *const c_char,
    rpc_conn_out: *mut *mut ArtiRpcConn,
    error_out: *mut *mut ArtiRpcError,
) -> ArtiRpcStatus {
    ffi_body_with_err!(
        {
            let connection_string: Option<&str> [in_str_opt];
            let rpc_conn_out: Option<OutPtr<ArtiRpcConn>> [out_ptr_opt];
            err error_out : Option<OutPtr<ArtiRpcError>>;
        } in {
            let connection_string = connection_string
                .ok_or(InvalidInput::NullPointer)?;

            let builder = RpcConnBuilder::from_connect_string(connection_string)?;

            let conn = builder.connect()?;

            rpc_conn_out.write_value_if_ptr_set(conn);
        }
    )
}

/// Run an RPC request over `rpc_conn` and wait for a successful response.
///
/// The message `msg` should be a valid RPC request in JSON format.
/// If you omit its `id` field, one will be generated: this is typically the best way to use this function.
///
/// On success, return `ARTI_RPC_STATUS_SUCCESS` and set `*response_out` to a newly allocated string
/// containing the JSON response to your request (including `id` and `response` fields).
///
/// Otherwise return some other status code,  set `*response_out` to NULL,
/// and set `*error_out` (if provided) to a newly allocated error object.
///
/// (If response_out is set to NULL, then any successful response will be ignored.)
///
/// # Ownership
///
/// The caller is responsible for making sure that `*error_out`, if set, is eventually freed.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_conn_execute(
    rpc_conn: *const ArtiRpcConn,
    msg: *const c_char,
    response_out: *mut *mut ArtiRpcStr,
    error_out: *mut *mut ArtiRpcError,
) -> ArtiRpcStatus {
    ffi_body_with_err!(
        {
            let rpc_conn: Option<&ArtiRpcConn> [in_ptr_opt];
            let msg: Option<&str> [in_str_opt];
            let response_out: Option<OutPtr<ArtiRpcStr>> [out_ptr_opt];
            err error_out: Option<OutPtr<ArtiRpcError>>;
        } in {
            let rpc_conn = rpc_conn.ok_or(InvalidInput::NullPointer)?;
            let msg = msg.ok_or(InvalidInput::NullPointer)?;

            let success = rpc_conn.execute(msg)??;
            response_out.write_value_if_ptr_set(Utf8CString::from(success));
        }
    )
}

/// Free a string returned by the Arti RPC API.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_str_free(string: *mut ArtiRpcStr) {
    ffi_body_raw!(
        {
            let string: Option<Box<ArtiRpcStr>> [in_ptr_consume_opt];
        } in {
            drop(string);
            // Safety: Return value is (); trivially safe.
        }
    );
}

/// Return a const pointer to the underlying nul-terminated string from an `ArtiRpcStr`.
///
/// The resulting string is guaranteed to be valid UTF-8.
///
/// (Returns NULL if the input is NULL.)
///
/// # Correctness requirements
///
/// The resulting string pointer is valid only for as long as the input `string` is not freed.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_str_get(string: *const ArtiRpcStr) -> *const c_char {
    ffi_body_raw!(
        {
            let string: Option<&ArtiRpcStr> [in_ptr_opt];
        } in {
            // Safety: returned pointer is null, or semantically borrowed from `string`.
            // It is only null if `string` was null.
            // The caller is not allowed to modify it.
            match string {
                Some(s) => s.as_ptr(),
                None => std::ptr::null(),
            }

        }
    )
}

/// Close and free an open Arti RPC connection.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_conn_free(rpc_conn: *mut ArtiRpcConn) {
    ffi_body_raw!(
        {
            let rpc_conn: Option<Box<ArtiRpcConn>> [in_ptr_consume_opt];
            // Safety: Return value is (); trivially safe.
        } in {
            drop(rpc_conn);
        }
    );
}
