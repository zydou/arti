//! Exposed C APIs for arti-rpc-client-core.
//!
//! See top-level documentation in header file for C conventions that affect the safety of these functions.
//! (These include things like "all input pointers must be valid" and so on.)

pub mod err;
mod util;

use err::{ArtiRpcError, InvalidInput};
use std::ffi::{c_char, c_int};
use util::{ffi_body_raw, ffi_body_with_err, OptOutPtrExt as _, OptOutValExt, OutPtr, OutVal};

use crate::{
    conn::{AnyResponse, RequestHandle},
    util::Utf8CString,
    RpcConnBuilder,
};

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

/// A handle to an in-progress RPC request.
///
/// This handle must eventually be freed with `arti_rpc_handle_free`.
///
/// You can wait for the next message with `arti_rpc_handle_wait`.
pub type ArtiRpcHandle = RequestHandle;

/// The type of a message returned by an RPC request.
pub type ArtiRpcResponseType = c_int;

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

            rpc_conn_out.write_boxed_value_if_ptr_set(conn);
        }
    )
}

/// Given a pointer to an RPC connection, return the object ID for its negotiated session.
///
/// (The session was negotiated as part of establishing the connection.
/// Its object ID is necessary to invoke most other functionality on Arti.)
///
/// The caller should be prepared for a possible NULL return, in case somehow
/// no session was negotiated.
///
/// # Ownership
///
/// The resulting string is a reference to part of the `ArtiRpcConn`.
/// It lives for no longer than the underlying `ArtiRpcConn` object.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_conn_get_session_id(
    rpc_conn: *const ArtiRpcConn,
) -> *const c_char {
    ffi_body_raw! {
        {
            let rpc_conn: Option<&ArtiRpcConn> [in_ptr_opt];
        } in {
            rpc_conn.and_then(crate::RpcConn::session)
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null())
            // Safety: returned pointer is null, or semantically borrowed from `rpc_conn`.
            // It is only null if `rpc_conn` was null or its session was null.
            // The caller is not allowed to modify it.
        }
    }
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
///
/// The caller is responsible for making sure that `*response_out`, if set, is eventually freed.
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
            response_out.write_boxed_value_if_ptr_set(Utf8CString::from(success));
        }
    )
}

/// Send an RPC request over `rpc_conn`, and return a handle that can wait for a successful response.
///
/// The message `msg` should be a valid RPC request in JSON format.
/// If you omit its `id` field, one will be generated: this is typically the best way to use this function.
///
/// On success, return `ARTI_RPC_STATUS_SUCCESS` and set `*handle_out` to a newly allocated `ArtiRpcHandle`.
///
/// Otherwise return some other status code,  set `*handle_out` to NULL,
/// and set `*error_out` (if provided) to a newly allocated error object.
///
/// (If `handle_out` is set to NULL, the request will not be sent, and an error will be returned.)
///
/// # Ownership
///
/// The caller is responsible for making sure that `*error_out`, if set, is eventually freed.
///
/// The caller is responsible for making sure that `*handle_out`, if set, is eventually freed.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_conn_execute_with_handle(
    rpc_conn: *const ArtiRpcConn,
    msg: *const c_char,
    handle_out: *mut *mut ArtiRpcHandle,
    error_out: *mut *mut ArtiRpcError,
) -> ArtiRpcStatus {
    ffi_body_with_err!(
        {
            let rpc_conn: Option<&ArtiRpcConn> [in_ptr_opt];
            let msg: Option<&str> [in_str_opt];
            let handle_out: Option<OutPtr<ArtiRpcHandle>> [out_ptr_opt];
            err error_out: Option<OutPtr<ArtiRpcError>>;
        } in {
            let rpc_conn = rpc_conn.ok_or(InvalidInput::NullPointer)?;
            let msg = msg.ok_or(InvalidInput::NullPointer)?;
            let handle_out = handle_out.ok_or(InvalidInput::NullPointer)?;

            let handle = rpc_conn.execute_with_handle(msg)?;
            handle_out.write_value_boxed(handle);
        }
    )
}

/// A constant indicating that a message is a final result.
///
/// After a result has been received, a handle will not return any more responses,
/// and should be freed.
pub const ARTI_RPC_RESPONSE_TYPE_RESULT: ArtiRpcResponseType = 1;
/// A constant indicating that a message is a non-final update.
///
/// After an update has been received, the handle may return additional responses.
pub const ARTI_RPC_RESPONSE_TYPE_UPDATE: ArtiRpcResponseType = 2;
/// A constant indicating that a message is a final error.
///
/// After an error has been received, a handle will not return any more responses,
/// and should be freed.
pub const ARTI_RPC_RESPONSE_TYPE_ERROR: ArtiRpcResponseType = 3;

impl AnyResponse {
    /// Return an appropriate `ARTI_RPC_RESPONSE_TYPE_*` for this response.
    fn response_type(&self) -> ArtiRpcResponseType {
        match self {
            Self::Success(_) => ARTI_RPC_RESPONSE_TYPE_RESULT,
            Self::Update(_) => ARTI_RPC_RESPONSE_TYPE_UPDATE,
            Self::Error(_) => ARTI_RPC_RESPONSE_TYPE_ERROR,
        }
    }
}

/// Wait until some response arrives on an arti_rpc_handle, or until an error occurs.
///
/// On success, return `ARTI_RPC_STATUS_SUCCESS`; set `*response_out`, if present, to a
/// newly allocated string, and set `*response_type_out`, to the type of the response.
/// (The type will be `ARTI_RPC_RESPONSE_TYPE_RESULT` if the response is a final result,
/// or `ARTI_RPC_RESPONSE_TYPE_ERROR` if the response is a final error,
/// or `ARTI_RPC_RESPONSE_TYPE_UPDATE` if the response is a non-final update.)
///
/// Otherwise return some other status code, set `*response_out` to NULL,
/// set `*response_type_out` to zero,
/// and set `*error_out` (if provided) to a newly allocated error object.
///
/// Note that receiving an error reply from Arti is _not_ treated as an error in this function.
/// That is to say, if Arti sends back an error, this function will return `ARTI_SUCCESS`,
/// and deliver the error from Arti in `*response_out`, setting `*response_type_out` to
/// `ARTI_RPC_RESPONSE_TYPE_ERROR`.
///
/// It is safe to call this function on the same handle from multiple threads at once.
/// If you do, each response will be sent to exactly one thread.
/// It is unspecified which thread will receive which response or which error.
///
/// # Ownership
///
/// The caller is responsible for making sure that `*error_out`, if set, is eventually freed.
///
/// The caller is responsible for making sure that `*response_out`, if set, is eventually freed.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_handle_wait(
    handle: *const ArtiRpcHandle,
    response_out: *mut *mut ArtiRpcStr,
    response_type_out: *mut ArtiRpcResponseType,
    error_out: *mut *mut ArtiRpcError,
) -> ArtiRpcStatus {
    ffi_body_with_err! {
        {
            let handle: Option<&ArtiRpcHandle> [in_ptr_opt];
            let response_out: Option<OutPtr<ArtiRpcStr>> [out_ptr_opt];
            let response_type_out: Option<OutVal<ArtiRpcResponseType>> [out_val_opt];
            err error_out: Option<OutPtr<ArtiRpcError>>;
        } in {
            let handle = handle.ok_or(InvalidInput::NullPointer)?;

            let response = handle.wait_with_updates()?;

            let rtype = response.response_type();
            response_type_out.write_value_if_ptr_set(rtype);
            response_out.write_boxed_value_if_ptr_set(response.into_string());
        }
    }
}

/// Release storage held by an `ArtiRpcHandle`.
///
/// NOTE, TODO: This does not cancel the request, but that is not guaranteed.
/// Once we implement cancellation, this may behave differently.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn arti_rpc_handle_free(handle: *mut ArtiRpcHandle) {
    ffi_body_raw!(
        {
            let handle: Option<Box<ArtiRpcHandle>> [in_ptr_consume_opt];
        } in {
            drop(handle);
            // Safety: Return value is (); trivially safe.
            ()
        }
    );
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
            ()
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
        } in {
            drop(rpc_conn);
            // Safety: Return value is (); trivially safe.
            ()

        }
    );
}
