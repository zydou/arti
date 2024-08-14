/**
 * # Arti RPC core library header.
 *
 * (TODO RPC: This is still a work in progress; please don't rely on it
 * being the final API.)
 *
 * ## What this library does
 *
 * The Arti RPC system works by establishing connections to an Arti instance,
 * and then exchanging requests and replies in a format inspired by
 * JSON-RPC.  This library takes care of the work of connecting to an Arti
 * instance, authenticating, validating outgoing JSON requests, and matching
 * their corresponding JSON responses as they arrive.
 *
 * This library _does not_ do the work of creating well-formed requests,
 * or interpreting the responses.
 *
 * (Note: Despite this library being exposed via a set of C functions,
 * we don't actually expect you to use it from C.  It's probably a better
 * idea to wrap it in a higher-level language and then use it from there.)
 *
 * ## Using this library
 *
 * TODO RPC Explain better.
 *
 * Your connection to Arti is represented by an `ArtiRpcConn *`.  Use
 * `arti_rpc_connect()` to create one of these.
 *
 * Once you have a connection, you can sent Arti various requests in
 * JSON format.  See (TODO RPC: Add a link to a list of comments.)
 * Use `arti_rpc_execute()` to send a simple request; the function will
 * return when the request succeeds, or fails.
 *
 * TODO: Explain handles and other APIs once I add those APIs.
 *
 * Except when noted otherwise, all functions in this library are thread-safe.
 *
 * ## Error handling
 *
 * On success, fallible functions return `ARTI_RPC_STATUS_SUCCESS`.  On failure,
 * they return some other error code, and set an `* error_out` parameter
 * to a newly allocated `ArtiRpcError` object.
 * (If `error_out==NULL`, then no error is allocated.)
 *
 * You can access information about the an `ArtiRpcError`
 * by calling `arti_rpc_err_{status,message,response}()` on it.
 * When you are done with an error, you should free it with
 * `arti_rpc_err_free()`.
 *
 * The `error_out` parameter always appears last.
 *
 * ## Interface conventions
 *
 * - All functions check for NULL pointers in their arguments.
 *   - As in C tor, `foo_free()` functions treat `foo_free(NULL)` as a no-op.
 *
 * - All input strings should be valid UTF-8.  (The library will check.)
 *   All output strings will be valid UTF-8.
 *
 * - Fallible functions return an ArtiStatus.
 *
 * - All identifiers are prefixed with `ARTI_RPC`, `ArtiRpc`, or `arti_rpc` as appropriate.
 *
 * - Newly allocated objects are returned via out-parameters,
 *   with `out` in their names.
 *   (For example, `ArtiRpcObject **out`).  In such cases, `* out` will be set to a resulting object,
 *   or to NULL if no such object is returned.   Any earlier value of `*out` will be replaced
 *   without freeing it.
 *   (If `out` is NULL, then any object the library would have returned will instead be discareded.)
 *   discarded.
 *   While the function is running,
 *   `*out` and `**out` may not be read or written by any other part of the program,
 *   and they may not alias any other arguments.)
 *   - Note that `*out` will be set to NULL if an error occurs
 *     or the function's inputs are invalid.
 *     (The `*error_out` parameter, of course,
 *     is set to NULL when there is _no_ error, and to an error otherwise.)
 *
 * - When any object is exposed as a non-const pointer,
 *   the application becomes the owner of that object.
 *   The application is expected to eventually free that object via the corresponding `arti_rpc_*_free()` function.
 *
 * - When any object is exposed via a const pointer,
 *   that object is *not* owned by the application.
 *   That object's lifetime will be as documented.
 *   The application must not modify or free such an object.
 *
 * - If a function should be considered a method on a given type of object,
 *   it will take a pointer to that object as its first argument.
 *
 * - If a function consumes (takes ownership of) one of its inputs,
 *   it does so regardless of whether the function succeeds or fails.
 *
 * ## Correctness requirements
 *
 * If any correctness requirements stated here or elsewhere are violated,
 * it is Undefined Behaviour.
 * Violations will not be detected by the library.
 *
 * - Basic C rules apply:
 *     - If you pass a non-NULL pointer to a function, the pointer must be properly aligned.
 *       It must point to valid, initialized data of the correct type.
 *       - As an exception, functions that take a `Type **out` parameter allow the value of `*out`
 *         (but not `out` itself!) to be uninitialized.
 *     - If you receive data via a `const *`, you must not modify that data.
 *     - If you receive a pointer of type `struct Type *`,
 *       and we do not give you the definition of `struct Type`,
 *       you must not attempt to dereference the pointer.
 *     - You may not call any `_free()` function on an object that is currently in use.
 *     - After you have `_freed()` an object, you may not use it again.
 * - Every object allocated by this library has a corresponding `*_free()` function:
 *   You must not use libc's free() to free such objects.
 * - All objects passed as input to a library function must not be mutated
 *   while that function is running.
 * - All objects passed as input to a library function via a non-const pointer
 *   must not be mutated, inspected, or passed to another library function
 *   while the function is running.
 *   - Furthermore, if a function takes any non-const pointer arguments,
 *     those arguments must not alias one another,
 *     and must not alias any const arguments passed to the function.
 * - All `const char*` passed as inputs to library functions
 *   are nul-terminated strings.
 *   Additionally, they must be no larger than `SSIZE_MAX`,
     including the nul.
 * - If a function takes any mutable pointers
 **/

#ifndef ARTI_RPC_CLIENT_CORE_H_
#define ARTI_RPC_CLIENT_CORE_H_

/* Automatically generated by cbindgen. Don't modify manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * A status code returned by an Arti RPC function.
 *
 * On success, a function will return `ARTI_SUCCESS (0)`.
 * On failure, a function will return some other status code.
 */
typedef uint32_t ArtiRpcStatus;

/**
 * An open connection to Arti over an a RPC protocol.
 *
 * This is a thread-safe type: you may safely use it from multiple threads at once.
 *
 * Once you are no longer going to use this connection at all, you must free
 * it with [`arti_rpc_conn_free`]
 */
typedef struct ArtiRpcConn ArtiRpcConn;

/**
 * An error returned by the Arti RPC code, exposed as an object.
 *
 * When a function returns an [`ArtiRpcStatus`] other than [`ARTI_RPC_STATUS_SUCCESS`],
 * it will also expose a newly allocated value of this type
 * via its `error_out` parameter.
 */
typedef struct ArtiRpcError ArtiRpcError;

/**
 * An owned string, returned by this library.
 *
 * This string must be released with `arti_rpc_str_free`.
 * You can inspect it with `arti_rpc_str_get`, but you may not modify it.
 * The string is guaranteed to be UTF-8 and NUL-terminated.
 */
typedef struct ArtiRpcStr ArtiRpcStr;

/**
 * A handle to an in-progress RPC request.
 *
 * This handle must eventually be freed with `arti_rpc_handle_free`.
 *
 * You can wait for the next message with `arti_rpc_handle_wait`.
 */
typedef struct ArtiRpcHandle ArtiRpcHandle;

/**
 * The type of a message returned by an RPC request.
 */
typedef int ArtiRpcResponseType;

/**
 * A constant indicating that a message is a final result.
 *
 * After a result has been received, a handle will not return any more responses,
 * and should be freed.
 */
#define ARTI_RPC_RESPONSE_TYPE_RESULT 1

/**
 * A constant indicating that a message is a non-final update.
 *
 * After an update has been received, the handle may return additional responses.
 */
#define ARTI_RPC_RESPONSE_TYPE_UPDATE 2

/**
 * A constant indicating that a message is a final error.
 *
 * After an error has been received, a handle will not return any more responses,
 * and should be freed.
 */
#define ARTI_RPC_RESPONSE_TYPE_ERROR 3

/**
 * The function has returned successfully.
 */
#define ARTI_RPC_STATUS_SUCCESS 0

/**
 * One or more of the inputs to a library function was invalid.
 *
 * (This error was generated by the library, before any request was sent.)
 */
#define ARTI_RPC_STATUS_INVALID_INPUT 1

/**
 * Tried to use some functionality
 * (for example, an authentication method or connection scheme)
 * that wasn't available on this platform or build.
 *
 * (This error was generated by the library, before any request was sent.)
 */
#define ARTI_RPC_STATUS_NOT_SUPPORTED 2

/**
 * Tried to connect to Arti, but an IO error occurred.
 *
 * This may indicate that Arti wasn't running,
 * or that Arti was built without RPC support,
 * or that Arti wasn't running at the specified location.
 *
 * (This error was generated by the library.)
 */
#define ARTI_RPC_STATUS_CONNECT_IO 3

/**
 * We tried to authenticate with Arti, but it rejected our attempt.
 *
 * (This error was sent by the peer.)
 */
#define ARTI_RPC_STATUS_BAD_AUTH 4

/**
 * Our peer has, in some way, violated the Arti-RPC protocol.
 *
 * (This error was generated by the library,
 * based on a response from Arti that appeared to be invalid.)
 */
#define ARTI_RPC_STATUS_PEER_PROTOCOL_VIOLATION 5

/**
 * The peer has closed our connection; possibly because it is shutting down.
 *
 * (This error was generated by the library,
 * based on the connection being closed or reset from the peer.)
 */
#define ARTI_RPC_STATUS_SHUTDOWN 6

/**
 * An internal error occurred in the arti rpc client.
 *
 * (This error was generated by the library.
 * If you see it, there is probably a bug in the library.)
 */
#define ARTI_RPC_STATUS_INTERNAL 7

/**
 * The peer reports that one of our requests has failed.
 *
 * (This error was sent by the peer, in response to one of our requests.
 * No further responses to that request will be received or accepted.)
 */
#define ARTI_RPC_STATUS_REQUEST_FAILED 8

/**
 * Tried to check the status of a request and found that it was no longer running.
 *
 * TODO RPC: We should make sure that this is the actual semantics we want for this
 * error!  Revisit after we have implemented real cancellation.
 */
#define ARTI_RPC_STATUS_REQUEST_CANCELLED 9















#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Try to open a new connection to an Arti instance.
 *
 * The location of the instance and the method to connect to it are described in
 * `connection_string`.
 *
 * (TODO RPC: Document the format of this string better!)
 *
 * On success, return `ARTI_RPC_STATUS_SUCCESS` and set `*rpc_conn_out` to a new ArtiRpcConn.
 * Otherwise return some other status code, set `*rpc_conn_out` to NULL, and set
 * `*error_out` (if provided) to a newly allocated error object.
 *
 *
 * # Ownership
 *
 * The caller is responsible for making sure that `*rpc_conn_out` and `*error_out`,
 * if set, are eventually freed.
 */
ArtiRpcStatus arti_rpc_connect(const char *connection_string,
                               ArtiRpcConn **rpc_conn_out,
                               ArtiRpcError **error_out);

/**
 * Given a pointer to an RPC connection, return the object ID for its negotiated session.
 *
 * (The session was negotiated as part of establishing the connection.
 * Its object ID is necessary to invoke most other functionality on Arti.)
 *
 * The caller should be prepared for a possible NULL return, in case somehow
 * no session was negotiated.
 *
 * # Ownership
 *
 * The resulting string is a reference to part of the `ArtiRpcConn`.
 * It lives for no longer than the underlying `ArtiRpcConn` object.
 */
const char *arti_rpc_conn_get_session_id(const ArtiRpcConn *rpc_conn);

/**
 * Run an RPC request over `rpc_conn` and wait for a successful response.
 *
 * The message `msg` should be a valid RPC request in JSON format.
 * If you omit its `id` field, one will be generated: this is typically the best way to use this function.
 *
 * On success, return `ARTI_RPC_STATUS_SUCCESS` and set `*response_out` to a newly allocated string
 * containing the JSON response to your request (including `id` and `response` fields).
 *
 * Otherwise return some other status code,  set `*response_out` to NULL,
 * and set `*error_out` (if provided) to a newly allocated error object.
 *
 * (If response_out is set to NULL, then any successful response will be ignored.)
 *
 * # Ownership
 *
 * The caller is responsible for making sure that `*error_out`, if set, is eventually freed.
 *
 * The caller is responsible for making sure that `*response_out`, if set, is eventually freed.
 */
ArtiRpcStatus arti_rpc_conn_execute(const ArtiRpcConn *rpc_conn,
                                    const char *msg,
                                    ArtiRpcStr **response_out,
                                    ArtiRpcError **error_out);

/**
 * Send an RPC request over `rpc_conn`, and return a handle that can wait for a successful response.
 *
 * The message `msg` should be a valid RPC request in JSON format.
 * If you omit its `id` field, one will be generated: this is typically the best way to use this function.
 *
 * On success, return `ARTI_RPC_STATUS_SUCCESS` and set `*handle_out` to a newly allocated `ArtiRpcHandle`.
 *
 * Otherwise return some other status code,  set `*handle_out` to NULL,
 * and set `*error_out` (if provided) to a newly allocated error object.
 *
 * (If `handle_out` is set to NULL, the request will not be sent, and an error will be returned.)
 *
 * # Ownership
 *
 * The caller is responsible for making sure that `*error_out`, if set, is eventually freed.
 *
 * The caller is responsible for making sure that `*handle_out`, if set, is eventually freed.
 */
ArtiRpcStatus arti_rpc_conn_execute_with_handle(const ArtiRpcConn *rpc_conn,
                                                const char *msg,
                                                ArtiRpcHandle **handle_out,
                                                ArtiRpcError **error_out);

/**
 * Wait until some response arrives on an arti_rpc_handle, or until an error occurs.
 *
 * On success, return `ARTI_RPC_STATUS_SUCCESS`; set `*response_out`, if present, to a
 * newly allocated string, and set `*response_type_out`, to the type of the response.
 * (The type will be `ARTI_RPC_RESPONSE_TYPE_RESULT` if the response is a final result,
 * or `ARTI_RPC_RESPONSE_TYPE_ERROR` if the response is a final error,
 * or `ARTI_RPC_RESPONSE_TYPE_UPDATE` if the response is a non-final update.)
 *
 * Otherwise return some other status code, set `*response_out` to NULL,
 * set `*response_type_out` to zero,
 * and set `*error_out` (if provided) to a newly allocated error object.
 *
 * Note that receiving an error reply from Arti is _not_ treated as an error in this function.
 * That is to say, if Arti sends back an error, this function will return `ARTI_SUCCESS`,
 * and deliver the error from Arti in `*response_out`, setting `*response_type_out` to
 * `ARTI_RPC_RESPONSE_TYPE_ERROR`.
 *
 * # Correctness requirements
 *
 * No other thread or code must be using `handle` while this function is running.
 * Accessing `handle` from multiple functions at once may result in undefined behavior.
 *
 * # Ownership
 *
 * The caller is responsible for making sure that `*error_out`, if set, is eventually freed.
 *
 * The caller is responsible for making sure that `*response_out`, if set, is eventually freed.
 */
ArtiRpcStatus arti_rpc_handle_wait(ArtiRpcHandle *handle,
                                   ArtiRpcStr **response_out,
                                   ArtiRpcResponseType *response_type_out,
                                   ArtiRpcError **error_out);

/**
 * Release storage held by an `ArtiRpcHandle`.
 *
 * NOTE, TODO: This does not cancel the request, but that is not guaranteed.
 * Once we implement cancellation, this may behave differently.
 */
void arti_rpc_handle_free(ArtiRpcHandle *handle);

/**
 * Free a string returned by the Arti RPC API.
 */
void arti_rpc_str_free(ArtiRpcStr *string);

/**
 * Return a const pointer to the underlying nul-terminated string from an `ArtiRpcStr`.
 *
 * The resulting string is guaranteed to be valid UTF-8.
 *
 * (Returns NULL if the input is NULL.)
 *
 * # Correctness requirements
 *
 * The resulting string pointer is valid only for as long as the input `string` is not freed.
 */
const char *arti_rpc_str_get(const ArtiRpcStr *string);

/**
 * Close and free an open Arti RPC connection.
 */
void arti_rpc_conn_free(ArtiRpcConn *rpc_conn);

/**
 * Return a string representing the meaning of a given `ArtiRpcStatus`.
 *
 * The result will always be non-NULL, even if the status is unrecognized.
 */
const char *arti_status_to_str(ArtiRpcStatus status);

/**
 * Return the status code associated with a given error.
 *
 * If `err` is NULL, return [`ARTI_RPC_STATUS_INVALID_INPUT`].
 */
ArtiRpcStatus arti_rpc_err_status(const ArtiRpcError *err);

/**
 * Return the OS error code underlying `err`, if any.
 *
 * This is typically an `errno` on unix-like systems , or the result of `GetLastError()`
 * on Windows.  It is only present when `err` was caused by the failure of some
 * OS library call, like a `connect()` or `read()`.
 *
 * Returns 0 if `err` is NULL, or if `err` was not caused by the failure of an
 * OS library call.
 */
int arti_rpc_err_os_error_code(const ArtiRpcError *err);

/**
 * Return a human-readable error message associated with a given error.
 *
 * The format of these messages may change arbitrarily between versions of this library;
 * it is a mistake to depend on the actual contents of this message.
 *
 * Return NULL if the input `err` is NULL.
 *
 * # Correctness requirements
 *
 * The resulting string pointer is valid only for as long as the input `err` is not freed.
 */
const char *arti_rpc_err_message(const ArtiRpcError *err);

/**
 * Return a Json-formatted error response associated with a given error.
 *
 * These messages are full responses, including the `error` field,
 * and the `id` field (if present).
 *
 * Return NULL if the specified error does not represent an RPC error response.
 *
 * Return NULL if the input `err` is NULL.
 *
 * # Correctness requirements
 *
 * The resulting string pointer is valid only for as long as the input `err` is not freed.
 */
const char *arti_rpc_err_response(const ArtiRpcError *err);

/**
 * Make and return copy of a provided error.
 *
 * Return NULL if the input is NULL.
 *
 * # Ownership
 *
 * The caller is responsible for making sure that the returned object
 * is eventually freed with `arti_rpc_err_free()`.
 */
ArtiRpcError *arti_rpc_err_clone(const ArtiRpcError *err);

/**
 * Release storage held by a provided error.
 */
void arti_rpc_err_free(ArtiRpcError *err);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* ARTI_RPC_CLIENT_CORE_H_ */
