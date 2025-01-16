//! Middle-level API for RPC connections
//!
//! This module focuses around the `RpcConn` type, which supports sending RPC requests
//! and matching them with their responses.

use std::{
    io::{self},
    sync::{Arc, Mutex},
};

use crate::msgs::{
    request::InvalidRequestError,
    response::{ResponseKind, RpcError, ValidatedResponse},
    AnyRequestId, ObjectId,
};

mod auth;
mod builder;
mod connimpl;
mod stream;

use crate::util::Utf8CString;
pub use builder::{BuilderError, RpcConnBuilder};
pub use connimpl::RpcConn;
use serde::{de::DeserializeOwned, Deserialize};
pub use stream::StreamError;
use tor_rpc_connect::{auth::cookie::CookieAccessError, HasClientErrorAction};

/// A handle to an open request.
///
/// These handles are created with [`RpcConn::execute_with_handle`].
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct RequestHandle {
    /// The underlying `Receiver` that we'll use to get updates for this request
    ///
    /// It's wrapped in a `Mutex` to prevent concurrent calls to `Receiver::wait_on_message_for`.
    //
    // NOTE: As an alternative to using a Mutex here, we _could_ remove
    // the restriction from `wait_on_message_for` that says that only one thread
    // may be waiting on a given request ID at once.  But that would introduce
    // complexity to the implementation,
    // and it's not clear that the benefit would be worth it.
    #[educe(Debug(ignore))]
    conn: Mutex<Arc<connimpl::Receiver>>,
    /// The ID of this request.
    id: AnyRequestId,
}

// TODO RPC: Possibly abolish these types.
//
// I am keeping this for now because it makes it more clear that we can never reinterpret
// a success as an update or similar.
//
// I am not at all pleased with these types; we should revise them.
//
// TODO RPC: Possibly, all of these should be reconstructed
// from their serde_json::Values rather than forwarded verbatim.
// (But why would we our json to be more canonical than arti's? See #1491.)
//
// DODGY TYPES BEGIN: TODO RPC

/// A Success Response from Arti, indicating that a request was successful.
///
/// This is the complete message, including `id` and `result` fields.
//
// Invariant: it is valid JSON and contains no NUL bytes or newlines.
// TODO RPC: check that the newline invariant is enforced in constructors.
#[derive(Clone, Debug, derive_more::AsRef, derive_more::Into)]
#[as_ref(forward)]
pub struct SuccessResponse(Utf8CString);

impl SuccessResponse {
    /// Helper: Decode the `result` field of this response as an instance of D.
    fn decode<D: DeserializeOwned>(&self) -> Result<D, serde_json::Error> {
        /// Helper object for decoding the "result" field.
        #[derive(Deserialize)]
        struct Response<R> {
            /// The decoded value.
            result: R,
        }
        let response: Response<D> = serde_json::from_str(self.as_ref())?;
        Ok(response.result)
    }
}

/// An Update Response from Arti, with information about the progress of a request.
///
/// This is the complete message, including `id` and `update` fields.
//
// Invariant: it is valid JSON and contains no NUL bytes or newlines.
// TODO RPC: check that the newline invariant is enforced in constructors.
// TODO RPC consider changing this to CString.
#[derive(Clone, Debug, derive_more::AsRef, derive_more::Into)]
#[as_ref(forward)]
pub struct UpdateResponse(Utf8CString);

/// A Error Response from Arti, indicating that an error occurred.
///
/// (This is the complete message, including the `error` field.
/// It also an `id` if it
/// is in response to a request; but not if it is a fatal protocol error.)
//
// Invariant: Does not contain a NUL. (Safe to convert to CString.)
//
// Invariant: This field MUST encode a response whose body is an RPC error.
//
// Otherwise the `decode` method may panic.
//
// TODO RPC: check that the newline invariant is enforced in constructors.
#[derive(Clone, Debug, derive_more::AsRef, derive_more::Into)]
#[as_ref(forward)]
// TODO: If we keep this, it should implement Error.
pub struct ErrorResponse(Utf8CString);
impl ErrorResponse {
    /// Construct an ErrorResponse from the Error reply.
    ///
    /// This not a From impl because we want it to be crate-internal.
    pub(crate) fn from_validated_string(s: Utf8CString) -> Self {
        ErrorResponse(s)
    }

    /// Try to interpret this response as an [`RpcError`].
    pub fn decode(&self) -> RpcError {
        crate::msgs::response::try_decode_response_as_err(self.0.as_ref())
            .expect("Could not decode response that was already decoded as an error?")
            .expect("Could not extract error from response that was already decoded as an error?")
    }
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = self.decode();
        write!(f, "Peer said {:?}", e.message())
    }
}

/// A final response -- that is, the last one that we expect to receive for a request.
///
type FinalResponse = Result<SuccessResponse, ErrorResponse>;

/// Any of the three types of Arti responses.
#[derive(Clone, Debug)]
#[allow(clippy::exhaustive_structs)]
pub enum AnyResponse {
    /// The request has succeeded; no more response will be given.
    Success(SuccessResponse),
    /// The request has failed; no more response will be given.
    Error(ErrorResponse),
    /// An incremental update; more messages may arrive.
    Update(UpdateResponse),
}
// TODO RPC: DODGY TYPES END.

impl AnyResponse {
    /// Convert `v` into `AnyResponse`.
    fn from_validated(v: ValidatedResponse) -> Self {
        // TODO RPC, Perhaps unify AnyResponse with ValidatedResponse, once we are sure what
        // AnyResponse should look like.
        match v.meta.kind {
            ResponseKind::Error => AnyResponse::Error(ErrorResponse::from_validated_string(v.msg)),
            ResponseKind::Success => AnyResponse::Success(SuccessResponse(v.msg)),
            ResponseKind::Update => AnyResponse::Update(UpdateResponse(v.msg)),
        }
    }

    /// Consume this `AnyResponse`, and return its internal string.
    #[cfg(feature = "ffi")]
    pub(crate) fn into_string(self) -> Utf8CString {
        match self {
            AnyResponse::Success(m) => m.into(),
            AnyResponse::Error(m) => m.into(),
            AnyResponse::Update(m) => m.into(),
        }
    }
}

impl RpcConn {
    /// Return the ObjectId for the negotiated Session.
    ///
    /// Nearly all RPC methods require a Session, or some other object
    /// accessed via the session.
    ///
    /// (This function will only return None if no authentication has been performed.
    /// TODO RPC: It is not currently possible to make an unauthenticated connection.)
    pub fn session(&self) -> Option<&ObjectId> {
        self.session.as_ref()
    }

    /// Run a command, and wait for success or failure.
    ///
    /// Note that this function will return `Err(.)` only if sending the command or getting a
    /// response failed.  If the command was sent successfully, and Arti reported an error in response,
    /// this function returns `Ok(Err(.))`.
    ///
    /// Note that the command does not need to include an `id` field.  If you omit it,
    /// one will be generated.
    pub fn execute(&self, cmd: &str) -> Result<FinalResponse, ProtoError> {
        let hnd = self.execute_with_handle(cmd)?;
        hnd.wait()
    }

    /// Helper for executing internally-generated requests and decoding their results.
    ///
    /// Behaves like `execute`, except on success, where it tries to decode the `result` field
    /// of the response as a `T`.
    ///
    /// Use this method in cases where it's reasonable for Arti to sometimes return an RPC error:
    /// in other words, where it's not necessarily a programming error or version mismatch.
    ///
    /// Don't use this for user-generated requests.
    pub(crate) fn execute_internal<T: DeserializeOwned>(
        &self,
        cmd: &str,
    ) -> Result<Result<T, ErrorResponse>, ProtoError> {
        match self.execute(cmd)? {
            Ok(success) => match success.decode::<T>() {
                Ok(result) => Ok(Ok(result)),
                Err(json_error) => Err(ProtoError::InternalRequestFailed(UnexpectedReply {
                    request: cmd.to_string(),
                    reply: Utf8CString::from(success).to_string(),
                    problem: UnexpectedReplyProblem::CannotDecode(Arc::new(json_error)),
                })),
            },
            Err(error) => Ok(Err(error)),
        }
    }

    /// Helper for executing internally-generated requests and decoding their results.
    ///
    /// Behaves like `execute_internal`, except that it treats any RPC error reply
    /// as an internal error or version mismatch.
    ///
    /// Don't use this for user-generated requests.
    pub(crate) fn execute_internal_ok<T: DeserializeOwned>(
        &self,
        cmd: &str,
    ) -> Result<T, ProtoError> {
        match self.execute_internal(cmd)? {
            Ok(v) => Ok(v),
            Err(err_response) => Err(ProtoError::InternalRequestFailed(UnexpectedReply {
                request: cmd.to_string(),
                reply: err_response.to_string(),
                problem: UnexpectedReplyProblem::ErrorNotExpected,
            })),
        }
    }

    /// Cancel a request by ID.
    pub fn cancel(&self, request_id: &AnyRequestId) -> Result<(), ProtoError> {
        /// Arguments to an `rpc::cancel` request.
        #[derive(serde::Serialize, Debug)]
        struct CancelParams<'a> {
            /// The request to cancel.
            request_id: &'a AnyRequestId,
        }

        let request = crate::msgs::request::Request::new(
            ObjectId::connection_id(),
            "rpc:cancel",
            CancelParams { request_id },
        );
        match self.execute_internal::<EmptyResponse>(&request.encode()?)? {
            Ok(EmptyResponse {}) => Ok(()),
            Err(_) => Err(ProtoError::RequestCompleted),
        }
    }

    /// Like `execute`, but don't wait.  This lets the caller see the
    /// request ID and  maybe cancel it.
    pub fn execute_with_handle(&self, cmd: &str) -> Result<RequestHandle, ProtoError> {
        self.send_request(cmd)
    }
    /// As execute(), but run update_cb for every update we receive.
    pub fn execute_with_updates<F>(
        &self,
        cmd: &str,
        mut update_cb: F,
    ) -> Result<FinalResponse, ProtoError>
    where
        F: FnMut(UpdateResponse) + Send + Sync,
    {
        let hnd = self.execute_with_handle(cmd)?;
        loop {
            match hnd.wait_with_updates()? {
                AnyResponse::Success(s) => return Ok(Ok(s)),
                AnyResponse::Error(e) => return Ok(Err(e)),
                AnyResponse::Update(u) => update_cb(u),
            }
        }
    }

    // TODO RPC: shutdown() on the socket on Drop.
}

impl RequestHandle {
    /// Return the ID of this request, to help cancelling it.
    pub fn id(&self) -> &AnyRequestId {
        &self.id
    }
    /// Wait for success or failure, and return what happened.
    ///
    /// (Ignores any update messages that are received.)
    ///
    /// Note that this function will return `Err(.)` only if sending the command or getting a
    /// response failed.  If the command was sent successfully, and Arti reported an error in response,
    /// this function returns `Ok(Err(.))`.
    pub fn wait(self) -> Result<FinalResponse, ProtoError> {
        loop {
            match self.wait_with_updates()? {
                AnyResponse::Success(s) => return Ok(Ok(s)),
                AnyResponse::Error(e) => return Ok(Err(e)),
                AnyResponse::Update(_) => {}
            }
        }
    }
    /// Wait for the next success, failure, or update from this handle.
    ///
    /// Note that this function will return `Err(.)` only if sending the command or getting a
    /// response failed.  If the command was sent successfully, and Arti reported an error in response,
    /// this function returns `Ok(AnyResponse::Error(.))`.
    ///
    /// You may call this method on the same `RequestHandle` from multiple threads.
    /// If you do so, those calls will receive responses (or errors) in an unspecified order.
    ///
    /// If this function returns Success or Error, then you shouldn't call it again.
    /// All future calls to this function will fail with `CmdError::RequestCancelled`.
    /// (TODO RPC: Maybe rename that error.)
    pub fn wait_with_updates(&self) -> Result<AnyResponse, ProtoError> {
        let conn = self.conn.lock().expect("Poisoned lock");
        let validated = conn.wait_on_message_for(&self.id)?;

        Ok(AnyResponse::from_validated(validated))
    }
    // TODO RPC: Cancel on drop.
    // TODO RPC: way to drop without cancelling.

    // TODO RPC: Sketch out how we would want to do this in an async world,
    // or with poll
}

/// An error (or other condition) that has caused an RPC connection to shut down.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ShutdownError {
    /// Io error occurred while reading.
    #[error("Unable to read response: {0}")]
    Read(#[source] Arc<io::Error>),
    /// Io error occurred while writing.
    #[error("Unable to write request: {0}")]
    Write(#[source] Arc<io::Error>),
    /// Something was wrong with Arti's responses; this is a protocol violation.
    #[error("Arti sent a message that didn't conform to the RPC protocol: {0}")]
    ProtocolViolated(String),
    /// Arti has told us that we violated the protocol somehow.
    #[error("Arti reported a fatal error: {0:?}")]
    ProtocolViolationReport(ErrorResponse),
    /// The underlying connection closed.
    ///
    /// This probably means that Arti has shut down.
    #[error("Connection closed")]
    ConnectionClosed,
}

impl From<crate::msgs::response::DecodeResponseError> for ShutdownError {
    fn from(value: crate::msgs::response::DecodeResponseError) -> Self {
        use crate::msgs::response::DecodeResponseError::*;
        use ShutdownError as E;
        match value {
            JsonProtocolViolation(e) => E::ProtocolViolated(e.to_string()),
            ProtocolViolation(s) => E::ProtocolViolated(s.to_string()),
            Fatal(rpc_err) => E::ProtocolViolationReport(rpc_err),
        }
    }
}

/// An error that has occurred while launching an RPC command.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The RPC connection failed, or was closed by the other side.
    #[error("RPC connection is shut down: {0}")]
    Shutdown(#[from] ShutdownError),

    /// There was a problem in the request we tried to send.
    #[error("Invalid request: {0}")]
    InvalidRequest(#[from] InvalidRequestError),

    /// We tried to send a request with an ID that was already pending.
    #[error("Request ID already in use.")]
    RequestIdInUse,

    /// We tried to wait for or inspect a request that had already succeeded or failed.
    #[error("Request has already completed (or failed)")]
    RequestCompleted,

    /// We tried to wait for the same request more than once.
    ///
    /// (This should be impossible.)
    #[error("Internal error: waiting on the same request more than once at a time.")]
    DuplicateWait,

    /// We got an internal error while trying to encode an RPC request.
    ///
    /// (This should be impossible.)
    #[error("Internal error while encoding request: {0}")]
    CouldNotEncode(#[source] Arc<serde_json::Error>),

    /// We got a response to some internally generated request that wasn't what we expected.
    #[error("{0}")]
    InternalRequestFailed(#[source] UnexpectedReply),
}

/// An error while trying to connect to the Arti process.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    /// Unable to parse connect points from an environment variable.
    #[error("Cannot parse connect points from environment variable")]
    BadEnvironment,
    /// We were unable to load and/or parse a given connect point.
    #[error("Unable to load and parse connect point: {0}")]
    CannotParse(#[from] tor_rpc_connect::load::LoadError),
    /// The path used to specify a connect file couldn't be resolved.
    #[error("Unable to resolve connect point path: {0}")]
    CannotResolvePath(#[source] tor_config_path::CfgPathError),
    /// A parsed connect point couldn't be resolved.
    #[error("Unable to resolve connect point: {0}")]
    CannotResolveConnectPoint(#[from] tor_rpc_connect::ResolveError),
    /// IO error while connecting to Arti.
    #[error("Unable to make a connection: {0}")]
    CannotConnect(#[from] tor_rpc_connect::ConnectError),
    /// Opened a connection, but didn't get a banner message.
    ///
    /// (This isn't a `BadMessage`, since it is likelier to represent something that isn't
    /// pretending to be Arti at all than it is to be a malfunctioning Arti.)
    #[error("Did not receive expected banner message upon connecting")]
    InvalidBanner,
    /// All attempted connect points were declined, and none were aborted.
    #[error("All connect points were declined (or there were none)")]
    AllAttemptsDeclined,
    /// A connect file or directory was given as a relative path.
    /// (Only absolute paths are supported).
    #[error("Connect file was given as a relative path.")]
    RelativeConnectFile,
    /// One of our authentication messages was rejected.
    #[error("Arti rejected our authentication: {0:?}")]
    AuthenticationRejected(ErrorResponse),
    /// The connect point uses an RPC authentication type we don't support.
    #[error("Authentication type is not supported")]
    AuthenticationNotSupported,
    /// We couldn't decode one of the responses we got.
    #[error("Message not in expected format: {0:?}")]
    BadMessage(#[source] Arc<serde_json::Error>),
    /// A protocol error occurred during negotiations.
    #[error("Error while negotiating with Arti: {0}")]
    ProtoError(#[from] ProtoError),
    /// The server thinks it is listening on an address where we don't expect to find it.
    /// This can be misconfiguration or an attempted MITM attack.
    #[error("We connected to the server at {ours}, but it thinks it's listening at {theirs}")]
    ServerAddressMismatch {
        /// The address we think the server has
        ours: String,
        /// The address that the server says it has.
        theirs: String,
    },
    /// The server tried to prove knowledge of a cookie file, but its proof was incorrect.
    #[error("Server's cookie MAC was not as expected.")]
    CookieMismatch,
    /// We were unable to access the configured cookie file.
    #[error("Unable to load secret cookie value")]
    LoadCookie(#[from] CookieAccessError),
}

impl HasClientErrorAction for ConnectError {
    fn client_action(&self) -> tor_rpc_connect::ClientErrorAction {
        use tor_rpc_connect::ClientErrorAction as A;
        use ConnectError as E;
        match self {
            E::BadEnvironment => A::Abort,
            E::CannotParse(e) => e.client_action(),
            E::CannotResolvePath(_) => A::Abort,
            E::CannotResolveConnectPoint(e) => e.client_action(),
            E::CannotConnect(e) => e.client_action(),
            E::InvalidBanner => A::Decline,
            E::RelativeConnectFile => A::Abort,
            E::AuthenticationRejected(_) => A::Decline,
            // TODO RPC: Is this correct?  This error can also occur when
            // we are talking to something other than an RPC server.
            E::BadMessage(_) => A::Abort,
            E::ProtoError(e) => e.client_action(),
            E::AllAttemptsDeclined => A::Abort,
            E::AuthenticationNotSupported => A::Decline,
            E::ServerAddressMismatch { .. } => A::Abort,
            E::CookieMismatch => A::Abort,
            E::LoadCookie(e) => e.client_action(),
        }
    }
}

impl HasClientErrorAction for ProtoError {
    fn client_action(&self) -> tor_rpc_connect::ClientErrorAction {
        use tor_rpc_connect::ClientErrorAction as A;
        use ProtoError as E;
        match self {
            E::Shutdown(_) => A::Decline,
            E::InternalRequestFailed(_) => A::Decline,
            // These are always internal errors if they occur while negotiating a connection to RPC,
            // which is the context we care about for `HasClientErrorAction`.
            E::InvalidRequest(_)
            | E::RequestIdInUse
            | E::RequestCompleted
            | E::DuplicateWait
            | E::CouldNotEncode(_) => A::Abort,
        }
    }
}

/// In response to a request that we generated internally,
/// Arti gave a reply that we did not understand.
///
/// This could be due to a bug in this library, a bug in Arti,
/// or a compatibility issue between the two.
#[derive(Clone, Debug, thiserror::Error)]
#[error(
    "In response to our request {request:?}, Arti gave the unexpected reply {reply:?}: {problem}"
)]
pub struct UnexpectedReply {
    /// The request we sent.
    request: String,
    /// The response we got.
    reply: String,
    /// What was wrong with the response.
    problem: UnexpectedReplyProblem,
}

/// Underlying reason for an UnexpectedReply
#[derive(Clone, Debug, thiserror::Error)]
enum UnexpectedReplyProblem {
    /// There was a json failure while trying to decode the response:
    /// the result type was not what we expected.
    #[error("Cannot decode as correct JSON type")]
    CannotDecode(Arc<serde_json::Error>),
    /// Arti replied with an RPC error in a context no error should have been possible.
    #[error("Unexpected error")]
    ErrorNotExpected,
}

/// Arguments to a request that takes no parameters.
#[derive(serde::Serialize, Debug)]
struct NoParameters {}

/// A response with no data.
#[derive(serde::Deserialize, Debug)]
struct EmptyResponse {}

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

    use std::{sync::atomic::AtomicUsize, thread, time::Duration};

    use io::{BufRead as _, BufReader, Write as _};
    use rand::{seq::SliceRandom as _, Rng as _, SeedableRng as _};
    use tor_basic_utils::{test_rng::testing_rng, RngExt as _};

    use crate::{
        llconn,
        msgs::request::{JsonMap, Request, ValidatedRequest},
    };

    use super::*;

    /// helper: Return a dummy RpcConn, along with a socketpair for it to talk to.
    fn dummy_connected() -> (RpcConn, socketpair::SocketpairStream) {
        let (s1, s2) = socketpair::socketpair_stream().unwrap();
        let s1_w = s1.try_clone().unwrap();
        let s1_r = io::BufReader::new(s1);
        let conn = RpcConn::new(llconn::Reader::new(s1_r), llconn::Writer::new(s1_w));

        (conn, s2)
    }

    fn write_val(w: &mut impl io::Write, v: &serde_json::Value) {
        let mut enc = serde_json::to_string(v).unwrap();
        enc.push('\n');
        w.write_all(enc.as_bytes()).unwrap();
    }

    #[test]
    fn simple() {
        let (conn, sock) = dummy_connected();

        let user_thread = thread::spawn(move || {
            let response1 = conn
                .execute_internal_ok::<JsonMap>(
                    r#"{"obj":"fred","method":"arti:x-frob","params":{}}"#,
                )
                .unwrap();
            (response1, conn)
        });

        let fake_arti_thread = thread::spawn(move || {
            let mut sock = BufReader::new(sock);
            let mut s = String::new();
            let _len = sock.read_line(&mut s).unwrap();
            let request = ValidatedRequest::from_string_strict(s.as_ref()).unwrap();
            let response = serde_json::json!({
                "id": request.id().clone(),
                "result": { "xyz" : 3 }
            });
            write_val(sock.get_mut(), &response);
            sock // prevent close
        });

        let _sock = fake_arti_thread.join().unwrap();
        let (map, _conn) = user_thread.join().unwrap();
        assert_eq!(map.get("xyz"), Some(&serde_json::Value::Number(3.into())));
    }

    #[test]
    fn complex() {
        use std::sync::atomic::Ordering::SeqCst;
        let n_threads = 16;
        let n_commands_per_thread = 4096;
        let n_commands_total = n_threads * n_commands_per_thread;
        let n_completed = Arc::new(AtomicUsize::new(0));

        let (conn, sock) = dummy_connected();
        let conn = Arc::new(conn);
        let mut user_threads = Vec::new();
        let mut rng = testing_rng();

        // -------
        // User threads: Make a bunch of requests.
        for th_idx in 0..n_threads {
            let conn = Arc::clone(&conn);
            let n_completed = Arc::clone(&n_completed);
            let mut rng = rand_chacha::ChaCha12Rng::from_seed(rng.gen());
            let th = thread::spawn(move || {
                for cmd_idx in 0..n_commands_per_thread {
                    // We are spawning a bunch of worker threads, each of which will run a number of
                    // commands in sequence.  Each command will be a request that gets optional
                    // updates, and an error or a success.
                    // We will double-check that each request gets the response it asked for.
                    let s = format!("{}:{}", th_idx, cmd_idx);
                    let want_updates: bool = rng.gen();
                    let want_failure: bool = rng.gen();
                    let req = serde_json::json!({
                        "obj":"fred",
                        "method":"arti:x-echo",
                        "meta": {
                            "updates": want_updates,
                        },
                        "params": {
                            "val": &s,
                            "fail": want_failure,
                        },
                    });
                    let req = serde_json::to_string(&req).unwrap();

                    // Wait for a final response, processing updates if we asked for them.
                    let mut n_updates = 0;
                    let outcome = conn
                        .execute_with_updates(&req, |_update| {
                            n_updates += 1;
                        })
                        .unwrap();
                    assert_eq!(n_updates > 0, want_updates);

                    // See if we liked the final response.
                    if want_failure {
                        let e = outcome.unwrap_err().decode();
                        assert_eq!(e.message(), "You asked me to fail");
                        assert_eq!(i32::from(e.code()), 33);
                        assert_eq!(
                            e.kinds_iter().collect::<Vec<_>>(),
                            vec!["Example".to_string()]
                        );
                    } else {
                        let success = outcome.unwrap();
                        let map = success.decode::<JsonMap>().unwrap();
                        assert_eq!(map.get("echo"), Some(&serde_json::Value::String(s)));
                    }
                    n_completed.fetch_add(1, SeqCst);
                    if rng.gen::<f32>() < 0.02 {
                        thread::sleep(Duration::from_millis(3));
                    }
                }
            });
            user_threads.push(th);
        }

        #[derive(serde::Deserialize, Debug)]
        struct Echo {
            val: String,
            fail: bool,
        }

        // -----
        // Worker thread: handles user requests.
        let worker_rng = rand_chacha::ChaCha12Rng::from_seed(rng.gen());
        let worker_thread = thread::spawn(move || {
            let mut rng = worker_rng;
            let mut sock = BufReader::new(sock);
            let mut pending: Vec<Request<Echo>> = Vec::new();
            let mut n_received = 0;

            // How many requests do we buffer before we shuffle them and answer them out-of-order?
            let scramble_factor = 7;
            // After receiving how many requests do we stop shuffling requests?
            //
            // (Our shuffling algorithm can deadlock us otherwise.)
            let scramble_threshold =
                n_commands_total - (n_commands_per_thread + 1) * scramble_factor;

            'outer: loop {
                let flush_pending_at = if n_received >= scramble_threshold {
                    1
                } else {
                    scramble_factor
                };

                // Queue a handful of requests in "pending"
                while pending.len() < flush_pending_at {
                    let mut buf = String::new();
                    if sock.read_line(&mut buf).unwrap() == 0 {
                        break 'outer;
                    }
                    n_received += 1;
                    let req: Request<Echo> = serde_json::from_str(&buf).unwrap();
                    pending.push(req);
                }

                // Handle the requests in "pending" in random order.
                let mut handling = std::mem::take(&mut pending);
                handling.shuffle(&mut rng);

                for req in handling {
                    if req.meta.unwrap_or_default().updates {
                        let n_updates = rng.gen_range_checked(1..4).unwrap();
                        for _ in 0..n_updates {
                            let up = serde_json::json!({
                                "id": req.id.clone(),
                                "update": {
                                    "hello": req.params.val.clone(),
                                }
                            });
                            write_val(sock.get_mut(), &up);
                        }
                    }

                    let response = if req.params.fail {
                        serde_json::json!({
                            "id": req.id.clone(),
                            "error": { "message": "You asked me to fail", "code": 33, "kinds": ["Example"], "data": req.params.val },
                        })
                    } else {
                        serde_json::json!({
                            "id": req.id.clone(),
                            "result": {
                                "echo": req.params.val
                            }
                        })
                    };
                    write_val(sock.get_mut(), &response);
                }
            }
        });
        drop(conn);
        for t in user_threads {
            t.join().unwrap();
        }

        worker_thread.join().unwrap();

        assert_eq!(n_completed.load(SeqCst), n_commands_total);
    }

    #[test]
    fn arti_socket_closed() {
        // Here we send a bunch of requests and then close the socket without answering them.
        //
        // Every request should get a ProtoError::Shutdown.
        let n_threads = 16;

        let (conn, sock) = dummy_connected();
        let conn = Arc::new(conn);
        let mut user_threads = Vec::new();
        for _ in 0..n_threads {
            let conn = Arc::clone(&conn);
            let th = thread::spawn(move || {
                // We are spawning a bunch of worker threads, each of which will run a number of
                // We will double-check that each request gets the response it asked for.
                let req = serde_json::json!({
                    "obj":"fred",
                    "method":"arti:x-echo",
                    "params":{}
                });
                let req = serde_json::to_string(&req).unwrap();
                let outcome = conn.execute(&req);
                if !matches!(
                    &outcome,
                    Err(ProtoError::Shutdown(ShutdownError::Write(_)))
                        | Err(ProtoError::Shutdown(ShutdownError::Read(_))),
                ) {
                    dbg!(&outcome);
                }

                assert!(matches!(
                    outcome,
                    Err(ProtoError::Shutdown(ShutdownError::Write(_)))
                        | Err(ProtoError::Shutdown(ShutdownError::Read(_)))
                        | Err(ProtoError::Shutdown(ShutdownError::ConnectionClosed))
                ));
            });
            user_threads.push(th);
        }

        drop(sock);

        for t in user_threads {
            t.join().unwrap();
        }
    }

    /// Send a bunch of requests and then send back a single reply.
    ///
    /// That reply should cause every request to get closed.
    fn proto_err_with_msg<F>(msg: &str, outcome_ok: F)
    where
        F: Fn(ProtoError) -> bool,
    {
        let n_threads = 16;

        let (conn, mut sock) = dummy_connected();
        let conn = Arc::new(conn);
        let mut user_threads = Vec::new();
        for _ in 0..n_threads {
            let conn = Arc::clone(&conn);
            let th = thread::spawn(move || {
                // We are spawning a bunch of worker threads, each of which will run a number of
                // We will double-check that each request gets the response it asked for.
                let req = serde_json::json!({
                    "obj":"fred",
                    "method":"arti:x-echo",
                    "params":{}
                });
                let req = serde_json::to_string(&req).unwrap();
                conn.execute(&req)
            });
            user_threads.push(th);
        }

        sock.write_all(msg.as_bytes()).unwrap();

        for t in user_threads {
            let outcome = t.join().unwrap();
            assert!(outcome_ok(outcome.unwrap_err()));
        }
    }

    #[test]
    fn syntax_error() {
        proto_err_with_msg("this is not json\n", |outcome| {
            matches!(
                outcome,
                ProtoError::Shutdown(ShutdownError::ProtocolViolated(_))
            )
        });
    }

    #[test]
    fn fatal_error() {
        let j = serde_json::json!({
            "error":{ "message": "This test is doomed", "code": 413, "kinds": ["Example"], "data": {} },
        });
        let mut s = serde_json::to_string(&j).unwrap();
        s.push('\n');

        proto_err_with_msg(&s, |outcome| {
            matches!(
                outcome,
                ProtoError::Shutdown(ShutdownError::ProtocolViolationReport(_))
            )
        });
    }
}
