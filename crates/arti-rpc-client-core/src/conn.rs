//! Middle-level API for RPC connections
//!
//! This module focuses around the `RpcConn` type, which supports sending RPC requests
//! and matching them with their responses.

use std::{
    io::{self, BufReader},
    path::PathBuf,
    sync::Arc,
};

use crate::{
    llconn,
    msgs::{
        response::{ResponseKind, RpcError, ValidatedResponse},
        AnyRequestId, ObjectId,
    },
    util::define_from_for_arc,
};

mod auth;
mod connimpl;

pub use connimpl::RpcConn;

/// A handle to an open request.
///
/// These handles are crated with [`RpcConn::execute_with_handle`].
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct RequestHandle {
    /// The underlying `Receiver` that we'll use to get updates for this request
    #[educe(Debug(ignore))]
    conn: Arc<connimpl::Receiver>,
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
// TODO RPC: Possibly, convert these to hold CString internally.
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
// TODO RPC consider changing this to CString.
#[derive(Clone, Debug, derive_more::AsRef)]
pub struct SuccessResponse(String);

/// An Update Response from Arti, with information about the progress of a request.
///
/// This is the complete message, including `id` and `update` fields.
//
// Invariant: it is valid JSON and contains no NUL bytes or newlines.
// TODO RPC: check that the newline invariant is enforced in constructors.
// TODO RPC consider changing this to CString.
#[derive(Clone, Debug, derive_more::AsRef)]
pub struct UpdateResponse(String);

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
// TODO RPC consider changing this to CString.
#[derive(Clone, Debug, derive_more::AsRef)]
// TODO: If we keep this, it should implement Error.
pub struct ErrorResponse(String);
impl ErrorResponse {
    /// Construct an ErrorResponse from the Error reply.
    ///
    /// This not a From impl because we want it to be crate-internal.
    pub(crate) fn from_validated_string(s: String) -> Self {
        ErrorResponse(s)
    }

    /// Try to interpret this response as an [`RpcError`].
    pub fn decode(&self) -> RpcError {
        crate::msgs::response::try_decode_response_as_err(&self.0)
            .expect("Could not decode response that was already decoded as an error?")
            .expect("Could not extract error from response that was already decoded as an error?")
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

/// Information about how to construct a connection to an Arti instance.
pub struct RpcConnBuilder {
    /// A path to a unix domain socket at which Arti is listening.
    // TODO RPC: Right now this is the only kind of supported way to connect.
    unix_socket: PathBuf,
    // todo RPC: include selector for how to connect.
    //
    // TODO RPC: Possibly kill off the builder entirely.
}

// TODO: For FFI purposes, define a slightly higher level API that
// tries to do this all at once, possibly decoding a "connect string"
// and some optional secret stuff?
impl RpcConnBuilder {
    /// Create a Builder from a connect string.
    ///
    /// (Right now the only supported string type is "unix:" followed by a path.)
    //
    // TODO RPC: Should this take an OsString?
    //
    // TODO RPC: Specify the actual metaformat that we want to use here.
    // Possibly turn this into a K=V sequence ... or possibly, just
    // turn it into a JSON object.
    pub fn from_connect_string(s: &str) -> Result<Self, BuilderError> {
        let (kind, location) = s
            .split_once(':')
            .ok_or(BuilderError::InvalidConnectString)?;
        if kind == "unix" {
            Ok(Self::new_unix_socket(location))
        } else {
            Err(BuilderError::InvalidConnectString)
        }
    }

    /// Create a Builder to connect to a unix socket at a given path.
    ///
    /// Note that this function may succeed even in environments where
    /// unix sockets are not supported.  On these environments,
    /// the `connect` attempt will later fail with `SchemeNotSupported`.
    pub fn new_unix_socket(addr: impl Into<PathBuf>) -> Self {
        Self {
            unix_socket: addr.into(),
        }
    }

    /// Try to connect to an Arti process as specified by this Builder.
    pub fn connect(&self) -> Result<RpcConn, ConnectError> {
        #[cfg(not(unix))]
        {
            return Err(ConnectError::SchemeNotSupported);
        }
        #[cfg(unix)]
        {
            let sock = std::os::unix::net::UnixStream::connect(&self.unix_socket)
                .map_err(|e| ConnectError::CannotConnect(Arc::new(e)))?;
            let sock_dup = sock
                .try_clone()
                .map_err(|e| ConnectError::CannotConnect(Arc::new(e)))?;
            let mut conn = RpcConn::new(
                llconn::Reader::new(Box::new(BufReader::new(sock))),
                llconn::Writer::new(Box::new(sock_dup)),
            );

            let session_id = conn.authenticate_inherent("inherent:unix_path")?;
            conn.session = Some(session_id);

            Ok(conn)
        }
    }
}

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
    /// Cancel a request by ID.
    pub fn cancel(&self, _id: &AnyRequestId) -> Result<(), ProtoError> {
        todo!()
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
        let mut hnd = self.execute_with_handle(cmd)?;
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
    pub fn wait(mut self) -> Result<FinalResponse, ProtoError> {
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
    /// If this function returns Success or Error, then you shouldn't call it again.
    /// All future calls to this function will fail with `CmdError::RequestCancelled`.
    /// (TODO RPC: Maybe rename that error.)
    pub fn wait_with_updates(&mut self) -> Result<AnyResponse, ProtoError> {
        let validated = self.conn.wait_on_message_for(&self.id)?;

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
    Read(Arc<io::Error>),
    /// Io error occurred while writing.
    #[error("Unable to write request: {0}")]
    Write(Arc<io::Error>),
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
    InvalidRequest(Arc<serde_json::Error>),

    /// We tried to send a request with an ID that was already pending.
    #[error("Request ID already in use.")]
    RequestIdInUse,

    /// We tried to wait for a request that had already been cancelled.
    //
    // TODO RPC: Possibly this should be impossible.  Revisit when I implement
    // cancellation here.
    #[error("Request already cancelled.")]
    RequestCancelled,

    /// We tried to wait for the same request more than once.
    ///
    /// (This should be impossible.)
    #[error("Internal error: waiting on the same request more than once at a time.")]
    DuplicateWait,

    /// We got an internal error while trying to encode an RPC request.
    ///
    /// (This should be impossible.)
    #[error("Internal error while encoding request: {0}")]
    CouldNotEncode(Arc<serde_json::Error>),
}

/// An error while trying to connect to the Arti process.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    /// We specified a prefix to our connect string, but we don't
    /// have run-time support for it.
    #[error("Selected connection scheme was not supported in this build")]
    SchemeNotSupported,
    /// IO error while connecting to Arti.
    #[error("Unable to make a connection: {0}")]
    CannotConnect(Arc<std::io::Error>),
    /// One of our protocol negotiation messages was rejected.
    #[error("Arti rejected our negotiation attempts: {0:?}")]
    NegotiationRejected(ErrorResponse),
    /// One of our authentication messages was rejected.
    #[error("Arti rejected our authentication: {0:?}")]
    AuthenticationRejected(ErrorResponse),
    /// We couldn't decode one of the responses we got.
    #[error("Message not in expected format: {0:?}")]
    BadMessage(Arc<serde_json::Error>),
    /// A protocol error occurred during negotiations.
    #[error("Error while negotiating with Arti: {0}")]
    ProtoError(#[from] ProtoError),
}
define_from_for_arc!(serde_json::Error => ConnectError [BadMessage]);

/// An error occurred while trying to construct or manipulate a
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuilderError {
    /// We couldn't decode a provided connect string.
    #[error("Invalid connect string.")]
    InvalidConnectString,
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

    use std::{sync::atomic::AtomicUsize, thread, time::Duration};

    use io::{BufRead as _, Write as _};
    use rand::{seq::SliceRandom as _, Rng as _, SeedableRng as _};
    use tor_basic_utils::{test_rng::testing_rng, RngExt as _};

    use crate::msgs::request::{JsonMap, Request};

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
                .execute(r#"{"obj":"fred","method":"arti:x-frob","params":{}}"#)
                .unwrap();
            (response1, conn)
        });

        let fake_arti_thread = thread::spawn(move || {
            let mut sock = BufReader::new(sock);
            let mut s = String::new();
            let _len = sock.read_line(&mut s).unwrap();
            let request: Request<JsonMap> = serde_json::from_str(&s).unwrap();
            let response = serde_json::json!({
                "id": request.id.clone(),
                "result": { "xyz" : 3 }
            });
            write_val(sock.get_mut(), &response);
            sock // prevent close
        });

        let _sock = fake_arti_thread.join().unwrap();
        let (response, _conn) = user_thread.join().unwrap();
        let map = response.unwrap().deserialize_as::<JsonMap>().unwrap();
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
                        assert_eq!(e.data().unwrap().as_str().unwrap(), &s);
                    } else {
                        let success = outcome.unwrap();
                        let map = success.deserialize_as::<JsonMap>().unwrap();
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
                assert!(matches!(
                    outcome,
                    Err(ProtoError::Shutdown(ShutdownError::Write(_)))
                        | Err(ProtoError::Shutdown(ShutdownError::Read(_)))
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
