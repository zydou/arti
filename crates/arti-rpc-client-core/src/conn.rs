/// Middle-level API for RPC connections
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

pub struct RequestHandle {
    conn: Arc<connimpl::Receiver>,
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
// DODGY TYPES BEGIN: TODO RPC
#[derive(Clone, Debug, derive_more::AsRef)]
pub struct SuccessResponse(String);
#[derive(Clone, Debug, derive_more::AsRef)]
pub struct UpdateResponse(String);
/// A response to request from Arti, indicating that an error occurred.
//
// Invariant: This field MUST encode a response whose body is an RPC error.
//
// Otherwise the `decode` method may panic.
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
        crate::msgs::response::response_err(&self.0)
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
    Success(SuccessResponse),
    Error(ErrorResponse),
    Update(UpdateResponse),
}
// TODO RPC: DODGY TYPES END.

pub struct RpcConnBuilder {
    // todo RPC: include selector for how to connect.
    unix_socket: PathBuf,
    // TODO RPC: Possibly kill off the builder entirely.
}

// TODO: For FFI purposes, define a slightly higher level API that
// tries to do this all at once, possibly decoding a "connect string"
// and some optional secret stuff?
impl RpcConnBuilder {
    /// Create a Builder from a connect string.
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

    pub fn new_unix_socket(addr: impl Into<PathBuf>) -> Self {
        Self {
            unix_socket: addr.into(),
        }
    }

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

            let session_id = conn.negotiate_inherent("inherent:unix_path")?;
            conn.session = Some(session_id);

            Ok(conn)
        }
    }
}

impl AnyResponse {
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
    // As execute(), but ensure that update_cb is run for every update we receive.
    pub fn execute_with_updates<F>(
        &self,
        cmd: &str,
        mut update_cb: F,
    ) -> Result<FinalResponse, ProtoError>
    where
        F: FnMut(UpdateResponse) + Send + Sync + 'static,
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

#[derive(Clone, Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("Selected connection scheme was not supported in this build")]
    SchemeNotSupported,
    #[error("Protocol version {0:?} is not supported")]
    ProtoNotSupported(String),
    #[error("Unable to make a connection: {0}")]
    CannotConnect(Arc<std::io::Error>),
    //#[error(" (launch fnot implemented) ")]
    // CantLaunchArti,
    #[error("Arti rejected our negotiation attempts: {0:?}")]
    NegotiationRejected(ErrorResponse),
    #[error("Arti rejected our authentication: {0:?}")]
    AuthenticationRejected(ErrorResponse),
    #[error("Message not in expected format: {0:?}")]
    BadMessage(Arc<serde_json::Error>),
    #[error("Error while negotiating with Arti: {0}")]
    ProtoError(#[from] ProtoError),
}
define_from_for_arc!(serde_json::Error => ConnectError [BadMessage]);

#[derive(Clone, Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Invalid connect string.")]
    InvalidConnectString,
}
