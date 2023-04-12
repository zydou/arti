//! RPC session support, mainloop, and protocol implementation.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use asynchronous_codec::JsonCodecError;
use futures::{
    channel::mpsc,
    stream::{FusedStream, FuturesUnordered},
    FutureExt, Sink, SinkExt, StreamExt,
};
use once_cell::sync::Lazy;
use pin_project::pin_project;
use serde_json::error::Category as JsonErrorCategory;

use crate::{
    cancel::{Cancel, CancelHandle},
    err::RequestParseError,
    msgs::{BoxedResponse, FlexibleRequest, Request, RequestId, ResponseBody},
};

use tor_rpcbase as rpc;

/// A session with an RPC client.  
///
/// Tracks information that persists from one request to another.
pub(crate) struct Session {
    /// The mutable state of this session
    inner: Mutex<Inner>,
}

impl rpc::Object for Session {}
rpc::decl_object! {Session}

/// An unauthenticated session object, as exposed to an RPC client that hasn't authenticated.
struct UnauthenticatedSession {
    /// The inner session.
    inner: Arc<Session>,
}
impl rpc::Object for UnauthenticatedSession {}
rpc::decl_object! {UnauthenticatedSession}

/// The inner, lock-protected part of a session.
struct Inner {
    /// Map from request ID to handles; used when we need to cancel a request.
    //
    // TODO: We have two options here for handling colliding IDs.  We can either turn
    // this into a multimap, or we can declare that cancelling a request only
    // cancels the most recent request sent with that ID.
    inflight: HashMap<RequestId, CancelHandle>,

    /// True if the user has authenticated.
    authenticated: bool,
}

/// How many updates can be pending, per session, before they start to block?
const UPDATE_CHAN_SIZE: usize = 128;

/// Channel type used to send updates to the main session loop.
type UpdateSender = mpsc::Sender<BoxedResponse>;

/// A type-erased [`FusedStream`] yielding [`Request`]s.
//
// (We name this type and [`BoxedResponseSink`] below so as to keep the signature for run_loop
// nice and simple.)
pub(crate) type BoxedRequestStream = Pin<
    Box<dyn FusedStream<Item = Result<FlexibleRequest, asynchronous_codec::JsonCodecError>> + Send>,
>;

/// A type-erased [`Sink`] accepting [`BoxedResponse`]s.
pub(crate) type BoxedResponseSink =
    Pin<Box<dyn Sink<BoxedResponse, Error = asynchronous_codec::JsonCodecError> + Send>>;

/// A lazily constructed type-based dispatch table used for invoking functions
/// based on RPC object and method types.
//
// TODO RPC: This will be moved into an Arc that lives in some kind of
// SessionManager.
static DISPATCH_TABLE: Lazy<rpc::DispatchTable> = Lazy::new(rpc::DispatchTable::from_inventory);

impl Session {
    /// Create a new session.
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                inflight: HashMap::new(),
                authenticated: false,
            }),
        }
    }

    /// Look up a given object by its object ID relative to this session.
    fn lookup_object(
        self: &Arc<Self>,
        id: &rpc::ObjectId,
    ) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        let authenticated = self.inner.lock().expect("lock poisoned").authenticated;

        if id.as_ref() == "session" {
            if authenticated {
                return Ok(self.clone());
            } else {
                return Ok(Arc::new(UnauthenticatedSession {
                    inner: self.clone(),
                }));
            }
        } else if !authenticated {
            // Maybe thos should be a permission-denied error instead.
            return Err(rpc::LookupError::NoObject(id.clone()));
        }

        Err(rpc::LookupError::NoObject(id.clone()))
    }

    /// Un-register the request `id` and stop tracking its information.
    fn remove_request(&self, id: &RequestId) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.inflight.remove(id);
    }

    /// Register the request `id` as a cancellable request.
    fn register_request(&self, id: RequestId, handle: CancelHandle) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.inflight.insert(id, handle);
    }

    /// Run in a loop, handling requests from `request_stream` and writing
    /// responses onto `response_stream`.
    pub(crate) async fn run_loop(
        self: Arc<Self>,
        mut request_stream: BoxedRequestStream,
        mut response_sink: BoxedResponseSink,
    ) -> Result<(), SessionError> {
        // This function will multiplex on three streams:
        // * `request_stream` -- a stream of incoming requests from the client.
        // * `finished_requests` -- a stream of responses from requests that
        //   are done, which we're sending to the client.
        // * `rx_update` -- a stream of updates sent from in-progress tasks.
        //
        // Note that the blocking behavior here is deliberate: We want _all_ of
        // these reads to start blocking when response_sink.send is blocked.

        let (tx_update, mut rx_update) = mpsc::channel::<BoxedResponse>(UPDATE_CHAN_SIZE);
        let mut finished_requests = FuturesUnordered::new();
        finished_requests.push(futures::future::pending().boxed());

        'outer: loop {
            futures::select! {
                r = finished_requests.next() => {
                    // A task is done, so we can inform the client.
                    let r: BoxedResponse = r.expect("Somehow, future::pending() terminated.");
                    debug_assert!(r.body.is_final());
                    self.remove_request(&r.id);
                    // Calling `await` here (and below) is deliberate: we _want_
                    // to stop reading the client's requests if the client is
                    // not reading their responses (or not) reading them fast
                    // enough.
                    response_sink.send(r).await.map_err(|_| SessionError::WriteFailed)?;
                }

                r = rx_update.next() => {
                    // The future for some request has sent an update, so we can
                    // inform the client.
                    let update = r.expect("Somehow, tx_update got closed.");
                    debug_assert!(! update.body.is_final());
                    response_sink.send(update).await.map_err(|_| SessionError::WriteFailed)?;
                }

                req = request_stream.next() => {
                    match req {
                        None => {
                            // We've reached the end of the stream of requests;
                            // time to close.
                            break 'outer;
                        }
                        Some(Err(e)) => {
                            // We got a non-recoverable error from the JSON codec.
                           let error = match e {
                                JsonCodecError::Io(_) => return Err(SessionError::ReadFailed),
                                JsonCodecError::Json(e) => match e.classify() {
                                    JsonErrorCategory::Eof => break 'outer,
                                    JsonErrorCategory::Io => return Err(SessionError::ReadFailed),
                                    JsonErrorCategory::Syntax => RequestParseError::InvalidJson,
                                    JsonErrorCategory::Data => RequestParseError::NotAnObject,
                                }
                            };

                            response_sink
                                .send(
                                    BoxedResponse::from_error(None, error)
                                ).await.map_err(|_| SessionError::WriteFailed)?;

                            // TODO RPC: Perhaps we should keep going on the NotAnObject case?
                            //      (InvalidJson is not recoverable!)
                            break 'outer;
                        }
                        Some(Ok(FlexibleRequest::Invalid(bad_req))) => {
                            // We could at least
                            response_sink
                                .send(
                                    BoxedResponse::from_error(bad_req.id().cloned(), bad_req.error())
                                ).await.map_err(|_| SessionError::WriteFailed)?;

                        }
                        Some(Ok(FlexibleRequest::Valid(req))) => {
                            // We have a request. Time to launch it!

                            let tx_channel = req.meta.updates.then(|| &tx_update);
                            let id = req.id.clone();
                            let fut = self.run_method_lowlevel(tx_channel, req);
                            let (handle, fut) = Cancel::new(fut);
                            self.register_request(id.clone(), handle);
                            let fut = fut.map(|r| match r {
                                Ok(Ok(v)) => BoxedResponse { id, body: ResponseBody::Success(v) },
                                Ok(Err(e)) => BoxedResponse { id, body: e.into() },
                                Err(_cancelled) => BoxedResponse::from_error(Some(id), RequestCancelled),
                            });


                            finished_requests.push(fut.boxed());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Run a single method, and return its final response.
    ///
    /// If `tx_updates` is provided, and this method generates updates, it
    /// should send those updates on `tx_updates`
    ///
    /// Note that this function is able to send responses with IDs that do not
    /// match the original.  It should enforce correct IDs on whatever response
    /// it generates.
    async fn run_method_lowlevel(
        self: &Arc<Self>,
        tx_updates: Option<&UpdateSender>,
        request: Request,
    ) -> Result<Box<dyn erased_serde::Serialize + Send + 'static>, rpc::RpcError> {
        let Request {
            id, obj, method, ..
        } = request;
        let obj = self.lookup_object(&obj)?;

        let context: Box<dyn rpc::Context> = match tx_updates {
            Some(tx) => Box::new(RequestContext {
                session: Arc::clone(self),
                id: id.clone(),
                reply_tx: tx.clone(),
            }),
            None => Box::new(RequestContext {
                session: Arc::clone(self),
                id: id.clone(),
                reply_tx: (),
            }),
        };

        DISPATCH_TABLE.invoke(obj, method, context)?.await
    }
}

/// A failure that results in closing a Session.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum SessionError {
    /// Unable to write to our connection.
    #[error("Could not write to connection")]
    WriteFailed,
    /// Read error from connection.
    #[error("Problem reading from connection")]
    ReadFailed,
}

/// A Context object that we pass to each method invocation.
///
/// It provides the `rpc::Context` interface, which is used to send incremental
/// updates and lookup objects by their ID.
#[pin_project]
struct RequestContext<T> {
    /// The underlying RPC session.
    session: Arc<Session>,
    /// The request ID. It's used to tag every reply.
    id: RequestId,
    /// A `futures::Sink` if incremental updates are wanted; `()` otherwise.
    #[pin]
    reply_tx: T,
}

impl<T> Sink<Box<dyn erased_serde::Serialize + Send + 'static>> for RequestContext<T>
where
    T: Sink<BoxedResponse>,
{
    type Error = rpc::SendUpdateError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.reply_tx
            .poll_ready(cx)
            .map_err(|_| rpc::SendUpdateError::RequestCancelled)
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: Box<dyn erased_serde::Serialize + Send + 'static>,
    ) -> Result<(), Self::Error> {
        let this = self.project();
        let item = BoxedResponse {
            id: this.id.clone(),
            body: ResponseBody::Update(item),
        };
        this.reply_tx
            .start_send(item)
            .map_err(|_| rpc::SendUpdateError::RequestCancelled)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.reply_tx
            .poll_flush(cx)
            .map_err(|_| rpc::SendUpdateError::RequestCancelled)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.reply_tx
            .poll_close(cx)
            .map_err(|_| rpc::SendUpdateError::RequestCancelled)
    }
}
impl<T> rpc::Context for RequestContext<T>
where
    T: Sink<BoxedResponse> + Send,
{
    fn lookup_object(&self, id: &rpc::ObjectId) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        self.session.lookup_object(id)
    }

    fn accepts_updates(&self) -> bool {
        true
    }
}

impl Sink<Box<dyn erased_serde::Serialize + Send + 'static>> for RequestContext<()> {
    type Error = rpc::SendUpdateError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Err(rpc::SendUpdateError::NoUpdatesWanted))
    }

    fn start_send(
        self: Pin<&mut Self>,
        _item: Box<dyn erased_serde::Serialize + Send + 'static>,
    ) -> Result<(), Self::Error> {
        Err(rpc::SendUpdateError::NoUpdatesWanted)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl rpc::Context for RequestContext<()> {
    fn lookup_object(&self, id: &rpc::ObjectId) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        self.session.lookup_object(id)
    }

    fn accepts_updates(&self) -> bool {
        false
    }
}

/// A simple temporary method to echo a reply.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Echo {
    /// A message to echo.
    msg: String,
}
#[typetag::deserialize(name = "echo")]
impl rpc::Method for Echo {}
rpc::decl_method! {Echo}

rpc::rpc_invoke_fn! {
    /// Implementation for calling "echo" on a session
    ///
    /// TODO RPC: Remove this. It shouldn't exist.
    async fn echo_on_session(_obj: Arc<Session>, method: Box<Echo>, _ctx:Box<dyn rpc::Context>) -> Result<Box<Echo>, rpc::RpcError> {
        Ok(method)
    }
}

/// The authentication scheme as enumerated in the spec.
///
/// Conceptually, an authentication scheme answers the question "How can the
/// Arti process know you have permissions to use or administer it?"
///
/// TODO RPC: The only supported one for now is "inherent:unix_path"
#[derive(Debug, Copy, Clone, serde::Deserialize)]
enum AuthenticationScheme {
    /// Inherent authority based on the ability to access an AF_UNIX address.
    #[serde(rename = "inherent:unix_path")]
    InherentUnixPath,
}

/// Method to implement basic authentication.  Right now only "I connected to
/// you so I must have permission!" is supported.
#[derive(Debug, serde::Deserialize)]
struct Authenticate {
    /// The authentication scheme as enumerated in the spec.
    ///
    /// TODO RPC: The only supported one for now is "inherent:unix_path"
    scheme: AuthenticationScheme,
}
#[typetag::deserialize(name = "auth:authenticate")]
impl rpc::Method for Authenticate {}
rpc::decl_method! {Authenticate}

/// An empty structure used for "okay" replies with no additional data.
///
/// TODO RPC: It would be good if we could specialize our serde impl so that we could just use () for this.
#[derive(Debug, serde::Serialize)]
struct Nil {}

/// An error during authentication.
#[derive(Debug, Clone, thiserror::Error, serde::Serialize)]
enum AuthenticationFailure {}

impl tor_error::HasKind for AuthenticationFailure {
    fn kind(&self) -> tor_error::ErrorKind {
        // TODO RPC not right.
        tor_error::ErrorKind::LocalProtocolViolation
    }
}

rpc::rpc_invoke_fn! {
    async fn authenticate_session(unauth: Arc<UnauthenticatedSession>, method: Box<Authenticate>, _ctx: Box<dyn rpc::Context>) -> Result<Nil, rpc::RpcError> {
        match method.scheme {
            // For now, we only support AF_UNIX connections, and we assume that if you have permission to open such a connection to us, you have permission to use Arti.
            // We will refine this later on!
            AuthenticationScheme::InherentUnixPath => {}
        }

        unauth.inner.inner.lock().expect("Poisoned lock").authenticated = true;
        Ok(Nil {})
    }
}

/// An error given when an RPC request is cancelled.
///
/// This is a separate type from [`crate::cancel::Cancelled`] since eventually
/// we want to move that type into a general-purpose location, and make it not
/// RPC-specific.
#[derive(thiserror::Error, Clone, Debug, serde::Serialize)]
#[error("RPC request was cancelled")]
pub(crate) struct RequestCancelled;
impl tor_error::HasKind for RequestCancelled {
    fn kind(&self) -> tor_error::ErrorKind {
        // TODO RPC: Can we do better here?
        tor_error::ErrorKind::Other
    }
}
