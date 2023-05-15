//! RPC connection support, mainloop, and protocol implementation.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
};

use arti_client::TorClient;
use asynchronous_codec::JsonCodecError;
use futures::{
    channel::mpsc,
    stream::{FusedStream, FuturesUnordered},
    FutureExt, Sink, SinkExt as _, StreamExt,
};
use pin_project::pin_project;
use rpc::dispatch::BoxedUpdateSink;
use serde_json::error::Category as JsonErrorCategory;
use tor_async_utils::SinkExt as _;
use tor_rtcompat::PreferredRuntime;

use crate::{
    cancel::{Cancel, CancelHandle},
    err::RequestParseError,
    msgs::{BoxedResponse, FlexibleRequest, Request, RequestId, ResponseBody},
    objmap::ObjMap,
};

use tor_rpcbase as rpc;

/// An open connection from an RPC client.  
///
/// Tracks information that persists from one request to another.
pub struct Connection {
    /// The mutable state of this connection
    inner: Mutex<Inner>,

    /// Lookup table to find the implementations for methods
    /// based on RPC object and method types.
    dispatch_table: Arc<rpc::DispatchTable>,
}
impl rpc::Object for Connection {}
rpc::decl_object! {Connection}

/// The inner, lock-protected part of an RPC connection.
struct Inner {
    /// Map from request ID to handles; used when we need to cancel a request.
    //
    // TODO: We have two options here for handling colliding IDs.  We can either turn
    // this into a multimap, or we can declare that cancelling a request only
    // cancels the most recent request sent with that ID.
    inflight: HashMap<RequestId, CancelHandle>,

    /// An object map used to look up most objects by ID, and keep track of
    /// which objects are owned by this connection.
    objects: ObjMap,

    /// A `TorClient` object that we will give out if the connection is successfully
    /// authenticated, _and not otherwise_.
    client: Arc<dyn rpc::Object>,
}

/// How many updates can be pending, per connection, before they start to block?
const UPDATE_CHAN_SIZE: usize = 128;

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

impl Connection {
    /// Create a new connection.
    pub(crate) fn new(
        dispatch_table: Arc<rpc::DispatchTable>,
        client: Arc<dyn rpc::Object>,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                inflight: HashMap::new(),
                objects: ObjMap::new(),
                client,
            }),
            dispatch_table,
        }
    }

    /// Look up a given object by its object ID relative to this connection.
    fn lookup_object(
        self: &Arc<Self>,
        id: &rpc::ObjectId,
    ) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        let inner = self.inner.lock().expect("lock poisoned");

        if id.as_ref() == "connection" {
            Ok(self.clone())
        } else {
            inner
                .objects
                .lookup(crate::objmap::GenIdx::try_decode(id)?)
                .ok_or(rpc::LookupError::NoObject(id.clone()))
        }
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

    /// Run in a loop, decoding JSON requests from `input` and
    /// writing JSON responses onto `output`.
    pub async fn run<IN, OUT>(
        self: Arc<Self>,
        input: IN,
        output: OUT,
    ) -> Result<(), ConnectionError>
    where
        IN: futures::AsyncRead + Send + Sync + Unpin + 'static,
        OUT: futures::AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let write = Box::pin(asynchronous_codec::FramedWrite::new(
            output,
            crate::streams::JsonLinesEncoder::<BoxedResponse>::default(),
        ));

        let read = Box::pin(
            asynchronous_codec::FramedRead::new(
                input,
                asynchronous_codec::JsonCodec::<(), FlexibleRequest>::new(),
            )
            .fuse(),
        );

        self.run_loop(read, write).await
    }

    /// Run in a loop, handling requests from `request_stream` and writing
    /// responses onto `response_stream`.
    pub(crate) async fn run_loop(
        self: Arc<Self>,
        mut request_stream: BoxedRequestStream,
        mut response_sink: BoxedResponseSink,
    ) -> Result<(), ConnectionError> {
        // This function will multiplex on three streams:
        // * `request_stream` -- a stream of incoming requests from the client.
        // * `finished_requests` -- a stream of requests that are done.
        // * `rx_response` -- a stream of updates and final responses sent from
        //   in-progress tasks. (We put updates and final responsese onto the
        //   same channel to ensure that they stay in-order for each method
        //   invocation.
        //
        // Note that the blocking behavior here is deliberate: We want _all_ of
        // these reads to start blocking when response_sink.send is blocked.

        let (tx_response, mut rx_response) = mpsc::channel::<BoxedResponse>(UPDATE_CHAN_SIZE);
        let mut finished_requests = FuturesUnordered::new();
        finished_requests.push(futures::future::pending().boxed());

        'outer: loop {
            futures::select! {
                r = finished_requests.next() => {
                    // A task is done, so we can forget about it.
                    let () = r.expect("Somehow, future::pending() terminated.");
                }

                r = rx_response.next() => {
                    // The future for some request has sent a response (success,
                    // failure, or update), so we can inform the client.
                    let update = r.expect("Somehow, tx_update got closed.");
                    debug_assert!(! update.body.is_final());
                    // Calling `await` here (and below) is deliberate: we _want_
                    // to stop reading the client's requests if the client is
                    // not reading their responses (or not) reading them fast
                    // enough.
                    response_sink.send(update).await.map_err(|_| ConnectionError::WriteFailed)?;
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
                                JsonCodecError::Io(_) => return Err(ConnectionError::ReadFailed),
                                JsonCodecError::Json(e) => match e.classify() {
                                    JsonErrorCategory::Eof => break 'outer,
                                    JsonErrorCategory::Io => return Err(ConnectionError::ReadFailed),
                                    JsonErrorCategory::Syntax => RequestParseError::InvalidJson,
                                    JsonErrorCategory::Data => RequestParseError::NotAnObject,
                                }
                            };

                            response_sink
                                .send(
                                    BoxedResponse::from_error(None, error)
                                ).await.map_err(|_| ConnectionError::WriteFailed)?;

                            // TODO RPC: Perhaps we should keep going on the NotAnObject case?
                            //      (InvalidJson is not recoverable!)
                            break 'outer;
                        }
                        Some(Ok(FlexibleRequest::Invalid(bad_req))) => {
                            response_sink
                                .send(
                                    BoxedResponse::from_error(bad_req.id().cloned(), bad_req.error())
                                ).await.map_err(|_| ConnectionError::WriteFailed)?;
                            if bad_req.id().is_none() {
                                // The spec says we must close the connection in this case.
                                break 'outer;
                            }
                        }
                        Some(Ok(FlexibleRequest::Valid(req))) => {
                            // We have a request. Time to launch it!
                            let fut = self.run_method_and_deliver_response(tx_response.clone(), req);
                            finished_requests.push(fut.boxed());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Invoke `request` and send all of its responses to `tx_response`.
    async fn run_method_and_deliver_response(
        self: &Arc<Self>,
        mut tx_response: mpsc::Sender<BoxedResponse>,
        request: Request,
    ) {
        let Request {
            id,
            obj,
            meta,
            method,
        } = request;

        let update_sender: BoxedUpdateSink = if meta.updates {
            let id_clone = id.clone();
            let sink =
                tx_response
                    .clone()
                    .with_fn(move |obj: Box<dyn erased_serde::Serialize + Send>| {
                        Result::<BoxedResponse, _>::Ok(BoxedResponse {
                            id: Some(id_clone.clone()),
                            body: ResponseBody::Update(obj),
                        })
                    });
            Box::pin(sink)
        } else {
            let sink = futures::sink::drain().sink_err_into();
            Box::pin(sink)
        };

        // Create `run_method_lowlevel` future, and make it cancellable.
        let fut = self.run_method_lowlevel(update_sender, obj, method);
        let (handle, fut) = Cancel::new(fut);
        self.register_request(id.clone(), handle);

        // Run the cancellable future to completion, and figure out how to respond.
        let body = match fut.await {
            Ok(Ok(value)) => ResponseBody::Success(value),
            // TODO: If we're going to box this, let's do so earlier.
            Ok(Err(err)) => {
                if err.is_internal() {
                    tracing::warn!(
                        "Reporting an internal error on an RPC connection: {:?}",
                        err
                    );
                }
                ResponseBody::Error(Box::new(err))
            }
            Err(_cancelled) => ResponseBody::Error(Box::new(rpc::RpcError::from(RequestCancelled))),
        };

        // Send the response.
        //
        // (It's okay to ignore the error here, since it can only mean that the
        // RPC connection has closed.)
        let _ignore_err = tx_response
            .send(BoxedResponse {
                id: Some(id.clone()),
                body,
            })
            .await;

        // Unregister the request.
        self.remove_request(&id);
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
        tx_updates: rpc::dispatch::BoxedUpdateSink,
        obj: rpc::ObjectId,
        method: Box<dyn rpc::DynMethod>,
    ) -> Result<Box<dyn erased_serde::Serialize + Send + 'static>, rpc::RpcError> {
        let obj = self.lookup_object(&obj)?;

        let context: Box<dyn rpc::Context> = Box::new(RequestContext {
            conn: Arc::clone(self),
        });
        self.dispatch_table
            .invoke(obj, method, context, tx_updates)?
            .await
    }
}

/// A failure that results in closing a [`Connection`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionError {
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
struct RequestContext {
    /// The underlying RPC connection.
    conn: Arc<Connection>,
}

impl rpc::Context for RequestContext {
    fn lookup_object(&self, id: &rpc::ObjectId) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        self.conn.lookup_object(id)
    }

    fn register_owned(&self, object: Arc<dyn rpc::Object>) -> rpc::ObjectId {
        self.conn
            .inner
            .lock()
            .expect("Lock poisoned")
            .objects
            .insert_strong(object)
            .encode()
    }

    fn register_weak(&self, object: Arc<dyn rpc::Object>) -> rpc::ObjectId {
        self.conn
            .inner
            .lock()
            .expect("Lock poisoned")
            .objects
            .insert_weak(object)
            .encode()
    }
}

/// A simple temporary method to echo a reply.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Echo {
    /// A message to echo.
    msg: String,
}
rpc::decl_method! { "arti:x-echo" => Echo}
impl rpc::Method for Echo {
    type Output = Echo;
    type Update = rpc::NoUpdates;
}

/// Implementation for calling "echo" on a TorClient.
///
/// TODO RPC: Remove this. It shouldn't exist.
async fn echo_on_session(
    _obj: Arc<TorClient<PreferredRuntime>>,
    method: Box<Echo>,
    _ctx: Box<dyn rpc::Context>,
) -> Result<Echo, rpc::RpcError> {
    Ok(*method)
}

rpc::rpc_invoke_fn! {
    echo_on_session(TorClient<PreferredRuntime>,Echo);

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

/// A reply from the `Authenticate` method.
#[derive(Debug, serde::Serialize)]
struct AuthenticateReply {
    /// An owned reference to a `TorClient` object.
    client: Option<rpc::ObjectId>,
}

rpc::decl_method! {"auth:authenticate" => Authenticate}
impl rpc::Method for Authenticate {
    type Output = AuthenticateReply;
    type Update = rpc::NoUpdates;
}

/// An error during authentication.
#[derive(Debug, Clone, thiserror::Error, serde::Serialize)]
enum AuthenticationFailure {}

impl tor_error::HasKind for AuthenticationFailure {
    fn kind(&self) -> tor_error::ErrorKind {
        // TODO RPC not right.
        tor_error::ErrorKind::LocalProtocolViolation
    }
}

/// Invoke the "authenticate" method on a connection.
///
/// TODO RPC: This behavior is wrong; we'll need to fix it to be all
/// capabilities-like.
async fn authenticate_connection(
    unauth: Arc<Connection>,
    method: Box<Authenticate>,
    ctx: Box<dyn rpc::Context>,
) -> Result<AuthenticateReply, rpc::RpcError> {
    match method.scheme {
        // For now, we only support AF_UNIX connections, and we assume that if
        // you have permission to open such a connection to us, you have
        // permission to use Arti. We will refine this later on!
        AuthenticationScheme::InherentUnixPath => {}
    }

    let client = Arc::clone(&unauth.inner.lock().expect("Poisoned lock").client);

    let client = Some(ctx.register_weak(client));
    Ok(AuthenticateReply { client })
}
rpc::rpc_invoke_fn! {
    authenticate_connection(Connection, Authenticate);
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
