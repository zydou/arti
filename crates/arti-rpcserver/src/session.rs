use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures::{
    channel::mpsc,
    stream::{FusedStream, FuturesUnordered},
    FutureExt, Sink, SinkExt, StreamExt,
};
use pin_project::pin_project;

use crate::{
    cancel::{Cancel, CancelHandle},
    msgs::{BoxedResponse, BoxedResponseBody, Request, RequestId},
};

use tor_rpccmd as rpc;

/// A session with an RPC client.  
///
/// Tracks information that persists from one request to another.
pub(crate) struct Session {
    /// The mutable state of this session
    inner: Mutex<Inner>,
}

impl rpc::Object for Session {}
rpc::decl_object! {Session}

/// The inner, lock-protected part of a session.
struct Inner {
    /// Map from request ID to handles; used when we need to cancel a request.
    //
    // TODO: We have two options here for handling colliding IDs.  We can either turn
    // this into a multimap, or we can declare that cancelling a request only
    // cancels the most recent request sent with that ID.
    inflight: HashMap<RequestId, CancelHandle>,
}

/// How many updates can be pending, per session, before they start to block?
const UPDATE_CHAN_SIZE: usize = 128;

/// Channel type used to send updates to the main session loop.
type UpdateSender = mpsc::Sender<BoxedResponse>;

impl Session {
    /// Create a new session.
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                inflight: HashMap::new(),
            }),
        }
    }

    /// Look up a given object by its object ID relative to this session.
    fn lookup_object(
        self: &Arc<Self>,
        id: &rpc::ObjectId,
    ) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        if id.as_ref() == "session" {
            return Ok(self.clone());
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
    pub(crate) async fn run_loop<IN, OUT>(
        self: Arc<Self>,
        mut request_stream: IN,
        mut response_sink: OUT,
    ) -> anyhow::Result<()>
    // XXXX Make a real error type and remove this dependency.
    where
        IN: FusedStream<Item = Result<Request, asynchronous_codec::JsonCodecError>> + Unpin,
        OUT: Sink<BoxedResponse> + Unpin,
        OUT::Error: std::error::Error + Send + Sync + 'static,
    {
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
                    response_sink.send(r).await?;
                }

                r = rx_update.next() => {
                    // The future for some request has sent an update, so we can
                    // inform the client.
                    let update = r.expect("Somehow, tx_update got closed.");
                    debug_assert!(! update.body.is_final());
                    response_sink.send(update).await?
                }

                req = request_stream.next() => {
                    match req {
                        None => {
                            // We've reached the end of the stream of requests;
                            // time to close.
                            break 'outer;
                        }
                        Some(Err(e)) => {
                            // We got a parse error from the JSON codec.

                            // TODO RPC: This is out-of-spec, but we may as well do something on a parse error.
                            response_sink
                                .send(BoxedResponse {
                                    id: RequestId::Str("-----".into()),
                                    // TODO RPC real error type
                                    body: BoxedResponseBody::Error(Box::new(format!("Parse error: {}", e)))
                                }).await?;

                            // TODO RPC: Perhaps we should keep going? (Only if this is an authenticated session!)
                            break 'outer;
                        }
                        Some(Ok(req)) => {
                            // We have a request. Time to launch it!

                            let tx_channel = req.meta.updates.then(|| &tx_update);
                            let id = req.id.clone();
                            let fut = self.run_command_lowlevel(tx_channel, req);
                            let (handle, fut) = Cancel::new(fut);
                            self.register_request(id.clone(), handle);
                            let fut = fut.map(|r| match r {
                                Ok(Ok(v)) => BoxedResponse { id, body: BoxedResponseBody::Result(v) },
                                Ok(Err(e)) => BoxedResponse { id, body: e.into() },
                                // TODO RPC: This is not the correct error type.
                                Err(_cancelled) =>  BoxedResponse{ id, body: BoxedResponseBody::Error(Box::new("hey i got cancelled")) }
                            });


                            finished_requests.push(fut.boxed());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Run a single command, and return its final response.
    ///
    /// If `tx_updates` is provided, and this command generates updates, it
    /// should send those updates on `tx_updates`
    ///
    /// Note that this function is able to send responses with IDs that do not
    /// match the original.  It should enforce correct IDs on whatever response
    /// it generates.
    async fn run_command_lowlevel(
        self: &Arc<Self>,
        tx_updates: Option<&UpdateSender>,
        request: Request,
    ) -> Result<Box<dyn erased_serde::Serialize + Send + 'static>, rpc::RpcError> {
        let Request {
            id, obj, command, ..
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

        rpc::invoke_command(obj, command, context)?.await
    }
}

#[pin_project]
struct RequestContext<T> {
    session: Arc<Session>,
    id: RequestId,
    #[pin]
    reply_tx: T,
}

impl<T> Sink<Box<dyn erased_serde::Serialize + Send + 'static>> for RequestContext<T>
where
    T: Sink<BoxedResponse>,
{
    type Error = rpc::SendUpdateError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.reply_tx
            .poll_ready(cx)
            .map_err(|_| rpc::SendUpdateError::RequestCancelled)
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: Box<dyn erased_serde::Serialize + Send + 'static>,
    ) -> Result<(), Self::Error> {
        let this = self.project();
        let item = BoxedResponse {
            id: this.id.clone(),
            body: BoxedResponseBody::Update(item),
        };
        this.reply_tx
            .start_send(item)
            .map_err(|_| rpc::SendUpdateError::RequestCancelled)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.reply_tx
            .poll_flush(cx)
            .map_err(|_| rpc::SendUpdateError::RequestCancelled)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
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

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Err(rpc::SendUpdateError::NoUpdatesWanted))
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        _item: Box<dyn erased_serde::Serialize + Send + 'static>,
    ) -> Result<(), Self::Error> {
        Err(rpc::SendUpdateError::NoUpdatesWanted)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
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

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Echo {
    msg: String,
}
#[typetag::deserialize(name = "echo")]
impl rpc::Command for Echo {}
rpc::decl_command! {Echo}

rpc::rpc_invoke_fn! {
    /// Implementation for calling "echo" on a session
    ///
    /// TODO RPC: Remove this. It shouldn't exist.
    async fn echo_on_session(_obj: Arc<Session>, cmd: Box<Echo>, _ctx:Box<dyn rpc::Context>) -> Result<Box<Echo>, rpc::RpcError> {
        Ok(cmd)
    }
}
