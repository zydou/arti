use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures::{
    channel::mpsc,
    stream::{FusedStream, FuturesUnordered},
    FutureExt, Sink, SinkExt, StreamExt,
};

use crate::{
    cancel::{Cancel, CancelHandle},
    msgs::{BoxedResponse, BoxedResponseBody, Request, RequestId},
};

/// A session with an RPC client.  
///
/// Tracks information that persists from one request to another.
pub(crate) struct Session {
    /// The mutable state of this session
    inner: Mutex<Inner>,
}

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
                            let fut = fut.map(|r| r.unwrap_or_else(|_cancelled|
                                // TODO RPC real error type
                                BoxedResponse{ id, body: BoxedResponseBody::Error(Box::new("hey i got cancelled"))}));
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
    ) -> BoxedResponse {
        // TODO RPC: This function does not yet actually run the commands!  it just echoes the request back.

        let encoded = format!("{:?}", request.command);
        if let Some(tx) = tx_updates {
            let mut tx = tx.clone();
            let _ = tx
                .send(BoxedResponse {
                    id: request.id.clone(),
                    body: BoxedResponseBody::Update(Box::new("thinking...")),
                })
                .await;
        }
        #[derive(serde::Serialize)]
        struct Echo {
            echo: String,
        }
        BoxedResponse {
            id: request.id,
            body: BoxedResponseBody::Result(Box::new(Echo { echo: encoded })),
        }
    }
}
