//! Implementation logic for RpcConn.
//!
//! Except for [`RpcConn`] itself, nothing in this module is a public API.
//! This module exists so that we can more easily audit the code that
//! touches the members of `RpcConn`.
//!
//! NOTE that many of the types and fields here have documented invariants.
//! Except if noted otherwise, these invariants only hold when nobody
//! is holding the lock on [`RequestState`].

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use crate::{
    msgs::{
        AnyRequestId, ObjectId,
        request::{IdGenerator, ValidatedRequest},
        response::ValidatedResponse,
    },
    nb_stream::PollingStream,
};

use super::{ProtoError, ShutdownError};

/// An identifier for a [`ResponseQueue`] within a [`RequestMap`].
trait QueueId {
    /// A tag type associated with responses in the identified queue.
    ///
    /// ("Polling" requests use tags to tell the user which response goes with which request.)
    type Tag: Sized;

    /// Find the queue identified by this `QueueId` within `map`,
    /// in order to wait for messages on it.
    fn get_queue_mut<'a>(
        &self,
        map: &'a mut RequestMap,
    ) -> Result<&'a mut ResponseQueue<Self>, ProtoError>;

    /// Given that we are polling on the queue identified by `self`,
    /// determine what we should do with `msg`.
    ///
    /// (Should we return it, drop it, or forward it to somebody else?)
    fn response_disposition<'a>(
        &self,
        map: &'a mut RequestMap,
        msg: &ValidatedResponse,
    ) -> ResponseDisposition<'a, Self>;

    /// Remove any state from `map` associated with `msg_id`.
    ///
    /// (If `msg_id` is absent, an error occurred that was not associated with any message ID.)
    fn remove_entry<'a>(&self, map: &'a mut RequestMap, msg_id: Option<&AnyRequestId>);

    /// Create and return a new RequestState to track a request associated with this kind of ID.
    fn new_entry() -> RequestState;
}

impl QueueId for AnyRequestId {
    type Tag = ();

    fn get_queue_mut<'a>(
        &self,
        map: &'a mut RequestMap,
    ) -> Result<&'a mut ResponseQueue<Self>, ProtoError> {
        match map.map.get_mut(self) {
            Some(RequestState::Waiting(s)) => Ok(s),
            None => Err(ProtoError::RequestCompleted),
        }
    }

    fn response_disposition<'a>(
        &self,
        map: &'a mut RequestMap,
        msg: &ValidatedResponse,
    ) -> ResponseDisposition<'a, Self> {
        if self == msg.id() {
            // This message is for us; no reason to look anything up.
            return ResponseDisposition::Return(());
        }

        match map.map.get_mut(msg.id()) {
            Some(RequestState::Waiting(q)) => ResponseDisposition::ForwardWaiting(q),
            None => ResponseDisposition::Ignore,
        }
    }

    fn remove_entry<'a>(&self, map: &'a mut RequestMap, _: Option<&AnyRequestId>) {
        map.map.remove(self);
    }

    /// Create and return a new RequestState to track a request associated with this kind of ID.
    fn new_entry() -> RequestState {
        RequestState::Waiting(ResponseQueue::default())
    }
}

/// A queue of responses used to alert a polling function about replies to
/// one or more requests.
#[derive(educe::Educe)]
#[educe(Default)]
struct ResponseQueue<Q: QueueId + ?Sized> {
    /// A queue of replies received with this request's identity.
    queue: VecDeque<(Q::Tag, ValidatedResponse)>,
    /// A condition variable used to wake a thread waiting for this request
    /// to have messages.
    ///
    /// We `notify` this condvar thread under one of three circumstances:
    ///
    /// * When we queue a response for this request.
    /// * When we store a fatal error affecting all requests in the RpcConn.
    /// * When the thread currently interacting with he [`PollingStream`] for this
    ///   RpcConn stops doing so, and the request waiting
    ///   on this thread has been chosen to take responsibility for interacting.
    ///
    /// Invariants:
    /// * The condvar is Some if (and only if) some thread is waiting
    ///   on it.
    waiter: Option<Arc<Condvar>>,
}

/// State held by the [`RpcConn`] for a single request ID.
enum RequestState {
    /// A request submitted by one of the `execute_*` functions:
    /// The user must call a "wait" function for this request specifically in order to get
    /// responses. This request has its own queue.
    Waiting(ResponseQueue<AnyRequestId>),
}

impl<Q: QueueId + ?Sized> ResponseQueue<Q> {
    /// Helper: Pop and return the next message for this request.
    ///
    /// If there are no queued messages, but a fatal error has occurred on the connection,
    /// return that.
    ///
    /// If there are no queued messages and no fatal error, return None.
    fn pop_next_msg(
        &mut self,
        fatal: &Option<ShutdownError>,
    ) -> Option<Result<(Q::Tag, ValidatedResponse), ShutdownError>> {
        if let Some(m) = self.queue.pop_front() {
            Some(Ok(m))
        } else {
            fatal.as_ref().map(|f| Err(f.clone()))
        }
    }

    /// Queue `response` for this request, and alert the condvar (if any).
    fn push_back_and_alert(&mut self, tag: Q::Tag, response: ValidatedResponse) {
        self.queue.push_back((tag, response));

        if let Some(cv) = &self.waiter {
            cv.notify_one();
        }
    }
}

/// A map from a [`QueueId`] to a request state.
#[derive(Default)]
struct RequestMap {
    /// A map from request ID to the state for that request ID.
    ///
    /// Entries are added to this map when a request is sent,
    /// and removed when the request encounters
    /// an error or a final response.
    map: HashMap<AnyRequestId, RequestState>,
}

/// An action to take with a given message.
///
/// Returned by [`QueueId::response_disposition`]
enum ResponseDisposition<'a, Q: QueueId + ?Sized> {
    /// This message is for the queue that we are waiting for;
    /// we should return it to the caller.
    Return(Q::Tag),

    /// This message if for a dead request that was probably cancelled;
    /// we should drop it.
    Ignore,

    /// This message is for some other request; we should instead forward it to that request's queue.
    ForwardWaiting(&'a mut ResponseQueue<AnyRequestId>),
}

/// Mutable state to implement receiving replies on an RpcConn.
struct ReceiverState {
    /// Helper to assign connection- unique IDs to any requests without them.
    id_gen: IdGenerator,
    /// A fatal error, if any has occurred.
    fatal: Option<ShutdownError>,
    /// A map from request ID to the corresponding state.
    ///
    /// There is an entry in this map for every request that we have sent,
    /// unless we have received a final response for that request,
    /// or we have cancelled that request.
    ///
    /// (TODO: We might handle cancelling differently.)
    pending: RequestMap,
    /// A steam that we use to send requests and receive replies from Arti.
    ///
    /// Invariants:
    ///
    /// * If this is None, a thread is polling and will take responsibility
    ///   for liveness.
    /// * If this is Some, no-one is polling and anyone who cares about liveness
    ///   must take on the interactor role.
    ///
    /// (Therefore, when it becomes Some, we must signal a cv, if any is set.)
    stream: Option<PollingStream>,
}

impl RequestMap {
    /// Notify an arbitrarily chosen request's condvar.
    fn alert_anybody(&self) {
        // TODO: This is O(n) in the worst case.
        //
        // But with luck, nobody will make a million requests and
        // then wait on them one at a time?
        for ent in self.map.values() {
            if let RequestState::Waiting(ResponseQueue {
                waiter: Some(cv), ..
            }) = ent
            {
                cv.notify_one();
                return;
            }
        }
    }

    /// Notify the condvar for every request.
    fn alert_everybody(&self) {
        for ent in self.map.values() {
            if let RequestState::Waiting(ResponseQueue {
                waiter: Some(cv), ..
            }) = ent
            {
                // By our rules, each condvar is waited on by precisely one thread.
                // So we call `notify_one` even though we are trying to wake up everyone.
                cv.notify_one();
            }
        }
    }
}

/// Object to receive messages on an RpcConn.
///
/// This is a crate-internal abstraction.
/// It's separate from RpcConn for a few reasons:
///
/// - So we can keep polling the channel while the RpcConn has
///   been dropped.
/// - So we can hold the lock on this part without being blocked on threads writing.
/// - Because this is the only part that for which
///   `RequestHandle` needs to keep a reference.
pub(super) struct Receiver {
    /// Mutable state.
    ///
    /// This lock should only be held briefly, and never while interacting with the
    /// `PollingStream`.
    state: Mutex<ReceiverState>,
}

/// An open RPC connection to Arti.
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct RpcConn {
    /// The receiver object for this conn.
    ///
    /// It's in an `Arc<>` so that we can share it with the RequestHandles.
    #[educe(Debug(ignore))]
    receiver: Arc<Receiver>,

    /// A writer that we use to queue requests to be sent back to Arti.
    writer: crate::nb_stream::WriteHandle,

    /// If set, we are authenticated and we have negotiated a session that has
    /// this ObjectID.
    pub(super) session: Option<ObjectId>,
}

/// Instruction to alert some additional condvar(s) before releasing our lock and returning
///
/// Any code which receives one of these must pass the instruction on to someone else,
/// until, eventually, the instruction is acted on in [`Receiver::wait_on_message_for`].
#[must_use]
#[derive(Debug)]
enum AlertWhom {
    /// We don't need to alert anybody;
    /// we have not taken the stream, or registered our own condvar:
    /// therefore nobody expects us to take the stream.
    Nobody,
    /// We have taken the stream or been alerted via our condvar:
    /// therefore, we are responsible for making sure
    /// that _somebody_ takes the stream.
    ///
    /// We should therefore alert somebody if nobody currently has the stream.
    Anybody,
    /// We have been the first to encounter a fatal error.
    /// Therefore, we should inform _everybody_.
    Everybody,
}

impl RpcConn {
    /// Construct a new RpcConn with a given PollingStream.
    pub(super) fn new(stream: PollingStream) -> Self {
        let writer = stream.writer();
        Self {
            receiver: Arc::new(Receiver {
                state: Mutex::new(ReceiverState {
                    id_gen: IdGenerator::default(),
                    fatal: None,
                    pending: RequestMap::default(),
                    stream: Some(stream),
                }),
            }),
            writer,
            session: None,
        }
    }

    /// Send the request in `msg` on this connection, and return a RequestHandle
    /// to wait for a reply.
    ///
    /// We validate `msg` before sending it out, and reject it if it doesn't
    /// make sense. If `msg` has no `id` field, we allocate a new one
    /// according to the rules in [`IdGenerator`].
    ///
    /// Limitation: We don't preserved unrecognized fields in the framing and meta
    /// parts of `msg`.  See notes in `request.rs`.
    pub(super) fn send_request(&self, msg: &str) -> Result<super::RequestHandle, ProtoError> {
        let id = self.send_request_impl::<AnyRequestId>(msg)?;
        Ok(super::RequestHandle {
            conn: Mutex::new(Arc::clone(&self.receiver)),
            id,
        })
    }

    /// Helper for send_request.
    ///
    /// We use the [`QueueId`] parameter to determine what kind of queue will
    fn send_request_impl<Q: QueueId>(&self, msg: &str) -> Result<AnyRequestId, ProtoError> {
        use std::collections::hash_map::Entry::*;

        let mut state = self.receiver.state.lock().expect("poisoned");
        if let Some(f) = &state.fatal {
            // If there's been a fatal error we don't even try to send the request.
            return Err(f.clone().into());
        }

        // Convert this request into validated form (with an ID) and re-encode it.
        let valid: ValidatedRequest =
            ValidatedRequest::from_string_loose(msg, || state.id_gen.next_id())?;

        // Do the necessary housekeeping before we send the request, so that
        // we'll be able to understand the replies.
        let id = valid.id().clone();
        match state.pending.map.entry(id.clone()) {
            Occupied(_) => return Err(ProtoError::RequestIdInUse),
            Vacant(v) => {
                v.insert(Q::new_entry());
            }
        }
        // Release the lock on the ReceiverState here; the two locks must not overlap.
        drop(state);

        // NOTE: This is the only block of code that holds the writer lock!
        let write_outcome = self.writer.send_valid(&valid);

        match write_outcome {
            Err(e) => {
                // A failed write is a fatal error for everybody.
                let e = ShutdownError::Write(Arc::new(e));
                let mut state = self.receiver.state.lock().expect("poisoned");
                if state.fatal.is_none() {
                    state.fatal = Some(e.clone());
                    state.pending.alert_everybody();
                }
                Err(e.into())
            }

            Ok(()) => Ok(id),
        }
    }
}

impl Receiver {
    /// Wait until there is either a fatal error on this connection,
    /// _or_ there is a new message for the queue with the provided waiting request `id`.
    /// Return that message, or a copy of the fatal error.
    pub(super) fn wait_on_message_for(
        &self,
        id: &AnyRequestId,
    ) -> Result<ValidatedResponse, ProtoError> {
        let ((), response) = self.wait_on_message_for_queue(id)?;
        Ok(response)
    }

    /// Wait until there is either a fatal error on this connection,
    /// _or_ there is a new message for the queue with the provided `queue_id`.
    /// Return that message, or a copy of the fatal error.
    fn wait_on_message_for_queue<Q: QueueId>(
        &self,
        queue_id: &Q,
    ) -> Result<(Q::Tag, ValidatedResponse), ProtoError> {
        // Here in wait_on_message_for_impl, we do the the actual work
        // of waiting for the message.
        let state = self.state.lock().expect("poisoned");
        let (result, mut state, should_alert) = self.wait_on_message_for_impl(state, queue_id);

        // Great; we have a message or a fatal error.  All we need to do now
        // is to restore our invariants before we drop state_lock.
        //
        // (It would be a bug to return early without restoring the invariants,
        // so we'll use an IEFE pattern to prevent "?" and "return Err".)
        #[allow(clippy::redundant_closure_call)]
        (|| {
            // "final" in this case means that we are not expecting any more
            // replies for this request.
            let (msg_id, is_final) = match &result {
                Err(_) => (None, true),
                Ok(r) => (Some(r.1.id()), r.1.is_final()),
            };

            if is_final {
                // Note 1: It might be cleaner to use Entry::remove(), but Entry is not
                // exactly the right shape for us; see note in
                // wait_on_message_for_impl.

                // Note 2: This remove isn't necessary if `result` is
                // RequestCancelled, but it won't hurt.

                // Note 3: On DuplicateWait, it is not totally clear whether we should
                // remove or not.  But that's an internal error that should never occur,
                // so it is probably okay if we let the _other_ waiter keep on trying.
                queue_id.remove_entry(&mut state.pending, msg_id);
            }

            match should_alert {
                AlertWhom::Nobody => {}
                AlertWhom::Anybody if state.stream.is_none() => {}
                AlertWhom::Anybody => state.pending.alert_anybody(),
                AlertWhom::Everybody => state.pending.alert_everybody(),
            }
        })();

        result
    }

    /// Helper to implement [`wait_on_message_for`](Self::wait_on_message_for).
    ///
    /// Takes a `MutexGuard` as one of its arguments, and returns an equivalent
    /// `MutexGuard` on completion.
    ///
    /// The caller is responsible for:
    ///
    /// - Removing the appropriate entry from `pending`, if the result
    ///   indicates that no more messages will be received for this request.
    /// - Possibly, notifying one or more condvars,
    ///   depending on the resulting `AlertWhom`.
    ///
    /// The caller must not drop the `MutexGuard` until it has done the above.
    #[allow(clippy::type_complexity)]
    fn wait_on_message_for_impl<'a, Q: QueueId>(
        &'a self,
        mut state_lock: MutexGuard<'a, ReceiverState>,
        queue_id: &Q,
    ) -> (
        Result<(Q::Tag, ValidatedResponse), ProtoError>,
        MutexGuard<'a, ReceiverState>,
        AlertWhom,
    ) {
        // At this point, we have not registered on a condvar, and we have not
        // taken the PollingStream.
        // Therefore, we do not yet need to ensure that anybody else takes the PollingStream.
        //
        // TODO: It is possibly too easy to forget to set this,
        // or to set it to a less "alerty" value.  Refactoring might help;
        // see discussion at
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2258#note_3047267
        let mut should_alert = AlertWhom::Nobody;

        let mut state: &mut ReceiverState = &mut state_lock;

        // Initialize `this_ent` to our own entry in the pending table.
        let mut this_ent = match queue_id.get_queue_mut(&mut state.pending) {
            Ok(ent) => ent,
            Err(err) => return (Err(err), state_lock, should_alert),
        };

        let mut stream = loop {
            // Note: It might be nice to use a hash_map::Entry here, but it
            // doesn't really work the way we want.  The `entry()` API is always
            // ready to insert, and requires that we clone `id`.  But what we
            // want in this case is something that would give us a .remove()able
            // Entry only if one is present.
            if this_ent.waiter.is_some() {
                // This is an internal error; nobody should be able to cause this.
                return (Err(ProtoError::DuplicateWait), state_lock, should_alert);
            }

            if let Some(ready) = this_ent.pop_next_msg(&state.fatal) {
                // There is a reply for us, or a fatal error.
                return (ready.map_err(ProtoError::from), state_lock, should_alert);
            }

            // If we reach this point, we are about to either take the stream or
            // register a cv.  This means that when we return, we need to make
            // sure that at least one other cv gets notified.
            should_alert = AlertWhom::Anybody;

            if let Some(r) = state.stream.take() {
                // Nobody else is polling; we have to do it.
                break r;
            }

            // Somebody else is polling; register a condvar.
            let cv = Arc::new(Condvar::new());
            this_ent.waiter = Some(Arc::clone(&cv));

            state_lock = cv.wait(state_lock).expect("poisoned lock");
            state = &mut state_lock;
            // Restore `this_ent`...
            let e = match queue_id.get_queue_mut(&mut state.pending) {
                Ok(ent) => ent,
                Err(err) => return (Err(err), state_lock, should_alert),
            };
            this_ent = e;
            // ... And un-register our condvar.
            this_ent.waiter = None;

            // We have been notified: either there is a reply or us,
            // or we are supposed to take the stream.  We'll find out on our
            // next time through the loop.
        };

        let (result, mut state_lock, should_alert) =
            self.read_until_message_for(state_lock, &mut stream, queue_id);
        // Put the stream back.
        state_lock.stream = Some(stream);

        (result.map_err(ProtoError::from), state_lock, should_alert)
    }

    /// Interact with `stream`, writing any queued messages,
    /// reading messages, and
    /// delivering them as appropriate, until we find one for the queue `queue_id`
    /// or a fatal error occurs.
    ///
    /// Return that message or error, along with a `MutexGuard`.
    ///
    /// The caller is responsible for restoring the following state before
    /// dropping the `MutexGuard`:
    ///
    /// - Putting `stream` back into the `stream` field.
    /// - Other invariants as discussed in wait_on_message_for_impl.
    #[allow(clippy::type_complexity)]
    fn read_until_message_for<'a, Q: QueueId>(
        &'a self,
        mut state_lock: MutexGuard<'a, ReceiverState>,
        stream: &mut PollingStream,
        queue_id: &Q,
    ) -> (
        Result<(Q::Tag, ValidatedResponse), ShutdownError>,
        MutexGuard<'a, ReceiverState>,
        AlertWhom,
    ) {
        loop {
            // Importantly, we drop the state lock while we are polling.
            // This is okay, since all our invariants should hold at this point.
            drop(state_lock);

            let result = match stream.interact() {
                Err(e) => Err(ShutdownError::Read(Arc::new(e))),
                Ok(None) => Err(ShutdownError::ConnectionClosed),
                Ok(Some(m)) => m.try_validate().map_err(ShutdownError::from),
            };

            state_lock = self.state.lock().expect("poisoned lock");
            let state = &mut state_lock;

            let response = match result {
                Ok(m) => m,
                Err(e) => {
                    // This is a fatal error on the whole connection.
                    //
                    // If it's the first one encountered, queue the error.
                    // In any case, return it.
                    if state.fatal.is_none() {
                        state.fatal = Some(e.clone());
                    }
                    return (Err(e), state_lock, AlertWhom::Everybody);
                }
            };

            match queue_id.response_disposition(&mut state.pending, &response) {
                ResponseDisposition::Return(tag) => {
                    // This only is for us, so there's no need to alert anybody specific
                    // or queue it.
                    return (Ok((tag, response)), state_lock, AlertWhom::Anybody);
                }
                ResponseDisposition::ForwardWaiting(queue) => {
                    queue.push_back_and_alert((), response);
                }
                ResponseDisposition::Ignore => {
                    // Nothing wanted this response any longer.
                    // _Probably_ this means that we decided to cancel the
                    // request but Arti sent this response before it handled
                    // our cancellation.
                }
            }
        }
    }
}
