//! Implementation logic for RpcConn.
//!
//! Except for [`RpcConn`] itself, nothing in this module is a public API.
//! This module exists so that we can more easily audit the code that
//! touches the members of `RpcConn`.
//!
//! NOTE that many of the types and fields here have documented invariants.
//! Except if noted otherwise, these invariants only hold when nobody
//! is holding the lock on [`State`].
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

use crate::{
    llconn,
    msgs::{
        request::{IdGenerator, LooseParsedRequest, ValidatedRequest},
        response::ValidatedResponse,
        AnyRequestId,
    },
};

use super::{CmdError, ShutdownError};

/// State held by the [`RpcConn`] for a single request ID.
#[derive(Default)]
struct RequestState {
    /// A queue of replies received with this request's identity.
    queue: VecDeque<ValidatedResponse>,
    /// A condition variable used to wake a thread waiting for this request
    /// to have messages.
    ///
    /// We `notify` this condvar thread under one of three circumstances:
    ///
    /// * When we queue a response for this request.
    /// * When we store a fatal error affecting all requests in the RpcConn.
    /// * When the thread currently reading from the [`llconn::Reader`] for this
    ///   RpcConn stops doing so, and the request waiting
    ///   on this thread has been chosen to take responsibility for reading.
    ///
    /// Invariants:
    /// * The condvar is Some if (and only if) some thread is waiting
    ///   on it.
    waiter: Option<Arc<Condvar>>,
}

impl RequestState {
    /// Helper: Pop and return the next message for this request.
    ///
    /// If there are no queued messages, but a fatal error has occurred on the connection,
    /// return that.
    ///
    /// If there are no queued messages and no fatal error, return None.
    fn pop_next_msg(
        &mut self,
        fatal: &Option<ShutdownError>,
    ) -> Option<Result<ValidatedResponse, ShutdownError>> {
        if let Some(m) = self.queue.pop_front() {
            Some(Ok(m))
        } else {
            fatal.as_ref().map(|f| Err(f.clone()))
        }
    }
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
    pending: HashMap<AnyRequestId, RequestState>,
    /// A reader that we use to receive replies from Arti.
    ///
    /// Invariants:
    ///
    /// * If this is None, a thread is reading and will take responsibility
    ///   for liveness.
    /// * If this is Some, no-one is reading and anyone who cares about liveness
    ///   must take on the reader role.
    ///
    /// (Therefore, when it becomes Some, we must signal a cv, if any is set.)
    reader: Option<crate::llconn::Reader>,
}

impl ReceiverState {
    /// Notify an arbitrarily chosen request's condvar.
    fn alert_anybody(&self) {
        // TODO: This is O(n) in the worst case.
        //
        // But with luck, nobody will make a million requests and
        // then wait on them one at a time?
        for ent in self.pending.values() {
            if let Some(cv) = &ent.waiter {
                cv.notify_one();
                return;
            }
        }
    }

    /// Notify the condvar for every request.
    fn alert_everybody(&self) {
        for ent in self.pending.values() {
            if let Some(cv) = &ent.waiter {
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
/// - So we can keep the reading side of the channel open while the RpcConn has
///   been dropped.
/// - So we can hold the lock on this part without being blocked on threads writing.
/// - Because this is the only part that for which
///   `RequestHandle` needs to keep a reference.
pub(super) struct Receiver {
    /// Mutable state.
    ///
    /// This lock should only be held briefly, and never while reading from the
    /// `llconn::Reader`.
    state: Mutex<ReceiverState>,
}

pub struct RpcConn {
    /// The receiver object for this conn.
    ///
    /// It's in an `Arc<>` so that we can share it with the RequestHandles.
    receiver: Arc<Receiver>,

    /// A writer that we use to send requests to Arti.
    ///
    /// This has its own lock so that we do not have to lock the Receiver
    /// just in order to write.
    ///
    /// This lock does not nest with the`receiver` lock.  You must never hold
    /// both at the same time.
    ///
    /// (For now, this lock is _ONLY_ held in the send_request method.)
    writer: Mutex<llconn::Writer>,
}

/// Instruction to alert some additional condvar(s) before releasing our lock and returning
///
/// Any code which receives one of these must pass the instruction on to someone else,
/// until, eventually, the instruction is acted on in [`Receiver::wait_on_message_for`].
#[must_use]
#[derive(Debug)]
enum AlertWhom {
    /// We don't need to alert anybody;
    /// we have not taken the reader, or registered our own condvar:
    /// therefore nobody expects us to take the reader.
    Nobody,
    /// We have taken the reader or been alerted via our condvar:
    /// therefore, we are responsible for making sure
    /// that _somebody_ takes the reader.
    ///
    /// We should therefore alert somebody if nobody currently has the reader.
    Anybody,
    /// We have been the first to encounter a fatal error.
    /// Therefore, we should inform _everybody_.
    Everybody,
}

impl RpcConn {
    /// Construct a new RpcConn with a given reader and writer.
    pub(super) fn new(reader: llconn::Reader, writer: llconn::Writer) -> Self {
        Self {
            receiver: Arc::new(Receiver {
                state: Mutex::new(ReceiverState {
                    id_gen: IdGenerator::default(),
                    fatal: None,
                    pending: HashMap::new(),
                    reader: Some(reader),
                }),
            }),
            writer: Mutex::new(writer),
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
    pub(super) fn send_request(&self, msg: &str) -> Result<super::RequestHandle, CmdError> {
        use std::collections::hash_map::Entry::*;

        let loose: LooseParsedRequest =
            serde_json::from_str(msg).map_err(|e| CmdError::InvalidRequest(Arc::new(e)))?;
        let mut state = self.receiver.state.lock().expect("poisoned");
        if let Some(f) = &state.fatal {
            // If there's been a fatal error we don't even try to send the request.
            return Err(f.clone().into());
        }

        // Convert this request into validated form (with an ID) and re-encode it.
        let valid: ValidatedRequest = loose
            .into_request(|| state.id_gen.next_id())
            .format()
            .map_err(|e| CmdError::CouldNotEncode(Arc::new(e)))?;

        // Do the necessary housekeeping before we send the request, so that
        // we'll be able to understand the replies.
        let id = valid.id().clone();
        match state.pending.entry(id.clone()) {
            Occupied(_) => return Err(CmdError::RequestIdInUse),
            Vacant(v) => {
                v.insert(RequestState::default());
            }
        }
        // Release the lock on the ReceiverState here; the two locks must not overlap.
        drop(state);

        // NOTE: This is the only block of code that holds the writer lock!
        let write_outcome = { self.writer.lock().expect("poisoned").send_valid(&valid) };

        match write_outcome {
            Err(e) => {
                // A failed write is a fatal error for everybody.
                let e = ShutdownError::Write(Arc::new(e));
                let mut state = self.receiver.state.lock().expect("poisoned");
                if state.fatal.is_none() {
                    state.fatal = Some(e.clone());
                    state.alert_everybody();
                }
                Err(e.into())
            }

            Ok(()) => Ok(super::RequestHandle {
                id,
                conn: Arc::clone(&self.receiver),
            }),
        }
    }
}

impl Receiver {
    /// Wait until there is either a fatal error on this connection,
    /// _or_ there is a new message for the request with the provided `id`.
    /// Return that message, or a copy of the fatal error.
    pub(super) fn wait_on_message_for(
        &self,
        id: &AnyRequestId,
    ) -> Result<ValidatedResponse, CmdError> {
        // Here in wait_on_message_for_impl, we do the the actual work
        // of waiting for the message.
        let state = self.state.lock().expect("posioned");
        let (result, mut state, should_alert) = self.wait_on_message_for_impl(state, id);

        // Great; we have a message or a fatal error.  All we need to do now
        // is to restore our invariants before we drop state_lock.
        //
        // (It would be a bug to return early without restoring the invariants,
        // so we'll use an IEFE pattern to prevent "?" and "return Err".)
        #[allow(clippy::redundant_closure_call)]
        (|| {
            // "final" in this case means that we are not expecting any more
            // replies for this request.
            let is_final = match &result {
                Err(e) => true,
                Ok(r) => r.is_final(),
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
                state.pending.remove(id);
            }

            match should_alert {
                AlertWhom::Nobody => {}
                AlertWhom::Anybody if state.reader.is_none() => {}
                AlertWhom::Anybody => state.alert_anybody(),
                AlertWhom::Everybody => state.alert_everybody(),
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
    ///    indicates that no more messages will be received for this request.
    /// - Possibly, notifying one or more condvars,
    ///   depending on the resulting `AlertWhom`.
    ///
    /// The caller must not drop the `MutexGuard` until it has done the above.
    fn wait_on_message_for_impl<'a>(
        &'a self,
        mut state_lock: MutexGuard<'a, ReceiverState>,
        id: &AnyRequestId,
    ) -> (
        Result<ValidatedResponse, CmdError>,
        MutexGuard<'a, ReceiverState>,
        AlertWhom,
    ) {
        // At this point, we have not registered on a condvar, and we have not
        // taken the reader.
        // Therefore, we do not yet need to ensure that anybody else takes the reader.
        let mut should_alert = AlertWhom::Nobody;

        let mut state: &mut ReceiverState = &mut state_lock;

        // Initialize `this_ent` to our own entry in the pending table.
        let Some(mut this_ent) = state.pending.get_mut(id) else {
            return (Err(CmdError::RequestCancelled), state_lock, should_alert);
        };

        let mut reader = loop {
            // Note: It might be nice to use a hash_map::Entry here, but it
            // doesn't really work the way we want.  The `entry()` API is always
            // ready to insert, and requires that we clone `id`.  But what we
            // want in this case is something that would give us a .remove()able
            // Entry only if one is present.
            if this_ent.waiter.is_some() {
                // This is an internal error; nobody should be able to cause this.
                return (Err(CmdError::DuplicateWait), state_lock, should_alert);
            }

            if let Some(ready) = this_ent.pop_next_msg(&state.fatal) {
                // There is a reply for us, or a fatal error.
                return (ready.map_err(CmdError::from), state_lock, should_alert);
            }

            // If we reach this point, we are about to either take the reader or
            // register a cv.  This means that when we return, we need to make
            // sure that at least one other cv gets notified.
            should_alert = AlertWhom::Anybody;

            if let Some(r) = state.reader.take() {
                // Nobody else is reading; we have to do it.
                break r;
            }

            // Somebody else is reading; register a condvar.
            let cv = Arc::new(Condvar::new());
            this_ent.waiter = Some(Arc::clone(&cv));

            state_lock = cv.wait(state_lock).expect("poisoned lock");
            state = &mut state_lock;
            // Restore `this_ent`...
            let Some(e) = state.pending.get_mut(id) else {
                return (Err(CmdError::RequestCancelled), state_lock, should_alert);
            };
            this_ent = e;
            // ... And un-register our condvar.
            this_ent.waiter = None;

            // We have been notified: either there is a reply or us,
            // or we are supposed to take the reader.  We'll find out on our
            // next time through the loop.
        };

        let (result, mut state_lock, should_alert) =
            self.read_until_message_for(state_lock, &mut reader, id);
        // Put the reader back.
        state_lock.reader = Some(reader);

        (result.map_err(CmdError::from), state_lock, should_alert)
    }

    /// Read messages, delivering them as appropriate, until we find one for `id`,
    /// or a fatal error occurs.
    ///
    /// Return that message or error, along with a `MutexGuard`.
    ///
    /// The caller is responsible for restoring the following state before
    /// dropping the `MutexGuard`:
    ///
    /// - Putting `reader` back into the `reader` field.
    /// - Other invariants as discussed in wait_on_message_for_impl.
    fn read_until_message_for<'a>(
        &'a self,
        mut state_lock: MutexGuard<'a, ReceiverState>,
        reader: &mut llconn::Reader,
        id: &AnyRequestId,
    ) -> (
        Result<ValidatedResponse, ShutdownError>,
        MutexGuard<'a, ReceiverState>,
        AlertWhom,
    ) {
        loop {
            // Importantly, we drop the state lock while we are reading.
            // This is okay, since all our invariants should hold at this point.
            drop(state_lock);

            let result: Result<ValidatedResponse, _> = match reader.read_msg() {
                Err(e) => Err(ShutdownError::Read(Arc::new(e))),
                Ok(None) => Err(ShutdownError::ConnectionClosed),
                Ok(Some(m)) => m.try_validate().map_err(ShutdownError::from),
            };

            state_lock = self.state.lock().expect("poisoned lock");
            let state = &mut state_lock;

            match result {
                Ok(m) if m.id() == id => {
                    // This only is for us, so there's no need to alert anybody
                    // or queue it.
                    return (Ok(m), state_lock, AlertWhom::Anybody);
                }
                Err(e) => {
                    // This is a fatal error on the whole connection.
                    //
                    // If it's the first one encountered, queue the error, and
                    // return it.
                    if state.fatal.is_none() {
                        state.fatal = Some(e.clone());
                    }
                    return (Err(e), state_lock, AlertWhom::Everybody);
                }
                Ok(m) => {
                    // This is a message for exactly one ID, that isn't us.
                    // Queue it and notify them.
                    if let Some(ent) = state.pending.get_mut(m.id()) {
                        ent.queue.push_back(m);
                        if let Some(cv) = &ent.waiter {
                            cv.notify_one();
                        }
                    } else {
                        // Nothing wanted this response any longer.
                        // _Probably_ this means that we decided to cancel the
                        // request but Arti sent this response before it handled
                        // our cancellation.
                    }
                }
            };
        }
    }
}
