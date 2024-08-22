//! [`oneshot`] channel between a circuit control message handler and the main code
//!
//! Wraps up a [`oneshot`] and deals with some error handling.
//!
//! Used by [`connect`](crate::connect)

use oneshot_fused_workaround as oneshot;
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::RelayMsg;
use tor_error::internal;
use tor_proto::circuit::MetaCellDisposition;

use crate::FailedAttemptError;

/// Sender, owned by the circuit message handler
///
/// Also records whether the message has been sent.
/// Forms part of the state for message handler's state machine.
pub(crate) struct Sender<M>(
    /// This is an `Option` so that we can `send` without consuming.
    ///
    /// Needed because `oneshot`'s send consumes, but the message handler gets `&mut self`.
    Option<oneshot::Sender<Result<M, tor_proto::Error>>>,
);

/// Receiver for awaiting the protocol message when the circuit handler sends it
pub(crate) struct Receiver<M>(
    oneshot::Receiver<Result<M, tor_proto::Error>>, // (force rustfmt to do this like Sender)
);

/// Create a new [`proto_oneshot::Sender`](Sender) and [`proto_oneshot::Receiver`](Receiver)
pub(crate) fn channel<M>() -> (Sender<M>, Receiver<M>) {
    let (tx, rx) = oneshot::channel();
    (Sender(Some(tx)), Receiver(rx))
}

impl<M> Sender<M> {
    /// Has this `Sender` yet to be used?
    ///
    /// Returns `true` until the first call to `deliver_expected_message`,
    /// then `false` .
    pub(crate) fn still_expected(&self) -> bool {
        self.0.is_some()
    }

    /// Try to decode `msg` as message of type `M`, and to send the outcome on the
    /// oneshot taken from `reply_tx`.
    ///
    /// Gives an error if `reply_tx` is None, or if an error occurs.
    ///
    /// Where possible, errors are also reported via the `oneshot`.
    pub(crate) fn deliver_expected_message(
        &mut self,
        msg: AnyRelayMsg,
        disposition_on_success: MetaCellDisposition,
    ) -> Result<MetaCellDisposition, tor_proto::Error>
    where
        M: RelayMsg + Clone + TryFrom<AnyRelayMsg, Error = tor_cell::Error>,
    {
        let reply_tx = self
            .0
            .take()
            .ok_or_else(|| internal!("Tried to handle two messages of the same type"))?;

        let outcome = M::try_from(msg).map_err(|err| tor_proto::Error::CellDecodeErr {
            object: "rendezvous-related cell",
            err,
        });

        #[allow(clippy::unnecessary_lazy_evaluations)] // want to state the Err type
        reply_tx
            .send(outcome.clone())
            // If the caller went away, we just drop the outcome
            .unwrap_or_else(|_: Result<M, _>| ());

        outcome.map(|_| disposition_on_success)
    }
}

impl<M> Receiver<M> {
    /// Receive the message `M`
    ///
    /// Waits for the call to `deliver_expected_message`, and converts the
    /// resulting error to a `FailedAttemptError` using `handle_proto_error`.
    pub(crate) async fn recv(
        self,
        handle_proto_error: impl Fn(tor_proto::Error) -> FailedAttemptError + Copy,
    ) -> Result<M, FailedAttemptError> {
        self.0
            .await
            // If the circuit collapsed, we don't get an error from tor_proto; make one up
            .map_err(|_: oneshot::Canceled| tor_proto::Error::CircuitClosed)
            .map_err(handle_proto_error)?
            .map_err(handle_proto_error)
    }
}
