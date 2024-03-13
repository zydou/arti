//! Declare a "command checker" trait that checks whether a given relay message
//! is acceptable on a given stream.

use tor_cell::relaycell::UnparsedRelayMsg;

use crate::Result;

/// A value returned by CmdChecker on success.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum StreamStatus {
    /// The stream is still open.
    Open,
    /// The stream has been closed successfully; any further messages received
    /// on this stream would be a protocol violation, which should cause
    /// us to close the circuit.
    Closed,
}

/// An object that checks incoming commands before they are sent to a stream.
///
/// These checks are called from the circuit reactor code, which runs in its own
/// task. The reactor code continues calling these checks we have sent our own
/// END cell on the stream.  See `crate::circuit::halfstream` for more
/// information.
///
/// NOTE: The checking DOES NOT take SENDME messages into account; those are
/// handled separately.  Neither of the methods on this trait will ever be
/// passed a SENDME message.
///
/// See [`circuit::reactor`](crate::circuit::reactor) for more information on
/// how these checks relate to other checks performed on incoming messages.
pub(crate) trait CmdChecker: std::fmt::Debug {
    /// Look at a message `msg` and decide whether it can be handled on this
    /// stream.
    ///
    /// If `msg` is invalid, return an error, indicating that the protocol has
    /// been violated and the corresponding circuit should be closed.
    ///
    /// If `msg` is invalid, update the state of this checker, and return a
    /// `StreamStatus` indicating whether the last message closed.
    fn check_msg(&mut self, msg: &UnparsedRelayMsg) -> Result<StreamStatus>;

    /// Consume `msg` and make sure it can be parsed correctly.
    ///
    /// This is an additional check, beyond check_msg(), performed for half-open
    /// streams.  It should only be called  if check_msg() succeeds.  It shouldn't
    /// be called on open streams: for those, the stream itself parses the message
    /// and consumes it.
    fn consume_checked_msg(&mut self, msg: UnparsedRelayMsg) -> Result<()>;
}

/// Type alias for a CmdChecker of unspecified type.
//
// TODO: Someday we might turn this into an enum if we decide it's beneficial.
pub(crate) type AnyCmdChecker = Box<dyn CmdChecker + Send + 'static>;
