# Relay command validation

This document covers the way we validate relay commands in `tor-proto`.
Note that Arti does not implement the state machine pattern described in [prop349],
but instead has a series of `CmdChecker`s and ad-hoc message handlers
that enforce the rules from [prop349].

## Motivation

[Dropped cells] (invalid or unrecognized cells injected by a relay and
subsequently dropped by the client), can serve as a side-channel,
which can help mount other attacks, such as [path bias],
that can be used to deanonymize clients.

As such, it is essential that Arti clients validate all incoming RELAY
messages, and close down the circuit if they receive an unexpected or
otherwise invalid cell.

## Patterns

### Stream ID validation

The circuit reactor ensures that all incoming relay cells have a valid stream ID
(i.e. either zero, or non-zero depending on the relay command).
If an incoming cell has an invalid stream ID, the circuit shuts down with an error
(see `msg_streamid()`).

Incoming cells that have an unrecognized stream ID (i.e. one that doesn't have a
corresponding open or half-stream entry in the `StreamMap`) are considered to be
in violation of the protocol, and will cause the reactor to shut down.


### `CmdChecker` pattern

`CmdChecker`s are objects that validate incoming stream commands.

In the stream map, open stream entries and half-streams have a `CmdChecker`.

> [!NOTE]
> Stream `SENDME`, `XON`, `XOFF` commands are handled separately, not by the `CmdChecker`s

There is a `CmdChecker` for each type of supported stream:

  * `DataCmdChecker`, for outbound data streams
  * `ResolveCmdChecker`, for resolve streams
  * `IncomingCmdChecker`, for incoming data streams

#### Per-stream `CmdChecker`s (RESOLVE, BEGIN)

Each `StreamMap` entry has a `CmdChecker` for validating incoming message commands
(note that because of leaky pipe, each hop has its own `StreamMap`).
This `CmdChecker` is instantiated with `DataCmdChecker` for data streams,
and `ResolveCmdChecker` for RESOLVE streams.

In `CircHop::deliver_msg_to_stream()`, flow-control messages (stream `SENDME`s, `XON`, `XOFF`)
are passed to the [flow-control subsystem for handling](#flow-control), while all the other messages
are delivered to their corresponding application streams (in unparsed form).
Prior to delivery, each message is validated with `CmdChecker::check_msg()`,
which returns an error if it detects a protocol violation,
or a `StreamStatus` indicating whether the stream should be closed or not.
In the case of a protocol violation, the error is propagated all the way to
`Reactor::run_once()`, causing the reactor to shut down
(as described in the section on [error propagation](#error-handling-in-the-reactor) below).

> [!CAUTION]
> `CircHop::deliver_msg_to_stream()` delivers an *unparsed* relay message to the stream.
> It is the responsibility of the stream implementation to handle the message
> parsing, and any errors that might result (see [out-of-reactor error handling](#errors-detected-outside-the-reactor)).

#### Incoming stream `CmdChecker`

Incoming commands that cause the receiver to open a stream
(`BEGIN`, `BEGIN_DIR`, `RESOLVE`) are validated using `IncomingCmdChecker`.
This is currently only used for onion service `BEGIN` handling,
but in the future, exits and directories will use it too.

Unlike `DataCmdChecker` and `ResolveCmdChecker`,
`IncomingCmdChecker`s are installed in an `IncomingStreamRequestHandler`,
inside the reactor's `CellHandlers` using the `AwaitStreamRequest` control command.

Unlike the other `CmdChecker`s, there can be only one `IncomingCmdChecker`
per reactor. This `IncomingCmdChecker` is used for validating
stream requests originating from the hop specified inside the
`IncomingStreamRequestHandler`.

`BEGIN`, `BEGIN_DIR`, `RESOLVE` messages are handled in
`Circuit::handle_incoming_stream_request()`.
This function validates the originating hop, calls the `IncomingCmdChecker`
to validate the message, and then parses it.
If any of these checks fail, the circuit is shut down.
Otherwise, the reactor adds a new stream entry for the incoming stream,
which, in turn, gets initialized with a `DataCmdChecker` for validating
any future messages on that stream.

### Error propagation to the circuit reactor

Any errors resulting from incoming cell validation
MUST lead to a circuit reactor shutdown,
so it is very important that `Result`s are handled correctly.

#### Error handling in the reactor

In the circuit reactor, this happens implicitly, through error propagation.
Incoming relay cells with a non-zero stream ID are handled by
`Circuit::handle_in_order_relay_cell()`, while meta-cells
(cells where stream ID = 0) are passed to
`Circuit::handle_meta_cell()`.
Any error returned from these functions eventually ends up in
`Reactor::run_once()`, and causes the reactor to shut down.

> [!NOTE]
> `Reactor_run_once()` currently logs all errors,
> including protocol violation errors, at debug level (#2187)

```
                        incoming relay message
                                 |
                                 v
                          stream ID == 0?
                          /         \
                       Yes           No
                        |             |
    Circuit::handle_meta_cell()     Circuit::handle_in_order_relay_msg()
```


#### Errors detected outside the reactor

However, there are cases where protocol violation errors occur *outside* of the circuit reactor.
Those errors MUST be handled explicitly, by issuing a manual shutdown command to the reactor.

One such case is that of stream messages, which are parsed late, outside of the reactor,
when the stream is being read from. For example, data messages are parsed in
`DataReaderInner::poll_read()`, while `RESOLVED` responses are parsed in
`ResolveStream::read_msg()`. If the message can't be parsed, the entire circuit
is shut down with an explicit call to `StreamReceiver::protocol_error()`,
(this sends a `Shutdown` control message to be sent to the circuit reactor,
telling it to shut down).

> [!CAUTION]
> When validating cells *outside* of the circuit reactor,
> you must ensure any errors are handled by sending `CtrlCmd::Shutdown`
> over the reactor's control channel.

### Circuit `SENDME` validation

Circuit `SENDME`s are parsed inside `handle_meta_cell()`, and passed over to
the congestion control subsystem (`CongestionControl::note_sendme_received()`)
for validation. Internally, this subsystem uses a `SendmeValidator`
for verifying the authenticated tag.

### Flow control

In addition to the `CmdChecker`, stream entries also have a `StreamFlowCtrl`
for handling flow control messages.

Internally, `StreamFlowCtrl` is initialized with `WindowFlowCtrl` for legacy
window-based flow control, or with `XonXoffFlowCtrl` for XON/XOFF flow control.

In  `CircHop::deliver_msg_to_stream()`,
`XON`, `XOFF`, and stream `SENDME` messages are special-cased:
they are not passed to the `CmdChecker` of the stream,
but instead are sent to `StreamFlowCtrl` for handling.

`XonXoffFlowCtrl` implements the XON/XOFF state machine,
which returns an error if we receive a stream SENDME while using XON/XOFF flow control,
and `SidechannelMitigation`,
which limits how often we can receive XON/XOFF messages.

`XonXoffFlowCtrl` also parses the incoming XON/XOFF messages, and ensures they
have the expected version.

`WindowFlowCtrl` returns a protocol violation if we receive an `XON`/`XOFF`,
or if we receive more stream `SENDME`s than expected for the amount of data sent.
In both cases, the protocol violation error will cause the reactor to
[shut down](#error-handling-in-the-reactor).

### Conflux

`CONFLUX_{LINK, LINKED, LINKED_ACK, SWITCH}` cells are handled in
`Circuit::handle_conflux_msg()`, which triggers a protocol violation if
conflux is not enabled, or if the message originates from an unexpected hop.

The conflux cell is then passed to `AbstractConfluxMsgHandler::handle_msg()`,
which will return an error if the cell is invalid or unexpected.
This error will eventually end up in the circuit reactor main loop through
[error propagation](#error-handling-in-the-reactor).

`AbstractConfluxMsgHandler` is currently only implemented for
`ClientConfluxMsgHandler`, which implements the client conflux state machine.
When we implement exit relays, will also need an `ExitConfluxMsgHandler`
implementation for the exit state machine.

### Onion service handshakes

Onion service handshakes are implemented using  `MetaCellHandler`s,
which are a type of ad-hoc message handler that gets installed in the circuit reactor.
The reactor passes all unrecognized meta-cells to its `MetaCellHandler`.

Arti currently has two such handlers: `CircuitExtender` (for handling
`EXTENDED` cells during the extension handshake), and `UserMsgHandler`,
which is used by onion service clients (for handling cells during the
rendezvous handshake), and by onion services (for handling messages
originating from its introduction points)


### Padding machine checks (for DROP commands)

Upon receiving a cell that consists of nothing but padding (`DROP` messages),
the reactor will notify the padding controller via `PaddingController::decrypted_call()`.
If padding is disabled, or not expected from the originating hop,
the padding controller returns a protocol error that will shut down the reactor.

[prop349]: https://spec.torproject.org/proposals/349-command-state-validation.html
[Dropped cells]: https://spec.torproject.org/proposals/344-protocol-info-leaks.html#113-dropped-cells
[path bias]: https://spec.torproject.org/proposals/344-protocol-info-leaks.html#3-glossary

### Half-closed streams

Like the open stream entries, half-closed streams have a `CmdChecker` and a `StreamFlowCtrl`
object for handling incoming cells.

In addition to the `CmdChecker::check_msg()` check performed on open streams,
half-streams must perform an additional check to ensure the message
can be parsed correctly, because unlike the open streams, where the messages
are parsed when they are read (see [error handling](#errors-detected-outside-the-reactor)),
half-streams do not have an external component to handle the parsing.
For this reason, `HalfStream::check_msg()` also calls
`CmdChecker::consume_checked_msg()` to parse the message, consuming it.

Half-streams have special handling for:

  * flow-control cells: `SENDME`, `XON`, `XOFF` are validated using `StreamFlowCtrl`,
    just like for open streams
  * stream receive window violation (if DATA cells are received in violation of the
    window, the reactor shuts down with a protocol violation error)
