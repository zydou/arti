## Conflux for exit relays

(December 2025)

### Current relay reactor architecture

> This section describes the current state of things,
> so you may wish to skip it if you don't need a refresher.
>
> Note: not everything described in this section is fully implemented (as of Dec 2025)

Internally, the relay circuit reactor consists of two reactors,
each running in a separate task:

  * `ForwardReactor` (`FWD`): handles cells coming from the client. It moves cells in the
    forward direction (from the client to the exit)
  * `BackwardReactor` (`BWD`): handles client-bound cells, by moving cells in the
    backward direction (from the exit to the client).

The read and write ends of the inbound and outbound (Tor) channels of the relay are "split",
such that each reactor holds an `input` stream (for reading)
and a `chan_sender` sink (for writing):

 * `FWD` holds the reading end of the inbound (coming from the client) Tor channel,
   and the writing end of the outbound (towards the exit) Tor channel, if there is one
 * `BWD` holds the reading end of the outbound channel, if there is one,
   and the writing end of the inbound channel

Note that because `BWD` contains the `StreamMap` of the circuit,
this reactor necessarily handles

  * the delivery of all client-bound cells (it writes them to the towards-the-client
    Tor channel sink) (**partially implemented**)
  * all stream management operations (the opening/closing of streams, and the delivery
    of DATA cells to their corresponding streams) (**partially implemented**)

But since incoming cells are received by `FWD`,
we have an MPSC channel for sending some cells (e.g. those carrying stream data)
from `FWD` to `BWD` for handling. This MPSC channel is `cell_tx` in the diagram below.

> **Note**: the `cell_tx` MPSC channel has no buffering, so if the `BWD`
> is not reading from it quickly enough (for example if its client-facing Tor channel
> sink is not ready to accept any more cells), the `FWD` will block,
> and therefore cease reading from its input channel, providing backpressure

The two reactors can be controlled via the `RelayCirc` handle.
Internally, `RelayCirc` uses control messages to communicate with the two reactors.

Cell flow, from client to backward reactor:

```
         +-------------------> FWD
         |                     |
         |                     | cell_tx
         |                     | <MPSC (0)>
  +--> client                  |
  |                            |
  |                            |
  | application stream data    v
  +-------------------------- BWD
                             (StreamMap->OpenStreamEnt->StreamQueueSender)
                                         |
                                         | <MPSC (unbounded if flowctl-cc enabled,
                                         |        1000      if flow-cc disabled)>
                                         |
                                (more buffering layers...)
                                         |
                                         v
                                   www.example.com
```

The `cell_tx` channel in the diagram above is used for sending:

  * circuit-level SENDMEs received from the client
  * circuit-level SENDMEs that need to be delivered to the client
  * stream messages, i.e. messages with a non-zero stream ID

And from the client to the next relay in the circuit:

```
                           cell FWD cannot decrypt
         client -----> FWD -----------------------> Relay
```

For more details, see the `crates/tor-proto/src/relay/reactor.rs` module-level docs.

### Conflux

#### Design philosophy

Instead of modifying the `FWD` and `BWD` reactors to support conflux,
I propose we redesign the relay reactor(s) to be more composable,
and implement the conflux subsystem as a separate component.
Making all the circuit reactor components composable should make the
overall system easier to reason about,
enabling us to reuse many of these components on the client side too.

The reactor components will use MPSC channels (with no buffering)
to interface with each other. The reason we don't want these
inter-component channels to buffer is because it is simpler to keep
all the buffering layers at the "edge" of the reactor
(i.e. at the `chan_sender` sinks, `StreamQueueSender`, etc.).
That way, blocking (for example due to an outbound MPSC channel being full)
can only be initiated by these egdes, and not by the intermediate MPSC channels.

> Note: eventually, we might want non-zero amounts of buffering on the
> inner MPSC channels for performance reasons.

> Currently, the client reactor architecture is completely
> different from the work-in-progress relay one,
> but if we are careful about our design choices here,
> we should be able to later parameterize all the reactor components
> and rewrite the client implementation to use them.

Before implementing conflux, we will need to do a preliminary refactoring/redesign of
the current relay reactor: we will first need to move the stream handling out of `BWD`,
so that `BWD` will no longer drive the application streams or handle stream data at all.
Instead, it will be exclusively responsible for moving cells,
read from an `mpsc::Receiver`, to an `mpsc::Sender`
(we could even use opaque `futures::Stream`s and `futures::Sink`s,
since we likely won't be needing any `mpsc`-specific APIs)

Streams will be read from, and written to, by a new `StreamReactor`,
running in a separate task:

```
                            <stream_tx
                             MPSC (0)>
  +--------------> FWD -------------------------+
  |                 |                           |
  |                 |                           |
  |                 |                           |
  |                 |                           v
client      BackwardReactorCmd            StreamReactor
  ^             <MPSC (0)>                      |
  |                 |                           |
  |                 |                           |
  |                 |                           |
  |                 v                           |
  +--------------- BWD <------------------------+
    application stream data    <stream_rx
                                MPSC (0)>

```

Later on, we might want to parallelize the stream read/write paths further,
such that streams are handled by *two* new reactors:

  * `StreamReadReactor` (`StreamRead`), which reads from the `Stream` of ready
    application streams, and sends the ready messages to `BWD` for writing
  * `StreamWriteReactor` (`StreamWrite`), which receives cells from `FWD`,
    and writes them to the application streams

So the first step will be to make the cell flow from the client to `BWD` look like this:

```
                            stream_fwd_tx
                             <MPSC (0)>
  +--------------> FWD ----------------------------> StreamWrite
  |                 |                                (StreamMapWrite->
  |                 |                                  OpenStreamEntWrite->
  |                 |                                   StreamQueueSender)
  |         BackwardReactorCmd                                   |
client           <MPSC (0)>                            <MPSC (unbounded if flowctl-cc enabled,
  ^                 |                                        1000      if flow-cc disabled)>
  |                 |                                            |
  |                 |                                            |
  |                 |                                            |
  |                 |                                            |
  |                 |                                   (more buffering layers...)
  |                 |                                            |
  |                 |                                            v
  |                 |                                      www.example.com
  |                 |
  |                 v
  +--------------- BWD <---------------------------- StreamRead
    application stream data    stream_bwd_rx        (StreamMapRead->
                                <MPSC (0)>            OpenStreamEntRead->
                                                       StreamUnobtrusivePeeker)

```

`FWD` will have a `stream_fwd_tx` `Sink` (internally an MPSC channel with no buffering)
for sending stream cells (`BEGIN`, `DATA`, `END`, `RESOLVE`, etc.) to `StreamWrite` for handling.

`BWD` will have a `stream_bwd_rx` `Stream` for reading ready stream messages
from `StreamRead`. `BWD` will write these messages to its "towards the client" Tor channel.

To implement this, we would need the ability to split the `StreamMap` in two,
such that each stream entry can be read from, and written to, from separate
tasks (we need to hand out the read and write ends of the streams to
`StreamRead` and `StreamWrite`, respectively)

Note that we'd need to retain `StreamPollSet` on the read side, for stream
prioritization (we want ready-streams to be iterated over in order of priority).

The `StreamMapRead` and `StreamMapWrite` halves of the `StreamMap`
will need to be kept in sync, or to share the same underlying map of streams.
(The design here is TBD, but we should bear in mind the suggestions from
https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3533#note_3305914)

In both cases, the stream-handling tasks will be launched lazily.
That is, they will be launched by `FWD` upon receiving the first `BEGIN`.
This will prevent unnecessarily launching stream handling tasks
for middle relays that don't do leaky pipe.

With this change, exits (and relays with leaky pipe) will spawn 3
(or 4, if we implement the stream read/write split)
tasks per circuit, instead of just 2.

> Note: in the case of conflux circuits (tunnels), the stream handling tasks won't be launched by `FWD`.
>
> More on that below.

-----
For conflux, we're going to need two additional components:

1. A `ConfluxMgr` for matching up circuits that receive `LINK` cells with matching
nonces. `

`ConfluxMgr` will be responsible for launching `ConfluxController`s (described
below), and instructing the `FWD`s and `BWD`s to stop routing cells directly to
and from `StreamWrite` and `StreamRead`, and to instead route them via `ConfluxController`.

There will be a single `ConfluxMgr` per relay process.
All `FWD`s will have an MPSC channel for sending `LINK` cells to it.

2. A `ConfluxController`, wedged between `FWD` and `BWD`, and the
  stream handling reactor

`ConfluxController` will handle the conflux seqno accounting and out-of-order cell buffering.
There will be one these per conflux set.
`ConfluxController` will receive cells from all the `FWD`
reactors in the set, and will write cells to the `BWD` reactor of the primary leg.

Alternatively, we might choose to merge `ConfluxController` and `StreamReactor`,
i.e. have `StreamReactor` handle conflux.

> `ConfluxMgr` and the `ConfluxController`s will be "reactors", in that they will run
> in the background and react to events (such as incoming cells and handshake timeouts).

Note that there will be one `FWD` and one `BWD` **per leg**,
but only one `StreamReactor` **per tunnel** (or conflux set).

Conflux handshake flow:

```
            LINK
            (nonce = 1234...)
         +----------------------> FWD 1 -----------+
         |                                         |
         |                                         |
         |                                         | LINK
         |                                         | (nonce = 1234...)
         |                                         v
       client                                  ConfluxMgr
         |                                         ^
         |                                         |
         |                                         | LINK
         |                                         | (nonce = 1234...)
         |                                         |
         |                                         |
         +----------------------> FWD 2 -----------+
            LINK
            (nonce = 1234...)

```

During the handshake, the `stream_fwd_tx` sinks of `FWD` reactors
and the `stream_bwd_rx` streams of the `BWD` reactors will be set to
send to, and receive from, the `ConfluxController`:

Upon receiving a `LINK` request, the `ConfluxMgr` checks if it has already
spawned a `ConfluxController` for the given nonce, and spawns it if not.
It then passes a handle to the controller to the `FWD` reactor to use as its `stream_fwd_rx`,
and instructs the `BWD` reactor to send back a `LINKED` cell.
Similarly, the `stream_bwd_rx` of the `BWD` reactor will be set to receive from `ConfluxController`.
At this this point, the leg is considered linked
(despite not having yet received the `LINKED_ACK` from the client).

If the `LINKED_ACK` doesn't arrive in time, the `ConfluxController` will tear
down the circuit. If the `ConfluxController` is left with zero legs, it will
need to shut down (TODO: the `ConfluxMgr` will also need to be informed when this happens).

> If the `stream_fwd_tx`/`stream_bwd_rx` channels are not `None`
> at the time of the conflux handshake, it means the circuit
> is dirty (it has been used for streams), which is a protocol
> violation (dirty circuits can't be LINKed). This will
> cause the circuit to shut down
>
> (TODO: should we shut down the entire conflux set?)

For example, for a two-legged conflux tunnel:

```
                  <stream_cell_tx MPSC (0)>
           FWD 1 ---------------------+
            |                         |
            |                         |
            |                         |       stream_tx
    BackwardReactorCmd                |       <MPSC (0)>
    <sendme_tx MPSC (0)>              |    +-------------+
            |                         |    |             |
            |                         v    |             v
            |                  ConfluxController    StreamReactor
            |                   | ^   |    ^             |
            |                   | |   |    |             |
            |                   | |   |    |             |
            |                   | |   |    +-------------+
            v                   | |   |      <stream_rx
           BWD 1 <--------------+ |   |       MPSC (0)>
                 <stream_cell_rx> |   |
                                  |   |
                                  |   |
                                  |   |
           FWD 2 -----------------+   |
            |    <stream_cell_tx>     |
            |                         |
   BackwardReactorCmd                 |
    <sendme_tx MPSC (0)>              |
            |                         |
            |                         |
            |                         |
            v                         |
           BWD 2 <--------------------+
                  <stream_cell_rx MPSC (0)>
```

Note that the `cell_rx` channel between `FWD` and `BWD` will be renamed to
`sendme_tx` (because it will only be used for circuit-level SENDMEs).

Here are some of the parts that will be a bit more tricky to get right:

  * The `ConfluxController` should only read from the `Stream` of ready
  streams (obtained from `StreamRead`) if its primary leg is not
  blocked on CC. To probe whether a given `BWD`
  is blocked on CC, the `ConfluxController` needs to know if
  `CongestionControl::can_send() == true` for each leg
  (note: in reality, the logic here is a bit more complicated,
  as it depends on the conflux UX).
  * The `ConfluxController` needs access to the RTT measurements of each of
  its `BWD`s, for choosing the primary leg

The tricky part here is that `ConfluxController`
needs access to the CC state of all of its legs,
so this state will need to be shared, somehow.
For example, we might choose to put it behind a mutex,
but if we do that, we need to make sure none of the tasks hold the lock for long...
Another option would be to rewrite the CC implementation and RTT estimator
to use `Arc<Atomic*>`instead (`num_inflight`, `cwnd`),
and make those atomics accessible to the components that need them.

One additional complication is that we will need to make this all work
for the client-side too
(see [retrofitting](#retrofitting-all-of-this-for-the-client-circuit-reactor) below).

For that, we will need ConfluxController to support being the initiator, as well as responder:

   * handshake initiator, for clients
   * handshake responder, for exit relays and onion services

##### What about XON/XOFF?

> XON/XOFF flow control is not yet implemented on the relay side.
> This section uses the client implementation as a reference,
> but we will likely need to come up with a slightly different approach
> given that the new relay architecture is so different from the client one

After delivering a message to a stream, if the incoming buffer of the stream
has become too large, the `StreamWrite` reactor needs to send an XOFF to the client.
But `StreamWrite` doesn't have the ability to do that, because its only
job is to forward incoming messages to its local streams.

We will need some way of signaling to `BWD` that we have an `XOFF` to send.

We could

   * add an MPSC channel between `StreamWrite` and `BWD`, for sending `XOFF` cells.
   * share state (a list of XOFF cells to send for each stream) between
   `StreamWrite` and `BWD`

The `XON` case is a bit different.
On the client side, when the stream reader's buffer becomes empty,
we send an `XON`s with an unlimited rate.
The decision to send XON happens outside the reactor, in `XonXoffReader::poll_read()`,
which calls `StreamTarget::drain_rate_update()` to send a control message to the
reactor informing it about a change in the drain rate for that stream.
I think the `XON` sending logic can stay the same in our multi-reactor design
(but we will need to adapt our reactors to support control messages).

> Note: the client implementation currently never uses anything other
> than XOFF and XON with an unlimited rate

#### Retrofitting all of this for the client circuit reactor

Ideally, we should be able to rewrite the client circuit reactor using
the multi-reactor, multi-task architecture we have on the relay side.

A client will have both a `FWD` and a `BWD` reactor but its `FWD` reactor
will never get initialized with an outgoing Tor channel.
The only responsibility of this reactor will be to read cells coming from the guard,
and forward them either to `BWD` (in the case of circuit-level SENDMEs),
or to the stream data `Sink` (connected either to `StreamReactor`, for
single-path cirucits, or `ConfluxController`, for the multi-path ones).
The `BWD` will write cells to the (Tor) channel to the guard.

> At this point, it's obvious `FWD` and `BWD` have become misnomers:
> for a client reactor, it is `BWD` who forwards cells in the CREATE direction,
> not `FWD`!
>
> In both cases, however, `FWD` is responsible for accepting cells
> coming from a Tor channel, and decrypting them, if possible.
> Similarly, in both cases `BWD` is the component in charge
> of encrypting and sending outgoing cells.
>
> A better name for these is TBD.


Unlike relays, clients have multiple stream maps, one for each hop
(because of leaky pipe).
This means each client circuit will have up to one stream reactor task per `CircHop`.

Cell flow, from guard to client backward reactor,
assuming the streams are all on the same hop:

```
  +--------------- FWD <--------------------+
  |                 |                       |
  |                 |                       |
  |                 |                       |
  v                 |                       |
StreamReactor  BackwardReactorCmd         guard
  |               <MPSC (0)>                ^
  |                 |                       |
  |                 |                       |
  |                 |                       |
  |                 v                       |
  +--------------> BWD ---------------------+
```

With leaky pipe (`SR` = `StreamReactor`):

```


  +------------------------------+
  |       +--------------------+ |
  |       |                    | |
  |       |       +----------- FWD <------------------+
  |       |       |             |                     |
  |       |       |             |                     |
  |       |       |             |                     |
  v       v       v             |                     |
 SR      SR      SR           BackwardReactorCmd    guard
(hop 4) (hop 3)  (hop 2)      <MPSC (0)>              ^
  |       |       |             |                     |
  |       |       |             |                     |
  |       |       |             |                     |
  |       |       |             v                     |
  |       |       |            BWD -------------------+
  |       |       |             ^
  |       |       |             |
  |       |       |             | <stream_rx
  |       |       |             |  MPSC (0)>
  +-------+-------+-------------+
```

The `BWD` will have a `stream_rx` MPSC channel for receiving `(HopNum, StreamEvent)` from
its various `StreamReactor`s (each `StreamReactor` will need to know the
`HopNum` it's associated with). The `HopNum` is there because on the client side,
the `BWD` needs to know the `HopNum` to encrypt outgoing cells. For relays,
the `HopNum` can just be `0`, as it will be unused (we could also make it an `Option<>`).


The conflux case is even more complicated.
For example, consider a conflux tunnel with two legs,
where the first leg has leaky pipe streams on two of its hops:

```
                                     +--------------------------------+
                                     |       +----------------------+ |
                                     |       |                      | |
                                     |       |       +------------- FWD 1 <--------+
         stream_tx                   |       |       |               |             |
   +-------------------+             |       |       |               |             |
   |                   |             |       |       |               |             |
   v                   |             |       v       v               |             |
   SR          ConfluxController <-- +      SR      SR               |           guard 1
(join point)           ^  | |        |     (hop 3)  (hop 2)       <MPSC (0)>       ^
   |                   |  | |        |       |       |               |             |
   +-------------------+  | |        |       |       |               |             |
         stream_rx        | |        |       |       |               |             |
                          | |        |       |       |               v             |
                          | |        |       |       |              BWD 1 ---------+
                          | |        |       |       |               ^
                          | |        |       |       |               |
                          | |        |       |       |               | <stream_rx
                          | |        |       |       |               |  MPSC (0)>
                          | +--------/-------+-------+---------------+
                          |          |
                          |          |
                          |          +----------------------------- FWD 2 <--------+
                          |                                          |             |
                          |                                          |             |
                          |                                          |           guard 2
                          |                                       <MPSC (0)>       ^
                          |                                          |             |
                          |                                          v             |
                          +---------------------------------------> BWD 2 ---------+
```

To support all of this `FWD` will need the ability to dispatch cells to the right `StreamReactor`.
Conceptually, we would need an SPMC channel, but for now we can just create an abstraction
over multiple MPSC/SPSC channels, and later swap out the implementation:

```rust
struct StreamReactorSender {
    /// The sender is set to None for the hops that don't have a stream reactor
    tx: SmallVec<[Option<mpsc::Sender<(StreamId, UnparsedRelayMsg)>>; MAX_HOPS]>,
}

impl StreamReactorSender {
    /// API used by the FWD to deliver messages to streams.
    fn send(&self, sid: StreamId, msg: UnparsedRelayMsg) -> Result<()> { ... }
}

struct ForwardReactor {
    /// A channel for delivering messages to the stream reactor.
    stream_tx: StreamReactorSender,
    ...
}
```

However, the logic for delivering stream messages
is unfortunately not trivial to decouple from the circuit reactor:

1. If the target stream reactor doesn't have an entry for the specified `sid`,
and the relay message is `BEGIN`, `BEGIN_DIR`, or `RESOLVE`,
it means we need to accept (or reject) an incoming stream,
and send a cell back to the stream initiator (`CONNECTED`/`END`),
which we cannot do directly from the `StreamReactor`

2. If the target stream reactor doesn't have an entry for the specified `sid`,
and the relay message is **not** `BEGIN`, `BEGIN_DIR`, or `RESOLVE`,
the circuit must be torn down with a protocol violation error

On top of that, the `StreamReactor`, which in this new design
is the only entity with access to the stream maps,
will sometimes decide it is time to send an `XOFF`
(if the stream entry it has just delivered the message for has too much data buffered).

This means the `StreamReactor`-> `BackwardReactor` MPSC channels need to be able
to send

  * `CONNECTED`/`END`, in response to an incoming stream request
  * `XOFF`, if `StreamReactor` notices a stream is not read from quickly enough
  * ready stream messages, obtained from `StreamMap::poll_ready_streams_iter()`

So the `StreamEvent`s `StreamReactor` sends to the `BackwardReactor` are:

```rust
/// A Tor stream event.
enum StreamEvent {
    /// A stream has a ready message.
    ReadyMsg {
        /// The ID of the stream to close.
        sid: StreamId,
        /// The message.
        msg: AnyRelayMsg,
    },
    /// Send a message to the other endpoint.
    ///
    /// This might be be XOFF, CONNECTED, or END
    SendMsg {
        /// The message.
        msg: AnyRelayMsgOuter,
    },
}
```

For 2., we can simply log the protocol violation error and shut down the `StreamReactor`.
When the `StreamReactor` shuts down, the other reactors will shut down as well,
tearing down the entire circuit:

  * the `BWD` shuts down because its RX channel towards the `StreamReactor` will close
  * the `relay::Reactor` shuts down because the `backward.run()` future resolves
  * the `FWD` shuts down because the `shutdown_rx` channel with `relay::Reactor` is closed
  * this will trickle down to all the other `StreamReactor` tasks,
    because they all have rx channels reading from the `FWD`

-----

Various parts of the `FWD`/`BWD` reactors will need to be abstracted away,
as they will be different on the client side:

  * the `crypto_in`/`crypto_out` states
  * the `Forward` state (representing the sending of the forward channel),
    and the `input` channel from the `BWD` will always be set
    to `None` in the client reactor
  * clients and relays support different incoming messages,
    so we might need to delegate their handling to an abstract `MsgHandler`
  * `FWD` and `BWD` will need to support handling `CtrlMsg`s.
    And since `CtrlMsg`s are going to be implementation-dependent,
    the `CtrlMsg` type will be eventually become one of the generic params on the reactors
  * `TunnelMutableState`, which is shared with `ClientCirc`,
    will need to be removed/redesigned
