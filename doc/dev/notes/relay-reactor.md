# Relay circuit reactor

This describes a possible design for the new relay circuit reactor,
and is loosely based on [doc/dev/notes/relay-sketch.md](../relay-sketch.md).

> Note: this design aims to serve as a starting point for the relay reactor
> work, but it is by no means final.

## Current tunnel reactor implementation

**Important: this is up to date with de0f4d3b5ead69cddefdc9e225bff338ff7eb7ea**

This diagram summarizes the current status quo in `tor-proto`:

```

                                    ClientCirc
                          +-------------------------------------------+
                          |      < fields omitted for brevity >       |
                          +----||-------------------------||----------+
                               ||                         ||
                               ||                         ||
                               ||                         ||
                     (Unbounded MPSC channel)    (Unbounded MPSC channel)
                               ||                         ||
                               ||                         ||
 Tunnel reactor:               ||                         ||
  +----------------------------||-------------------------||--------------------------+
  |                            \/                         ||                          |
  |        +-------------------------------------+        ||                          |
  |        |                RX                   |        ||                          |
  |        +-------------------------------------+        ||                          |
  |        | control: UnboundedReceiver<CtrlCmd> |        ||                          |
  |        +-------------------------------------+        ||                          |
  |                                                       \/                          |
  |                                        +-------------------------------------+    |
  |                                        |                RX                   |    |
  |                                        +-------------------------------------+    |
  |                                        | command: UnboundedReceiver<CtrlMsg> |    |
  |                                        +-------------------------------------+    |
  |                                                                                   |
  |      ==================                                                           |
  |      === run_once() ===                                                           |
  |      ==================                                                           |
  |                          |  * control.next()                                      |
  |           select_biased! |  * command.next()                                      |
  |                          |  * ConfluxSet::next_circ_action()                      |
  |                                                                                   |
  |      ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   |
  |      +      ConfluxSet { circuits: SmallVec<Circuit> }                        +   |
  |      +                                                                        +   |
  |      +  ==========================                                            +   |
  |      +  === next_circ_action() ===                                            +   |
  |      +  ==========================                                            +   |
  |      +                                                                        +   |
  |      +  For each circuit leg (returning the result of the future that         +   |
  |      +  resolves first):                                                      +   |
  |      +                                                                        +   |
  |      +                   |  * conflux handshake timeout future                +   |
  |      +                   |                                                    +   |
  |      +                   |                     | * input.next()               +   |
  |      +    select_biased! |  * select_biased!   |                              +   |
  |      +                   |  (if chan sink rdy) | * ready_streams_iter.next()  +   |
  |      +                                                                        +   |
  |      +    +----------------------------------------------------------------+  +   |
  |      +    | Circuit                                                        |  +   |
  |      +    | +----------------------------+                                 |  +   |
  |      +    | |           RX               |                                 |  +   |
  |      +    | |----------------------------|                                 |  +   |
  |      +    | | input: CircuitRxReceiver   |                                 |  +   |
  |      +    | +----------------------------+                                 |  +   |
  |      +    |     /\                                                         |  +   |
  |      +    |     ||         +----------------------------------------------+|  +   |
  |      +    |     ||         |                       TX                     ||  +   |
  |      +    |     ||         |----------------------------------------------||  +   |
  |      +    |     ||         | chan_sender: SometimesUnboundedSink<         ||  +   |
  |      +    |     ||         |                AnyChanCell, ChannelSender>   ||  +   |
  |      +    |     ||         +----------------------------------------------+|  +   |
  |      +    +-----||-------------------------------------||------------------+  +   |
  |      +++++++++++||+++++++++++++++++++++++++++++++++++++||++++++++++++++++++++++   |
  +-----------------||-------------------------------------||-------------------------+
                    ||                                     ||
           (Bounded MPSC channel)                 (Bounded MPSC channel)
              (size = 128)                   (size = CHANNEL_BUFFER_SIZE = 128)
                    ||                                     ||
Channel reactor:    ||                                     ||
 +------------------||-------------------------------------||--------------------+
 |                  ||                                     \/                    |
 |                  ||                        +-------------------------------+  |
 |                  ||                        |              RX               |  |
 |                  ||                        +-------------------------------+  |
 |                  ||                        | cells: Receiver<AnyChanCell>  |  |
 |                  ||                        +---------------+---------------+  |
 |                  ||                                        |                  |
 |                  ||        CircMap                  if output is ready,       |
 |  +---------------||----------------------------+      cells.next()            |
 |  |               ||    ...                     |  and deliver cell to sink    |
 |  |               ||                            |           |                  |
 |  |               ||  CircEnt::Open             |           +--------------+   |
 |  |         +-------------------------------+   |                          |   |
 |  |         |              TX               |   |  deliver message         |   |
 |  | CircId: |-------------------------------|<------------------+          |   |
 |  |         |     CircuitRxSender           |   |      to circuit reactor  |   |
 |  |         +-------------------------------+   |               |          |   |
 |  |                                             |               |          |   |
 |  |          ...                                |               |          |   |
 |  +---------------------------------------------+               |          |   |
 |                                                                |          |   |
 |                                                                |          |   |
 |      ==================                             input      |          |   |
 |      === run_once() ===                    +-----------------------+      |   |
 |      ==================                    |   ChannelCodec        |      |   |
 |         /                                  |  +----------------+   |      |   |
 |         |  * control.next()                |  | TLS stream     |   |      |   |
 | select! |  * input.next()                  |  | +----------+   |   |      |   |
 |         |  * output ready to send          |  | | TCP sock |   |   |      |   |
 |         \                                  |  | +----------+   |   |      |   |
 |                                            |  +----------------+   |      |   |
 |                                            +-----------------------+      |   |
 |                                                                           |   |
 |                                                                  output   v   |
 |                                                         +-------------------+ |
 |                                                         |  ChannelCodec     | |
 |                                                         | +---------------+ | |
 |                                                         | | TLS stream    | | |
 |                                                         | | +-----------+ | | |
 |                                                         | | | TCP sock  | | | |
 |                                                         | | +-----------+ | | |
 |                                                         | +---------------+ | |
 |                                                         +-------------------+ |
 +-------------------------------------------------------------------------------+
```

> NOTE: Circuit is a private type that represents the state
> of a client circuit, including its underlying Arc<Channel>,
> CircHops, chan sender, input stream, cryptographic state, and conflux state).
> This type is client-specific, so we will need to redesign the reactor such that
> it deals with an abstract circuit type instead of the client-specific one.

## A circuit reactor for relays

> Unless specified otherwise, in the rest of this document,
> the word "channel" refers to a Tor channel.
> All references to Rust channel types are prefixed with the
> a channel type (mpsc, oneshot, etc.)

> The terms "tunnel reactor", "circuit reactor", "relay reactor",
> "relay circuit reactor" are used somewhat interchangeably in this document,
> but they all refer to the reactor from tor_proto::tunnel::reactor.

### How many circuit reactors?

We have at least a couple of options here:

  * every circuit gets its own tunnel reactor (a channel reactor spawns N relay
    tunnel reactors, one for each CREATE/CREATE_FAST). IOW, a relay will spawn a
    new task for each circuit, which will enable us to more effectively
    parallelize the work
  * each channel reactor has an associated tunnel reactor
    (so a channel reactors spawns a single relay tunnel reactor
    that handles *all* circuits)

It seems simpler and better for performance to have 1 circuit reactor per
circuit instead of handling all circuits in a single task, so we will implement
the first option.

### Handling incoming channels

From [doc/dev/notes/relay-sketch.md](./relay-sketch.md):

> Relay channels still use the Channel type. There is some API to use when
> constructing a channel, to tell the channel to negotiate using the relay
> protocol, and to accept incoming circuits.

On channels where we have authenticated, we need to start allowing incoming
`CREATE2` and `CREATE_FAST` cells.

> NOTE: The channel reactor will maintain a `CircMap` as before,
> except in this case the circuit allocation is initiated by the receipt
> of a CREATE2/CREATE_FAST cell (instead of `CtrlMsg::AllocateCircuit`),
> and the circuit ID is picked by the initiator.

Upon receiving `CREATE2`/`CREATE_FAST`, the channel reactor will add a new
`CircEnt::Open` in its `CircMap` with the `circID` from received from the
initiator, and respond with a `CREATED2` cell.
The resulting `CircEnt` has a `CircuitRxSender` for sending cells
to its associated relay circuit reactor.

### Opening outgoing channels

The relay reactor will need the ability to open outgoing channels
(with `ChannelType::RelayInitiator`).

We will need a `ChanMgr` equivalent in `tor-proto`. We can't use the `ChanMgr`
from `tor-chanmgr` directly, because `tor-proto` can't depend on `tor-chanmgr`
(it would be a circular dependency).

The creator of the relay reactor will need to initialize it with an
`Arc<dyn ChannelProvider>`, where `ChannelProvider` is a trait
of the form:

```rust

trait ChannelProvider {
   /// Returns the *tor channel* via the `tx` oneshot channel,
   /// enabling the relay circuit reactor to not block on its creation.
   fn get_or_launch_channel(
        &self,
        target: BuildSpec,
        usage: ChannelUsage,
        // TODO: the channel type is not quite right here,
        // we probably one a oneshot-like wrapper
        // over the mpsc sender, because the ChannelProvider
        // is only supposed to yield one channel
        // per get_or_launch_channel call.
        // The reactor OTOH, will listen on the Stream
        // of its mpsc::Receiver for updates on its
        // requested channels
        tx: mpsc::Sender<Result<Arc<Channel>>>,
   ) -> Result<()>;
}
```

Note: all circuit reactors will need to share the *same* `ChanMgr`
(`dyn ChannelProvider`), to enable the reuse of existing channels
where possible.

This is #1447

The circuit reactor will need to maintain a mapping from `CircId` to outbound
(tor) channels(`CircChanMap`). Upon receiving an unrecognized cell,
the circuit reactor will write the cell to the (tor) channel associated
with the `CircId` specified in the cell. This `CircChanMap` will need to
keep track of both the *open* and *opening* channels, and will provide
an API for obtaining a `Stream` that yields newly opened channels
(obtained from the `ChannelProvider`). This stream (`new_channel_stream`
in the diagram below) will be handled by the reactor main loop,
which will add all newly opened channels to the `open` list in the `CircChanMap`.

```

 +-------------------------------------------------------------------------------+
 |    Outbound                                                                   |
 |   channel reactor                                                             |
 | (ChannelType::RelayInitiator)                                                 |
 |                              //======================================(Bounded MPSC)==========\\
 |                              ||                                               |              ||
 |           input              ||           output                              |              ||
 |      +------------------+    ||     +-------------------+                     |              ||
 |      |  ChannelCodec    |    ||     |  ChannelCodec     |                     |              ||
 |      | +--------------+ |    ||     | +---------------+ |                     |              ||
 |      | | TLS stream   | |    ||     | | TLS stream    | |<----\               |              ||
 |      | | +----------+ | |====//     | | +-----------+ | |     |               |              ||
 |      | | | TCP sock | | |           | | | TCP sock  | | |     |               |              ||
 |      | | +----------+ | |           | | +-----------+ | |     |               |              ||
 |      | +--------------+ |           | +---------------+ |     |               |              ||
 |      +------------------+           +-------------------+     |               |              ||
 |                      |                                        |               |              ||
 |                      | deliver message to circuit reactor     |               |              ||
 |                      +--------------------------------+       |               |              ||
 |                                                       |       |               |              ||
 |                                                       |       |               |              ||
 |                                                       |       |               |              ||
 |                                                       |       |               |              ||
 |                            CircMap                    |       |               |              ||
 |  +---------------------------------------------+      |       |               |              ||
 |  |                     ...                     |      |       |               |              ||
 |  |                                             |      |       |               |              ||
 |  |                   CircEnt::Open             |      |       |               |              ||
 |  |         +-------------------------------+   |      |       |               |              ||
 |  |         |              TX               |   |      |  +----------+         |              ||
 |  | CircId: |-------------------------------|<---------+  |   RX     |         |              ||
 |  |         |     CircuitRxSender           |   |         +----------+         |              ||
 |  |         +-------------------------------+   |         | cells    |         |              ||
 |  |                                             |         +----------+         |              ||
 |  |          ...                                |               /\             |              ||
 |  +---------------------------------------------+               ||             |              ||
 |                                                                \\======(Bounded MPSC)==\\    ||
 +-------------------------------------------------------------------------------+        ||    ||
                                                                                          ||    ||
               RelayCirc                                                                  ||    ||
       (it's unclear who will consume this type                                           ||    ||
       but it will likely be an internal                                                  ||    ||
       relay circuit manager. See #1445, #1446)                                           ||    ||
     +-------------------------------------------+   +-------------------------------+    ||    ||
     |      < fields omitted for brevity >       |   | dyn ChannelProvider (ChanMgr) |    ||    ||
     +----||-----------------------||------------+   +-------------------------------+    ||    ||
          ||                       ||                    ||                               ||    ||
          ||                       ||                    ||                               ||    ||
          ||                       ||                    ||                               ||    ||
(Unbounded MPSC channel)  (Unbounded MPSC channel)  (Unbounded MPSC channel)              ||    ||
          ||                       ||                 (limit on outgoing                  ||    ||
          ||                       ||                   channel will be imposed by ChanMg ||    ||
          ||                       ||                    ||                               ||    ||
  +-------||-----------------------||--------------------||---------------------------+   ||    ||
  |       \/                       \/                    \/           Tunnel reactor  |   ||    ||
  | +------------+           +------------+    +--------------------+    (relay)      |   ||    ||
  | |   RX       |           |   RX       |    |        RX          |                 |   ||    ||
  | +------------+           +------------+    +--------------------+                 |   ||    ||
  | |  control   |           |  command   |    | new_channel_stream |                 |   ||    ||
  | +------------+           +------------+    +--------------------+                 |   ||    ||
  |                                                                                   |   ||    ||
  |                                                                                   |   ||    ||
  |                                                                                   |   ||    ||
  |                         +----------------------------------------------------+    |   ||    ||
  |                         | OutgoingFoo (maps CircIds to RelayOutboundCircuits)|    |   ||    ||
  |                         +----------------------------------------------------+    |   ||    ||
  |                         |                                                    |    |   ||    ||
  |                         |                        CircEnt::Open               |    |   ||    ||
  |                         |                  +-------------------------------+ |    |   ||    ||
  |                         |                  |      RelayOutboundCircuit     | |    |   ||    ||
  |                         |                  +-------------------------------+ |    |   ||    ||
  |                         |                  | +-------+  +-------------+    | |    |   ||    ||
  |                         |         CircId:  | |   RX  |  |    TX       |    | |    |   ||    ||
  |                         |                  | |-------|  |-------------|===============||    ||
  |                         |                  | | input |  | chan_sender |    | |    |         ||
  |                         |                  | +-------+  +-------------+    | |    |         ||
  |                         |                  +----/\-------------------------+ |    |         ||
  |                         |                       ||                           |    |         ||
  |                         |                       \\==========================================//
  |                         |                                                    |    |
  |                         |  ===========================                       |    |
  |                         |  === next_circ_action()  ===                       |    |
  |                         |  ===========================                       |    |
  |                         |       TODO                                         |    |
  |                         +----------------------------------------------------+    |
  |                                                                                   |
  |      ==================                                                           |
  |      === run_once() ===                                                           |
  |      ==================                                                           |
  |                          |  * control.next()                                      |
  |           select_biased! |  * command.next()                                      |
  |                          |  * new_channel_stream.next()                           |
  |                          |  * ConfluxSet::next_circ_action()                      |
  |                          |  * OutgoingFoo::next_circ_action()                     |
  |                                                                                   |
  |      ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   |
  |      +      ConfluxSet { circuits: SmallVec<RelayInboundCircuit> }            +   |
  |      +       circuits.len() will always be 1, for now                         +   |
  |      +       essentially, ConfluxSet just serves as an abstraction            +   |
  |      +       over the circuit state and streams                               +   |
  |      +        TODO: we will need to figure out how to implement conflux       +   |
  |      +          for exits, which will likely require another refactoring      +   |
  |      +          in this area                                                  +   |
  |      +                                                                        +   |
  |      +  ===========================                                           +   |
  |      +  === next_circ_action()  ===                                           +   |
  |      +  ===========================                                           +   |
  |      +                                                                        +   |
  |      +  For each circuit leg (returning the result of the future that         +   |
  |      +  resolves first):                                                      +   |
  |      +                                                                        +   |
  |      +                   |  * conflux handshake timeout future                +   |
  |      +                   |                                                    +   |
  |      +                   |                     | * input.next()               +   |
  |      +    select_biased! |  * select_biased!   |                              +   |
  |      +                   |  (if chan sink rdy) | * ready_streams_iter.next()  +   |
  |      +                   |                                                    +   |
  |      +                                                                        +   |
  |      +                                                                        +   |
  |      +    +-----------------------------+                                     +   |
  |      +    | RelayInboundCircuit         |                                     +   |
  |      +    | +-------+  +-------------+  |                                     +   |
  |      +    | |   RX  |  |    TX       |  |                                     +   |
  |      +    | |-------|  |-------------|  |                                     +   |
  |      +    | | input |  | chan_sender |  |                                     +   |
  |      +    | +-------+  +-------------+  |                                     +   |
  |      +    |     /\             ||       |                                     +   |
  |      +    |     ||             ||       |                                     +   |
  |      +    +-----||-------------||-------+                                     +   |
  |      +++++++++++||+++++++++++++||++++++++++++++++++++++++++++++++++++++++++++++   |
  +-----------------||-------------||-------------------------------------------------+
                    ||             \==============\
           (Bounded MPSC channel)       (Bounded MPSC channel)
              (size = 128)          size = CHANNEL_BUFFER_SIZE = 128)
                    ||                           ||
                    ||                           ||
                    ||                           ||
 +------------------||---------------------------||------------------------------+
 |    Incoming      ||                           \/                              |
 |   channel reactor||              +-------------------------------+            |
 | (ChannelType::RelayResponder)    |              RX               |            |
 |                  ||              +-------------------------------+            |
 |                  ||              | cells: Receiver<AnyChanCell>  |            |
 |                  ||              +---------------+---------------+            |
 |                  ||                                        |                  |
 |                  ||        CircMap                  if output is ready,       |
 |  +---------------||----------------------------+      cells.next()            |
 |  |               ||    ...                     |  and deliver cell to sink    |
 |  |               ||                            |           |                  |
 |  |               ||  CircEnt::Open             |           +--------------+   |
 |  |         +-------------------------------+   |                          |   |
 |  |         |              TX               |   |  deliver message         |   |
 |  | CircId: |-------------------------------|<------------------+          |   |
 |  |         |     CircuitRxSender           |   |      to circuit reactor  |   |
 |  |         +-------------------------------+   |               |          |   |
 |  +---------------------------------------------+               |          |   |
 |                                                                |          |   |
 |                                                                |          |   |
 |      ==================                             input      |          |   |
 |      === run_once() ===                    +-----------------------+      |   |
 |      ==================                    |   ChannelCodec        |      |   |
 |         /                                  |  +----------------+   |      |   |
 |         |  * control.next()                |  | TLS stream     |   |      |   |
 | select! |  * input.next()                  |  | +----------+   |   |      |   |
 |         |  * output ready to send          |  | | TCP sock |   |   |      |   |
 |         \                                  |  | +----------+   |   |      |   |
 |                                            |  +----------------+   |      |   |
 |                                            +-----------------------+      |   |
 |                                                                           |   |
 |                                                                  output   v   |
 |                                                         +-------------------+ |
 |                                                         |  ChannelCodec     | |
 |                                                         | +---------------+ | |
 |                                                         | | TLS stream    | | |
 |                                                         | | +-----------+ | | |
 |                                                         | | | TCP sock  | | | |
 |                                                         | | +-----------+ | | |
 |                                                         | +---------------+ | |
 |                                                         +-------------------+ |
 +-------------------------------------------------------------------------------+
```

### Can we use the existing tunnel reactor?

We should try to reuse as much of the client tunnel reactor as possible,
as much of the logic is shared.

The plan is to refactor the base reactor to be generic,
and pull the implementation-specific (client, relay) parts into separate types:

The base reactor will be generic over `CtrlCmd`/`CtrlMsg` (because relays won't
support the same set of control commands as clients), which will be sent by a
`RelayCirc` object (see #1445, #1446)

The tunnel reactor will also need an abstraction for the subcomponents
that represent the incoming and outgoing channels.
The current version of the client reactor has a `ConfluxSet`,
which is a leaky abstraction over the "outgoing state"
(for the forward direction) of the circuit.
`ConfluxSet` is mostly opaque, and yields a stream of `CircuitAction`s that
the reactor acts upon.
The plan is to further refine this `ConfluxSet` abstraction,
and make it usable as both the incoming and the outgoing subcomponent
(needed by exits and clients, respectively).
The concrete types of the incoming/outgoing components won't be known
within the base reactor itself, but they will all implement a shared interface
(modeled as a trait).

```rust
// TODO: figure out what traits T, T::Incoming, T::Outgoing will need to implement
struct BaseReactor<T> {
    control: mpsc::UnboundedReceiver<T::CtrlMsg>,
    command: mpsc::UnboundedReceiver<T::CtrlCmd>,
    reactor_closed_tx: oneshot::Sender<void::Void>,
    // `incoming` and `outgoing` are types that can be polled
    // to obtain a CircuitAction the reactor can execute
    // in its main  loop.
    //
    // For clients `incoming` will be set to a no-op type
    // that returns a stream of actions that never yields anything,
    // and `outgoing` will be a `ConfluxSet<ClientCirc>`.
    incoming: T::Incoming,
    outgoing: T::Outgoing,
    ...
}

pub(crate) type ClientReactor = BaseReactor<ClientFoo>;
pub(crate) type RelayReactor = BaseReactor<RelayFoo>;
```

## Future redesign

@nickm suggests a better design might be to split the circuit reactor into
multiple different reactors (one for each reactor subtask).
This would make the code easier to understand, and simpler to extend,
as we will have fewer nested `select_biased!`s.

To achieve this, we would need to rewrite the existing tunnel reactor
as multiple different composable reactors.
With this implementation, each circuit will have its own circuit reactor,
even if the circuit is part of a multi-path conflux tunnel
(as opposed to the current state of affairs where a single
tunnel reactor manages multiple circuits).
The resulting circuit reactor will be conflux-agnostic,
and therefore suitable for relays too (with some modification).
The decision of which circuit to send outgoing cells on
will be delegated to a different task.

TODO: this is very light on details right now, and will require a more
detailed design before we can implement it
