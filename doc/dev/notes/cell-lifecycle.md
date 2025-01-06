# Cell life cycle

**Important: this is up to date with 834a51c7eb795750015d653812fa7df89f7466b7**

Unless specified otherwise, this document describes
the *current* state of affairs.

> This document describes the cell delivery flow,
> *not* the high-level life cycle of a circuit or channel.
> You can read about about the life cycle of circuits and channels
> in the [`ClientCirc`] and [`Channel`] docs, respectively.
>
> Stream management and prioritization is also not covered here.
> See the `StreamMap`, `StreamPollSet` docs, and the use of `StreamMap`
> in the circuit reactor to learn about stream management.

## TLDR

This diagram summarizes the message flows discussed in the rest of this doc:

```

            ClientCirc
  +-------------------------------------------+
  |                                           |
  |  +-------------------------------------+  |
  |  |                TX                   |  |
  |  +-------------------------------------+  |
  |  | control: UnboundedSender<CtrlMsg>   |  |
  |  +-------------------------------------+  |
  +---------------------||--------------------+
                        ||
                        ||
                        ||
              (Unbounded MPSC channel)
                        ||
                        ||
 Circuit reactor:       ||
  +---------------------||-------------------------------------------------------+
  |                     \/                                                       |
  |        +-------------------------------------+                               |
  |        |                RX                   |                               |
  |        +-------------------------------------+                               |
  |        | control: UnboundedReceiver<CtrlMsg> |                               |
  |        +-------------------------------------+                               |
  |                                                                              |
  |      ==================                                                      |
  |      === run_once() ===                                                      |
  |      ==================                                                      |
  |      * control.poll_next()                                                   |
  |      * input.poll_next()                                                     |
  |      * chan_sender.poll_ready_unpin_bool()                                   |
  |      * if chan_sender is ready and SENDME window is open                     |
  |        for each hop see if there are any cells to send                       |
  |      * chan_sender.poll_flush()                                              |
  |                                                                              |
  |             +----------------------------+                                   |
  |             |           RX               |                                   |
  |             |----------------------------|                                   |
  |             | input: CircuitRxReceiver   |                                   |
  |             +----------------------------+                                   |
  |                 /\                                                           |
  |                 ||         +----------------------------------------------+  |
  |                 ||         |                       TX                     |  |
  |                 ||         |----------------------------------------------|  |
  |                 ||         | chan_sender: SometimesUnboundedSink<         |  |
  |                 ||         |                AnyChanCell, ChannelSender>   |  |
  |                 ||         +----------------------------------------------+  |
  |                 ||                                     ||                    |
  |                 ||                                     ||                    |
  +-----------------||-------------------------------------||--------------------+
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
 |                                                                           |   |
 |                                                     output                v   |
 |                                            +--------------------------------+ |
 |                                            |   ChannelCodec                 | |
 |                                            |  +---------------------------+ | |
 |                                            |  | TLS stream                | | |
 |                                            |  | +-----------------------+ | | |
 | +-------------------------------------+    |  | | TCP sock              | | | |
 | |                RX                   |    |  | | (soon to be KIST sock)| | | |
 | +-------------------------------------+    |  | +-----------------------+ | | |
 | | control: UnboundedReceiver<CtrlMsg> |    |  +---------------------------+ | |
 | +-------------------------------------+    +--------------------------------+ |
 |                      /\                                                       |
 +----------------------||-------------------------------------------------------+
                        ||
                        ||
              (Unbounded MPSC channel)
                        ||
    Channel             ||
  +---------------------||--------------------+
  |                     ||                    |
  |  +-------------------------------------+  |
  |  |                TX                   |  |
  |  +-------------------------------------+  |
  |  | control: UnboundedSender<CtrlMsg>   |  |
  |  +-------------------------------------+  |
  +-------------------------------------------+

```

## Creating a channel

Channels are (typically) created using a `ChanBuilder`
(using its `ChannelFactory::connect_via_transport` impl).
The underlying connection (usually TCP) is established using the
`TransportImplHelper` contained within the `ChanBuilder`.

`ChanBuilder::connect_no_timeout`
(called from the `ChannelFactory::connect_via_transport` impl)
does all the work for creating and launching the channel. This function
  * establishes the TCP connection
  * performs the client handshake
  * spawns the channel reactor in a separate task

> Note: the above describes the way client-initiated channels are launched.
> For relays, we will also have a separate `ChannelFactory`-like trait
> called `IncomingChannelFactory`, which is not described here.

`ChanBuilder::connect_no_timeout` returns a `Channel`,
which can be used to send control messages to the channel reactor,
or to obtain a `ChannelSender` that can directly send cells down the channel.

One thing to note here is that
after negotiating the link protocol, we wrap
the underlying transport stream in a [`futures_codec::Framed`]
(see `ChannelCodec`).
The stream is then `split()` (grep for `tls.split()`)
and its read/write handles are stored separately.
These become the `sink` and `stream` parts of the channel.
But note these aren't stored in `Channel` itself,
but in the channel *reactor* (as its `input` sink and `output` stream).

## Creating a circuit

Once you have a channel, you can create a circuit.

Client circuits are created using `PendingClientCirc`.
You can obtain a `PendingClientCirc` and a corresponding circuit reactor
from `Channel::new_circ()`, which registers a new circuit with the channel reactor.
It does this by sending a `channel::CtrlMsg::AllocateCircuit` control message.
These control messages are sent over an *unbounded* MPSC channel
(see the `mpsc::UnboundedSender` `control` field in `Channel`).

After the circuit reactor is spawned,
it *awaits* on `wait_for_create` until it receives a control message,
which is expected to be either `CtrlMsg::Create` or `CtrlMsg::Shutdown`.
This is described further in the "Sending CREATE cells" section below.

### Handling `AllocateCircuit` control messages

In the channel reactor (in `handle_control`):
  * a new circuit ID is computed
  * the circuit is added to the `self.circs` circuit map,
    which maps circuit IDs to sinks that `ClientCircChanMsg`s[^1] can be written to.
    (the *receiving* end of each sink is held
    by its corresponding circuit reactor.
    IOW, this is the channel the circuit reactor receives cells from).
    The map entry is `CircEnt::Opening` entry, that is initially inert

To mark the circuit as open, the entry is replaced with a `CircEnt::Open`
entry using `CircMap::advance_from_opening`.
This `CircEnt::Open` entry contains the aforementioned `CircuitRxSender` sink
down which `ClientCircChanMsg` messages for this circuit are sent.
This is the sending end of an MPSC channel that has a buffer of size 128
(see `Channel::new_circ`). Its total capacity is 129 (`buffer-size + num-senders`).

**All of this is internal state management.
Nothing gets sent to the network at this point**

### Sending CREATE cells

Circuits are created by sending a `circuit::CtrlMsg::Create`
to the circuit reactor via an `mpsc` channel.

> At the time of writing, the only type of circuit supported is the `ClientCirc`
> (a circuit initiated by the client).

Client circuits can be created using `PendingClientCirc::create_firsthop_ntor_v3`,
which creates a 1-hop `ClientCirc` that can later be extended
using `ClientCirc::extend_ntor`
(there are other `create_firsthop_*` functions,
but they're not described here for brevity).
Under the hood, `PendingClientCirc::create_firsthop_ntor_v3`
sends a `circuit::CtrlMsg::Create` control message
to the circuit reactor to create the 1-hop circuit.

In the circuit reactor, the message is received via the unbounded
`control: mpsc::UnboundedReceiver<CtrlMsg>` MPSC channel.

So, when the reactor receives a `CtrlMsg::Create` message, it calls
`Reactor::create_impl` via `Reactor::create_firsthop_ntor_v3`
(note this is **not** the same function as the function with the same name mentioned above),
which is where the magic happens.

`Reactor::create_impl` creates the cell and then sends it over to the
circuit's channel reactor for delivery via the `self.chan_sender` channel:
  * `self.chan_sender` is an **unbounded** `SometimesUnboundedSink` that wraps
  a `ChannelSender`
  * the cell is written to `self.chan_sender` in `Reactor::send_msg_direct`,
  which calls the `pollish_send_unbounded` function of the unbounded sink to
  enqueue (or send!) the cell on the sink
  * the important thing to note here is that `chan_sender` (`SometimesUnboundedSink`)
  has an internal **unbounded** buffer than contains cells that couldn't be sent
  right away (i.e. the cells the `ChannelSender` sink blocked on)

## Places where we buffer data *unboundedly*

The places where cells may be buffered unboundedly include:

* the `chan_sender` in the circuit reactor: `circuit::Reactor` --`SometimesUnboundedSink<AnyChanCell, ChannelSender>`---> `channel::Reactor`
* the `control` channel in `ClientCirc`: `ClientCirc` ----unbounded `Reactor::control` ctrl channel-----> `circuit::Reactor`

However, currently neither of these channels can be made
to buffer unboundedly remotely.
See the explanation in the `circuit::Reactor::chan_sender` docs
for more details.

As for the bounded buffers/queues, see the diagram above.

-------

## How does all of this affect how we implement KIST?

We continue reading from the stream, but we stop writing to it.

1. We can no longer write to `channel::Reactor::output`
   because KIST says "no more!".
   As a result `self.output.prepare_send_from()` will block
   (technically speaking the future will be pending)
2. We stop reading from `channel::Reactor::cells`,
   because the channel reactor only reads from `cells` if the `output` sink
   is ready to receive more cells.
   Consequently, the sender (`circuit::Reactor::chan_sender`) will start buffering
   any cells written to it, until it's filled
   with `CHANNEL_BUFFER_SIZE + num-senders` = 129 cells
3. The channel reactor continues reading from the channel's `input` stream.
   The cells read are sent to the circuit reactor of their corresponding circuits.
   In the circuit reactor, these are received on the `circuit::Reactor::input`
   queue, which is **bounded** (with a bound of `128 cells + num-senders` = 129 cells)
4. When the `circuit::Reactor::chan_sender` is filled with 129 buffered cells,
   technically the circuit reactor will start buffering in the unbounded sender
   (which wraps the bounded MPSC channel).
   However, we do not expect to buffer unboundedly here, because
   the reactor first calls `chan_sender.poll_ready_unpin_bool`
   to check if the channel is ready to receive any more cells
   (and if not, it will stop trying to write)
5. In the circuit reactor, `chan_sender` is not ready,
   so we move on and flush it (`poll_flush`).
   `chan_sender.poll_flush()` will be `Pending` too, but that's okay
   because the circuit reactor doesn't block on it.
6. In the circuit reactor, we continue reading from `input`
   which receives `ClientCircChanMsgs` from the corresponding circuit entry
   from the channel reactor's circuit map.
7. But reading from `input` means having to respond to the received cell,
   e.g. by sending a circuit-level SENDME.
   The other end won't receive our "response" though,
   because our "response" cells will get queued
   until our KIST Socket says it's ok to write some more

However, when KIST-limiting kicks in, we don't expect to actually receive
more cells via `input` queue. This is because the lack of SENDMEs from
us should count as a congestion signal to the other edge of the connection,
which will stop sending, assuming it's well-behaved.
But if the other side does not impl congestion control the way we expect
(meaning we notice output queues such as the unbounded `chan_sender` start to fill up),
we need to be able to kill the circuit (something we don't currently do)

Rough KIST implementation plan:
  * [ ] Implement prop324 congestion control
  * [ ] Add a new `TransportImplHelper` that wraps a KIST write-limited `KistSocket`
    (Linux only, for now)
  * [ ] Make the circuit reactor kill circuits whose `chan_sender` sink
    is buffering too many unsent cells
  * [ ] Implement the (as yet unwritten) ["SENDME everywhere"] proposal,
which will enable us to be lower the circuit cut-off queue length limit

[^1]: `ClientCircChanMsg` is the subset of channel messages allowed allowed to
    arrive on a client circuit

[`ClientCirc`]: https://docs.rs/tor-proto/0.24.0/tor_proto/circuit/struct.ClientCirc.html#circuit-life-cycle
[`Channel`]: https://docs.rs/tor-proto/0.24.0/tor_proto/channel/struct.Channel.html#channel-life-cycle
[`futures_codec::Framed`]: https://docs.rs/futures_codec/0.4.1/futures_codec/struct.Framed.html
["SENDME everywhere"]: https://gitlab.torproject.org/tpo/core/torspec/-/issues/216
