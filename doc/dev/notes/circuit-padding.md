# Implementing circuit padding in Arti

We're using Maybenot as our backend for circuit padding.
Maybenot provides a general framework for padding,
which we won't document fully here.
Instead, we'll describe the design decisions we've made
about _how_ to instantiate Maybenot within Arti.

This is up to date as of 3 Sep 2025.
As of this writing, our circuit padding support is not fully built,
so some of this document is speculative.

## Our outbound queues

For reference, here's a diagram of how our queues work
for outbound RELAY cells today.

```text
             Per-circuit queues
               |
               V
   Circ --> (Queue) --> MPSC Sender \
                                     --> MPSC Receiver --> Channel --> TLS --> TCP
   Circ --> (Queue) --> MPSC Sender /     (Queue)
                                              ^-- Per-channel queue
            |---------------------|
              SometimesUnboundSink
```

Note that every Tor channel has a single MSPC sender/receiver pair
that circuits use to send it cells.
Every MPSC Sender/Receiver instance shares a single queue of cells.
If this queue is full, the circuit can queue more cells
on a circuit-specific deque.
(Currently, it only does this for control messages,
never for data.)

> Note that we might, in the future, tweak the SometimesUnboundedSink queue
> so that it can be filled _up to a point_ by data messages,
> before they get flushed to the channel.
>
> We're also likely to refactor this whole business severely when
> implement proper circuit-mux support, so it might not be so worthwhile
> messing with it right now.

## Frameworks and circuits

We assume that each hop of a circuit
has zero or one `maybenot::Framework`s,
tracking padding sent to and from that hop of the circuit.

Each framework has at least one padding machine.

## The events we trigger

First off, we need to define the exact time
when each traffic-related event is generated.
For outbound traffic, we trigger PaddingSent or NormalSent
as soon as the relevant RELAY cell is queued.
We trigger TunnelSent when the cell is given
to the TLS connection object.

> Note that there is therefore some delay
> between when we trigger TunnelSent
> and when the cell is actually sent over the network.
> Depending on TCP congestion,
> this delay can be significant and variable.

For inbound traffic,
we either trigger (TunnelRecv,PaddingRecv) or (TunnelRecv,NormalRecv)
when each RELAY cell is decrypted.
(We can't trigger TunnelRecv at the time that the cell is first received,
since we don't yet know which hop sent it.)

Now, consider Tor's multi-hop architecture.
In a circuit with relays R1, R2, R3, and so on,
any cell (normal or padding) that we send to R3
will first traverse R1 and R2 as a normal cell.
Correspondingly, any cell that we receive from R3
will have also been sent towards us by R1 and R2
as a normal cell.

Therefore,
whenever we trigger a set of "Sent" or "Recv" events for hop Rn,
we must also trigger Sent or Recv events
for intermediate hops R1..R(n-1).
Regardless of the Padding/Normal status of the cell
sent or received from hop Rn,
the intermediate hops all receive "Normal" events, not Padding.

This, combined with the fact that we send TunnelSent
at the time a cell is flushed,
means that we need to remember the target hop for each queued cell.
We do this in a `QueuedCellPaddingInfo` struct.

## Interacting with congestion control

We do not have any _direct_ interaction
between padding and congestion control.

However, since our blocking design below
allows a circuit's outbound cell queue to become blocked
for reasons other than becoming full,
we need to look at the blocking status of the inner MPSC sink
(the one connected directly to the channel).

> TODO: Do we actually want to do this?
>
> See discussion at
> <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3225#note_3252061>.

## Scope of blocking

Maybenot defines the ability for padding machines
to block or unblock traffic.

As we'll implement it in the first version of our padding wrappers,
all blocking is done at the circuit level, not at the hop level.

> Per-hop blocking would better reflect the overall design of maybenot,
> but it presents certain difficulties.
> Notably, if a later hop is blocking traffic, and a cell for that hop is queued
> (and encrypted),
> then we can't deliver traffic to any _earlier_ hops,
> since each circuit's encrypted cells must be sent in order.

When traffic is blocked on a circuit,
then we do not flush any traffic for that circuit.
Specifically, we do not flush any traffic for the circuit's
SometimesUnboundedSink queue;
but any traffic that has already been queued on the per-channel
MPSC queue _will_ be sent.

> This implies that even after blocking has begun,
> padding machines will still receive some TunnelSent events,
> since we have no way to stop per-circuit traffic
> once it gets onto the channel queue.
> (This is supported.)

We also treat the per-circuit outbound queue as "full"
with respect to adding more normal DATA messages to that circuit.
(Control messages can still be enqueued,
since arti breaks badly if they can't.)

We consider a circuit's blocking to be _bypassable_
if the bypass flag for _every_ blocking hop is set.

## Padding flags

Maybenot defines two flags for padding: `bypass`
(to indicate that bypassable blocking should, in this case, by bypassed)
and `replace`
(to indicate that normal data, if we have any, may replace the padding).

We treat these flags as follows:

- When not blocking:
  - bypass: does nothing.
  - replace: If we have any cells in the per-circuit queue,,
    do not queue padding as well
    Otherwise queue padding.

- With bypassable blocking:
  - !bypass: Queue a padding cell.
  - bypass: Queue a padding cell.  If the per-circuit queue was empty,
    allow that cell to be flushed.
  - replace: If the stream is empty,
    try to queue a data cell if any stream can read.
    If the stream is still empty,
    queue a padding cell.
  - replace+bypass: If the per-circuit queue was empty,
    try to queue a data cell if any stream can read.
    If the stream is still empty,
    queue a padding cell.
    Allow a single cell to be flushed.

- With non-bypassable blocking:
  - !replace: Queue a padding cell.
  - replace: If the stream is empty,
    try to queue a data cell if any stream can read.
    If the stream is still empty,
    queue a padding cell.

## Receiving padding

We treat an incoming RELAY cell as padding
if it contains _only_ a DROP message.
Any cell containing any fragment of any other message type
is not padding.

Padding is only allowed from hops where padding machines have been
negotiated. If padding arrives from any other hop,
the client _should_ destroy the circuit with a warning.

> For hops where padding has been negotiated,
> we may keep overall limits of the number or fraction of padding messages
> that may be accepted.
> These limits will be associated with a set of padding machines.
>
> We'll need to specify these.
> They might have to be future work.
>
> For one possible design, see
> <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3225#note_3251976>.


## Sets of padding machines

Instead of letting the client negotiate each padding machines independently,
we define _sets_ of padding machines.
These sets, not the machines themselves,
are now the subject of `PADDING_NEGOTIATE` messages.

> Other designs here would require changes in the maybenot API,
> as well as changes to the `PADDING_NEGOTIATE` protocol,
> and it's not clear that they'd actually serve us any better.

For now, all padding machines and sets of padding machines
need to be hardcoded in Arti.
We may revisit this to make experimentation easier,
but we don't plan to support e.g. consensus-provided padding machines.

## Advertising which padding machines are supported

> TODO: This needs a proposal.  This could be as simple as a new set of
> subprotocol capabilities; a "PaddingSet" to go with "Padding".
> Or we could say that each "Padding" capability corresponds
> to a group of sets of padding machines that are available.

## Optimization assumptions.

Here are some assumptions we're making,
with respect to how to optimize:

- A significant fraction of all circuits will have padding enabled,
  and a significant fraction will not.
- On such circuits, typically one or two hops will have padding enabled.
- There will almost never be more than ~5 padding machines per hop.
- Nearly all users will build Arti with padding enabled.
- We will never need to support an arbitrary chain of
  UptimeTimer->TimerBegin->UpdateTimer triggers and actions;
  it's okay to end them after 3..4 cycles.

# Future work

- Perhaps add the ability to negotiate padding as part of the circuit
  handshake.

- When we build circuit-muxes, make their blocking behavior smarter.

- Tweak maybenot API so that we enter machines with a TriggerEvent::Startup event.

