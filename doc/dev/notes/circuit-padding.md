# Implementing circuit padding in Arti

We're using Maybenot as our backend for circuit padding.
Maybenot provides a general framework for padding,
which we won't document fully here.
Instead, we'll describe the design decisions we've made
about _how_ to instantiate Maybenot within Arti.

This is up to date as of 3 Sep 2025.
As of this writing, our circuit padding support is not fully built,
so some of this document is speculative.

This document describes both client-side and relay-side Maybenot instantiation, but
our we have only implemented client-side Maybenot framework support
at this time (Sep 2025). The relay-side information is provided to enable accurate
simulation in the Maybenot simulator framework, to support research into
Tor-specific Maybenot defense machines.

We do not expect to deploy any actual Maybenot defense machines until arti-relay is
suitable for middle relay usage, at the earliest.

## Our outbound queues

For reference, here's a diagram of how our queues work
for outbound RELAY cells today.

<div id="queue-diagram">

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

</div>

Note that every Tor channel has a single MPSC sender/receiver pair
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

## Intended Usage of Maybenot

We intend to use the Maybenot framework in two places in the Tor network, with
different padding characteristics, different adversary models, and for
orthogonal purposes. Proposal 344 provides the context necessary to understand
why we are choosing this deployment strategy.

Machines that require heavy amounts of padding traffic will be negotiated with
Guard nodes, and will defend against TLS observers only.  Machines that require
less traffic will be negotiated with middle nodes, to defend against malicious
Guard nodes.

The target attack categories for these initial deployments will be website
traffic fingeprinting and handshake fingerprinting.

Website Traffic Fingerprinting defenses generally operate during stream usage,
require far more overhead, and may perform minimal blocking of stream traffic. These
defenses will be negotiated with Guards. The adversary model in this case is one
that can observe the TLS connection to the Guard.

Handshake fingeprinting defenses typically will be used prior to stream usage, during
circuit setup, conflux, and onion service handshakes. They require much less
traffic, and will be negotiated with a middle hop. The adversary model in this
case is a malicious Guard, as well as one that can observe the TLS connection.

> NOTE: This does NOT mean that we are ignoring the website traffic fingeprinting
> attacks with respect to the malicious Guard threat model. As Proposal 344
> explains: eliminating handshake fingerprinting will removes onion service
> circuit oracles, which will reduce accuracy of website fingerprinting attacks
> against onion services, and to a lesser extent, regular circuits as well.

> In order to support any further defenses against this threat model that require
> larger amounts of padding traffic during actual stream usage, we will need
> improvements to congestion control, such as
> [backward ECN](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/ideas/xxx-backward-ecn.txt).

## Frameworks and circuits

We assume that each hop of a circuit
has zero or one `maybenot::Framework`s,
tracking padding sent to and from that hop of the circuit.

Each framework has at least one padding machine.

> NOTE: Because our guard-negotiated machines only concern themselves with a
> TLS-observing adversary (as per the [Intended Usage](#intended-usage-of-maybenot)
> section above), there is no benefit from using a separate guard-negotiated maybenot
> framework for each circuit. As a
> [future optimization](https://gitlab.torproject.org/tpo/core/arti/-/issues/2189),
> we intend to refactor the implementation so that guard-negotiated machines only have
> one framework for all circuits, to eliminate the likelihood of redundtant padding.
> Middle-negotiated machines, on the other hand will retain one framework per circuit.

## Constraints on Maybenot Padding and Blocking

In order to avoid excessive queueing and negative interactions with
circuit setup and congestion control, our implementation and acceptable
defense deployment is constrained compared to what is supported by Maybenot.

We satisfy these constraints through modification of the Maybenot [blocking rules](#blocking) and
[Padding flag behaviors](#padding-flags), and through some additional conventions for
acceptable Padding machines.

This section contains the non-normative motivation and explanation for those
rules and flag behaviors.

### Control Cells Must Not Be Blocked

Padding machines MUST NOT block circuit activity during circuit setup, confux,
and onion service handshakes. If these commands are blocked by either client or
relay-side machines, the Tor client will time out on handshakes and close the
circuit.

> In the case of circuit build timeout, the difference between accepting a circuit versus
> disarding it is in the milliseconds range. Similar amounts of delay
> can cause conflux to change which leg it decides to use for initial data
> transmission, cause it to discard legs, and/or cause it to abandon the tunnel entirely
> and build a new one.
>
> While defenses that add a fixed amount of delay to *all* cells (for example to spoof
> location-based network latency) theoretically do not have this problem, this
> defense is far better implemented via `tq` or other mechanisms to apply delay
> at network interfaces (for example, by running arti in a container, or via
> onionmasq).
>
> Additionally, our current understanding of these attacks is that they are not worth
> this complexity. See Proposal 344 for details.

Additionally, SENDME cells SHOULD NOT be blocked, as they will cause congestion
control to reduce throughput of _**the other direction of traffic**_, in proportion
to the amount of delay of the SENDME. This problem is most severe at the client,
where blocking **outgoing** SENDME cells will cause **incoming** speeds to drop in
proportion to outgoing SENDME delay.

We ensure that all control cells are exempt from blocking at the client-side
machines by defining blocking to operate only on the packaging of DATA cells
in the [Blocking for Client-side Machines](#blocking-for-client-side-machines).

We ensure that critical circuit-setup control cells are not delayed relay-side, by requring
that relay-side machines MUST NOT block while the usage of RELAY_EARLY cells is ongoing,
in the [Blocking for Relay-side Machines](#blocking-for-relay-side-machines) section.

### Interacting with congestion control

For both client-side and relay-side machines, there are no *direct* interactions
between padding machines and congestion control. Padding machine induced blocking
is NOT a congestion signal to the congestion control system (unlike TLS-induced blocking,
which is such a signal).

Addtionally, we do not have *any* interaction between padding and congestion control at
client-side machines, because our [Client-side Blocking Design](#blocking-for-client-side-machines)
only operates on the packaging of DATA cells from streams. With this design, client-side blocking
is always safe to use, because blocking at this point only causes _local pushback_ on streams,
and does not interfere with the RTT measurement of DATA cell delivery vs SENDME responses.

However, since our [Relay-Side Blocking Design](#blocking-for-relay-side-machines) allows
a circuit's inbound (toward-the-client) cell queue to become blocked for reasons other
than becoming full, it is possible for relay-side blocking to cause the delay of queued SENDME
cells towards the client, thus diminishing client _upload_ speeds.

This is an unavoidable consequence circuit encryption. It will be more
severe when SENDMEs outnumber DATA cells (ie: relay-side inbound delay will
kneecap client upload ability, generally, and in a difficult to control manner).

Additionally, excessive relay-side blocking will create circuit queue buildup in the
relay. If this delay is short in duration and happens to be evenly
distributed with respect to actual DATA cells (as opposed to SENDME cells),
congestion control will correctly measure this delay and adjust throughput
accordingly, in the actual direction traffic being delayed, so that queues do
not increase in size.

Excessively long and intermittent relay-side blocking will result in queue
accumulation and eventual circuit close, due to individual circuit queue limits
and/or OOM killer limits being hit.

For these reasons, relay-side machines should minimize blocking, or avoid it entirely.

> See
> <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3225#note_3252061>
> for more discussion.

### Guard padding and TCP-blocked channels

We need the ability to avoid sending padding to a guard
when the outbound channel to that guard is too full. This is essential
for our heavy-weight website traffic fingerprinting machines to be usable
without bloating queues and/or overloading the network.

By ensuring that padding is omitted when the TCP connection is blocked, we
favor using spare Guard capacity for padding, rather than increasing contention
for Guard capacity.

To achieve this, we require padding machine designers to _only_ generate 'replace'
padding with Guard-negotiated machines, at both the client and the Guard machines.

With our implementation of [Padding flags](#padding-flags), 'replace' padding
will ensure that excessive padding to the first hop is never generated, since we
consider _any_ cells queued to the first hop as acceptable replacements for
first-hop padding.

> NOTE: We do not perform any accounting on this replacement. A single queued cell
> can replace an infinite number of padding cell requests, for as long as it remains
> in the queue.

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

> (As an exception, when we treat an already queued cell as padding
> because of a "replace" flag,
> we trigger a PaddingSent event for the target hop,
> and nothing else, since no actual data was sent
> through the intermediate hops.)

This, combined with the fact that we send TunnelSent
at the time a cell is flushed,
means that we need to remember the target hop for each queued cell.
We do this in a `QueuedCellPaddingInfo` struct.

## Blocking

Maybenot defines the ability for padding machines
to block or unblock traffic, including padding cells from other machines.

In this document, generic usage of the term "blocking" refers to this blocking requested
by padding machines, unless we explicitly say otherwise (for example in the
[Guard padding and TCP-blocked channels](#guard-padding-and-tcp-blocked-channels) section
above).

### Scope of blocking

As we'll implement it in the first version of our padding wrappers,
all blocking is done at the circuit level, not at the hop level.

> Per-hop blocking would better reflect the overall design of maybenot,
> but it presents certain difficulties.
> Notably, if a later hop is blocking traffic, and a cell for that hop is queued
> (and encrypted),
> then we can't deliver traffic to any _earlier_ hops,
> since each circuit's encrypted cells must be sent in order.

#### Blocking for Relay-side Machines

At relays, when traffic is blocked on a circuit,
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

Relay-side machines MUST NOT block while the usage of RELAY_EARLY cells is ongoing.

Relay-side blocking will happen _only_ on the inbound (toward-the-client)
circuit queue. Outbound traffic must be blocked by client-side machines.

#### Blocking for Client-side Machines

On client-side machines, blocking requests cause us to treat the per-circuit
outbound queue as "full" with respect to adding more normal DATA messages to
that circuit.

Crucially, this blocking must happen such that congestion control does NOT measure
it as additional delay on these DATA cells, during its RTT calculations. So long as
this blocking happens such that no further DATA cells are packaged, there will be
no such interference.

Non-DATA messages can still be enqueued, since arti breaks badly if they can't.
Additionally, this also means that non-DATA won't be delayed by blocking, which
is important for most (if not all) control cells in the Tor protocol.

> Similar to the relay-side, this means that additional TunnelSent events will
> be delivered after blocking. Additionally, NormalSent events will still be delivered
> if any control messages are generated by Arti during this block.

### Kinds of Blocking

Maybenot defines two kinds of blocking: _bypassable blocking_ and
_non-bypassable blocking_. These govern how padding interacts with blocking
and any queued packets.

We consider a circuit's blocking to be _bypassable_ if the bypass flag for
_every_ blocking hop is set.

The Maybenot framework
[specifies how padding behaves](https://docs.rs/maybenot/latest/maybenot/#blocking),
under each kind of blocking for these flags, but it assumes that padding may bypass a queue.
Since queue bypass is not possible in Tor, all padding cell delivery happens via
the same queues as all other cells, as per the MPSC diagram above.

Thus, while we can allow cells to be packaged from streams and/or flushed from
the head of the queue for bypassable blocking, we cannot ensure if it is padding
or non-padding in all cases. This changes our implementation of the padding
flags during bypassable blocking, as specified below.

## Padding flags

Maybenot defines two flags when requesting a padding cell: `bypass`
(to indicate that bypassable blocking should, in this case, be bypassed)
and `replace`
(to indicate that normal data, if we have any, may replace the padding).

We treat the Maybenot flags as follows:

- When not blocking:
  - bypass: does nothing.
  - replace: If the queue[^1] contains no cells for the target
    hop or later, queue a padding cell (there should be
    no pending stream data in this case).

- With bypassable blocking:
  - !bypass: Queue a padding cell.
  - bypass: Queue a padding cell.
    At relays, allow a single cell to be flushed,
    _if_ the channel permits it.
  - replace:
    If the queue[^1] contains no cells
    queued to the target hop or later,
    try to queue a data cell if any stream can read
    else queue a padding cell.
  - replace+bypass:
    If the queue[^1] contains no cells
    queued to the target hop or later,
    try to queue a data cell if any stream can read,
    else queue a padding cell.
    At relays, allow a single cell to be flushed.
    _if_ the channel permits it.

- With non-bypassable blocking:
  - !replace: Queue a padding cell.
  - replace:
    If the queue contains no cells
    queued to the target hop or later,
    try to queue a data cell if any stream can read,
    else queue a padding cell.

[^1]: If the padding is for any hop other than the first,
      we consider only the per-circuit queue when deciding whether to queue 'replace' padding.
      If the padding is for the first hop,
      we consider the per-circuit queue _as well as_ the channel queue,
      and we consider _any cell queued on the same channel_
      to be an acceptable replacement for padding to the first hop.

> Note that we don't ordinarily put DATA messages onto per-circuit queues
> unless they would be flushed immediately to the Channel.
> Therefore, per-circuit queues will _usually_ be empty
> unless we have queued a cell with non-DATA message
> when the Channel's queue was blocked.
>
> Additionally, as of Sep 2025, Arti only partially implements the replace flag.
> When the replace flag is set,  Arti _does_ decline to send padding
> when there are already messages on the relevant queue(s).
> But Arti _does not yet_ honor the replace flag
> by packaging pending data from streams. This means that
> in practice, the replace flag will usually only replace control cells,
> and only when the channel's queue is blocked. A proper implementation
> of replace is [complicated and may require changes to
> maybenot](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3276/diffs#note_3263262)

## Receiving padding

We treat an incoming RELAY cell as padding
if it contains _only_ a DROP message.
Any cell containing any fragment of any other message type
is not padding.

Padding is only allowed from hops where padding machines have been
negotiated. If padding arrives from any other hop,
the client _should_ destroy the circuit with a warning.

For hops where padding has been negotiated,
we may keep overall limits of the number or fraction of padding messages
that may be accepted.
These limits will be associated with a set of padding machines.

In particular, we can configure:
 - A maximum fraction of incoming cells from this hop
   that may be padding.
 - A minimum threshold number of received cells below which the above limit does not apply.

> For example, if the maximum padding fraction is 0.25,
> and the threshold is 10,
> then we kill the circuit whenever
> `n_padding_received + n_normal_received >= 10`
> and
> `n_padding_received / n_padding_received + n_normal_received > 0.25`.

> For a more sophisticated design, see
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

## Per-Channel padding

In addition to per-circuit padding with maybenot,
we also support per-channel padding.
We expect that this will give better performance and security
than would using a separate framework for the first hop of each circuit
on the same channel.

We implement per-channel padding in the channel reactor,
marked "Channel" in our [queue diagram](#queue-diagram) above.

Every time _any_ cell is queued on a circuit queue,
we trigger a `NormalSent` event for the channel padding framework.
We only give the channel padding framework `PaddingSent` events for padding
that it tells us to generate.
We trigger `TunnelSent` when a cell is given to the TLS framing queue.

From the point of view of the "replace" flag,
we treat our outbound queue as having a message already
if the TLS framing queue is _full_.

>We would prefer to treat the outbound queue as having a message ready
>if it has _any_ data cells.
>But the current TLS and `futures_codec` implementations
>don't give us a way to do that.

The Tor protocol already has a simple channel padding mechanism,
used to resist netflow-based adversaries.
Since this padding is not created by a padding machine,
we treat its outgoing PADDING cells as _normal_ cells
(from maybenot's point of view).
We treat all incoming PADDING or VPADDING cells as received padding cells
(from maybenot's point of view).


Other differences from circuit padding are as follows:

- For channel-level blocking, we _do_ support the padding "replace" flag
  fully.  If real data is waiting, we'll package it.
- PADDING and VPADDING cells are always allowed.
- Channel-level blocking does not make any exception for different cell types.
- Channel-level blocking is treated as opaque from the point of view of
  congestion control: if it makes the MPSC channel look full,
  then from the circuits' point of view, the MPSC channel _is_ full.

> We expect that the last two behaviors may have performance implications:
> when experimenting with per-channel padding,
> we'll need to be careful to test the effects on congestion control,
> and revisit these decisions.






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
