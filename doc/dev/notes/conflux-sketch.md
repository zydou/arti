# Conflux design sketch

Date: Jan 29th, 2025

Document sketching out the design for Conflux (traffic splitting), [proposal
329](https://spec.torproject.org/proposals/329), in arti on the client side.

Client and relay won't share the same circuit reactor but there is a good
chance that this design can be shared between the two due to the similar
behavior on both the client and relay exit side.

## 10,000 feet from above

Conflux is the ability to split traffic between multiple circuits which
increases performance, resilience and stability of a stream of data.

The protocol defines that N legs can be in a "conflux set" that is N circuits
to the same exit point. Taken from the prop329, this is an example where N=2:

         Primary Circuit (lower RTT)
            +-------+      +--------+
            |Guard 1|----->|Middle 1|----------+
            +---^---+      +--------+          |
   +-----+      |                           +--v---+
   | OP  +------+                           | Exit |--> ...
   +-----+      |                           +--^---+
            +---v---+      +--------+          |
            |Guard 2|----->|Middle 2|----------+
            +-------+      +--------+
         Secondary Circuit (higher RTT)


The primary leg is chosend based on the desired UX properties (see proposal) as
long as congestion control allows it. Several factors can trigger a switch to a
secondary leg.

## Path Selection

Conflux circuits, called "set", are built preemptively due to the high cost of
building (waiting for multiple circuits to open then linking them).

The `AbstractCircMgr` keeps a circuit list (`CircList`) and so we'll likely
need a list of conflux set similar to this list that keeps track of unlinked
(pending) sets and linked (opened) sets.

A likely approach to this is to do what `HsCircPool` does that is keeps its own
list of circuits along a series of parameters that Conflux has from the
consensus. A `ConfluxCircMgr` seems logical here which is attached to the
`AbstractCircMgr` object so it can piggy back on the preemptive circuit
mechanics.

It can then hook automagically to the `.get_or_launch_exit` of the `CircMgr`.
This returns a `ClientCirc` which is essentially a two-way portal to a circuit
reactor.

NOTE: The `ClientCirc` has a `Arc<Channel>` but it has a fat comment that says
to NOT use it so that is unclear how this will play out with this plan.

The splitting magic will then be in the circuit reactor.

## Circuit Reactor

We have two possibilities:

1. Keep it like it is and have one reactor per circuit. We then have a conflux
   channel between the reactors.

   Problem: A conflux set can have N legs which can be above 2 meaning that if
   we have, for example, 3 legs in a set, it means we would have 3 reactors
   meaning they would need to each talk to each other seamlessly likely
   requiring us to build a MPMC communication system along an entire protocol
   in order to inform each reactor the state of the conflux construction.

   Not impossible here at all but could be more complex than (2) and introduce
   a performance hit. Unclear.

2. One single reactor has multiple channels. This might be simpler but has its
   challenge detailed below.


Assuming (2) is with what we go for, the approach would be to allow N channels
within a reactor. This however is not without significant changes.

### Conflux circuit builder

The aforementioned conflux circuit builder is where the `CONFLUX_LINK` and
`CONFLUX_LINKED` would be handled. The first leg is created, likely from
`Channel::new_circ()`, which returns a reactor.

This is a tricky piece. Each new circuit gets a reactor and so in this case we
would need to use the `meta_handler` of the reactor and set it to a "conflux
linked set" handler that would have the shared conflux set state in order to be
updated from the receiving cell. And so upon receiving the `LINKED` cell, it
could update that state and inform back the conflux builder that we have that
this specific circuit is linked. See `IptMsgHandler` for a good example on how
to pull this off.

Once all legs are linked, we need a way to "merge" the reactors into the
primary one leaving only one that rules them all (`Reactor::absorb()`?). Is
this crazy? Maybe... but because of the `LINK` and `LINKED` cell on the open
circuit, we require a reactor to be able to receive those until we don't.

### Reactor changes

For the above to work, we need to create the concept of a "Circuit" within the
`Reactor` meaning moving all of these fields into such struct:

  * `channel`: The channel the circuit is attached to.
  * `chan_sender`: Sender object to send cell on the channel.
  * `input`: Input stream from the circuit's channel.
  * `crypto_in`: Inbound crypto state of the circuit.
  * `crypto_out`: Outbound crypto state of the circuit.
  * `hops`: List of hop of the circuit (ordered).
  * `channel_id`: Weirdly name that but it is the circuit ID.


The `Reactor` would then have a list of these "Circuit" object and a way to
identify them primary and secondary.

When a `CONFLUX_SWITCH` arrives, the reactor can then make the appropriate
switch within its list of "Circuit".

## Putting it all together

The application stream (arti client side) sends data which is then received by
the circuit `Reactor` which sends it onto the primary leg (conflux or not,
always the primary leg).

The `Reactor` also listens on all "Circuit" channel of its list and handles
incoming cell according to the conflux protocol (sequence number, switch, ...).

## What Remains

- Unclear how we can re-open a new leg if one collapses? We would need the
  circmgr to notice that somehow or make the reactor inform that manager? Note
  that in C-tor, we don't have resumption so if one leg dies, we don't attempt
  to re-create a new one.

- Full session resumption (see proposal section 2.7 RESUMPTION) is not in scope
  for the initial piece of work. Because it requires buffering at least a
  congestion window worth of cells, this can mushroom and requires thinking.
