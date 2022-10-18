# Adding Bridges and Pluggable Transports to Arti

This document will go over the general issues that we face when building
client-side support for bridges and pluggable transports in Arti.


## Tor's anticensorship features: a lower-level perspective

Here's what you need to know about bridges.

Fundamentally, a "**Bridge**" is a relay that we use as the first hop
for our circuits _because it is configured by the user_, not because it is
listed in the main network directory.[^1]

A "Bridge" can either be reached by the regular Tor (cells over TLS)
protocol, or by some different censorship-resistant "**transport**"
protocol.[^2]

Users configure a single bridge by listing some of the following:
  * A set of supported transports that can be used.  If this set is
    empty, the client just uses the default transport.
  * A set of IP:Port addresses that can be used to reach the bridge.
    (With some transports, the transport itself figures out how to
    contact the bridge, and this set is empty or ignored.)
  * A set of identities to expect for the bridge.  (Note that C Tor
    allows this set to be empty; Arti will not, since it tends to
    create severe implementation headaches.)
  * For each transport, a set of transport-specific parameters.  (These
    might, for example, be additional protocol-specific authentication
    keys.)

Users can turn bridge usage on and off.  This is a single boolean that
does not require deleting their entire list of bridges.

Users can configure a large number of bridges; if they do, then we want
to pick randomly from among them and favor just a few, in the same way
that we do when choosing guard relays.  We want to reuse our `GuardMgr`
code for this.  (Doing so, however, may require a bit of refactoring,
since the current `GuardMgr` selects `Relay`s from a `NetDir`, and we'll
have to select `Bridge`s from some kind of underlying `BridgeSet`.)

Since bridges are not listed in the main network directory, we can't use
the directory to look up their **onion keys** (the ones we use to build
multihop circuits).  Instead, we have to connect to the bridge and ask
the bridge for a **router descriptor**—a self-signed document describing
the bridge and its supported keys.  Descriptors are only valid for a
while.

Some transports are implemented as external processes, using a
"**managed pluggable transport**" mechanism.  In this design, the Tor
client program is responsible for launching and monitoring external
binaries that provide transports over SOCKS4 or SOCKS5.  The [protocol]
for communicating with these binaries uses stdin, stdout, and the
environment.  To use these binaries as transports, the client treats
them as SOCKS4 or SOCKS5 proxies, and encodes per-connection arguments
in the authentication fields of the SOCKS handshakes.

A single managed PT binary can implement multiple transports: if it
does, each one gets its own local proxy address.

[protocol]: https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/pt-spec.txt

## Architectural implications

With those issues in mind, let's go through the parts of the
implementation that are simple.

We'll need to extend the definition of `ChanTarget` to include the
additional information that bridges need: which protocol to use, and
protocol-specific information.  We might want a separate trait for
`ChanTarget`s that can have this information, since relays will never
want to look at it, and in fact will require that it is absent.

We'll want to extend the `tor-chanmgr` crate to know about more ways to
launch channels.  It will probably have a registry of known transport
mechanisms (including the default transport) and know how to connect to
each one.

We'll need to implement `tor-ptmgr` crate that launches and monitors
managed pluggable transport binaries.  It should have the ability to
launch and shut down PTs on demand, not just because they are
configured.  (In other words, if no bridge wants a given transport, we
shouldn't run that transport.)

We'll need to teach `tor-guardmgr` to be able to take its input from a
configured set of bridges rather than from a `NetDir`.  This needs to be
a separate "guard selection", since we want to be able to switch back
and forth between using bridges and not using bridges.

In `ChanMgr` and `GuardMgr`, we'll need a way to identify bridges. This
will be interesting, since bridges can be configured only with a single
identity that is _not_ their Ed25519 identity.  (In `GuardMgr`, we might
have as little as an `RsaIdentity`.  In `ChanMgr`, we will have more
identity information, but only _after_ the channel handshake is
successful.)  If the same identity is listed twice with different
addresses and transports, we may need to treat them as different
bridges.[^3] We may need to assign configured bridges a local unique ID,
and use that identify which bridge is which in ChanMgr.  We may need a
flexible matching approach in our `GuardMgr` code to see which
remembered guard is equivalent to which configured bridge.

We'll need to download and cache bridge's router descriptors as needed.
This is different from downloading regular directory information in
several ways:
   * We can only download a bridge's descriptor _from that bridge_.
   * We need to be able to download a bridge's descriptor _even when we
     have no directory_.
   * When using bridges, we _only use bridges_ as our directory caches:
     never fallback directories.

Let's try to, to the extent possible, to  put all of the client-side
bridge and pluggable
transport code behind Cargo features (`bridge-client` and `pt-client`,
maybe), so that we can disable them for Relays and for
resource-constrained clients that don't want them.

## Challenges with implementing anticensorship in Arti

Now that we've been through all of that, here are some of the challenges
and open questions that we need to solve as we implement these
anticensorship features in Arti.

### Problem 1: The directory infrastructure and logic

Our existing directory code doesn't know about bridges.  We'll need to
think carefully about the logic that drives guard selection and
directory downloads.

We'll need an additional directory state where we try to make sure we
fetch bridge descriptors.  This has to happen after bridges are
selected.  There needs to be feedback between the `GuardMgr` and the
`DirMgr` here: the `GuardMgr` can't hand out bridges for multi-hop
circuits until it knows descriptors for them; the `DirMgr` can't fetch
any bridge descriptors until it knows what the `GuardMgr` wants.

(The `DirMgr` also needs to keep bridge descriptors separate from regular
relays, to avoid leaking whether we've used a given bridge when using it
as a relay, and vice versa.)


### Problem 2: Circuits through bridges

Our `CircMgr` can build one-hop directory circuits through any kind of
`ChanTarget`.  But right now it can only build multihop circuits by
first looking up the `Relay` object for the first hop in the `NetDir`.

Here we have two options: We can make bridges with known descriptors
into `Relay`s, or we can adjust `CircMgr` so that any `CircTarget` can
start a multihop circuit.

We'll also want a meaningful way to know if a bridge is in the same
family as a `Relay`, which presents its own challenges.

### Problem 3: Discarding unused channels and circuits

When a user turns bridges on and off, or changes the set of configured
bridges, we can easily have the `ChanMgr` and the `CircMgr` drop all of
their existing channels and circuits.  That will cause these channels
and circuits to close once there are no longer any streams using them,
which is all well and good.

But the user may want channels and circuits to close sooner!  People
sometimes get worried when an they flip a "anticensorship" switch and
their non-resistant channels and circuits don't close immediately.

That's a challenge in our current `ChanMgr`/`CircMgr` API, since we
don't actually keep track of the channels and circuits that we no longer
track in those managers.  We might instead need to keep weak references
to deprecated channels and circuits.  But doing _that_ might require new
`WeakChannel` and `WeakCircuit` types in `tor-proto`.

### Problem 4: Channel equivalency, bridge identity

If a bridge's configured addresses or transports are changed, then
existing channels to that bridge may no longer be used.

If a bridge has multiple transports, we might need to remember which
ones work and which ones don't.

What's more, we might not always know an Ed25519 identity for a bridge:
this will mess with our guard and channel code, both of which assume
that all known relays have an Ed25519 identity.

### Problem 5: Tuning, tuning, tuning

Our existing code has some constants and consensus values that are tuned
for the main network.  We'll need to revisit them for bridges.  Notably,
we'll need to reconsider our required guard parallelism, our recommended
guard parallelism, our willingness to retry a guard that seems not to be
working, our timeouts, our happy-eyeballs parameters, and more.


### Problem 6: Existing bridge-line format

We would like to have backward compatibility with Tor's current bridge
configuration mechanism, which uses a line format something like this:

```
[TransportId] 1.2.3.4:9100 RsaIdentity [Param1=Val1] [Param2=Val2] ...
```

We need to support this indefinitely, though it has a number of design
problems, since its usage is established basically everywhere.
Nonetheless, we may want to look into alternatives, so that we could:

  * Have more identity types
  * Make addresses optional
  * Use a type better suited for encoding binary data.


## APIs to design

These are some APIs to sketch out as next steps.

* Extended ChanTarget/CircTarget API

* Protocol or TransportId API

* Revised GuardMgr interfaces

* TransportRegistry (part of ChanMgr, knows how to connect via different
  protocols.  Takes an `ExtendedChanTarget`; returns a `Result<Channel>`)

* PtMgr (handles managed pluggable transports)

* Whatever the heck is going on inside DirMgr and between
  DirMgr/GuardMgr now.



----

[^1]: In fact, bridges are typically _not_ listed in the main network
   directory: if they were, a censor could easily block their IP addresses.

[^2]: In practice, all of our transports are implemented as extra layers
   over which we tunnel our regular cells-over-TLS protocol.  This is a
   deliberate choice: Even when the transport provides authenticity and
   and confidentiality on its own

[^3]: This is an uncommon case in C Tor, and we might not want to
   support it.

