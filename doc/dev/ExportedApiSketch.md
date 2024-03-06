
# Some early thoughts on Arti FFI & RPC

There are certainly quite a few environments that we want Arti to be
deployable into!  They include:

 * Arti as a Rust crate, used from a Rust program written to use `async`
   networking.  (This is what we have today.)
 * Arti as a rust crate, used from a Rust program that doesn't know
   about `async` networking.  (I'll be skipping over this option.)
 * Arti running as a separate process, accessed via RPC.
 * Arti as a library, loadable from an arbitrary programming environment.
 * Arti as a drop-in replacement for your program's existing networking
   solution.

I'm going to discuss options for each one below and implementation
strategies.  Some general principles to think about are:

1. It would be nice if adding a new feature to Arti didn't require adding a
   huge amount of extra boilerplate to 5-10 different embedding systems.

2. It would be nice if existing programs that use C Tor could migrate to
   using Arti without too much effort.

Before we start looking at the strategies, let's talk about some
difficulties that any Arti API will face.

## Difficulties with designing APIs for a Tor implementation.

### Problem 1: Sockets are not so well supported

The major abstraction used in Tor is an **anonymous socket**, which
presents a problem with RPC:

It is not easy to transfer real sockets across all process boundaries.
You can do it with unix sockets and `sendmsg`, and there is a similar
windows thing, but they are both slight forms of dark magic.

Many RPC systems simply don't support transferring sockets.  We can
instead add a proxy alongside the RPC mechanism (like C tor does), but
that does require additional coordination between the two mechanisms so
that the RPC could refer to the proxy's sockets unambiguously.

### Problem 2: Sockets are not so well abstracted

Applications want to use sockets in their native format, which presents
a problem with FFI:

If all the world were `async` Rust, we could simply expose a type that
implemented `AsyncRead + AsyncWrite`.  If all the world were Java, we
could expose a type that exposed an `InputStream` and an `OutputStream`.
If every C program were written using NSPR, we could expose a
`PRFileDesc`...

But in reality, the space of existing higher-level socket APIs is too
huge for us to emulate all of them.

So we need to support the most basic low-level socket API we can.  On
Unix, that's a file descriptor.  On Windows, that's a `SOCKET`.

Absent a set of uniform kernel plugins to let us define new file
descriptor types, our viable only option is to use a `socketpair()` API
to provide the application with a real honest-to-goodness socket, and to
proxy the other end of that socket over the Tor network.

This kind of approach consumes kernel resources, but there's no way
around that, and in most cases the overhead won't matter in comparison
to the rest of the Tor network API.


### Problem 3: The API surface is large

Arti (like C tor before it) has a **complex API surface**.  There are
many knobs that can be turned, and many of them have their own
functions.  We do not want (for example) to make a separate function
call for our entire configuration builder infrastructure; instead, we
should look for solutions that let us hide complexity.

For example, we could expose access to our configuration as a
string-based tree structure, rather than as a separate function per
option.  We can also use string-based or object-based properties to
configure streams, rather than exposing every option as a new function.

(Our use of the `serde` crate might make this easier to solve, since we
already have access to our configuration as a structured tree of strings.)

### Problem 4: We want to expose asynchronous events

Many of the things that we want to tell applications about happen
asynchronously, such as circuit construction, log events, and bootstrap
events.

Not every RPC system makes this kind of API simple to expose. Some want
to have a only request at a time per "session", and make it nontrivial
or inefficient to support requests whose responses never end, or whose
responses might come a long time later.  We need to make sure we avoid
these designs.

In-process FFI also makes this kind of thing tricky.  The simplest way
to learn about events in process might be to register a callback, but
badly programmed callbacks have a tendency to run out of hand.  Some
environments prefer to poll and drain a queue of events, but many
polling systems rely on fd-based notification, or behave badly if the
queue isn't drained fast enough.

Again, it might be best to offer the application a way to get a socket
which arti writes the information to in some kind of structured way
using serde.  (serde makes it easy to support a variety of formats
including (say) JSON and messagepack.)


## Thoughts on particular options

### Arti over RPC

There is a pretty large body of existing programs that use C tor by
launching it, connecting to a control port to manage it, and talking to
that control port over a somewhat clunky protocol.

In practice, some of these programs roll their own implementation of
launching and controlling C tor; others use an existing library like
`stem`, `txtorcon`, or `jtorctl`.

The existing control protocol is pretty complex, and it exposes an API
with a large surface that is somewhat attached to implementation details
of the C tor implementation.

There is also a fairly large body of RPC protocols out there _other_
than the Tor controller protocols!  Using one of them would make Arti
easier to contact in environments that have support for (say) JSON-RPC,
but which don't want to do a from-scratch clone of our control porotcol.

Here are several options that we might provide in Arti.

#### RPC via a control port clone.

We could attempt a control-protocol reimplementation.  A complete
bug-compatible clone is probably impossible, since the control protocol
is immense, and tied to details of C tor.  But we might be able to do a
somewhat-compatible, very partial reimplementation.  It's not clear how
much of the protocol we'd need to clone in order to actually support
existing applications, though!

Also note that the control port exposes more than the control port API:
In addition to translating e.g. CIRC events to Arti, we'd also need to
translate Arti's configuration options so that they looked similar to
old C tor options.  (Otherwise, for example, `GETCONF SocksPort`
wouldn't work, since Arti doesn't have an option called `SocksPort`, and
its socks port configuration option doesn't accept arguments in the same
format.)

#### RPC via some standard system


We could create a new incompatible RPC interface, using some standard
RPC framework.  (See problems 1, 3, and 4 above for some constraints on
the RPC systems we could choose.)  This is the cleanest approach, but of
course it doesn't help existing code that uses C tor.



(If we took this approach, we might be able to port one or more of the
APIs above (`txtorcon`, `stem`, `jtorctl`, etc) to use the new RPC
interface.  That might be cleaner than a control port clone.  But as
above, we'd need to translate more than the API:
`get_config("SocksPort")` would need a compatibility layer too.)

With an appropriate implementation strategy, it might be possible to
implement a subset of the C Tor control port protocol *in terms of*
a new protocol based on a sensible RPC framework.


#### A note about HTTP and RPC

Many popular RPC protocols are based upon HTTP.  This creates a
challenge if we use them: specifically, that your local web browser
makes a decent attack vector against any local HTTP service.  We'll
need to make sure that any HTTP-based RPC system we build can resist the
usual attacks, of course. But also we'll need to make sure that that
it's hard to trick any plausible client implementation holding the
credentials for the RPC system into accidentally leaking them our using
them for something else.


### Arti via FFI

We probably don't want to just expose all our Rust APIs unthinkingly,
because of problems 2 (other languages can't easily consume
`AsyncRead+AsyncWrite` sockets) and problem 3 (huge API surface) above.

Instead, we probably want to define a simplified API based on a handle
to a managed TorClient instance, `socketpair()`-based proxying, and
string-based handling of configuration and other similar data.

This API would have to work by launching our async runtime in a separate
thread, and communicating with it either via function calls or via
messages over some kind of queue.

Every `async` API that we want to re-export from TorClient would need to either
get a blocking equivalent, a polling equivalent, or a callback-based
equivalent.

We'd have to expose C API here.  We might also want to provide wrappers
for that API Java and Python.

Fortunately, we don't have to worry about backward compatibility with
existing applications here, since there is not a C tor API of this type.



### Arti as plugin

Some applications already have support for multiple networking
backends.  With this in mind, we could expose Arti as one of those.

For example, there's some interest in having Arti expose a
`libp2p` interface.


## Where to start?

### Selecting APIs

I think our first steps here would be to approach the question of APIs from
two ends.

1. What APIs do current applications use in C tor?

2. What APIs does Arti currently have and want to expose?

If we can find the simplest intersection of those two that is useful,
I suggest we begin by trying to expose that small intersection of APIs
via whatever candidate RPC and FFI mechanisms we think of.

The very simplest useful API is probably something like:

```
  startup() -> * TorClient or error;
  status(client: *TorClient) -> SomeStatusObject;
  connect(client: *TorClient, target: *Address) -> Socket or error;
  shutdown(* TorClient);
```

We could begin by implementing that, and then add other functionality as
needed.

### Picking our tooling

We'll need to do a survey of RPC options (including rust tooling) and see
whether they provide a feasible way to support async events and/or proxying.

We should see whether cbindgen can help us with our FFI needs.


