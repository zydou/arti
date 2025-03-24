# Style notes

Most code style questions are dealt with by rustfmt and clippy.
Here we document some other style issues commonly arising in Arti.

## Avoid abbreviating Onion Service (Hidden Service) to just "Onion"

In the Tor protocols and codebase the word "Onion" can mean (at least):

 * The Onion Router - the whole protocol suite
 * Relating to Hidden Services
 * A router's medium-term circuit extension key KP\_onion\_*
 * An "onion handshake", the hop-by-hop circuit handshake
 * An "onion proxy", which is a Tor client presenting a SOCKS (or
   similar) proxy to (mostly)-naive local clients

It is a fundamental principle of naming that a name should always
refer to the same thing.  This principle can reasonably be violated in
informal and more marketing-y context, perhaps; or, when the name is
used for different aspects of the same thing, or isomorphic things,
and there is no risk of confusion.

But in most cases, using just "onion" to mean "hidden service" is
ambiguous and therefore wrong.

Examples of deprecated uses:

 * *"onion proxy" to mean a hidden service reverse proxy
 * *"onion tunnel" to mean a tunnel to a hidden service
 * *"onion" to mean HS identity (KP\_hs\_id, `.onion` domain),
   for example "if this is the same onion"

In lower-level crates and APIs, prefer "hs" (short for hidden service).
In higher-level user-facing code, write out "onion service" in full.

When referring to specifically the `.onion` domain name for an HS,
prefer "onion address".  `.onion` is also OK.

## Unix domain sockets (AF_UNIX) terminology

AF\_UNIX sockets are not "unix sockets".  (Unix supports many other
kinds of sockets and some non-Unix operating systems support, or
emulate, AF_UNIX sockets.)

Examples of deprecated uses:

 * *"unix socket".  Use "unix domain socket" or "AF_UNIX socket".
 * *"unix address".  Use "AF_UNIX address".
 * *"unix path" to mean the path of a unix domain socket.
   Use "socket path", "unix domain socket path", or
   "AF_UNIX socket path".

Enum variants for AF_UNIX addresses, within an enum which contains
variants for various address families, *should* be called `Unix`.
(This is analogous to the `UNIX` in `AF_UNIX`.)  When talking about a
Rust type, one *can* correctly refer to a "`Unix` address", but this
is close to a deprecated usage and another formulation is often
better.

Apart from that, ideally, Rust identifiers at least in public APIs
should avoid using `unix`, `UNIX` or `Unix` to mean "unix domain
socket".  Consider `af_unix`, `AF_UNIX`, or `AfUnix`.  However, Rust's
stdlib and Tokio already (incorrectly) use names like `UnixSocket`,
`UnixListener`, `UnixStream` (and have incorrect descriptions of these
as "unix sockets").  In our APIs mirroring those APIs, use the same
approach in identifiers, for consistency.
