# tor-socksproto

Implements SOCKS in the flavors provided by Tor.

## Overview

SOCKS is an old and somewhat janky protocol for telling a TCP
proxy where to connect.  Versions 4, 4a, and 5 are sometimes
encountered in the wild.

The `tor-socksproto` crate tries to hide the actual details of the
protocol, and expose a stateful handshake type that eventually
provides a [`SocksRequest`] or an error.  It is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
At present, it is only used to provide a
SOCKS proxy _over_ the Tor network, but eventually it may be used
to implement support for connecting to the Tor network over a
SOCKS proxy.

This crate may be a good choice for you if you need a SOCKS
implementation that "behaves like Tor", but otherwise it is
probably better to use some other SOCKS crate.

For more information about SOCKS:

  * SOCKS5 (which is preferred) is specified in
    [RFC 1928](https://tools.ietf.org/html/rfc1928), and see also
    [RFC 1929](https://tools.ietf.org/html/rfc1929) for
    Username/Password authentication in SOCKS5.
  * [The wikipedia article](https://en.wikipedia.org/wiki/SOCKS)
    is the best surviving documentation for SOCKS4 and SOCKS4a.
  * See
    [socks-extensions.txt](https://spec.torproject.org/socks-extensions)
    for a description of Tor's extensions and restrictions on the
    SOCKS protocol.

### Design notes

Arti uses this crate instead of some other SOCKS implementation,
for two reasons:

 * First, because we need to support Tor SOCKS extensions.
 * Second, and because we sometimes need to see particular details
   of the individual handshakes that most other SOCKS
   implementations don't expose.  (For example, if we are told to
   connect to a raw IP address, the type of the handshake can help
   us guess whether that IP address came from a DNS response–in
   which case we should warn about a possible DNS leak.)

Currently, `tor-socksproto` does no networking code: it _only_
implements the server (proxy) side of the SOCKS handshake by
handling a series of bytes.  We may (or may not) want to add
network functionality to this crate or elsewhere in the future.
We'll definitely want to add client functionality.

Possibly, this approach will prove useful for other uses.  If it
does, We can put the tor-only functionality behind a Cargo build
feature, so that others can use this crate more safely.

License: MIT OR Apache-2.0
