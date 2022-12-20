# tor-ptmgr

Manage a set of anti-censorship pluggable transports.

## Overview

This crate is part of [Arti](https://gitlab.torproject.org/tpo/core/arti/),
a project to implement [Tor](https://www.torproject.org/) in Rust.

In Tor, a "transport" is a mechanism used to avoid censorship by disguising
the Tor protocol as some other kind of traffic.

A "pluggable transport" is one that is not implemented by default as part of
the Tor protocol, but which can instead be added later on by the packager or
the user.  Pluggable transports are typically provided as external binaries
that implement a SOCKS proxy, along with certain other configuration
protocols.

This crate provides a means to manage a set of configured pluggable
transports

## Limitations

TODO: Currently, the APIs for this crate make it quite
tor-specific.  Notably, it can only return Channels!  It would be good
instead to adapt it so that it was more generally useful by other projects
that want to use pluggable transports in rust.  For now, I have put the
Tor-channel-specific stuff behind a `tor-channel-factory` feature, but there
are no APIs for using PTs without that feature currently.  That should
change. (See issue [arti#666](https://gitlab.torproject.org/tpo/core/arti/-/issues/666))

TODO: The first version of this crate will probably only conform
to the original Tor pluggable transport protocol, and not to more recent variants
as documented at `pluggabletransports.info`

## Feature flags

### Additive features

* `tor-channel-factory`: Build with support for a ChannelFactory implementation
  that allows this crate's use with Tor.  (Currently, this is the only way to
  use the crate; see "Limitations" section above.)

* `full` -- Build with all the features above.

### Experimental and unstable features

 Note that the APIs enabled by these features are NOT covered by semantic
 versioning guarantees: we might break them or remove them between patch
 versions.

* `experimental-api` -- build with experimental, unstable API support.

* `experimental` -- Build with all experimental features above, along with
  all experimental features from other arti crates.


License: MIT OR Apache-2.0
