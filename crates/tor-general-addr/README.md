# tor-general-addr

Generalized address type used within Arti

## Overview

This crate provides a generalization 
of [`std::net::SocketAddr`] and [`std::os::unix::net::SocketAddr`]
for cases where an application to needs to bind or connect
to both of them interchangeably.

It also provides a stub, uninhabited version of
[`std::os::unix::net::SocketAddr`] for platforms that lack it.

----

License: MIT OR Apache-2.0
