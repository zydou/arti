# About this documentation

This documentation aims to explain what you need to know in order to
connect to [Arti](https://arti.torproject.org/) over its RPC interface.

At present (Jan 2025), it is incomplete; you can help expand it by
collaborating at <https://gitlab.torproject.org/tpo/core/arti>.

Here we try to explain what Arti's RPC interface is,
the key concepts you'll need to know to use it,
and how to use it to invoke methods on Arti.

This documentation is currently divided into a user guide,
and a set of specifications.
They have different intended audiences:
the user guide is meant for all application developers,
whereas the specifications are meant for developers
who need to write an RPC client library from scratch.

## Other documentation

The method reference, which explains which methods that you can invoke,
is currently documented at a [temporary location];
we'll replace this with a more permanent URL.

> Note that you can't do very much with the RPC API right now;
> we'll be adding new methods as development continues.

Assuming that you don't want to write your own RPC client from scratch,
you'll probably be using our own
[Rust RPC client library][arti-rpc-client-core],
which has wrappers [in C][arti-rpc-client-core.h]
and [in Python][arti_rpc].
We'll touch on using them here,
but you'll also want to consult their own API reference documentation.


[temporary location]: https://people.torproject.org/~nickm/volatile/rpc-reference.html
[arti-rpc-client-core]: https://tpo.pages.torproject.net/core/doc/rust/arti_rpc_client_core/index.html
[arti-rpc-client-core.h]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti-rpc-client-core/arti-rpc-client-core.h?ref_type=heads
[arti_rpc]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/python/arti_rpc?ref_type=heads
