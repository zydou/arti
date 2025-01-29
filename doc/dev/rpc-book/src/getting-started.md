# Getting started with Arti RPC

Here we'll walk through a quick tutorial
where you'll open and use an RPC session.

The code here is in Python;
using other languages is possible,
but as of this writing,
Python and Rust are the two with existing wrappers.

<!-- TODO: Add link to auto-generated python documentation once we have it. -->

> This section is written based on the status of RPC in Jan 2025.
> We hope that things will get even more streamlined moving forward.
>
> This section assumes that you have Arti 1.3.3 or later,
> or that you are using Arti from the git repository.
> As of this writing, the latest release (1.3.2) does not yet support all the
> functionality here.


## Building and running Arti with RPC support

First, you need an Arti binary with RPC support enabled.
For now, RPC is not on by default,
so you'll need to configure it at compile-time
and at run-time.

To build Arti with RPC support, use the `--features=rpc` option.
For example you might say:
```shell
cargo build --package arti --release --features=rpc
```

Then you'll need to configure Arti with RPC support.
(This may later be on-by-default, but it isn't yet.)
To do this, put the following into your `arti.toml` file:
```toml
[rpc]
enable = true
```

<!-- TODO: Add link to "how to configure arti documentation -->

Then start Arti.

## Building the client library

We provide an RPC client library written in Rust, with C bindings.
(Those C bindings in turn can be wrapped from other languages.)

To build that library, use something like:
```shell
cargo build --package arti-rpc-client-core --release --features=full
```

On Linux this will crate a file with a name something like
`target/release/libarti_rpc_client_core.so`.
The extension will be different on other platforms.

## Setting up the Python package

In real life,
you'd want to install the `arti_rpc` Python package
and the C client library.
But for now,
we'll use environment variables to set them up noninvasively.

Assuming that you're using a bash-like shell,
and you're at the top level of the Arti git repository,
you can say:
```shell
export PYTHONPATH="$(pwd)/python/arti_rpc/src:${PYTHONPATH}"
export LIBARTI_RPC_CLIENT_CORE="$(pwd)/target/release/libarti_rpc_client_core.so"
```

The first environment variable
tells Python how to find the `arti_rpc` library.
The second tells the `arti_rpc` library where to look
for the C client library.

### "But what if I'm not writing Python?"

If you're writing a Rust application,
you'd probably want to use the [`arti-rpc-client-core`] crate directly.

If you're writing in some other language,
you'll probably want to write a set of wrappers around the
[C API][arti-rpc-client-core.h].
We recommend using the Python wrappers for guidance on design;
please get in touch with us to learn more!

> Because string handling in C is such an error-prone headache,
> we don't recommend using the C API in applications directly.
> Instead, we recommend using wrappers in a safer language.

## A deceptively simple program: let's connect to Arti!

Here's a little Python program you can use
to open an RPC connection to Arti,
check the client's bootstrap status,
and open a stream through Arti.

```python
#!/usr/bin/env python3

import arti_rpc

# Make the connection, and authenticate to produce a session.
conn = arti_rpc.ArtiRpcConn()

print("Connection successful!")

# Get an ArtiRpcObject wrapper for the Session object.
session = conn.session()

# Get the default Client object from the session object.
#
# (See `arti:get_client` in the method reference for details.)
reply = = session.invoke("arti:get_client")

# Now 'reply' is something like `{ "id" : "X" }`,
# where X is replaced with the client object's Object ID.
#
# Here we extract that ID, and wrap it in an ArtiRpcObject.
client_object_id = reply["id"]
client = conn.make_object(client_object_id)

# Invoke a method on the client object, to ask for the client's
# bootstrap status.
result = client.invoke(
    "arti:get_client_status"
)
# Print some of the fields in the result of our request.
#
# For documentation on this method and its reply value,
# look for `arti:get_client_status` in the rpc method reference.
percent = int(result['fraction'] * 100)
print(f"Client is {percent}% bootstrapped.")
if result["blocked"]:
    print(f"Bootstrapping appears blocked: {result['blocked']}")

# Now open a stream to www.example.com:443.
#
# This takes care of finding out the right Arti SOCKS port to use,
# prove to the server that we're opening the stream for _this_ session,
# and giving ourselves access to the stream as an RPC object.
#
# After this call, "stream" is socket, and "stream_obj" is an ArtiRpcObject.
#
# See `ArtiRpcConn.open_stream` documentation for more information.
stream, stream_obj = conn.open_stream(
    "www.example.com", 443,
    want_stream_id=True)
print("Stream opened successfully!")
```

<!-- TODO: Maybe make an HTTPS request? -->

## What comes next?

For more information on the current set of RPC objects
and the methods you can invoke on them,
see the RPC method reference at its
[temporary location].

For information on the actual messages
that encode your requests and responses,
read on to the next section.
This will introduce a few additional concepts that you will need
to use the client libraries successfully.

For more information on the [Rust API][`arti-rpc-client-core`],
[C API][arti-rpc-client-core.h],
and [Python API][arti_rpc],
see their respective reference documentation.


[`arti-rpc-client-core`]: https://tpo.pages.torproject.net/core/doc/rust/arti_rpc_client_core/index.html
[arti-rpc-client-core.h]: https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates
[temporary location]: https://people.torproject.org/~nickm/volatile/rpc-reference.html
[arti_rpc]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/python/arti_rpc?ref_type=heads
