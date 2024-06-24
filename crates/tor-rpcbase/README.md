# tor-rpcbase

Backend for Arti's RPC service

## Overview

Arti's RPC subsystem centers around the idea
of calling methods to objects,
and receiving asynchronous replies to those method calls.

In this crate, we define the APIs
to implement those methods and objects.
This is a low-level crate, since we want to be able to define objects
and methods throughout the arti codebase
in the places that are most logical.

## Key concepts

An RPC session is implemented as a bytestream
encoding a series of [I-JSON] (RFC7493) messages.
Each message from the application
describes a _method_ to invoke on an _object_.
In response to such a message,
Arti replies asynchronously with zero or more "update messages",
and up to one final "reply" or "error" message.

This crate defines the mechanisms
for defining these objects and methods in Rust.

An Object is a value
that can participate in the RPC API
as the target of messages.
To be an Object,
a value must implement the [`Object`] trait.
Objects should be explicitly stored in an `Arc`
whenever possible.

In order to use object,
an RPC client must have an [`ObjectId`] referring to that object.
We say that such an object is "visible" on the client's session.
Not all objects are visible to all clients.

Each method is defined as a Rust type
that's an instant of [`DynMethod`].
The method's arguments are the type's fields.
Its return value is an associated type in the `DynMethod` trait.
Each method will typically have an associated output type,
error type,
and optional update type,
all defined by having the method implement the [`Method`] trait.

In order to be invoked from an RPC session,
the method must additionally implement [`DeserMethod`]
which additionally requires that the method
and its associated types.
(Method that do not have this property
are called "special methods";
they can only be invoked from outside Rust.)

Once a method and an object both exist,
it's possible to define an implementation of the method
on the object.
This is done by writing an `async fn` taking the
object and method types as arguments,
and later registering that `async fn` using
[`static_rpc_invoke_fn!`] or [`DispatchTable::extend`].

These implementation functions additionally take as arguments
a [`Context`], which defines an interface to the RPC session,
and an optional [`UpdateSink`],
which is used to send incremental update messages.

## Example

```rust
use derive_deftly::Deftly;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tor_rpcbase as rpc;

// Here we declare that Cat is an Object.
// This lets us make Cats visible to the RPC system.
#[derive(Deftly)]
#[derive_deftly(rpc::Object)]
pub struct Cat {}

// Here we define a Speak method, reachable via the
// RPC method name "x-example:speak", taking a single argument.
#[derive(Deftly, Deserialize, Debug)]
#[derive_deftly(rpc::DynMethod)]
#[deftly(rpc(method_name = "x-example:speak"))]
pub struct Speak {
    message: String,
}

// We define a type type to represent the output of the method.
#[derive(Debug, Serialize)]
pub struct SpeechReply {
    speech: String,
}

// We declare that "Speak" will always have a given set of
// possible output, update, and error types.
impl rpc::Method for Speak {
    type Output = SpeechReply;
    type Update = rpc::NoUpdates;
    type Error = rpc::RpcError;
}

// We write a function with this signature to implement `Speak` for `Cat`.
async fn speak_for_cat(
    cat: Arc<Cat>,
    method: Box<Speak>,
    _context: Arc<dyn rpc::Context>
) -> Result<SpeechReply, rpc::RpcError> {
    Ok(SpeechReply {
        speech: format!(
            "meow meow {} meow", method.message
        )
    })
}

// We register `speak_for_cat` as an RPC implementation function.
rpc::static_rpc_invoke_fn!{
    speak_for_cat;
}
```



## How it works

The key type in this crate is [`DispatchTable`];
it stores a map from `(method, object)` type pairs
to type-erased invocation functions
(implementations of [`dispatch::RpcInvocable`]).
When it's time to invoke a method on an object,
the RPC session uses [`invoke_rpc_method`]
with a type-erased [`Object`] and [`DynMethod`].
The `DispatchTable` is then used to look up
the appropriate `RpcInvocable` and
call it on the provided arguments.

How are the type-erased `RpcInvocable` functions created?
They are created automatically from appropriate `async fn()`s
due to blanket implementations of `RpcInvocable`
for `Fn()`s with appropriate types.

## Related crates

See also:
  * `arti-rpcserver`, which actually implements the RPC protocol,
    sessions, and objectId mappings.
  * `arti`, where RPC sessions are created based on incoming connections to
    an RPC socket.
  * Uses of `Object` or `DynMethod` throughout other arti crates.


[I-JSON]: https://datatracker.ietf.org/doc/html/rfc7493

License: MIT OR Apache-2.0
