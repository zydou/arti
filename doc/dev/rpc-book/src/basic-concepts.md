# Arti RPC: The basic concepts

The Arti RPC system is a way for applications to control Arti.
The application behaves as an _RPC client_,
whereas Arti acts as an _RPC server_.

## Requests and responses

In the RPC protocol, the application issues _requests_ to Arti,
and gets incremental _updates_ and final _replies_ in response.

There can be multiple requests inflight at once:
each response is given in reply to exactly one request.
Your RPC [client library][arti-rpc-client-core]
should take care of sending requests for you,
and matching responses to your requests.

Requests and responses are all encoded in JSON.
We'll discuss the encoding below.
For now, your application or your client library
will need to take care of some of this encoding and decoding.


## RPC objects and their IDs

The RPC protocol is built upon _objects_ within Arti.
In order to use an object,
the application needs to have an ID for it.
When an application first connects to Arti,
it has only a single object ID,
representing the _Connection_ itself.
After it has authenticated,
it receives a second object ID,
representing the RPC _Session_.

Object IDs behave like capabilities
that give your application permission to do certain things.
Object IDs are connection-local:
an object ID from one RPC connection does not work on another.

The Connection object provides functionality
(like trying to authenticate)
that is safe to use when the application hasn't authenticated.
The Session object is the result of authenticating,
and is the source of all other RPC objects.

## Security model

An application has only limited access to Arti.
It can only interact with its own data streams,
their circuits, and so forth.
One application isn't allowed to interfere with another.

> Note that this interference rule is a best-effort goal to isolate
> well-behaved applications, and not a strong guarantee.
> A hostile application can always
> interfere with another by consuming system resources,
> hogging the network, or so on.

<!-- TODO: Describe this isolation in more detail,
  or link to documentation -->

An application can also be connected in *superuser mode*.
When an application is running as a superuser,
it is allowed to observe and modify more parts of Arti,
including those that can interfere with other applications.
*(As of Jan 2025, superuser mode is not yet implemented.)*

## Discovery and connecting

In order to use Arti's RPC APIs,
the client needs to know where the server is listening.
We have tried to make this discovery process as seamless
as possible.

In brief:
there is a kind of TOML document called a
["connect point"](rpc-connect-spec.md)
that tells an RPC server how to listen,
and tells the client how to connect and authenticate.
The RPC client and server typically use the same connect point document.
There are built-in default connect points for Arti to use,
which the RPC client also uses by default.

Administrators and integrators can configure Arti
to use different connect points;
if they do, they'll also need to arrange for the client to find it.
In production,
administrators would typically do this with an environment variable,
or by putting the connect point in a file in the client's
[default search path](rpc-connect-spec.md#default-client-path).

Application developers should typically not have
to be concerned with connect points:
the client RPC library's defaults should be reasonable.
Integrators, administrators, and users
can override those defaults depending on their needs.

> Eventually we will also support using an RPC library
> to launch a new Arti process,
> or to start an embedded Arti client in process.
> As of Jan 2025 this is not implemented.

## Restricted access and authentication

Currently, we use filesystem permissions
to ensure that only an authorized user
can connect to Arti.
(For now, only the user running Arti is considered authorized.)

On Unix-like systems (including MacOS),
we prefer AF\_UNIX domain sockets
in a directory that only the authorized user can access.
On Windows,
we put a "cookie" file on disk
and make the client prove knowledge of the secret cookie
before they can authenticate.

Again, application developers shouldn't need to reconfigure this.

> In the future we expect to add other authentication mechanisms.

[arti-rpc-client-core]: https://tpo.pages.torproject.net/core/doc/rust/arti_rpc_client_core/index.html
