## Status

This is a draft document.
It does not reflect anything we've buil,t
or anything we necessarily will build.

It attempts to describe semantics for an RPC mechanism
for use in Arti.

By starting with our RPC mechanism
and its semantics,
we aim to define a set of operations
that we can implement reasonably
for both local and out-of-process use.

This document will begin by focusing
on the _semantics_ of our RPC system
using an abstract stream of objects.

Once those are defined, we'll discuss
a particular instantiation of the system
using the `jsonlines` encoding:
we intend that other encodings should also be possible,
in case we need to change in the future.

Finally, we will describe an initial series of methods
that the system could support,
to start exploring the design space, and
to show what our specifications might look like going forward,

# Intended semantics

## Sessions

The application begins by establishing a session with Arti.
There may be multiple sessions at once,
but each applications should only need one at a time.

Sessions are authenticated enough to prove at least
that they that they're launched by an authorized user,
and aren't coming from a confused web browser or something.

(This authentication can use unix domain sockets,
proof of an ability to read some part of the filesystem,
or a pre-established shared secret.
Sessions should not normally cross the network.
If they do, they must use TLS.)

Different sessions cannot access one another's status:
they cannot ordinarily list each other's circuits,
get information on each other's requests,
see each other's onion services,
and so on.

As an exception, a session may have administrative access.
If it does, it can access information from any session.

(This isolation is meant to resist
programming mistakes and careless application design,
but it is not sufficient to sandbox
a hostile application:
Such an application could, for example,
use CPU or network exhaustion
to try to detect other applications' load and behavior.
We don't try to resist attacks on that level.)

In this specification, sessions are not persistent:
once a session is closed, there is no way to re-establish it.
Instead, the application must start a new session,
without access to the previous session's state.
We may eventually provide a way to make sessions persistent
and allow apps to re-connect to a session,
but that will not be the default.


## Messages

Once a connection is established, the application and Arti
communicate in a message-oriented format
inspired by JSON-RPC (and its predecessors).
Messages are sent one at a time in each direction,
in an ordered stream.

The application's messages are called "requests".
Arti's replies are called "responses".
Every response will be in response to a single request.

A response may be an "update", an "error", or a "result".
An "error" or a "result" is a "final response":
that is, it is the last response
that will be sent in answer to a request.
An update, however, may be followed
by zero or more updates responses,
and up to one error or result.
By default, requests will _only_ receive final responses,
unless the application specifically tags the request
as accepting updates.
All updates are tagged as such.

A "result" indicates a successful completion
of an operation;
an "error" indicates a failure.

> Note that although the client must be prepared
> to receive a final response for any request,
> some request types will never get one in practice.
> For example, a request to observe all circuit-build events
> will receive only a series of updates.

## Requests, Objects, and Visibility

Every request is directed to some object.
(For example, an object may be a session,
a circuit, a stream, an onion service,
or the arti process itself.)

Only certain objects are visible within a given session.
When a session is first created,
the session itself is the only object visible.
Other objects may become visible
in response to the application's requests.
If an object is not visible in a session,
that session cannot access it.

Clients identify each object within a session
by an opaque "object identifier".
Each identifier may be a "handle" or a "reference".
If a session has a _handle_ to an object,
Arti won't deliberately discard that object
until it the handle is "released",
or the session is closed.
If a session only has a _reference_ to an object, however,
that object might be closed or discarded in the background,
and there is no need to release it.

> For more on how this is implemented,
> see "Representing object identifiers" below.

## Request and response types

There are different kinds of requests,
each identified by a unique method name,
and each with an associated set of named parameters.
Some requests can be sent to many kinds of object;
some are only suitable for one kind of object.

When we define a request,
we must also define the types of responses
that will be sent in reply to it.
Every response has a given set of named parameters.

Unrecognized parameters must be ignored.

Invalid JSON
and parameter values that do not match their specified types
will be treated as an error.

## Data Streams

We do not want to force users
to mix application data streams and control connections
on a single pipe.
But we need a way to associate application requests
with RPC sessions,
so that the application can manipulate their own streams.

We can do this in two ways.

1. When an RPC-using application wants to open a stream,
   it uses a request message to tell Arti what kind of stream it wants,
   and where the stream should go.
   Arti replies with an opaque identifier for the stream.
   The application then opens a data connection
   (e.g. via the SOCKS port)
   and gives that identifier as the target address for the stream.

2. The application asks Arti for a session-identifier
   suitable for tagging its data streams.
   Arti replies with such an identifier.
   The application then attaches that identifier
   to every data stream it opens
   (e.g. via a SOCKS authentication mechanism)
   and Arti uses it to identify which streams belong to the application.


# Instantiating our semantics with JSON, Rust, and Serde

## Encoding with JSON

We use the following metaformat, based on JSON-RPC,
for our requests:

id
: An identifier for the request.
  This may be an integer or a string. It is required.
  Arti will accept integers between `INT64_MIN` and `INT64_MAX`.

obj
: An object identifier for the object that will receive this request.
  This is a string.  It is required.

method
: A string naming the method to invoke. It is required.
  Method names are namespaced;
  For now, we commit to not using any method name
  beginning with "x-" or "X-".
  (If you want to reserve any other prefix,
  we can eventually start a registry or something.)

params
: An object describing the parameters for the method. It is optional.
  Its format depends on the method.

meta
: An object describing protocol features to enable for this request.
  It is optional.
  Unrecognized fields are ignored.
  The only recognized field is currently:
  "updates"­a boolean that indicates whether
  updates are acceptable.
  It defaults to false.

> Note: It is not an error for the client to send
> multiple concurrent requests with the same `id`.
> If it does so, however, then Arti will reply
> with response(s) for each request,
> all of them with the same ID:
> this will likely make it hard for the client
> to tell the responses apart.
>
> Therefore, it is recommended that a client
> should not reuse an ID
> before it has received a final response for that ID.

Responses follow the following metaformat:

id
: An identifier for the request.
  It is required.
  As in JSON-RPC, it will match the id of a request
  previously sent in this session.
  It will match the id of a request
  that has not received a final response.

update
: An object whose type depends on the request.
  It is required on an update.

result
: An object whose type depends on the request.
  It is required on a successful final response.

error
: An error object, format TBD.
  It is required on a failed final response.

Any given response will have exactly one of
"update", "result", and "error".

> Note:
>
> The JSON-RPC metaformat does most of what we want,
> with two exceptions:
> It doesn't support updates.
> It doesn't assume object-based dispatch.
>
> We could try to make this format align even closer with JSON-RPC,
> if we believe that there will be significant applications
> that do not want to support updates.
>
> If we want, we could change this section
> to talk more abstractly about "objects" rather than JSON,
> so that later on we could re-instantiate it with some other encoding.

> TODO: Specify our error format to be the same as,
> or similar to, that used by JSON-RPC.

### A variant: JSON-RPC.

> (This is not something we plan to build
> unless it's actually needed.)
>
> If, eventually, we need backward compatibility
> with the JSON-RPC protocol,
> we will wrap the above request and response objects
> in JSON-RPC requests and responses.
>
> Under this scheme,
> it will not be possible to support updates (intermediate responses)
> unless we add a regular "poll" request or something:
> this is also left for future work.

## Framing messages

Arti's responses are formatted according to [jsonlines](jsonlines.org):
every message appears as precisely one line, terminated with a single linefeed.
(Clients are recommended to format their requests as jsonlines
for ease of debugging and clarity,
but JSON documents are self-delimiting and
Arti will parse them disregarding any newlines.)

## Representing object identifiers.

> This section describes implementation techniques.
> Applications should not need to care about it.

Here are two ways to provide our object visibility semantics.
Applications should not care which one Arti uses.
Arti may use both methods for different objects
in the same session.

In one method,
we use a generational index for each live session
to hold reference-counted pointers
to the objects visible in the session.
The generational index is the identifier for the object.
(This method is suitable for representing _handles_
as described above.)

In another method,
when it is more convenient for Arti to access an object
by a global identifier `GID`,
we use a string `GID:MAC(N_s,GID)` for the object's identifier,
where `N_s` is a per-session secret nonce
that Arti generates and does not share with the application.
Arti verifies that the MAC is correct
before looking up the object by its GID.
(This method is suitable for representing _references_ as
described above.)

Finally, in either method, we use a single fixed identifier
(e.g. `session`)
for the current session.

## Authentication

When a connection is first opened,
only authentication requests may be use
until authentication is successful.

> TODO: Perhaps it would be a good idea to say
> that when a connection is opened,
> there is an authentication object (not a session object)
> and only _that object_ can be used
> until one of its responses eventually gives the application
> a session object?
> In that case

The authentication methods are:

auth:get_proto
: Ask Arti which version of the protocol is in use.

auth:query
: Ask Arti which authentication methods are acceptable.

auth:authenticate
: Try to authenticate using one of the provided authentication
  methods.

> TODO: Provide more information about these in greater detail.

Three recognized authentication methods are:

inherent:peer_uid
: Attempt to authenticate based on the the application's
  user-id.

inherent:unix_path
: Attempt to authenticate based on the fact that the application
  has opened a connection to a given named socket,
  which shouldn't be possible unless it is running on behalf
  of an authorized user.

fs:cookie
: Attempt to authenticate based on the application's ability
  to read a small cookie from the filesystem,
  which shouldn't be possible unless it is running on behalf
  of an authorized user.

> TODO Maybe add a "this is a TLS session and I presented a good certificate"
> type?

Until authentication is successful on a connection,
Arti closes the connection after any error.

> Taking a lesson from Tor's control port:
> we always want a correct authentication handshake to complete
> before we allow any requests to be handled,
> even if the stream itself is such
> that no authentication should be requires.
> This helps prevent cross-protocol attacks in cases
> where things are misconfigured.


## Specifying requests and replies.

When we are specifying a request, we list the following.

* The method string for the request.

* Which types of object can receive that request.

* The allowable format for that request's associated parameters.
  This is always given as a Rust struct
  annotated for use with serde.

* The allowable formats for any responses
  for the request.
  This is always given as a Rust struct or enum,
  annotated for use with serde.


# A list of requests


...

## Cancellation

> TODO: take a request ID (as usual),
> and the ID of the request-to-cancel as a parameter.
>
> (Using the 'id' as the subject of the request is too cute IMO,
> even if we change the request's meaning to
> "cancel every request with the same id as this request".)

## Authentication

...

## Requests that apply to most objects

...

## Checking bootstrap status

...

## Opening data streams

...

## Working with onion services

...

