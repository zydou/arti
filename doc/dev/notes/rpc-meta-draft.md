# Status

This is a draft document.
It does not reflect anything we've built,
or anything we necessarily will build.

It attempts to describe semantics for an RPC mechanism
for use in Arti.


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
The control stream itself should be done with TLS.)

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

By default, sessions are not persistent:
once a session is closed, there is no way to re-establish it.
Instead, the application must start a new session,
without access to the previous session's state.
We may eventually provide a way to make sessions persistent
and allow apps to re-connect to a session.


## Messages

Once a connection is established, the application and Arti
communicate in a message-oriented format
inspired by JSON-RPC (and its predecessors).
Messages are sent one at a time in each direction,
in an ordered stream.

The application's messages are called "requests".
Arti's replies are called "responses".
Every response must be in response to a single request.

A response may be "final" or "intermediate".
A final response is the last one that a request will receive.
An intermediate response may be followed
by zero or more intermediate responses,
and up to one final response.
By default, requests will only receive final responses,
unless the application specifically tags them
as accepting intermediate responses.
All intermediate responses are tagged as such.

A final response may be an "error",
indicating that the request was not well-formed,
or could not be performed successfully.

> Note that although every request must accept a final response,
> some request types will never get one in practice.
> For example, a request to observe all circuit-build events
> will receive only a series of intermediate responses.

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


## Request and response types

There are different kinds of requests,
each identified by a unique command,
and each with an associated set of named parameters.
Some requests can be sent to many kinds of object;
some are only suitable for one kind of object.

Every request is associated with one or more types of response.
Every response has a given set of named parameters.

> TODO: Describe what should be done with unrecognized parameters.
> This will represent a compromise between
> the desire to be extensible,
> and the desire to avoid surprising behavior
> if an unrecognized parameter has important semantics.

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
  This may be a positive integer or a string. It is required.
  Implementations MUST accept integers up to U64_MAX.

obj
: An identifier for the object that will receive this request.
  This is a string. It is required.

method
: A string naming the method to invoke. It is required.

params
: An object describing the parameters for the. It is optional.
  Its format depends on the method.

meta
: An object describing protocol features to enable for this command.
  It is optional.
  Unrecognized fields are ignored.
  The only recognized field is currently:
  "accept_intermediate"­a boolean that indicates whether
  intermediate responses are acceptable.
  It defaults to false.

> TODO: "accept-intermediate" sure is long!
> Maybe we should minimize some of these identifviers.

Responses follow the following metaformat:

id
: An identifier for the request.
  It is required.
  As in JSON-RPC, it must match the id of a request
  previously sent in this session.
  It must match the id of a request
  that has not received a final response.

intermediate
: An optional boolean, defaulting to false.
  It indicates whether the response is intermediate or final.

info
: An object whose type depends on the request.
  It is required on an intermediate response.

result
: An object whose type depends on the request.
  It is required on a successful final response.

error
: An error object, format TBD.
  It is required on a failed final response.

> Note:
>
> The JSON-RPC metaformat does most of what we want,
> with two exceptions:
> It doesn't support intermediate responses.
> It doesn't assume object-based dispatch.
>
> We could try to make this format align even closer with JSON-RPC,
> if we believe that there will be significant applications
> that do not want to support intermediate responses.
>
> If we want, we could change this section
> to talk more abstractly about "objects" rather than JSON,
> so that later on we could re-instantiate it with some other encoding.

## Representing objects

Here are two ways to provide our object visibility semantics.
Applications should not care which one Arti uses.
Arti may use both methods for different objects
in the same session.

In one method,
we use a generational index for each live session
to hold weak references to the objects visible in the session.
The generational index is the identifier for the object.

In another method,
when it is more convenient for Arti to access an object
by a global identifier `GID`,
we use a string `GID:MAC(N_s,GID)` for the object's identifier,
where `N_s` is a per-session secret nonce
that Arti generates and does not share with the application.
Arti verifies that the MAC is correct
before looking up the object by its GID.

Finally, in either method, we use a single fixed identifier
(e.g. `session`)
for the current session.

## Authentication

When a connection is first opened,
only authentication commands may be use
until authentication is successful.

> TODO: Perhaps it would be a good idea to say
> that when a connection is opened,
> there is an authentication object (not a session object)
> and only _that object_ can be used
> until one of its responses eventually gives the application
> a session object?
> In that case

The authentication commands are:

auth:get_proto
: Ask Arti which version of the protocol is in use.

auth:query
: Ask Arti which authentication methods are acceptable.

auth:authenticate
: Try to authenticate using one of the provided authentication
  methods.

> TODO: Provide more information about these in greater detail.

Three recognized authentication methods are:

inherent:unix_user
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
> before we allow any commands to be handled,
> even if the stream itself is such
> that no authentication should be requires.
> This helps prevent cross-protocol attacks in cases
> where things are misconfigured.


## Specifying commands and replies.

When we are specifying a command, we list the following.

* The name of the command

* Which types of object can receive that command.

* The allowable format for that command's parameters.
  This is always given as a Rust struct or enum
  annotated for use with serde.

* The allowable formats for any intermediate and final responses
  for the command.
  This is always given as a set of Rust structs or enums
  annotated for use with serde.


# A list of commands

...

## Authentication

...

## Commands that apply to most objects

...

## Checking bootstrap status

...

## Opening data streams

...

## Working with onion services

...
