# The Arti RPC protocol

## Preliminaries

### Document status

This document is a work in progress.
It describes our RPC system as we've designed it.

Where possible,
we'll try to describe what is implemented
and what is not.

### Goals and organization

This document tries to specify our RPC protocol.
Ultimately we hope it will be sufficient
for a (perhaps hypothetical) reimplementation.
Right now, though, its primary role
is to support our own implementation work,
on both the RPC implementation
and its consumers.
This document does not discuss internal implementation details:
Although there are some interesting challenges
in implementing this protocol inside Arti,
they are not part of the protocol itself.

What we do cover are:

* The semantics underlying the RPC system,
  its objects, and its messages.
* The protocol (based on `jsonlines`) that we
  use to send the messages described above.
* A few of the methods currently implemented
  by the RPC system in Arti,
  along with other methods we expect to implement in the future.
* The protocol extension(s) we use to integrate the RPC system
  with SOCKS5 (or later, HTTP CONNECT).

## Intended semantics

### Sessions

The application begins by establishing a session with Arti.
There may be multiple sessions at once,
but each applications should only need one at a time.

Sessions are authenticated enough to prove at least
that they're launched by an authorized user,
and aren't coming from a confused web browser or something.

(This authentication can use unix domain sockets,
proof of an ability to read some part of the filesystem,
an in-process socketpair,
or a pre-established shared secret.
Sessions should not normally cross the network.
If they do, they must use TLS.)

Different sessions cannot access one another's status:
they cannot ordinarily list each other's circuits,
get information on each other's requests,
see each other's onion services,
and so on.

As an exception, a session may have administrative "superuser" access.
If it does, it can access information from any session.

> At present (Sep 2024)
> administrative access is not implemented.

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

### Objects

At any given time,
a session has access to one or more "RPC Objects"
(or just "Objects").

> For example, an Object may be a session,
> a circuit, a stream, an onion service,
> or the arti process itself.

In this document, Object means an RPC Object,
not a JSON document object.

Each object is denoted by an opaque "Object ID",
which is serialised in JSON as a string.
An Object ID is a sequence of printable non-space ASCII characters.
The format of an Object Identifier string is not otherwise stable,
and clients must not rely on it.

Object IDs behave like capabilities:
an application can use an object if and only if
it has an ID for that object.

Unless otherwise specified,
an Object ID is session-local:
an Object ID from one session must not be used in another session.
(It might refer to a totally different object in that other session,
or to no object at all.)

(Some "externally visible" Object IDs
_can_ be used outside of a session.
These are used in order to integrate with SOCKS and similar protocols.)

> TODO: In Arti, we call such IDs "exposed outside of session".
> Should we rename them there or here?

> At present (Sep 2024),
> we guarantee that an externally visible object ID
> will never contain a colon (`:`).
> This may change if we change how we handle SOCKS request encoding.

With a session,
any given Object ID always refers to the same object,
or to no object at all.
(That is to say
if an object ID `X` refers to some object within some session at time `T`,
then at time `T+delta`,
`X` will definitely not refer to any different object.)

An Object ID can be a
Handle (a strong ID) or a
Reference (a weak ID).
Each method that returns an Object ID
states whether the returned ID is a Handle or a Reference.

A Handle is valid until
it is explicitly released with the `rpc:release` method
(or, the session is closed).
So long as a Handle exists,
Arti will not dispose of the underlying object,
or close it as unused.
Therefore, clients which make long-running RPC connections
must explicitly release no-longer-needed Handles,
to avoid leaks.

A mere Reference is valid until
the underlying object is freed,
but doesn't influence the lifecycle of that object.

There can be multiple IDs for the same Object.
(So performing string comparisons on Object IDs
does not yield reliable information about
whether two IDs refer to the same Object.)

However, the same Object ID string will never be reused within a session
for a different underlying object,
even after the underlying object is disposed of.
Even the ID string for a Handle which has been explicitly released
will not be reused.

> TODO: "release" is a funny word here.
> Many objects can be destroyed or enter a "closed" state
> independent of what Arti wants:
> for example, a circuit can be destroyed by any relay on the circuit,
> or even by a network failure.

> NOTE: Previously we referred to strong IDs as "handles"
> and weak IDs as "references", but we did not do so consistently.
>
> At present (Jan 2025)
> the RPC system supports weak IDs, but doesn't yet generate any.

An Object ID never changes from strong to weak,
or from weak to strong.
Instead, functions that downgrade or upgrade Object IDs
return a new Object ID.

> At present (Sep 2024),
> there are no weak IDs,
> so downgrade and upgrade aren't implemented.

A strong Object ID can be "owning" or "non-owning".
If an Object ID "owns" its object,
then the relevant object will be destroyed
(torn down, closed, etc)
when the session closes.
Otherwise, the object will continue to exist
for the rest of its ordinary lifecycle.

(For example, if a session owns a DataStream,
and the session closes,
then the DataStream will be closed even if it is still in use.)

> TODO: "destroyed" is also a funny word here.
> Can we come up with a better word that applies
> to all of our things can be closed, torn down, destroyed,
> deleted, expunged, etc?
>
> Also TODO: "ordinary lifecycle" is a bit fuzzy.

> At present (Sep 2024),
> owning object IDs are not implemented.

#### Objects and authentication

When an application first connects to Arti,
before it authenticates,
it has access to only one object,
which represents the RPC connection itself.
The Object ID for this connection object is `connection`.
The only operations available on an RPC connection
are those necessary to authenticate.

The application uses this connection object
to authenticate with Arti.
By doing so successfully,
it receives an Object ID for a "session" object,
which serves as a root capability
for all other available functionality.

(See discussion of authentication below.)


### Messages

Once a connection is established, the application and Arti
communicate in a message-oriented format
inspired by JSON-RPC (and its predecessors).
Messages are sent one at a time in each direction,
in an ordered stream.

Before the application sends any requests,
Arti sends a single ["banner"](#banner) message
to indicate that it is correctly initialized,
and likely to understand the client.

The application's messages are called "requests".
Every request is directed to a single RPC Object.

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

Messages are representable as JSON -
specifically, they are within the subset defined in RFC7493 (I-JSON).
In the current concrete protocol they are *represented as* JSON;
we may define other encodings/framings in the future.

> The message stream may not contain NUL (zero-valued) bytes.
> This is not an additional requirement;
> it is a consequence of the JSON data format.

### Banner message {#banner}

The banner message is a JSON object containing
the key "arti_rpc", with any JSON value.

> Valid banners include `{"arti_rpc":True}`,
> and `{"other-info": 7, "arti_rpc":"Hello world"}`.

As noted above, Arti sends a banner upon
accepting the application's connection,
to indicate that it is initialized and running.

Applications MUST NOT send any requests before receiving a banner.

> One purpose of the banner message is to avoid race conditions
> between when the RPC server has bound its ports,
> and when it has initialized any necessary files on disk.
> Since the server won't send a banner until it is fully initialized,
> the client can safely read other files from disk only when
> the banner is received.

### Request and response types

There are different kinds of requests,
each identified by a unique method name.

Each method is associated with a set of named parameters.
Some requests can be sent to many kinds of Object;
some are only suitable for one kind of Object.

When we define a method,
we state its name,
and the names and types of its parameters `params`.
and the expected contents of the successful `result`,
and any `updates`s.

Unrecognized parameters must be ignored.
(Indeed, any unrecognized fields in a JSON object must be ignored,
both by the server and by the client.)

Invalid JSON
and parameter values that do not match their specified types
must be treated as an error,
both by the server and by the client.

### Concurrent requests and pipelining {#pipelining}

A client may send multiple requests,
without waiting for responses to earlier requests.

When multiple requests are outstanding,
the ordering of responses from the server
is not necessarily the same as the ordering of the requests.

The server may impose limits on the amount of concurrency
and may stop reading from the client when server buffers are full.
It is the client's responsibility
to avoid concurrent-writing-induced deadlocks.

### Data Streams

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


## Instantiating our semantics with JSON, Rust, and Serde

### Encoding with JSON

We use the following metaformat, based on JSON-RPC,
for our requests:

id
: An identifier for the request.
  This may be a number or a string. It is required.
  (Floating point numbers and
  integers that can't be precisely represented as an IEEE-754 double
  are not guaranteed to round trip accurately.
  Integers whose absolute value is no greater than
  `2^53-1 = 9007199254740991`,
  will round trip accurately.
  64-bit integers might not.)

obj
: An Object Identifier for the Object that will receive this request.
  This is a string.  It is required.

method
: A string naming the method to invoke. It is required.
  Method names are namespaced; see
  "Method Namespacing" below.

params
: A JSON object describing the parameters for the method.
  Its format depends on the method.
  (Unlike in JSON-RPC, this field is mandatory;
  or to put it another way, every method we define will
  require `params` to be provided,
  even if it is allowed to be empty.)
  Unrecognized parameters _MUST_ be ignored;
  see "Methods and forward compatibility" below.

meta
: A JSON object describing protocol features to enable for this request.
  It is optional.
  Unrecognized fields are ignored.

The fields in the `meta` object are as follows:

updates
: A boolean that indicates whether
  updates are acceptable.

require
: A list of "features" that must be supported
  if the request is not to be rejected.
  (See "Methods and forward compatibility" below.)
  Defaults to the empty list.

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
  It is (almost always) required.
  As in JSON-RPC, it will match the id of a request
  previously sent in this session.
  It will match the id of a request
  that has not received a final response.

  (As an exception:
  A error caused by a request in which the id could not be parsed
  will have no id itself.
  We can't use the id of the request with the syntax problem,
  since it couldn't be parsed.
  Such errors are always fatal;
  after sending one, the server will close the connection.)

update
: A JSON object whose contents depends on the request method.
  It is required on an update.

result
: A JSON object whose contents depends on the request method.
  It is required on a successful final response.

error
: A JSON error object, format TBD.
  It is required on a failed final response.
  Unlike a `result` and `update`,
  an error can be parsed and validated without knowing the request method.

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
> to talk more abstractly about "document objects" rather than JSON,
> so that later on we could re-instantiate it with some other encoding.

> TODO: Specify our error format to be the same as,
> or similar to, that used by JSON-RPC.

#### Handling invalid JSON

Upon receiving any syntactically incorrect JSON,
the server MUST close the connection.

(This applies only to strings that are not valid JSON;
not to strings that are valid JSON
but which do not match the expected objects.)

> **This is a security feature.**
>
> If the server tolerated syntax errors,
> it would be open to more protocol-in-protocol attacks.
> For example,
> an attacker might be able to trick a web browser
> into making an HTTP request a TCP port serving RPC,
> and then embed its payload as the HTTP request body.
> If our protocol were to tolerate incorrect JSON,
> it would ignore the HTTP headers,
> and then process the attackers payload.
>
> Alternatively, we could have said that syntax errors
> are only permitted _after_ authentication.
> But if we did that,
> an attacker could more easily exploit string injection opportunities
> in a badly programmed client.
> (Also, "never allowed" is easier to implement than "sometimes allowed".)

> **Example**
>
> Upon receiving `{ a: 3 }\n`, the server will close the connection,
> since `{ a : 3 }` is not valid JSON.
>
> Upon receiving `{ 'a' : 3 }\n`, the server will not close the connection,
> even though `{ 'a': 3 }` is not a valid request,
> since `{ 'a' : 3 }` _is_ valid JSON.
>
> Upon receiving `{ 'a' : 3\n` (with no closing brace),
> the server will still not close the connection:
> The closing brace may appear on a later line,
> and the server does not enforce
> one-request-per-line encoding for its inputs.




#### Method namespacing

All methods names consist of a namespace and an identifier.
Both must be valid C identifiers.
The namespace and identifier are separated by a colon.
(For example, the method name `arti:connect`
is in the namespace `arti`, and has the identifier `connect`.)

> All methods appear in a namespace;
> there are no un-namespaced methods.

Right now, the following namespaces are reserved:

* `arti` — For use by the Arti tor implementation project.
* `auth` — Defined in this spec; for authenticating an initial session.
* `rpc` — Defined in this spec.

To reserve a namespace, open a merge request to change the list above.

Namespaces starting with `x_` will never be allocated.
They are reserved for experimental use.

Method names starting with `x_` indicate
experimental or unstable status:
any code using them should expect to be unstable.

##### Method naming conventions

> By convention,
> the identifier part of each method begins with a verb.
> (We count "new" as a verb.)
>
> For example, a method might be called `arti:get_circuit`
> (but not `arti:circuit`)
> or `arti:new_isolated_client`
> (but not `arti:isolated_client`).
>
> The verb `get` should only be used
> for methods that return pre-existing objects,
> not for methods that construct new objects.

#### Errors

Errors are reported as responses with an `error` field (as above).
The `error` field is itself an object, with the following fields:

message
: A String providing a short human-readable description of the error.
  Clients SHOULD NOT rely on any aspect of the format of this String,
  or do anything with it besides display it to the end user.
  This may be a long, multiline string, listing multiple nested errors.
  (It is generated by `tor_error::Report` or equivalent.)

kinds
: An array of Strings, each
  denoting a category of error.
  Kinds defined by Arti will begin with the prefix
  "arti:", and will
  denote one of the members of [`tor_error::ErrorKind`].

  If Arti renames an `ErrorKind`,
  the old name will be provided after the new name.
  If an error is reclassified,
  Arti will provide the previous classification
  (the previously reported kind)
  after the current classification,
  if it's meaningful,
  and it's reasonably convenient to do so.

  Therefore, a client which is trying to classify an error
  should look through the array from start to finish,
  stopping as soon as it finds a recognised `ErrorKind`.

  Note that this set may be extended in future,
  so a client must be prepared to receive unknown values from Arti,
  and fall back to some kind of default processing.

data
: An optional JSON object containing additional error information.
  An application may use this to handle certain known errors,
  but must always be prepared to receive unknown errors.

  When `data` is present, its keys will always be namespaced strings.
  The type and interpretation of the values of these strings will depend
  on the keys.

  The semantics and stability for a field in `data` will be defined
  by the method documentation for the method that it generated it,
  or by this documentation.

  See "Anticipated use of error.data" below for more on how we
  plan to use this field.

<a id="error-code"></a>

code
: A Number that indicates the error type that occurred according
  to the following table.
  The values are in accordance with the JSON-RPC specification.

  The `code` field is provided for JSON-RPC compatibility,
  and its use is not recommended.
  Use `kinds` to distinguish error categories instead.
  For example, instead of comparing `code` to `-32601`,
  recognize `NoSuchMethod` in `kinds`.

```
code 	message 	meaning
-32600 	Invalid Request 	The JSON sent is not a valid Request object.
-32601 	Method not found 	The method does not exist.
-32602 	Invalid params 		Invalid method parameter(s).
-32603 	Internal error		The server suffered some kind of internal problem
1	Object error		Some requested object was not valid
2	Request error		Some other error occurred.
3   No method impl      This method isn't available on this object.
4   Request cancelled   The request was cancelled before it could finish.
5   Feature not present     A required feature was not available
```
We do not anticipate regularly extending this list of code values.

[`tor_error::ErrorKind`]: https://docs.rs/tor-error/latest/tor_error/enum.ErrorKind.html



##### Future extensions to the Error type.

We're aware that the Error type above
does not expose a lot of useful details
about the actual errors that have occurred.
If you find that you need more data,
**please** do not start parsing the message strings:
instead let us know, so we can extend the Error format.

##### Anticipated use of error.data

> We intend that an error's `data` should be used in cases
> where a method intends to deliberately expose
> a specific piece of data on failure,
> and that piece of data can become part of the method's API.

> We do _not_ anticipate having `data` be present-by-default for all errors:
> for example, we don't plan to have an on-by-default `data` member that serializes
> an entire Rust error.
> If we were to add such a mechanism,
> it would likely be via a new flag in `request.meta` that would add
> a `data.rpc:serialized_error` field or something similar to any returned error.
> In such a case, we would have to include warnings in our documentation
> that these serialized errors were not a stable part of the RPC API.)
>
> If we want to change a stable `data.error.foo` that's generated
> in some particular circumstances,
> when possible we will usually take one of these two approaches:
>
> - *extend* the value provided for `foo`, or
> - provide both the old `data.error.foo`
>   and a new `data.error.foo-updated` (naming TBD).
>
> This will provides compatibility with older clients
> that expect the old error data.

##### Example error response JSON document

Note: this is an expanded display for clarity!
Arti will actually send an error response on a single line,
to conform to jsonlines framing.

```
{
   "id" : "5631557cdce0caa0",
   "error" : {
      "message" : "Cannot connect to a local-only address without enabling allow_local_addrs",
      "kinds" : [
         "arti:ForbiddenStreamTarget"
      ],
      "code" : -32001
   }
}
```

##### JSON-RPC compatibility

This error format is compatible with JSON-RPC 2.0.
The differences are:

 * Input that cannot be parsed as JSON is not reported as an error;
   it is dealt with at the framing layer
   (probably, by summarily closing the transport connection)

 * The `kinds` field has been added,
   and use of `code` is discouraged.

 * The `message` field may be less concise than JSON-RPC envisages.

#### We use I-JSON

In this spec JSON means I-JSON (RFC7493).
The client must not send JSON documents that are not valid I-JSON.
(but Arti may not necessarily reject such documents).
Arti will only send valid I-JSON
(assuming the client does so too).

We speak of `fields`, meaning the members of a JSON object.

#### A variant: JSON-RPC.

> (This is not something we plan to build
> unless it's actually needed.)
>
> If, eventually, we need backward compatibility
> with the JSON-RPC protocol,
> we will wrap the above request and response JSON objects
> in JSON-RPC requests and responses.
>
> Under this scheme,
> it will not be possible to support updates (intermediate responses)
> unless we add a regular "poll" request or something:
> this is also left for future work.

### Framing messages

Arti's responses are formatted according to [jsonlines](jsonlines.org):
every message appears as precisely one line, terminated with a single linefeed.
(Clients are recommended to format their requests as jsonlines
for ease of debugging and clarity,
but JSON documents are self-delimiting and
Arti will parse them disregarding any newlines.)

Clients may send as many requests at the same time as they like.
arti may send the responses in any order.
I.e., *arti may send responses out of order*.

If a client sends too many requests at once,
arti may stop reading the transport connection,
until arti has dealt with and replied to some of them.
There is no minimum must-be-supported number or size of concurrent requests.
Therefore a client which sends more than one request at a time
must be prepared to buffer requests at its end,
while concurrently reading arti's replies;
otherwise deadlock may occur.

(See note on implementation strategies in the appendix.)

### Methods and forward compatibility

All server implementations must ignore unrecognized method parameters,
to ensure that additional parameters can be added later on.

> As a consequence of the above,
> we should be very careful when adding new parameters to existing methods,
> if it is likely that a user who expects those parameters to be interpreted
> will receive insecure behavior if those parameters are ignored instead.
>
> The "feature" mechanism below describes a way for a user
> to mark some behavior as "must provide".

In the future, as RPC methods gain new parameters or new features,
clients may want to tell the server that a given request should only be
processed if a given feature is available.
To do so, the client may put the name of that feature in the list
`meta.require` in its request.
If any feature in that list is not recognized or not supported,
the server must fail with an error
using the "Feature not present" error code.
The `error.data['rpc:unsupported_features']` field in the reply
will hold a list of the features that will not supported.

Feature names are UTF-8 strings.

A feature that applies only to a single method is
named with the method name,
followed by a colon, and then a C identifier.
(For example, `arti:fetch_consensus:compression`.)

A feature that applies to all or most RPC methods,
or to the RPC system as a whole,
has a name beginning with `rpc`, and then _two_ colons,
and then a C identifier.
(For example, `rpc::timeout`.)


> Note: As a side effect of the above rules,
> it is correct for an implementation that understands no features to
> reject every request that has a nonempty `meta.require` field.


> Example:
>
> Suppose we have an `arti:open-onion-service` method
> to open an anonymous onion service,
> and we are thinking of adding a new parameter `onehop` to that method
> to say that the onion service should be _non-anonymous_.
>
> If a user passes this parameter to an old version of Arti,
> it will get an anonymous onion service, since the older version of Arti
> doesn't recognize the parameter.
> This situation is probably okay,
> since accidentally getting _more_ anonymity than you wanted
> is not a security hole.
>
> We could additionally define a feature
> (say, `arti:open-onion-service:hs-onehop`)
> to indicate that the new parameter is understood.
> A client could then pass this feature in the `meta.require` of a request,
> to indicate that the request should only be processed
> if one-hop onion services are supported.

Features are properties of specific requests.
It is not guaranteed that the set of supported features
is the same from one request to the next.
(For example, different methods,
or the same method on different objects,
or on the same object in different state(s),
might support different sets of features.)

Therefore a client MUST indicate its need for features in *every* applicable request.
A client MUST NOT retain information about features apparently supported
and then rely on the same feature being supported in future requests.

When trying to work with multiple server implementations,
a client SHOULD simply try its available strategies in sequence,
attempting what it considers the "best" approach first,
tolerating "not supported" errors, and falling back to compatibility code.
Clients usually SHOULD NOT attempt to optimise this process
by remembering which method(s) were previously successful
(and/or which feature(s) were previously supported).

#### Breaking changes

> As a general rule, but not a formal guarantee:
> at the current level of stability in Arti's RPC system,
> when we _do_ make a breaking change,
> we will try to only make breaking changes that cause
> previously working code to fail with an error.
> We will try _not_ to make any breaking changes that cause
> previously working code to behave in a subtly different way.

### Superuser / Administrative access

> This section is a sketch, and is not implemented.
> All names will be probably be changed.
>
> * Some RPC Sessions are _privileged_.
> * Such sessions support an `rpc:su` method
>   that returns an `ArtiRoot` object.
>   * Just as all regular arti functionality is available from a Session,
>     all privileged functionality is available from an `ArtiRoot`.
> * A privileged RPC session supports an `rpc:new_unprivileged_session`
>   method that gives you a new session that _doesn't_ support `rpc:su`.
>   This method can be used as part of dropping capabilities.

### Authentication

When a connection is first opened,
only a single "connection" object is available.
Its object ID is "`connection`".
The client must authenticate to the connection
in order to receive any other object IDs.

The pre-authentication methods available on a connection are:

auth:authenticate
: Try to authenticate using a simple authentication
  methods.

> TODO: Provide more information about these in greater detail.

The recognized authentication schemes are:

auth:inherent
: Attempt to authenticate based on the fact that the application
  has opened a connection to a given named socket,
  which shouldn't be possible unless it is running on behalf
  of an authorized user.

auth:cookie
: Attempt to authenticate based on the application's ability
  to read a small cookie from the filesystem,
  which shouldn't be possible unless it is running on behalf
  of an authorized user.
  (See [cookie authentication](./rpc-cookie-sketch.md).)

> TODO Maybe add a "this is a TLS session and I presented a good certificate"
> type?

Until authentication is successful on a connection,
Arti closes the connection after any error.

### Specifying requests and replies.

When we are specifying a request, we list the following.

* The method string for the request.

* Which types of Object can receive that request.

* The allowable format for that request's associated parameters.
  This is always given as a Rust struct
  annotated for use with serde.

* The allowable formats for any responses
  for the request.
  This is always given as a Rust struct or enum,
  annotated for use with serde.


## Differences from JSON-RPC

 * We use I-JSON (RFC7493).

 * Every request must have an `obj` field.

 * A request's `id` may not be `null`.

 * There can be `update`s - non-final responses.

 * We specify a framing protocol
   (although we permit new framing protocols in the future).

 * We have connection-oriented session state.

 * We support [overlapping and pipelined responses](#pipeing).

 * TODO our errors are likely to be a superset of JSON-RPC's.  TBD.

 * TODO re-check this spec against JSON-RPC.


## A list of requests

This section lists some requests with additional semantics
not currently covered in their reference documentation.

This text should all, eventually, be merged into the reference documentation.

### Cancellation

> At present (Sep 2024)
> a cancellation mechanism is not implemented.

To try to cancel a request,
the RPC connection object implements
an `rpc:cancel` method, taking parameters of the form:

```
{ "request_id": id }
```

Upon receiving an `rpc:cancel` request targeting
some pending request
the RPC server must guarantee
that the target request and the cancel request both complete "reasonably quickly",
(with some status)
without doing "much" more work.

If the target request completes without being cancelled,
then the target request will return a success
(or some error other than "request cancelled").
The cancel request may or may not return an error.

If the target operation is cancelled,
then the target operation will return a "request cancelled" error,
and the cancel request will return success.

> Note that in these two cases above,
> we do not guarantee any relative ordering between the two replies,
> and we do not guarantee that a "cancel" request
> will cause the request to actually be cancelled.
>
> For further non-guarantees, see
> <https://gitlab.torproject.org/tpo/core/arti/-/issues/818#note_2998166>.


If the request has already completed
before the "cancel" request is canceled,
or if there is no such request,
the cancellation request will return an error.
(It might not be possible to distinguish these two cases,
but in both of these cases, we guarantee that
the `rpc:cancel` method has had no effect.)

If there have been multiple object requests with the same request ID,
and those requests have been in-flight simultaneously,
then it is not specified whether `rpc:cancel` will cancel one,
both, or neither.

> In general, users should avoid simultaneous requests with the same
> request ID.

Not all requests are cancellable.
Methods which cannot be cancelled should be documented as such.

> In Arti, only the rpc:cancel method is uncancellable.

## Appendix


### Client implementation strategies

We hope that most clients will choose to use
the `arti-rpc-client-core` library
(or a wrapper around it)
in order to interact with Arti RPC.
It is fairly small, efficient, and well audited.

If you choose to write your own client implementation,
you will need to consider how to prevent deadlock
when multiple requests are waiting for a reply at once.
One simple strategy is to have only one thread
responsible for reading replies from Arti,
and dispatching those replies to the appropriate requesting code.
This thread must never block on anything besides reading—which implies
that its mechanism for dispatching replies must not block.
(One example mechanism is having a nonblocking queue for each request.)

More aggressive strategies are possible.
