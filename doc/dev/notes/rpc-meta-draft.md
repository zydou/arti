# Arti RPC protocol design

## Preliminaries

### Document status

This document is a work in progress.
It describes our RPC system as we've designed it,
but it includes some pieces that are not yet built,
or not yet built correctly.

Where possible,
we'll try to describe what is implemented
and what is not.

### Goals and organization

This document tries to sketch our RPC protocol.
It is not a substitute for a more formal specification;
nonetheless, it should give enough detail
to help keep our planning in sync
as we build our RPC implementation
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
that they that they're launched by an authorized user,
and aren't coming from a confused web browser or something.

(This authentication can use unix domain sockets,
proof of an ability to read some part of the filesystem,
an in-process socketpair,
or a pre-established shared secret.
Sessions should not normally cross the network.
If they do, they must use TLS.)

> At present (Sep 2024)
> only unix domain sockets are implemented.

Different sessions cannot access one another's status:
they cannot ordinarily list each other's circuits,
get information on each other's requests,
see each other's onion services,
and so on.

As an exception, a session may have administrative access.
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
For example, an Object may be a session,
a circuit, a stream, an onion service,
or the arti process itself.

> In this document, Object means an RPC Object,
> not a JSON document object.

Each object is denoted by an opaque "Object ID".
The format of an Object Identifier string is not stable,
and clients must not rely on it.
An Object ID is a sequence of printable non-space ASCII characters.

Object IDs behave like capabilities:
an application can use an object if and only if
it has an ID for that object.

Unless otherwise specified,
an Object ID is session-local:
an Object ID from one session can't be used in another session.
(Either it refers to another object in that session,
or it refers to no object at all.)

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

An Object ID can be "strong" or "weak".
So long as a session holds a "strong" Object ID,
Arti will not release the underlying object,
or close it as unused.
If a session holds a "weak" object ID,
the underlying object may be released at any time.

> TODO: "release" is a funny word here.
> Many objects can be destroyed or enter a "closed" state
> independent of what Arti wants:
> for example, a circuit can be destroyed by any relay on the circuit,
> or even by a network failure.

> NOTE: Previously we referred to strong IDs as "handles"
> and weak IDs as "references", but we did not do so consistently.
>
> At present (Sep 2024)
> the RPC system supports weak IDs, but doesn't yet generate any.

An Object ID never changes from strong to weak,
or from weak to strong.
Instead, functions that downgrade or upgrade Object IDs
return a new Object ID.

> At present (Sep 2024),
> downgrade and upgrade aren't implemented.

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
> deleted, expunged, etc?)
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
specifically, the are within the subset defined in RFC7493 (I-JSON).
In the current concrete protocol they are *represented as* JSON;
we may define other encodings/framings in the future.

> The message stream may not contain NUL (zero-valued) bytes.
> This is not an additional requirement;
> it is a consequence of the JSON data format.

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

meta
: A JSON object describing protocol features to enable for this request.
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


##### Method namespacing

All methods names consist of a namespace and an identifier.
Both should be valid C identifiers.
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


code
: A Number that indicates the error type that occurred according
  to the following table.
  The values are in accordance with the JSON-RPC specification.

  The `code` field is provided for JSON-RPC compatibility,
  and its use is not recommended.
  Use `kinds` to distinguish error categories instead.
  For example, instead of comparing `code` to `-32601`,
  recognise `RpcMethodNotFound` in `kinds`.

```
code 	message 	meaning
-32600 	Invalid Request 	The JSON sent is not a valid Request object.
-32601 	Method not found 	The method does not exist.
-32602 	Invalid params 		Invalid method parameter(s).
-32603 	Internal error		The server suffered some kind of internal problem
1	Object error		Some requested object was not valid
2	Request error		Some other error occurred.
3   No method impl      This method isn't available on this object.
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


##### Unimplemented extension: "data"

We **do not** currently implement this field in the Error type:
It was originally part of our design, but we are leaving it out
as under-specified.

data
: A JSON value containing additional error information.
  An application may use this to handle certain known errors,
  but must always be prepared to receive unknown errors.

  The value of `data` will be one of the following:
    * a string, being the error data type name
    * an object with a single field; the field name is the error data type name;
      the meaning of the value of that field depends on the error data type name.

  Each method type name defines the format of the associated value.
  (Note: this is the "externally tagged" serde serialisation format for a Rust enum.)

  The error data type names are in a global namespace,
  like method names.
  The `data` can be parsed without knowing the method that generated the error,
  although obviously the meaning will depend on what operation was being attempted.

  Improved error handling in Arti may make Arti generate
  different error `data` for particular situations in the future,
  so clients should avoid relying on the precise contents,
  other than for non-critical functions such as reporting.


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
         "ForbiddenStreamTarget"
      ],
      "data" : {
         "arti::ErrorDetail::Address" : "BadOnion",
      },
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
while concurrently reading arti's replies.

### Authentication

When a connection is first opened,
only a single "connection" object is available.
Its object ID is "`connection`".
The client must authenticate to the connection
in order to receive any other object IDs.

The pre-authentication methods available on a connection are:

auth:get_rpc_protocol
: Ask Arti which version of the protocol is in use.

auth:query
: Ask Arti which authentication schemes are acceptable.

auth:authenticate
: Try to authenticate using one of the provided authentication
  methods.

> At present (Sep 2024)
> auth:get_rpc_protocol is deprecated.

> TODO: Provide more information about these in greater detail.

Three recognized authentication schemes are:

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

> At present (Sep 2024)
> only `inherent:unix_path` is implemented.

> TODO Maybe add a "this is a TLS session and I presented a good certificate"
> type?

Until authentication is successful on a connection,
Arti closes the connection after any error.

> Taking a lesson from Tor's control port:
> we always want a correct authentication handshake to complete
> before we allow any requests to be handled,
> even if the stream itself is such
> that no authentication should be required.
> This helps prevent cross-protocol attacks in cases
> where things are misconfigured.

> TODO-RPC: Make sure "close on any error" is implemented,
> and test it.
> It is essential for security.

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

 * We support overlapping and pipelined responses,
   rather than batched multi-requests.

 * TODO our errors are likely to be a superset of JSON-RPC's.  TBD.

 * TODO re-check this spec against JSON-RPC.


## A list of requests

> At present (Sep 2024),
> the request methods described in this section aren't implemented.
> We'll probably remove this section (or most of it)
> and replace it with better API documentation or plans.

...

### Cancellation

> At present (Sep 2024)
> a cancellation mechanism is not implemented.

To try to cancel a request,
the RPC session object supports
an `rpc:cancel` method, taking parameters of the form:

```
{ "request_id": id }
```

A successful response is the empty JSON object.
If a successful response is sent,
then the request was canceled,
and an error was sent for the canceled request.

If the request has already completed
before the "cancel" request is canceled,
or if there is no such request,
Arti will return an error.
(It might not be possible to distinguish these two cases).

> Alternative: we might implement this on the connection
> object, rather than on the session object?


### Authentication

...

> Also authorization, "get instance"


### Requests that apply to most Objects

...

> get type

> get status / info.

> set status / info

### Checking bootstrap status

...

> session.bootstrap Object, supports get status

### Instance operations

> Shut down

> Get configuration

> Set configuration



### Opening data streams

...

> session.connect()
>     takes target
>     takes circuit, optionally?
>     isolation
>     hs-credential
>     returns ... hm. Does it return a connection object with token that you can connect to
>           immediately, or a request that you can observe that eventually
>           gives you a connection?



### Working with onion services

...

> session.hsclient?
>     configure [service]


> session.hsservices. [...]
>     create
>     provision
>     reconfigure
>     getstatus



## Appendix

> At present (Sep 2024), this section is outdated.
> Once the API is more stable, we'll generate and include an updated trace.

Experimenting with Arti

We have a limited implementation of this protocol in Arti right now,
on an experimental basis.
It only works on Unix, with `tokio`.
To try it, enable the `rpc` Cargo feature on the `arti` crate,
and then connect to `~/.arti-rpc-TESTING/PIPE`.  (You can use
`nc -U` to do this.)

Right now only two commands are supported:
Authenticating and an echo command.
The echo command will only work post-authentication.

Here is an example session:

```
>>> {"id": "abc", "obj": "connection", "method": "auth:get_rpc_protocol", "params": {}}
<<< {"id":"abc","result":{"version":"alpha"}}
>>> {"id": "abc", "obj": "connection", "method": "auth:query", "params": {}}
<<< {"id":"abc","result":{"schemes":["inherent:unix_path"]}}
>>> {"id": 3, "obj": "connection", "method": "auth:authenticate", "params": {"scheme": "inherent:unix_path"}}
<<< {"id":3,"result":{"session":"2yFi5qrMD9LbIWLmqswP0iTenRlVM_Au"}}
>>> {"id": 4, "obj": "2yFi5qrMD9LbIWLmqswP0iTenRlVM_Au", "method": "arti:x-echo", "params": {"msg": "Hello World"}}
<<< {"id":4,"result":{"msg":"Hello World"}}
```

Note that the server will currently close your connection
at the first sign of invalid JSON.

Please don't expect the final implementation to work this way!
