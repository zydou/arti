# Requests, responses, JSON, and protocol details

Every request and every response is encoded as a JSON object.
Here we'll talk about these objects and their behavior.

> Note: In JSON, an "object" is a key-value association
> wrapped in `{` and `}`.
> When we're referring to these, we will always say "JSON object"
> to distinguish them from objects in the RPC system.

## Request format

Requests are sent from the RPC client (application)
to the RPC server (Arti).

An example request looks something like this:

```json
{ "id": "121879",
  "obj": "8966",
  "method": "arti:example_method",
  "params": {
      "an_argument": {},
      "another_argument": "example"
  },
  "meta": {
     "updates": true
  }
}
```

We'll talk about each member of this JSON object in turn.
(Unrecognized members are ignored.)

`id`
: An identifier for the request; used to match responses with requests.
  Can be a string or an integer.
  The client library should generate unique id values on its own;
  the application should not include this field.

`obj`
: An Object ID string identifying the RPC object on the server
  that should receive the method invocation.
  When a connection is first created,
  only a special object with the object ID "connection"
  is available to receive requests.
  After the connection has authenticated,
  a session object is also available;
  the client library can give you its object ID.
  Other object IDs will become available later on.

`method`
: The name of the method to be invoked.

`params`
: A JSON object holding arguments to the method.
  Unrecognized arguments are ignored.

`meta`
: A JSON object holding additional information
  about how the method is to be invoked.
  Optional.

Recognized fields in `meta` are as follows.
(Unrecognized fields are ignored.)

`updates`
: Optional, defaults to `false`.
  The `updates` field here indicates whether
  the application wants to receive
  incremental updates about the method's progress.
  Has no effect if the method does not support updates.
  Don't set `updates` to true unless you actually want updates.

`require`
: Optional, defaults to `[]`.
  A list of strings indicating features that the method must support.
  The server will reply with an error if any listed feature is not supported.
  Typically, you can ignore this;
  it will be used to enable compatibility when new method arguments are added.


> In the Rust and C APIs,
> your application will generate these requests as JSON strings,
> and pass them to the library.
>
> In the Python library,
> your application will typically use
> the `ArtiRpcObject.invoke` and `invoke_with_handle` methods
> to construct the JSON objects for you.

## Response format

Responses are also JSON objects.

Responses come in three types: _results_, _errors_, and _updates_.
A result indicates that a request completed successfully.
An error indicates that a request failed somehow.
An update indicates that an incremental change has occurred
with a running request,
and that the request is still running.

Updates are only given in response to requests
in which the `meta.updates` field was set to `true`.

Results and errors are "final":
no request will receive more than one final response.

Every kind of response (result, error, or update) has an `id` field
that exactly matches the `id` of the request it is in reply to.

> This is not exactly true:
> If an application sends Arti a request so malformed
> that Arti cannot determine the request's `id`,
> then Arti will respond with an error
> containing no `id` field,
> and close the connection.


### Result format

An example result might look like this:

```json
{ "id": "121879",
  "result" : {
     "value" : 77,
     "notes": "hello world",
     "extra data": { 1: 77.0, "example": "thing" }
  }
}
```

In addition to the `id` field,
a result contains a field called `result`.
The `result` is a JSON object
whose members depend on the method that was invoked.


### Update format

An example update might look like this:

```json
{ "id": "121879",
  "update" : {
     "status" : "doing okay",
     "percent_done": "25",
     "problems": null
  }
}
```

In addition to the `id` field,
an update contains a field called `update`.
The `update` is a JSON object
whose members depend on the method that was invoked.

### Error format

An example error might look like this:

```json
{ "id": "121879",
  "error": {
      "message": "Something fell down",
      "code": 2,
      "kinds": [ "arti:TopplingObject" ],
      "data": {
          "object_name": "priceless vase",
          "former_status": "precariously balanced"
      }
  }
}
```

In addition to the `id` field,
an error contains single field called `error`.
The `error` is a JSON object containing these members:

`message`
: A string providing a human-readable description of the error.
  Don't try to parse this message; its format may change in the future!

`kinds`
: An array of strings, each denoting a category of error.
  When testing whether an error has a given kind,
  be sure to search through the whole list.

> As of this writing (Jan 2025),
> we do not have a complete list of the error kinds
> that our RPC methods will return,
> and we might change the kinds associated with individual errors.
> Unless an error kind is explicitly documented,
> please do not depend on it remaining constant.

`code`
: An integer code indicating
  [a general sort of error](rpc-meta-spec.md#error-code).
  This is a leftover from JSON-RPC;
  you shouldn't rely on it.
  Use `kinds` instead.

`data`
: An optional JSON object with additional error information.
  When present,
  it indicates method-specific error implementation,
  and the method should document what it contains.

### Parsing flexibility and forward compatibility

When handling JSON responses,
all clients _must_ accept JSON objects containing unexpected fields
and treat them as if those fields were not present.
Future versions of Arti will often introduce new fields
in results, errors, and updates:
It is the application's responsibility
not to misbehave in the presence of new fields.
