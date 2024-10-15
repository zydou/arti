# Opening a connection to Arti RPC

## Scope and status

In C Tor, applications have had to use a variety of methods to answer
questions like "Is Tor running?" and "How can I connect to it?"
We hope to build on the experiences they've had
in order to design a better system.

This is a sketch for how we want applications to connect to Arti.
It isn't yet final, and it isn't yet built.
We hope to get comment from application developers
before we implement it.

This document only applies to applications
that connect to Arti over the RPC API.
An application that embeds Arti directly in Rust,
or via a hand-written Rust FFI wrapper,
will not need to use the methods in this document.

## General sketch

There will be a JSON configuration object,
called a "connect string",
that describes where Arti is listening for RPC connections.

These connect strings will be stored at well-known locations
on disk, depending on operating system.
(For example, on [XDG][XDG-user]-compliant Unix, a well-known location
might be `~/.config/arti-rpc/arti-rpc-connect.json` or
`/etc/arti-rpc/arti-rpc-connect.json`.)

There will be a default connect string
to be used when no file is found.

Applications will read connect strings to learn where to connect to Arti RPC.
Application users can override these file search paths via environment variables.

Arti will read these connect strings to learn where to listen for RPC connections.
Arti users can override these file locations via a configuration option.
Arti can be told to listen for RPC connections at multiple locations
by specifying multiple connect string files.

> Note that "connecting to RPC" is the only part we need to specify here;
> once the application has an RPC connection, it can find a SOCKS port
> and everything else it needs.

## Highest level

We expect that most RPC users will connect to Arti
via a library we provide with a C interface,
or by wrappers around that library.
(You can check out the current
[work-in-progress version][arti-rpc-client-core].)

When using this library,
the most usual way to get an RPC connection
will be by calling a C function:
`arti_rpc_connect()`.

In most cases, no further configuration will be needed:
users won't need to care too much about its actual behavior.

We strongly encourage other libraries that provide access to Arti RPC
to follow the same conventions as described here,
to keep consistency in the Arti RPC ecosystem.

### Details and options


To find a working connect string,
an Arti RPC client proceeds over a "search path",
trying each entry in sequence.

Each entry in the search path must be one of the following:
  * a literal connect string, which can be:
    - A description for how to connect to an Arti RPC server.
    - An instruction to use an embedded copy of Arti, if there is one.
    - An instruction to abort (q.v.) the search process
  * An absolute path on disk,
    to a file that should contain a connect string.

Any attempt to use a single entry will "succeed", "decline", or "abort":
  - If an attempt succeeds, the search ends immediately with success.
  - If an attempt aborts, the search ends immediately with failure.
  - If an attempt declines, the search continues to the next entry.

By default, there is a single default embedded search path.
Developers can extend this path via the RPC client API;
users can extend this path via environment variables.

> Note: Below we describe several methods
> that _prepend_ to a search path, but none that _replace_ a search path.
> To effectively replace a search path,
> a user or developer can add an "abort" instruction
> at the end of their prepended entries,
> causing the RPC client not to search any subsequent entries.

The connection Builder API methods are as follows:
 - `prepend_search_path` — Prepends additional entries before the start
   of the client's search path.

The environment variables are as follows:
 - `ARTI_RPC_CONNECT_PATH` — Additional entries to override the Arti
   client's defaults.
 - `ARTI_RPC_CONNECT_PATH_OVERRIDE` — Additional entries to override
   the application's defaults.
 - `ARTI_RPC_FORCE_SYSTEM_ARTI` — To force use of a system Arti,
   even when an embedded Arti is present.
   (Must be one of: `0`, `1`, or unset.
   If it is unset, it is treated as `0`.
   Only inspected when attempting to connect to an embedded Arti.
   If it is any value other than listed here when it is inspected,
   then the attempt to connect to arti *aborts* (q.v.))

The path is built as follows:
 1. We start with the default path.
 2. We prepend the contents of `ARTI_RPC_CONNECT_PATH`, if it is set.
 3. We prepend any elements set with `prepend_search_path`.
 4. We prepend the contents of `ARTI_RPC_CONNECT_PATH_OVERRIDE`, if it is set.

Path expansion is supported everywhere,
using syntax similar to [`tor_config::CfgPath`].

> TODO RPC: _How_ similar?

When specifying a set of paths as an environment variable,
we use colon-separated paths on Unix,
and semicolon-separated paths on Windows.

When including a literal connect string _in an environment variable_,
we must URL-encoding.
Additional particular we require:
 - The first character of the unencoded literal connect string *must* be `{`.
   (Thus, the first character of the encoded string must be `{` or `%`,
   which is never the first character of a valid absolute path.)
 - All path-separating characters (`;` on windows, `:` elsewhere)
   *must* be escaped when URL-encoding.
   (RPC client implementations *may* operate by first splitting the
   string on the path-seprating character, and then by decoding
   the individual entries.)

The default search path is:
  - `${ARTI_LOCAL_DATA}/rpc/arti-rpc-connect.json`.  (Note B)
  - `/etc/arti-rpc/arti-rpc-connect.json` (unix and mac only)

> Note A: `$ARTI_LOCAL_DATA` above expands to:
>  - `$XDG_DATA_HOME/arti/` on Unix if  `$XDG_DATA_HOME` is set.
>  - `$HOME/.local/arti/` on Unix otherwise.
>  - `$HOME/Library/Application Support/org.torproject.arti` on MacOS.
>  - `{FOLDERID_LocalAppData}/arti/` on Windows.
>    (This is typically `\Users\<USERNAME>\AppData\Local\arti`.)

> Note B: The library should detect whether it is running in a setuid
> environment, and refuse to connect if so.
> (Nice-to-have but not necessary to implement in the first version.)

The following errors are all tolerated;
when an Arti RPC client encounters encounter them,
the corresponding entry is *declined*.

 - A connect string file is absent.
 - A connect string file is present
   but the _type_ of its connect string is not recognized.
   (This likely indicates the presence of a version of Arti
   that is newer than our library.)
 - A connect string file is present,
   but we cannot read it due to `EACCES`, `ENOENT`,
   or platform-specific equivalents.
 - A connect string file is present and readable,
   but no Arti process is listening at the location it describes.
 - The connect string tells us to try an embedded
   Arti client, but no embedded client is available.

We do not tolerate these failures:
when an Arti RPC client encounters any of them,
the corresponding entry *aborts* the entire search process.

 - A connect string file is present, but cannot be parsed
   (either because it isn't JSON, or because it represents a recognized
   type of connect string with invalid options).
 - A connect string file is present, but its permissions
   (or the permissions on its parent directory, etc)
   indicate that it is writable by untrusted users.
 - A connect string file is present,
   but we cannot read it due to an error other than `EACCES`, `ENOENT`,
   etc.
 - The connect string explicitly tells us to abort.

TODO RPC These are still TBD; are they "decline" or "abort"?

 - A filename contains a `${VARIABLE}` that cannot be expanded.
 - A filename is not absolute.

## Interpreting connect strings.

Two variations of connect strings are currently defined:
"builtin" and regular.

(Note that it is possible to construct a single JSON object
that could be interpreted as both
a built-in connect string and as a regular connect string.
Such objects are invalid
and cause the search process to abort.)


### "Builtin" connect strings.

A "builtin" connect string is a JSON object with these members.
(Unrecognized members should be ignored.)

 - `builtin`: One of `"embedded"` or `"abort"`.

If the `builtin` field is `embedded`,
then the Arti RPC client should try to launch an embedded Arti client,
if possible.
If the `builtin` field is `abort`,
then the Arti RPC client must abort the search process.

Any other value for the `builtin` field is an error
and causes the search process to abort.

### Regular connect strings.

A regular connect string is a JSON object with these members.
(Unrecognized members should be ignored.)

  - `connect`: a socket-connection object, described below.

A socket-connection object is a JSON object with these members.
(Unrecognized members should be ignored.)

 - `socket`: a string or JSON object describing
   how to open a connection to the Arti RPC server.
   (Required.)

 - `auth`: a json value describing how to authenticate to the Arti RPC server.
   (Required.)


Currently recognized `socket` members are in these forms:
  - A TCP socket address, optionally prefixed with `tcp:`.
    (Examples: `127.0.0.1:9999`, `[::1]:9999`, `tcp:[::1]:9999`.)
  - An AF_UNIX socket address, prefixed with `unix:`.
    (Example: `unix:/var/run/arti/rpc_socket`)
If the `socket` member is a JSON object,
or if it has a schema prefix other than `tcp:` or `unix:`,
then the connection attempt is *declined*.

Currently recognized `auth` memebers are in one of these forms:
  - The JSON string `"none"`.
  - A TCP coookie authentication object.
Each is explained below.
If the `auth` member is in some other unsupported format,
the connection attempt is *declined*.

#### Authentication type "none"

When the `auth` member of a regular connect string is "none",
the connect string is claiming that no real authentication is necessary.

> The "none" method is appropriate in cases where
> the client's ability to connect to the specified socket
> is sufficient proof of its identity.
>
> (The RPC client must still send an `auth:none` command in this case
> to get an RPC session object.)

It is invalid to specify `none` authentication
for any socket address type other than:
 - AF_UNIX sockets

> (We may describe other types in the future.)


#### Cookie authentication

When the `auth` member of a regular connect string is in this format,
cookie authentication is in use.

> With cookie authentication, the RPC client proves that it is authorized
> by demonstrating knowledge of a secret cookie generated by the RPC server.
> It is suitable for use over local transports
> which an adversary cannot eavesdrop.
>
> Cookie authentication is described more fully elsewhere.
> (TODO RPC say where once all the documentation is merged.)

The format is a JSON object, containing the fields:
  - `cookie`: a JSON object, containing the field:
    - `cookie-path`: A path to an absolute location on disk containing a
      secret cookie.

It is invalid to specify cookie authentication
for any socket address type other than:
 - AF_UNIX sockets
 - TCP sockets to localhost.

> TODO: We might later decide to allow non-localhost cookie authentication
> for use when communicating among VMs or containers.
> On the other hand, we might instead specify a TLS-based socket and
> authentication method.

### "Owned" connect strings

> This section is sketch only,
> exploring ideas about how we might implement owned connections.
>
> An RPC client could have the ability to start an "owned" connection,
> in which it launches an external Arti RPC server process,
> with which only it can communicate,
> and which exits whenever the RPC client no longer needs it.
>
> This would likely be a third kind of connect string,
> likely looking for `arti` in the default search `$PATH`,
> with option to override the location of `arti`.
>
> It would likely work internally creating a socketpair,
> and telling the launched copy of arti to use its half
> of that socketpair alone for its connection.

> We do not plan to implement functionality for
> starting a shared system Arti on demand:
> we think that this does not belong in an RPC client code.

## Restricting access

Some developers have requested the ability to ensure
that unauthorized applications cannot access Arti.
We can do that in a few different ways.

> Orthogonally, we hope that restricting access in this way
> will not usually be necessary!
> Remember that Arti's RPC is meant to provide
> isolation among unprivileged RPC clients,
> such that one a client on RPC connection can't interfere
> with anything owned by another.
>
> Assuming that this protection is adequate,
> we hope that it it should mostly be acceptable
> to have a single Arti instance
> shared by multiple applications.


Trivially, a **fully embedded Arti**
will be able to provide no externally accessible ports,
and as such can make itself unreachable from outside its own process space.

On systems with meaningful filesystem restrictions,
the `AF_UNIX` socket paths and cookie file paths
can be used to restrict access to a single _user_.
(The User's Other applications can be added, of course.)

Beyond this, we could possibly add "per application" authentication schemes
(based on password, shared secrets, TLS client certificates, etc)
and ban unauthenticated RPC sessions.

To harden these forms of RPC protection so that they apply to SOCKS as well,
we could implement an option in Arti
so that only RPC users can actually use the SOCKS port.

## Security concerns

RPC connect strings can contain instructions to read and write files,
and possibly, in the future, perform other security-relevant actions.
RPC connect strings (and paths to them)
should be handled the same way as other critical configuration.

> For example, a future connect string variant might
> specify a *program to execute*.

RPC connect strings, and connect string paths,
MUST ONLY be obtained from trusted sources
(such as environment variables, and trustworthy parts of the filesystem).

Arti RPC connect strings from untrusted sources MUST NOT be used
(neither by RPC clients, nor by the Arti RPC server).
A client application MUST NOT allow software that it does not trust completely
to supply RPC connect strings.

> For example, an Android app providing Tor services
> MUST NOT provide RPC connect strings to other apps,
> since (per the Android security model)
> those other apps MUST NOT completely trust the Tor provider app.
>
> Allowing the Tor servce to supply the connect string,
> might allow the Tor service to completely take over the client app.
> While the Tor service can inevitably, by its nature,
> subvert client apps' use of Tor,
> the service is not supposed to have total control over the clients.
>
> (Instead, the Tor service might proxy the RPC requests,
> or, when supported in the future by Arti RPC, provide an RPC connection
> which has seen a "drop privileges" call restricting the clients' use.)


## Still unspecified

How do applications behave if they want to spin up an owned copy of Arti?
(That is, one that exits when they exit.)
Is that a special API for that?)

What does the cookie authentication look like?
(See [arti#1521] for one sketch.)




[arti-rpc-client-core]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/arti-rpc-client-core
[XDG-user]: https://www.freedesktop.org/wiki/Software/xdg-user-dirs/
[`tor_config::CfgPath`]: https://docs.rs/tor-config/latest/tor_config/struct.CfgPath.html
[arti#1521]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1521
