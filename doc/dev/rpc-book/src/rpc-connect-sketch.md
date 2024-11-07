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

There will be a TOML configuration object,
called a "connect point",
that describes where Arti is listening for RPC connections.

A file holding a "connect point" is called a "connect file".
These "connect files" will be stored at well-known locations
on disk, depending on operating system.
(For example, on [XDG][XDG-user]-compliant Unix, a well-known location
might be `~/.config/arti-rpc/connect.d/` or
`/etc/arti-rpc/connect.d/`.)

There will be a default connect point
to be used when no file is found.

Applications will read connect files to learn where to connect to Arti RPC.
Application users can override these file search paths via environment variables.

Arti will read these connect files to learn where to listen for RPC connections.
Arti users can override these file locations via a configuration option.
Arti can be told to listen for RPC connections at multiple locations
by specifying multiple connect files.

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


To find a working connect point,
an Arti RPC client proceeds over a "search path",
trying each entry in sequence.

Each entry in the search path must be one of the following:
  * a literal connect point, which can be:
    - A description for how to connect to an Arti RPC server.
    - An instruction to use an embedded copy of Arti, if there is one.
    - An instruction to abort (q.v.) the search process
  * An absolute path on disk of
    a connect file
    (a file that should contain a connect point).
  * An absolute path on disk,
    to a directory containing one or more connect files.

When reading a directory,
an implementation ignores
all files that do not have the correct extension (`.toml`).
On Unix-like systems, it also ignores all filenames beginning with `.`.
It considers the files within a directory
in lexicographical order, by filename.

Any attempt to use a single entry will "succeed", "decline", or "abort":
  - If an attempt succeeds, the search ends immediately with success.
  - If an attempt aborts, the search ends immediately with failure.
  - If an attempt declines, the search continues to the next entry.

By default, there is a single default built-in search path.
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

These environment variables can contain
three kinds of entry:
filenames, directory names, and literal connect points.
When concatenating these entries,
we use colon-separated paths on Unix,
and semicolon-separated paths on Windows.

Because a _literal connect point_ can contain the path separator character,
we need to escape them when including it an environment variable.
Therefore,
it is percent-encoded as per RFC 3986 s2.1.
(The percent encoding is of UTF-8, even if the operating system's character set is not.)
Percent-encoding must be applied to, at least:
the path delimiter;
everything other than ASCII graphic characters;
the first character, unless that character is `[`.

Thus we are able to guarantee:
 - The first character of the encoded string must be `[` or `%`,
   which is never the first character of a valid absolute path.
 - All path-separating characters (`;` on windows, `:` elsewhere)
   *must* be escaped when URL-encoding.
   (RPC client implementations *must* operate by first splitting the
   string on the path-seprating character, and then by decoding
   the individual entries.)

The default search path is:
  - `${ARTI_LOCAL_DATA}/rpc/connect.d/`.  (Notes A,B)
  - `/etc/arti-rpc/connect.d/` (unix and mac only)
  - The "USER\_DEFAULT" connect point. (Note C)
  - The "SYSTEM\_DEFAULT" connect point. (Note C)

> Note A: `$ARTI_LOCAL_DATA` above expands to:
>  - `$XDG_DATA_HOME/arti/` on Unix if  `$XDG_DATA_HOME` is set.
>  - `$HOME/.local/arti/` on Unix otherwise.
>  - `$HOME/Library/Application Support/org.torproject.arti` on MacOS.
>  - `{FOLDERID_LocalAppData}/arti/` on Windows.
>    (This is typically `\Users\<USERNAME>\AppData\Local\arti`.)

> Note B: The library should detect whether it is running in a setuid
> environment, and refuse to connect if so.
> (Nice-to-have but not necessary to implement in the first version.)
>
> Note C:
> The USER\_DEFAULT and SYSTEM\_DEFAULT connect points
> are defined as follows on Unix and Mac:
>
> USER\_DEFAULT:
> ```toml
> [connect]
> socket = "unix:${ARTI_LOCAL_DATA}/rpc/arti_rpc_socket"
> auth = "none"
> ```
>
> SYSTEM\_DEFAULT:
> ```toml
> [connect]
> socket = "/var/run/arti-rpc/arti_rpc_socket"
> auth = "none"
> ```

### Handling errors as an RPC client.

On a RPC client, some errors are fatal
and cause the connect point to **abort**;
others are nonfatal
and cause the connect point to be **declined**.

As a general guideline,
the decision about which errors are handled in which way
is meant to support a use case
in which the client is configured
with a series of "possibly good" connect points,
and is intended to choose "the first one that works."

Therefore, the sort of errors
hat typically cause a connect point to be *declined*
are those that represent a "possibly good" connect point
that "didn't work", including:
- A connect point for a server that isn't currently running,
  but might be running later.
- A connect point that some other user might be able to reach,
  but this client can't.
- A connect point that some other client might support,
  but this client doesn't.

By contrast, the sort of errors
that typically cause a connect point to be *abort*
are those that represent
 - A system failure or misconfiguration.
 - A connect point that is broken by nature
   and cannot ever work.

More specifically,
the following errors are all tolerated;
when an Arti RPC client encounters encounter them,
the corresponding entry is *declined*.

 - A connect file is absent.
 - A connect file is present
   but the _type_ of its connect is not recognized.
   (This likely indicates the presence of a version of Arti
   that is newer than our library.)
 - A connect file is present,
   but we cannot read it due to `EACCES`, `ENOENT`,
   or platform-specific equivalents.
 - A connect file is present and readable,
   but no Arti process is listening at the location it describes.
 - The connect point tells us to try an embedded
   Arti client, but no embedded client is available.

The following errors are not tolerated;
when an Arti RPC client encounters any of them,
the corresponding entry *aborts* the entire search process.

 - A connect file is present, but cannot be parsed
   (either because it isn't TOML, or because it represents a recognized
   type of connect point with invalid options).
 - A connect file is present, but its permissions
   (or the permissions on its parent directory, etc)
   indicate that it is writable by untrusted users.
 - A connect file is present,
   but we cannot read it due to an error other than `EACCES`, `ENOENT`,
   etc.
 - The connect file explicitly tells us to abort.

TODO RPC These are still TBD; are they "decline" or "abort"?

 - A filename within a connect point
   contains a `${VARIABLE}` that cannot be expanded.
 - A filename within a connect point is not absolute.

## Interpreting connect points.

Two variations of connect points are currently defined:
"builtin" and regular.

(Note that it is possible to construct a single TOML object
that could be interpreted as both
a built-in connect point and as a regular connect point.
Such objects are invalid
and cause the search process to abort.)

Unrecognized TOML tables and members in a connect point
must be ignored.

### "Builtin" connect points.

A "builtin" connect point is a TOML object with a `[builtin]` table.

The `[builtin]` table contains a single member:

 - `builtin`: One of `"embedded"` or `"abort"`.
   (Required)

If the `builtin` field is `embedded`,
then the Arti RPC client should try to launch an embedded Arti client,
if possible.
If the `builtin` field is `abort`,
then the Arti RPC client must abort the search process.

Any other value for the `builtin` field is an error,
and causes the entry to decline.


### Regular connect points.

A regular connect point is a TOML object with a "connect" table.

  - `connect`: a socket-connection table, described below.

A socket-connection table has the following members.
(Unrecognized members should be ignored.)

 - `socket`: a string describing
   how to open a connection to the Arti RPC server.
   (Required.)

 - `socket_canonical`: a string describing
   the "official" address of the Arti RPC server.
   Used in some authentication protocols to restrict MITM attacks.
   Ignored outside of those authentication protocols.
   If absent, defaults to the value of `socket`.
   (Optional.
   Note that nobody actually binds or connects based on the value of this field.)

 - `auth`: a TOML value describing how to authenticate to the Arti RPC server.
   (Required.)


The `socket` members must be in a form accepted by
[`general::SocketAddr::from_str`](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2519).

> TODO: Fix that above link once !2519 is merged.

> These formats are, roughly:
>  - A TCP socket address, optionally prefixed with `inet:`.
>    (Examples: `127.0.0.1:9999`, `[::1]:9999`, `inet:[::1]:9999`.)
>  - An AF_UNIX socket address, prefixed with `unix:`.
>    (Example: `unix:/var/run/arti/rpc_socket`)

If the `socket` member
has a schema prefix other than `inet:` or `unix:`,
or if it is a relative `unix:` path,
then the connection attempt is *declined*.


Currently recognized `auth` memebers are in one of these forms:
  - The string `"none"`.
  - A TCP coookie authentication object.
Each is explained below.
If the `auth` member is in some other unsupported format,
the connection attempt is *declined*.

**Security concerns**: Do not construct a connect point with an
`socket_canonical` field unless you have some way to guarantee
that an attacker cannot bind to the address specified in the `socket`
field.

#### Authentication type "none"

When the `auth` member of a regular connect point is "none",
the connect point is claiming that no real authentication is necessary.

> The "none" method is appropriate in cases where
> the client's ability to connect to the specified socket
> is sufficient proof of its identity.
>
> (The RPC client must still send an `auth:none` command in this case
> to get an RPC session object.)

As a matter of policy we do not support `none` authentication
for any socket address type other than:
 - AF_UNIX sockets
Any such connect point is declined by the client library
(and Arti would reject such an authentication attempt).

> (We may describe other types in the future.)


#### Cookie authentication

When the `auth` member of a regular connect point is in this format,
cookie authentication is in use.

> With cookie authentication, the RPC client proves that it is authorized
> by demonstrating knowledge of a secret cookie generated by the RPC server.
> It is suitable for use over local transports
> which an adversary cannot eavesdrop.
>
> Cookie authentication is described more fully elsewhere.
> (TODO RPC say where once all the documentation is merged.)

The format is a TOML table, containing:
  - `cookie`: a TOML table, containing the field:
    - `path`: A path to an absolute location on disk containing a
     secret cookie.

> See examples below.

As a matter of policy we do not support cookie authentication
for any socket address type other than:
 - AF_UNIX sockets
 - TCP sockets to localhost IP addresses.
Any such connect point is declined (as with the policy for `none` above).

> TODO: We might later decide to allow non-localhost cookie authentication
> for use when communicating among VMs or containers.
> On the other hand, we might instead specify a TLS-based socket and
> authentication method.

### "Owned" connect points

> This section is sketch only,
> exploring ideas about how we might implement owned connections.
>
> An RPC client could have the ability to start an "owned" connection,
> in which it launches an external Arti RPC server process,
> with which only it can communicate,
> and which exits whenever the RPC client no longer needs it.
>
> This would likely be a third kind of connect point,
> likely looking for `arti` in the default search `$PATH`,
> with option to override the location of `arti`.
>
> It would likely work internally creating a socketpair,
> and telling the launched copy of arti to use its half
> of that socketpair alone for its connection.
>
> We'd likely need some way to control command-line options
> and configuration options.

> We do not plan to implement functionality for
> starting a shared system Arti on demand:
> we think that this does not belong in an RPC client code.

### "Embedded" connect points

> This section is a sketch only, to capture ideas and open issues.
>
> When we implement support for embedded Arti,
> the connect point format may involve
> using a pre-built socketpair,
> and giving one end of the socketpair to the Arti process.
>
> A connect point for such a case could be something like
> ```toml
> [connect]
> controlling_fd = 732
> ```
>
> (We might say "pre-established" instead of "connect", for strict accuracy.)

> Note/TODO: Embedded client operation is not yet completely specified
> here.  In particular, we have not yet decided:
>   - Whether it is an error to try to launch two embedded Arti instances
>     in the same process, or whether subsequent attempts give connections
>     to the existing embedded arti.
>   - Whether an embedded arti will need to have the ability to take
>     command line arguments to override its storage and cache defaults.
>   - Whether to have some special process for passing command line options
>     or configuration options to the embedded Arti.
>
> These issues will apply to owned arti instances as well.


### Example connect points

Here are some examples of connect points

```toml
[builtin]
builtin = "abort"
```

```toml
[connect]
socket = "unix:/var/run/arti/rpc_socket"
auth = "none"
```

```toml
[connect]
socket = "inet:[::1]:9191"
socket_canonical = "inet:[::1]:2020"

auth = { cookie = { path = "/home/user/.arti_rpc/cookie" } }
```

```toml
[connect]
socket = "inet:[::1]:9191"
socket_canonical = "inet:[::1]:2020"

[connect.auth.cookie]
path = "/home/user/.arti_rpc/cookie"
```

## RPC server behavior

An Arti RPC server uses connect points
to decide where to listen for incoming RPC connections.

Unlike an RPC client, an RPC server tries to listen using
_every_ configured connect point.
If any connect point fails, it treats the error as fatal,
and stops searching.

The RPC server also has an option `rpc.enabled`
that can be used to turn off RPC entirely.
If it is set to `false`, then the server doesn't listen on any RPC ports.

Connect points or their locations can be given in a
tabular option `rpc.listen`, taking a form something like:

```
[rpc]
enable = true   # (default)

[rpc.listen."my-connect"]
enable = true   # (default)
file = "/home/arti-rpc/arti-rpc-connect.toml"

[rpc.listen."other"]
enable = false
file = "/etc/arti-rpc/arti-rpc-connect.toml"

[rpc.listen."a-directory"]
dir = "/home/arti-rpc/rpc-connect.d/"
# Override configuration options on individual members
override = { "experimental.toml" : { "enable" : false } }
```

> These sections are given names so that the user
> can turn them on and off in later config files.

There is a pair of default entries in this table:

```
[rpc.listen."user-default"]
enable = true
dir = "${ARTI_LOCAL_DATA}/rpc/connect.d"

[rpc.listen."system-default"]
enable = false
dir = "/etc/arti-rpc/connect.d"
```

Finally, there is an option `[rpc.listen-default]`,
representing a verbatim lists of connect points.
Its default is
```
[rpc]
listen-default = [ "<USER_DEFAULT>" ]
```
(where `"<USER_DEFAULT>"` is replaced with the same `USER_DERFAUT`
value defined above in discussion of client default.)


The RPC server behaves as follows.

1. If `rpc.enabled` is false, the server binds to no RPC ports.
2. Otherwise, the server looks for the locations of connect files
   (or for the connect points themselves)
   among all enabled entries
   in the `rpc.listen` table in `arti.toml`,
   and tries to bind to each,
   treating all errors as fatal.
   (It does not attempt to load or validate connect files
   whose entries are disabled.)
3. If a fatal error did not occur,
   but no connect points were bound,
   the server uses the connect points in `rpc.listen-default`,
   treating all errors as fatal.

> The behavior above will, by default, capture the "user Arti" case,
> where an Arti process is running on behalf of a single user and shared
> by that user's applications.
>
> For the "system arti" case, where Arti is to be shared by many users,
> the integrator or sysadmin needs to specify an alternative connect points
> in Arti's configuration.  Our documentation should recommend the use
> of SYSTEM\_DEFAULT, or of storing a special connect point in
> the system default location
> (`/etc/arti-rpc/connect.d/` on Unix).
>
> We might also provide a command-line option
> to override _all_ relevant configuration defaults
> with ones that make more sense for a "system arti".
> This option would override both
> `rpc.listen."system-default".enable` and
> `rpc.listen-default`.
> See [#1710](https://gitlab.torproject.org/tpo/core/arti/-/issues/1710)
> for more information.


### Servers and privileged access

> This section is not going to be implemented in v0 of the protocol.

RPC servers can be configured to support privileged access.
This is done with a boolean option,
`rpc.listen.*.superuser`,
which will be `false` by default.

We might have a separate `rpc.enable_superuser` option
to turn off _all_ superuser access.

> Not all connect point types will necessarily be supported
> for superuser access.
> For example, we may institute a rule that cookie authentication
> is only permitted for superuser access
> on systems with meaningful filesystem restrictions.

> We _may_ later specify default superuser connect points
> or their locations.
> We do not currently plan to have any by default
> in our first releases.

### Servers and file permissions

> This section is not going to be implemented in v0 of the protocol.

We may need to alter our default `fs-mistrust` permissions
or file ownership options for the sockets and cookie files we create.
If we do so, we will add a new
`rpc.listen.*.fs_permissions`
sub-option, or something similar, to be determined.


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

RPC connect points can contain instructions to read and write files,
and possibly, in the future, perform other security-relevant actions.
RPC connect points (and paths to them)
should be handled the same way as other critical configuration.

> For example, a future connect point variant might
> specify a *program to execute*.

RPC connect points, and paths to connect files,
MUST ONLY be obtained from trusted sources
(such as environment variables, and trustworthy parts of the filesystem).

Arti RPC connect points from untrusted sources MUST NOT be used
(neither by RPC clients, nor by the Arti RPC server).
A client application MUST NOT allow software that it does not trust completely
to supply RPC connect points.

> For example, an Android app providing Tor services
> MUST NOT provide RPC connect points to other apps,
> since (per the Android security model)
> those other apps MUST NOT completely trust the Tor provider app.
>
> Allowing the Tor servce to supply the connect point
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
