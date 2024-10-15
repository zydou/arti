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

> Note: These names aren't final!  Please help me refine them.

The `arti_rpc_connect()` API will have additional options:
 - `connect_search_path` — To override the default search path for connect string files.
 - `use_embedded` — To support an internal, embedded copy of arti.
 - `force_connect_string` — To force a specific connect string. (not recommended)
 - `force_connect_string_file` — To force a specific connect string
   file. (not recommended. Mutually exclusive with `force_connect_string`.)

The `arti_rpc_connect()` function will support environment variables:
 - `ARTI_RPC_CONNECT_PATH` — To override the search path for connect string files.
 - `ARTI_RPC_FORCE_SYSTEM_ARTI` — To force use of a system Arti,
   even when an embedded Arti is present.

When specifying a filename, we'll use syntax similar to
[`tor_config::CfgPath`].

When specifying a set of paths as an environment variable,
we'll use colon-separated paths on Unix,
and semicolon-separated paths on Windows.

The precedence order for connect strings is as follows:

- The value of `force_connect_string` if present.  (Note A)
- The value of `force_connect_string_file` if present. (Note A)
- An internal copy of Arti, if present and `use_embeded` is set,
  and if `ARTI_RPC_FORCE_SYSTEM_ARTI` is not set.  (Note A)
- Each element of the search path in order.
  The search path is defined to be the first one of these options that is set:
    - The `ARTI_RPC_CONNECT_PATH` environment variable.
    - The `connect_search_path` option.
    - The default search path.
- A default connect string.

The default search path is:
  - `${ARTI_LOCAL_DATA}/rpc/arti-rpc-connect.json`.  (Note B)
  - `/etc/arti-rpc/arti-rpc-connect.json` (unix and mac only)

> Note A: If any of the options marked with "Note A" above
> is attempted but fails,
> then `rpc_connect()` exits without trying any subsequent options.

> Note B: `$ARTI_LOCAL_DATA` above expands to:
>  - `$XDG_DATA_HOME/arti/` on Unix if  `$XDG_DATA_HOME` is set.
>  - `$HOME/.local/arti/` on Unix otherwise.
>  - `$HOME/Library/Application Support/org.torproject.arti` on MacOS.
>  - `{FOLDERID_LocalAppData}/arti/` on Windows.
>    (This is typically `\Users\<USERNAME>\AppData\Local\arti`.)

> Note C: The library should detect whether it is running in a setuid
> environment, and refuse to connect if so.
> (Nice-to-have but not necessary to implement in the first version.)

When processing elements from a search path,
the `arti_rpc_connect()` function has limited tolerance for failures.
Specifically, we *tolerate* these failures if we encounter them in the search
path, and continue to the next element of the search path:

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

We *do not tolerate* these failures;
`arti_rpc_connect()` returns immediately if any of these are encountered.

 - A connect string file is present, but cannot be parsed
   (either because it isn't JSON, or because it represents a recognized
   type of connect string with invalid options).
 - A connect string file is present, but its permissions
   (or the permissions on its parent directory, etc)
   indicate that it is writable by untrusted users.
 - A connect string file is present,
   but we cannot read it due to an error other than `EACCES`, `ENOENT`,
   etc.


## Interpreting connect strings.

The connect string is a JSON object with these members.
(Unrecognized members should be ignored.)

- `connect`: A connect object, described below. (Required.)

A connect object is an JSON object with a single name/value pair.
The name indicates the type of connection and authentication to make.
The value is in turn JSON object specific to the name.

We describe two types of connection:

- `inherent:unix` - Connect to Arti RPC via an AF_UNIX socket,
  and authenticate by proving ability to connect to that socket.
- `cookie:tcp-localhost` - Connect to Arti RPC via a localhost TCP socket,
  and authenticate by proving the ability to read a given filename.

### `inherent:unix`

The members of the associated object are:

- `socket` — A path to the unix socket on the filesystem.

An example connect string of this type is:

```json
{
    "arti-rpc-connect-string" : "arti-rpc-2024",
    "connect" : {
       "inherent:unix" : {
          "socket" : "/home/username/.local/run/arti/SOCKET"
       }
    }
}
```

### `cookie:tcp-localhost`

The members of the associated object are:

- `socket` - The IP address and port of the listening socket.
  The IP address MUST be `127.0.0.1` or `[::1]`.
- `cookie-path` - The location of a secret cookie file on disk.
  Arti writes a secret to this file; during the authentication,
  the application and arti both prove that they know this secret.

An example connect string of this type is:

```json
{
    "arti-rpc-connect-string" : "arti-rpc-2024",
    "connect" : {
       "cookie:tcp-localhost" : {
          "socket" : "[::1]:9191",
          "cookie-path" : "/home/username/local/run/arti/rpc-cookie"
       }
    }
}
```

The actual authentication protocol will be described elsewhere.

### Default connect strings

> Note: These aren't final, but we _do_ need to specify what the
> defaults actually are.

The default connect string on Unix is:

```json
{
    "arti-rpc-connect-string" : "arti-rpc-2024",
    "connect" : {
       "inherent:unix" : {
          "socket" : "$HOME/.local/run/arti/SOCKET"
       }
    }
}
```

The default connect string on OSX is:

```json
{
    "arti-rpc-connect-string" : "arti-rpc-2024",
    "connect" : {
       "inherent:unix" : {
          "socket" : "$HOME/Library/Application Support/org.torproject.arti/run"
       }
    }
}
```

The default connect string on Windows is:

```json
{
    "arti-rpc-connect-string" : "arti-rpc-2024",
    "connect" : {
       "cookie:tcp-localhost" : {
          "socket" : "[::1]:9191",
          "cookie-path" : "/Users/<USERNAME>/AppData/Local/arti/rpc/rpc-cookie
       }
    }
}
```

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

