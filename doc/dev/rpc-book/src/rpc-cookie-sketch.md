# RPC cookie authentication

This is based on the Tor control port's cookie authentication mechanism.

It's meant for use over a connection to a TCP port on localhost.

We try to provide the property that if a client and a server successfully
complete this process, then each one knows that the other was able to read
a given secure cookie file on the filesystem.


## Preliminaries

Let `P` be the 32-byte string
"====== arti-rpc-cookie-v1 ======".

Let MAC(a,b,c,...) be TupleHash,
the Keccak-based cryptographic digest function
described in Section 5 of [NIST SP 800-185],
using the output length `L = 256 bits`,
and the customization string `S = "arti-rpc-cookie-v1"`

> NOTE: Do not substitute any other hash function without cryptographic
> analysis!  In particular, we rely on TupleHash(K,a,b,c,d,...)
> instantiating a proper message-authentication-code over a unique
> encoding of the tuple `(a,b,c,d,...)`.

The client and server begin by knowing the location of a "cookie file."
That file contains the 32-byte fixed string `P`, followed by a 32-byte secret
`cookie` generated by the server. The server generates this file at startup.
Before connecting, the client reads this file,
and determines the value of `cookie`.

> Both parties need to make sure that the file isn't writeable by any
> untrusted user.  This is out-of-scope for this document.

The RPC client treats failures to read a cookie file
the same as a failure to read a connect file.

> To recap those rules:
>
> If the client cannot read the cookie file because of `EACCESS` or `ENOENT`
> or local equivalent,
> then the client *declines* the connect point.
> If the client fails to read the cookie file for some other reason,
> then the client *aborts* its connection to RPC.

If the cookie file is malformed, the client also *aborts*.
(A cookie file is malformed if it does not begin with `P`,
or if it is not exactly 64 bytes long.)

If the RPC server cannot write the cookie file,
it is a fatal error regardless of the reason.

Strings are represented in UTF-8 without a trailing NUL byte.

[NIST SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

## The protocol

At the start of the process,
the client knows this value from the connect point:
  - `socket`: The address at which to connect to the server.

At the start of the process,
the client and server additionally know this value from the connect point:
  - `socket_canonical`:
     The address at which the server is actually listening.
     If absent, defaults to the value of `socket` from the connect point.

> Note that this protocol will only succeed
> if the value of `socket_canonical` seen by the client
> is exactly the same string as
> the value of `socket_canonical` seen by the server.

The client and server know this value from the cookie file:
  - `cookie`: The value of the cookie.

1. The client connects to the server at `socket`.

   The client generates a random 32-byte nonce `client_nonce`,
   and the server generates a random 32-byte nonce `server_nonce`.
   These nonces MUST NOT be reused.

2. The client sends `client_nonce`.

3. The server computes
   `server_mac = MAC(cookie, "Server", socket_canonical, client_nonce)`
   and sends (`server_mac`, `socket_canonical`, `server_nonce`).
   (See below for the encoding.)

4. The client computes `server_mac`,
   and verifies that its value matches the one
   provided by the server.  If it does not match, it aborts the protocol.
   If it does match, the client computes
   `client_mac = MAC(cookie, "Client", socket_canonincal, server_nonce)`,
   and sends `client_mac` to the server.

5. The server computes `client_mac`, and verifies that its value matches the one
   provided by the client.  If it does not match, this connection attempt aborts.
   Otherwise, the parties are authenticated.

## In Arti-RPC.

This protocol is selected from an RPC connect point as discussed
in `rpc-connect-sketch.md`.

The client's message in step 2 is sent by invoking the `auth:cookie_begin` method,
implemented on the connection object.
It expects a single `client_nonce` parameter.

The server's message in step 3 is embedded in the server's response to that
method, in a set of fields: `server_addr`, `server_mac`, and `server_nonce.`
Additionally, the response includes an object ID in a `cookie_auth` field
This object holds the in-progress authentication state, and can be used
for a single `auth:cookie_continue` command.

The client's message in step 4 is sent by invoking the
`auth:cookie_continue` method,
directed to the object ID received in the `cookie_auth` field.

All binary values are encoded as hexadecimal strings before sending in JSON.
