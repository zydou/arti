# tor-cert

Implementation for Tor certificates

## Overview

The `tor-cert` crate implements the binary certificate types
documented in Tor's cert-spec.txt, which are used when
authenticating Tor channels.  (Eventually, support for onion service
certificate support will get added too.)

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

There are other types of certificate used by Tor as well, and they
are implemented in other places.  In particular, see
[`tor-netdoc::doc::authcert`] for the certificate types used by
authorities in the directory protocol.

### Design notes

The `tor-cert` code is in its own separate crate because it is
required by several other higher-level crates that do not depend
upon each other.  For example, [`tor-netdoc`] parses encoded
certificates from router descriptors, while [`tor-proto`] uses
certificates when authenticating relays.

## Examples

Parsing, validating, and inspecting a certificate:

```rust
use base64ct::{Base64, Encoding as _};
use tor_cert::*;
use tor_checkable::*;
// Taken from a random relay on the Tor network.
let cert_base64 =
 "AQQABrntAThPWJ4nFH1L77Ar+emd4GPXZTPUYzIwmR2H6Zod5TvXAQAgBAC+vzqh
  VFO1SGATubxcrZzrsNr+8hrsdZtyGg/Dde/TqaY1FNbeMqtAPMziWOd6txzShER4
  qc/haDk5V45Qfk6kjcKw+k7cPwyJeu+UF/azdoqcszHRnUHRXpiPzudPoA4=";
// Remove the whitespace, so base64 doesn't choke on it.
let cert_base64: String = cert_base64.split_whitespace().collect();
// Decode the base64.
let cert_bin = Base64::decode_vec(&cert_base64).unwrap();

// Decode the cert and check its signature.
let cert = Ed25519Cert::decode(&cert_bin).unwrap()
    .check_key(None).unwrap()
    .check_signature().unwrap()
    .dangerously_assume_timely();
let signed_key = cert.subject_key();
```

License: MIT OR Apache-2.0

[`tor-netdoc`]: https://docs.rs/tor-netdoc/
[`tor-netdoc::doc::authcert`]: https://docs.rs/tor-netdoc/latest/tor_netdoc/doc/authcert/index.html
[`tor-proto`]: https://docs.rs/tor-proto/
