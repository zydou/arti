# tor-cert

Code for generating x509 certificates.

## Overview


For the most part, Tor doesn't actually need x509 certificates.
We only keep them around for two purposes:

1. The `RSA_ID_X509` certificate is provided in a CERTS cell,
   and used to transmit the RSA identity key.
2. TLS requires the responder to have an x509 certificate.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

See also [`tor-cert`] and [`tor-netdoc::doc::authcert`]
for other kinds of certificates implemented by Tor.


License: MIT OR Apache-2.0

[`tor-cert`]: https://docs.rs/tor-cert/latest/tor_cert/
[`tor-netdoc::doc::authcert`]: https://docs.rs/tor-netdoc/latest/tor_netdoc/doc/authcert/index.html

