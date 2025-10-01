
# Tor Browser downloader

Downloads the Tor Browser using multiple tor connections.
We use [HTTP Range header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests) to request specific ranges of data.

> [!WARNING]
> **Notice for MacOS users:** This example uses `native-tls` which on MacOS might fail to perform a TLS handshake due to a known bug.
> This will be fixed once `security-framework` 3.5.1 is used by `native-tls`. View issue [#2117](https://gitlab.torproject.org/tpo/core/arti/-/issues/2117) for more details.
