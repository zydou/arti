---
title: Sample Code
---

# Examples

The following are sample projects built with Arti.

- [**Download Manager**][download-manager] is a small download manager prototype which can download Tor Browser using Arti. This demonstrates how to make TLS-encrypted HTTP requests over the Tor network.

- [**Pt-proxy**][pt-proxy] provides an interface to run the obfs4 pluggable transport in a standalone manner, ie, instead of using obfs4 to connect to the Tor network, we can use it to connect to the Internet directly.

- [**DNS resolver**][dns-resolver] uses Tor to make a DNS over TCP request for a hostname, and get IP addresses back.

- [**Connection checker**][connection-checker] attempts to check connectivity to the Tor network through a variety of ways.

[download-manager]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/examples/download-manager
[pt-proxy]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/examples/gsoc2023/pt-proxy
[dns-resolver]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/examples/gsoc2023/dns-resolver
[connection-checker]: https://gitlab.torproject.org/tpo/core/arti/-/tree/main/examples/gsoc2023/connection-checker
