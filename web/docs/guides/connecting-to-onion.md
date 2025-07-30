---
title: Connecting to Onion Services
---

# Connecting to an Onion Service with Arti

Arti supports connecting to [Tor Hidden Services](https://tb-manual.torproject.org/onion-services/), commonly known as Onion Services.

You can attempt to make a connection to a `.onion` service by running the command:

```bash
curl --socks5-hostname localhost:9150 https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/ | head | cat -v
```

