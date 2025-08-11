---
title: Connecting to Onion Services
---

# Connecting to an Onion Service with Arti

Arti supports connecting to [Tor Hidden Services](https://tb-manual.torproject.org/onion-services/), commonly known as Onion Services.

You can attempt to make a connection to a `.onion` service by running the command:

```bash
curl --socks5-hostname localhost:9150 http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion | head | cat -v
```

