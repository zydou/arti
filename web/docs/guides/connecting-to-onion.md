---
title: Connecting to Onion Services
---

# Connecting to an Onion Service with Arti

Arti has the support to connect to [Tor Hidden Services](https://tb-manual.torproject.org/onion-services/), commonly known as Onion Services. However, it is important to note that this feature is presently deactivated by default. The reason for this default setting is the current lack of "vanguards", a feature employed by Tor to mitigate guard discovery attacks over time, within Arti.

Therefore, it is recommended that you continue with using C Tor if your usage involves creating numerous connections to onion services, or if the Tor protocol implementation can enable an attacker to manipulate the number of onion service connections you make (for example, when using Arti's SOCKS support through a web browser like Tor Browser).

As part of our ongoing efforts to enhance security, we have plans to address this limitation and subsequently enable `.onion` connections as the default setting in the future.

In the meantime, there are two ways to enable it if you want to try it out.

### Through the command line

You can enable `.onion` connections with Arti by running the command:

```bash
target/debug/arti -o address_filter.allow_onion_addrs=true proxy
```

### By editing your config file

In your configuration file, locate the section `[address_filter]`, and set the `allow_onion_addrs` parameter value to `true` using `allow_onion_addrs = true`.

To test that you’ve configured it correctly, you can attempt to make a connection to a `.onion` service by running the command:

```bash
curl --socks5-hostname localhost:9150 https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/ | head | cat -v
```

