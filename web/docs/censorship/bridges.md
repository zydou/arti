---
title: Bridges
---

# Using bridges with Arti

A bridge is a specific kind of Tor relay that is not included in the open Tor directory. The Tor network depends on a public directory of relays to assist users in locating nodes via which they can route their traffic in order to maintain anonymity. However, in some cases, access to this open directory may be restricted or under monitoring, making it challenging for users to connect to the Tor network.

Bridges enable users to access the Tor network while preserving their anonymity and privacy. They serve as gateways into the Tor network, but their addresses are not made available to the general public. This makes it difficult for censors or network administrators to block access to the Tor network, as they cannot simply block the unknown public IP addresses.

This guide explains how to configure bridges with Arti but assumes that you already know how to [set them up with Tor](https://tb-manual.torproject.org/bridges/).

## Configuring bridges

To add a bridge to arti, you can add a section like this to your to your [`arti.toml` configuration](/guides/cli-reference#configuration-file), or to a file in your `arti.d` configuration directory.

```
[bridges]

enabled = true
bridges = [
  # These are just examples, and will not work!
  "Bridge 192.0.2.66:443 8C00000DFE0046ABCDFAD191144399CB520C29E8",
  "Bridge 192.0.2.78:9001 6078000DFE0046ABCDFAD191144399CB52FFFFF8",
]
```

By default, bridges are enabled when any bridges are listed, and disabled when no bridges are listed.  You can adjust this behavior by changing the value of `enabled` to "true" or "false".
