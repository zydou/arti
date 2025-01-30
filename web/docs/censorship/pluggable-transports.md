---
title: Pluggable Transports
---

Traditional Tor traffic can be identified, which makes it vulnerable to blocking attempts. [Pluggable transports](https://tb-manual.torproject.org/circumvention/) are intended to circumvent censorship and make it easier for users to use the Tor network in locations where it might be restricted or blocked. They obfuscate or transform Tor traffic to make it appear as something else, making it more difficult for censors to identify and block it. 

This guide explains how to configure pluggable transports with Arti. Though, it assumes that you already know how to [set them up with Tor](https://tb-manual.torproject.org/circumvention/).

## Configuring pluggable transports

To run with obfs4proxy, add the following block of code to your [`arti.toml` configuration](/guides/cli-reference#configuration-file), or to a file in your `arti.d` configuration directory.

```yaml

[[bridges.transports]]
protocols = ["obfs4"]
path = "/PATH/TO/obfs4proxy"
#arguments = ["-enableLogging", "-logLevel", "DEBUG"]
arguments = []
run_on_startup = false
```

To run with snowflake, add this to your arti configuration:

```yaml
[[bridges.transports]]
protocols = ["snowflake"]
path = "/PATH/TO/snowflake-client"
#arguments = ["-log-to-state-dir", "-log", "snowflake.log"]
arguments = []
run_on_startup = false
```
