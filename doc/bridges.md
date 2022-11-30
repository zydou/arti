# Using bridges with Arti

This documentation will probably get folded somewhere else, and
should definitely get a quality improvement.  For now, I'm writing
it as a quick-and-dirty introduction to how to actually set up
bridges and pluggable transports with Arti.

This document assumes that you already know how to set up bridges
and pluggable transports with Tor.

## Configuring bridges

To add a bridge to arti, you can add a section like this to your to your
`arti.toml` configuration, or to a file in your `arti.d` configuration
directory.

```
[bridges]

enabled = true
bridges = [
  # These are just examples, and will not work!
  "Bridge 192.0.2.66:443 8C00000DFE0046ABCDFAD191144399CB520C29E8",
  "Bridge 192.0.2.78:9001 6078000DFE0046ABCDFAD191144399CB52FFFFF8",
]
```

By default, bridges are enabled when any bridges are listed, and
disabled when no bridges are listed.  You can adjust this behavior by
changing the value of `enabled` to "true" or "false".

## Configuring pluggable transports

To run with obfs4proxy, add this stanza to your `arti.toml`
configuration, or to a file in your `arti.d` configuration directory.

```
[[bridges.transports]]
protocols = ["obfs4"]
path = "/PATH/TO/obfs4proxy"
#arguments = ["-enableLogging", "-logLevel", "DEBUG"]
arguments = []
run_on_startup = false
```

To run with snowflake, add this stanza to your arti configuration:

```
[[bridges.transports]]
protocols = ["snowflake"]
path = "/PATH/TO/snowflake-client"
#arguments = ["-log-to-state-dir", "-log", "snowflake.log"]
arguments = []
run_on_startup = false
```

