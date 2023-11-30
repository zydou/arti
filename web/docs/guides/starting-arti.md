---
title: Starting Arti as a proxy
---

# Starting Arti as a proxy

After [compiling Arti](/guides/compiling-arti), it can be run as a SOCKS proxy on port `9150` by running the command:

```bash
target/release/arti proxy
```

Once Arti is running, you can configure your applications or browsers to use the `localhost:9150` SOCKS proxy.

#### Notes:

- Before running Arti, ensure that you have compiled it as described in [Compiling Arti](/guides/compiling-arti).
- The provided instructions assume that you have a working Rust development environment.
- Ensure that you are in the correct directory (`arti`) when running the `cargo` commands.

