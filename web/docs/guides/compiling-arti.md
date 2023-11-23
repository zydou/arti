---
title: Compiling Arti
---

# Compiling Arti

Arti can act as a SOCKS(Socket Secure) proxy that uses the Tor network. To use Arti as a proxy, it is required that you obtain a Rust development environment and build it yourself as there are no official binaries yet. 

To start building and compiling Arti, clone the Arti repository using git and navigate to the directory by running the commands:

```bash
# clone the repo
git clone https://gitlab.torproject.org/tpo/core/arti.git

# navigate to the directory
cd arti
```

To build the Arti binary, compile the code and generate the executable by running the command:

```bash
cargo build -p arti --release
```

The `--release` flag is used to build the release version with optimisations. After the build process is complete, you can find the compiled Arti binary in `target/release/arti`. To enable additional features when building Arti, see our [compile time features](https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/arti?ref_type=heads#compile-time-features).

To run Arti as a SOCKS proxy on port `9150`, execute the following command:

```bash
./target/release/arti proxy
```

With Arti running, you can configure your applications to use the SOCKS proxy at `localhost:9150`. This is useful for routing traffic through the Tor network.

#### Notes:

- The provided instructions assume that you have a working [Rust development environment](https://www.rust-lang.org/learn/get-started).
- Ensure that you are in the correct directory (`arti`) when running the `cargo` commands.

