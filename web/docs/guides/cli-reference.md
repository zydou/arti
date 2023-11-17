---
title: CLI Reference
---

Once you have successfully compiled Arti, you can execute various commands through the Command Line Interface (CLI) for configuration purposes. 

To utilize the Arti CLI commands alongside specific flags, there are two main approaches available: using the `cargo` package manager or running the compiled binary directly.

When using `cargo`, you can run the command:

```bash
cargo run -p arti --all-features -- <flag>
```

Alternatively, if you've already compiled the binary, you can directly run the Arti CLI command:

```bash
target/debug/arti <flag>
```

### CLI flag Options

| Flag | Description |
| --- | --- |
|`-c`,`--config <FILE>` | Specify which config file(s) to read. Usually, Arti uses the default config. See the sample file, [`arti-config-example.toml`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti/src/arti-example-config.toml), to create your own configuration file.  |
| `--disable-fs-permission-checks` | Don't check permissions on the files in use. |
| `-h`, `--help` | Print help information. |
| `-l`, `--log-level` | Override the log level (usually one of 'trace', 'debug', 'info', 'warn', 'error'). |
| `-o <KEY=VALUE>` | Override config file parameters, using TOML-like syntax. |
| `proxy` | Run Arti in SOCKS proxy mode, proxying connections through the Tor network. |
