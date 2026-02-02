---
title: CLI Reference
---

Once you've obtained an [arti binary](/guides/compiling-arti), you can use the Command Line Interface (CLI) to run various commands for configuration. 

The Arti CLI commands support a number [flags](#flags) that can be used to configure the behavior of the command.
If you are running Arti through `cargo`, the flags are specified using the format:

```bash
cargo run -p arti -- <subcommand> <flags>
```

Alternatively, if you have already compiled the binary, you can pass the flags directly to the `arti` command using:

```bash
target/debug/arti <subcommand> <flag>
```

### Subcommands

| Subcommand | Description |
| --- | --- |
| `help` | Print help information. |
| `proxy` | Run Arti in SOCKS proxy mode, proxying connections through the Tor network. |

### Flags

| Flag | Description |
| --- | --- |
|`-c`,`--config <FILE>` | Specify which config file(s) to read. Usually, Arti uses the default config. See the sample file, [`arti-config-example.toml`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti/src/arti-example-config.toml), to create your own configuration file.  |
| `--disable-fs-permission-checks` | Don't check permissions on the files in use. |
| `-h`, `--help` | Print help information. |
| `-l`, `--log-level` | Override the log level (usually one of 'trace', 'debug', 'info', 'warn', 'error'). |
| `-o <KEY=VALUE>` | Override config file parameters, using TOML-like syntax. |

### Usage Examples

For example, the following command is used to launch Arti in SOCKS proxy mode with the default settings. 

```bash
target/debug/arti proxy
```

To override the default settings, you can use the `-o` flag to specify the parameters you want to change. For example, the following command is used to launch Arti in SOCKS proxy mode with the default settings, but with the `proxy.socks_listen` parameter set to `9000`.

```bash
target/debug/arti proxy -o 'proxy.socks_listen = 9000'
```

This starts Arti in SOCKS proxy mode using default settings, listening on port 9000 instead of 9150.

### Configuration File

The Arti CLI uses a configuration file to specify the parameters for the Arti instance. The default configuration file is `arti.toml`. You can override the default configuration file using the `-c` flag.

You can create your own configuration file by copying the sample file and modifying the parameters as needed. See the sample file [`arti-config-example.toml`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti/src/arti-example-config.toml) to create your own configuration file.
