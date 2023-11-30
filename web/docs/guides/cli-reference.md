---
title: CLI Reference
---

Once you've obtained an [arti binary](/guides/compiling-arti), you may use the Command Line Interface (CLI) to run various commands for configuration. 

Once you obtain an arti binary, you can use it as a Command Line Interface (CLI).

The Arti CLI commands support a number [flags](#cli-flag-options) that can be used to configure the behavior of the command.
If you are running Arti through `cargo`, the flags are specified using the format:

```bash
cargo run -p arti --all-features <subcommand> -- <flags>
```

Alternatively, if you have already compiled the binary, you can pass the flags directly to the `arti` command using:

```bash
target/debug/arti <subcommand> <flag>
```

### CLI Subcommands

| Subcommand | Description |
| --- | --- |
| `help` | Print help information. |
| `proxy` | Run Arti in SOCKS proxy mode, proxying connections through the Tor network. |

### CLI flag Options

| Flag | Description |
| --- | --- |
|`-c`,`--config <FILE>` | Specify which config file(s) to read. Usually, Arti uses the default config. See the sample file, [`arti-config-example.toml`](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/arti/src/arti-example-config.toml), to create your own configuration file.  |
| `--disable-fs-permission-checks` | Don't check permissions on the files in use. |
| `-h`, `--help` | Print help information. |
| `-l`, `--log-level` | Override the log level (usually one of 'trace', 'debug', 'info', 'warn', 'error'). |
| `-o <KEY=VALUE>` | Override config file parameters, using TOML-like syntax. |


### CLI Usage Examples

For instance, to simply run Arti as in SOCKS proxy mode using default settings the following command is run. 

```bash
target/debug/arti proxy
```


