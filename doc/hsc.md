# `arti hsc`

`arti hsc` is a command line utility for managing client keys. In the future, we
plan to extend it to support managing other types of state as well.

Like the other `arti` subcommands, it has an optional `--config` option for
specifying the TOML configuration file. Using the correct configuration file is
important, because the state and keys managed by `arti hsc` are relative to the
state directory, which you might have overridden in the configuration.

## `arti hsc get-key`

Client service discovery keys (previously known as "client authorization" keys)
can be generated and/or retrieved using the
`arti hsc get-key --onion-name <SVC>.onion` command.
By default `get-key` will generate a new keypair for use with `<SVC>.onion`,
if one does not already exist, and output its public part in the file specified
with the `--output` option. If such a keypair already exists, a new one will
**not** be generated.

```console
$ arti -c hsc.toml hsc get-key --key-type=service-discovery
>      --onion-name mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion
>      --output -
descriptor:x25519:RWWKYMW5EXDUZ2ESDDC7FQJCG6ROAR34LXNSTXFSY6JMQOWNDVNQ
```

See `arti hsc get-key --help` for more information.
