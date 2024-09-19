# `arti hsc`

`arti hsc` is a command line utility for managing client keys. In the future, we
plan to extend it to support managing other types of state as well.

Like the other `arti` subcommands, it has an optional `--config` option for
specifying the TOML configuration file. Using the correct configuration file is
important, because the state and keys managed by `arti hsc` are relative to the
state directory, which you might have overridden in the configuration.

## Generating a service discovery key

Client service discovery keys (previously known as "client authorization" keys)
can be generated and/or retrieved using the
`arti hsc key get --onion-name <SVC>.onion` command.
By default `key get` will generate a new keypair for use with `<SVC>.onion`,
if one does not already exist, and output its public part in the file specified
with the `--output` option. If such a keypair already exists, a new one will
**not** be generated.

```console
$ arti -c hsc.toml hsc key get --key-type=service-discovery
>      --onion-name mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion
>      --output -
descriptor:x25519:RWWKYMW5EXDUZ2ESDDC7FQJCG6ROAR34LXNSTXFSY6JMQOWNDVNQ
```

See `arti hsc key get --help` for more information.

## Rotating a service discovery key

Keys can be rotated with the `arti hsc key rotate` command.

To rotate a service discovery key:
```ignore
$ arti -c hsc.toml hsc key rotate
>      --onion-name mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion
>      --output -
rotate client restricted discovery key for mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion? (type YES or no): YES
descriptor:x25519:4E4B6CILWAAM2JFSVTOTCANCCUIMSOOSXZWONSR52ETXSTCKIYIA
```

> NOTE: if the client keystore already contains a restricted discovery keypair
> for the service, it will be overwritten. Otherwise, a new keypair is generated.

As key rotation is a destructive operation (the old key will be lost),
`arti hsc key rotate` will prompt you to confirm the operation.
If you wish to force removal, or to run this command non-interactively,
use the `-f` option, which disables the confirmation prompt.

See `arti hsc key rotate --help` for more information.

## Removing a service discovery key

Keys can be rotated with the `arti hsc key remove` command.

To remove a service discovery key:
```ignore
$ arti -c hsc.toml hsc key remove
>      --onion-name mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion
remove client restricted discovery key for mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion? (type YES or no): YES
descriptor:x25519:4E4B6CILWAAM2JFSVTOTCANCCUIMSOOSXZWONSR52ETXSTCKIYIA
```

As with `hsc key rotate`, you can disable the confirmation prompt and force
removal using the `-f` option.

See `arti hsc key remove --help` for more information.
