# `arti hsc`

`arti hsc` is a command line utility for managing client keys. In the future, we
plan to extend it to support managing other types of state as well.

Like the other `arti` subcommands, it has an optional `--config` option for
specifying the TOML configuration file. Using the correct configuration file is
important, because the state and keys managed by `arti hsc` are relative to the
state directory, which you might have overridden in the configuration.

> `arti hsc` is an experimental subcommand.
> To use it, you will need to compile `arti` with the experimental `hsc` feature

## Generating a service discovery key

Client service discovery keys (previously known as "client authorization" keys)
can be generated and/or retrieved using the `arti hsc key get` command.

`key get` prompts the user for an onion address (`<SVC>.onion`). If no keypair
exists for that service, it will first be generated. It then outputs the public
part of that service's key to the file specified with the --output option.

```ignore
$ arti -c hsc.toml hsc key get --output -
Enter an onion address: mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion
descriptor:x25519:RWWKYMW5EXDUZ2ESDDC7FQJCG6ROAR34LXNSTXFSY6JMQOWNDVNQ

```

If you are running this command non-interactively, you can suppress the prompt
with `--batch`:

```ignore
$ echo "mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion" | arti -c hsc.toml hsc key get --output - --batch
descriptor:x25519:RWWKYMW5EXDUZ2ESDDC7FQJCG6ROAR34LXNSTXFSY6JMQOWNDVNQ
```

> Note: the public part of the generated keypair must be shared with the
> service, and the service must be configured to allow the client that owns it
> to discover its introduction points. The caller is responsible for sharing the
> public key with the hidden service.

See `arti hsc key get --help` for more information.

## Rotating a service discovery key

Keys can be rotated with the `arti hsc key rotate` command.

To rotate a service discovery key:
```ignore
$ arti -c hsc.toml hsc key rotate --output -
Enter an onion address: mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion
rotate client restricted discovery key for mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion? (type YES or no): YES
descriptor:x25519:4E4B6CILWAAM2JFSVTOTCANCCUIMSOOSXZWONSR52ETXSTCKIYIA
```

> Note: if the client keystore already contains a restricted discovery keypair
> for the service, it will be overwritten. Otherwise, a new keypair is generated.

As key rotation is a destructive operation (the old key will be lost),
`arti hsc key rotate` will prompt you to confirm the operation.
If you wish to force removal, or to run this command non-interactively,
use the `-f` option, which disables the confirmation prompt.

> Note: as with `arti gsc key get`, the public part of the new keypair
> must be shared with the service

See `arti hsc key rotate --help` for more information.

## Removing a service discovery key

Keys can be rotated with the `arti hsc key remove` command.

To remove a service discovery key:
```ignore
$ arti -c hsc.toml hsc key remove
Enter an onion address: mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion
remove client restricted discovery key for mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion? (type YES or no): YES
```

As with `hsc key rotate`, you can disable the confirmation prompt and force
removal using the `-f` option.

See `arti hsc key remove --help` for more information.

## Migrating from C Tor to Arti

Arti supports importing C Tor client restricted discovery keys
(formerly known as ["client authorization keys"])
to Arti's keystore using the experimental `arti hsc ctor-migrate` command.

> Note: this feature is only available in builds that have the experimental
> `onion-service-cli-extra` feature enabled.

This command converts restricted discovery keys to the Arti native key format
(OpenSSH key format), and copies them to Arti's keystore.

> ⚠️**WARNING** ⚠️
>
> `arti hsc ctor-migrate` will **not** remove the migrated C Tor keys from disk.
> After running this command, the discovery keys of your client
> will exist both in its original location, and in the Arti native keystore.
> **You will need to manually remove one  set of keys at the end of the migration**
> (the C Tor ones, if you are confident you no longer want to use C Tor
> as an onion service client, or the Arti ones if you don't wish to switch to Arti)

To use this command, you will first need to configure Arti with a C Tor keystore
pointing to the `ClientOnionAuthDir` of the client you wish to migrate:

```toml
[[storage.keystore.ctor.clients]]

# The identifier of this keystore.  (Ie, the local nickname
# used to refer to this keystore in the rest of your config.)
id = "ctor-client"

# This should be set to the `ClientOnionAuthDir` of your client.
# If Arti is configured to run as a client (i.e. if it runs in SOCKS proxy mode),
# it will read the client restricted discovery keys from this path.
#
# The key files are expected to have the `.auth_private` extension,
# and their content **must** be of the form:
# `<56-char-onion-addr-without-.onion-part>:descriptor:x25519:<x25519 private key in base32>`.
#
# Malformed files, and files that don't have the `.auth_private` extension, will be ignored.
path = "/path/to/ctor_keystore"
```

Each C Tor keystore **must** have a unique identifier.
It is an error to configure multiple keystores with the same ID.

Once you are satisfied with the configuration, you can run the migration using:

```ignore
$ arti -c hsc.toml hsc ctor-migrate --from ctor-client
```

Alternatively, you can pass the C Tor configuration as an argument using the `-o` flag:

```ignore
$ arti hsc -o storage.keystore.ctor.clients='[{id = "ctor-client", path = "/path/to/ctor_keystore"}]' ctor-migrate --from ctor-client
```

If your Arti client already has some keys for the onion services
you are migrating discovery keys for,
they will be removed as part of the migration
(by default, `ctor-migrate` prompts before removal,
but you can disable that behavior using `--batch`).

> ⚠️**WARNING** ⚠️
>
> To avoid data loss, `arti hsc ctor-migrate` should only be run when
> no other process is accessing either keystore.
> So, you must shut down your client while you do the migration.

["client authorization keys"]: https://community.torproject.org/onion-services/advanced/client-auth/
