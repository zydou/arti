# `arti hss`

`arti hss` is a command line utility for managing onion service keys.
In the future, we plan to extend it to support managing other types of state as well.

Like the other `arti` subcommands, it has an optional `--config` option for
specifying the TOML configuration file. Using the correct configuration file is
important, because the state and keys managed by `arti hss` are relative to the
state directory, which you might have overridden in the configuration.

> Note: to use `arti hss` you will need to compile `arti` with the
> `onion-service-service` feature enabled.

## Displaying your .onion address

```ignore
$ arti --config hss.toml hss --nickname allium-cepa onion-address
wrxdvcaqpuzakbfww5sxs6r2uybczwijzfn2ezy2osaj7iox7kl7nhad.onion

```

## Migrating from C Tor to Arti

### Running Arti with your C Tor keys

Arti has experimental support for C Tor's key format.
This means you can configure Arti to use the identity key from the
`HiddenServiceDirectory` directory of your C Tor service.

> Note: this feature is only available in builds that have the experimental
> `onion-service-cli-extra` feature enabled.

For example:

```toml
[storage.keystore.ctor.services."allium-cepa"]

# This should be set to the `HiddenServiceDirectory` of your hidden service.
# Arti will read `HiddenServiceDirectory/hostname`
# and `HiddenServiceDirectory/private_key`.
# (Note: if your service is running in restricted discovery mode, you must also set the
# `[[onion_services."<the nickname of your svc>".restricted_discovery.key_dirs]]`
# to `HiddenServiceDirectory/client_keys`).
path = "/var/lib/tor/allium_cepa"

# The identifier of this keystore.
id = "foo"
```

Each C Tor keystore **must**:

  * have a unique identifier. It is an error to configure multiple keystores
    with the same ID.
  * have a corresponding arti hidden service configured in the
    `[onion_services]` section with the same nickname

### Migrating from C Tor

Arti supports importing C Tor onion service keys to Arti's keystore
using the experimental `arti hss ctor-migrate` command.

> Note: the `ctor-migrate` subcommand is only available in builds that
> have the experimental `onion-service-cli-extra` feature enabled.

`arti hss ctor-migrate` converts the identity key of a C Tor onion service
to the Arti native key format (OpenSSH key format), and copies it to Arti's keystore.

> ⚠️**WARNING** ⚠️
>
> `arti hss ctor-migrate` will **not** remove the migrated C Tor keys from disk.
> After running this command, the identity key of your
> service will exist both in its original location, and in the
> Arti native keystore. **You will need to manually remove one
> of the copies at the end of the migration** (the C Tor one, if
> you are confident you no longer want to run the service
> using C Tor, or the Arti one if you don't wish to switch to Arti)

To use this command, you will first need to configure Arti
with a C Tor keystore pointing to the `HiddenServiceDirectory`
of the onion service you wish to migrate, as described in
[Running Arti with your C Tor keys](#running-arti-with-your-c-tor-keys).
Once you are satisfied with the configuration, you can run the migration using:

```ignore
arti --config hss.toml hss --nickname allium-cepa ctor-migrate
```

If the service with the specified `--nickname` already has some keys in the Arti keystore,
they will be removed as part of the migration (by default, `ctor-migrate` prompts before removal,
but you can disable that behavior using `--batch`).

> ⚠️**WARNING** ⚠️
>
> To avoid data loss, `arti hss ctor-migrate` should only be run when
> no other process is accessing either keystore.
> So, you must shut down your hidden service while you do the migration.

> Note: in the future, we plan to support running `ctor-migrate`
> without having to configure a C Tor keystore in
> the TOML config (#2087)
