# `arti keys`

`arti keys` is a command line utility for listing and displaying keystores and their content. In the
future, we will extend `arti keys` with additional functionality, for example multiple formatting
options for the output.

Like the other `arti` subcommands, it has an optional `--config` option for
specifying the TOML configuration file. Using the correct configuration file is
important, because the keystores that `arti keys` interacts with are relative to the
state directory, which you might have overridden in the configuration.

> `arti keys` is an experimental subcommand.
> To use it, you will need to compile `arti` with the experimental `onion-service-cli-extra` feature.

## Listing keystores

`arti keys list-keystores` allows the user to list all the available keystores in the state
directory (i.e.: `~/.local/share/arti` on Linux platforms)

```
$ arti -c keys.toml keys list-keystores
 Keystores:

 - "arti"


```


## Listing the content of keystores

The command `arti keys list` is used for listing the content of keystores.

By default the command displays the content of all the keystores. If the
flag `-k` (`--keystore-id`) is provided, only the content of the specified
keystore will be displayed.

This command displays three possible types of entry:

- Recognized: keys that present a valid path.
- Unrecognized: keys that are in a valid location but do not present a
valid filename.
- Unrecognized paths: filesystem objects that should not be in the state directory.

Example usage:

With `-k`:
```ignore
$ arti -c keys.toml keys list -k arti
 ===== Keystore entries =====


 Keystore ID: arti
 Role: ks_hsc_desc_enc
 Summary: Descriptor decryption key
 KeystoreItemType: X25519StaticKeypair
 Extra info:
 - hs_id: mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion

 --------------------------------------------------------------------------------

 Unrecognized entry
 Location: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private
 Error: Key has invalid path: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Role: ks_hs_id
 Summary: Long-term identity keypair
 KeystoreItemType: Ed25519ExpandedKeypair
 Extra info:
 - nickname: allium-cepa

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Unrecognized path: herba-spontanea/ks_hs_id

 --------------------------------------------------------------------------------


```

Default behavior:
```ignore
$ arti -c keys.toml keys list
 ===== Keystore entries =====


 Keystore ID: arti
 Role: ks_hsc_desc_enc
 Summary: Descriptor decryption key
 KeystoreItemType: X25519StaticKeypair
 Extra info:
 - hs_id: mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion

 --------------------------------------------------------------------------------

 Unrecognized entry
 Location: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private
 Error: Key has invalid path: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Role: ks_hs_id
 Summary: Long-term identity keypair
 KeystoreItemType: Ed25519ExpandedKeypair
 Extra info:
 - nickname: allium-cepa

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Unrecognized path: herba-spontanea/ks_hs_id

 --------------------------------------------------------------------------------


```
