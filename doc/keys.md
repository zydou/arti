# `arti keys`

`arti keys` is a command line utility for managing keystores and their content. In the
future, we will extend `arti keys` with additional functionality, for example multiple formatting
options for the output.

Like the other `arti` subcommands, it has an optional `--config` option for
specifying the TOML configuration file. Using the correct configuration file is
important, because the keystores that `arti keys` interacts with are relative to the
state directory, which you might have overridden in the configuration.

> `arti keys` is an experimental subcommand.
> To use it, you will need to compile `arti` with the experimental `onion-service-cli-extra` feature.

## Listing keystores

`arti keys list-keystores` lists all the configured keystores:

```
$ arti -c keys.toml keys list-keystores
 Keystores:

 - "arti"


```


## Listing the content of keystores

The command `arti keys list` is used for listing the content of keystores.

By default the command displays the content of all the keystores. If the
flag `--keystore-id` is provided, only the content of the specified
keystore will be displayed.

This command provides a way of listing both recognized and unrecognized entries.

- Recognized: keys that present a valid path.
- Unrecognized: keys that are in a valid location but do not present a
valid filename.
- Unrecognized paths: filesystem objects that should not be in the state directory.

Some of the information displayed by `keys list` can be used as input for other
commands. For instance: "Location", is the raw identifier of the entry; and
"Keystore ID", the identifier, of the keystore. These can be used together
with `arti keys-raw remove-by-id`.

Example usage:

<details>
<summary>With `-k`:</summary>

```ignore
$ arti -c keys.toml keys list -k arti
 ===== Keystore entries =====


 Keystore ID: arti
 Role: ks_hsc_desc_enc
 Summary: Descriptor decryption key
 KeystoreItemType: X25519StaticKeypair
 Location: client/mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad/ks_hsc_desc_enc.x25519_private
 Extra info:
 - hs_id: mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Unrecognized path: herba-spontanea/ks_hs_id.ed25519_expanded_private

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Role: ks_hs_id
 Summary: Long-term identity keypair
 KeystoreItemType: Ed25519ExpandedKeypair
 Location: hss/allium-cepa/ks_hs_id.ed25519_expanded_private
 Extra info:
 - nickname: allium-cepa

 --------------------------------------------------------------------------------

 Unrecognized entry
 Keystore ID: arti
 Location: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private
 Error: Key has invalid path: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private

 --------------------------------------------------------------------------------


```
</details>

<details>
<summary>Default behavior</summary>

```ignore
$ arti -c keys.toml keys list
 ===== Keystore entries =====


 Keystore ID: arti
 Role: ks_hsc_desc_enc
 Summary: Descriptor decryption key
 KeystoreItemType: X25519StaticKeypair
 Location: client/mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad/ks_hsc_desc_enc.x25519_private
 Extra info:
 - hs_id: mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Unrecognized path: herba-spontanea/ks_hs_id.ed25519_expanded_private

 --------------------------------------------------------------------------------

 Keystore ID: arti
 Role: ks_hs_id
 Summary: Long-term identity keypair
 KeystoreItemType: Ed25519ExpandedKeypair
 Location: hss/allium-cepa/ks_hs_id.ed25519_expanded_private
 Extra info:
 - nickname: allium-cepa

 --------------------------------------------------------------------------------

 Unrecognized entry
 Keystore ID: arti
 Location: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private
 Error: Key has invalid path: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private

 --------------------------------------------------------------------------------

 CTor service key
 Hidden service nickname: allium-cepa
 Keystore ID: ctor
 KeystoreItemType: Ed25519ExpandedKeypair
 Location: hs_ed25519_secret_key

 --------------------------------------------------------------------------------

 Unrecognized entry
 Keystore ID: ctor
 Location: hostname
 Error: Key hostname is malformed

 --------------------------------------------------------------------------------

 CTor service key
 Hidden service nickname: allium-cepa
 Keystore ID: ctor
 KeystoreItemType: Ed25519PublicKey
 Location: hs_ed25519_public_key

 --------------------------------------------------------------------------------

```
</details>

> The `hostname` file of a CTor keystore is represented as an unrecognized entry.


## Validate the integrity of keystores

The command `arti keys check-integrity` performs a validity check on keystores.
It detects and reports unrecognized entries and paths, as well as malformed or
expired keys. Such entries can be removed if requested.

By default, the command displays invalid entries from all keystores. If the
`--keystore-id` flag is provided, only the invalid elements of the specified
keystore are displayed. When the `--sweep` flag is used, you will be
prompted to remove the detected invalid elements. If the `--batch` flag
is used in conjunction with `-s`, invalid elements are removed without a prompt.

The output displays invalid entries grouped by keystores and indicates whether no
invalid entries are found in a given keystore.

Some keys are time-bound and may expire. Expired entries correspond to keys
associated with time periods (obtained from a consensus document) for which the
owning service is not publishing descriptors. An internet connection is required
to retrieve the consensus document and verify the validity of these keys.

Example usage:

<details>
<summary>Default behavior</summary>

```ignore
$ arti keys check-integrity
Found problems in keystores: arti, ctor.

Invalid keystore entries in keystore arti:

hss/allium-cepa/Ks_hs_blind_id+20241_1440_43200.ed25519_expanded_private
	Error: Key has invalid path: hss/allium-cepa/Ks_hs_blind_id+20241_1440_43200.ed25519_expanded_private
hss/allium-cepa/ks_hs_id.ed25519_expanded_private
	Error: Failed to parse OpenSSH with type Ed25519ExpandedKeypair
asdf/allium-cepa/ks_hs_blind_id+20242_1440_43200.ed25519_expanded_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_blind_id+20242_1440_43200
asdf/allium-cepa/ipts/k_sid+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_sid+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae
asdf/allium-cepa/ipts/k_sid+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_sid+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53
asdf/allium-cepa/ipts/k_hss_ntor+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de.x25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_hss_ntor+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de
asdf/allium-cepa/ipts/k_sid+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_sid+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de
asdf/allium-cepa/ipts/k_hss_ntor+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae.x25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_hss_ntor+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae
asdf/allium-cepa/ipts/k_hss_ntor+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53.x25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_hss_ntor+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53
asdf/allium-cepa/ks_hs_blind_id+20241_1440_43200.ed25519_expanded_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_blind_id+20241_1440_43200
asdf/allium-cepa/ks_hs_desc_sign+20242_1440_43200.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_desc_sign+20242_1440_43200
asdf/allium-cepa/ks_hs_desc_sign+20241_1440_43200.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_desc_sign+20241_1440_43200
asdf/allium-cepa/ks_hs_id.ed25519_expanded_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_id
hss/allium-cepa/ks_hs_desc_sign+20300_1440_43200.ed25519_private
	Error: The entry is expired.
hss/allium-cepa/ks_hs_desc_sign+20299_1440_43200.ed25519_private
	Error: The entry is expired.
hss/allium-cepa/ks_hs_blind_id+20300_1440_43200.ed25519_expanded_private
	Error: The entry is expired.
hss/allium-cepa/ks_hs_blind_id+20299_1440_43200.ed25519_expanded_private
	Error: The entry is expired.

Invalid keystore entries in keystore ctor:

hostname
	Error: Key hostname is malformed
```
</details>

<details>
<summary>With `-k` and `-s`</summary>

```ignore
$ arti keys check-integrity -k arti -s
Found problems in keystore: arti.

Invalid keystore entries in keystore arti:

hss/allium-cepa/Ks_hs_blind_id+20241_1440_43200.ed25519_expanded_private
	Error: Key has invalid path: hss/allium-cepa/Ks_hs_blind_id+20241_1440_43200.ed25519_expanded_private
hss/allium-cepa/ks_hs_id.ed25519_expanded_private
	Error: Failed to parse OpenSSH with type Ed25519ExpandedKeypair
asdf/allium-cepa/ks_hs_blind_id+20242_1440_43200.ed25519_expanded_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_blind_id+20242_1440_43200
asdf/allium-cepa/ipts/k_sid+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_sid+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae
asdf/allium-cepa/ipts/k_sid+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_sid+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53
asdf/allium-cepa/ipts/k_hss_ntor+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de.x25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_hss_ntor+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de
asdf/allium-cepa/ipts/k_sid+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_sid+bf2c5fb26446e00877757a126fcdf48fa460021497d46aac1afa78ef380003de
asdf/allium-cepa/ipts/k_hss_ntor+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae.x25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_hss_ntor+4a487c4a6e5b666a64e748848146e621e2a096f3e18f110696e42d16e11374ae
asdf/allium-cepa/ipts/k_hss_ntor+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53.x25519_private
	Error: Unrecognized path: asdf/allium-cepa/ipts/k_hss_ntor+6674c2d98191e632ff20c030e6f73ec4c7fec10e17d63d86a4f974e7da18ac53
asdf/allium-cepa/ks_hs_blind_id+20241_1440_43200.ed25519_expanded_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_blind_id+20241_1440_43200
asdf/allium-cepa/ks_hs_desc_sign+20242_1440_43200.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_desc_sign+20242_1440_43200
asdf/allium-cepa/ks_hs_desc_sign+20241_1440_43200.ed25519_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_desc_sign+20241_1440_43200
asdf/allium-cepa/ks_hs_id.ed25519_expanded_private
	Error: Unrecognized path: asdf/allium-cepa/ks_hs_id
hss/allium-cepa/ks_hs_desc_sign+20300_1440_43200.ed25519_private
	Error: The entry is expired.
hss/allium-cepa/ks_hs_desc_sign+20299_1440_43200.ed25519_private
	Error: The entry is expired.
hss/allium-cepa/ks_hs_blind_id+20300_1440_43200.ed25519_expanded_private
	Error: The entry is expired.
hss/allium-cepa/ks_hs_blind_id+20299_1440_43200.ed25519_expanded_private
	Error: The entry is expired.
Remove all invalid entries? (type yes or no):
```
</details>

<details>
<summary>If no invalid entry is encountered</summary>

```ignore
$ arti keys check-integrity -k arti
arti: OK.
```
</details>

> With this and other interactive commands, logs can be intrusive and disrupt the
> tool's workflow. In such cases, it is recommended to disable logging, either in
> the configuration file or using these flags:
>
> ```bash
> arti -o logging.console="off" -o logging.files='[{path = "file.log", filter = "info"}]' keys check-integrity
> ```
