# Draft for `arti keys check-integrity` CLI tool


## Summary

The tool being discussed here takes inspiration from the `arti-keys-verify` proposed
in [dev/notes/state-management-cli.md](./state-management-cli.md?ref_type=heads#arti-keys-verify).
Like the original draft, the new tool will perform a validity check on a
specified store.

This new tool will include a `sweep` functionality for removing unrecognized entries,
unrecognized paths, invalid keys, and expired keys.

Conceptually, this command can be split into two different functionalities:

1. List all invalid keys in a keystore
2. Clean up the keystore by removing the identified invalid keys


## Possible designs

### Enhance `arti keys list` and add `arti keys sweep` (discarded)

The first possible design would be to split listing and cleaning into two separate
commands: the already existing `keys list`, and a new `keys sweep`.

With this design, `keys list` would gain the ability to detect expired and invalid
keys, along with optional filtering to show only valid or invalid keys/entries. This
would require introducing a `--verbose` flag.

Here is an example:

```bash
arti keys list -k arti
```

With this configuration, `list` will display the current default output of the
command.
With the following configuration:

```bash
arti keys list -k arti -v
```

`list` will internally extract the entries from the keystore, retrieve the actual
keys corresponding to valid keystore entries, verify the validity of those keys,
check their expiration dates against a consensus document, and display the detailed
results.

> Note: `list` at the moment doesn't display all invalid keys, but just recognized
> and unrecognized keystore entries, and unrecognized paths.

An optional flag `--filter <valid|invalid>` will filter out valid or invalid
keys/entries.

The command `keys sweep` will be added. It will be able to remove all the invalid keys
(unrecognized entries and paths, invalid keys, and expired keys) of a
specified keystore (currently only the default primary keystore), or of a specific
service, or of a specific client.

An example:

```bash
arti keys sweep -k arti
```


### Add `arti keys check-integrity`

The other possibility could be to have a new `keys check-integrity`. This would
include both the functionalities of listing and cleaning up.
Example:

```bash
keys check-integrity -k arti
```

This will list all invalid keys of the `arti` keystore.

```bash
keys check-integrity -k arti --sweep
```

This will list and remove all unrecognized items from the `arti` keystore, as well
as all the invalid or expired items.


### Considerations

The first implementation was discarded for the reasons discussed in this
[thread](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3126#note_3234420).

The optimal format for the output (of the chosen design) will be decided
during implementation, but it will closely resemble the output of the original
[draft](./state-management-cli.md?ref_type=heads&plain=1#L295).


## Steps

Here is a rough draft of the steps necessary to implement the chosen option:

- Extract keystore entries using `KeyMgr::{list|list_by_id}`.
- Store invalid entries (perhaps just their `RawEntryId`).
- Use valid entries to verify the integrity of the corresponding keys by leveraging
  the new method, `KeyMgr::integrity_check_entry` (name to be determined). Entries
  with an invalid corresponding key should be added to the previously stored invalid
  entries.
- Obtain a `NetDir`, and use `NetDir::hs_all_time_periods` to get a
  `Vec<HsDirParams>`. This will be used to assess the expiration date of valid
  keystore entries that have corresponding valid keys.
- Add expired entries to the list of invalid keystore entries.
- Display invalid entries. Eventually use `KeyMgr::remove_unchecked` to remove
  them, either interactively (prompt) or using a `batch` flag.


## Implementation details

The procedure for checking the expiration date is very similar to what happens
[here](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/tor-hsservice/src/keys.rs?ref_type=heads#L174).
In order to obtain the `tor_hscrypto::time::TimePeriod` of the entries, it is likely
that `tor_hsservice::keys::HsTimePeriodKeySpecifier` will need to be exposed, or
a higher-level API (higher than the CLI) that provides this information will need
to be built. In either case, similar to
[expire_publisher_keys](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/tor-hsservice/src/keys.rs?ref_type=heads#L216),
the specifiers for the keys that can be expired must be listed manually.

`KeyMgr::integrity_check_entry` will be a new method that checks the integrity of
the key corresponding to a keystore entry. It will function similarly to the public
`KeyMgr::get`* methods, but unlike those, it won't require a `K: ToEncodableKey`
generic type parameter. The `integrity_check_entry` method is necessary for the
reason discussed in this
[thread](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3126#note_3234286).
Internally, this function will call another new method, `Keystore::integrity_check_entry`,
which will implement the low-level logic on an individual `Keystore`, the specified
`Keystore` will be indicated by the `keystore_id` field of the `entry: &KeystoreEntry`
parameter. The `Keystore::integrity_check_entry` method will need to be implemented for
every `Keystore` implementor.

Below is a draft of what the methods will look like:

```rust
impl KeyMgr {
     // The return value still needs to be decided. One alternative could be
     // `Result<Result<()>>`, where the inner `Result` represents the outcome of
     // the integrity validation, and the outer `Result` represents a general
     // failure (e.g., I/O errors).
     #[cfg(feature = "..")]
     pub fn integrity_check_entry(&self, entry: &KeystoreEntry) -> Result<()> {
         // delegate to the Keystore::integrity_check_entry
     }
}
```

```rust
impl Keystore {
     #[cfg(feature = "..")]
     pub fn integrity_check_entry(
        &self,
        key_spec: &dyn KeySpecifier,
        item_type: &KeystoreItemType,
    ) -> Result<bool>;
}
```


## Additional considerations

Everything here is subject to change, from the low-level implementation to the
abstract high-level logic.
