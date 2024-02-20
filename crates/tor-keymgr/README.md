# tor-keymgr

Code to fetch, store, and update keys.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

### **Likely to change**

The APIs exposed by this crate (even without the `keymgr` feature)
are new and are likely to change rapidly.
We'll therefore often be making semver-breaking changes
(and will update the crate version accordingly).

## Key stores

The [`KeyMgr`] is an interface to one or more key stores. A key
store is a type that implements the [`Keystore`] trait.

The following key store implementations are provided:
* [`ArtiNativeKeystore`]: an on-disk store that stores keys in OpenSSH format.
  It does not currently support keys that have a passphrase. Passphrase support
  will be added in the future (see [#902]).
* (not yet implemented) C Tor key store: an on-disk store that is
  backwards-compatible with C Tor (new keys are stored in the format used by C
  Tor, and any existing keys are expected to be in this format too).

In the future we plan to also support HSM-based key stores.

## Key specifiers and key types

The [`Keystore`] APIs identify a particular instance of a key using a
[`KeySpecifier`] and a [`KeyType`].
This enables key stores to have multiple keys with the same role
(i.e. the same [`KeySpecifier::arti_path`]), but different key types (i.e.
different [`KeyType::arti_extension`]s).

A `KeySpecifier` identifies a group of equivalent keys, each of a different
type (algorithm). In the `ArtiNativeKeystore`, it is used to determine the
path of the key within the key store, minus the extension (the extension of
the key is derived from its `KeyType`). `KeySpecifier` implementers must
specify:
* the [`ArtiPath`] of the specifier: this serves
  as a unique identifier for a particular instance of a key, and is used by
  `ArtiNativeKeystore` to determine the path of a key on disk
* the [`CTorPath`] of the key: the location of the key in the C Tor key store
  (optional).

`KeyType` represents the type ("keypair", "public key") and
algorithm ("ed25519", "x25519") of a key
[`KeyType::arti_extension`] specifies what file extension keys of that type are
expected to have when stored in an `ArtiNativeKeystore`: [`ArtiNativeKeystore`]s
join the [`KeySpecifier::arti_path`] and [`KeyType::arti_extension`] to form the
path of the key on disk (relative to the root directory of the key store).

## Feature flags

### Additive features

* `keymgr` -- build with full key manager support. Disabling this
  feature causes `tor-keymgr` to export a no-op, placeholder implementation.

### Experimental and unstable features

 Note that the APIs enabled by these features are NOT covered by semantic
 versioning[^1] guarantees: we might break them or remove them between patch
 versions.

* (None at present)

[^1]: Remember, semantic versioning is what makes various `cargo`
features work reliably. To be explicit: if you want `cargo update`
to _only_ make safe changes, then you cannot enable these
features.

[#902]: https://gitlab.torproject.org/tpo/core/arti/-/issues/902
