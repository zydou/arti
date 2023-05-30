# tor-keymgr

Code to fetch, store, and update keys.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

### **UNSTABLE**

The APIs exposed by this crate are experimental and not covered by semver
guarantees.

## Key stores

The [`KeyMgr`] is an interface to one or more key stores. The key
stores are types that implement the [`KeyStore`] trait.

This crate provides the following key store implementations:
* Arti key store: an on-disk store that stores keys in OpenSSH format.
* (not yet implemented) C Tor key store: an on-disk store that is
  backwards-compatible with C Tor (new keys are stored in the format used by C
  Tor, and any existing keys are expected to be in this format too).

In the future we plan to also support HSM-based key stores.

## Key specifiers and key types

The [`KeyStore`] APIs expect a "key specifier" (specified for each supported key
type via the [`KeySpecifier`] trait), and a [`KeyType`].

A "key specifier" identifies a group of equivalent keys, each of a different
type (algorithm). It is used to determine the path of the key within the key
store (minus the extension).

[`KeyType`] represents the type of a key (e.g. "Ed25519 keypair").
[`KeyType::arti_extension`] specifies what file extension keys of that type are
expected to have (when stored in an Arti store).

The [`KeySpecifier::arti_path`] and [`KeyType::arti_extension`] are joined
to form the path of the key on disk (relative to the root dir of the key store).
This enables the key stores to have multiple keys with the same role (i.e. the
same `KeySpecifier::arti_path`), but different key types (i.e. different
`KeyType::arti_extension`s).

`KeySpecifier` implementers must specify:
* `arti_path`: the location of the key in the Arti key store. This also serves
  as a unique identifier for a particular instance of a key.
* `ctor_path`: the location of the key in the C Tor key store (optional).

TODO hs: write more comprehensive documentation when the API is a bit more
stable
