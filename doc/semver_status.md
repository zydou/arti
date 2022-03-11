# Semver tracking

This is a helpful file that we use for checking which crates will have
breaking or nonbreaking API changes in the next release of Arti.

For each crate, please write "BREAKING" if there is an API change that counts
as breaking in semver, and "MODIFIED" if there is a backward-compatible API
change.

You can change from MODIFIED to BREAKING, but never from BREAKING to
MODIFIED.

You don't need to list details; this isn't the changelog.

Don't document other changes in this file.

We can delete older sections here after we bump the releases.


## Since Arti 0.1.0

arti-client, arti-config, tor-circmgr, tor-dirmgr:

  Drop conversion from FooConfig to FooConfigBuilder for many Foo.
  Further change in this area is expected.

  Drop impl Deserialize for ArtiConfig.

arti-client:

  Replace ArtiClientBuilder's methods for individual elements of TorClientConfigBuilder
  with an accessor `.tor()` to get `&mut TorClientConfigBuilder`.

arti:

  Provide library crate with unstable API.

tor-llcrypto:

  new-api: Added RsaIdentity::from\_hex().

arti-client:

  api-break (experimental only): changed circmgr() and dirmgr() to return
  &Arc, not Arc.

tor-dirmgr:
  new-api: DirMgrConfig object now has accessors.


tor-netdoc:

  new-api (experimental only): Can modify the set of relays in an unverified
  consensus.

  api-break: changed the return type of GenericRouterStatus::version()

tor-protover:
  new-api: Protocols now implements Eq, PartialEq, and Hash.

tor-basic-utils:

  Remove `humantime_serde_option` module.
  (Use `humantime_serde::option` instead.)

tor-rtcompt:

  api-break: Runtime require an additional supertrait UdpProvider
