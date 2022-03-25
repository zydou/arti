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

  Abolished `TorClientConfig::get_circmgr_config`.
  Abolished `TorClientConfig::get_dirmgr_config`.

arti:

  Provide library crate with unstable API.

tor-llcrypto:

  new-api: Added RsaIdentity::from\_hex().
  new-api: Ed25519Identity implements PartialOrd.

arti-client:

  api-break (experimental only): changed circmgr() and dirmgr() to return
  &Arc, not Arc.

  api-break: isolation completely revised

tor-circmgr:

  api-break: The fallbacks case of DirInfo now wants a slice of references to
  fallbacks.

  api-break: Some error types have changed to include peer info.

tor-dirclient:
  api-break: refactored Error type.

tor-dirmgr:
  new-api: DirMgrConfig object now has accessors.
  DirMgrCfg: totally changed, builder abolished.
  Authority, NetworkConfig: removed several accessors for these config elements.
  api-break: DirEvent is now in tor-netdir instead

tor-circmgr:
  CircMgrCfg: totally changed, builder abolished.

  api-break: isolation completely revised

  api-break: config must now implement AsRef<FallbackList>

tor-netdoc:

  new-api (experimental only): Can modify the set of relays in an unverified
  consensus.

  api-break: changed the return type of GenericRouterStatus::version()

tor-netdir:

   api-break: moved FallbackDir to guardmgr.

tor-guardmgr:

   new-api: moved FallbackDir from netdir.

   api-break: FallbackDir required in constructor.

tor-proto:
  new-api: ClientCirc path accessors.

tor-protover:
  new-api: Protocols now implements Eq, PartialEq, and Hash.

tor-proto:
  api-break: OutboundClientHandshake::connect() now takes now_fn.

  new-api: New Error::HandshakeCertsExpired.

tor-error:
  new-api: New ErrorKind::ClockSkew.

tor-cell:
  new-api: Netinfo message now has a timestamp() accessor.

tor-basic-utils:

  Remove `humantime_serde_option` module.
  (Use `humantime_serde::option` instead.)

tor-rtcompt:

  api-break: Runtime require an additional supertrait UdpProvider
