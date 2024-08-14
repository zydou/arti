# Moving high-level KeyMgr APIs out of `TorClient`

`TorClient` has recently grown some extra, non-client functionality, which
exists mainly for implementing the `hsc` subcommand:
  * `TorClient::get_service_discovery_key`
  * `TorClient::generate_service_discovery_key`

These functions don't really belong in `TorClient`, but we currently have no
better place to put them.

Since `arti hsc` will soon need to be extended with new key/state management
functionality, it's time to find a new place for its underlying APIs
(otherwise we'll end up cluttering `TorClient` with even more APIs that don't
belong there!).

## Motivation

To call `TorClient::{get_service_discovery_key,
generate_service_discovery_key}`, you need to create a `TorClient`, but
neither of these functions actually uses any client functionality (they don't
connect to the Tor network). Having to build a `TorClient` is not only inconvenient,
but can also fail in surprising ways: any client (bootstrapped or
unbootstrapped) will try to initialize its `DirMgr`, so if you run two `arti
hsc` commands with the same config (and therefore the same cache directory) at
the same time, you will run into problems (usually because of the concurrent
access to the sqlite store). See #1497 for more details.

## Proposed `TorClient` changes

The `get_service_discovery_key`, `generate_service_discovery_key` functions are
essentially just porcelain keymgr APIs for handling client keys, so they could be
moved to a new public `ClientKeyMgr` type:

```rust
// arti-client/src/keymgr_client.rs

/// Type providing porcelain key management APIs.
#[derive(Debug, From, Clone)]
pub struct ClientKeyMgr(Arc<KeyMgr>);

impl ClientKeyMgr {
    /// Create a [`ClientKeyMgr`] using the specified configuration.
    ///
    /// Returns `Ok(None)` if keystore use is disabled.
    pub fn new(config: &TorClientConfig) -> StdResult<Option<Self>, ErrorDetail> {
        // This will contain the TorClient::create_keymgr() impl
        // (with minor modifications)
        ...
    }

    // This will only be used internally by TorClient.
    pub(crate) fn keymgr(&self) -> &Arc<KeyMgr> {
        &self.0
    }

    // Moved from TorClient
    #[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
    pub fn generate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        ...
    }

    // Moved from TorClient
    #[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
    pub fn get_service_discovery_key(
        &self,
        hsid: HsId,
    ) -> crate::Result<Option<HsClientDescEncKey>> {
        ...
    }
}
```

This change would enable us to remove the `get_service_discovery_key`,
`generate_service_discovery_key` functions from `TorClient`, so instead of
having to build a full `TorClient`, the `hsc` subcommand implementation will
only need to construct a `ClientKeyMgr`.

The `TorClient::create_keymgr` `KeyMgr` constructor will be moved to
`ClientKeyMgr::new`, and `TorClient` will contain a `ClientKeyMgr` instead of a
raw `KeyMgr` (but it will still be able to access the underlying `KeyMgr` via
`ClientKeyMgr::keymgr()`).

## `OnionService::onion_name`

If we move the key/state management APIs out of `TorClient`, it would only make
sense to make a similar change to `OnionService`, wrapping `KeyMgr` in a new
`ServiceKeyMgr` type and moving the implementation of `OnionService::onion_name`
to `ServiceKeyMgr::onion_name` (we will keep the `OnionService::onion_name`
convenience function and have it delegate to `ServiceKeyMgr::onion_name`). Any
new service key management functions (e.g. for managing services that have an
offline hsid) would then be added to `ServiceKeyMgr`.

(Within the same process, `ServiceKeyMgr` and `ClientKeyMgr` are just views over
the same `KeyMgr`, with different high-level APIs. Alternatively, they could
just be one and the same `FooHighLevelKeyMgr` type).

## Alternatives

A more future-proof idea might be to add a more general-purpose
`TorClientThatIsntRunning` (name TBD) type for accessing the keystore *and*
other on-disk state. Initially,  its only methods will be
`generate_service_discovery_key`, `get_service_discovery_key` (we can always
expose other operations on the on-disk storage later, when/if the need arises).

Like `TorClient`, `TorClientThatIsntRunning` will be created by
`TorClientBuilder` (TODO: decide whether to allow turning a
`TorClientThatIsntRunning` into a running `TorClient`).
