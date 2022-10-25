//! Code for working with bridge descriptors.
//!
//! Here we need to keep track of which bridge descriptors we need, and inform
//! the directory manager of them.

use std::collections::HashMap;
use std::sync::Arc;

use crate::bridge::BridgeConfig;
use dyn_clone::DynClone;
use futures::stream::BoxStream;
use tor_error::{HasKind, HasRetryTime};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
use tor_netdoc::doc::routerdesc::RouterDesc;

/// A router descriptor that can be used to build circuits through a bridge.
///
/// These descriptors are fetched from the bridges themselves, and used in
/// conjunction with configured bridge information and ppluggable transports to
/// contact bridges and build circuits through them.
#[derive(Clone, Debug)]
pub struct BridgeDesc {
    /// The inner descriptor.
    ///
    /// NOTE: This is wrapped in an `Arc<>` because we expect to pass BridgeDesc
    /// around a bit and clone it frequently.  If that doesn't actually happen,
    /// we can remove the Arc here.
    desc: Arc<RouterDesc>,
}

impl AsRef<RouterDesc> for BridgeDesc {
    fn as_ref(&self) -> &RouterDesc {
        self.desc.as_ref()
    }
}

impl BridgeDesc {
    /// Construct a new BridgeDesc from `desc`.
    ///
    /// The provided `desc` must be a descriptor retrieved from the bridge
    /// itself.
    pub fn new(desc: Arc<RouterDesc>) -> Self {
        Self { desc }
    }
}

impl tor_linkspec::HasRelayIdsLegacy for BridgeDesc {
    fn ed_identity(&self) -> &Ed25519Identity {
        self.desc.ed_identity()
    }

    fn rsa_identity(&self) -> &RsaIdentity {
        self.desc.rsa_identity()
    }
}

/// This is analogous to NetDirProvider.
///
/// TODO pt-client: improve documentation.
pub trait BridgeDescProvider {
    /// Return the current set of bridge descriptors.
    fn bridges(&self) -> Arc<BridgeDescList>;

    /// Return a stream that gets a notification when the set of bridge
    /// descriptors has changed.
    fn events(&self) -> BoxStream<'static, BridgeDescEvent>;

    /// Change the set of bridges that we want to download descriptors for.
    ///
    /// Bridges outside of this set will not have their descriptors updated,
    /// and will not be revealed in the BridgeDescList.
    //
    // Possibly requiring a slice of owned Arc<BridgeConfig> here will involve too much copying.
    // But this isn't on the fast path, we hope.
    fn set_bridges(&self, bridges: &[Arc<BridgeConfig>]);
}

/// An event describing a change in a `BridgeDescList`.
///
/// Currently changes are always reported as `BridgeDescEvent::SomethingChanged`.
///
/// In the future, as an optimisation, more fine-grained information may be provided.
/// Unrecognized variants should be handled the same way as `SomethingChanged`.
/// (So right now, it is not necessary to match on the variant at all.)
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BridgeDescEvent {
    /// Some change occurred to the set of descriptors
    ///
    /// The return value from [`bridges()`](BridgeDescProvider::bridges)
    /// may have changed.
    ///
    /// The nature of the change is not specified; it might affect multiple descriptors,
    /// and include multiple different kinds of change.
    ///
    /// This event may also be generated spuriously, if nothing has changed,
    /// but this will usually be avoided for performance reasons.
    SomethingChanged,
}

/// An error caused while fetching bridge descriptors
///
/// Note that when this appears in `BridgeDescList`, as returned by `BridgeDescManager`,
/// the fact that this is `HasRetryTime` does *not* mean the caller should retry.
/// Retries will be handled by the `BridgeDescManager`.
/// The `HasRetryTime` impl can be used as a guide to
/// whether the situation is likely to improve soon.
///
/// Does *not* include the information about which bridge we were trying to
/// get a descriptor for.
pub trait BridgeDescError:
    std::error::Error + DynClone + HasKind + HasRetryTime + Send + Sync + 'static
{
}

dyn_clone::clone_trait_object!(BridgeDescError);

/// A set of bridge descriptors, managed and modified by a BridgeDescProvider.
pub type BridgeDescList = HashMap<Arc<BridgeConfig>, Result<BridgeDesc, Box<dyn BridgeDescError>>>;
