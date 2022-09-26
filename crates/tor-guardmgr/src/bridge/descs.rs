//! Code for working with bridge descriptors.
//!
//! Here we need to keep track of which bridge descriptors we need, and inform
//! the directory manager of them.

// TODO pt-client: remove these "allow"s.
#![allow(clippy::missing_panics_doc)]
#![allow(dead_code, unused_variables, clippy::needless_pass_by_value)]

use std::sync::Arc;

use futures::stream::BoxStream;
use tor_linkspec::{OwnedChanTarget, RelayId, RelayIds};

// TODO pt-client: I think we may want another layer of abstraction between
// RouterDesc and BridgeDesc, to implement e.g. CircTarget for RouterDesc.
// Likely it should contain an Arc<RouterDesc>.
use tor_netdoc::doc::routerdesc::RouterDesc as BridgeDesc;

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
    fn set_bridges(&self, bridges: &[OwnedChanTarget]);
}

/// An event describing a change in a `BridgeDescList`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BridgeDescEvent {
    /// A new descriptor has arrived
    //
    // TODO: (Should we do anything to indicate which one? If so, we
    // won't be able to use a flag-based publisher.)
    NewDesc,
}

/// A set of bridge descriptors, managed and modified by a BridgeDescProvider.
#[derive(Clone, Debug)]
pub struct BridgeDescList {
    /// The known bridges.
    ///
    /// TODO pt-client: This is almost certainly the wrong data structure; some
    /// kind of ID-based hashmap is likelier to be right.
    ///
    /// TODO pt-client: Maybe we should have an intermediary struct between
    /// RouterDescriptors and "usable bridge", as we have for `Relay`.
    bridges: Vec<BridgeDesc>,
}

impl BridgeDescList {
    /// Return the bridge descriptor, if any, for the given `RelayId`.
    pub fn by_id(&self, id: &RelayId) -> Option<&BridgeDesc> {
        todo!() // TODO pt-client: implement.
    }

    /// Return the bridge descriptor, if any, that has all of the given `RelayIds`.
    pub fn by_ids(&self, id: &RelayIds) -> Option<&BridgeDesc> {
        todo!() // TODO pt-client: implement.
    }

    /// Return an iterator over every bridge descriptor in this list.
    ///
    /// No bridge descriptors will be returned more than once, and no more than
    /// one descriptor will be returned for any given `RelayId`.
    pub fn bridges(&self) -> impl Iterator<Item = &BridgeDesc> {
        todo!(); // TODO pt-client: implement.
        #[allow(unreachable_code)]
        [].iter()
    }

    /// Insert `desc` into this list of bridges.
    ///
    /// Replace every already-existing descriptor that shares any identity with
    /// `desc`.
    pub fn insert(&mut self, desc: BridgeDesc) {
        todo!() // TODO pt-client: implement.
    }

    /// Drop every member of this list for which `func` returns false.
    pub fn retain<F>(&mut self, func: F)
    where
        F: FnMut(&BridgeDesc) -> bool,
    {
        todo!() // TODO pt-client: implement.
    }
}
