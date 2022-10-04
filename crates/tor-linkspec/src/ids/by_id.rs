//! Define a type for a set of HasRelayIds objects that can be looked up by any
//! of their keys.

use tor_basic_utils::n_key_set;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use crate::{HasRelayIds, RelayIdRef};

n_key_set! {
    /// A set of objects that can be accessed by relay identity.
    ///
    /// No more than one object in the set can have any given relay identity.
    ///
    /// # Invariants
    ///
    /// Every object in the set MUST have at least one recognized relay
    /// identity; if it does not, it cannot be inserted.
    ///
    /// This set may panic or give incorrect results if the values can change their
    /// keys through interior mutability.
    ///
    #[derive(Clone, Debug)]
    pub struct[H:HasRelayIds] ByRelayIds[H] for H
    {
        (Option) rsa: RsaIdentity { rsa_identity() },
        (Option) ed25519: Ed25519Identity { ed_identity() },
    }
}

impl<H: HasRelayIds> ByRelayIds<H> {
    /// Return the value in this set (if any) that has the key `key`.
    pub fn by_id<'a, T>(&self, key: T) -> Option<&H>
    where
        T: Into<RelayIdRef<'a>>,
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.by_ed25519(ed),
            RelayIdRef::Rsa(rsa) => self.by_rsa(rsa),
        }
    }

    /// Return the value in this set (if any) that has _all_ the relay IDs
    /// that `key` does.
    ///
    /// Return `None` if `key` has no relay IDs.
    pub fn by_all_ids<T>(&self, key: &T) -> Option<&H>
    where
        T: HasRelayIds,
    {
        let any_id = key.identities().next()?;
        self.by_id(any_id)
            .filter(|val| val.has_all_relay_ids_from(key))
    }
}

// TODO MSRV: Remove this `allow` once we no longer get a false positive
// for it on our MSRV.  1.56 is affected; 1.60 is not.
#[allow(unreachable_pub)]
pub use tor_basic_utils::n_key_set::Error as ByRelayIdsError;
