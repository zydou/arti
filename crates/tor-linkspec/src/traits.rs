//! Declare traits to be implemented by types that describe a place
//! that Tor can connect to, directly or indirectly.

use std::{iter::FusedIterator, net::SocketAddr};
use tor_llcrypto::pk;

use crate::{RelayIdRef, RelayIdType, RelayIdTypeIter};

/// An object containing information about a relay's identity keys.
pub trait HasRelayIds {
    /// Return the identity of this relay whose type is `key_type`, or None if
    /// the relay has no such identity.
    ///
    /// (Currently all relays have all recognized identity types, but we might
    /// implement or deprecate an identity type in the future.)
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Rsa => Some(self.rsa_identity().into()),
            RelayIdType::Ed25519 => Some(self.ed_identity().into()),
        }
    }
    /// Return an iterator over all of the identities held by this object.
    fn identities(&self) -> RelayIdIter<'_, Self> {
        RelayIdIter {
            info: self,
            next_key: RelayIdType::all_types(),
        }
    }

    /// Return the ed25519 identity for this relay.
    fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity;
    /// Return the RSA identity for this relay.
    fn rsa_identity(&self) -> &pk::rsa::RsaIdentity;
    /// Return the ed25519 identity key for this relay, if it is valid.
    ///
    /// This can be costly.
    fn ed_identity_key(&self) -> Option<pk::ed25519::PublicKey> {
        self.ed_identity().try_into().ok()
    }

    /// Return true if this object has exactly the same relay IDs as `other`.
    //
    // TODO: Once we make it so particular identity key types are optional, we
    // should add a note saying that this function is usually not what you want
    // for many cases, since you might want to know "could this be the same
    // relay" vs "is this definitely the same relay."
    fn same_relay_ids<T: HasRelayIds>(&self, other: &T) -> bool {
        self.ed_identity() == other.ed_identity() && self.rsa_identity() == other.rsa_identity()
    }
}

/// An iterator over all of the relay identities held by a [`HasRelayIds`]
#[derive(Clone)]
pub struct RelayIdIter<'a, T: HasRelayIds + ?Sized> {
    /// The object holding the keys
    info: &'a T,
    /// The next key type to yield
    next_key: RelayIdTypeIter,
}

impl<'a, T: HasRelayIds + ?Sized> Iterator for RelayIdIter<'a, T> {
    type Item = RelayIdRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        for key_type in &mut self.next_key {
            if let Some(key) = self.info.identity(key_type) {
                return Some(key);
            }
        }
        None
    }
}
// RelayIdIter is fused since next_key is fused.
impl<'a, T: HasRelayIds + ?Sized> FusedIterator for RelayIdIter<'a, T> {}

/// An object that represents a host on the network with known IP addresses.
pub trait HasAddrs {
    /// Return the addresses at which you can connect to this server.
    // TODO: This is a questionable API. I'd rather return an iterator
    // of addresses or references to addresses, but both of those options
    // make defining the right associated types rather tricky.
    fn addrs(&self) -> &[SocketAddr];
}

/// Information about a Tor relay used to connect to it.
///
/// Anything that implements 'ChanTarget' can be used as the
/// identity of a relay for the purposes of launching a new
/// channel.
pub trait ChanTarget: HasRelayIds + HasAddrs {}

/// Information about a Tor relay used to extend a circuit to it.
///
/// Anything that implements 'CircTarget' can be used as the
/// identity of a relay for the purposes of extending a circuit.
pub trait CircTarget: ChanTarget {
    /// Return a new vector of link specifiers for this relay.
    // TODO: This is a questionable API. I'd rather return an iterator
    // of link specifiers, but that's not so easy to do, since it seems
    // doing so correctly would require default associated types.
    fn linkspecs(&self) -> Vec<crate::LinkSpec> {
        let mut result: Vec<_> = self.identities().map(|id| id.to_owned().into()).collect();
        for addr in self.addrs().iter() {
            result.push(addr.into());
        }
        result
    }
    /// Return the ntor onion key for this relay
    fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey;
    /// Return the subprotocols implemented by this relay.
    fn protovers(&self) -> &tor_protover::Protocols;
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hex_literal::hex;
    use std::net::IpAddr;
    use tor_llcrypto::pk;

    struct Example {
        addrs: Vec<SocketAddr>,
        ed_id: pk::ed25519::Ed25519Identity,
        rsa_id: pk::rsa::RsaIdentity,
        ntor: pk::curve25519::PublicKey,
        pv: tor_protover::Protocols,
    }
    impl HasAddrs for Example {
        fn addrs(&self) -> &[SocketAddr] {
            &self.addrs[..]
        }
    }
    impl HasRelayIds for Example {
        fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity {
            &self.ed_id
        }
        fn rsa_identity(&self) -> &pk::rsa::RsaIdentity {
            &self.rsa_id
        }
    }
    impl ChanTarget for Example {}
    impl CircTarget for Example {
        fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey {
            &self.ntor
        }
        fn protovers(&self) -> &tor_protover::Protocols {
            &self.pv
        }
    }

    /// Return an `Example` object, for use in tests below.
    fn example() -> Example {
        Example {
            addrs: vec![
                "127.0.0.1:99".parse::<SocketAddr>().unwrap(),
                "[::1]:909".parse::<SocketAddr>().unwrap(),
            ],
            ed_id: pk::ed25519::PublicKey::from_bytes(&hex!(
                "fc51cd8e6218a1a38da47ed00230f058
                 0816ed13ba3303ac5deb911548908025"
            ))
            .unwrap()
            .into(),
            rsa_id: pk::rsa::RsaIdentity::from_bytes(&hex!(
                "1234567890abcdef12341234567890abcdef1234"
            ))
            .unwrap(),
            ntor: pk::curve25519::PublicKey::from(hex!(
                "e6db6867583030db3594c1a424b15f7c
                 726624ec26b3353b10a903a6d0ab1c4c"
            )),
            pv: tor_protover::Protocols::default(),
        }
    }

    #[test]
    fn test_linkspecs() {
        let ex = example();
        let specs = ex.linkspecs();
        assert_eq!(4, specs.len());

        use crate::ls::LinkSpec;
        assert_eq!(
            specs[0],
            LinkSpec::Ed25519Id(
                pk::ed25519::PublicKey::from_bytes(&hex!(
                    "fc51cd8e6218a1a38da47ed00230f058
                     0816ed13ba3303ac5deb911548908025"
                ))
                .unwrap()
                .into()
            )
        );
        assert_eq!(
            specs[1],
            LinkSpec::RsaId(
                pk::rsa::RsaIdentity::from_bytes(&hex!("1234567890abcdef12341234567890abcdef1234"))
                    .unwrap()
            )
        );
        assert_eq!(
            specs[2],
            LinkSpec::OrPort("127.0.0.1".parse::<IpAddr>().unwrap(), 99)
        );
        assert_eq!(
            specs[3],
            LinkSpec::OrPort("::1".parse::<IpAddr>().unwrap(), 909)
        );
    }

    #[test]
    fn key_accessor() {
        let ex = example();
        // We can get the ed25519 key if it's valid...
        let key = ex.ed_identity_key().unwrap();
        assert_eq!(&pk::ed25519::Ed25519Identity::from(key), ex.ed_identity());

        // Now try an invalid example.
        let a = hex!("6d616e79737472696e677361726565646b6579736e6f74746869736f6e654091");
        let ex = Example {
            ed_id: pk::ed25519::Ed25519Identity::from_bytes(&a).unwrap(),
            ..ex
        };
        let key = ex.ed_identity_key();
        assert!(key.is_none());
    }
}
