//! Declare traits to be implemented by types that describe a place
//! that Tor can connect to, directly or indirectly.

use std::net::SocketAddr;
use tor_llcrypto::pk;

/// An object containing information about a relay's identity keys.
pub trait HasRelayIds {
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
}

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
        let mut result = vec![(*self.ed_identity()).into(), (*self.rsa_identity()).into()];
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
