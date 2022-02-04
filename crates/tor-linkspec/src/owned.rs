//! Owned variants of [`ChanTarget`] and [`CircTarget`].

use std::fmt::{self, Display};
use std::net::SocketAddr;
use tor_llcrypto::pk;

use crate::{ChanTarget, CircTarget};

/// OwnedChanTarget is a summary of a [`ChanTarget`] that owns all of its
/// members.
#[derive(Debug, Clone)]
pub struct OwnedChanTarget {
    /// Copy of the addresses from the underlying ChanTarget.
    addrs: Vec<SocketAddr>,
    /// Copy of the ed25519 id from the underlying ChanTarget.
    ed_identity: pk::ed25519::Ed25519Identity,
    /// Copy of the rsa id from the underlying ChanTarget.
    rsa_identity: pk::rsa::RsaIdentity,
}

impl ChanTarget for OwnedChanTarget {
    fn addrs(&self) -> &[SocketAddr] {
        &self.addrs[..]
    }
    fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity {
        &self.ed_identity
    }
    fn rsa_identity(&self) -> &pk::rsa::RsaIdentity {
        &self.rsa_identity
    }
}

impl OwnedChanTarget {
    /// Construct a new OwnedChanTarget from its parts.
    // TODO: Put this function behind a feature.
    pub fn new(
        addrs: Vec<SocketAddr>,
        ed_identity: pk::ed25519::Ed25519Identity,
        rsa_identity: pk::rsa::RsaIdentity,
    ) -> Self {
        Self {
            addrs,
            ed_identity,
            rsa_identity,
        }
    }

    /// Construct a OwnedChanTarget from a given ChanTarget.
    pub fn from_chan_target<C>(target: &C) -> Self
    where
        C: ChanTarget + ?Sized,
    {
        OwnedChanTarget {
            addrs: target.addrs().to_vec(),
            ed_identity: *target.ed_identity(),
            rsa_identity: *target.rsa_identity(),
        }
    }
}

/// Primarily for error reporting and logging
impl Display for OwnedChanTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        match &*self.addrs {
            [] => write!(f, "?")?,
            [a] => write!(f, "{}", a)?,
            [a, ..] => write!(f, "{}+", a)?,
        };
        write!(f, "{}", &self.ed_identity)?; // short enough to print
        write!(f, "]")?;
        Ok(())
    }
}

/// OwnedCircTarget is a summary of a [`CircTarget`] that owns all its
/// members.
#[derive(Debug, Clone)]
pub struct OwnedCircTarget {
    /// The fields from this object when considered as a ChanTarget.
    chan_target: OwnedChanTarget,
    /// The ntor key to use when extending to this CircTarget
    ntor_onion_key: pk::curve25519::PublicKey,
    /// The subprotocol versions that this CircTarget supports.
    protovers: tor_protover::Protocols,
}

impl OwnedCircTarget {
    /// Construct a new OwnedCircTarget from its parts.
    // TODO: Put this function behind a feature.
    pub fn new(
        chan_target: OwnedChanTarget,
        ntor_onion_key: pk::curve25519::PublicKey,
        protovers: tor_protover::Protocols,
    ) -> OwnedCircTarget {
        OwnedCircTarget {
            chan_target,
            ntor_onion_key,
            protovers,
        }
    }

    /// Construct an OwnedCircTarget from a given CircTarget.
    pub fn from_circ_target<C>(target: &C) -> Self
    where
        C: CircTarget + ?Sized,
    {
        OwnedCircTarget {
            chan_target: OwnedChanTarget::from_chan_target(target),
            ntor_onion_key: *target.ntor_onion_key(),
            // TODO: I don't like having to clone here.  Our underlying
            // protovers parsing uses an Arc, IIRC.  Can we expose that here?
            protovers: target.protovers().clone(),
        }
    }
}

/// Primarily for error reporting and logging
impl Display for OwnedCircTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.chan_target, f)
    }
}

impl ChanTarget for OwnedCircTarget {
    fn addrs(&self) -> &[SocketAddr] {
        self.chan_target.addrs()
    }
    fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity {
        self.chan_target.ed_identity()
    }
    fn rsa_identity(&self) -> &pk::rsa::RsaIdentity {
        self.chan_target.rsa_identity()
    }
}

impl CircTarget for OwnedCircTarget {
    fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey {
        &self.ntor_onion_key
    }
    fn protovers(&self) -> &tor_protover::Protocols {
        &self.protovers
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    #[allow(clippy::redundant_clone)]
    fn chan_target() {
        let ti = OwnedChanTarget::new(
            vec!["127.0.0.1:11".parse().unwrap()],
            [42; 32].into(),
            [45; 20].into(),
        );

        let ti2 = OwnedChanTarget::from_chan_target(&ti);
        assert_eq!(ti.addrs(), ti2.addrs());
        assert_eq!(ti.ed_identity(), ti2.ed_identity());
        assert_eq!(ti.rsa_identity(), ti2.rsa_identity());

        assert_eq!(format!("{:?}", ti), format!("{:?}", ti2));
        assert_eq!(format!("{:?}", ti), format!("{:?}", ti.clone()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn circ_target() {
        let ch = OwnedChanTarget::new(
            vec!["127.0.0.1:11".parse().unwrap()],
            [42; 32].into(),
            [45; 20].into(),
        );
        let ct = OwnedCircTarget::new(ch.clone(), [99; 32].into(), "FlowCtrl=7".parse().unwrap());

        assert_eq!(ct.addrs(), ch.addrs());
        assert_eq!(ct.rsa_identity(), ch.rsa_identity());
        assert_eq!(ct.ed_identity(), ch.ed_identity());
        assert_eq!(ct.ntor_onion_key().as_bytes(), &[99; 32]);
        assert_eq!(&ct.protovers().to_string(), "FlowCtrl=7");
        let ct2 = OwnedCircTarget::from_circ_target(&ct);
        assert_eq!(format!("{:?}", ct), format!("{:?}", ct2));
        assert_eq!(format!("{:?}", ct), format!("{:?}", ct.clone()));
    }
}
