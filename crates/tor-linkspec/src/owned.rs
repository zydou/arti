//! Owned variants of [`ChanTarget`] and [`CircTarget`].

use safelog::Redactable;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::net::SocketAddr;
use tor_config::impl_standard_builder;
use tor_llcrypto::pk;

use crate::{
    ChanTarget, ChannelMethod, CircTarget, HasAddrs, HasChanMethod, HasRelayIds, RelayIdRef,
    RelayIdType,
};

/// RelayIds is an owned copy of the set of known identities of a relay.
///
/// Note that an object of this type will not necessarily have every type of
/// identity: it's possible that we don't know all the identities, or that one
/// of the identity types has become optional.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    derive_builder::Builder,
)]
#[builder(derive(Debug))]
pub struct RelayIds {
    /// Copy of the ed25519 id from the underlying ChanTarget.
    #[serde(rename = "ed25519")]
    #[builder(default, setter(strip_option))]
    ed_identity: Option<pk::ed25519::Ed25519Identity>,
    /// Copy of the rsa id from the underlying ChanTarget.
    #[serde(rename = "rsa")]
    #[builder(default, setter(strip_option))]
    rsa_identity: Option<pk::rsa::RsaIdentity>,
}
impl_standard_builder! { RelayIds : !Deserialize + !Builder + !Default }

impl HasRelayIds for RelayIds {
    fn identity(&self, key_type: RelayIdType) -> Option<crate::RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Ed25519 => self.ed_identity.as_ref().map(RelayIdRef::from),
            RelayIdType::Rsa => self.rsa_identity.as_ref().map(RelayIdRef::from),
        }
    }
}

impl RelayIds {
    /// Return an empty set of identities.
    ///
    /// This is _not_ a `Default` method, since this is not what you should
    /// usually construct.
    pub fn empty() -> Self {
        Self {
            ed_identity: None,
            rsa_identity: None,
        }
    }

    /// Construct a new `RelayIds` object from another object that implements
    /// [`HasRelayIds`].
    ///
    /// Note that it is possible to construct an _empty_ `RelayIds` object if
    /// the input does not contain any recognized identity type.
    pub fn from_relay_ids<T: HasRelayIds + ?Sized>(other: &T) -> Self {
        Self {
            ed_identity: other
                .identity(RelayIdType::Ed25519)
                .map(|r| *r.unwrap_ed25519()),
            rsa_identity: other.identity(RelayIdType::Rsa).map(|r| *r.unwrap_rsa()),
        }
    }
}

impl std::fmt::Display for RelayIds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_relay_ids())
    }
}
impl Redactable for RelayIds {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_relay_ids().redacted())
    }
}

/// OwnedChanTarget is a summary of a [`ChanTarget`] that owns all of its
/// members.
#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(derive(Debug))]
pub struct OwnedChanTarget {
    /// Copy of the addresses from the underlying ChanTarget.
    #[builder(default)]
    addrs: Vec<SocketAddr>,
    /// Copy of the channel methods from the underlying ChanTarget.
    //
    // TODO: in many cases this will be redundant with addrs; if we allocate a
    // lot of these objects, we might want to handle that.
    #[builder(default = "self.make_method()")]
    method: ChannelMethod,
    /// Identities that this relay provides.
    #[builder(sub_builder)]
    ids: RelayIds,
}
impl_standard_builder! { OwnedChanTarget : !Deserialize + !Builder + !Default }

impl OwnedChanTargetBuilder {
    /// Set the ed25519 identity in this builder to `id`.
    pub fn ed_identity(&mut self, id: pk::ed25519::Ed25519Identity) -> &mut Self {
        self.ids().ed_identity(id);
        self
    }

    /// Set the RSA identity in this builder to `id`.
    pub fn rsa_identity(&mut self, id: pk::rsa::RsaIdentity) -> &mut Self {
        self.ids().rsa_identity(id);
        self
    }

    /// Helper: make a channel method if none was specified.
    fn make_method(&self) -> ChannelMethod {
        ChannelMethod::Direct(self.addrs.clone().unwrap_or_default())
    }
}

impl HasAddrs for OwnedChanTarget {
    fn addrs(&self) -> &[SocketAddr] {
        &self.addrs[..]
    }
}

impl HasChanMethod for OwnedChanTarget {
    fn chan_method(&self) -> ChannelMethod {
        self.method.clone()
    }
}

impl HasRelayIds for OwnedChanTarget {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.ids.identity(key_type)
    }
}

impl ChanTarget for OwnedChanTarget {}

impl OwnedChanTarget {
    /// Construct a OwnedChanTarget from a given ChanTarget.
    pub fn from_chan_target<C>(target: &C) -> Self
    where
        C: ChanTarget + ?Sized,
    {
        OwnedChanTarget {
            addrs: target.addrs().to_vec(),
            method: target.chan_method(),
            ids: RelayIds::from_relay_ids(target),
        }
    }

    /// Return a mutable reference to this [`OwnedChanTarget`]'s [`ChannelMethod`]
    ///
    pub fn chan_method_mut(&mut self) -> &mut ChannelMethod {
        &mut self.method
    }
}

/// Primarily for error reporting and logging
impl Display for OwnedChanTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.display_chan_target())
    }
}

impl Redactable for OwnedChanTarget {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_chan_target().display_redacted(f)
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_chan_target().debug_redacted(f)
    }
}

/// OwnedCircTarget is a summary of a [`CircTarget`] that owns all its
/// members.
#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(derive(Debug))]
pub struct OwnedCircTarget {
    /// The fields from this object when considered as a ChanTarget.
    #[builder(sub_builder)]
    chan_target: OwnedChanTarget,
    /// The ntor key to use when extending to this CircTarget
    ntor_onion_key: pk::curve25519::PublicKey,
    /// The subprotocol versions that this CircTarget supports.
    protocols: tor_protover::Protocols,
}
impl_standard_builder! { OwnedCircTarget : !Deserialize + !Builder + !Default }

impl OwnedCircTarget {
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
            protocols: target.protovers().clone(),
        }
    }

    /// Return a mutable view of this OwnedCircTarget as an [`OwnedChanTarget`].
    pub fn chan_target_mut(&mut self) -> &mut OwnedChanTarget {
        &mut self.chan_target
    }
}

impl HasAddrs for OwnedCircTarget {
    fn addrs(&self) -> &[SocketAddr] {
        self.chan_target.addrs()
    }
}

impl HasRelayIds for OwnedCircTarget {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.chan_target.identity(key_type)
    }
}
impl HasChanMethod for OwnedCircTarget {
    fn chan_method(&self) -> ChannelMethod {
        self.chan_target.chan_method()
    }
}

impl ChanTarget for OwnedCircTarget {}

impl CircTarget for OwnedCircTarget {
    fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey {
        &self.ntor_onion_key
    }
    fn protovers(&self) -> &tor_protover::Protocols {
        &self.protocols
    }
}

/// A value that can be converted into an OwnedChanTarget.
pub trait IntoOwnedChanTarget {
    /// Convert this value into an [`OwnedChanTarget`].
    fn to_owned(self) -> OwnedChanTarget;

    /// Convert this value into an [`LoggedChanTarget`].
    fn to_logged(self) -> LoggedChanTarget
    where
        Self: Sized,
    {
        self.to_owned().into()
    }
}

impl<'a, T: ChanTarget + ?Sized> IntoOwnedChanTarget for &'a T {
    fn to_owned(self) -> OwnedChanTarget {
        OwnedChanTarget::from_chan_target(self)
    }
}

impl IntoOwnedChanTarget for OwnedChanTarget {
    fn to_owned(self) -> OwnedChanTarget {
        self
    }
}

/// An `OwnedChanTarget` suitable for logging and including in errors
pub type LoggedChanTarget = safelog::BoxSensitive<OwnedChanTarget>;

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    #[allow(clippy::redundant_clone)]
    fn chan_target() {
        let ti = OwnedChanTarget::builder()
            .addrs(vec!["127.0.0.1:11".parse().unwrap()])
            .ed_identity([42; 32].into())
            .rsa_identity([45; 20].into())
            .build()
            .unwrap();

        let ti2 = OwnedChanTarget::from_chan_target(&ti);
        assert_eq!(ti.addrs(), ti2.addrs());
        assert!(ti.same_relay_ids(&ti2));

        assert_eq!(format!("{:?}", ti), format!("{:?}", ti2));
        assert_eq!(format!("{:?}", ti), format!("{:?}", ti.clone()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn circ_target() {
        let mut builder = OwnedCircTarget::builder();
        builder
            .chan_target()
            .addrs(vec!["127.0.0.1:11".parse().unwrap()])
            .ed_identity([42; 32].into())
            .rsa_identity([45; 20].into());
        let ct = builder
            .ntor_onion_key([99; 32].into())
            .protocols("FlowCtrl=7".parse().unwrap())
            .build()
            .unwrap();
        let ch = ct.chan_target.clone();

        assert_eq!(ct.addrs(), ch.addrs());
        assert!(ct.same_relay_ids(&ch));
        assert_eq!(ct.ntor_onion_key().as_bytes(), &[99; 32]);
        assert_eq!(&ct.protovers().to_string(), "FlowCtrl=7");
        let ct2 = OwnedCircTarget::from_circ_target(&ct);
        assert_eq!(format!("{:?}", ct), format!("{:?}", ct2));
        assert_eq!(format!("{:?}", ct), format!("{:?}", ct.clone()));
    }

    #[test]
    fn format_relay_ids() {
        let mut builder = RelayIds::builder();
        builder
            .ed_identity([42; 32].into())
            .rsa_identity([45; 20].into());
        let ids = builder.build().unwrap();
        assert_eq!(format!("{}", ids), "ed25519:KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio $2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d");
        assert_eq!(format!("{}", ids.redacted()), "ed25519:Ki…");
    }
}
