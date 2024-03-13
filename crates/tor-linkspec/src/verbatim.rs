//! Wrappers for using a CircTarget with a verbatim list of
//! [link specifiers](EncodedLinkSpec).

use crate::{ChanTarget, CircTarget, EncodedLinkSpec, HasAddrs, HasChanMethod, HasRelayIds};

/// A wrapper around an underlying [`CircTarget`] that provides a user-specified
/// list of [link specifiers](EncodedLinkSpec).
///
/// Onion services and their clients use this type of target when telling a
/// relay to extend a circuit to a target relay (an introduction point or
/// rendezvous point) chosen by some other party.
#[derive(Clone, Debug)]
pub struct VerbatimLinkSpecCircTarget<T> {
    /// The underlying CircTarget
    target: T,
    /// The link specifiers to provide.
    linkspecs: Vec<EncodedLinkSpec>,
}

impl<T> VerbatimLinkSpecCircTarget<T> {
    /// Construct a new `VerbatimLinkSpecCircTarget` to wrap an underlying
    /// `CircTarget` object, and provide it with a new set of encoded link
    /// specifiers that will be used when telling a relay to extend to this
    /// node.
    ///
    /// Note that nothing here will check that `linkspecs` is sufficient to
    /// actually connect to the chosen target, or to any target at all. It is
    /// the caller's responsibility to choose a valid set of link specifiers.
    pub fn new(target: T, linkspecs: Vec<EncodedLinkSpec>) -> Self {
        Self { target, linkspecs }
    }
}

// Now, the delegation functions.  All of these are simple delegations to
// self.target, except for `CircTarget::linkspecs` with returns self.linkspecs.

impl<T: HasRelayIds> HasRelayIds for VerbatimLinkSpecCircTarget<T> {
    fn identity(&self, key_type: crate::RelayIdType) -> Option<crate::RelayIdRef<'_>> {
        self.target.identity(key_type)
    }
}
impl<T: HasAddrs> HasAddrs for VerbatimLinkSpecCircTarget<T> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        self.target.addrs()
    }
}
impl<T: HasChanMethod> HasChanMethod for VerbatimLinkSpecCircTarget<T> {
    fn chan_method(&self) -> crate::ChannelMethod {
        self.target.chan_method()
    }
}
impl<T: ChanTarget> ChanTarget for VerbatimLinkSpecCircTarget<T> {}
impl<T: CircTarget> CircTarget for VerbatimLinkSpecCircTarget<T> {
    fn linkspecs(&self) -> tor_bytes::EncodeResult<Vec<EncodedLinkSpec>> {
        Ok(self.linkspecs.clone())
    }

    fn ntor_onion_key(&self) -> &tor_llcrypto::pk::curve25519::PublicKey {
        self.target.ntor_onion_key()
    }

    fn protovers(&self) -> &tor_protover::Protocols {
        self.target.protovers()
    }
}

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

    use crate::OwnedCircTarget;

    use super::*;
    #[test]
    fn verbatim_linkspecs() {
        let mut builder = OwnedCircTarget::builder();
        builder
            .chan_target()
            .addrs(vec!["127.0.0.1:11".parse().unwrap()])
            .ed_identity([42; 32].into())
            .rsa_identity([45; 20].into());
        let inner = builder
            .ntor_onion_key([99; 32].into())
            .protocols("FlowCtrl=7".parse().unwrap())
            .build()
            .unwrap();
        let weird_linkspecs = vec![EncodedLinkSpec::new(
            77.into(),
            b"mysterious whisper".to_vec(),
        )];
        let wrapped = VerbatimLinkSpecCircTarget::new(inner.clone(), weird_linkspecs.clone());

        assert_eq!(wrapped.addrs(), inner.addrs());
        assert!(wrapped.same_relay_ids(&inner));
        assert_eq!(wrapped.ntor_onion_key(), inner.ntor_onion_key());
        assert_eq!(wrapped.protovers(), inner.protovers());

        assert_ne!(inner.linkspecs().unwrap(), weird_linkspecs);
        assert_eq!(wrapped.linkspecs().unwrap(), weird_linkspecs);
    }
}
