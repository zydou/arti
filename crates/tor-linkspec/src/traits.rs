//! Declare traits to be implemented by types that describe a place
//! that Tor can connect to, directly or indirectly.

use derive_deftly::derive_deftly_adhoc;
use safelog::Redactable;
use std::{fmt, iter::FusedIterator, net::SocketAddr};
use tor_llcrypto::pk;

use crate::{ChannelMethod, RelayIdRef, RelayIdType, RelayIdTypeIter};

#[cfg(feature = "pt-client")]
use crate::PtTargetAddr;

/// Legacy implementation helper for HasRelayIds.
///
/// Previously, we assumed that everything had these two identity types, which
/// is not an assumption we want to keep making in the future.
pub trait HasRelayIdsLegacy {
    /// Return the ed25519 identity for this relay.
    fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity;
    /// Return the RSA identity for this relay.
    fn rsa_identity(&self) -> &pk::rsa::RsaIdentity;
}

/// An object containing information about a relay's identity keys.
///
/// This trait has a fairly large number of methods, most of which you're not
/// actually expected to implement.  The only one that you need to provide is
/// [`identity`](HasRelayIds::identity).
pub trait HasRelayIds {
    /// Return the identity of this relay whose type is `key_type`, or None if
    /// the relay has no such identity.
    ///
    /// (Currently all relays have all recognized identity types, but we might
    /// implement or deprecate an identity type in the future.)
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>>;

    /// Return an iterator over all of the identities held by this object.
    fn identities(&self) -> RelayIdIter<'_, Self> {
        RelayIdIter {
            info: self,
            next_key: RelayIdType::all_types(),
        }
    }

    /// Return the ed25519 identity for this relay if it has one.
    fn ed_identity(&self) -> Option<&pk::ed25519::Ed25519Identity> {
        self.identity(RelayIdType::Ed25519)
            .map(RelayIdRef::unwrap_ed25519)
    }

    /// Return the RSA identity for this relay if it has one.
    fn rsa_identity(&self) -> Option<&pk::rsa::RsaIdentity> {
        self.identity(RelayIdType::Rsa).map(RelayIdRef::unwrap_rsa)
    }

    /// Check whether the provided Id is a known identity of this relay.
    ///
    /// Remember that a given set of identity keys may be incomplete: some
    /// objects that represent a relay have only a subset of the relay's
    /// identities. Therefore, a "true" answer means that the relay has this
    /// identity,  but a "false" answer could mean that the relay has a
    /// different identity of this type, or that it has _no_ known identity of
    /// this type.
    fn has_identity(&self, id: RelayIdRef<'_>) -> bool {
        self.identity(id.id_type()).map(|my_id| my_id == id) == Some(true)
    }

    /// Return true if this object has any known identity.
    fn has_any_identity(&self) -> bool {
        RelayIdType::all_types().any(|id_type| self.identity(id_type).is_some())
    }

    /// Return true if this object has exactly the same relay IDs as `other`.
    //
    // TODO: Once we make it so particular identity key types are optional, we
    // should add a note saying that this function is usually not what you want
    // for many cases, since you might want to know "could this be the same
    // relay" vs "is this definitely the same relay."
    //
    // NOTE: We don't make this an `Eq` method, since we want to make callers
    // choose carefully among this method, `has_all_relay_ids_from`, and any
    // similar methods we add in the future.
    fn same_relay_ids<T: HasRelayIds + ?Sized>(&self, other: &T) -> bool {
        // We use derive-deftly to iterate over the id types, rather than strum
        //
        // Empirically, with rustc 1.77.0-beta.5, this arranges that
        //     <tor_netdir::Relay as HasRelayIds>::same_relay_ids
        // compiles to the same asm (on amd64) as the open-coded inherent
        //     tor_netdir::Relay::has_same_relay_ids
        //
        // The problem with the strum approach seems to be that the compiler doesn't inline
        //     <RelayIdTypeIter as Iterator>::next
        // and unroll the loop.
        // Adding `#[inline]` and even `#[inline(always)]` to the strum output didn't help.
        //
        // When `next()` isn't inlined and the loop unrolled,
        // the compiler can't inline the matching on the id type,
        // and generate the obvious simple function.
        //
        // Empirically, the same results with non-inlined next() and non-unrolled loop,
        // were obtained with:
        //   - a simpler hand-coded Iterator struct
        //   - that hand-coded Iterator struct locally present in tor-netdir,
        //   - using `<[RelayIdType; ] as IntoIterator>`
        //
        // I experimented to see if this was a general problem with `strum`'s iterator.
        // In a smaller test program the compiler *does* unroll and inline.
        // I suspect that the compiler is having trouble with the complexities
        // of disentangling `HasLegacyRelayIds` and/or comparing `Option<RelayIdRef>`.
        //
        // TODO: do we want to replace RelayIdType::all_types with derive-deftly
        // in RelayIdIter, has_all_relay_ids_from, has_any_relay_id_from, etc.?
        // If so, search this crate for all_types.
        derive_deftly_adhoc! {
            RelayIdType:
            $(
                self.identity($vtype) == other.identity($vtype) &&
            )
                true
        }
    }

    /// Return true if this object has every relay ID that `other` does.
    ///
    /// (It still returns true if there are some IDs in this object that are not
    /// present in `other`.)
    fn has_all_relay_ids_from<T: HasRelayIds + ?Sized>(&self, other: &T) -> bool {
        RelayIdType::all_types().all(|key_type| {
            match (self.identity(key_type), other.identity(key_type)) {
                // If we both have the same key for this type, great.
                (Some(mine), Some(theirs)) if mine == theirs => true,
                // Uh oh. They do have a key for his type, but it's not ours.
                (_, Some(_theirs)) => false,
                // If they don't care what we have for this type, great.
                (_, None) => true,
            }
        })
    }

    /// Return true if this object has any relay ID that `other` has.
    ///
    /// This is symmetrical:
    /// it returns true if the two objects have any overlap in their identities.
    fn has_any_relay_id_from<T: HasRelayIds + ?Sized>(&self, other: &T) -> bool {
        RelayIdType::all_types()
            .filter_map(|key_type| Some((self.identity(key_type)?, other.identity(key_type)?)))
            .any(|(self_id, other_id)| self_id == other_id)
    }

    /// Compare this object to another HasRelayIds.
    ///
    /// Objects are sorted by Ed25519 identities, with ties decided by RSA
    /// identities. An absent identity of a given type is sorted before a
    /// present identity of that type.
    ///
    /// If additional identities are added in the future, they may taken into
    /// consideration before _or_ after the current identity types.
    fn cmp_by_relay_ids<T: HasRelayIds + ?Sized>(&self, other: &T) -> std::cmp::Ordering {
        for key_type in RelayIdType::all_types() {
            let ordering = Ord::cmp(&self.identity(key_type), &other.identity(key_type));
            if ordering.is_ne() {
                return ordering;
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Return a reference to this object suitable for formatting its
    /// [`HasRelayIds`] members.
    fn display_relay_ids(&self) -> DisplayRelayIds<'_, Self> {
        DisplayRelayIds { inner: self }
    }
}

impl<T: HasRelayIdsLegacy> HasRelayIds for T {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Rsa => Some(self.rsa_identity().into()),
            RelayIdType::Ed25519 => Some(self.ed_identity().into()),
        }
    }
}

/// A helper type used to format the [`RelayId`](crate::RelayId)s in a
/// [`HasRelayIds`].
#[derive(Clone)]
pub struct DisplayRelayIds<'a, T: HasRelayIds + ?Sized> {
    /// The HasRelayIds that we're displaying.
    inner: &'a T,
}
// Redactable must implement Debug.
impl<'a, T: HasRelayIds + ?Sized> fmt::Debug for DisplayRelayIds<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DisplayRelayIds").finish_non_exhaustive()
    }
}

impl<'a, T: HasRelayIds + ?Sized> DisplayRelayIds<'a, T> {
    /// Helper: output `self` in a possibly redacted way.
    fn fmt_impl(&self, f: &mut fmt::Formatter<'_>, redact: bool) -> fmt::Result {
        let mut iter = self.inner.identities();
        if let Some(ident) = iter.next() {
            write!(f, "{}", ident.maybe_redacted(redact))?;
        }
        if redact {
            return Ok(());
        }
        for ident in iter {
            write!(f, " {}", ident.maybe_redacted(redact))?;
        }
        Ok(())
    }
}
impl<'a, T: HasRelayIds + ?Sized> fmt::Display for DisplayRelayIds<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_impl(f, false)
    }
}
impl<'a, T: HasRelayIds + ?Sized> Redactable for DisplayRelayIds<'a, T> {
    fn display_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_impl(f, true)
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

/// An object that represents a host on the network which may have known IP addresses.
pub trait HasAddrs {
    /// Return the addresses listed for this server.
    ///
    /// NOTE that these addresses are not necessarily ones that we should
    /// connect to directly!  They can be useful for telling where a server is
    /// located, or whether it is "close" to another server, but without knowing
    /// the associated protocols you cannot use these to launch a connection.
    ///
    /// Also, for some servers, we may not actually have any relevant addresses;
    /// in that case, the returned slice is empty.
    ///
    /// To see how to _connect_ to a relay, use [`HasChanMethod::chan_method`]
    //
    // TODO: This is a questionable API. I'd rather return an iterator
    // of addresses or references to addresses, but both of those options
    // make defining the right associated types rather tricky.
    fn addrs(&self) -> &[SocketAddr];
}

/// An object that can be connected to via [`ChannelMethod`]s.
pub trait HasChanMethod {
    /// Return the known ways to contact this
    // TODO: See notes on HasAddrs above.
    // TODO: I don't like having this return a new ChannelMethod, but I
    // don't see a great alternative. Let's revisit that.-nickm.
    fn chan_method(&self) -> ChannelMethod;
}

/// Implement `HasChanMethods` for an object with `HasAddr` whose addresses
/// _all_ represent a host we can connect to by a direct Tor connection at its
/// IP addresses.
pub trait DirectChanMethodsHelper: HasAddrs {}

impl<D: DirectChanMethodsHelper> HasChanMethod for D {
    fn chan_method(&self) -> ChannelMethod {
        ChannelMethod::Direct(self.addrs().to_vec())
    }
}

/// Information about a Tor relay used to connect to it.
///
/// Anything that implements 'ChanTarget' can be used as the
/// identity of a relay for the purposes of launching a new
/// channel.
pub trait ChanTarget: HasRelayIds + HasAddrs + HasChanMethod {
    /// Return a reference to this object suitable for formatting its
    /// [`ChanTarget`]-specific members.
    ///
    /// The display format is not exhaustive, but tries to give enough
    /// information to identify which channel target we're talking about.
    fn display_chan_target(&self) -> DisplayChanTarget<'_, Self>
    where
        Self: Sized,
    {
        DisplayChanTarget { inner: self }
    }
}

/// Information about a Tor relay used to extend a circuit to it.
///
/// Anything that implements 'CircTarget' can be used as the
/// identity of a relay for the purposes of extending a circuit.
pub trait CircTarget: ChanTarget {
    /// Return a new vector of encoded link specifiers for this relay.
    ///
    /// Note that, outside of this method, nothing in Arti should be re-ordering
    /// the link specifiers returned by this method.  It is this method's
    /// responsibility to return them in the correct order.
    ///
    /// The default implementation for this method builds a list of link
    /// specifiers from this object's identities and IP addresses, and sorts
    /// them into the order specified in tor-spec to avoid implementation
    /// fingerprinting attacks.
    //
    // TODO: This is a questionable API. I'd rather return an iterator
    // of link specifiers, but that's not so easy to do, since it seems
    // doing so correctly would require default associated types.
    fn linkspecs(&self) -> tor_bytes::EncodeResult<Vec<crate::EncodedLinkSpec>> {
        let mut result: Vec<_> = self.identities().map(|id| id.to_owned().into()).collect();
        #[allow(irrefutable_let_patterns)]
        if let ChannelMethod::Direct(addrs) = self.chan_method() {
            result.extend(addrs.into_iter().map(crate::LinkSpec::from));
        }
        crate::LinkSpec::sort_by_type(&mut result[..]);
        result.into_iter().map(|ls| ls.encode()).collect()
    }
    /// Return the ntor onion key for this relay
    fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey;
    /// Return the subprotocols implemented by this relay.
    fn protovers(&self) -> &tor_protover::Protocols;
}

/// A reference to a ChanTarget that implements Display using a hopefully useful
/// format.
#[derive(Debug, Clone)]
pub struct DisplayChanTarget<'a, T> {
    /// The ChanTarget that we're formatting.
    inner: &'a T,
}

impl<'a, T: ChanTarget> DisplayChanTarget<'a, T> {
    /// helper: output `self` in a possibly redacted way.
    fn fmt_impl(&self, f: &mut fmt::Formatter<'_>, redact: bool) -> fmt::Result {
        write!(f, "[")?;
        // We look at the chan_method() (where we would connect to) rather than
        // the addrs() (where the relay is, nebulously, "located").  This lets us
        // give a less surprising description.
        match self.inner.chan_method() {
            ChannelMethod::Direct(v) if v.is_empty() => write!(f, "?")?,
            ChannelMethod::Direct(v) if v.len() == 1 => {
                write!(f, "{}", v[0].maybe_redacted(redact))?;
            }
            ChannelMethod::Direct(v) => write!(f, "{}+", v[0].maybe_redacted(redact))?,
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => {
                match target.addr() {
                    PtTargetAddr::None => {}
                    other => write!(f, "{} ", other.maybe_redacted(redact))?,
                }
                write!(f, "via {}", target.transport())?;
                // This deliberately doesn't include the PtTargetSettings, since
                // they can be large, and they're typically unnecessary.
            }
        }

        write!(f, " ")?;
        self.inner.display_relay_ids().fmt_impl(f, redact)?;

        write!(f, "]")
    }
}

impl<'a, T: ChanTarget> fmt::Display for DisplayChanTarget<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_impl(f, false)
    }
}

impl<'a, T: ChanTarget + fmt::Debug> safelog::Redactable for DisplayChanTarget<'a, T> {
    fn display_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_impl(f, true)
    }
    fn debug_redacted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChanTarget({:?})", self.redacted().to_string())
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
    use super::*;
    use crate::RelayIds;
    use hex_literal::hex;
    use std::net::IpAddr;
    use tor_llcrypto::pk::{self, ed25519::Ed25519Identity, rsa::RsaIdentity};

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
    impl DirectChanMethodsHelper for Example {}
    impl HasRelayIdsLegacy for Example {
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
        let specs = ex
            .linkspecs()
            .unwrap()
            .into_iter()
            .map(|ls| ls.parse())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(4, specs.len());

        use crate::ls::LinkSpec;
        assert_eq!(
            specs[0],
            LinkSpec::OrPort("127.0.0.1".parse::<IpAddr>().unwrap(), 99)
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
            specs[3],
            LinkSpec::OrPort("::1".parse::<IpAddr>().unwrap(), 909)
        );
    }

    #[test]
    fn cmp_by_ids() {
        use crate::RelayIds;
        use std::cmp::Ordering;
        fn b(ed: Option<Ed25519Identity>, rsa: Option<RsaIdentity>) -> RelayIds {
            let mut b = RelayIds::builder();
            if let Some(ed) = ed {
                b.ed_identity(ed);
            }
            if let Some(rsa) = rsa {
                b.rsa_identity(rsa);
            }
            b.build().unwrap()
        }
        // Assert that v is strictly ascending.
        fn assert_sorted(v: &[RelayIds]) {
            for slice in v.windows(2) {
                assert_eq!(slice[0].cmp_by_relay_ids(&slice[1]), Ordering::Less);
                assert_eq!(slice[1].cmp_by_relay_ids(&slice[0]), Ordering::Greater);
                assert_eq!(slice[0].cmp_by_relay_ids(&slice[0]), Ordering::Equal);
            }
        }

        let ed1 = hex!("0a54686973206973207468652043656e7472616c205363727574696e697a6572").into();
        let ed2 = hex!("6962696c69747920746f20656e666f72636520616c6c20746865206c6177730a").into();
        let ed3 = hex!("73736564207965740a497420697320616c736f206d7920726573706f6e736962").into();
        let rsa1 = hex!("2e2e2e0a4974206973206d7920726573706f6e73").into();
        let rsa2 = hex!("5468617420686176656e2774206265656e207061").into();
        let rsa3 = hex!("696c69747920746f20616c65727420656163680a").into();

        assert_sorted(&[
            b(Some(ed1), None),
            b(Some(ed2), None),
            b(Some(ed3), None),
            b(Some(ed3), Some(rsa1)),
        ]);
        assert_sorted(&[
            b(Some(ed1), Some(rsa3)),
            b(Some(ed2), Some(rsa2)),
            b(Some(ed3), Some(rsa1)),
            b(Some(ed3), Some(rsa2)),
        ]);
        assert_sorted(&[
            b(Some(ed1), Some(rsa1)),
            b(Some(ed1), Some(rsa2)),
            b(Some(ed1), Some(rsa3)),
        ]);
        assert_sorted(&[
            b(None, Some(rsa1)),
            b(None, Some(rsa2)),
            b(None, Some(rsa3)),
        ]);
        assert_sorted(&[
            b(None, Some(rsa1)),
            b(Some(ed1), None),
            b(Some(ed1), Some(rsa1)),
        ]);
    }

    #[test]
    fn compare_id_sets() {
        // TODO somehow nicely unify these repeated predefined examples
        let ed1 = hex!("0a54686973206973207468652043656e7472616c205363727574696e697a6572").into();
        let rsa1 = hex!("2e2e2e0a4974206973206d7920726573706f6e73").into();
        let rsa2 = RsaIdentity::from(hex!("5468617420686176656e2774206265656e207061"));

        let both1 = RelayIds::builder()
            .ed_identity(ed1)
            .rsa_identity(rsa1)
            .build()
            .unwrap();
        let mixed = RelayIds::builder()
            .ed_identity(ed1)
            .rsa_identity(rsa2)
            .build()
            .unwrap();
        let ed1 = RelayIds::builder().ed_identity(ed1).build().unwrap();
        let rsa1 = RelayIds::builder().rsa_identity(rsa1).build().unwrap();
        let rsa2 = RelayIds::builder().rsa_identity(rsa2).build().unwrap();

        fn chk_equal(v: &impl HasRelayIds) {
            assert!(v.same_relay_ids(v));
            assert!(v.has_all_relay_ids_from(v));
            assert!(v.has_any_relay_id_from(v));
        }
        fn chk_strict_subset(bigger: &impl HasRelayIds, smaller: &impl HasRelayIds) {
            assert!(!bigger.same_relay_ids(smaller));
            assert!(bigger.has_all_relay_ids_from(smaller));
            assert!(bigger.has_any_relay_id_from(smaller));
            assert!(!smaller.same_relay_ids(bigger));
            assert!(!smaller.has_all_relay_ids_from(bigger));
            assert!(smaller.has_any_relay_id_from(bigger));
        }
        fn chk_nontrivially_overlapping_one_way(a: &impl HasRelayIds, b: &impl HasRelayIds) {
            assert!(!a.same_relay_ids(b));
            assert!(!a.has_all_relay_ids_from(b));
            assert!(a.has_any_relay_id_from(b));
        }
        fn chk_nontrivially_overlapping(a: &impl HasRelayIds, b: &impl HasRelayIds) {
            chk_nontrivially_overlapping_one_way(a, b);
            chk_nontrivially_overlapping_one_way(b, a);
        }

        chk_equal(&ed1);
        chk_equal(&rsa1);
        chk_equal(&both1);

        chk_strict_subset(&both1, &ed1);
        chk_strict_subset(&both1, &rsa1);
        chk_strict_subset(&mixed, &ed1);
        chk_strict_subset(&mixed, &rsa2);

        chk_nontrivially_overlapping(&both1, &mixed);
    }

    #[test]
    fn display() {
        let e1 = example();
        assert_eq!(
            e1.display_chan_target().to_string(),
            "[127.0.0.1:99+ ed25519:/FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU \
              $1234567890abcdef12341234567890abcdef1234]"
        );

        #[cfg(feature = "pt-client")]
        {
            use crate::PtTarget;

            let rsa = hex!("234461644a6f6b6523436f726e794f6e4d61696e").into();
            let mut b = crate::OwnedChanTarget::builder();
            b.ids().rsa_identity(rsa);
            let e2 = b
                .method(ChannelMethod::Pluggable(PtTarget::new(
                    "obfs4".parse().unwrap(),
                    "127.0.0.1:99".parse().unwrap(),
                )))
                .build()
                .unwrap();
            assert_eq!(
                e2.to_string(),
                "[127.0.0.1:99 via obfs4 $234461644a6f6b6523436f726e794f6e4d61696e]"
            );
        }
    }

    #[test]
    fn has_id() {
        use crate::RelayIds;
        assert!(example().has_any_identity());
        assert!(!RelayIds::empty().has_any_identity());
    }
}
