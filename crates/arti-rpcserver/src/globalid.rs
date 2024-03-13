//! Manager-global identifiers, for things that need to be identified outside
//! the scope of a single RPC connection.
//!
//! We expect to use this code to identify `TorClient`s and similar objects that
//! can be passed as the target of a SOCKS request.  Since the SOCKS request is
//! not part of the RPC session, we need a way for it to refer to these objects.

use tor_bytes::Reader;
use tor_llcrypto::util::ct::CtByteArray;
use tor_rpcbase::{LookupError, ObjectId};
use zeroize::Zeroizing;

use crate::{connection::ConnectionId, objmap::GenIdx};

/// A [RpcMgr](crate::RpcMgr)-scoped identifier for an RPC object.
///
/// A `GlobalId` identifies an RPC object uniquely among all the objects visible
/// to any active session on an RpcMgr.
///
/// Its encoding is unforgeable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GlobalId {
    /// The RPC connection within whose object map `local_id` is visible.
    pub(crate) connection: ConnectionId,
    /// The identifier of the object within `connection`'s object map.
    pub(crate) local_id: GenIdx,
}

/// The number of bytes in our [`MacKey`].
///
/// (Our choice of algorithm allows any key length we want; 128 bits should be
/// secure enough.)
const MAC_KEY_LEN: usize = 16;
/// The number of bytes in a [`Mac`].
///
/// (Our choice of algorithm allows any MAC length we want; 128 bits should be
/// enough to make the results unforgeable.)
const MAC_LEN: usize = 16;

/// An key that we use to compute message authentication codes (MACs) for our
/// [`GlobalId`]s
///
/// We do not guarantee any particular MAC algorithm; we should be able to
/// change MAC algorithms without breaking any user code. Right now, we choose a
/// Kangaroo12-based construction in order to be reasonably fast.
#[derive(Clone)]
pub(crate) struct MacKey {
    /// The key itself.
    key: Zeroizing<[u8; MAC_KEY_LEN]>,
}

/// A message authentication code produced by [`MacKey::mac`].
type Mac = CtByteArray<MAC_LEN>;

impl MacKey {
    /// Construct a new random `MacKey`.
    pub(crate) fn new<Rng: rand::Rng + rand::CryptoRng>(rng: &mut Rng) -> Self {
        Self {
            key: Zeroizing::new(rng.gen()),
        }
    }

    /// Compute the AMC of a given input `inp`, and store the result into `out`.
    ///
    /// The current construction allows `out` to be any length.
    fn mac(&self, inp: &[u8], out: &mut [u8]) {
        use tiny_keccak::{Hasher as _, Kmac};
        let mut mac = Kmac::v128(&self.key[..], b"artirpc globalid");
        mac.update(inp);
        mac.finalize(out);
    }
}

impl GlobalId {
    /// The number of bytes used to encode a `GlobalId` in binary form.
    const ENCODED_LEN: usize = MAC_LEN + ConnectionId::LEN + GenIdx::BYTE_LEN;
    /// The number of bytes used to encode a `GlobalId` in base-64 form.
    // TODO: use div_ceil once it's stable.
    pub(crate) const B64_ENCODED_LEN: usize = (Self::ENCODED_LEN * 8 + 5) / 6;

    /// Create a new GlobalId from its parts.
    pub(crate) fn new(connection: ConnectionId, local_id: GenIdx) -> GlobalId {
        GlobalId {
            connection,
            local_id,
        }
    }

    /// Encode this ID in an unforgeable string that we can later use to
    /// uniquely identify an RPC object.
    ///
    /// As with local IDs, this encoding is nondeterministic.
    pub(crate) fn encode(&self, key: &MacKey) -> ObjectId {
        use base64ct::{Base64Unpadded as B64, Encoding};
        let bytes = self.encode_as_bytes(key, &mut rand::thread_rng());
        B64::encode_string(&bytes[..]).into()
    }

    /// As `encode`, but do not base64-encode the result.
    fn encode_as_bytes<R: rand::RngCore>(&self, key: &MacKey, rng: &mut R) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::ENCODED_LEN);
        bytes.resize(MAC_LEN, 0);
        bytes.extend_from_slice(self.connection.as_ref());
        bytes.extend_from_slice(&self.local_id.to_bytes(rng));
        {
            // TODO RPC: Maybe we should stick the MAC at the end to make everything simpler.
            let (mac, text) = bytes.split_at_mut(MAC_LEN);
            key.mac(text, mac);
        }
        bytes
    }

    /// Try to decode and validate `s` as a [`GlobalId`].
    pub(crate) fn try_decode(key: &MacKey, s: &ObjectId) -> Result<Self, LookupError> {
        use base64ct::{Base64Unpadded as B64, Encoding};
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        let byte_slice = B64::decode(s.as_ref(), &mut bytes[..])
            .map_err(|_| LookupError::NoObject(s.clone()))?;
        Self::try_decode_from_bytes(key, byte_slice).ok_or_else(|| LookupError::NoObject(s.clone()))
    }

    /// As `try_decode`, but expect a byte slice rather than a base64-encoded string.
    fn try_decode_from_bytes(key: &MacKey, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }

        // TODO RPC: Just use Reader here?

        let mut found_mac = [0; MAC_LEN];
        key.mac(&bytes[MAC_LEN..], &mut found_mac[..]);
        let found_mac = Mac::from(found_mac);

        let mut r: Reader = Reader::from_slice(bytes);
        let declared_mac: Mac = r.extract().ok()?;
        if found_mac != declared_mac {
            return None;
        }
        let connection = r.extract::<[u8; ConnectionId::LEN]>().ok()?.into();
        let rest = r.into_rest();
        let local_id = GenIdx::from_bytes(rest)?;

        Some(Self {
            connection,
            local_id,
        })
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

    #[test]
    fn roundtrip() {
        use generational_arena as ga;
        let mut rng = tor_basic_utils::test_rng::testing_rng();

        let conn1 = ConnectionId::from(*b"example1-------!");
        let conn2 = ConnectionId::from(*b"example2!!!!!!!!");
        let genidx_s1 = GenIdx::Strong(ga::Index::from_raw_parts(42, 42));
        let genidx_w2 = GenIdx::Weak(ga::Index::from_raw_parts(172, 171));

        let gid1 = GlobalId {
            connection: conn1,
            local_id: genidx_s1,
        };
        let gid2 = GlobalId {
            connection: conn2,
            local_id: genidx_w2,
        };

        let mac_key = MacKey::new(&mut rng);
        let enc1 = gid1.encode(&mac_key);
        let gid1_decoded = GlobalId::try_decode(&mac_key, &enc1).unwrap();
        assert_eq!(gid1, gid1_decoded);

        let enc2 = gid2.encode(&mac_key);
        let gid2_decoded = GlobalId::try_decode(&mac_key, &enc2).unwrap();
        assert_eq!(gid2, gid2_decoded);
        assert_ne!(gid1_decoded, gid2_decoded);

        assert_eq!(enc1.as_ref().len(), GlobalId::B64_ENCODED_LEN);
        assert_eq!(enc2.as_ref().len(), GlobalId::B64_ENCODED_LEN);
    }

    #[test]
    fn mac_works() {
        use generational_arena as ga;
        let mut rng = tor_basic_utils::test_rng::testing_rng();

        let conn1 = ConnectionId::from(*b"example1-------!");
        let conn2 = ConnectionId::from(*b"example2!!!!!!!!");
        let genidx_s1 = GenIdx::Strong(ga::Index::from_raw_parts(42, 42));
        let genidx_w1 = GenIdx::Weak(ga::Index::from_raw_parts(172, 171));

        let gid1 = GlobalId {
            connection: conn1,
            local_id: genidx_s1,
        };
        let gid2 = GlobalId {
            connection: conn2,
            local_id: genidx_w1,
        };
        let mac_key = MacKey::new(&mut rng);
        let enc1 = gid1.encode_as_bytes(&mac_key, &mut rng);
        let enc2 = gid2.encode_as_bytes(&mac_key, &mut rng);

        // Make a 'combined' encoded gid with the mac from one and the info from
        // the other.
        let mut combined = Vec::from(&enc1[0..MAC_LEN]);
        combined.extend_from_slice(&enc2[MAC_LEN..]);
        let outcome = GlobalId::try_decode_from_bytes(&mac_key, &combined[..]);
        // Can't decode, because MAC was wrong.
        assert!(outcome.is_none());
    }
}
