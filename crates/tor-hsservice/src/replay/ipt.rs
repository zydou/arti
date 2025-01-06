//! Code for a replay log for [`Introduce2`] messages.

use super::{ReplayLogType, MAGIC_LEN, REPLAY_LOG_SUFFIX};
use crate::internal_prelude::*;
use hash::{hash, HASH_LEN};
use tor_cell::relaycell::msg::Introduce2;

/// A [`ReplayLogType`] to indicate using [`Introduce2`] messages with [`IptLocalId`] names.
pub(crate) struct IptReplayLogType;

impl ReplayLogType for IptReplayLogType {
    type Name = IptLocalId;
    type Message = Introduce2;

    // It would be better to specifically say that this is a IPT replay log here, but for backwards
    // compatability we should keep this as-is.
    const MAGIC: &'static [u8; MAGIC_LEN] = b"<tor hss replay Kangaroo12>\n\0\0\0\0";

    fn format_filename(name: &IptLocalId) -> String {
        format!("{name}{REPLAY_LOG_SUFFIX}")
    }

    fn message_bytes(message: &Introduce2) -> [u8; HASH_LEN] {
        // This line here is really subtle!  The decision of _what object_
        // to check for replays is critical to making sure that the
        // introduction point cannot do replays by modifying small parts of
        // the replayed object.  So we don't check the header; instead, we
        // check the encrypted body.  This in turn works only because the
        // encryption format is non-malleable: modifying the encrypted
        // message has negligible probability of making a message that can
        // be decrypted.
        //
        // (Ancient versions of onion services used a malleable encryption
        // format here, which made replay detection even harder.
        // Fortunately, we don't have that problem in the current protocol)
        hash(message.encrypted_body()).0
    }

    fn parse_log_leafname(leaf: &OsStr) -> Result<(IptLocalId, &str), Cow<'static, str>> {
        let leaf = leaf.to_str().ok_or("not proper unicode")?;
        let lid = leaf.strip_suffix(REPLAY_LOG_SUFFIX).ok_or("not *.bin")?;
        let lid: IptLocalId = lid
            .parse()
            .map_err(|e: crate::InvalidIptLocalId| e.to_string())?;
        Ok((lid, leaf))
    }
}

/// Implementation code for pre-hashing our inputs.
///
/// We do this because we don't actually want to record the entirety of each
/// encrypted introduction request.
///
/// We aren't terribly concerned about collision resistance: accidental
/// collision don't matter, since we are okay with a false-positive rate.
/// Intentional collisions are also okay, since the only impact of generating
/// one would be that you could make an introduce2 message _of your own_ get
/// rejected.
///
/// The impact of preimages is also not so bad. If somebody can reconstruct the
/// original message, they still get an encrypted object, and need the
/// `KP_hss_ntor` key to do anything with it. A second preimage attack just
/// gives another message we won't accept.
mod hash {
    /// Length of the internal hash.
    ///
    /// We only keep 128 bits; see note above in the module documentation about why
    /// this is okay.
    pub(super) const HASH_LEN: usize = 16;

    /// The hash of an input.
    pub(super) struct H(pub(super) [u8; HASH_LEN]);

    /// Compute a hash from a given bytestring.
    pub(super) fn hash(s: &[u8]) -> H {
        // I'm choosing kangaroo-twelve for its speed. This doesn't affect
        // compatibility, so it's okay to use something a bit odd, since we can
        // change it later if we want.
        use digest::{ExtendableOutput, Update};
        use k12::KangarooTwelve;
        let mut d = KangarooTwelve::default();
        let mut output = H([0; HASH_LEN]);
        d.update(s);
        d.finalize_xof_into(&mut output.0);
        output
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn hash_basics() {
            let a = hash(b"123");
            let b = hash(b"123");
            let c = hash(b"1234");
            assert_eq!(a.0, b.0);
            assert_ne!(a.0, c.0);
        }
    }
}
