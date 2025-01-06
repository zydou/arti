//! Code for a replay log for [`Introduce2`] messages.

use super::{ReplayLogType, MAGIC_LEN, REPLAY_LOG_SUFFIX};
use crate::internal_prelude::*;
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

    fn message_bytes(message: &Introduce2) -> Vec<u8> {
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
        message.encrypted_body().to_vec()
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
