//! Code for a replay log for Proof-of-Work [`Nonce`]s.

use std::{borrow::Cow, ffi::OsStr};

use tor_hscrypto::pow::v1::{Nonce, Seed};

use super::{MAGIC_LEN, OUTPUT_LEN, REPLAY_LOG_SUFFIX, ReplayLogType};

/// A [`ReplayLogType`] to indicate using [`Nonce`] messages with [`Seed`] names.
pub(crate) struct PowNonceReplayLogType;

impl ReplayLogType for PowNonceReplayLogType {
    type Name = Seed;
    type Message = Nonce;

    const MAGIC: &'static [u8; MAGIC_LEN] = b"<tor hss pow replay Kangaroo12>\n";

    fn format_filename(name: &Seed) -> String {
        format!("{name}{REPLAY_LOG_SUFFIX}")
    }

    fn transform_message(message: &Nonce) -> [u8; OUTPUT_LEN] {
        *message.as_ref()
    }

    fn parse_log_leafname(leaf: &OsStr) -> Result<Seed, Cow<'static, str>> {
        let leaf = leaf.to_str().ok_or("not proper unicode")?;
        let seed = leaf.strip_suffix(REPLAY_LOG_SUFFIX).ok_or("not *.bin")?;
        seed.parse().or(Err("invalid seed".into()))
    }
}
