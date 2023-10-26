BREAKING: `StreamId` can no longer be zero. (Use `Option<StreamId>` instead)
BREAKING: Removed `StreamId::is_zero`.
BREAKING: `From<u16>` is no longer implemented for `StreamId`.
BREAKING: `RelayCmd::accepts_streamid_val` now takes `Option<StreamId>` instead of `StreamId`.
BREAKING: `UnparsedRelayCell::stream_id` now returns `Option<StreamId>` instead of `StreamId`.
BREAKING: `RelayCell::new` now takes `Option<StreamId>` instead of `StreamId`.
BREAKING: `RelayCell::into_streamid_and_msg` now returns `Option<StreamId>` instead of `StreamId`.
BREAKING: `RelayCell::stream_id` now returns `Option<StreamId>` instead of `StreamId`.
MODIFIED: Added `From<NonZeroU16>` for `StreamId`.
MODIFIED: Added `StreamId::new`.
MODIFIED: Added `StreamId::get_or_zero`.
MODIFIED: Added `From<StreamId>` for `NonZeroU16`.
BREAKING: `CircId` can no longer be zero. (Use `Option<CircId>` instead)
BREAKING: `From<u32>` is no longer implemented for `CircId`.
MODIFIED: Added `From<NonZeroU32>` for `CircId`.
MODIFIED: Added `CircId::new`.
BREAKING: Removed `CircId::is_zero`.
BREAKING: `ChanCmd::accepts_circid_val` now takes `Option<CircId>` instead of `CircId`.
BREAKING: `ChanCell::new` now takes `Option<CircId>` instead of `CircId`.
MODIFIED: Added `ChanCell::get_or_zero`.
BREAKING: `ChanCell::circid` now returns `Option<CircId>` instead of `CircId`.
BREAKING: `ChanCell::into_circid_and_msg` now returns `Option<CircId>` instead of `CircId`.
MODIFIED: `CircIdRange::sample` can no longer return 0 (previously possible if rng returned 0x8000_0000 when generating into a low range)
MODIFIED: Added `chancell::msg::HandshakeType`
BREAKING: `chancell::msg::Create2::new` now takes `HandshakeType` instead of `u16`
BREAKING: `chancell::msg::Create2::handshake_type` now returns `HandshakeType` instead of `u16`
