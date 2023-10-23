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
