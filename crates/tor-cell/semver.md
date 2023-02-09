BREAKING:  The interfaces for ChanMsg::Body and RelayMsg::Body have been made
more uniform.
BREAKING: RelayMsg no longer has any unit variants.
BREAKING: Renamed VPadding to Vpadding, for consistent snake case.
BREAKING: Moved ChanMsg methods into a trait.
BREAKING: Moved RelayMsg methods into a trait.
BREAKING: Renamed ChanCell->AnyChanCell, ChanMsg->AnyChanMsg.
BREAKING: Renamed RelayCell->AnyRelayCell, RelayMsg->AnyRelayMsg.
BREAKING: Make ChannelCodec::decode() parameterized.
BREAKING: RelayEarly is now a real type.
