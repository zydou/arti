BREAKING: Individual relay flags are now variants of a `RelayFlag` enum, rather than constants.
BREAKING: `RelayFlags` has a different API - it's now an `EnumSet` from `enumset`
BREAKING: `RelayFlags`: no longer impl `FromStr`; use `RelayFlag` or `RelayFlagsParser` instead
BREAKING: `RelayFlags` is now in new `types::relay_flags` module
BREAKING: `RouterStatus` now contains new `DocRelayFlags`.
BREAKING: `parse2` entrypoints now take a new `ParseInput`.
ADDED: Some initial support for encoding `RelayFlags`.
ADDED: Much more API exposed in the `encode` module
