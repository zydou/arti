BREAKING: `RelayFlags`: add underscores, giving `H_S_DIR`, `V2_DIR`, for consistency with spec
BREAKING: `RelayFlags`: no longer impl `FromStr`; use `RelayFlagsParser` instead
BREAKING: `RelayFlags` is now in new `types::relay_flags` module
BREAKING: `RouterStatus` now contains new `DocRelayFlags`.
BREAKING: `parse2` entrypoints now take a new `ParseInput`.
ADDED: Some initial support for encoding `RelayFlags`.
