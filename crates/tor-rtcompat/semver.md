# BREAKING: `BlockOn` trait split into `ToplevelBlockOn` and `Blocking`.

New rules for `BlockOn::block_on`; when `ToplevelBlockOn` not
available, use methods from `Blocking` instead.  Documentation explains.

# BREAKING: Rename `UnsupportedUnixAddressType` to `UnsupportedAfUnixAddressType`

No change to the semantics, just corrected terminology.

The old name is still present as a deprecated type alias, so some (but
not all) uses of the old name will still work for now.
