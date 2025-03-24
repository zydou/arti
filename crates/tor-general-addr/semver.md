# BREAKING: `AddrParseError::InvalidUnixAddress` renamed to `InvalidAfUnixAddress`

No change to the semantics, just corrected terminology

We have removed the old variant so that any code which actively matches
on this variant won't be silently broken.

# BREAKING: `NoUnixAddressSupport` renamed to `NoAfUnixSocketSupport`

No change to the semantics, just corrected terminology.

The old name is still present as a deprecated type alias, so some (but
not all) uses of the old name will still work for now.
