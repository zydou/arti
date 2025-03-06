# BREAKING: `CfgAddrError::ConstructUnixAddress` renamed to `ConstructAfUnixAddress`

No change to the semantics, just corrected terminology

We have removed the old variant so that any code which actively matches
on this variant won't be silently broken.
