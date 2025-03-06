### BREAKING: Rename `ConnectError::UnixAddressAccess` to `AfUnixSocketPathAccess` 

No change to the semantics, just corrected terminology

We have removed the old variant so that any code which actively matches
on this variant won't be silently broken.

### BREAKING: Abolished `ConnectError::InvalidUnixAddress`

This error was misnamed, had a description which didn't correspond to
its name, and was in any case never generated.
