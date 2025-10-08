BREAKING: `RouterStatus::addrs` now returns `impl Iterator<Item = SocketAddr>`.
BREAKING: `RouterStatus::orport_addrs` abolished; use `::addrs` instead.
BREAKING: Replace `ItemArgumentParseable for impl FromStr` with `NormalItemParseable`
ADDED: `Fingerprint` and `Base64Fingerprint` are now `Display`
ADDED: `impl From<Base64Fingerprint> for RsaIdentity`

