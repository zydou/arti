BREAKING: `ItemEncoder::object()` renamed to `.object_bytes()`
ADDED: `ItemEncoder::object()` taking an `ItemObjectEncodable`
ADDED: `ItemEncoder::text_sofar()`
BREAKING: `AuthCertUnverified::verify_self_signed()` renamed to `.verify()`
ADDED: `SpFingerprint`, `Fingerprint`, `Base64Fingerprint` `LongIdent` impl `From<RsaIdentity>`
BREAKING: `Microdesc::ed25519_id` is now stored as a `Ed25519IdentityLine`
