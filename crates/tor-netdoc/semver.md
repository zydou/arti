BREAKING: `ItemEncoder::object()` renamed to `.object_bytes()`
ADDED: `ItemEncoder::object()` taking an `ItemObjectEncodable`
ADDED: `ItemEncoder::text_sofar()`
BREAKING: `AuthCertUnverified::verify_self_signed()` renamed to `.verify()`
ADDED: `SpFingerprint`, `Fingerprint`, `Base64Fingerprint` `LongIdent` impl `From<RsaIdentity>`
BREAKING: `Microdesc::ed25519_id` is now stored as a `Ed25519IdentityLine`
BREAKING: `Microdesc::family_ids` is now stored as a `RelayFamilyIds`
BREAKING: `Microdesc::ntor_onion_key` is now stored as a `Curve25519Public`
BREAKING: `PortRange`'s fields are private now
ADDED: `types::ContactInfo`
ADDED: `types::B64` implements `Deref`, `DerefMut`, various `AsRef`/`AsMut`
ADDED: `types::FixedB64`
ADDED: `types::B64`'s field is now `pub`
BREAKING: Removed `types::B64::into_array`; use methods on `Vec` and slice instead
ADDED: `types::B16`, `types::B16U`
ADDED: `types::Curve25519Public` impls `Deref`, `DerefMut`, `AsRef`, `AsMut`
ADDED: `types::Iso8601TimeSp`, `Iso8601TimeSp` impl `AsRef`, `AsMut`
ADDED: `types::SpFingerprint`, `Fingerprint`, `Base64Fingerprint`, `LongIdent`, impl `Hash`, `AsRef`, `AsMut`
ADDED: `types::Hostname`, `types::InternetHost`
BREAKING: `types::Nickname`, `FromStr` error type is now `InvalidNickname`
ADDED: `#[deftly(netdoc(skip))]` supported in `ItemValueParseable` and `ItemValueEncodable` derives
ADDED: Encoding traits implemented for `Arc<T>`
BREAKING: `netstatus::Preamble.consensus_method` and `.published` are now 1-element tuples.
ADDED: `ItemValueEncodable` impl for `ConsensusMethods`
ADDED: `doc::netstatus::Lifetime` fields are `pub`, and added `LifetimeConstructor`
