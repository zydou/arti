#![doc = include_str!("README.md")]
//!
//! Constants are the file contents from CI, with names converted to SHOUTING_SNAKE_CASE.
//! TODO it would be nice if this data were more structured, like `testdata-live` is.

/// `testdata2/cached-certs`
pub const CACHED_CERTS: &str = include_str!("cached-certs");
/// `testdata2/cached-certs--1`
pub const CACHED_CERTS__1: &str = include_str!("cached-certs--1");
/// `testdata2/cached-certs--2`
pub const CACHED_CERTS__2: &str = include_str!("cached-certs--2");
/// `testdata2/cached-certs--3`
pub const CACHED_CERTS__3: &str = include_str!("cached-certs--3");
/// `testdata2/cached-certs--4`
pub const CACHED_CERTS__4: &str = include_str!("cached-certs--4");
/// `testdata2/cached-consensus`
pub const CACHED_CONSENSUS: &str = include_str!("cached-consensus");
/// `testdata2/cached-descriptors.new`
pub const CACHED_DESCRIPTORS_NEW: &str = include_str!("cached-descriptors.new");
/// `testdata2/cached-extrainfo.new`
pub const CACHED_EXTRAINFO_NEW: &str = include_str!("cached-extrainfo.new");
/// `testdata2/cached-microdesc-consensus`
pub const CACHED_MICRODESC_CONSENSUS: &str = include_str!("cached-microdesc-consensus");
/// `testdata2/cached-microdescs.new`
pub const CACHED_MICRODESCS_NEW: &str = include_str!("cached-microdescs.new");
/// `testdata2/consensus-transparency-microdesc`
pub const CONSENSUS_TRANSPARENCY_MICRODESC: &str = include_str!("consensus-transparency-microdesc");
/// `testdata2/consensus-transparency-ns`
pub const CONSENSUS_TRANSPARENCY_NS: &str = include_str!("consensus-transparency-ns");
/// `testdata2/fingerprint`
pub const FINGERPRINT: &str = include_str!("fingerprint");
/// `testdata2/fingerprint-ed25519`
pub const FINGERPRINT_ED25519: &str = include_str!("fingerprint-ed25519");
/// `testdata2/key-pinning-journal`
pub const KEY_PINNING_JOURNAL: &str = include_str!("key-pinning-journal");
/// `testdata2/keys`
pub mod keys {
/// `testdata2/keys/authority_certificate`
pub const AUTHORITY_CERTIFICATE: &str = include_str!("keys/authority_certificate");
/// `testdata2/keys/authority_identity_key`
pub const AUTHORITY_IDENTITY_KEY: &str = include_str!("keys/authority_identity_key");
/// `testdata2/keys/authority_signing_key`
pub const AUTHORITY_SIGNING_KEY: &str = include_str!("keys/authority_signing_key");
/// `testdata2/keys/ed25519_master_id_public_key`
pub const ED25519_MASTER_ID_PUBLIC_KEY: &[u8] = include_bytes!("keys/ed25519_master_id_public_key");
/// `testdata2/keys/ed25519_master_id_secret_key`
pub const ED25519_MASTER_ID_SECRET_KEY: &[u8] = include_bytes!("keys/ed25519_master_id_secret_key");
/// `testdata2/keys/ed25519_signing_cert`
pub const ED25519_SIGNING_CERT: &[u8] = include_bytes!("keys/ed25519_signing_cert");
/// `testdata2/keys/ed25519_signing_secret_key`
pub const ED25519_SIGNING_SECRET_KEY: &[u8] = include_bytes!("keys/ed25519_signing_secret_key");
/// `testdata2/keys/secret_id_key`
pub const SECRET_ID_KEY: &str = include_str!("keys/secret_id_key");
/// `testdata2/keys/secret_onion_key`
pub const SECRET_ONION_KEY: &str = include_str!("keys/secret_onion_key");
/// `testdata2/keys/secret_onion_key_ntor`
pub const SECRET_ONION_KEY_NTOR: &[u8] = include_bytes!("keys/secret_onion_key_ntor");
}
/// `testdata2/router-stability`
pub const ROUTER_STABILITY: &str = include_str!("router-stability");
/// `testdata2/sr-state`
pub const SR_STATE: &str = include_str!("sr-state");
/// `testdata2/state`
pub const STATE: &str = include_str!("state");
/// `testdata2/torrc`
pub const TORRC: &str = include_str!("torrc");
/// `testdata2/v3-status-votes`
pub const V3_STATUS_VOTES: &str = include_str!("v3-status-votes");
/// `testdata2/v3-status-votes--1`
pub const V3_STATUS_VOTES__1: &str = include_str!("v3-status-votes--1");
/// `testdata2/v3-status-votes--2`
pub const V3_STATUS_VOTES__2: &str = include_str!("v3-status-votes--2");
/// `testdata2/v3-status-votes--3`
pub const V3_STATUS_VOTES__3: &str = include_str!("v3-status-votes--3");
/// `testdata2/v3-status-votes--4`
pub const V3_STATUS_VOTES__4: &str = include_str!("v3-status-votes--4");
