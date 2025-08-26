//! router status entries - items for all varieties, that vary
//!
//! **This file is reincluded multiple times**,
//! by the macros in [`crate::doc::ns_variety_definition_macros`],
//! once for votes, and once for each consensus flavour.
//! It is *not* a module `crate::doc::netstatus::rs::each_variety`.
//!
//! Each time this file is included by one of the macros mentioned above,
//! the `ns_***` macros (such as `ns_const_name!`) may expand to different values.
//!
//! See [`crate::doc::ns_variety_definition_macros`].

use super::*;

/// A single relay's status, in a network status document.
#[cfg_attr(
    feature = "dangerous-expose-struct-fields",
    visible::StructFields(pub),
    non_exhaustive
)]
#[derive(Debug, Clone)]
pub struct RouterStatus {
    /// The nickname for this relay.
    ///
    /// Nicknames can be used for convenience purpose, but no more:
    /// there is no mechanism to enforce their uniqueness.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) nickname: Nickname,
    /// Fingerprint of the old-style RSA identity for this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) identity: RsaIdentity,
    /// A list of address:port values where this relay can be reached.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) addrs: Vec<net::SocketAddr>,
    /// Digest of the document for this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) doc_digest: DocDigest,
    /// Flags applied by the authorities to this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) flags: RelayFlags,
    /// Version of the software that this relay is running.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) version: Option<Version>,
    /// List of subprotocol versions supported by this relay.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) protos: Arc<Protocols>,
    /// Information about how to weight this relay when choosing a
    /// relay at random.
    #[cfg_attr(docsrs, doc(cfg(feature = "dangerous-expose-struct-fields")))]
    pub(crate) weight: RelayWeight,
}
