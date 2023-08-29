//! Configuration information for onion services.
//
// TODO HSS: We may want rename some of the types and members here!

use std::path::PathBuf;

use tor_llcrypto::pk::curve25519;

use crate::HsNickname;

/// Configuration for an onion service.
#[derive(Debug, Clone)]
pub struct OnionServiceConfig {
    /// The nickname used to look up this service's keys, state, configuration, etc,
    //
    // TODO HSS: It's possible that instead of having this be _part_ of the
    // service's configuration, we want this to be the key for a map in
    // which the service's configuration is stored.  We'll see how the code
    // evolves.
    // (^ ipt_mgr::IptManager contains a copy of this nickname, that should be fixed too)
    name: HsNickname,

    // TODO HSS: Perhaps this belongs at a higher level.
    // enabled: bool,
    /// Whether we want this to be a non-anonymous "single onion service".
    /// We could skip this in v1.  We should make sure that our state
    /// is built to make it hard to accidentally set this.
    anonymity: crate::Anonymity,

    /// Number of intro points; defaults to 3; max 20.
    /// TODO HSS config this Option should be defaulted prior to the value ending up here
    pub(crate) num_intro_points: Option<u8>,

    /// Limits on rates and concurrency of connections to our service.
    limits: LimitConfig,

    /// Configure proof-of-work defense against DoS attacks.
    pow: PowConfig,

    /// Configure descriptor-based client authorization.
    ///
    /// When this is enabled, we encrypt our list of introduction point and keys
    /// so that only clients holding one of the listed keys can decrypt it.
    encrypt_descriptor: Option<DescEncryptionConfig>,
    //
    // TODO HSS: Do we want a "descriptor_lifetime" setting? C tor doesn't have
    // one.
}

/// Configuration for maximum rates and concurrency.
#[derive(Debug, Clone)]
pub struct LimitConfig {
    /// A rate-limit on the acceptable rate of introduction requests.
    ///
    /// We send this to the send to the introduction point to configure how many
    /// introduction requests it sends us.
    rate_limit_at_intro: Option<TokenBucketConfig>,

    /// How many streams will we allow to be open at once for a single circuit on
    /// this service?
    max_concurrent_streams_per_circuit: u16,
}

/// Configuration for proof-of-work defense against DoS attacks.
#[derive(Debug, Clone)]
pub struct PowConfig {
    /// If true, we will require proof-of-work when we're under heavy load.
    enable_pow: bool,
    /// Disable the compiled backend for proof-of-work.
    disable_pow_compilation: bool,
    // TODO HSS: C tor has this, but I don't know if we want it.
    // /// A rate-limit on dispatching requests from the request queue when
    // /// our proof-of-work defense is enabled.
    // pow_queue_rate: TokenBucketConfig,
    // ...
}

/// Configure a token-bucket style limit on some process.
//
// TODO HSS: possibly lower this; it will be used in far more places.
#[derive(Debug, Clone)]
pub struct TokenBucketConfig {
    /// The maximum number of items to process per second.
    rate: u32,
    /// The maximum number of items to process in a single burst.
    burst: u32,
}

/// Configuration for descriptor encryption.
#[derive(Debug, Clone)]
pub struct DescEncryptionConfig {
    /// A list of our authorized clients.
    ///
    /// Note that if this list is empty, no clients can connect.  
    authorized_client: Vec<AuthorizedClientConfig>,
}

/// A single client (or a collection of clients) authorized using the descriptor encryption mechanism.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthorizedClientConfig {
    /// A directory full of authorized public keys.
    DirectoryOfKeys(PathBuf),
    /// A single authorized public key.
    // TODO HSS: Use the appropriate wrapper type.
    Curve25519Key(curve25519::PublicKey),
}
