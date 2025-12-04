//! Provide builder functionality for routerstatuses.

use crate::doc::netstatus::{IgnoredPublicationTimeSp, RelayWeight};
use crate::types::relay_flags::{DocRelayFlags, RelayFlags};
use crate::types::{Base64Fingerprint, NotPresent, Unknown};
use crate::{BuildError as Error, BuildResult as Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::net::SocketAddr;

pub(crate) mod md;
#[cfg(feature = "plain-consensus")]
pub(crate) mod plain;
