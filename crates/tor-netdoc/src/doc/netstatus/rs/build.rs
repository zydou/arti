//! Provide builder functionality for routerstatuses.

use super::{GenericRouterStatus, MdConsensusRouterStatus};
use crate::doc;
use crate::doc::microdesc::MdDigest;
use crate::doc::netstatus::{RelayFlags, RelayWeight};
use crate::{BuildError as Error, BuildResult as Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::net::SocketAddr;

#[cfg(feature = "plain-consensus")]
pub(crate) mod plain;
pub(crate) mod md;

#[cfg(feature = "plain-consensus")]
use super::PlainConsensusRouterStatus;
#[cfg(feature = "plain-consensus")]
use crate::doc::routerdesc::RdDigest;
