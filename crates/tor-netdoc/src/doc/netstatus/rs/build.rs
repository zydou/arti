//! Provide builder functionality for routerstatuses.

use crate::doc;
use crate::doc::netstatus::{RelayFlags, RelayWeight};
use crate::types::{ArgumentNotPresent, Base64Fingerprint};
use crate::{BuildError as Error, BuildResult as Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::net::SocketAddr;

pub(crate) mod md;
#[cfg(feature = "plain-consensus")]
pub(crate) mod plain;
