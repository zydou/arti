//! Configuration logic for tor-ptmgr.

use std::net::SocketAddr;

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{impl_standard_builder, CfgPath, ConfigBuildError};
use tor_linkspec::PtTransportName;
use tor_socksproto::SocksVersion;

use crate::ipc::PtClientMethod;

/// A single pluggable transport.
///
/// Pluggable transports are programs that transform and obfuscate traffic on
/// the network between a Tor client and a Tor bridge, so that an adversary
/// cannot recognize it as Tor traffic.
///
/// A pluggable transport can be either _managed_ (run as an external process
/// that we launch and monitor), or _unmanaged_ (running on a local port, not
/// controlled by Arti).
#[derive(Clone, Debug, Builder, Eq, PartialEq)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError", validate = "Self::validate"))]
pub struct TransportConfig {
    /// Names of the transport protocols that we are willing to use from this transport.
    ///
    /// (These protocols are arbitrary identifiers that describe which protocols
    /// we want. They must match names that the binary knows how to provide.)
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    pub(crate) protocols: Vec<PtTransportName>,

    /// The path to the binary to run, if any.
    ///
    /// This needs to be the path to some executable file on disk.
    ///
    /// Present only for managed transports.
    #[builder(default, setter(strip_option))]
    pub(crate) path: Option<CfgPath>,

    /// One or more command-line arguments to pass to the binary.
    ///
    /// Meaningful only for managed transports.
    // TODO: Should this be OsString? That's a pain to parse...
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    #[builder(default)]
    pub(crate) arguments: Vec<String>,

    /// The location at which to contact this transport.
    ///
    /// Present only for unmanaged transports.
    #[builder(default, setter(strip_option))]
    pub(crate) proxy_addr: Option<SocketAddr>,

    /// If true, launch this transport on startup.  Otherwise, we launch
    /// it on demand.
    ///
    /// Meaningful only for managed transports.
    #[builder(default)]
    pub(crate) run_on_startup: bool,
}

impl_standard_builder! { TransportConfig: !Default }

impl TransportConfig {
    /// Return true if this transport is managed.
    pub(crate) fn is_managed(&self) -> bool {
        self.path.is_some()
    }

    /// If this is an unmanaged transport, return a client method that can be
    /// used to contact it.
    pub(crate) fn cmethod_for_unmanaged_pt(&self) -> Option<PtClientMethod> {
        self.proxy_addr.map(|a| PtClientMethod {
            // TODO: Someday we might want to support other protocols;
            // but for now, let's see if we can get away with just socks5.
            kind: SocksVersion::V5,
            endpoint: a,
        })
    }
}

impl TransportConfigBuilder {
    /// Inspect the list of protocols (ie, transport names)
    ///
    /// If none have yet been specified, returns an empty list.
    pub fn get_protocols(&self) -> &[PtTransportName] {
        self.protocols.as_deref().unwrap_or_default()
    }

    /// Make sure that this builder is internally consistent.
    fn validate(&self) -> Result<(), ConfigBuildError> {
        match (&self.path, &self.proxy_addr) {
            (Some(_), Some(_)) => Err(ConfigBuildError::Inconsistent {
                fields: vec!["path".into(), "proxy_addr".into()],
                problem: "Cannot provide both path and proxy_addr".into(),
            }),
            // TODO: There is no ConfigBuildError for "one of two fields is missing."
            (None, None) => Err(ConfigBuildError::MissingField {
                field: "{path or proxy_addr}".into(),
            }),
            (None, Some(_)) => {
                if self.arguments.as_ref().is_some_and(|v| !v.is_empty()) {
                    Err(ConfigBuildError::Inconsistent {
                        fields: vec!["proxy_addr".into(), "arguments".into()],
                        problem: "Cannot provide arguments for an unmanaged transport".into(),
                    })
                } else if self.run_on_startup.is_some() {
                    Err(ConfigBuildError::Inconsistent {
                        fields: vec!["proxy_addr".into(), "run_on_startup".into()],
                        problem: "run_on_startup is meaningless for an unmanaged transport".into(),
                    })
                } else {
                    Ok(())
                }
            }
            (Some(_), None) => Ok(()),
        }
    }
}
