//! Types for parsing socket listen related config options.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// A collection of socket addresses to listen to.
///
/// This is somewhat similar to `tor_config::listen::Listen`,
/// but is intended for public listeners rather than loopback listeners.
/// For example in `tor_config::listen::Listen`, a value of "200" will be interpreted as
/// "127.0.0.1:8080", whereas here we want to interpret it as "0.0.0.0:8080".
/// We also have more flexibility to change things here where it won't break arti's config parsing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedListen")]
// We use a `BTreeSet` here for (1) ensuring there are no duplicates and (2) deterministic ordering
// compared to a `HashSet`.
pub(crate) struct Listen(BTreeSet<SocketAddr>);

impl Listen {
    /// The addresses to listen on.
    pub(crate) fn addrs(&self) -> impl Iterator<Item = &SocketAddr> + Clone {
        self.0.iter()
    }
}

/// A deserialize helper for [`Listen`].
///
/// This is a `Listen` that has not yet been validated.
#[derive(Deserialize)]
// TODO: "untagged" has error messages that are useless for users;
// we should implement `Deserialize` ourselves to give a useful message.
#[serde(untagged, rename = "Listen")]
enum UncheckedListen {
    /// Listen on a port for all IPv4 and IPv6 addresses (`0.0.0.0` and `[::]`).
    Port(u16),
    /// Listen on a set of socket addresses.
    Addr(Vec<SocketAddr>),
}

impl TryFrom<UncheckedListen> for Listen {
    type Error = ListenError;

    fn try_from(from: UncheckedListen) -> Result<Self, Self::Error> {
        // We don't allow a port of 0 to be consistent with arti's proxy port config.
        // We also don't want an "auto" port option at the moment.
        // TODO: Maybe accept and handle network interface names to bind to.
        match from {
            UncheckedListen::Port(port @ 0) => Err(ListenError::InvalidPort { ip: None, port }),
            UncheckedListen::Port(port) => {
                // Listen at 0.0.0.0 and [::].
                let addrs: [IpAddr; 2] =
                    [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()];
                let addrs = addrs
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect();
                Ok(Self(addrs))
            }
            UncheckedListen::Addr(addrs) => {
                // Ensure that no address had a port of 0.
                for addr in &addrs {
                    if addr.port() == 0 {
                        return Err(ListenError::InvalidPort {
                            ip: Some(addr.ip()),
                            port: addr.port(),
                        });
                    }
                }

                // Ensure that there were no duplicates.
                let count = addrs.len();
                let addrs: BTreeSet<_> = addrs.into_iter().collect();
                if addrs.len() != count {
                    return Err(ListenError::Duplicates);
                }

                Ok(Self(addrs))
            }
        }
    }
}

/// An error while deserializing a [`Listen`].
#[derive(Copy, Clone, Debug, thiserror::Error)]
pub(crate) enum ListenError {
    /// An invalid port was given.
    #[error(
        "{} does not have a valid port",
        .ip.map(|ip| SocketAddr::new(ip, *.port).to_string()).unwrap_or_else(|| .port.to_string()),
    )]
    InvalidPort {
        /// If this port was attached to an IP address, then the IP address can be provided here to
        /// give a better error message.
        ip: Option<IpAddr>,
        /// The invalid port.
        port: u16,
    },
    /// Duplicate socket addresses were given.
    #[error("duplicate socket addresses were given")]
    Duplicates,
}
