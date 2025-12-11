//! Record information about where we are listening to a file,
//! so that other programs can find it without going through RPC.
//!
//! ## File format
//!
//! The file holds a single json Object, containing the key "ports".
//!
//! The "ports" entry contains a list.
//! Each entry in "ports" is a json Object containing these fields:
//!
//! * "protocol" - one of "socks", "http", or "dns_udp".
//! * "address" - An IPv4 or IPv6 socket address, prefixed with the string "inet:".
//!
//! All software using this format MUST ignore:
//! - unrecognized keys in json Objects,
//! - entries in the "ports" list with unrecognized "protocol"s
//! - entries in "ports" whose "address" fields are null.
//! - entries in "ports" whose "address" fields have an unrecognized prefix (not "inet:").
//!
//! (Note that as with other formats, we may break this across Arti major versions,
//! though we will make our best effort not to do so.)
//!
//! ## Liveness
//!
//! Arti updates this file whenever on startup, when it binds to its ports.
//! It does not try to delete the file on shutdown, however,
//! and on a crash or unexpected SIGKILL,
//! it will have no opportunity to delete the file.
//! Therefore, you should not assume that the file will always be up to date,
//! or that the ports will not be bound by some other program.

use std::path::Path;

use anyhow::{Context as _, anyhow};
use fs_mistrust::{Mistrust, anon_home::PathExt as _};
use serde::{Serialize, Serializer};
use tor_general_addr::general;

/// Information about all the ports we are listening on as a proxy.
///
/// (RPC is handled differently; see `tor-rpc-connect-port` for info.)
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct PortInfo {
    /// A list of the ports that we're listening on.
    pub(crate) ports: Vec<Port>,
}

impl PortInfo {
    /// Serialize this port information and write it to a chosen file.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn write_to_file(&self, mistrust: &Mistrust, path: &Path) -> anyhow::Result<()> {
        let s = serde_json::to_string(self)?;

        let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
            return Err(anyhow!(
                "port_info_file {} is not something we can write to",
                path.anonymize_home()
            ));
        };

        // Create the parent directory if it isn't there.
        // TODO #2267.
        let parent = if parent.to_str() == Some("") {
            Path::new(".")
        } else {
            parent
        };
        let dir = mistrust
            .verifier()
            .permit_readable()
            .make_secure_dir(parent)
            .with_context(|| {
                format!(
                    "Creating parent directory for port_info_file {}",
                    path.anonymize_home()
                )
            })?;

        dir.write_and_replace(file_name, s)
            .with_context(|| format!("Unable to write port_info_file {}", path.anonymize_home()))?;

        Ok(())
    }
}

/// Representation of a single port in a port_info.json file.
///
/// Each port corresponds to a single address, and a protocol that can be spoken at this address.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct Port {
    /// A protocol that this port expects.
    ///
    /// If the address accepts multiple protocols, there will be multiple [`Port`] entries in the [`PortInfo`],
    /// with the same address.
    pub(crate) protocol: SupportedProtocol,
    /// The address we're listening on.
    ///
    /// (Right now, this is always an Inet address, but we intend to support AF_UNIX in the future.
    /// See [arti#1965](https://gitlab.torproject.org/tpo/core/arti/-/issues/1965))
    #[serde(serialize_with = "serialize_address")]
    pub(crate) address: general::SocketAddr,
}

/// Helper: serialize a general::SocketAddr as a string if possible,
/// or as None if it can't be represented as a string.
fn serialize_address<S: Serializer>(addr: &general::SocketAddr, ser: S) -> Result<S::Ok, S::Error> {
    match addr.try_to_string() {
        Some(string) => ser.serialize_str(&string),
        None => ser.serialize_none(),
    }
}

/// A protocol that a given port supports.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[allow(unused)] // Some of these variants are feature-dependent.
#[non_exhaustive]
pub(crate) enum SupportedProtocol {
    /// SOCKS4, SOCKS4a, and SOCKS5; all with Tor extensions.
    #[serde(rename = "socks")]
    Socks,
    /// HTTP CONNECT with Tor extensions.
    #[serde(rename = "http")]
    Http,
    /// DNS over UDP.
    #[serde(rename = "dns_udp")]
    DnsUdp,
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::str::FromStr;

    use super::*;

    #[test]
    fn format() {
        use SupportedProtocol::*;
        let pi = PortInfo {
            ports: vec![Port {
                protocol: Socks,
                address: "127.0.0.1:99".parse().unwrap(),
            }],
        };
        let got = serde_json::to_string(&pi).unwrap();
        let expected = r#"
        { "ports" : [ {"protocol":"socks", "address":"inet:127.0.0.1:99"} ] }
        "#;
        assert_eq!(
            serde_json::Value::from_str(&got).unwrap(),
            serde_json::Value::from_str(expected).unwrap()
        );
    }
}
