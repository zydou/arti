//! Code for parsing the relay specific config options.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use derive_deftly::Deftly;
use derive_more::Constructor;
use serde::{Deserialize, Serialize};
use tor_config::derive::prelude::*;
use tor_netdoc::types::{ContactInfo, Nickname};

use super::{BandwidthConfig, BandwidthConfigBuilder, DnsConfig, DnsConfigBuilder, Listen};
use crate::util::NonEmptyList;

/// Configuration for the "relay" part of the relay.
///
/// TODO: I'm not really sure what to call this yet. I'm expecting that we'll rename and reorganize
/// things as we add more options. But we should come back to this and update the name and/or doc
/// comment.
///
/// TODO: There's a high-level issue for discussing these options:
/// <https://gitlab.torproject.org/tpo/core/arti/-/issues/2252>
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[deftly(tor_config(no_default_trait))]
pub(crate) struct RelayConfig {
    /// The nickname of this relay.
    ///
    /// Nicknames are a legacy (and fun!) mechanism that is occasionally useful for
    /// debugging. They should never be used to uniquely identify a relay. Nothing
    /// prevents two relays from having the same nickname.
    ///
    /// It must be between 1 and 19 ASCII alphanumeric characters inclusive.
    #[deftly(tor_config(default = "default_nickname()"))]
    pub(crate) nickname: Nickname,

    /// Contact information for the operator(s) of this relay.
    ///
    /// This is published in the descriptor so that the network health team can reach you
    /// if there is a problem with the relay. It is free-form text but it must be a
    /// single line and must not start with whitespace.
    ///
    /// If unset, the descriptor is published without a contact information.
    //
    // TODO(relay): Before stable, we need to settle with Network Health team on the
    // format of that contact info. It will still be a free-form string in the descriptor
    // but we'll likely enforce a format at the config level.
    #[deftly(tor_config(default))]
    pub(crate) contact: Option<ContactInfo>,

    /// Addresses to listen on for incoming OR connections.
    #[deftly(tor_config(no_default))]
    pub(crate) listen: Listen,

    /// The DNS configuration.
    #[deftly(tor_config(sub_builder))]
    pub(crate) dns: DnsConfig,

    /// The bandwidth rate limiting configuration.
    #[deftly(tor_config(sub_builder))]
    pub(crate) bandwidth: BandwidthConfig,

    /// Addresses to advertise on the network for receiving OR connections.
    // For now, we've decided that we don't want to include any IP address auto-detection in
    // arti-relay, so we require users to provide the addresses to advertise. (So no `Option` and
    // `builder(default)` here).
    #[deftly(tor_config(no_default))]
    pub(crate) advertise: Advertise,
}

/// The address(es) to advertise on the network.
// TODO: We'll want to make sure we check that the addresses are valid before uploading them in a
// server descriptor (for example no `INADDR_ANY`, multicast, etc). We can't do that validation here
// during parsing, since we don't know exactly which addresses are valid or not. For example we
// don't know if local addresses are allowed as we don't know here whether the user plans to run a
// testing tor network. We also don't want to do the validation too late (for example when uploading
// the server descriptor) as it's better to validate at startup. A better place might be to perform
// the validation in the `RelayConfig` builder validate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Constructor)]
pub(crate) struct Advertise {
    /// All relays must advertise an IPv4 address.
    ///
    /// The first IPv4 address is considered the relay's primary address.
    ipv4: NonEmptyList<SocketAddrV4>,
    /// Relays may optionally advertise an IPv6 address.
    ipv6: Vec<SocketAddrV6>,
}

impl Advertise {
    /// Return all addresses (both IPv4 and IPv6) as in IP + Port ([`SocketAddr`]).
    pub(crate) fn all_addr(&self) -> Vec<SocketAddr> {
        self.ipv4
            .iter()
            .map(|s| (*s).into())
            .chain(self.ipv6.iter().map(|s| (*s).into()))
            .collect()
    }

    /// Return the primary IPv4 address.
    ///
    /// This is used to get the `router` line of our server descriptor.
    pub(crate) fn primary_ipv4(&self) -> &SocketAddrV4 {
        self.ipv4.iter().next().expect("No primary IPv4")
    }
}

/// Return the default relay nickname. Again, taken from C-tor.
pub(crate) fn default_nickname() -> Nickname {
    "Unnamed".parse().expect("Default nickname is invalid")
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[test]
    fn contact_valid() {
        for info in [
            "Arti relay team",
            "8096R/13371337 Rosa Park<rosa.park@awesome.com>",
            "trailing whitespace is fine  ",
            "Du français avec accent ééé, on aime!",
        ] {
            let contact: ContactInfo = info.parse().unwrap();
            assert_eq!(contact.to_string(), info);
        }
    }

    #[test]
    fn contact_invalid() {
        for info in [
            " leading whitespace", // Leading whitespace
            "\tleading tab",       // Same but with a tab
            "two\nlines",          // New line
            "trailing newline\n",  // Trailing new line
        ] {
            assert!(info.parse::<ContactInfo>().is_err());
        }
    }

    #[test]
    fn nickname_valid() {
        // Some basic names that are all valid.
        for name in ["Unnamed", "a", "42", "Op3nB0rd3rs", "A".repeat(19).as_str()] {
            let nickname: Nickname = name.parse().unwrap();
            assert_eq!(nickname.to_string(), name);
        }
    }

    #[test]
    fn nickname_invalid() {
        for name in [
            "",                      // Too short
            "A".repeat(20).as_str(), // Too long
            "with space",            // Windows spaces...
            "under_score",           // Non alphanumeric
            "dash-ing",              // Non alphanumeric
            "unicödé",               // The French... :P
        ] {
            assert!(name.parse::<Nickname>().is_err());
        }
    }
}
