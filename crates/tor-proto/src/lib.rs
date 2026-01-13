#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #2010: Remove this global allow, and either propagate it to the functions that need it,
// or make those functions less complex.
#![allow(clippy::cognitive_complexity)]
// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(
    not(all(feature = "full", feature = "experimental")),
    allow(unused, unreachable_pub)
)]

#[cfg(feature = "bench")]
pub mod bench_utils;
pub mod channel;
pub mod circuit;
pub mod client;
pub(crate) mod conflux;
mod congestion;
mod crypto;
pub mod memquota;
mod stream;
pub(crate) mod streammap;
pub(crate) mod tunnel;
mod util;

#[cfg(feature = "relay")]
pub mod relay;
#[cfg(feature = "relay")]
pub use relay::channel::{RelayChannelBuilder, RelayIdentities};

pub use util::err::{Error, ResolveError};
pub use util::skew::ClockSkew;

pub use channel::params::ChannelPaddingInstructions;
pub use client::{ClientTunnel, HopLocation, TargetHop, channel::ClientChannelBuilder};
pub use congestion::params as ccparams;
pub use crypto::cell::{HopNum, HopNumDisplay};
pub use stream::flow_ctrl::params::{CellCount, FlowCtrlParameters};
#[cfg(feature = "send-control-msg")]
pub use {
    crate::client::Conversation,
    crate::client::msghandler::{MsgHandler, UserMsgHandler},
    crate::client::reactor::MetaCellDisposition,
};

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

use std::fmt::Debug;
use tor_memquota::{
    HasMemoryCost,
    mq_queue::{self, ChannelSpec as _},
};
use tor_rtcompat::DynTimeProvider;

#[doc(hidden)]
pub use {derive_deftly, tor_memquota};

/// Timestamp object that we update whenever we get incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
static LAST_INCOMING_TRAFFIC: util::ts::AtomicOptTimestamp = util::ts::AtomicOptTimestamp::new();

/// Called whenever we receive incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
#[inline]
pub(crate) fn note_incoming_traffic() {
    LAST_INCOMING_TRAFFIC.update();
}

/// Return the amount of time since we last received "incoming traffic".
///
/// This is a global counter, and is subject to interference from
/// other users of the `tor_proto`.  Its only permissible use is for
/// checking how recently we have been definitely able to receive
/// incoming traffic.
///
/// When enabled, this timestamp is updated whenever we receive a valid
/// cell, and whenever we complete a channel handshake.
///
/// Returns `None` if we never received "incoming traffic".
pub fn time_since_last_incoming_traffic() -> Option<std::time::Duration> {
    LAST_INCOMING_TRAFFIC.time_since_update().map(Into::into)
}

/// Make an MPSC queue, of any type, that participates in memquota, but a fake one for testing
#[cfg(any(test, feature = "testing"))] // Used by Channel::new_fake which is also feature=testing
pub(crate) fn fake_mpsc<T: HasMemoryCost + Debug + Send>(
    buffer: usize,
) -> (
    mq_queue::Sender<T, mq_queue::MpscSpec>,
    mq_queue::Receiver<T, mq_queue::MpscSpec>,
) {
    mq_queue::MpscSpec::new(buffer)
        .new_mq(
            // The fake Account doesn't care about the data ages, so this will do.
            //
            // Thiw would be wrong to use generally in tests, where we might want to mock time,
            // since we end up, here with totally *different* mocked time.
            // But it's OK here, and saves passing a runtime parameter into this function.
            DynTimeProvider::new(tor_rtmock::MockRuntime::default()),
            &tor_memquota::Account::new_noop(),
        )
        .expect("create fake mpsc")
}

/// Return a list of the protocols [supported](tor_protover::doc_supported)
/// by this crate, running as a client.
pub fn supported_client_protocols() -> tor_protover::Protocols {
    use tor_protover::named::*;
    // WARNING: REMOVING ELEMENTS FROM THIS LIST CAN BE DANGEROUS!
    // SEE [`tor_protover::doc_changing`]
    let mut protocols = vec![
        LINK_V4,
        LINK_V5,
        LINKAUTH_ED25519_SHA256_EXPORTER,
        FLOWCTRL_AUTH_SENDME,
        RELAY_NTOR,
        RELAY_EXTEND_IPv6,
        RELAY_NTORV3,
        RELAY_NEGOTIATE_SUBPROTO,
    ];
    #[cfg(feature = "flowctl-cc")]
    protocols.push(FLOWCTRL_CC);
    #[cfg(feature = "counter-galois-onion")]
    protocols.push(RELAY_CRYPT_CGO);

    protocols.into_iter().collect()
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

    use cfg_if::cfg_if;

    use super::*;

    #[test]
    fn protocols() {
        let pr = supported_client_protocols();
        cfg_if! {
            if #[cfg(all(feature="flowctl-cc", feature="counter-galois-onion"))] {
                let expected = "FlowCtrl=1-2 Link=4-5 LinkAuth=3 Relay=2-6".parse().unwrap();
            } else if #[cfg(feature="flowctl-cc")] {
                let expected = "FlowCtrl=1-2 Link=4-5 LinkAuth=3 Relay=2-5".parse().unwrap();
                // (Note that we don't have to check for cgo without cc, since that isn't possible.)
            } else {
                let expected = "FlowCtrl=1 Link=4-5 LinkAuth=3 Relay=2-5".parse().unwrap();
            }
        }
        assert_eq!(pr, expected);
    }
}
