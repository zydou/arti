#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
//! `tor-ptmgr`: Manage a set of anti-censorship pluggable transports.
//!
//! # Overview
//!
//! This crate is part of [Arti](https://gitlab.torproject.org/tpo/core/arti/),
//! a project to implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In Tor, a "transport" is a mechanism used to avoid censorship by disguising
//! the Tor protocol as some other kind of traffic.
//!
//! A "pluggable transport" is one that is not implemented by default as part of
//! the Tor protocol, but which can instead be added later on by the packager or
//! the user.  Pluggable transports are typically provided as external binaries
//! that implement a SOCKS proxy, along with certain other configuration
//! protocols.
//!
//! This crate provides a means to manage a set of configured pluggable
//! transports
//!
//! # Limitations
//!
//! TODO pt-client: Currently, the APIs for this crate make it quite
//! tor-specific.  Notably, it can only return Channels!  It would be good
//! instead to adapt it so that it was more generally useful by other projects
//! that want to use pluggable transports in rust.  For now, I have put the
//! Tor-channel-specific stuff behind a `tor-channel-factory` feature, but there
//! are no APIs for using PTs without that feature currently.  That should
//! change.
//!
//! TODO pt-client: Nothing in this crate is actually implemented yet.
//!
//! TODO pt-client: The first version of this crate will probably only conform
//! to the old Tor pluggable transport protocol, and not to more recent variants
//! as documented at `pluggabletransports.info`

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod config;

use config::PtMgrConfig;

use async_trait::async_trait;
#[cfg(feature = "tor-channel-factory")]
use tor_chanmgr::factory::ChannelFactory;
use tor_linkspec::TransportId;
use tor_rtcompat::Runtime;

/// A pluggable transport manager knows how to make different
/// kinds of connections to the Tor network, for censorship avoidance.
///
/// Currently, we only support two kinds of pluggable transports: Those
/// configured in a PtConfig object, and those added with PtMgr::register.
//
// TODO: Will we need a <R:Runtime constraint> here? I don't know. -nickm
#[derive(Clone, Debug)]
pub struct PtMgr<R> {
    /// An underlying `Runtime`, used to spawn background tasks.
    runtime: R,
}

#[allow(clippy::missing_panics_doc, clippy::needless_pass_by_value)]
impl<R: Runtime> PtMgr<R> {
    /// Create a new PtMgr.
    pub fn new(cfg: PtMgrConfig, rt: R) -> Self {
        let _ = (cfg, rt);
        todo!("TODO pt-client: implement this.")
    }
    /// Reload the configuration
    pub fn reconfigure(&self, cfg: PtMgrConfig) -> Result<(), tor_config::ReconfigureError> {
        let _ = cfg;
        todo!("TODO pt-client: implement this.")
    }
    /// Manually add a new channel factory to this registry.
    #[cfg(feature = "tor-channel-factory")]
    pub fn register_factory(&self, ids: &[TransportId], factory: impl ChannelFactory) {
        let _ = (ids, factory);
        todo!("TODO pt-client: implement this.")
    }

    // TODO pt-client: Possibly, this should have a separate function to launch
    // its background tasks.
}

#[cfg(feature = "tor-channel-factory")]
#[allow(clippy::missing_panics_doc)]
#[async_trait]
impl<R: Runtime> tor_chanmgr::factory::TransportRegistry for PtMgr<R> {
    // There is going to be a lot happening "under the hood" here.
    //
    // When we are asked to get a ChannelFactory for a given
    // connection, we will need to:
    //    - launch the binary for that transport if it is not already running*.
    //    - If we launched the binary, talk to it and see which ports it
    //      is listening on.
    //    - Return a ChannelFactory that connects via one of those ports,
    //      using the appropriate version of SOCKS, passing K=V parameters
    //      encoded properly.
    //
    // * As in other managers, we'll need to avoid trying to launch the same
    //   transport twice if we get two concurrent requests.
    //
    // Later if the binary crashes, we should detect that.  We should relaunch
    // it on demand.
    //
    // On reconfigure, we should shut down any no-longer-used transports.
    //
    // Maybe, we should shut down transports that haven't been used
    // for a long time.

    async fn get_factory(&self, transport: &TransportId) -> Option<&dyn ChannelFactory> {
        let _ = transport;
        let _ = &self.runtime;
        todo!("TODO pt-client")
    }
}
