//! Code for building paths for HS circuits.

use rand::Rng;
use tor_linkspec::OwnedChanTarget;
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage};

use crate::{Error, Result};

use super::AnonymousPathBuilder;

use {
    crate::path::TorPath,
    crate::{DirInfo, PathConfig},
    std::time::SystemTime,
    tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable},
    tor_rtcompat::Runtime,
};

/// A path builder for hidden service circuits.
pub struct HsPathBuilder {
    /// If present, a "target" that every chosen relay must be able to share a circuit with with.
    compatible_with: Option<OwnedChanTarget>,
}

impl HsPathBuilder {
    /// Create a new builder that will try to build a three-hop non-exit path
    /// for use with the onion services protocols
    /// that is compatible with being extended to an optional given relay.
    ///
    /// (The provided relay is _not_ included in the built path: we only ensure
    /// that the path we build does not have any features that would stop us
    /// extending it to that relay as a fourth hop.)
    pub(crate) fn new(compatible_with: Option<OwnedChanTarget>) -> Self {
        Self { compatible_with }
    }
}

impl<'a> AnonymousPathBuilder<'a> for HsPathBuilder {
    fn chosen_exit(&self) -> Option<&Relay<'_>> {
        None
    }

    fn compatible_with(&self) -> Option<&OwnedChanTarget> {
        self.compatible_with.as_ref()
    }

    fn path_kind(&self) -> &'static str {
        "onion-service circuit"
    }

    fn pick_exit<'s, R: Rng>(
        &'s self,
        rng: &mut R,
        netdir: &'a NetDir,
        guard_exclusion: RelayExclusion<'a>,
        _rs_cfg: &RelaySelectionConfig<'_>,
    ) -> Result<(Relay<'a>, RelayUsage)> {
        // TODO: This usage is a bit convoluted, and some onion-service-
        // related circuits don't need this much stability.
        let usage = RelayUsage::middle_relay(Some(&RelayUsage::new_intro_point()));
        let selector = RelaySelector::new(usage, guard_exclusion);

        let (relay, info) = selector.select_relay(rng, netdir);
        let relay = relay.ok_or_else(|| Error::NoRelay {
            path_kind: self.path_kind(),
            role: "final hop",
            problem: info.to_string(),
        })?;
        Ok((relay, RelayUsage::middle_relay(Some(selector.usage()))))
    }

    #[cfg(feature = "vanguards")]
    fn pick_path<'s, R: Rng, RT: Runtime>(
        &'s self,
        _rng: &mut R,
        _netdir: DirInfo<'a>,
        _guards: Option<&GuardMgr<RT>>,
        _config: &PathConfig,
        _now: SystemTime,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        // TODO HS-VANGUARDS (#1279): this will likely share some logic with
        // AnonymousPathBuilder::pick_path, so we might want to split
        // AnonymousPathBuilder::pick_path into multiple smaller functions
        // that we can use here
        todo!()
    }
}
