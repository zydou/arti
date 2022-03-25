//! A filtering mechanism for directory objects.
//!
//! This module and its members are only available when `tor-dirmgr` is built
//! with the `dirfilter` feature.
//!
//! This is unstable code, currently used for testing only.  It might go away in
//! future versions, or its API might change completely. There are no semver
//! guarantees.

use std::fmt::Debug;
use std::sync::Arc;

use crate::Result;
use tor_netdoc::doc::{microdesc::Microdesc, netstatus::UncheckedMdConsensus};

/// Filtering configuration, as provided to the directory code
pub type FilterConfig = Option<Arc<dyn DirFilter>>;

/// An object that can filter directory documents before they're handled.
///
/// Instances of DirFilter can be used for testing, to modify directory data
/// on-the-fly.
pub trait DirFilter: Debug + Send + Sync {
    /// Modify `consensus` in an unspecified way.
    fn filter_consensus(&self, consensus: UncheckedMdConsensus) -> Result<UncheckedMdConsensus> {
        Ok(consensus)
    }
    /// Modify `md` in an unspecified way.
    fn filter_md(&self, md: Microdesc) -> Result<Microdesc> {
        Ok(md)
    }
}

/// A [`DirFilter`] that does nothing.
#[derive(Debug)]
#[allow(clippy::exhaustive_structs)]
pub struct NilFilter;

impl DirFilter for NilFilter {}
