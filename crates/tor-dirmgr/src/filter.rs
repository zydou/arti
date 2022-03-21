//! A filtering mechanism for directory objects.
//!
//! This module and its members are only available when `tor-dirmgr` is built
//! with the `dirfilter` feature.
//!
//! This is unstable code, currently used for testing only.  It might go away in
//! future versions, or its API might change completely. There are no semver
//! guarantees.

use std::sync::Arc;

use crate::Result;
use tor_netdoc::doc::{microdesc::Microdesc, netstatus::UncheckedMdConsensus};

/// An object that can filter directory documents before they're handled.
///
/// Instances of DirFilter can be used for testing, to modify directory data
/// on-the-fly.
pub trait DirFilter {
    /// Modify `consensus` in an unspecified way.
    fn filter_consensus(&self, consensus: UncheckedMdConsensus) -> Result<UncheckedMdConsensus>;
    /// Modify `md` in an unspecified way.
    fn filter_md(&self, md: Microdesc) -> Result<Microdesc>;
}

/// A dynamic [`DirFilter`] instance.
#[derive(Clone)]
pub struct DynFilter {
    /// A reference to the DirFilter object
    filter: Arc<dyn DirFilter + Send + Sync>,
}

impl From<&Option<DynFilter>> for DynFilter {
    fn from(option: &Option<DynFilter>) -> Self {
        option.as_ref().map(Clone::clone).unwrap_or_default()
    }
}

impl Default for DynFilter {
    fn default() -> Self {
        DynFilter::new(NilFilter)
    }
}

impl DynFilter {
    /// Wrap `filter` as a [`DynFilter`]
    pub fn new<T>(filter: T) -> Self
    where
        T: DirFilter + Send + Sync + 'static,
    {
        DynFilter {
            filter: Arc::new(filter),
        }
    }
}

impl DirFilter for DynFilter {
    fn filter_consensus(&self, consensus: UncheckedMdConsensus) -> Result<UncheckedMdConsensus> {
        self.filter.filter_consensus(consensus)
    }

    fn filter_md(&self, md: Microdesc) -> Result<Microdesc> {
        self.filter.filter_md(md)
    }
}

impl std::fmt::Debug for DynFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynFilter").finish_non_exhaustive()
    }
}

/// A [`DirFilter`] that does nothing.
struct NilFilter;

impl DirFilter for NilFilter {
    fn filter_consensus(&self, consensus: UncheckedMdConsensus) -> Result<UncheckedMdConsensus> {
        Ok(consensus)
    }
    fn filter_md(&self, md: Microdesc) -> Result<Microdesc> {
        Ok(md)
    }
}
