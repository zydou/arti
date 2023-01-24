//! Declare an error type for the `tor-hsservice` crate.

use thiserror::Error;

/// An error affecting the operation of an onion service.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum Error {}
