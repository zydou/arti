//! Declare error type for tor-netdir

use thiserror::Error;

/// An error returned by the network directory code
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// We don't have enough directory info to build circuits
    #[error("not enough directory information to build circuits")]
    NotEnoughInfo,
}
