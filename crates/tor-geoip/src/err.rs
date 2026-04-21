//! Error types for GeoIP parsing.

use std::borrow::Cow;
use std::net::AddrParseError;
use std::num::ParseIntError;
use thiserror::Error;

/// An error type from the tor-geoip crate.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The GeoIP file is formatted wrong.
    #[error("Invalid GeoIP data file: {0}")]
    BadFormat(Cow<'static, str>),

    /// We got a country code that isn't 2 ASCII letters.
    #[error("Unsupported country code in file: {0}")]
    BadCountryCode(String),

    /// Tried to use ?? somewhere that expected a country code.
    #[error("The 'nowhere' country code ('??') is not supported in this context.")]
    NowhereNotSupported,
}

impl From<ParseIntError> for Error {
    fn from(_e: ParseIntError) -> Error {
        Error::BadFormat("can't parse number".into())
    }
}

impl From<AddrParseError> for Error {
    fn from(_e: AddrParseError) -> Error {
        Error::BadFormat("can't parse IPv6 address".into())
    }
}

impl From<crate::dense_range_map::Error> for Error {
    fn from(value: crate::dense_range_map::Error) -> Self {
        Error::BadFormat(value.to_string().into())
    }
}
