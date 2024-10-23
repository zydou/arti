//! A module exporting timestamps types that can be encoded as [`Slug`]s.

use crate::slug::{BadSlug, Slug};

use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use derive_more::{From, Into};
use thiserror::Error;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};
use tor_error::{into_internal, Bug};

/// A UTC timestamp that can be encoded in ISO 8601 format,
/// and that can be used as a `Slug`.
///
/// The encoded timestamp does not have a `-` separator between date values,
/// or `:` between time values, or any spaces.
/// The encoding format is `[year][month][day][hour][minute][second]`.
///
/// # Example
///
/// ```
/// # use tor_persist::slug::timestamp::{Iso8601TimeSlug, BadIso8601TimeSlug};
/// # fn demo() -> Result<(), BadIso8601TimeSlug> {
///
/// let slug = "20241023130545".parse::<Iso8601TimeSlug>()?;
/// assert_eq!("20241023130545", slug.to_string());
///
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)] //
#[derive(Into, From)]
pub struct Iso8601TimeSlug(SystemTime);

/// The format of a [`Iso8601TimeSlug`].
const ISO_8601SP_FMT: &[FormatItem] =
    format_description!("[year][month][day][hour][minute][second]");

impl FromStr for Iso8601TimeSlug {
    type Err = BadIso8601TimeSlug;

    fn from_str(s: &str) -> Result<Iso8601TimeSlug, Self::Err> {
        let d = PrimitiveDateTime::parse(s, &ISO_8601SP_FMT)?;

        Ok(Iso8601TimeSlug(d.assume_utc().into()))
    }
}

impl TryInto<Slug> for Iso8601TimeSlug {
    type Error = Bug;

    fn try_into(self) -> Result<Slug, Self::Error> {
        Slug::new(self.to_string()).map_err(into_internal!("Iso8601TimeSlug is not a valid slug?!"))
    }
}

/// Error for an invalid `Iso8601TimeSlug`.
#[derive(Error, Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum BadIso8601TimeSlug {
    /// Invalid timestamp.
    #[error("Invalid timestamp")]
    Timestamp(#[from] time::error::Parse),

    /// The timestamp is not a valid slug.
    #[error("Invalid slug")]
    Slug(#[from] BadSlug),
}

impl fmt::Display for Iso8601TimeSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ts = OffsetDateTime::from(self.0)
            .format(ISO_8601SP_FMT)
            .map_err(|_| fmt::Error)?;

        write!(f, "{ts}")
    }
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::slug::TryIntoSlug as _;

    use super::*;
    use humantime::parse_rfc3339;

    #[test]
    fn timestamp_parsing() {
        const VALID_TIMESTAMP: &str = "20241023130545";
        const VALID_TIMESTAMP_RFC3339: &str = "2024-10-23T13:05:45Z";

        let t = VALID_TIMESTAMP.parse::<Iso8601TimeSlug>().unwrap();
        let t: SystemTime = t.into();
        assert_eq!(t, parse_rfc3339(VALID_TIMESTAMP_RFC3339).unwrap());

        assert!("2024-10-23 13:05:45".parse::<Iso8601TimeSlug>().is_err());
        assert!("20241023 13:05:45".parse::<Iso8601TimeSlug>().is_err());
        assert!("2024-10-23 130545".parse::<Iso8601TimeSlug>().is_err());
        assert!("20241023".parse::<Iso8601TimeSlug>().is_err());
        assert!("2024102313054".parse::<Iso8601TimeSlug>().is_err());
        assert!(format!("{VALID_TIMESTAMP}Z")
            .parse::<Iso8601TimeSlug>()
            .is_err());
        assert!("not a timestamp".parse::<Iso8601TimeSlug>().is_err());

        let parsed_timestamp = VALID_TIMESTAMP.parse::<Iso8601TimeSlug>().unwrap();
        assert_eq!(VALID_TIMESTAMP, parsed_timestamp.to_string());

        assert_eq!(
            VALID_TIMESTAMP,
            VALID_TIMESTAMP.parse::<Iso8601TimeSlug>().unwrap().to_string()
        );
    }
}
