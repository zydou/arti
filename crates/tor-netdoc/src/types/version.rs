//! Parsing and comparison for Tor versions
//!
//! Tor versions use a slightly unusual encoding described in Tor's
//! [version-spec.txt](https://spec.torproject.org/version-spec).
//! Briefly, version numbers are of the form
//!
//! `MAJOR.MINOR.MICRO[.PATCHLEVEL][-STATUS_TAG][ (EXTRA_INFO)]*`
//!
//! Here we parse everything up to the first space, but ignore the
//! "EXTRA_INFO" component.
//!
//! Why does Arti have to care about Tor versions?  Sometimes a given
//! Tor version is broken for one purpose or another, and it's
//! important to avoid using them for certain kinds of traffic.  (For
//! planned incompatibilities, you should use protocol versions
//! instead.)
//!
//! # Examples
//!
//! ```
//! use tor_netdoc::types::version::TorVersion;
//! let older: TorVersion = "0.3.5.8".parse()?;
//! let latest: TorVersion = "0.4.3.4-rc".parse()?;
//! assert!(older < latest);
//!
//! # tor_netdoc::Result::Ok(())
//! ```
//!
//! # Limitations
//!
//! This module handles the version format which Tor has used ever
//! since 0.1.0.1-rc.  Earlier versions used a different format, also
//! documented in
//! [version-spec.txt](https://spec.torproject.org/version-spec).
//! Fortunately, those versions are long obsolete, and there's not
//! much reason to parse them.
//!
//! TODO: Possibly, this module should be extracted into a crate of
//! its own.  I'm not 100% sure though -- does anything need versions
//! but not network docs?

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use crate::{NetdocErrorKind as EK, Pos};

/// Represents the status tag on a Tor version number
///
/// Status tags indicate that a release is alpha, beta (seldom used),
/// a release candidate (rc), or stable.
///
/// We accept unrecognized tags, and store them as "Other".
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
enum TorVerStatus {
    /// An unknown release status
    Other,
    /// An alpha release
    Alpha,
    /// A beta release
    Beta,
    /// A release candidate
    Rc,
    /// A stable release
    Stable,
}

impl TorVerStatus {
    /// Helper for encoding: return the suffix that represents a version.
    fn suffix(self) -> &'static str {
        use TorVerStatus::*;
        match self {
            Stable => "",
            Rc => "-rc",
            Beta => "-beta",
            Alpha => "-alpha",
            Other => "-???",
        }
    }
}

/// A parsed Tor version number.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TorVersion {
    /// Major version number.  This has been zero since Tor was created.
    major: u8,
    /// Minor version number.
    minor: u8,
    /// Micro version number.  The major, minor, and micro version numbers
    /// together constitute a "release series" that starts as an alpha
    /// and eventually becomes stable.
    micro: u8,
    /// Patchlevel within a release series
    patch: u8,
    /// Status of a given release
    status: TorVerStatus,
    /// True if this version is given the "-dev" tag to indicate that it
    /// isn't a real Tor release, but rather indicates the state of Tor
    /// within some git repository.
    dev: bool,
}

impl Display for TorVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let devsuffix = if self.dev { "-dev" } else { "" };
        write!(
            f,
            "{}.{}.{}.{}{}{}",
            self.major,
            self.minor,
            self.micro,
            self.patch,
            self.status.suffix(),
            devsuffix
        )
    }
}

impl FromStr for TorVersion {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        // Split the string on "-" into "version", "status", and "dev."
        // Note that "dev" may actually be in the "status" field if
        // the version is stable; we'll handle that later.
        let mut parts = s.split('-').fuse();
        let ver_part = parts.next();
        let status_part = parts.next();
        let dev_part = parts.next();
        if parts.next().is_some() {
            // NOTE: If `dev_part` cannot be unwrapped then there are bigger
            // problems with `s` input
            #[allow(clippy::unwrap_used)]
            return Err(EK::BadTorVersion.at_pos(Pos::at_end_of(dev_part.unwrap())));
        }

        // Split the version on "." into 3 or 4 numbers.
        let vers: Result<Vec<_>, _> = ver_part
            .ok_or_else(|| EK::BadTorVersion.at_pos(Pos::at(s)))?
            .splitn(4, '.')
            .map(|v| v.parse::<u8>())
            .collect();
        let vers = vers.map_err(|_| EK::BadTorVersion.at_pos(Pos::at(s)))?;
        if vers.len() < 3 {
            return Err(EK::BadTorVersion.at_pos(Pos::at(s)));
        }
        let major = vers[0];
        let minor = vers[1];
        let micro = vers[2];
        let patch = if vers.len() == 4 { vers[3] } else { 0 };

        // Compute real status and version.
        let status = match status_part {
            Some("alpha") => TorVerStatus::Alpha,
            Some("beta") => TorVerStatus::Beta,
            Some("rc") => TorVerStatus::Rc,
            None | Some("dev") => TorVerStatus::Stable,
            _ => TorVerStatus::Other,
        };
        let dev = match (status_part, dev_part) {
            (_, Some("dev")) => true,
            (_, Some(s)) => {
                return Err(EK::BadTorVersion.at_pos(Pos::at(s)));
            }
            (Some("dev"), None) => true,
            (_, _) => false,
        };

        Ok(TorVersion {
            major,
            minor,
            micro,
            patch,
            status,
            dev,
        })
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
    use super::*;

    #[test]
    fn parse_good() {
        let mut lastver = None;
        for (s1, s2) in &[
            ("0.1.2", "0.1.2.0"),
            ("0.1.2.0-dev", "0.1.2.0-dev"),
            ("0.4.3.1-bloop", "0.4.3.1-???"),
            ("0.4.3.1-alpha", "0.4.3.1-alpha"),
            ("0.4.3.1-alpha-dev", "0.4.3.1-alpha-dev"),
            ("0.4.3.1-beta", "0.4.3.1-beta"),
            ("0.4.3.1-rc", "0.4.3.1-rc"),
            ("0.4.3.1", "0.4.3.1"),
        ] {
            let t: TorVersion = s1.parse().unwrap();
            assert_eq!(&t.to_string(), s2);

            if let Some(v) = lastver {
                assert!(v < t);
            }
            lastver = Some(t);
        }
    }

    #[test]
    fn parse_bad() {
        for s in &[
            "fred.and.bob",
            "11",
            "11.22",
            "0x2020",
            "1.2.3.marzipan",
            "0.1.2.5-alpha-deeev",
            "0.1.2.5-alpha-dev-turducken",
        ] {
            assert!(s.parse::<TorVersion>().is_err());
        }
    }
}
