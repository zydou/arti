//! `ByteQty`, Quantity of memory used, measured in bytes.
//
// The closest crate to this on crates.io is `bytesize`.
// But it has serious bugs including confusion about KiB vs KB,
// and isn't maintained.
//
// There is also humansize, but that just does printing.

#![allow(clippy::comparison_to_empty)] // unit == "" etc. is much clearer

use derive_more::{Deref, DerefMut, From, Into};
use itertools::Itertools;
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::fmt::{self, Display};
use std::str::FromStr;

use InvalidByteQty as IBQ;

/// Quantity of memory used, measured in bytes.
///
/// Like `usize` but `FromStr` and `Display`s in a more friendly and less precise way
///
/// Parses from (with or without the internal space):
///  * `<amount>` (implicitly, bytes)
///  * `<amount> B`
///  * `<amount> KiB`/`MiB`/`GiB`/`TiB` (binary, 1024-based units)
///  * `<amount> KB`/`MB`/`GB`/`TB` (decimal, 1000-based units)
///
/// Displays to approximately 3 significant figures,
/// preferring binary (1024-based) multipliers.
/// (There is no facility for adjusting the format.)
#[derive(Debug, Clone, Copy, Hash, Default, Eq, PartialEq, Ord, PartialOrd)] //
#[derive(From, Into, Deref, DerefMut)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(into = "usize", try_from = "ByteQtySerde")
)]
#[allow(clippy::exhaustive_structs)] // this is a behavioural newtype wrapper
pub struct ByteQty(pub usize);

/// Error parsing (or deserialising) a [`ByteQty`]
#[derive(Error, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum InvalidByteQty {
    /// Value bigger than `usize::MAX`
    #[error(
        "size/quantity outside range supported on this system (max is {} B)",
        usize::MAX
    )]
    Overflow,
    /// Unknown unit
    #[error(
        "size/quantity specified unknown unit; supported are {}",
        SupportedUnits
    )]
    UnknownUnit,
    /// Unknown unit, probably because the B at the end was missing
    ///
    /// We insist on the `B` so that all our units end in `B` or `iB`.
    #[error(
        "size/quantity specified unknown unit - we require the `B`; supported units are {}",
        SupportedUnits
    )]
    UnknownUnitMissingB,
    /// Bad syntax
    #[error("size/quantity specified string in bad syntax")]
    BadSyntax,
    /// Negative value
    #[error("size/quantity cannot be negative")]
    Negative,
    /// NaN
    #[error("size/quantity cannot be obtained from a floating point NaN")]
    NaN,
    /// BadValue
    #[error("bad type for size/quantity (only numbers, and strings to parse, are supported)")]
    BadValue,
}

//---------- units (definitions) ----------

/// Units that can be suffixed to a number, when displaying [`ByteQty`] (macro)
const DISPLAY_UNITS: &[(&str, u64)] = &[
    ("B", 1),
    ("KiB", 1024),
    ("MiB", 1024 * 1024),
    ("GiB", 1024 * 1024 * 1024),
    ("TiB", 1024 * 1024 * 1024 * 1024),
];

/// Units that are (only) recognised parsing a [`ByteQty`] from a string
const PARSE_UNITS: &[(&str, u64)] = &[
    ("", 1),
    ("KB", 1000),
    ("MB", 1000 * 1000),
    ("GB", 1000 * 1000 * 1000),
    ("TB", 1000 * 1000 * 1000 * 1000),
];

/// Units that are used when parsing *and* when printing
const ALL_UNITS: &[&[(&str, u64)]] = &[
    //
    DISPLAY_UNITS,
    PARSE_UNITS,
];

//---------- inherent methods ----------

impl ByteQty {
    /// Maximum for the type
    pub const MAX: ByteQty = ByteQty(usize::MAX);

    /// Return the value as a plain number, a `usize`
    ///
    /// Provided so call sites don't need to write an opaque `.0` everywhere,
    /// even though that would be fine.
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

//---------- printing ----------

impl Display for ByteQty {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = self.0 as f64;

        // Find the first entry which is big enough that the mantissa will be <999.5,
        // ie where it won't print as 4 decimal digits after the point.
        // Or, if that doesn't work, we'll use the last entry which is the largest.

        let (unit, mantissa) = DISPLAY_UNITS
            .iter()
            .copied()
            .filter(|(unit, _)| *unit != "")
            .map(|(unit, multiplier)| (unit, v / multiplier as f64))
            .find_or_last(|(_, mantissa)| *mantissa < 999.5)
            .expect("DISPLAY_UNITS Is empty?!");

        // Select a precision so that we'll print about 3 significant figures.
        // We can't do this precisely, so we err on the side of slighlty
        // fewer SF with mantissae starting with 9.

        let after_decimal = if mantissa < 9. {
            2
        } else if mantissa < 99. {
            1
        } else {
            0
        };

        write!(f, "{mantissa:.*} {unit}", after_decimal)
    }
}

//---------- incoming conversions ----------

// We don't provide Into<u64> or Into<f64> because they're actually quite faffsome
// due to all the corner cases.  We only provide these two, because we need them
// ourselves for parsing and deserialisation.

impl TryFrom<u64> for ByteQty {
    type Error = InvalidByteQty;
    fn try_from(v: u64) -> Result<ByteQty, IBQ> {
        let v = v.try_into().map_err(|_| IBQ::Overflow)?;
        Ok(ByteQty(v))
    }
}

impl TryFrom<f64> for ByteQty {
    type Error = InvalidByteQty;
    fn try_from(f: f64) -> Result<ByteQty, IBQ> {
        if f.is_nan() {
            Err(IBQ::NaN)
        } else if f > (usize::MAX as f64) {
            Err(IBQ::Overflow)
        } else if f >= 0. {
            Ok(ByteQty(f as usize))
        } else {
            Err(IBQ::Negative)
        }
    }
}

/// Helper for deserializing [`ByteQty`]
#[cfg(feature = "serde")]
#[derive(Deserialize)]
#[serde(untagged)]
enum ByteQtySerde {
    /// `String`
    U(u64),
    /// `String`
    S(String),
    /// `f64`
    F(f64),
    /// Other things
    Bad(serde::de::IgnoredAny),
}
#[cfg(feature = "serde")]
impl TryFrom<ByteQtySerde> for ByteQty {
    type Error = InvalidByteQty;
    fn try_from(qs: ByteQtySerde) -> Result<ByteQty, IBQ> {
        match qs {
            ByteQtySerde::S(s) => s.parse(),
            ByteQtySerde::U(u) => u.try_into(),
            ByteQtySerde::F(f) => f.try_into(),
            ByteQtySerde::Bad(_) => Err(IBQ::BadValue),
        }
    }
}

//---------- FromStr ----------

impl FromStr for ByteQty {
    type Err = InvalidByteQty;
    fn from_str(s: &str) -> Result<Self, IBQ> {
        let s = s.trim();

        let last_digit = s
            .rfind(|c: char| c.is_ascii_digit())
            .ok_or(IBQ::BadSyntax)?;

        // last_digit points to an ASCII digit so +1 is right to skip it
        let (mantissa, unit) = s.split_at(last_digit + 1);

        let unit = unit.trim_start(); // remove any whitespace in the middle

        // defer unknown unit errors until we've done the rest of the parsing
        let multiplier: Result<u64, _> = ALL_UNITS
            .iter()
            .copied()
            .flatten()
            .find(|(s, _)| *s == unit)
            .map(|(_, m)| *m)
            .ok_or_else(|| {
                if unit.ends_with('B') {
                    IBQ::UnknownUnit
                } else {
                    IBQ::UnknownUnitMissingB
                }
            });

        // We try this via u64 (so we give byte-precise answers if possible)
        // and via f64 (so we can support fractions).
        //
        // (Byte-precise amounts aren't important here in tor-memquota,
        // but this code seems like it may end up elsewhere.)
        if let Ok::<u64, _>(mantissa) = mantissa.parse() {
            let multiplier = multiplier?;
            (|| {
                mantissa
                    .checked_mul(multiplier)? //
                    .try_into()
                    .ok()
            })()
            .ok_or(IBQ::Overflow)
        } else if let Ok::<f64, _>(mantissa) = mantissa.parse() {
            let value = mantissa * (multiplier? as f64);
            value.try_into()
        } else {
            Err(IBQ::BadSyntax)
        }
    }
}

/// Helper to format the list of supported units into `IBQ::UnknownUnit`
struct SupportedUnits;

impl Display for SupportedUnits {
    #[allow(unstable_name_collisions)] // Itertools::intersperse vs std's;  rust-lang/rust#48919
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for s in ALL_UNITS
            .iter()
            .copied()
            .flatten()
            .copied()
            .map(|(unit, _multiplier)| unit)
            .filter(|unit| !unit.is_empty())
            .intersperse("/")
        {
            Display::fmt(s, f)?;
        }
        Ok(())
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
    fn display_qty() {
        let chk = |by, s: &str| {
            assert_eq!(ByteQty(by).to_string(), s, "{s:?}");
            assert_eq!(s.parse::<ByteQty>().expect(s).to_string(), s, "{s:?}");
        };

        chk(10 * 1024, "10.0 KiB");
        chk(1024 * 1024, "1.00 MiB");
        chk(1000 * 1024 * 1024, "0.98 GiB");
    }

    #[test]
    fn parse_qty() {
        let chk = |s: &str, b| assert_eq!(s.parse::<ByteQty>(), b, "{s:?}");
        let chk_y = |s, v| chk(s, Ok(ByteQty(v)));

        chk_y("1", 1);
        chk_y("1B", 1);
        chk_y("1KB", 1000);
        chk_y("1 KB", 1000);
        chk_y("1 KiB", 1024);
        chk_y("1.0 KiB", 1024);
        chk_y(".00195312499909050529 TiB", 2147483647);

        chk("1 2 K", Err(IBQ::BadSyntax));
        chk("1.2 K", Err(IBQ::UnknownUnitMissingB));
        chk("no digits", Err(IBQ::BadSyntax));
        chk("1 2 KB", Err(IBQ::BadSyntax));
        chk("1 mB", Err(IBQ::UnknownUnit));
        chk("1.0e100 TiB", Err(IBQ::Overflow));
    }

    #[test]
    fn convert() {
        fn chk(a: impl TryInto<ByteQty, Error = IBQ>, b: Result<ByteQty, IBQ>) {
            assert_eq!(a.try_into(), b);
        }
        fn chk_y(a: impl TryInto<ByteQty, Error = IBQ>, v: usize) {
            chk(a, Ok(ByteQty(v)));
        }

        chk_y(0.0_f64, 0);
        chk_y(1.0_f64, 1);
        chk_y(f64::from(u32::MAX), u32::MAX as usize);
        chk_y(-0.0_f64, 0);

        chk(-0.01_f64, Err(IBQ::Negative));
        chk(1.0e100_f64, Err(IBQ::Overflow));
        chk(f64::NAN, Err(IBQ::NaN));

        chk_y(0_u64, 0);
        chk_y(u64::from(u32::MAX), u32::MAX as usize);
        // we can't easily test the u64 overflow case without getting arch-specific
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_deser() {
        // Use serde__value so we can try all the exciting things in the serde model
        use serde_value::Value as SV;

        let chk = |sv: SV, b: Result<ByteQty, IBQ>| {
            assert_eq!(
                sv.clone().deserialize_into().map_err(|e| e.to_string()),
                b.map_err(|e| e.to_string()),
                "{sv:?}",
            );
        };
        let chk_y = |sv, v| chk(sv, Ok(ByteQty(v)));
        let chk_bv = |sv| chk(sv, Err(IBQ::BadValue));

        chk_y(SV::U8(1), 1);
        chk_y(SV::String("1".to_owned()), 1);
        chk_y(SV::String("1 KiB".to_owned()), 1024);
        chk_y(SV::I32(i32::MAX), i32::MAX as usize);
        chk_y(SV::F32(1.0), 1);
        chk_y(SV::F64(f64::from(u32::MAX)), u32::MAX as usize);
        chk_y(SV::Bytes("1".to_string().into()), 1);

        chk_bv(SV::Bool(false));
        chk_bv(SV::Char('1'));
        chk_bv(SV::Unit);
        chk_bv(SV::Option(None));
        chk_bv(SV::Option(Some(Box::new(SV::String("1".to_owned())))));
        chk_bv(SV::Newtype(Box::new(SV::String("1".to_owned()))));
        chk_bv(SV::Seq(vec![]));
        chk_bv(SV::Map(Default::default()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_ser() {
        // Use serde_json so we don't have to worry about how precisely
        // serde decides to encode a usize (eg is it u32 or u64 or what).
        assert_eq!(
            serde_json::to_value(ByteQty(1)).unwrap(),
            serde_json::json!(1),
        );
    }
}
