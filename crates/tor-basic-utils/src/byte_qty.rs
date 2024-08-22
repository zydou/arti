//! `ByteQty`, Quantity of memory used, measured in bytes.
//
// The closest crate to this on crates.io is `bytesize`.
// But it has serious bugs including confusion about KiB vs KB,
// and isn't maintained.
//
// There is also humansize, but that just does printing.

use derive_more::{Deref, DerefMut, From, Into};
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::fmt::{self, Display};

use InvalidByteQty as IBQ;

/// Quantity of memory used, measured in bytes.
///
/// Like `usize` but `Display`s in a more friendly and less precise way
#[derive(Debug, Clone, Copy, Hash, Default, Eq, PartialEq, Ord, PartialOrd)] //
#[derive(From, Into, Deref, DerefMut)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(transparent),
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
    /// Negative value
    #[error("size/quantity cannot be negative")]
    Negative,
    /// NaN
    #[error("size/quantity cannot be obtained from a floating point NaN")]
    NaN,
}

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
        let mb = self.0 as f32 / (1024. * 1024.);
        write!(f, "{:.2}MiB", mb)
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
        let chk = |by, s| assert_eq!(ByteQty(by).to_string(), s);

        chk(10 * 1024, "0.01MiB");
        chk(1024 * 1024, "1.00MiB");
        chk(1000 * 1024 * 1024, "1000.00MiB");
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
}
