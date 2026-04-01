//! Helpers for parse2 and encode

use void::Void;

use tor_error::Bug;

/// Conversion module for `Vec<u8>` as Object with `ItemValueParseable`/`ItemValueEncodable`
pub mod raw_data_object {
    use super::*;

    /// "Parse" the data
    #[cfg(feature = "parse2")]
    pub fn try_from(data: Vec<u8>) -> Result<Vec<u8>, Void> {
        Ok(data)
    }

    /// "Encode" the data
    #[cfg(feature = "encode")]
    pub fn write_object_onto(self_: &[u8], out: &mut Vec<u8>) -> Result<(), Bug> {
        out.extend(self_);
        Ok(())
    }
}
