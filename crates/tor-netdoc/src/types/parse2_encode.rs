//! Helpers for parse2 and encode

use void::Void;

/// Conversion module for `Vec<u8>` as Object with `ItemValueParseable`
pub mod raw_data_object {
    use super::*;

    /// "Parse" the data
    #[cfg(feature = "parse2")]
    pub fn try_from(data: Vec<u8>) -> Result<Vec<u8>, Void> {
        Ok(data)
    }
}
