//! Methods for storing and loading directory information from disk.
//!
//! We have code implemented for a flexible storage format based on sqlite.

// (There was once a read-only format based on the C tor implementation's
// storage: Search the git history for tor-dirmgr/src/storage/legacy.rs
// if you ever need to reinstate it.)

pub(crate) mod sqlite;

use crate::{Error, Result};
use std::{path::Path, str::Utf8Error};

/// A document returned by a directory manager.
///
/// This document may be in memory, or may be mapped from a cache.  It is
/// not necessarily valid UTF-8.
pub struct DocumentText {
    /// The underlying InputString.  We only wrap this type to make it
    /// opaque to other crates, so they don't have to worry about the
    /// implementation details.
    s: InputString,
}

impl From<InputString> for DocumentText {
    fn from(s: InputString) -> DocumentText {
        DocumentText { s }
    }
}

impl AsRef<[u8]> for DocumentText {
    fn as_ref(&self) -> &[u8] {
        self.s.as_ref()
    }
}

impl DocumentText {
    /// Try to return a view of this document as a a string.
    pub(crate) fn as_str(&self) -> std::result::Result<&str, Utf8Error> {
        self.s.as_str_impl()
    }

    /// Create a new DocumentText holding the provided string.
    pub(crate) fn from_string(s: String) -> Self {
        DocumentText {
            s: InputString::Utf8(s),
        }
    }
}

/// An abstraction over a possible string that we've loaded or mapped from
/// a cache.
#[derive(Debug)]
pub(crate) enum InputString {
    /// A string that's been validated as UTF-8
    Utf8(String),
    /// A set of unvalidated bytes.
    UncheckedBytes(Vec<u8>),
    #[cfg(feature = "mmap")]
    /// A set of memory-mapped bytes (not yet validated as UTF-8).
    MappedBytes(memmap2::Mmap),
}

impl InputString {
    /// Return a view of this InputString as a &str, if it is valid UTF-8.
    pub(crate) fn as_str(&self) -> Result<&str> {
        self.as_str_impl()
            .map_err(|_| Error::CacheCorruption("Invalid UTF-8").into())
    }

    /// Helper for [`Self::as_str()`], with unwrapped error type.
    fn as_str_impl(&self) -> std::result::Result<&str, Utf8Error> {
        // TODO: it is not strictly necessary to re-check the UTF8 every time
        // this function is called; we could instead remember the result
        // we got.
        match self {
            InputString::Utf8(s) => Ok(&s[..]),
            InputString::UncheckedBytes(v) => std::str::from_utf8(&v[..]),
            #[cfg(feature = "mmap")]
            InputString::MappedBytes(m) => std::str::from_utf8(&m[..]),
        }
    }

    /// Construct a new InputString from a file on disk, trying to
    /// memory-map the file if possible.
    pub(crate) fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let f = std::fs::File::open(path)?;
        #[cfg(feature = "mmap")]
        {
            let mapping = unsafe {
                // I'd rather have a safe option, but that's not possible
                // with mmap, since other processes could in theory replace
                // the contents of the file while we're using it.
                memmap2::Mmap::map(&f)
            };
            if let Ok(m) = mapping {
                return Ok(InputString::MappedBytes(m));
            }
        }
        use std::io::{BufReader, Read};
        let mut f = BufReader::new(f);
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        Ok(InputString::Utf8(result))
    }
}

impl AsRef<[u8]> for InputString {
    fn as_ref(&self) -> &[u8] {
        match self {
            InputString::Utf8(s) => s.as_ref(),
            InputString::UncheckedBytes(v) => &v[..],
            #[cfg(feature = "mmap")]
            InputString::MappedBytes(m) => &m[..],
        }
    }
}

impl From<String> for InputString {
    fn from(s: String) -> InputString {
        InputString::Utf8(s)
    }
}

impl From<Vec<u8>> for InputString {
    fn from(v: Vec<u8>) -> InputString {
        InputString::UncheckedBytes(v)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn strings() {
        let s: InputString = "Hello world".to_string().into();
        assert_eq!(s.as_ref(), b"Hello world");
        assert_eq!(s.as_str().unwrap(), "Hello world");

        let s: InputString = b"Hello world".to_vec().into();
        assert_eq!(s.as_ref(), b"Hello world");
        assert_eq!(s.as_str().unwrap(), "Hello world");

        // bad utf-8
        let s: InputString = b"Hello \xff world".to_vec().into();
        assert_eq!(s.as_ref(), b"Hello \xff world");
        assert!(s.as_str().is_err());
    }

    #[test]
    fn files() {
        let td = tempdir().unwrap();

        let absent = td.path().join("absent");
        let s = InputString::load(&absent);
        assert!(s.is_err());

        let goodstr = td.path().join("goodstr");
        std::fs::write(&goodstr, "This is a reasonable file.\n").unwrap();
        let s = InputString::load(&goodstr);
        let s = s.unwrap();
        assert_eq!(s.as_str().unwrap(), "This is a reasonable file.\n");
        assert_eq!(s.as_ref(), b"This is a reasonable file.\n");

        let badutf8 = td.path().join("badutf8");
        std::fs::write(&badutf8, b"Not good \xff UTF-8.\n").unwrap();
        let s = InputString::load(&badutf8);
        assert!(s.is_err() || s.unwrap().as_str().is_err());
    }

    #[test]
    fn doctext() {
        let s: InputString = "Hello universe".to_string().into();
        let dt: DocumentText = s.into();
        assert_eq!(dt.as_ref(), b"Hello universe");
        assert_eq!(dt.as_str(), Ok("Hello universe"));

        let s: InputString = b"Hello \xff universe".to_vec().into();
        let dt: DocumentText = s.into();
        assert_eq!(dt.as_ref(), b"Hello \xff universe");
        assert!(dt.as_str().is_err());
    }
}
