//! Methods for storing and loading directory information from disk.
//!
//! We have code implemented for a flexible storage format based on sqlite.

// (There was once a read-only format based on the C tor implementation's
// storage: Search the git history for tor-dirmgr/src/storage/legacy.rs
// if you ever need to reinstate it.)

use tor_netdoc::doc::authcert::AuthCertKeyIds;
use tor_netdoc::doc::microdesc::MdDigest;
use tor_netdoc::doc::netstatus::ConsensusFlavor;

#[cfg(feature = "routerdesc")]
use tor_netdoc::doc::routerdesc::RdDigest;

#[cfg(feature = "bridge-client")]
pub(crate) use tor_guardmgr::bridge::BridgeConfig;

use crate::docmeta::{AuthCertMeta, ConsensusMeta};
use crate::{Error, Result};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Result as IoResult;
use std::str::Utf8Error;
use std::time::SystemTime;
use time::Duration;

pub(crate) mod sqlite;

pub(crate) use sqlite::SqliteStore;

/// Convenient Sized & dynamic [`Store`]
pub(crate) type DynStore = Box<dyn Store>;

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
    /// Try to return a view of this document as a string.
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
    UncheckedBytes {
        /// The underlying bytes
        bytes: Vec<u8>,
        /// Whether the bytes have been validated previously as UTF-8
        validated: RefCell<bool>,
    },
    #[cfg(feature = "mmap")]
    /// A set of memory-mapped bytes (not yet validated as UTF-8).
    MappedBytes {
        /// The underlying bytes
        bytes: memmap2::Mmap,
        /// Whether the bytes have been validated previously as UTF-8
        validated: RefCell<bool>,
    },
}

impl InputString {
    /// Return a view of this InputString as a &str, if it is valid UTF-8.
    pub(crate) fn as_str(&self) -> Result<&str> {
        self.as_str_impl().map_err(Error::BadUtf8InCache)
    }

    /// Helper for [`Self::as_str()`], with unwrapped error type.
    fn as_str_impl(&self) -> std::result::Result<&str, Utf8Error> {
        // It is not necessary to re-check the UTF8 every time
        // this function is called so remember the result
        // we got with `validated`

        match self {
            InputString::Utf8(s) => Ok(&s[..]),
            InputString::UncheckedBytes { bytes, validated } => {
                if *validated.borrow() {
                    unsafe { Ok(std::str::from_utf8_unchecked(&bytes[..])) }
                } else {
                    let result = std::str::from_utf8(&bytes[..])?;
                    validated.replace(true);
                    Ok(result)
                }
            }
            #[cfg(feature = "mmap")]
            InputString::MappedBytes { bytes, validated } => {
                if *validated.borrow() {
                    unsafe { Ok(std::str::from_utf8_unchecked(&bytes[..])) }
                } else {
                    let result = std::str::from_utf8(&bytes[..])?;
                    validated.replace(true);
                    Ok(result)
                }
            }
        }
    }
    /// Try to create an [`InputString`] from an open [`File`].
    ///
    /// We'll try to memory-map the file if we can.  If that fails, or if we
    /// were built without the `mmap` feature, we'll fall back to reading the
    /// file into memory.
    pub(crate) fn load(file: File) -> IoResult<Self> {
        #[cfg(feature = "mmap")]
        {
            let mapping = unsafe {
                // I'd rather have a safe option, but that's not possible
                // with mmap, since other processes could in theory replace
                // the contents of the file while we're using it.
                memmap2::Mmap::map(&file)
            };
            if let Ok(bytes) = mapping {
                return Ok(InputString::MappedBytes {
                    bytes,
                    validated: RefCell::new(false),
                });
            }
        }
        use std::io::{BufReader, Read};
        let mut f = BufReader::new(file);
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        Ok(InputString::Utf8(result))
    }
}

impl AsRef<[u8]> for InputString {
    fn as_ref(&self) -> &[u8] {
        match self {
            InputString::Utf8(s) => s.as_ref(),
            InputString::UncheckedBytes { bytes, .. } => &bytes[..],
            #[cfg(feature = "mmap")]
            InputString::MappedBytes { bytes, .. } => &bytes[..],
        }
    }
}

impl From<String> for InputString {
    fn from(s: String) -> InputString {
        InputString::Utf8(s)
    }
}

impl From<Vec<u8>> for InputString {
    fn from(bytes: Vec<u8>) -> InputString {
        InputString::UncheckedBytes {
            bytes,
            validated: RefCell::new(false),
        }
    }
}

/// Configuration of expiration of each element of a [`Store`].
pub(crate) struct ExpirationConfig {
    /// How long to keep router descriptors.
    ///
    /// This timeout is measured since the publication date of the router
    /// descriptor.
    ///
    /// TODO(nickm): We may want a better approach in the future; see notes in
    /// `EXPIRATION_DEFAULTS`.
    pub(super) router_descs: Duration,
    /// How long to keep unlisted microdescriptors.
    ///
    /// This timeout counts the amount of time since a microdescriptor is no
    /// longer listed in a live consensus. Shorter values save storage at the
    /// expense of extra bandwidth spent re-downloading microdescriptors; higher
    /// values save bandwidth at the expense of storage used to store old
    /// microdescriptors that might become listed again.
    pub(super) microdescs: Duration,
    /// How long to keep expired authority certificate.
    pub(super) authcerts: Duration,
    /// How long to keep expired consensus.
    pub(super) consensuses: Duration,
}

/// Configuration of expiration shared between [`Store`] implementations.
pub(crate) const EXPIRATION_DEFAULTS: ExpirationConfig = {
    ExpirationConfig {
        // TODO: This is the value that C Tor uses here, but it may be desirable
        // to adjust it depending on what we find in practice.  For relays,
        // instead of looking at publication date, we might want to use an
        // approach more similar to the "last-listed" approach taken by
        // microdescriptors.  For bridges, we can keep descriptors for a longer
        // time.  In either case, we may be able to discard all but the most
        // recent descriptor from each identity.
        router_descs: Duration::days(5),
        // This value is a compromise between saving bandwidth (by not having to
        // re-download microdescs) and saving space (by not having to store too
        // many microdescs).  It's the same one that C tor uses; experiments on
        // 2022 data suggest that it winds up using only 1% more microdesc dl
        // bandwidth than strictly necessary, at the cost of storing 40% more
        // microdescriptors than will be immediately useful at any given time.
        microdescs: Duration::days(7),
        authcerts: Duration::ZERO,
        consensuses: Duration::days(2),
    }
};

/// Representation of a storage.
///
/// When creating an instance of this [`Store`], it should try to grab the lock during
/// initialization (`is_readonly() iff some other implementation grabbed it`).
pub(crate) trait Store: Send + 'static {
    /// Return true if this [`Store`] is opened in read-only mode.
    fn is_readonly(&self) -> bool;
    /// Try to upgrade from a read-only connection to a read-write connection.
    ///
    /// Return true on success; false if another process had the lock.
    fn upgrade_to_readwrite(&mut self) -> Result<bool>;

    /// Delete all completely-expired objects from the database.
    ///
    /// This is pretty conservative, and only removes things that are
    /// definitely past their good-by date.
    fn expire_all(&mut self, expiration: &ExpirationConfig) -> Result<()>;

    /// Load the latest consensus from disk.
    ///
    /// If `pending` is given, we will only return a consensus with
    /// the given "pending" status.  (A pending consensus doesn't have
    /// enough descriptors yet.)  If `pending_ok` is None, we'll
    /// return a consensus with any pending status.
    fn latest_consensus(
        &self,
        flavor: ConsensusFlavor,
        pending: Option<bool>,
    ) -> Result<Option<InputString>>;
    /// Return the information about the latest non-pending consensus,
    /// including its valid-after time and digest.
    fn latest_consensus_meta(&self, flavor: ConsensusFlavor) -> Result<Option<ConsensusMeta>>;
    /// Try to read the consensus corresponding to the provided metadata object.
    #[cfg(test)]
    fn consensus_by_meta(&self, cmeta: &ConsensusMeta) -> Result<InputString>;
    /// Try to read the consensus whose SHA3-256 digests is the provided
    /// value, and its metadata.
    fn consensus_by_sha3_digest_of_signed_part(
        &self,
        d: &[u8; 32],
    ) -> Result<Option<(InputString, ConsensusMeta)>>;
    /// Write a consensus to disk.
    fn store_consensus(
        &mut self,
        cmeta: &ConsensusMeta,
        flavor: ConsensusFlavor,
        pending: bool,
        contents: &str,
    ) -> Result<()>;
    /// Mark the consensus generated from `cmeta` as no longer pending.
    fn mark_consensus_usable(&mut self, cmeta: &ConsensusMeta) -> Result<()>;
    /// Remove the consensus generated from `cmeta`.
    //
    // Nothing uses this yet; removal is handled from `expire_all`.
    #[allow(dead_code)]
    fn delete_consensus(&mut self, cmeta: &ConsensusMeta) -> Result<()>;

    /// Read all of the specified authority certs from the cache.
    fn authcerts(&self, certs: &[AuthCertKeyIds]) -> Result<HashMap<AuthCertKeyIds, String>>;
    /// Save a list of authority certificates to the cache.
    fn store_authcerts(&mut self, certs: &[(AuthCertMeta, &str)]) -> Result<()>;

    /// Read all the microdescriptors listed in `input` from the cache.
    fn microdescs(&self, digests: &[MdDigest]) -> Result<HashMap<MdDigest, String>>;
    /// Store every microdescriptor in `input` into the cache, and say that
    /// it was last listed at `when`.
    fn store_microdescs(&mut self, digests: &[(&str, &MdDigest)], when: SystemTime) -> Result<()>;
    /// Update the `last-listed` time of every microdescriptor in
    /// `input` to `when` or later.
    fn update_microdescs_listed(&mut self, digests: &[MdDigest], when: SystemTime) -> Result<()>;

    /// Read all the microdescriptors listed in `input` from the cache.
    ///
    /// Only available when the `routerdesc` feature is present.
    #[cfg(feature = "routerdesc")]
    fn routerdescs(&self, digests: &[RdDigest]) -> Result<HashMap<RdDigest, String>>;
    /// Store every router descriptors in `input` into the cache.
    #[cfg(feature = "routerdesc")]
    #[allow(unused)]
    fn store_routerdescs(&mut self, digests: &[(&str, SystemTime, &RdDigest)]) -> Result<()>;

    /// Look up a cached bridge descriptor.
    #[cfg(feature = "bridge-client")]
    fn lookup_bridgedesc(&self, bridge: &BridgeConfig) -> Result<Option<CachedBridgeDescriptor>>;

    /// Store a cached bridge descriptor.
    ///
    /// This entry will be deleted some time after `until`
    /// (but the caller is not allowed to rely on either timely deletion,
    /// or retention until that time).
    #[cfg(feature = "bridge-client")]
    fn store_bridgedesc(
        &mut self,
        bridge: &BridgeConfig,
        entry: CachedBridgeDescriptor,
        until: SystemTime,
    ) -> Result<()>;

    /// Delete a cached bridge descriptor for this bridge.
    ///
    /// It's not an error if it's not present.
    #[cfg(feature = "bridge-client")]
    // Nothing uses this yet; removal is handled from `expire_all`.
    #[allow(dead_code)]
    fn delete_bridgedesc(&mut self, bridge: &BridgeConfig) -> Result<()>;
}

/// Value in the bridge descriptor cache
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
pub(crate) struct CachedBridgeDescriptor {
    /// When we fetched this
    pub(crate) fetched: SystemTime,

    /// The document text, as we fetched it
    pub(crate) document: String,
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
    use tempfile::tempdir;

    #[test]
    fn strings() {
        let s: InputString = "Hello world".to_string().into();
        assert_eq!(s.as_ref(), b"Hello world");
        assert_eq!(s.as_str().unwrap(), "Hello world");
        assert_eq!(s.as_str().unwrap(), "Hello world");

        let s: InputString = b"Hello world".to_vec().into();
        assert_eq!(s.as_ref(), b"Hello world");
        assert_eq!(s.as_str().unwrap(), "Hello world");
        assert_eq!(s.as_str().unwrap(), "Hello world");

        // bad utf-8
        let s: InputString = b"Hello \xff world".to_vec().into();
        assert_eq!(s.as_ref(), b"Hello \xff world");
        assert!(s.as_str().is_err());
    }

    #[test]
    fn files() {
        let td = tempdir().unwrap();

        let goodstr = td.path().join("goodstr");
        std::fs::write(&goodstr, "This is a reasonable file.\n").unwrap();
        let s = InputString::load(File::open(goodstr).unwrap());
        let s = s.unwrap();
        assert_eq!(s.as_str().unwrap(), "This is a reasonable file.\n");
        assert_eq!(s.as_str().unwrap(), "This is a reasonable file.\n");
        assert_eq!(s.as_ref(), b"This is a reasonable file.\n");

        let badutf8 = td.path().join("badutf8");
        std::fs::write(&badutf8, b"Not good \xff UTF-8.\n").unwrap();
        let s = InputString::load(File::open(badutf8).unwrap());
        assert!(s.is_err() || s.unwrap().as_str().is_err());
    }

    #[test]
    fn doctext() {
        let s: InputString = "Hello universe".to_string().into();
        let dt: DocumentText = s.into();
        assert_eq!(dt.as_ref(), b"Hello universe");
        assert_eq!(dt.as_str(), Ok("Hello universe"));
        assert_eq!(dt.as_str(), Ok("Hello universe"));

        let s: InputString = b"Hello \xff universe".to_vec().into();
        let dt: DocumentText = s.into();
        assert_eq!(dt.as_ref(), b"Hello \xff universe");
        assert!(dt.as_str().is_err());
    }
}
