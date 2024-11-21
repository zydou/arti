//! Read-only C Tor client key store implementation
//!
//! See [`CTorClientKeystore`] for more details.

use std::fs;
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::str::FromStr as _;

use crate::keystore::ctor::err::{CTorKeystoreError, MalformedClientKeyError};
use crate::keystore::ctor::CTorKeystore;
use crate::keystore::fs_utils::{checked_op, FilesystemAction, FilesystemError, RelKeyPath};
use crate::keystore::{EncodableItem, ErasedKey, KeySpecifier, Keystore};
use crate::{CTorPath, KeyPath, KeystoreId, Result};

use fs_mistrust::Mistrust;
use itertools::Itertools as _;
use tor_basic_utils::PathExt as _;
use tor_error::debug_report;
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsId};
use tor_key_forge::{KeyType, KeystoreItemType};
use tor_llcrypto::pk::curve25519;
use tracing::debug;

/// A read-only C Tor client keystore.
///
/// This keystore provides read-only access to the client restricted discovery keys
/// rooted at a given `ClientOnionAuthDir` directory (see `ClientOnionAuthDir` in `tor(1)`).
///
/// The key files must be in the
/// `<hsid>:descriptor:x25519:<base32-encoded-x25519-public-key>` format
/// and have the `.auth_private` extension.
/// Invalid keys, and keys that don't have the expected extension, will be ignored.
///
/// The only supported [`Keystore`] operations are [`contains`](Keystore::contains),
/// [`get`](Keystore::get), and [`list`](Keystore::list). All other keystore operations
/// will return an error.
///
/// This keystore implementation uses the [`CTorPath`] of the requested [`KeySpecifier`]
/// and the [`KeystoreItemType`] to identify the appropriate restricted discovery keypair.
/// If the requested `CTorPath` is not [`ClientHsDescEncKey`](CTorPath::ClientHsDescEncKey),
/// the keystore will declare the key not found.
/// If the requested `CTorPath` is [`ClientHsDescEncKey`](CTorPath::ClientHsDescEncKey),
/// but the `KeystoreItemType` is not [`X25519StaticKeypair`](KeyType::X25519StaticKeypair),
/// an error is returned.
pub struct CTorClientKeystore(CTorKeystore);

impl CTorClientKeystore {
    /// Create a new `CTorKeystore` rooted at the specified `keystore_dir` directory.
    ///
    /// This function returns an error if `keystore_dir` is not a directory,
    /// or if it does not conform to the requirements of the specified `Mistrust`.
    pub fn from_path_and_mistrust(
        keystore_dir: impl AsRef<Path>,
        mistrust: &Mistrust,
        id: KeystoreId,
    ) -> Result<Self> {
        CTorKeystore::from_path_and_mistrust(keystore_dir, mistrust, id).map(Self)
    }
}

/// Extract the HsId from `spec, or return `res`.
macro_rules! hsid_if_supported {
    ($spec:expr, $ret:expr, $key_type:expr) => {{
        // If the key specifier doesn't have a CTorPath,
        // we can't possibly handle this key.
        let Some(ctor_path) = $spec.ctor_path() else {
            return $ret;
        };

        // This keystore only deals with service keys...
        let CTorPath::ClientHsDescEncKey(hsid) = ctor_path else {
            return $ret;
        };

        if *$key_type != KeyType::X25519StaticKeypair.into() {
            return Err(CTorKeystoreError::InvalidKeyType {
                key_type: $key_type.clone(),
                key: "client restricted discovery key".into(),
            }
            .into());
        }

        hsid
    }};
}

impl CTorClientKeystore {
    /// List all the key entries in the keystore_dir.
    fn list_entries(&self, dir: &RelKeyPath) -> Result<fs::ReadDir> {
        let entries = checked_op!(read_directory, dir)
            .map_err(|e| FilesystemError::FsMistrust {
                action: FilesystemAction::Read,
                path: dir.rel_path_unchecked().into(),
                err: e.into(),
            })
            .map_err(CTorKeystoreError::Filesystem)?;

        Ok(entries)
    }
}

/// The extension of the client keys stored in this store.
const KEY_EXTENSION: &str = "auth_private";

impl CTorClientKeystore {
    /// Read the contents of the specified key.
    ///
    /// Returns `Ok(None)` if the file doesn't exist.
    fn read_key(&self, key_path: &Path) -> Result<Option<String>> {
        let key_path = self.0.rel_path(key_path.into());

        // TODO: read and parse the key, see if it matches the specified hsid
        let content = match checked_op!(read_to_string, key_path) {
            Err(fs_mistrust::Error::NotFound(_)) => {
                // Someone removed the file between the time we read the directory and now.
                return Ok(None);
            }
            res => res
                .map_err(|err| FilesystemError::FsMistrust {
                    action: FilesystemAction::Read,
                    path: key_path.rel_path_unchecked().into(),
                    err: err.into(),
                })
                .map_err(CTorKeystoreError::Filesystem)?,
        };

        Ok(Some(content))
    }

    /// List all entries in this store
    fn list_keys(&self) -> Result<impl Iterator<Item = (HsId, HsClientDescEncKeypair)> + '_> {
        let dir = self.0.rel_path(PathBuf::from("."));
        Ok(self.list_entries(&dir)?.filter_map(|entry| {
            let entry = entry
                .map_err(|e| {
                    // Note: can't use debug_report here, because debug_report
                    // expects the ErrorKind (returned by e.kind()) to be
                    // tor_error::ErrorKind (which has a is_always_a_warning() function
                    // used by the macro).
                    //
                    // We have an io::Error here, which has an io::ErrorKind,
                    // and thus can't be used with debug_report.
                    debug!("cannot access key entry: {e}");
                })
                .ok()?;

            let file_name = entry.file_name();
            let path: &Path = file_name.as_ref();
            let extension = path.extension().and_then(|e| e.to_str());
            if extension != Some(KEY_EXTENSION) {
                debug!(
                    "found entry {} with unrecognized extension {} in C Tor client keystore",
                    path.display_lossy(),
                    extension.unwrap_or_default()
                );
                return None;
            }

            let content = self
                .read_key(path)
                .map_err(|e| {
                    debug_report!(e, "failed to read {}", path.display_lossy());
                })
                .ok()
                .flatten()?;

            let (hsid, key) = parse_client_keypair(content.trim())
                .map_err(|e| CTorKeystoreError::MalformedKey {
                    path: path.into(),
                    err: e.into(),
                })
                .map_err(|e| {
                    debug_report!(
                        e,
                        "cannot parse C Tor client keystore entry {}",
                        path.display_lossy()
                    );
                })
                .ok()?;

            Some((hsid, key))
        }))
    }
}

/// Parse a client restricted discovery keypair,
/// returning the [`HsId`] of the service the key is meant for,
/// and the corresponding [`HsClientDescEncKeypair`].
///
/// `key` is expected to be in the
/// `<hsid>:descriptor:x25519:<base32-encoded-x25519-public-key>`
/// format.
///
/// TODO: we might want to move this to tor-hscrypto at some point,
/// but for now, we don't actually *need* to expose this publically.
fn parse_client_keypair(
    key: impl AsRef<str>,
) -> StdResult<(HsId, HsClientDescEncKeypair), MalformedClientKeyError> {
    let key = key.as_ref();
    let (hsid, auth_type, key_type, encoded_key) = key
        .split(':')
        .collect_tuple()
        .ok_or(MalformedClientKeyError::InvalidFormat)?;

    if auth_type != "descriptor" {
        return Err(MalformedClientKeyError::InvalidAuthType(auth_type.into()));
    }

    if key_type != "x25519" {
        return Err(MalformedClientKeyError::InvalidKeyType(key_type.into()));
    }

    // Note: Tor's base32 decoder is case-insensitive, so we can't assume the input
    // is all uppercase.
    //
    // TODO: consider using `data_encoding_macro::new_encoding` to create a new Encoding
    // with an alphabet that includes lowercase letters instead of to_uppercase()ing the string.
    let encoded_key = encoded_key.to_uppercase();
    let x25519_sk = data_encoding::BASE32_NOPAD.decode(encoded_key.as_bytes())?;
    let x25519_sk: [u8; 32] = x25519_sk
        .try_into()
        .map_err(|_| MalformedClientKeyError::InvalidKeyMaterial)?;

    let secret = curve25519::StaticSecret::from(x25519_sk);
    let public = (&secret).into();
    let x25519_keypair = curve25519::StaticKeypair { secret, public };
    let hsid = HsId::from_str(&format!("{hsid}.onion"))?;

    Ok((hsid, x25519_keypair.into()))
}

impl Keystore for CTorClientKeystore {
    fn id(&self) -> &KeystoreId {
        &self.0.id
    }

    fn contains(&self, key_spec: &dyn KeySpecifier, item_type: &KeystoreItemType) -> Result<bool> {
        self.get(key_spec, item_type).map(|k| k.is_some())
    }

    fn get(&self, key_spec: &dyn KeySpecifier, item_type: &KeystoreItemType) -> Result<Option<ErasedKey>> {
        let want_hsid = hsid_if_supported!(key_spec, Ok(None), item_type);
        Ok(self
            .list_keys()?
            .find_map(|(hsid, key)| (hsid == want_hsid).then(|| key.into()))
            .map(|k: curve25519::StaticKeypair| Box::new(k) as ErasedKey))
    }

    fn insert(
        &self,
        _key: &dyn EncodableItem,
        _key_spec: &dyn KeySpecifier,
        _item_type: &KeystoreItemType,
    ) -> Result<()> {
        Err(CTorKeystoreError::NotSupported { action: "insert" }.into())
    }

    fn remove(&self, _key_spec: &dyn KeySpecifier, _item_type: &KeystoreItemType) -> Result<Option<()>> {
        Err(CTorKeystoreError::NotSupported { action: "remove" }.into())
    }

    fn list(&self) -> Result<Vec<(KeyPath, KeystoreItemType)>> {
        let keys = self
            .list_keys()?
            .map(|(hsid, _)| {
                (
                    CTorPath::ClientHsDescEncKey(hsid).into(),
                    KeyType::X25519StaticKeypair.into(),
                )
            })
            .collect();

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
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
    use std::fs;
    use tempfile::{tempdir, TempDir};

    use crate::test_utils::{assert_found, DummyKey, TestCTorSpecifier};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// A valid client restricted discovery key.
    const ALICE_AUTH_PRIVATE_VALID: &str = include_str!("../../../testdata/alice.auth_private");

    /// An invalid client restricted discovery key.
    const BOB_AUTH_PRIVATE_INVALID: &str = include_str!("../../../testdata/bob.auth_private");

    /// A valid client restricted discovery key.
    const CAROL_AUTH_PRIVATE_VALID: &str = include_str!("../../../testdata/carol.auth_private");

    /// A valid client restricted discovery key.
    const DAN_AUTH_PRIVATE_VALID: &str = include_str!("../../../testdata/dan.auth_private");

    // An .onion addr we don't have a client key for.
    const HSID: &str = "mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad.onion";

    fn init_keystore(id: &str) -> (CTorClientKeystore, TempDir) {
        let keystore_dir = tempdir().unwrap();

        #[cfg(unix)]
        fs::set_permissions(&keystore_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let id = KeystoreId::from_str(id).unwrap();
        let keystore =
            CTorClientKeystore::from_path_and_mistrust(&keystore_dir, &Mistrust::default(), id)
                .unwrap();

        let keys: &[(&str, &str)] = &[
            ("alice.auth_private", ALICE_AUTH_PRIVATE_VALID),
            // A couple of malformed key, added to check that our impl doesn't trip over them
            ("bob.auth_private", BOB_AUTH_PRIVATE_INVALID),
            (
                "alice-truncated.auth_private",
                &ALICE_AUTH_PRIVATE_VALID[..100],
            ),
            // A valid key, but with the wrong extension (so it should be ignored)
            ("carol.auth", CAROL_AUTH_PRIVATE_VALID),
            ("dan.auth_private", DAN_AUTH_PRIVATE_VALID),
        ];

        for (name, key) in keys {
            fs::write(keystore_dir.path().join(name), key).unwrap();
        }

        (keystore, keystore_dir)
    }

    #[test]
    fn get() {
        let (keystore, _keystore_dir) = init_keystore("foo");
        let path = CTorPath::ClientHsDescEncKey(HsId::from_str(HSID).unwrap());

        // Not found!
        assert_found!(
            keystore,
            &TestCTorSpecifier(path.clone()),
            &KeyType::X25519StaticKeypair,
            false
        );

        for hsid in &[ALICE_AUTH_PRIVATE_VALID, DAN_AUTH_PRIVATE_VALID] {
            // Extract the HsId associated with this key.
            let onion = hsid.split(":").next().unwrap();
            let hsid = HsId::from_str(&format!("{onion}.onion")).unwrap();
            let path = CTorPath::ClientHsDescEncKey(hsid.clone());

            // Found!
            assert_found!(
                keystore,
                &TestCTorSpecifier(path.clone()),
                &KeyType::X25519StaticKeypair,
                true
            );
        }

        let keys: Vec<_> = keystore.list().unwrap();

        assert_eq!(keys.len(), 2);
        assert!(keys
            .iter()
            .all(|(_, key_type)| *key_type == KeyType::X25519StaticKeypair.into()));
    }

    #[test]
    fn unsupported_operation() {
        let (keystore, _keystore_dir) = init_keystore("foo");
        let path = CTorPath::ClientHsDescEncKey(HsId::from_str(HSID).unwrap());

        let err = keystore
            .remove(
                &TestCTorSpecifier(path.clone()),
                &KeyType::X25519StaticKeypair.into(),
            )
            .unwrap_err();

        assert_eq!(err.to_string(), "Operation not supported: remove");

        let err = keystore
            .insert(
                &DummyKey,
                &TestCTorSpecifier(path),
                &KeyType::X25519StaticKeypair.into(),
            )
            .unwrap_err();

        assert_eq!(err.to_string(), "Operation not supported: insert");
    }

    #[test]
    fn wrong_keytype() {
        let (keystore, _keystore_dir) = init_keystore("foo");
        let path = CTorPath::ClientHsDescEncKey(HsId::from_str(HSID).unwrap());

        let err = keystore
            .get(&TestCTorSpecifier(path.clone()), &KeyType::Ed25519PublicKey.into())
            .map(|_| ())
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid key type Ed25519PublicKey for client restricted discovery key"
        );
    }
}
