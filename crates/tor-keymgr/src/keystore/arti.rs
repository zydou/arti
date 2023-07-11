//! The Arti key store.
//!
//! The Arti key store stores the keys on disk in OpenSSH format.

pub(crate) mod err;

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::key_type::ssh::UnparsedOpenSshKey;
use crate::keystore::{EncodableKey, ErasedKey, KeySpecifier, Keystore};
use crate::{KeyType, Result};
use err::{ArtiNativeKeystoreError, FilesystemAction};

use fs_mistrust::{CheckedDir, Mistrust};

/// The Arti key store.
#[derive(Debug)]
pub struct ArtiNativeKeystore {
    /// The root of the key store.
    keystore_dir: CheckedDir,
}

impl ArtiNativeKeystore {
    /// Create a new [`ArtiNativeKeystore`] rooted at the specified `keystore_dir` directory.
    ///
    /// The `keystore_dir` directory is created if it doesn't exist.
    ///
    /// This function returns an error if `keystore_dir` is not a directory, if it does not conform
    /// to the requirements of the specified `Mistrust`, or if there was a problem creating the
    /// directory.
    pub fn from_path_and_mistrust(
        keystore_dir: impl AsRef<Path>,
        mistrust: &Mistrust,
    ) -> Result<Self> {
        let keystore_dir = mistrust
            .verifier()
            .check_content()
            .make_secure_dir(&keystore_dir)
            .map_err(|e| ArtiNativeKeystoreError::FsMistrust {
                action: FilesystemAction::Init,
                path: keystore_dir.as_ref().into(),
                err: e.into(),
            })?;

        Ok(Self { keystore_dir })
    }

    /// The path on disk of the key with the specified identity and type, relative to
    /// `keystore_dir`.
    fn key_path(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<PathBuf> {
        let arti_path: String = key_spec.arti_path()?.into();
        let mut rel_path = PathBuf::from(arti_path);
        rel_path.set_extension(key_type.arti_extension());

        Ok(rel_path)
    }
}

impl Keystore for ArtiNativeKeystore {
    fn get(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<ErasedKey>> {
        let path = self.key_path(key_spec, key_type)?;

        let inner = match self.keystore_dir.read(&path) {
            Err(fs_mistrust::Error::NotFound(_)) => return Ok(None),
            Err(fs_mistrust::Error::Io { err, .. }) if err.kind() == ErrorKind::NotFound => {
                return Ok(None);
            }
            res => res.map_err(|err| ArtiNativeKeystoreError::FsMistrust {
                action: FilesystemAction::Read,
                path: path.clone(),
                err: err.into(),
            })?,
        };

        key_type
            .parse_ssh_format_erased(UnparsedOpenSshKey::new(inner, path))
            .map(Some)
    }

    fn insert(
        &self,
        key: &dyn EncodableKey,
        key_spec: &dyn KeySpecifier,
        key_type: KeyType,
    ) -> Result<()> {
        let path = self.key_path(key_spec, key_type)?;
        let openssh_key = key_type.to_ssh_format(key)?;

        Ok(self
            .keystore_dir
            .write_and_replace(&path, openssh_key)
            .map_err(|err| ArtiNativeKeystoreError::FsMistrust {
                action: FilesystemAction::Write,
                path,
                err: err.into(),
            })?)
    }

    fn remove(&self, key_spec: &dyn KeySpecifier, key_type: KeyType) -> Result<Option<()>> {
        let key_path = self.key_path(key_spec, key_type)?;

        let abs_key_path =
            self.keystore_dir
                .join(&key_path)
                .map_err(|e| ArtiNativeKeystoreError::FsMistrust {
                    action: FilesystemAction::Remove,
                    path: key_path.clone(),
                    err: e.into(),
                })?;

        match fs::remove_file(abs_key_path) {
            Ok(()) => Ok(Some(())),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound) => Ok(None),
            Err(e) => Err(ArtiNativeKeystoreError::Filesystem {
                action: FilesystemAction::Remove,
                path: key_path,
                err: e.into(),
            }
            .into()),
        }
    }

    fn has_key_bundle(&self, _key_spec: &dyn KeySpecifier) -> Result<bool> {
        // TODO HSS (#903): implement
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::{ArtiPath, CTorPath};
    use std::fs;
    use tempfile::{tempdir, TempDir};
    use tor_llcrypto::pk::ed25519;

    // TODO HS TEST: this is included twice in the binary (refactor the test utils so that we only
    // include it once)
    const OPENSSH_ED25519: &[u8] = include_bytes!("../../testdata/ed25519_openssh.private");

    struct TestSpecifier;

    impl KeySpecifier for TestSpecifier {
        fn arti_path(&self) -> Result<ArtiPath> {
            ArtiPath::new("test-specifier".into())
        }

        fn ctor_path(&self) -> Option<CTorPath> {
            None
        }
    }

    fn key_path(key_store: &ArtiNativeKeystore, key_type: KeyType) -> PathBuf {
        let rel_key_path = key_store.key_path(&TestSpecifier, key_type).unwrap();

        key_store.keystore_dir.as_path().join(rel_key_path)
    }

    fn init_keystore(gen_keys: bool) -> (ArtiNativeKeystore, TempDir) {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let keystore_dir = tempdir().unwrap();

        #[cfg(unix)]
        fs::set_permissions(&keystore_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let key_store =
            ArtiNativeKeystore::from_path_and_mistrust(&keystore_dir, &Mistrust::default())
                .unwrap();

        if gen_keys {
            let key_path = key_path(&key_store, KeyType::Ed25519Keypair);
            fs::write(key_path, OPENSSH_ED25519).unwrap();
        }

        (key_store, keystore_dir)
    }

    macro_rules! assert_found {
        ($key_store:expr, $key_spec:expr, $key_type:expr, $found:expr) => {{
            let res = $key_store.get($key_spec, $key_type).unwrap();
            if $found {
                assert!(res.is_some());
            } else {
                assert!(res.is_none());
            }
        }};
    }

    #[test]
    #[cfg(unix)]
    fn init_failure_perms() {
        use std::os::unix::fs::PermissionsExt;

        let keystore_dir = tempdir().unwrap();

        // Too permissive
        let mode = 0o777;

        fs::set_permissions(&keystore_dir, fs::Permissions::from_mode(mode)).unwrap();
        let err = ArtiNativeKeystore::from_path_and_mistrust(&keystore_dir, &Mistrust::default())
            .expect_err(&format!("expected failure (perms = {mode:o})"));

        assert_eq!(
            err.to_string(),
            format!(
                "Invalid path or permissions on {} while attempting to Init",
                keystore_dir.path().display()
            ),
            "expected keystore init failure (perms = {:o})",
            mode
        );
    }

    #[test]
    fn key_path_repr() {
        let (key_store, _) = init_keystore(false);

        assert_eq!(
            key_store
                .key_path(&TestSpecifier, KeyType::Ed25519Keypair)
                .unwrap(),
            PathBuf::from("test-specifier.ed25519_private")
        );

        assert_eq!(
            key_store
                .key_path(&TestSpecifier, KeyType::X25519StaticSecret)
                .unwrap(),
            PathBuf::from("test-specifier.x25519_private")
        );
    }

    #[cfg(unix)]
    #[test]
    fn get_and_rm_bad_perms() {
        use std::os::unix::fs::PermissionsExt;

        let (key_store, _keystore_dir) = init_keystore(true);

        let key_path = key_path(&key_store, KeyType::Ed25519Keypair);

        // Make the permissions of the test key too permissive
        fs::set_permissions(key_path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(key_store
            .get(&TestSpecifier, KeyType::Ed25519Keypair)
            .is_err());

        // TODO HSS: remove works even if the permissions are not restrictive enough for other
        // the operations... I **think** this is alright, but we might want to give this a bit more
        // thought before we document and advertise this behaviour.
        assert_eq!(
            key_store
                .remove(&TestSpecifier, KeyType::Ed25519Keypair)
                .unwrap(),
            Some(())
        );
    }

    #[test]
    fn get() {
        // Initialize an empty key store
        let (key_store, _keystore_dir) = init_keystore(false);

        // Not found
        assert_found!(key_store, &TestSpecifier, KeyType::Ed25519Keypair, false);

        // Initialize a key store with some test keys
        let (key_store, _keystore_dir) = init_keystore(true);

        // Found!
        assert_found!(key_store, &TestSpecifier, KeyType::Ed25519Keypair, true);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")] // TODO HSS: remove when KeyType::to_ssh_format is implemented
    fn insert() {
        // Initialize an empty key store
        let (key_store, _keystore_dir) = init_keystore(false);

        // Not found
        assert_found!(key_store, &TestSpecifier, KeyType::Ed25519Keypair, false);

        // Insert the key
        let key = UnparsedOpenSshKey::new(OPENSSH_ED25519.into(), PathBuf::from("/test/path"));
        let erased_kp = KeyType::Ed25519Keypair
            .parse_ssh_format_erased(key)
            .unwrap();

        let Ok(key) = erased_kp.downcast::<ed25519::Keypair>() else {
            panic!("failed to downcast key to ed25519::Keypair")
        };

        key_store
            .insert(&*key, &TestSpecifier, KeyType::Ed25519Keypair)
            .unwrap();

        // Found!
        assert_found!(key_store, &TestSpecifier, KeyType::Ed25519Keypair, true);
    }

    #[test]
    fn remove() {
        // Initialize the key store
        let (key_store, _keystore_dir) = init_keystore(true);

        assert_found!(key_store, &TestSpecifier, KeyType::Ed25519Keypair, true);

        // Now remove the key... remove() should indicate success by returning Ok(Some(()))
        assert_eq!(
            key_store
                .remove(&TestSpecifier, KeyType::Ed25519Keypair)
                .unwrap(),
            Some(())
        );

        // Can't find it anymore!
        assert_found!(key_store, &TestSpecifier, KeyType::Ed25519Keypair, false);

        // remove() returns Ok(None) now.
        assert!(key_store
            .remove(&TestSpecifier, KeyType::Ed25519Keypair)
            .unwrap()
            .is_none());
    }

    #[test]
    fn key_bundles() {
        // TODO HSS TEST: implement has_key_bundle and write a proper test
        let (key_store, _keystore_dir) = init_keystore(true);

        assert!(key_store.has_key_bundle(&TestSpecifier).unwrap());
    }
}
