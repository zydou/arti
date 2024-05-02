//! ArtiEphemeralKeystore implementation (in-memory ephemeral key storage)

pub(crate) mod err;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ssh_key::private::PrivateKey;
use ssh_key::{LineEnding, PublicKey};
use zeroize::Zeroizing;

use crate::key_type::ssh::UnparsedOpenSshKey;
use crate::keystore::ephemeral::err::ArtiEphemeralKeystoreError;
use crate::Error;
use crate::{
    ArtiPath, EncodableKey, ErasedKey, KeyPath, KeySpecifier, KeyType, Keystore, KeystoreId,
    SshKeyData,
};

/// The identifier of a key stored in the `ArtiEphemeralKeystore`.
type KeyIdent = (ArtiPath, KeyType);
/// The value of a key stored in `ArtiEphemeralKeystore`
type KeyValue = Zeroizing<String>;

/// The Ephemeral Arti key store
///
/// This is a purely in-memory key store. Keys written to this store
/// are never written to disk, and are stored in-memory as `Zeroizing<String>`.
/// Keys saved in this Keystore do not persist between restarts!
pub struct ArtiEphemeralKeystore {
    /// Identifier hard-coded to 'ephemeral'
    id: KeystoreId,
    /// Keys stored as openssl-encoded zeroizing strings
    key_dictionary: Arc<Mutex<HashMap<KeyIdent, KeyValue>>>,
}

impl ArtiEphemeralKeystore {
    /// Create a new [`ArtiEphemeralKeystore`]
    pub fn new(id: String) -> Self {
        Self {
            id: KeystoreId(id),
            key_dictionary: Default::default(),
        }
    }
}

impl Keystore for ArtiEphemeralKeystore {
    fn id(&self) -> &KeystoreId {
        &self.id
    }

    fn contains(&self, key_spec: &dyn KeySpecifier, key_type: &KeyType) -> Result<bool, Error> {
        let arti_path = key_spec
            .arti_path()
            .map_err(ArtiEphemeralKeystoreError::ArtiPathUnavailableError)?;
        let key_dictionary = self.key_dictionary.lock().expect("lock poisoned");
        let contains_key = key_dictionary.contains_key(&(arti_path, key_type.clone()));
        Ok(contains_key)
    }

    fn get(
        &self,
        key_spec: &dyn KeySpecifier,
        key_type: &KeyType,
    ) -> Result<Option<ErasedKey>, Error> {
        let arti_path = key_spec
            .arti_path()
            .map_err(ArtiEphemeralKeystoreError::ArtiPathUnavailableError)?;
        let key_dictionary = self.key_dictionary.lock().expect("lock poisoned");
        match key_dictionary.get(&(arti_path.clone(), key_type.clone())) {
            Some(openssh_key) => {
                let unparsed_openssh_key =
                    UnparsedOpenSshKey::new(openssh_key.to_string(), Default::default());
                unparsed_openssh_key
                    .parse_ssh_format_erased(key_type)
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    fn insert(
        &self,
        key: &dyn EncodableKey,
        key_spec: &dyn KeySpecifier,
        key_type: &KeyType,
    ) -> Result<(), Error> {
        let arti_path = key_spec
            .arti_path()
            .map_err(ArtiEphemeralKeystoreError::ArtiPathUnavailableError)?;
        // serialise key to string
        let ssh_data = key.as_ssh_key_data()?;
        let comment = "";
        let openssh_key = match ssh_data {
            SshKeyData::Public(key_data) => PublicKey::new(key_data, comment)
                .to_openssh()
                .map_err(ArtiEphemeralKeystoreError::SshKeySerialize)?,
            SshKeyData::Private(keypair) => PrivateKey::new(keypair, comment)
                .map_err(ArtiEphemeralKeystoreError::SshKeySerialize)?
                .to_openssh(LineEnding::LF)
                .map_err(ArtiEphemeralKeystoreError::SshKeySerialize)?
                .to_string(),
        };
        // verify our serialised key round-trips before saving it to dictionary
        let unparsed_openssh_key = UnparsedOpenSshKey::new(openssh_key.clone(), Default::default());
        let _ = unparsed_openssh_key.parse_ssh_format_erased(key_type)?;

        // save to dictionary
        let mut key_dictionary = self.key_dictionary.lock().expect("lock poisoned");
        let _ = key_dictionary.insert((arti_path, key_type.clone()), openssh_key.into());
        Ok(())
    }

    fn remove(&self, key_spec: &dyn KeySpecifier, key_type: &KeyType) -> Result<Option<()>, Error> {
        let arti_path = key_spec
            .arti_path()
            .map_err(ArtiEphemeralKeystoreError::ArtiPathUnavailableError)?;
        let mut key_dictionary = self.key_dictionary.lock().expect("lock poisoned");
        Ok(key_dictionary
            .remove(&(arti_path, key_type.clone()))
            .map(|_| ()))
    }

    fn list(&self) -> Result<Vec<(KeyPath, KeyType)>, Error> {
        let key_dictionary = self.key_dictionary.lock().expect("lock poisoned");
        Ok(key_dictionary
            .keys()
            .map(|(arti_path, key_type)| (arti_path.clone().into(), key_type.clone()))
            .collect())
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

    use tor_basic_utils::test_rng::testing_rng;
    use tor_llcrypto::pk::ed25519;

    use super::*;

    use crate::test_utils::TestSpecifier;

    // some helper methods

    fn key() -> ErasedKey {
        let mut rng = testing_rng();
        let keypair = ed25519::Keypair::generate(&mut rng);
        Box::new(keypair)
    }

    fn key_type() -> &'static KeyType {
        &KeyType::Ed25519Keypair
    }

    fn key_type_bad() -> &'static KeyType {
        &KeyType::X25519StaticKeypair
    }

    fn key_spec() -> Box<dyn KeySpecifier> {
        Box::<TestSpecifier>::default()
    }

    // tests!

    #[test]
    fn id() {
        let key_store = ArtiEphemeralKeystore::new("test-ephemeral".to_string());

        assert_eq!(&KeystoreId("test-ephemeral".to_string()), key_store.id());
    }

    #[test]
    fn contains() {
        let key_store = ArtiEphemeralKeystore::new("test-ephemeral".to_string());

        // verify no key in store
        assert!(!key_store.contains(key_spec().as_ref(), key_type()).unwrap());

        // insert key and verify in store
        assert!(key_store
            .insert(key().as_ref(), key_spec().as_ref(), key_type())
            .is_ok());
        assert!(key_store.contains(key_spec().as_ref(), key_type()).unwrap());
    }

    #[test]
    fn get() {
        let key_store = ArtiEphemeralKeystore::new("test-ephemeral".to_string());

        // verify no result to get
        assert!(key_store
            .get(key_spec().as_ref(), key_type())
            .unwrap()
            .is_none());

        // insert and verify get is a result
        assert!(key_store
            .insert(key().as_ref(), key_spec().as_ref(), key_type())
            .is_ok());
        assert!(key_store
            .get(key_spec().as_ref(), key_type())
            .unwrap()
            .is_some());
    }

    #[test]
    fn insert() {
        let key_store = ArtiEphemeralKeystore::new("test-ephemeral".to_string());

        // verify inserting a key with the wrong key type fails
        assert!(key_store
            .insert(key().as_ref(), key_spec().as_ref(), key_type_bad())
            .is_err());
        // further ensure theres is no sideffects
        assert!(!key_store
            .contains(key_spec().as_ref(), key_type_bad())
            .unwrap());
        assert!(key_store
            .get(key_spec().as_ref(), key_type_bad())
            .unwrap()
            .is_none());
        assert!(key_store.list().unwrap().is_empty());

        // verify inserting a goood key succeeds
        assert!(key_store
            .insert(key().as_ref(), key_spec().as_ref(), key_type())
            .is_ok());

        // further ensure correct side effects
        assert!(key_store.contains(key_spec().as_ref(), key_type()).unwrap());
        assert!(key_store
            .get(key_spec().as_ref(), key_type())
            .unwrap()
            .is_some());
        assert_eq!(key_store.list().unwrap().len(), 1);
    }

    #[test]
    fn remove() {
        let key_store = ArtiEphemeralKeystore::new("test-ephemeral".to_string());

        // verify removing from an empty store returns None
        assert!(key_store
            .remove(key_spec().as_ref(), key_type())
            .unwrap()
            .is_none());

        // verify inserting and removing results in Some(())
        assert!(key_store
            .insert(key().as_ref(), key_spec().as_ref(), key_type())
            .is_ok());
        assert!(key_store
            .remove(key_spec().as_ref(), key_type())
            .unwrap()
            .is_some());
    }

    #[test]
    fn list() {
        let key_store = ArtiEphemeralKeystore::new("test-ephemeral".to_string());

        // verify empty by default
        assert!(key_store.list().unwrap().is_empty());

        // verify size 1 after inserting a key
        assert!(key_store
            .insert(key().as_ref(), key_spec().as_ref(), key_type())
            .is_ok());
        assert_eq!(key_store.list().unwrap().len(), 1);
    }
}
