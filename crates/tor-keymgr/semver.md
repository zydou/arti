BREAKING: `ErasedKey` (returned by `Keystore::get`) is now a type alias to
`Box<dyn EncodableKey>` instead of `Box<dyn Any>`
ADDED: `config` module exposing `ArtiNativeKeystoreConfig`
BREAKING: `ArtiNativeKeyStoreConfig` fields are now private
ADDED: `ArtiNativeKeyStoreConfig::is_enabled` function
BREAKING: `KeyMgr::new` takes an extra argument (the default keystore)
ADDED: `KeystoreSelector`
BREAKING: `KeystoreError` now has a `boxed` function
ADDED: an `id` function to `Keystore` trait
BREAKING: `KeyMgr::insert`, `KeyMgr::remove` now take an
`selector: KeystoreSelector` argument
REMOVED: the `has_key_bundle` function (from the `Keystore` trait)
ADDED: `PartialEq`, `Eq`, `Hash` derives for `ArtiPath` and `KeyType`
ADDED: a `to_bytes` function to `EncodableKey` trait

