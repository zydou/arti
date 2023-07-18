BREAKING: `ErasedKey` (returned by `Keystore::get`) is now a type alias to
`Box<dyn EncodableKey>` instead of `Box<dyn Any>`
ADDED: `config` module exposing `ArtiNativeKeystoreConfig`
BREAKING: `ArtiNativeKeyStoreConfig` fields are now private
ADDED: `ArtiNativeKeyStoreConfig::is_enabled` function
BREAKING: `KeyMgr::new` takes an extra argument (the default keystore)
ADDED: an `id` function to `Keystore` trait
