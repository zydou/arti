BREAKING: `ArtiNativeKeystoreConfig` type renamed to `ArtiKeystoreConfig`
BREAKING: `KeystoreSelector::Default` renamed to  `KeystoreSelector::Primary`
BREAKING: `KeymgrBuilder::default_store` renamed to `KeystoreSelector::primary_store`
BREAKING: The `config::arti` module doesn't exist anymore (all the types from it are now exported directly from `config`)
BREAKING: `KeyPath` no longer implements `PartialOrd`, `Ord`
BREAKING: `CTorPath` no longer implements `PartialOrd`, `Ord`, `Deref`, `DerefMut`
