### BREAKING:

`UnrecognizedEntryError::new` associated function is now only accessible within the crate `tor-keymgr`.
`UnrecognizedEntryId` is renamed to `UnrecognizedEntry`.
`KeyMgr::list()` and `Keystore::list()` now return `Result<Vec<KeystoreEntryResult<KeystoreEntry>>>`.
