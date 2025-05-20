### BREAKING: The signature of `Keystore::list` has changed

* `Keystore::list` now returns type `Result<Vec<KeystoreEntryResult<(KeyPath, KeystoreItemType)>>>`.
