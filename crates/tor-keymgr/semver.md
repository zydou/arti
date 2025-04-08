### BREAKING: Drop param `item_type: &KeystoreItemType` from `Keystore::insert`

`Keystore::insert` now uses param `key: &dyn EncodableItem` to obtain a `KeystoreItemType`.
