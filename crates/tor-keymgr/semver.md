ADDED: getters for `KeyPathInfo`
REMOVED: `KeyPathExtractor`
ADDED: `KeyPathInfoExtractor`
BREAKING: `KeyMgr::insert` returns `Result<Option<K>>`
BREAKING: `KeyMgr::remove` returns `Result<Option<K>>`
ADDED: `KeystoreEntry`
BREAKING: `KeyMgr::list_matching` now returns `KeystoreEntry`
REMOVED: `KeyMgr::remove_with_type`
ADDED: `KeyMgr::remove_entry`
REMOVED: `KeyMgr::get_with_type`
ADDED: `KeyMgr::get_entry`
