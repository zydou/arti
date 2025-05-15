BREAKING: Removed the always-deprecated `empty_iterator()` method from types
created using `n_key_list!` macro. This is not *technically* a semver breaking
change, but will break crates that use the now-removed `empty_iterator()`
method, so should probably be documented in the changelog.
