ADDED: `PartialEq` and `Eq` for `Lifetime`
BREAKING: `types::routerdesc` moved into `doc::routerdesc` and `types::descriptor`
ADDED: `RouterDesc` now provides construction logic instead of `#[non_exhaustive]`
ADDED: `Lines::clone_entirely_consumed`
BREAKING: `parse2::ItemStream::new` is now infallible.
ADDED: `parse2::parse_netdoc_multiple_sophisticated`
ADDED: `test_support::parse_test_document`
ADDED: `testdata_live`: parsed document functions (eg `netstatus_plain`)
ADDED: `testdata_live::relay_document_by_nick`
ADDED: `Nickname::as_str` and `AsRef<str>`
ADDED: `ItemStream::with_inner_lines_mut`
