BREAKING: `RouterStatus::addrs` now returns `impl Iterator<Item = SocketAddr>`.
BREAKING: `RouterStatus::orport_addrs` abolished; use `::addrs` instead.
BREAKING: Replace `ItemArgumentParseable for impl FromStr` with `NormalItemParseable`
ADDED: `Fingerprint` and `Base64Fingerprint` are now `Display`
ADDED: `impl From<Base64Fingerprint> for RsaIdentity`
BREAKING: `ArgumentStream::is_nonempty_after_trim_start` renamed to `something_to_yield`
BREAKING: `ArgumentStream::reject_extra_args` now throws new `UnexpectedArgument` error type
BREAKING: `ItemArgumentParseable` etc. now throws new `ArgumentError` enum
ADDED: `ArgumentStream::handle_error` and `error_handler` for converting `ArgumentError`
BREAKING: `ItemArgumentParseable` etc. no longer take `field: &'static str`
ADDED: `parse2::UnparsedItem::args()` accessor
BREAKING: Some `parse2::ErrorProblem` variants have new `column` field.
ADDED: `parse2::ErrorProblem::column()`
