BREAKING: `parse2 ItemValueParseable` `netdoc(rest, with=)` attr behaviour changed
ADDED: `ItemEncoder::args_raw_string`
ADDED: `NetdocEncodable`, `ItemValueEncodable` etc. derivable traits for encoding,
ADDED: `parse2::ItemStream::byte_position`
ADDED: `parse2::parse_netdoc_multiple_with_offsets`
BREAKING: `AuthCert::key_ids` returns an owned `AuthCertKeyIds`
BREAKING: `AuthCert::sk_fingerprint` removed.  Use `key_ids()`.
