BREAKING: Remove `Eq` on `RouterDesc` and `RouterDescSignatures`
BREAKING: Remove `Eq` on `EmbeddedCert` and `NtorOnionKeyCrossCert`
ADDED: `NetdocEncodable` for `RouterDesc`
ADDED: `NetdocEncodable` for `RouterDescSignatures`
ADDED: `ItemValueEncodable` for `RouterSignature`
ADDED: `types::policy::IpPattern`
ADDED: `types::policy::AddrPortPattern`: `addrs` and `ports` fields exposed
ADDED: `types::policy::AddrPortPattern`: impl `Hash`, provide `new`
ADDED: `types::policy::AddrPolicy::rules` accessor
ADDED: `types::policy::PortRange::from_range`, `to_range`
ADDED: `types::policy::PortRange` is `Copy`
ADDED: `types::policy::AddrPolicy::rules` returns a `DoubleEndedIterator`
ADDED: `rangemap_mutate_range`
ADDED: votes: `doc::netstatus::vote`, `NetworkStatusVote`
ADDED: parts of votes: `VoteAuthoritySection`, `RouterStatusMdDigestsVote`
ADDED: encoding for votes: `doc::nettstatus::consensus_methods_comma_separated::write_arg_onto`
ADDED: `AuthCert`: `encode_sign`, `EncodedAuthCert`
ADDED: `types::policy::AddrPolicy::summarise_precise` (and `PortPolicies`, `PortSummaryThresholds`
ADDED: `ConsensusMethod`'s field is now `pub`
BREAKING: `NetdocParseableFields::Accumulator` must be `Default`
ADDED: `types::policy::PortPolicy::from_ordered_allowed_ranges`
BREAKING: `HsDesc::parse_decrypt_validate` no longer takes a `SystemTime` and **no longer checks validity time**
ADDED: `encode::encode_netdoc_unsigned` and `encode_netdoc_fields`
ADDED: impl `Hash` for `netstatus::ConsensusMethods`
