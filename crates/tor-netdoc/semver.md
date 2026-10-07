BREAKING: Abolished `DirectorySignaturesHashesAccu` field `sha1_unnamed`.
BREAKING: `Preamble`: `voting_delay` is now a mandatory field in the `Constructor`
BREAKING: `Preamble`: `voting_delay` is now a custom type `VotingDelay`
ADDED: `DocRelayFlag`, `DocRelayFlags::iter_incl_unknown`, `contains_impl_unknown`
ADDED: `DocRelayFlags` impl `FromIterator<DocRelayFlag>`
ADDED: `SupersededAuthorityKey::from_dir_source_and_key`
ADDED: `netstatus::ConsensusAuthoritySectionConstructor`, `DirSourceConstructor`
ADDED: `IdentifiedDigest` is now exhaustive, with fields `pub`
ADDED: `{FixedB64, FixedB16U}::from_byte_slice`
ADDED: `ProtoStatusesConstructor`; `ProtoStatuses` fields are now `pub`
ADDED: `ProtoStatusConstructor`; `ProtoStatus` fields are now `pub`
