BREAKING: Abolished `DirectorySignaturesHashesAccu` field `sha1_unnamed`.
BREAKING: `Preamble`: `voting_delay` is now a mandatory field in the `Constructor`
BREAKING: `Preamble`: `voting_delay` is now a custom type `VotingDelay`
ADDED: `DocRelayFlag`, `DocRelayFlags::iter_incl_unknown`, `contains_impl_unknown`
ADDED: `DocRelayFlags` impl `FromIterator<DocRelayFlag>`
ADDED: `SupersededAuthorityKey::from_dir_source_and_key`
