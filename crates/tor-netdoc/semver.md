BREAKING: Rename `RelayWeight` to `RelayBandwidth`, `RelayBandwidthItem` as `RelayWeightsItem`, etc.
BREAKING: Rename `RouterStatus` field `weight` to `w`
BREAKING: `NetParams<T>` split up into `NetParams` and `ParamValues<T>`
BREAKING: Rename `RelayFamilyId` to `HappyFamilyId`
BREAKING: Rename `RelayFamilyIds` to `HappyFamilyIds`
BREAKING: Rename `RelayFamily` to `LegacyFamily`
ADDED: `NetParamValues` type alias
ADDED: `RouterStatusMdDigestsVoteConstructor`
ADDED: `RouterStatusMdDigestsVote::iter_cross_product_digests`
ADDED: `ConsensusMethods` convertible to/from, and derefs to, `BTreeSet`; is exhaustive
ADDED: `SharedRandVal` impls `Hash`
ADDED: `SharedRandStatus` impls `Eq, PartialEq, Hash`
ADDED: `SharedRandStatusesConstructdor`
ADDED: `NetParams::clear`, `ParamValues::clear`
ADDED: `RelayBandwidth::value`
BREAKING: `parse2::ParseInput::retain_unknown_values` now returns a copy rather than mutating
BREAKING: `vote::NetworkStatusUnverified` now takes an `&mut VoteVerifier`
ADDED: `NetworkStatusSignaturesConstructor`
BREAKING: Removed legacy family support from microdescriptors.
ADDED: `netstatus::SignatureConstructor`
ADDED: `SignatureHashInputs::new_for_signature`
ADDED: `DigestAlgoInSignature::from_algo`, and `From<DirectorySignatureHashAlgo>`
