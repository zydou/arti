BREAKING: Rename `RelayWeight` to `RelayBandwidth`, `RelayBandwidthItem` as `RelayWeightsItem`, etc.
BREAKING: Rename `RouterStatus` field `weight` to `w`
BREAKING: `NetParams<T>` split up into `NetParams` and `ParamValues<T>`
ADDED: `NetParamValues` type alias
ADDED: `RouterStatusMdDigestsVoteConstructor`
ADDED: `RouterStatusMdDigestsVote::iter_cross_product_digests`
ADDED: `ConsensusMethods` convertible to/from, and derefs to, `BTreeSet`; is exhaustive
