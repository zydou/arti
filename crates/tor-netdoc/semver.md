BREAKING: Significant API changes for accessing and building consensus and parts thereof
BREAKING: It is no longer possible to write code which is generic over md and full consensuses.
BREAKING: `Consensus`, `RouterStatu` etc. are no longer generic.  Use `MdConsensus` etc.
DEPRECATED: cargo feature name "ns_consensus" replaced with `plain-consensus`
DEPRECATED: `*Ns*Consensus` types (part of `ns_consensus`), now called `*Plain*`
BREAKING: `ConsensusFlavor::Ns` renamed to `ConsensusFlavor::Plain`; no compat alias
