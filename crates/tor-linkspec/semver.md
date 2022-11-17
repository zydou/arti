MODIFIED: New ByRelayIds type.
BREAKING: Changed the semantics of HasAddrs
BREAKING: ChanTarget now requires HasChanMethod
MODIFIED: RelayIdRef now implements Hash.
MODIFIED: RelayId and RelayIdRef now implement Ord.
MODIFIED: Added cmp_by_relay_ids() to HasRelayIds.
BREAKING: Replaced functions to access addresses from ChanMethod.
BREAKING: Replaced functions to strip addresses from ChanMethod.
BREAKING: Remove impl Display for OwnedCircTarget.
ADDED: Provide deconstructors for PtTargetSettings and PtTarget
