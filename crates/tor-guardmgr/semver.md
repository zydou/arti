BREAKING: Exposed objects implement the new versions of the linkspec traits
BREAKING: note_external_{success,failure} functions now take HasRelayIds
BREAKING: GuardRestriction now takes a RelayId or RelayIdSet.  This doesn't
          affect serde users, but anybody calling it directly will need to
          change.

