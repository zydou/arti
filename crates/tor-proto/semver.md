BREAKING: Remove key-specific accessors.
BREAKING: ChannelsParamsUpdates renamed to ChannelPaddingInstructionsUpdates
ADDED: Channel::engage_padding_activities
ADDED: New methods for updating dormancy, netparams, and config
BREAKING: padding::Parameters fields (builder methods) renamed to remove _ms suffix
ADDED: padding::Parameters constructor disabled, and method padding_negotiate_cell
BREAKING: ChannelsParamsUpdates::total_update changed, is now initial_update
ADDED: ChannelPaddingInstructionsUpdates::combine, and field accessors
