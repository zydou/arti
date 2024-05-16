BREAKING: Channel is no longer a Sink.  There is now a separate,
internal, ChannelSender type.

BREAKING: You can no longer send cells on a Sender from outside this
crate.

BREAKING: Channel is now explicitly wrapped in Arc<> wherever it
occurs.  Previously, it was an implicitly Arc<> type.
