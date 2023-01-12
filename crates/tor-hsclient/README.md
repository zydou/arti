# tor-hsclient

Core implementation for onion services client.

## EXPERIMENTAL DRAFT

This crate is a work in progress; it is not the least bit complete.

Right now, it does not even work: it's only here so that we can prototype
our APIs.

## ARCHITECTURAL NOTE

This crate creates circuits to onion circuits, but does not remember them: it is
the circmgr's job to remember circuits.  The tor-circmgr crate uses this module
indirectly, via a trait that it defines.

