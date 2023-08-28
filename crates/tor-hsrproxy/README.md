# tor-hsrproxy

A "reverse proxy" implementation for onion services.

This crate is used in connection with `tor-hsservice` to crate an
onion service that works by opening connections to local services.

It is a separate crate from `tor-hsservice` because it is only one of
the possible ways to handle incoming onion service streams.

## EXPERIMENTAL DRAFT

This crate is a work in progress; it is not the least bit complete.

Right now, it does not even work: it's only here so that we can prototype
our APIs.

