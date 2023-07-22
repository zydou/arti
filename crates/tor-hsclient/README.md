# tor-hsclient

Core implementation for onion services client.

This crate creates circuits to onion circuits,
retains them for reuse,
and hands them out as appropriate.
It is also responsible for maintaining all relevant state
about hidden services, and their descriptors and introduction points.
