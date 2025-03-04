# BREAKING: `BlockOn` trait split into `ToplevelBlockOn` and `Blocking`.

New rules for `BlockOn::block_on`; when `ToplevelBlockOn` not
available, use methods from `Blocking` instead.  Documentation explains.
