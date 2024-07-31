# slotmap-careful: Wrapper for slotmap generational arena to prevent key reuse.

The [`slotmap`] generational arena implementation is efficient and easy to use.
Unfortunately, it has a behavior where if a single index slot is reused
about 2^31 times, its version field will wrap around, and the same key will be returned twice.
This can lead to security problems in programs that rely on each for a slotmap
being permanently unique.

This crate implement a wrapper around [`slotmap::SlotMap`] to prevent key reuse.
It works by noticing when any slot with a very high version counter is about to become empty,
and instead marking such slots as permanently unusable.

Note that this new behavior can result in memory usage that grows slowly over time,
even if the actual capacity of the slotmap remains low.

