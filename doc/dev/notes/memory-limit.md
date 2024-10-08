# Memory limiting and reclamation

`tor-memquota` has the implemented facility for tracking memory use
and reclaiming queued data, when under memory pressure.

## Plan for caches

Possible plans for evicrting cached data when under memory pressure.

We may or may not use this "shared quota, delete oldest thing" notion.
We may or may not want caches to share quota with queues, or to be independent.

### If we want to purge oldest cache data, with same age scale as queues

A cache knows its oldest data and will need to know how old each thing it has, is.

On reclaim, it discards the oldest things until it reaches roughly (at least) next_oldest,
or has freed the amount requested.
If that's not enough, tracker will call reclaim again.

### If we want a single quota, but a different reclamation strategy for caches

I.e. we want to balance caches with queues "somehow" (TBD).

We'll introduce a new kind of `Participant`, probably a new trait,
and a `new_cache_participant` enrolment method.
(We may want to rename `Participant`?)

When memory pressure occurs the `MemoryQuotaTracker`
will ask queues about their oldest data.

It will ask caches about whatever it is that is relevant (via
`CacheParticipant`?).

The manager will decide who needs to free memory,
and give instructions via the `Participant`/`CacheParticipant` trait method(s).

Policy and algorithms TBD.

### If we want caches to reclaim oldest data, but with a separate quota

We could make a separate `MemoryQuotaTracker` for each cache.
That cache will then end up using an LRU policy.

### If we want caches to be totally independent with a different policy

We may or may not reuse some of the code here, but the API will be different.
