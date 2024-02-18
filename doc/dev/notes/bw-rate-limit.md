# Designing bandwidth rate-limits for Arti

> This is a draft from Feb 2024 to explore the space
> of implementing bandwidth limits in Arti.


We need a feature where some of our connections can be throttled
to use no more than a specified amount of bandwidth,
according to a token-bucket scheme.

We want separate upload and download token buckets,
with the same value for each.

The rate limit will be applied to channels,
since these are the only recommended
non-localhost connections we support.
Later, we may support limiting other things,
such as individual circuits, or other TCP streams.

The C tor implementation supports other options here;
I believe that we can do without them.

## Candidate design (rejected)

Our tor-rtcompat design lets us define a Runtime
that wraps another Runtime;
we can use this to define a runtime that wraps
the TcpProvider of an underlying runtime
so as to apply a rate limiter wrapper
to each TcpStream we make.

Ideally, we would not write or maintain our own rate-limiting tool.
Instead, we should use an off-the-shelf crate
and submit patches as needed in order to make it more suitable.

If it does turn out that we need to maintain a rate-limiting crate
we should learn from our experience and from other implementations.

I've looked over a few possibilities,
and it looks like the `async_speed_limit` crate
is the only viable option for now.
There is also an `aio_limited` crate, but it isn't maintained,
and a `stream-limiter` crate, but it isn't async.

I don't especially love `async_speed_limit`:
it does some things well,
but there are areas where I expect it to underperform,
and other areas where I think it's not strictly correct.
Nonetheless, it might be our fastest route to an MVP.

## Candidate design (improved)


We've decided that there's a decent chance
we'll want to apply rate limiting
in other places in our system, later on.
For example, we might want
to limit different outbound users of a channel differently.

Because of that, we should make our rate-limiting logic first-class.

We should implement this logic in a way
that hides our choice of implementation strategy.

Here is a sketch of a possible _minimal_ API.

```
// Here and below, please assume Send, Sync, and Pin have been added
// as appropriate.
//
// (We should not consider these APIs remotely stable until we've
// got tests that compile, since we may need to add these additional
// constraints.)

pub struct Limiter { ... }
pub struct LimitedIo<T> { ... }

// We don't have separate LimitedIoRead and LimitedIoWrite types;
// instead, the one thing does both (subject to trait bounds).
// If the caller has separate read and write objects, it needs two LimitedIo
// objects to wrap them.  But there's still only one copy of the config,
// token buckets, etc.
impl<T: AsyncRead> AsyncRead for LimitedAsycnIo<T> {...}
impl<T: AsyncWrite> AsyncWrite for LimitedAsyncIo<T> {...}


impl<T> LimitedAsyncIo<T> {
   pub fn inner(Pin<&mut self>) -> Pin<&mut T>
   // like Box<TcpThingy> and at least some unboxed !Unpin types
   pub fn inner(&self) -> &T {...}
   pub fn into_inner(self) -> T where T: Unpin, presumably? {...}

   // (maybe, a function to inspect the current limit status?)
   // (maybe, a function to get the Limit? I hope we don't need that.)
}


pub struct BucketConfig {
    max_bytes_per_sec: u64, // or usize?
    max_bucket_size: u64
}

pub struct LimitConfig {
    upload_limit: BucketConfig,
    download_limit: BucketConfig,
}

impl Limiter {
    /// This might need to take a Runtime, a clock type, or who
    /// knows what else. Maybe we need a generalization of SleepProvider
    /// that provides its own Instant and Duration types.
    ///
    /// Ack; I think what we need is a generalization of a SleepProvider that defines its own Instant and Duration types.
    pub fn new(cfg: &LimitConfig) -> Result<Arc<Self>> { ... }

    pub fn reconfigure(&self, cfg: &LimitConfig) -> Result<(), ReconfigError> { ... }

    /// All `LimitIo` from the same `Limiter` interact,
    /// sharing the limit and using from kthe same quota.
    pub fn limit_async_io<T>(self: &Arc<Self>, io: T) -> LimitedAsyncIo<T> { ... }
}
```


In the future, we might want to have a more complex set of
interrelated limits.  If we do, we can either add a "group" or "key"
or "category" field.  We might need to define a Limiter and a
SubLimiter or something too.  I think it's okay to expect some churn
here if the functionality grows in this way.


### Stream/Sink APIs

We may somday want to add the ability to limit Stream/Sink objects
other than AsyncRead and AsyncWrite.  To do so, we define a cost
function on the members of the Stream/Sinks, to make them
comparable with our other read/writes.

(This is not something we should build
until we have an application for it.)

```
pub trait LimitedObject {
    /// Return the "cost" in bytes to send or receive this object.
    fn cost(&self) -> u64;
}

#[derive(From,Into)]
pub struct FixedCost<T,COST:u64>(T);
impl<T,COST:u64> LimitedObject for FixedCost<T,COST> {
    fn cost(&self) -> u64 { COST }
}

/// Does this count against the upload limit or the download limit?
pub enum Direction {
    Upload, Download
}

pub struct LimitedStream<T> {...}
impl<T> Stream for LimitedStream<T>
  where T: Stream, T::Item: LimitedObject {...}

pub struct LimitedSink<T> {...}
impl<T,Item> Sink<Item> for LimitedSink<T>
  where T: Sink<Item> {...}

impl Limiter {
   pub fn limit_stream<T>(self: &Arc<Self>, stream: T, d: Direction) -> LimitedStream<T> {...}
   pub fn limit_sink<T>(self: &Arc<Self>, sink: T, d: Direction) -> LimitedSink<T> {...}
```


### Lower-level APIs


Conceivably we might want even lower-level APIs
to do things like:
 - checking the current token bucket levels (or equivalent)
 - draining the buckets directly
 - determining how long to pause before a given operation can be attempted

We should implement these carefully, if at all:
they are likely to depend a lot on our backend,
and possibly tie us into a particular backend.

We should not build any more here than we need
to implement our LimitedIo types.
If we expose them,
they should be behind an `experimental` feature
until we actually need them for something.

One proposed possiblity (from diziet):

```

impl RawLimiter {
    // questions of details:
    //    Q. does it need to take Pin<&mut self> ?
    //    Q. is this a method on LimitedIo ?
    //       (You could have "just raw" with LimitedIo<()>)
    //       seems like it might be possible, but maybe a LimitedIo has a buffer?
    //    Q. separate read and write types?
    //       Probably not
    //    Q. should qty be a Range or something
    //          which causes this to return only when min is fulfulled?
    //          probably not.
    // As I propose here this API is equivalent to AsyncWrite except
    // that it doesn't get involved with `&[u8]` etc.  so it hopefully doesn't impose
    // any different requirements on the innards/algorithms/whatever.
    async fn await_and_consume_quota_for_write(&mut self, qty: usize) -> usize;

```


## An alternative: Ask the OS!

When it's viable, an OS-based traffic-shaping approach
will always outperform what we can do in userspace.
At minimum, we should mention this in our documentation,
and link to resources for how to set it up.

Perhaps in the long term it would be neat
to ask the operating system to limit our traffic.
Unfortunately, I can't find any plausible user-space API
for this.
(For example, there isn't an RLIMIT_NETWORK_BW.)

We should probably discuss this in general terms
as a possibility,
once we build relays,
and maybe link to relevant resources.

