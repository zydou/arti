# Designing bandwidth rate-limits for Arti

> This is a draft from Feb 2024 to explore the space
> of implementing bandwidth limits in Arti.


We need a feature where some of our connections can be throttled
to use no more than a specified amount of bandwidth,
according to a token-bucket scheme.

We want separate upload and download token buckets,
with the same value for each.

The rate limit will be applied to connections based on address;
by default, we'll apply a rate limit (when configured)
to everything that isn't localhost.

The C tor implementation supports other options here;
I believe that we can do without them.

## Candidate design

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
