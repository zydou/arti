# arti dirauth design sketch

## dirauth functions

 * receive relays' server descriptor submissions
 * exchange server submissions with other dirauths
 * perform basic reachability tests for candidate relays
 * generate a vote from
   - available descriptors
   - configuration (including relay-specific configuration provided
     by network health team, mediated by dirauth local policy
   - bandwidth measurements
 * exchange votes with other dirauths (make them publicly available)
 * given votes, generate and sign consensus

## principal components

 * dircache

 * reachability tester

 * ingester for relay-specific configuration from Network Health

 * consensus algorithm implementation
   - We will not attempt to 100% match the behaviour of C Tor.
     Instead, we provide this as `.so` (or a maybe an executable)
     and will arrange for C Tor diaruth to  be able to use it
     (see transition plan).

 * vote calculator

The latter two don't need to be always-online.
We'll to separate them out so that they can (likely in the future)
use a static data dump, or a restricted protocol,
so that they don't need full internet access.

## deployment transition plan

Directory consensus protocol means that
if we change the consensus algorithm
at least 1/3 of functioning dirauths, and probably more,
must change simultaneously.
(We go from \<1/3 new to \>2/3 new in one go.)

We think it is probably not going to be feasible to precisely reproduce
the consensus calculations from C Tor in Arti.

This is practical only if the simultaneously-switching dirauths
all implement both the old and new consensus algorithm.
(This is what the consensus methods are for.)
We can't switch all dirauths from C Tor to Arti on the same day.

Instead, we will
make the Arti implementation of the consensus protocol
available in a form that can be used by C Tor.
We'l
adapt C Tor to be able to call that implementation,
making the choice based on the consensus method.

When enough (C Tor) dirauths have the Arti consensus algorithm available,
the consensus method protocol will automatically switch
to using the Arti consensus.

After that, C Tor dirauths without the Arti consensus algorithm
will effectively not participate, until they are upgraded.
But pure-Arti dirauths (which can only perform the Arti consensus algorithm)
can be deployed.

(In practice there may be, during the transition,
more than one relevant Arti consensus method
and possibly more than one relevant C Tor consensus method.)
