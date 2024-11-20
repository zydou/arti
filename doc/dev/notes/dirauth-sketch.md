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
We'll
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

### Rationale, dirauth upgrade impact

Arti dirauth is not going to be a drop-in replacement
for C Tor dirauth.
While we'll aim to minimise unnecessary changes,
it will interact with the operating system somewhat differently,
be configured somewhat differently,
and there will be possible complications involving key management.

So the upgrade process for each dirauth
will involve human work by the operator,
and carries some risk.
It is likely to involve some downtime.

Attempting to do this near-simultaneously for all dirauths
has a big coordination problem and risks a long outage.

Ideally dirauth upgrades would be staggered,
to maximise availability and minimise risk.

### dirauth operator options

Each dirauth operator can choose
from the following options,
(presented in order from least to most effort):

 1. Do nothing until the network consensus
    is using the Arti consensus method,
    at which point their dirauth ceases to be part of the consensus.
    Then, upgrade straight to Arti dirauth at operator's convenience.

    The transition plan depends on no more than
    1/3 of dirauth operators choosing this option -
    ideally, fewer.

 2. Install the Arti dirauth plugin when it becomes available,
    and tell C Tor to load/use it.
    Eventually, when Arti consensuses are stable, upgrade to Arti dirauth.
    This dirauth will participate in the consensus
    throughout the transition.
    Low-latency communication with and quick response by the operator
    is not required.

 3. Install the Arti dirauth plugin,
    but initially configure it to run only in a testing mode -
    ie, don't advertise the Arti consensus method.
    Engage with the transition scheduling team
    (Arti team, Network Health team, interested dirauths)
    and be part of the coordinated configuration change
    to switch to the Arti consensus method.
    Eventually, when Arti consensuses are stable, upgrade to Arti dirauth.
    We need at least a handful of these,
    depending precisely on what options everyone picks.

 4. Switch over to Arti dirauth as soon as possible.
    These dirauths will not participate in consensuses
    until the consensus switches to the Arti method.

    These operators can provide valuable feedback on Arti dirauth,
    but having many dirauths in this state reduces network resilience,
    so ideally this would be a minority choice.
    Ideally we would have at least one dirauth operator in this category,
    so we can discover issues with Arti dirauth as soon as possible,
    but that's not essential for the transition plan.

dirauth operators may change their mind,
moving from one category to another,
but for simplicity we'll write as if
each dirauth is in a fixed category determined at the start.

### Detailed schedule

 * Phase 1: software development.

   Discussions with dirauth operators, Network Health team,
   about requirements, planning, etc.

   Arti team develops:
     - Arti dirauth
     - Arti consensus method plugin for C Tor
     - C Tor configuration for using Arti consensus method plugin

   dirauth operators provide feedback, additional testing, etc.

   There are likely to be updates to C Tor to tidy up
   some aspects of the Tor protocols which we don't want to reimplement.
   These will be released and deployed according to normal C Tor processes.

 * Milestone 1: Software available.

   The Arti project is shipping both
    1. Arti dirauth
    2. the Arti consensus method plugin and its support in C Tor
   as formal software deliverables,
   in a form suitable for production use by dirauth operators.

   Any necessary updates to C Tor dirauths (and maybe relays)
   for compatibility with Arti votes and consensuses
   have been deployed.

   Schedule determined by: software development timescale.

 * Phase 2: deployment of support for the Arti consensus method.

   dirauths in category 4 switch to Arti dirauth
   (and stop running C Tor entirely).
   Each of these dirauths will be down during its transition.

   dirauths in categories 2 and 3 install the Arti dirauth plugin,
   and configure their C Tor accordingly.
 
 * Milestone 2: Arti consensus method available.

   At least 2/3 of dirauths have the Arti consensus method available
   (ie, are in categories 2-4 and have completed their phase 2 setup).

   Schedule determined by: dirauth operators' deployment decisions.

 * Phase 3: switch to the Arti consensus method.

   dirauths in category 3 coordinate,
   and switch their configuration to advertise the Arti consensus method.

   The Tor network consensus switches over.
   Category 4 dirauths now participate in consensus;
   category 1 dirauths no longer participate in consensus.
   We monitor the network behaviour,
   ready to revert if we see problems.

   Schedule determined by:
   explicit decision by category 3 dirauth operators
   as advised by Arti experts, Network Health team, etc.

 * Milestone 3: we believe the Arti consensus method is stable.

   Schedule determined by:
   explicit decision by category 3 dirauth operators
   as advised by Arti experts, Network Health team, etc.

 * Phase 4: deployment of Arti dirauth

   dirauths (in categories 1-3) install Arti dirauth and deinstall C Tor,
   on their own schedule.
   Each of these dirauths will be down during its transition;
   some coordination is advisable to reduce overall network impact.

 * Milestone 4: C Tor dirauth withdrawn.

   All (or nearly all) dirauths are running Arti dirauth
   (not C Tor with Arti plugin).
   C Tor dirauth can be desupported.
