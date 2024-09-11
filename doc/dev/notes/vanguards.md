# Building vanguards in Arti

Here's a summary of the vanguards design.
For canonical information, see the
[specification](https://spec.torproject.org/vanguards-spec/index.html)


## Summary of what we're building.

The Vanguards design is a change to circuit path construction rules.

This change applies to HS circuits only.
(That is, circuits that are built for hsservice or hsclient.
This includes circuits to connect to introduction points,
rendezvous points, and hsdirs.)

We call "circuit stem" the portion of a hidden service circuit
that is built differently when vanguards are in use.

The vanguard design will apply to the "stem" circuits
that we build in HsCircPool.  These circuits correspond to
everything in an HS circuit _before_ we add an introduction point,
rendezvous point, or hsdir.  For client rendezvous connections,
we use the circuits stems unmodified, and use the
final hop as our rendezvous point.

Here's our schema:
```
     Client hsdir:  GUARDED -> HsDir
     Client intro:  GUARDED -> Ipt
     Client rend:   GUARDED
     Service hsdir: NAIVE   -> HsDir      (*)
     Service intro: NAIVE   -> Ipt
     Service rend:  GUARDED -> Rpt
```

Note that in some of these cases (marked above with `GUARDED`),
we are building a circuit to a final hop
that an adversary can easily control.
Right now, we don't distinguish these cases,
but with vanguards we will.

> Note: the client rendezvous case is an exception to this rule:
> the rendezvous point is selected by the client, so it cannot easily be
> controlled by an attacker.
>
> This type of circuit would more accurately be described as a NAIVE circuit
> that gets extended by an extra hop if Full-Vanguards are in use
> (this is necessary to avoid using the L3 guard as a rendezvous point).
> However, for the sake of simplicity, we define these circuits in terms of
> GUARDED.
>
> Note: in the client rendezvous case, the last node from the GUARDED
> circuit stem is the rendezvous point.

> (I've marked "service hsdir" with a *,
> since maybe we want to call that one "guarded" as well.)

Currently, circuit stems are built by taking a guard node,
then two arbitrarily chosen middle nodes:
```
   NAIVE   = G -> M -> M
   GUARDED = G -> M -> M
```

There two variants of vanguards: "lite" and "full".
Both of then introduce pools of additional guards,
called "vanguards".
The "lite" variant adds a single "L2" pool.
The "full" variant adds an "L2" pool and an "L3" pool.

With "lite", we build circuit stems by taking a guard node,
then a vanguard from the "L2" pool, then an arbitrary middle node:
```
   NAIVE   = G -> L2 -> M
   GUARDED = G -> L2 -> M
```

With "full", we build circuit stems by taking a guard node,
a vanguard from the L2 pool,
and a vanguard from the L3 pool.
For "guarded" circuits, we also add a middle node:
```
   NAIVE   = G -> L2 -> L3
   GUARDED = G -> L2 -> L3 -> M
```

### Pool management

Here's how we maintain L2 and L3 guards.

In both cases, vanguards are added to each pool
up to a target `NUM_GUARDS` number taken from a consensus parameter.
This number depends on the variant and the pool in question.

To be added as a vanguard, a relay must be flagged Stable and Fast.

The vanguards in single a pool must be distinct from one another.
There is no inter-pool restriction.

Every vanguard gets an "expiration time" when it's added to the pool;
when this time expires, we remove the vanguard.
We additionally remove a vanguard if it is every unlisted,
or if it ever loses the Stable or Fast flag.

To pick the expiration time when adding a vanguard,
we choose from a random distribution.
This distribution depends on the variant and the pool in question.

In vanguards-full, these pools are persistent,
and must be stored to disk.

In vanguards-lite, these pools are not persistent.

### Loosened path restirctions

When building a circuit stem,
we no longer apply certain restrictions to the circuits we build.
In particular:

 - We no longer apply family or same-subnet restrictions at all.
 - We do not exclude the guard from appearing as
   either of the last two hops of the circuit.

### Which variant to apply

By default, "vanguards-lite" applies to every circuit stem.

We will implement a global option that applies "vanguards-full"
to every circuit stem.

For now, we will share a single L2 pool,
no matter which variant is in use:
vanguards will not be discarded on a switch
from one variant to another.

> In the future, we might want to apply "full" or "lite"
> to specific services,
> either when providing those services or connecting to them.
>
> To do so, our main open design question to answer
> would be whether they share an L2 pool.


-----


## Implementing vanguards in arti

Pool maintenance might belong logically in tor-guardmgr,
or might belong in a new tor-vanguardmgr crate.
It shouldn't share an implementation with the main guard pool though,
since the criteria for keeping and using
guards and vanguards are completely different.

New vanguard code will be:
 * pool maintenance
 * pool persistence

We can have a single VanguardPool implementation
shared by both variants, and both pools.

Code to modify will be concentrated in `tor_circmgr`:
 * `HsCircPool::take_or_launch_stub_circuit`.
 * `HsCircPool::get_or_launch_client_rend`.
 * `HsCircPool::get_or_launch_specific`.
 * `hspool::circuit_compatible_with_target`
 * `CircMgr::launch_hs_unmanaged`

 * `TargetCircUsage::build_path`.
 * Anything that touches `SupportedCircUsage::HsOnly`.

We will also need a new path-selection implementation.
This will either be a new implementation
similar to `ExitPathBuilder`,
or an additional set of options to a possibly renamed
`ExitPathBuilder`.
It will probably share some code with `ExitPathBuilder`.

We'll need `CircMgr` to have access to the vanguard pools,
either by owning a `VanguardMgr` directly,
or by owning it through `GuardMgr`.

The `VanguardMgr` will need to know which pools
will be required.
This will depend on whether "full" might be wanted.

So that we can later support fine-grained decisions
about whether to use "lite" or "full",
we should have it be a parameter passed to HsCircPool,
telling it whether a "lite" or "full" circuit is needed.

## Estimated steps:

 * [ ] Implement vanguard pools and a vanguard manager to maintain them.
 * [ ] Give CircMgr an Arc<VanguardMgr> whenever `onion-service-client`
       or `onion-service-service` is enabled.
 * [ ] Implement a global "full-vanguards" configuration option;
       have it get fed to the vanguardmgr, to tor-hsclient, and to tor-hsservice.
 * [ ] Give HsCircPool additional arguments to declare whether its
       circuits are Naive or Guarded
       (probably not so named in the code!)
       and whether they are "lite" or "full".
 * [ ] Implement path selection for (Naive, Guarded) x (lite, full)
       circuits in CircMgr::launch_hs_unmanaged.

