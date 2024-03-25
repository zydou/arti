# Stability and semver, for crates which are part of the Arti Project

This policy applies to all crates which are part of
[the `arti` repository](https://gitlab.torproject.org/tpo/core/arti).
Other crates maintained by the Tor Project may have different policies.

## Rust and cargo semver

We will honour the usual Rust conventions about semver stability:
whenever we make a breaking API change, we'll bump the version appropriately.
(See Rust upstream documentation for the precise details.)

However, many of our crates have optional unstable APIs, 
enabled by cargo features.
Those features are *not* covered by semver.
When you enable those features, `cargo update` might break for you.
This will be mentioned in the documentation for the feature(s),
in each crate's `README`.

## Unstable Tor crates

For all `tor-*` and `arti-*` crates with 0.x version numbers:

We will do a minor version bump (0.x -> 0.y; y > x) for all crates,
on every release (ie, roughly monthly).

So we do not *track* semver API changes.

We will try to retain compatibility APIs (usually for 12 months at least),
and generally try to make it easy for out-of-tree users of these crates
to do a semver upgrade -
ie, to try to make their source code changes reasonably easy.
(This is a woolly goal, not a well-defined hard requirement.)

When we consider that particular crates' APIs have become
sufficiently solid and future-proof,
we may switch those crates to 1.x versions.
But we do not currently intend to put significant effort into making this true.

## Stable crates (1.x, 2.x, ...) and published utility crates (heither `tor-*` nor `arti-*`)

We will do semver analysis:
we track in-tree when we breaking API changes,
and try to bump the version numbers only then.

Crates in this category do not (non-experimentally)
export any types from unstable Tor crates, obviously.

Crates in this category
they may have more cautious MSRV policies than Arti as a whole.

These crates might depend on `tor-*` crates internally,
but this is probably undesirable;
it's only acceptable if the utility crate has a no less firm semver policy than Arti itself.

## User feedback and revising the policy

We encourage downstreams to give us feedback, including
on our approach to compatibility and versioning.

This policy is a living document; if our practices are causing trouble we will change them.
