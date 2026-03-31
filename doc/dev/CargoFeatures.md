
# Policy: Using cargo features in arti

> Also see the comments at the head of fixup-features/src/main.rs

We use cargo features for things that the user or distributor might want to
turn off.

A non-exhaustive list of reasons for turning off a feature are:

    - The feature is unstable, and the code might not work.
      (These are "experimental" features.)
    - The feature involves a substantial amount of code,
      and is something that many users won't want.
    - The feature selects the presence of an optional backend
      for networking, cryptography, etc.
    - The feature flag does not enable functionality,
      but rather switches something about an underlying crate.
      (Static-library flags are like this.)
      These are "non-additive" features.

Every crate has a feature called "full"
that enables all features except experimental and non-additive features.

Every crate has a feature called "experimental" that enables all experimental features.

To mark experimental features,
they should all depend on a feature called `__is_experimental`.

To mark non-additive features,
they should all depend on a feature called `__is_nonadditive`.

Only experimental features should depend on other experimental features.

No experimental or non-additive features should be enabled by default,
and the set of default features should be a subset of "full".

> The fixup-features crate tries to enforce the above properties,
> but apparently there is a bug to track down.
> See arti#2365.

## Experimental features

We make no semver guarantees about experimental features.
We do, however, try to keep `arti` working even if all features are enabled.
If an experimental feature is known or suspected to be broken in a way
that would make `--all-features` builds fail to be usable,
we should ensure that such features
are additionally behind a configuration flag,
a negotiation step, or something similar.

(Rationale: Even though we recommend building with `--features=full`,
some users are used to building with `--all-features` instead,
and some of our CI tests run with --all-features.
If we make --all-features builds break in unexpected ways,
we will encounter hard-to-diagnose bug reports,
and power users will run into surprising errors.

Note that it's okay for the experimental feature itself to be broken:
It just shouldn't break tests, or break user experience in a significant manner.
The "user experience" here refers not just to user-visible functionality,
but also includes any security or privacy effects that the user may rely on.
Whether something breaks the user experience,
and the significance of that breakage, is a judgement call.

[!3759]:  https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3759

## Non-additive features

Non-additive features should be used sparingly
as they can cause build conflicts or unexpected behavior,
especially when exposed to Cargo feature unification.

We should avoid introducing non-additive features
that alter the behavior of any crate.
For example, a "relay" feature in a low-level library
can be used to expose additional relay APIs,
but should not alter the behaviour of that library.

In general, the only times when we should use non-additive
features are when we need to switch out different backends
libraries, **and** it is not practical to compile both
backends/libraries and allow the user to select one at runtime.

## Default vs Full

Generally, we should put a feature in "default" for the `arti` crate
(and in "full" as well)
if we think that users will generally be surprised not to have it,
whereas we should put a feature _only_ in "full"
(and not "default")
if we think that most users will not actually want it.

For features that lie somewhere in the middle, it's a judgment call.
It's preferred to put them in "full" for a while
and see whether to promote them to "default" later on,
since removing default features is typically a breaking change.


## To stabilize a feature:

Move the Cargo feature flag from "experimental" to "full".

Remove the dependency from the Cargo feature on "__is_experimental".

Document the feature as stable in the relevant crates' README.md documentation




