# Security response process

This document is a work-in-progress.

Currently it contains only some notes about particular aspects, not a
whole recipe.

It should be read in conjunction with:

 * [Tor software issue security response policy][Security Policy]
 * [TROVE]

## Handling upstream RUSTSEC issues

This should be read in conjunction with the overall policy.
Notably, when we see a RUSTSEC issue, we need to figure out
what the impact is (if any), just as for any other issue.

In general, we do not need to keep RUSTSEC issues confidential:
any attacker who would spend their time trawling our bugtracker
for cargo-audit failures could just as easily run cargo-audit themselves.

We _should_ use a confidential issue
(or confidential comments on a public issue)
if we need to discuss details of how an exploit would work
that would not be easy for an attacker to figure out on their own.
(It's okay to make things confidential at first if you're not sure.)

Upon finding a RUSTSEC issue in a dependency,
normally it's sufficient to just bump the dependency in Cargo.lock.

> TODO: Add an official means to alert users and distributors
> for issues at trivial/low/medium severity.

If our analysis of the issue suggests it's important
(typically, "high" or worse according to our [Security Policy])
we might update our dependency in Cargo.toml
and put out a new interim Arti release.
In this case, we _may_ yank old versions.
We always announce new Arti releases on the blog.

If the issue affects Arti security at level "medium" or higher,
then we _should_ allocate a [TROVE] ID according to our regular policy.

## Checking whether we are affected by a RUSTSEC

A common reason for a RUSTSEC advisory is that a method is unsound.
That *might* be a practical vulnerability in Arti, but often it isn't.
Vulnerabilities are often in newly-added methods which may not even be used
anywhere in our whole stack.

### Checking whether a method is used in our stack

 * Clone the affected crate (alongside `arti`)
   and check out the tag for the version we're using.
 * Use cargo's `[patch]` mechanism to redirect all uses of that crate,
   to the one you've just checked out.
 * Put `#![cfg(any())]` at the top of the affected crate's `lib.rs`
   and verify that that breaks the build.
   Now you know the `patch` is effective.
 * Somehow sabotage the affected method, eg by deleting or renaming it.
   If the whole stack still builds, the method isn't used.
   Be sure to do your whole arti stack build with `--all-features --workspace`.
   (If the build fails, that doesn't necessarily mean the method is
   actually used and called.  More analysis will be needed.)

[Security Policy]: https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/SecurityPolicy
[TROVE]: https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/TROVE
