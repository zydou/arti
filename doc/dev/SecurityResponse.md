# Security response process

This document is a work-in-progress.

Currently it contains only some notes about particular aspects, not a
whole recipe.

It should be read in conjunction with:

 * [Tor software issue security response policy](https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/SecurityPolicy)
 * [TROVE](https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/TROVE)

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
