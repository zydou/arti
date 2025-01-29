---
title: Protocol support & Compatibility
---

# Protocol support and compatibility in Arti

As of late 2023, there is no support in Arti yet for running as a relay or running as a directory authority.
Support for providing onion services is almost (but not quite) done. However, we hope to build these in the future.

Arti aims for compatibility with all _currently recommended_ Tor protocols. We have not implemented, and do not plan to implement, obsolete versions of anything.

## Protocol support

Here's a checklist of Tor sub-protocol versions that we currently have client-side support for:

  * [x] `Cons=2` [^1]
  * [x] `Desc=2`
  * [x] `DirCache=2`
  * [x] `FlowCtrl=0`
  * [x] `FlowCtrl=1`
  * [ ] `HSDir=2`
  * [ ] `HSIntro=4` (maybe?)
  * [ ] `HSIntro=5`
  * [ ] `HSRend=2`
  * [x] `Link=4`
  * [x] `Link=5`
  * [x] `Microdesc=2` [^1]
  * [ ] `Padding=2`
  * [x] `Relay=2`
  * [ ] `Relay=3` (not sure whether we're compliant with this client-side)

[^1]: If a consensus method before 28 is used, we won't find IPv6 addresses correctly. All such consensus methods are currently obsolete, though, and authorities won't negotiate them any more.

There is no relay-side support for anything right now. If there were, we'd want to support:

  * [ ] `Cons=2`
  * [ ] `Desc=2`
  * [ ] `DirCache=2`
  * [ ] `FlowCtrl=0`
  * [ ] `FlowCtrl=1`
  * [ ] `HSDir=2`
  * [ ] `HSIntro=4` (maybe)
  * [ ] `HSIntro=5`
  * [ ] `HSRend=2`
  * [ ] `Link=4`
  * [ ] `Link=5`
  * [ ] `LinkAuth=3`
  * [ ] `Microdesc=2`
  * [ ] `Padding=2`
  * [ ] `Relay=2`
  * [ ] `Relay=3`

We do not ever plan to support these:

  * `Cons=1` (obsolete format)
  * `Desc=1` (obsolete format)
  * `DirCache=1` (no relays still support this)
  * `HSDir=2`
  * `HSIntro=3` (will be obsolete in 2021)
  * `HSRend=1` (will be obsolete in 2021)
  * `LinkAuth=1` (only used by RSA-only relays)
  * `Microdesc=1` (obsolete format)
  * `Padding=1` (deprecated)

We presume that these proposals will be accepted and merged into Tor:
  * [ ] 285 (Directory documents should be standardized as utf-8, tor#40131)
  * [ ] 315 (Make some directory fields "required", tor#40132)

