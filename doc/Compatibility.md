
# Protocol support and compatibility in Arti

**Up to date as of Feb 2026**

Summary:

Arti runs as a client, and supports running onion services and connecting to
them.  It supports using bridges and pluggable transports.

There is no support in Arti yet for running as a relay, a bridge, or a
directory authority.  We are currently building those.

Arti aims for compatibility with all _currently recommended_ Tor protocols.
We have not implemented, and do not plan to implement, obsolete versions of
anything.

## Protocol support

### Client-side support

Here's a checklist of Tor [sub-protocol capabilities][subproto]
versions that we currently have
client-side support for:

  * [ ] `Conflux=1` (`CONFLUX_BASE`) [^conflux]
  * [x] `Cons=2` (`CONS_ED25519_MDS`) [^cons28]
  * [x] `Desc=2` (`DESC_CROSSSIGN`)
  * [x] `Desc=3` (`DESC_NO_TAP`)
  * [x] `Desc=4` (`DESC_FAMILY_IDS`)
  * [x] `DirCache=2` (`DIRCACHE_CONSDIFF`)
  * [x] `FlowCtrl=0` (`FLOWCTRL_AUTH_SENDME`)
  * [x] `FlowCtrl=1` (`FLOWCTRL_CC`)
  * [x] `HSDir=2` (`HSDIR_V3`)
  * [x] `HSIntro=4` (`HSINTRO_V3`)
  * [x] `HSIntro=5` (`HSINTRO_RATELIM`)
  * [x] `HSRend=2` (`HSREND_V3`)
  * [x] `Link=4` (`LINK_V4`)
  * [x] `Link=5` (`LINK_V5`)
  * [x] `Microdesc=2` (`MICRODESC_ED25519_KEY`) [^cons28]
  * [x] `Microdesc=3` (`MICRODESC_NO_TAP`)
  * [ ] `Padding=2` (`PADDING_MACHINE_CIRC_SETUP`) [^padding]
  * [x] `Relay=2` (`RELAY_NTOR`)
  * [x] `Relay=3` (`RELAY_EXTEND_IPV6`)
  * [x] `Relay=4` (`RELAY_NTORV3`)
  * [x] `Relay=5` (`RELAY_NEGOTIATE_SUBPROTO`)
  * [x] `Relay=6` (`RELAY_CRYPT_CGO`)

Going forward, Arti is the preferred Tor client for new feature development.
All new client features will have implementations in Arti.

[^cons28]: If a consensus method before 28 is used, we won't find IPv6
    addresses correctly. All such consensus methods are currently obsolete,
    though, and authorities won't negotiate them any more.

[^conflux]: The `tor-proto` crate supports conflux tunnels,
    but Arti does not currently build or use them.

[^padding]: The `tor-proto` crate supports padding machines based on
    [`maybenot`], but they are not currently implemented.

### Relay-side support

Relay-side support is a work in progress.
We want to support all of these [sub-protocol capabilities][subproto].
Many of them are partly implemented;
we'll check them off as they become accessible on a running relay.

  * [ ] `Conflux=1` (`CONFLUX_BASE`)
  * [ ] `Cons=2` (`CONS_ED25519_MDS`)
  * [ ] `Desc=2` (`DESC_CROSSSIGN`)
  * [ ] `Desc=3` (`DESC_NO_TAP`)
  * [ ] `Desc=4` (`DESC_FAMILY_IDS`)
  * [ ] `DirCache=2` (`DIRCACHE_CONSDIFF`)
  * [ ] `FlowCtrl=0` (`FLOWCTRL_AUTH_SENDME`)
  * [ ] `FlowCtrl=1` (`FLOWCTRL_CC`)
  * [ ] `HSDir=2` (`HSDIR_V3`)
  * [ ] `HSIntro=4` (`HSINTRO_V3`)
  * [ ] `HSIntro=5` (`HSINTRO_RATELIM`)
  * [ ] `HSRend=2` (`HSREND_V3`)
  * [ ] `Link=4` (`LINK_V4`)
  * [ ] `Link=5` (`LINK_V5`)
  * [ ] `LinkAuth=3` (`LINKAUTH_ED25519_SHA256_EXPORTER`)
  * [ ] `Microdesc=2` (`MICRODESC_ED25519_KEY`)
  * [ ] `Microdesc=3` (`MICRODESC_NO_TAP`)
  * [ ] `Padding=2` (`PADDING_MACHINE_CIRC_SETUP`)
  * [ ] `Relay=2` (`RELAY_NTOR`)
  * [ ] `Relay=3` (`RELAY_EXTEND_IPV6`)
  * [ ] `Relay=4` (`RELAY_NTORV3`)
  * [ ] `Relay=5` (`RELAY_NEGOTIATE_SUBPROTO`)
  * [ ] `Relay=6` (`RELAY_CRYPT_CGO`)

We do not ever plan to support these:

  * `Cons=1` (obsolete format)
  * `Desc=1` (obsolete format)
  * `DirCache=1` (no relays still support this)
  * `HSDir=2`(obsolete since 2021)
  * `HSIntro=3` (obsolete since 2021)
  * `HSRend=1` (obsolete since 2021)
  * `LinkAuth=1` (only used by RSA-only relays)
  * `Microdesc=1` (obsolete format)
  * `Padding=1` (deprecated)

[subproto]: https://spec.torproject.org/tor-spec/subprotocol-versioning.html
[`maybenot`]: https://docs.rs/crate/maybenot/latest
