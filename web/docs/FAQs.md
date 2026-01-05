---
title: Frequently Asked Questions
---

## What is Arti?

Arti is a project to rewrite the entire codebase of the [Tor anonymity network](https://torproject.org/) in [Rust](https://rustlang.org/).
Arti is also the name of the software produced by this project.

See ["About Arti"](/about) for details.

## What is the status of Arti today?

As of January 2026: Arti is ready for use as a proxy or by developers interested in embedding Tor support in their Rust projects. Arti can run as a Tor client and send anonymized traffic over the network. It supports Tor's client-side anticensorship features, and it supports accessing and hosting onion services. However, it currently does not support acting as a relay.

You can track our progress in the [project's CHANGELOG](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CHANGELOG.md) for our monthly releases.

## Should I use Arti?

Yes you can use Arti as a client. But note that Arti does not have all of the functionality of C tor. Please [let us know](https://gitlab.torproject.org/tpo/core/arti/-/issues) if Arti is missing features that you need.

If you are interested in shipping Arti as part of your own application, you should start experimenting with it *now*, so that you can let us know what features and APIs are missing for you, and we have a chance to add them.

## Will Arti replace the C Tor implementation?

Eventually, yes. But it will take a *lot* of work.

We plan to maintain and support the C Tor implementation until Arti is a viable replacement for the vast majority of use cases. We estimate that this will take us several more years, at the least.  Even then, we plan to continue supporting the C Tor implementation for some while, to give people time to switch.

