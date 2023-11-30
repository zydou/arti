---
title: Frequently Asked Questions
---

## What is Arti?

Arti is a project to rewrite the entire codebase of the [Tor anonymity network](https://torproject.org/) in [Rust](https://rustlang.org/).
Arti is also the name of the software produced by this project.

## What is the status of Arti today?

As of November 2023: Arti is ready for experimental use by developers interested in embedding Tor support in their projects. Arti can run as a simple Tor client and send anonymized traffic over the network. It supports Tor's client-side anticensorship features, and it supports using onion services as a client. However, it currently does not completely support running onion services or acting as a relay.

Before Arti is ready for production use, there are a few more security features that we need to implement, especially in relation to onion services. We also need to complete our integration with other applications, and stabilize our interfaces.
You can track our progress in the [project's CHANGELOG](/changelog.md) for our monthly releases.

## Should I use Arti?

As of November 2023: You should only use Arti as a client if you are interesting in helping us experiment and find bugs.

If you are interested in shipping Arti as part of your own application, you should start experimenting with it *now*, so that you can let us know what features and APIs are missing for you, and we have a chance to add them.

## Will Arti replace the C Tor implementation?

Eventually, yes. But it will take a *lot* of work.

We plan to maintain and support the C Tor implementation until Arti is a viable replacement for the vast majority of use cases. We estimate that this will take us several more years, at the least.  Even then, we plan to continue supporting the C Tor implementation for some while, to give people time to switch.

