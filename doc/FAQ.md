# Arti: Frequently Asked Questions

## What is Arti?

Arti is a project to rewrite the entire codebase of the
[Tor anonymity network](https://torproject.org) in
[Rust](https://rustlang.org/).

Arti is also the name of the software produced by this project.

## What is the status of Arti today?

As of March 2022: Arti is ready for experimental use by developers
interested in embedding Tor support in their projects.  Arti can run as
a simple Tor client and send anonymized traffic over the network, but it
has no support for running as a relay or for using onion services.

Before Arti is ready for production use, we need to make sure that it
has all the important security features from the C Tor implementation; we
need to improve its performance; and we need to improve its APIs based
on user requirements.  We hope to have this done for
[our 1.0.0 milestone](https://gitlab.torproject.org/tpo/core/arti/-/milestones/8#tab-issues) in September 2022.

(After that, our 1.1 milestone will focus on anticensorship work,
and 1.2 will focus on support for onion services.)

## Should I use Arti?

As of March 2022: You should only use Arti as a client if you are
interesting in helping us experiment and find bugs.

If you are interested in shipping Arti as part of your own application,
you should start experimenting with it _now_, so that you can let us
know what features and APIs are missing for you, and we have a chance to
add them.

## Will Arti replace the C Tor implementation?

Eventually, yes.  But it will take a _lot_ of work.

We plan to maintain and support the C Tor implementation until Arti is a
viable replacement for the vast majority of use cases.  We estimate that
this will take us several more years, at the least.  Even then, we plan
to continue supporting the C Tor implementation for some while, to give
people time to switch.

