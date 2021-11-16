# tor-events

`tor-events`: a typed event broadcasting framework for Arti

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

This crate implements functionality to allow other Arti crates to emit
typed events when certain things happen (for example, bootstrap progress,
or a guard becoming disabled), and for library consumers to selectively
consume the subset of said events they deem important to them.

License: MIT OR Apache-2.0
