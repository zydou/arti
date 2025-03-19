# tor-rpc-connect

Functionality related to RPC connect points.

## Overview

A "connect point" is Toml string
that  describes how an RPC client should connect to an RPC server;
and how an RPC server should wait for client connections.

This crate implements parsing for the format,
and facilities to either connect to an RPC server
or listen as an RPC server
given a connect point.

License: MIT OR Apache-2.0
