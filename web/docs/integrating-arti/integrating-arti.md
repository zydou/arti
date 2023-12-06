---
title: Overview
---

# Integrating Arti in three ways

To accommodate multiple programming languages and architectural requirements, there are 3 methods to easily integrate Arti into a varied range of applications.

### In-Rust API integration:

The use of Rust APIs is the primary method for integrating Arti into Rust-based applications. By leveraging Arti's Rust APIs, developers can seamlessly connect their Rust programs to the Tor Network, taking advantage of the features and functionalities provided by Arti within the Rust environment.

### Custom FFI wrappers:

This approach is especially helpful for bridging the gap between Arti and non-Rust programs. Developers can simplify the integration process by encapsulating Arti's functionality and providing a more user-friendly interface for applications created in other programming languages by using custom FFI wrappers.

### Remote Procedure Calls (RPC) integration:

Although this isn't a feature at the moment, integrating Arti via RPC is another option. The idea is that external programs will be able to communicate with Arti remotely, via its RPC interface.
