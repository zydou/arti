---
title: Exposing APIs
---

# Exposing APIs

In Rust, each crate defines a distinct set of APIs accessible to other crates. Notably, certain key crates in Arti, such as `arti` and `arti-client`, purposefully define APIs intended for regular developers seeking stable and straightforward interactions with Arti. 

On the other hand, crates identified by names beginning with `tor-*` are designed for developers requiring the capability to make unconventional and unforeseen adjustments to the Arti framework or the Tor network. 

`arti-client` (as well as `arti-hyper`) is designed for those who simply want to use the Tor network, while the `tor-*` crates are more suitable for tasks such as measuring, interacting with the network in unconventional ways, or developing innovative utilities.

To design new APIs that adhere to Arti's architecture and strike a balance between general use and experimental features:

### 1. Determine the nature of the API

Decide whether the API serves a general-purpose function or if it's more internal to the project. If the functionality is entirely external and doesn't need broader exposure, consider housing it in a lower-level crate. Skip to the implementation part, making it a public API in an existing crate or creating a new crate for it.
    
### 2. Expose the API to a crate

If the API is for general use, expose it as a public member of a higher-level crate. Typically, this involves adding the API to `arti-client`, which serves as the project's general façade over lower-level code.
    
If you’re considering creating a new crate, evaluate if the new functionality is distinct enough to warrant a new higher-level crate. For significant features like relay support, it might be more appropriate to create a separate crate as this allows for better code organization and structure.
    
Although the API is exposed from a higher-level crate, the implementation might reside in a lower-level crate. This separation maintains a clean and modular structure, with the higher-level crate serving as an interface to the lower-level functionality
    
### 3. Specify its experimental status
    
Specify if the API should be labeled as "experimental" or not. We mark an API as `experimental` if there's a good possibility we'll want to provide it differently, or if there's a good chance we are unlikely to provide it at all. An API does not need to be experimental if it is simple enough that we can be certain it is correct in the first version.
    
If the API is experimental, use `#[cfg(feature="experimental-api")]` (or some similar feature instead of `experimental-api`) to indicate that it isn't stable, and to turn it off by default.
