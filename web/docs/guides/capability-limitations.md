---
title: Capability and Limitations
---

# Arti's current capabilities and limitations

Our eventual goal with Arti is to provide a complete, full-featured implementation of the Tor network in Rust. We have completed some of the necessary features. However, many other important features are pending.

:::warning
This page has not been updated since 2023 and some of the details are out of date.
:::

## Current Capabilities

### Arti as a SOCKS Proxy
Arti can act as a [SOCKS proxy](https://tpo.pages.torproject.net/core/doc/rust/arti/index.html), which allows applications that support SOCKS to route their network traffic through the Tor network. This makes it possible to anonymize the traffic of a wide range of applications, not just web browsing.

### Rust Crate Integration: 
Arti can be integrated directly into other Rust applications. This allows you to build software that uses Tor for network communications, benefiting from Tor's anonymity and privacy features.

You can integrate Arti into your application as a Rust crate. To integrate Arti into your program, you should use the [`arti-client`](https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html) Rust crate. This crate provides the necessary functionalities to interact with the Tor network, such as making anonymized requests or accessing Onion services (turned off by default and currently under development).

Note that some APIs in `arti-client` are explicitly labeled as _experimental_ in the documentation.
These APIs are only available when you explicitly enable their corresponding [feature flags](https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html#feature-flags).
These experimental features are not stable. If you use them in your programs, you should expect that future versions of Arti will break your programs.

## Limitations

### Experimental Use
We encourage users and developers to experiment with Arti and help [report bugs](https://gitlab.torproject.org/tpo/core/arti/-/issues) and [development](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CONTRIBUTING.md). Arti is not currently recommended for production use due to several factors:

#### Under development
Arti hasn't been tested as thoroughly as Tor's more established C implementation, leading to potential unknown issues or bugs.

#### Performance and Stability
Arti may not yet match the performance and stability of the existing C implementation. Performance is crucial for a tool like Tor, where speed and reliability can significantly impact user experience and the practicality of the network.

#### Security Features
Full security features, essential for a tool designed for anonymity and privacy, still need to be fully implemented in Arti. Given Tor's focus on security, this is a significant consideration for production use.
- **Incomplete Security Features**: Full security features are not yet supported. You can find details on these limitations in the Arti issue tracker ([Arti Issues Tracker](https://gitlab.torproject.org/tpo/core/arti/-/issues/?label_name%5B%5D=Onion%20Services%3A%20Improved%20Security)).

#### API Stability
The APIs, especially the internal ones, are currently unstable in Arti and may change. This instability can be challenging for developers who need a stable and consistent API for their production applications.

#### Lack of Full Features
 Arti does not currently support all the functionalities of the C implementation of Tor, such as running as a relay, hosting onion services, anti-censorship features, and certain control-port protocol features.

- **Hosting Onion Services**: The ability to host Onion Services, which ensures privacy for service operators and users, has only been partially implemented. We have turned off this feature by default.
- **Lack of RPC API**: Arti has no Remote Procedure Call (RPC) API.
- **Relay Functionality**: Users cannot operate Arti as a relay, an integral part of the Tor network's traffic routing.
- **Control-Port Protocol Features**: Features dependent on Tor's control-port protocol, which allows applications to control the Tor client, are not supported in Arti.
- **Proxy Limitations**: Currently, Arti is primarily a SOCKS proxy and does not offer other types of proxy functionalities.


## Conclusion
While Arti represents a promising evolution in the Tor ecosystem, it's important to note its current experimental status. Developers and users should be aware of its limitations, particularly the lack of full security features, relay functionality, and the instability of its APIs. As Arti continues to develop, we will address these limitations and pave the way for a more robust and versatile implementation of the Tor network in Rust. To do that, though, [we need your help!](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CONTRIBUTING.md)
