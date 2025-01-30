---
title: About Arti
---

# About Arti

Arti is a project committed to delivering an embeddable, production-quality [Rust](https://www.rust-lang.org/) implementation of the [Tor](https://www.torproject.org/) anonymity protocols. It is a complete rewrite of the [C tor](https://gitweb.torproject.org/tor.git/) codebase, and it is currently under active development.

## Why rewrite Tor in Rust?

- Rust serves as the foundation of our development philosophy since ***it is naturally more secure than C***.
    
    The surface area for potential vulnerabilities has been greatly diminished thanks to Rust's focus on memory safety. According to our estimations, Rust would make at least half of the security flaws we've identified impossible, and many more would have been extremely unlikely.

- Security is only one piece of the puzzle. ***It enables faster development than C.***

    The expressiveness and safety guarantees of Rust have also been contributing factors to Arti's rapid development. We can attest to the fact that Rust's efficiency and our trust in it enable us to write code more quickly. In the long run, we believe that this will not only speed up the development of our software but also set higher standards for the entire sector.
    
- Arti represents a paradigm shift from our previous C tor implementation; ***it is more flexible than C tor.***
    
    While the C `tor` implementation was initially designed as a SOCKS proxy, Arti was conceived from the ground up to function as a modular, embeddable library. This architectural difference opens up new realms of flexibility, allowing Arti to seamlessly integrate into various applications.
    
- Beyond flexibility, ***Arti is a testament to cleaner design principles.***
    
    Arti avoids potential hazards of complex "spaghetti" relationships in the codebase by building on the lessons learned since the birth of C tor in 2002. Because of our dedication to clarity and simplicity, Arti is not only a technical masterpiece, but also a joy for developers to understand and improve.

