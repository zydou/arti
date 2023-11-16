---
title: About Arti
---

# About Arti

Arti is a project committed to delivering an embeddable, production-quality implementation of the [Tor](https://www.torproject.org/) anonymity protocols, crafted in the [Rust](https://www.rust-lang.org/) programming language.

## Why rewrite Tor in Rust?

- Rust serves as the foundation of our development philosophy since ***it is naturally more secure than C***.
    
    The surface area for potential vulnerabilities has been greatly diminished because to Rust's focus on memory safety. According to our estimations, Rust would have made it impossible for at least half of the security flaws we've identified, and many more would have been extremely unlikely.

- Security is only one piece of the puzzle. ***It enables faster development than C.***

    The expressiveness of Rust also contribute to its rapid development. We can attest to the fact that Rust's efficiency and our trust in it enable us to write code more quickly. In the long run, we believe that this will not only speed up the development of our software but also set higher standards for the entire sector.
    
- Arti represents a paradigm shift from our previous C tor implementation; ***it is more flexible than C tor.***
    
    While the C `tor` was initially designed as a SOCKS proxy, Arti is conceived from the ground up to function as a modular, embeddable library. This architectural difference opens up new realms of flexibility, allowing Arti to seamlessly integrate into various applications.
    
- Beyond flexibility, ***Arti is a testament to cleaner design principles.***
    
    Building upon the lessons learned since the inception of C tor in 2002, Arti sidesteps the pitfalls of complicated "spaghetti" relationships in the codebase. Our commitment to clarity and simplicity ensures that Arti is not just a technological marvel but also a joy for developers to understand and improve.

