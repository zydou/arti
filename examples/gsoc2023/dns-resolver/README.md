# dns-resolver
Use Tor to make a DNS over TCP request for a hostname, and get IP addresses back

### Intro
This is a project intended to illustrate how Arti can be used to tunnel
arbitrary TCP traffic. Here, a DNS client implementation has been hand crafted
to illustrate custom made protocols being able to be used seamlessly over Tor

### Usage
Simply run the program:
`cargo run <hostname-to-look-up>`

The program will then attempt to create a new Tor connection, craft the DNS
query, and send it to a DNS server (right now, Cloudflare's 1.1.1.1)

The response is then decoded into a struct and pretty printed to the user

### Note on DNS
The DNS implementation showcased is not really meant for production. It is just
a quick series of hacks to show you how, if you do have a very custom protocol
that you need tunnelled over Tor, to use that protocol with Arti. For actually
tunneling DNS requests over Tor, it is recommended to use a more tried-and-tested
crate.

For more information on DNS, you can read [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)
or [this educational guide](https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf)
