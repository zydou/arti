---
title: oniux
---

# oniux

> Security isn't just about the tools you use or the software you download.
> It begins with understanding the unique threats you face and how you can
> counter those threats.

*oniux* is a tool that utilizes various Linux `namespaces(7)` features in order
to isolate an arbitrary application over the Tor network.  To achieve this, it
makes heavy use of *arti* and
[*onionmasq*](https://gitlab.torproject.org/tpo/core/onionmasq), the
latter offering a TUN device to tunnel Tor traffic through.

The *oniux* repository is available on
[GitLab](https://gitlab.torproject.org/tpo/core/oniux).

## Usage

```sh
oniux <CMD>
```

## Installation

1. Check whether your distribution packages *oniux*.
    * Alpine Linux, Nix, and Void Linux and do!
    * See [Repology](https://repology.org/project/oniux/versions).
2. If your distribution **DOES NOT** offer oniux, do the following
    1. Setup a recent Rust toolchain on your system, by installing
       `rustup` from your distribution or from rust-lang.org.
        * You probably want to do `rustup default stable`.
    2.
        ```
        cargo install --locked --git https://gitlab.torproject.org/tpo/core/oniux --tag v0.8.0 oniux
        ```

## Internals

### What are Linux namespaces? 🐧

Namespaces are an isolation feature found in the Linux kernel that were
introduced around the year 2000.  They provide a secure way of isolating a
certain part of an application from the rest of the system.  Namespaces come in
various forms and shapes.  Some examples include network namespaces, mount
namespaces, process namespaces, and a few more; each of them isolating a certain
amount of system resources from an application.

What do we mean by **system resources**?  In Linux, system resources are
available globally by all applications on the system.  The most notable example
of this is probably your operating system clock, but there are many other areas
as well, such as the list of all processes, the file system, and the list of
users.

Namespaces *containerize* a certain part of an application from the rest of the
operating system; this is exactly what Docker uses in order to provide its
isolation primitives.

### Tor + Namespaces = ❤️

As outlined above, namespaces are a powerful feature that gives us the ability
to isolate Tor network access of an arbitrary application.  We put each
application in a network namespace that doesn't provide access to system-wide
network interfaces (such as `eth0`), and instead provides a custom network
interface `onion0`.

This allows us to isolate an arbitrary application over Tor in the most secure
way possible software-wise, namely by relying on a security primitive offered by
the operating system kernel.  Unlike SOCKS, the application cannot accidentally
leak data by failing to make some connection via the configured SOCKS, which may
happen due to a mistake by the developer.[^ipc]

### `oniux` vs. `torsocks`

You may have also heard of a tool with a similar goal, known as `torsocks`,
which works by overwriting all network-related libc functions in a way to route
traffic over a SOCKS proxy offered by Tor.  While this approach is a bit more
cross-platform, it has the notable downside that applications making system
calls not through a dynamically linked libc, either with malicious intent or
not, will leak data.  Most notably, this excludes support for purely static
binaries and applications from the Zig ecosystem.

The following provides a basic comparison on *oniux* vs. *torsocks*:
| _oniux_                           | _torsocks_                                                                  |
|-----------------------------------|-----------------------------------------------------------------------------|
| Standalone application            | Requires running Tor daemon                                                 |
| Uses Linux namespaces             | Uses an ld.so preload hack                                                  |
| Works on all applications         | Only works on applications making system calls through libc                 |
| Malicious application cannot leak | Malicious application can leak by making a system call through raw assembly |
| Linux only                        | Cross-platform                                                              |
| New and experimental              | Battle-proven for over 15 years                                             |
| Uses Arti as its engine           | Uses CTor as its engine                                                     |
| Written in Rust                   | Written in C                                                                |

### How does this work internally? 🧅

*oniux* works by immediately spawning a child process using the `clone(2)`
system call, which is isolated in its own network, mount, PID, and user
namespace.  This proces then mounts its own copy of `/proc` followed by UID and
GID mappings to the respective UID and GID of the parent process.

Afterwards, it creates a temporary file with nameserver entries which will then
be bind mounted onto `/etc/resolv.conf`, so that applications running within
will use a custom name resolver that supports resolving through Tor.

Next, the child process utilizes `onionmasq` to create a TUN interface named
`onion0` followed by some `rtnetlink(7)` operations required to set up the
interface, such as assigning IP addresses.

Then, the child process sends the file descriptor of the TUN interface over a
Unix Domain socket to the parent process, who has been waiting for this message
ever since executing the initial `clone(2)`.

Once that is done, the child process drops all of its capabilities which were
acquired as part of being the root process in the user namespace.

Finally, the command supplied by the user is executed using facilities provided
by the Rust standard library.

### oniux is experimental ⚠️

Although this section should not discourage you from using *oniux*, you should
keep in mind that this is a relatively new feature which uses new Tor software,
such as *arti* and *onionmasq*.

While things are already working as expected at the moment, tools such as
*torsocks* have been around for over 15 years, giving them more experience to
the battlefield.

But we do want to reach a similar state with oniux, so please go ahead and check
it out.

## Credits

Many thanks to the developers of [`smoltcp`](https://github.com/smoltcp-rs),
which is a Rust crate that implements a full IP stack in Rust, something we make
heavy use of.

Also many thanks go to `7ppKb5bW`, who taught us on how this can implemented
without the use of `capabilities(7)` by using `user_namespaces(7)` properly.

[^ipc]: Although *oniux* makes it harder for an application to leak traffic, it
    is not fully immune to this.  A notable exception to this are applications
    that do networking over IPC to processes running outside the oniux
    container.  The most notable example of this is starting a Chromium instance
    outside of *oniux* and then running `oniux chromium`, in which case the
    *oniux* spawned window will leak, as it will use the networking process of
    the already existing instance of Chromium.
