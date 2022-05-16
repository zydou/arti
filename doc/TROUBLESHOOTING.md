# Fixing some common (and not-so-common) problems

Here's an infrequently-asked-questions list about fixing some common (and
not-so-common) issues in your Arti compilation or usage.

If you run into a problem that isn't on this list, please let us know on
[our bugtracker](../README.md#reporting-bugs).

## Compilation issues

### When I try to build Arti, linking fails!

Arti uses your system's sqlite3 and TLS libraries. Make sure that you have
development libraries for sqlite3 installed.  You might also need to install
the development libraries for OpenSSL, if you aren't on Windows or OSX.
You may also need to install `pkg-config`.

#### In more detail...

We use sqlite3 via the `rusqlite` crate.  Our TLS implementation is the
`native_tls` crate, which relies on `security-framework` (on OSX),
`schannel` (on Windows), or `openssl` (elsewhere).

Both of these crates, by default, access their dependencies via
`pkg-config` or `vpkg` as appropriate.  But you can override this
behavior if you run into trouble:

  * You can build `arti` or `arti-client` with the `static` feature, and
    the underlying crates will be told to build their own dependencies
    from source and link statically.

  * For more information on building `rusqlite` in different
    environments, see [this section of their README](https://github.com/rusqlite/rusqlite#notes-on-building-rusqlite-and-libsqlite3-sys).

  * For more information on building the `openssl` crate in different
    environments, see the
    ["building" section](https://docs.rs/openssl/latest/openssl/#building)
    of their documentation.


### I get a weird segfault on startup on Alpine Linux!

If you're seeing this kind of error from inside the native_tls crate

```
arti[62370]: segfault at 0 ip 0000000000000000 sp 00007fff9fa01128 error 14
```

then you might be hitting a
[known issue](https://githubmemory.com/repo/sfackler/rust-native-tls/issues/190)
on native_tls on Alpine linux.

You can solve this by building with `RUSTFLAGS=-Ctarget-feature=-crt-static`.

### I get an error about "configuring both an async runtime and a TLS stack" when building Arti!

If you're getting

```
error: You must configure both an async runtime and a TLS stack. See doc/TROUBLESHOOTING.md for more.
```

...then the combination of [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html) (`--features`) you
you configured while compiling Arti doesn't specify both an asynchronous runtime *and* a TLS stack to use.

You must choose:

- at least one asynchronous runtime (features `tokio`, `async-std`)
  - (if you choose both, `tokio` will be used)
- at least one TLS stack (features `native-tls`, `rustls`)
  - (if you choose both, `native-tls` will be used)

Pass these in with the `--features` argument when compiling (e.g. `--features tokio,native-tls`).

Note that Arti configures Tokio and native-tls by default, so if you're gettnig this error, you probably tried to do
something fancy with `--no-default-features`.

### Arti isn't respecting my custom runtime choice!

Make sure you're building just the Arti binary, and not the whole workspace; to do this, you'll need to specify `-p arti`
when invoking Cargo, e.g.

    $ cargo build -p arti --no-default-features --features async-std,native-tls

You can verify which runtime is being used by passing `--version` to Arti, e.g.

    $ target/release/arti --version
