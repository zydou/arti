# Fixing some common (and not-so-common) problems

Here's an infrequently-asked-questions list about fixing some common (and
not-so-common) issues in your Arti compilation or usage

## Compilation issues

### When I try to build Arti, linking fails!

Arti uses your system's sqlite3 and TLS libraries. Make sure that you have
development libraries for sqlite3 installed.  You might also need to install
the development libraries for OpenSSL, if you aren't on Windows or OSX.

### I get a weird segfault on startup on Alpine Linux!

If you're seeing this kind of error from inside the native_tls crate

```
arti[62370]: segfault at 0 ip 0000000000000000 sp 00007fff9fa01128 error 14
```

then you might be hitting a
[known issue](https://githubmemory.com/repo/sfackler/rust-native-tls/issues/190)
on native_tls on Alpine linux.

You can solve this by building with `RUSTFLAGS=-Ctarget-feature=-crt-static`.
