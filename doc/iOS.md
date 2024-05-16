# Compiling Arti for iOS

## Limitation
At the moment of writing this guide, Arti does not have a stable Rust API yet. For that reason, no proper bindings are provided.
You'll need to write these bindings yourself by leveraging Rust FFI for C.

There are also rough edges, which will hopefully get polished over time. Most of these should be explained below.

This guide assumes you already have installed Cargo and XCode (but not that you used both together).

Apple requires to have MacOS installed to develop iOS apps, this guide won't work for Linux, Windows or other BSDs.

Finally: These guidelines are correct as far as we know, but they haven't
been tested by many people. If you find any problems in them, please let us
know!

## Installing the requirements

First install targets so Rust know how to compile to iOS
```sh
$ rustup target add aarch64-apple-ios \
	aarch64-apple-ios-sim \
	x86_64-apple-ios
```

## Configuring a Rust project

To create a new project in the directory you're in. You can do:
```sh
$ cargo init <project-name> --lib
```

You'll then need to add some content to the Cargo.toml.

First add the subcrates of arti you want to use to the `[dependencies]` section. You'll have to add `features=["static"]` to crates that support this feature
(at the moment tor-rtcompat, tor-dirmgr and arti-client): otherwise they will fail either to compile or to run.

You'll probably want to add some other dependencies, like futures, but these are not technically requirements.

You'll also need to specify what kind of lib this is. By default, it's a Rust lib that can only be used in the rust ecosystem.
We want it to be a static library:
```toml
[lib]
name = "arti_mobile"
crate-type = ["staticlib"]
```

You are good to start programming in `src/lib.rs`.
To make your functions available to Swift, you need to set certain modifiers on them.
```rust
// defined the function my_function which will be exported without mangling its name, as a C-compatible function.
#[no_mangle]
pub extern "C" fn my_function( /* parameters omitted */ ) {..}
```

You also need to add these functions to a C header file which will be imported later in XCode.
```C
// You'll probably need to import stdbool, stdint and stdlib for the type definitions they contain

void my_function(void);
```

There exist a tool to build this header file for you, see in `Tips and caveats` below.

Once you are satisfied with your code, you can compile it by running these commands. (This is a good time to take a coffee break)
```sh
 ## build for 64bit iPhone/iPad (32bit is no longer supported since iOS 11)
$ cargo build --locked --target aarch64-apple-ios
 ## build for M1 based Mac (emulator)
$ cargo build --locked --target aarch64-apple-ios-sim
 ## build for x86 based Mac (emulator)
$ cargo build --locked --target x86_64-apple-ios
```

You can add `--release` to each of this commands to build release libs that are smaller and faster, but take longer to compile.

## The Swift part

I'll assume you already have a project setup. This can be a brand new project, or an already existing one.

First you'll need to add the native library and its header to your project.

Open your project settings Go in Build Settings and search Objective-C Bridging Header. Set it to the path
to your C header file.

Now close XCode, and open your project.pbxproj in a text editor. Jump to `LD_RUNPATH_SEARCH_PATHS`. You 
should find it two times, in a section named Debug and an other named Release.

In the Debug section, after `LD_RUNPATH_SEARCH_PATHS`, add the following:
```
"LIBRARY_SEARCH_PATHS[sdk=iphoneos*][arch=arm64]" = (
	"$(inherited)",
	"../<path_to_rust_project>/target/aarch64-apple-ios/debug",
);
"LIBRARY_SEARCH_PATHS[sdk=iphonesimulator*][arch=arm64]" = (
	"$(inherited)",
	"../<path_to_rust_project>/target/aarch64-apple-ios-sim/debug",
);
"LIBRARY_SEARCH_PATHS[sdk=iphonesimulator*][arch=x86_64]" = (
	"$(inherited)",
	"../<path_to_rust_project>/target/x86_64-apple-ios/debug",
);
OTHER_LDFLAGS = (
	"$(inherited)",
	"-larti_mobile", /* replace arti-mobile with what you put as name in [lib] in Cargo.toml */
);
```

In the Release section, add the same block, but replace `debug` at the end of each path with `release`.

Now you can start calling your Rust functions from Swift like normal functions. Types are a bit difficult to
work with, strings get transformed into char\* at the FFI interface, and Swift consider them as 
`Optional<UnsafeMutablePointer<CChar>>` which need unwrapping and conversion before being used. You also
need to free such a pointer by passing it back to Rust and dropping the value there. Otherwise these
functions should work almost as any other.

You can now build your application, and test it in an emulator or on your device. Hopefully it should work.

## Tips and caveats

You can find a sample project to build a very basic app using Arti [here](https://gitlab.torproject.org/trinity-1686a/arti-mobile-example/).
It does not respect most good practices of app development, but should otherwise be a good starting point.

## Generating C headers from Rust code
Instead of writing C headers manually and hopping to not make mistakes, it's possible to generate them
automatically by using cbindgen. First install it.
```sh
$ cargo install cbindgen
```

Then use bindgen to generate the headers. You should put all functions you want to export in a single rust file.
```sh
$ cbindgen src/lib.rs -l c > arti-mobile.h
```

### Debugging and stability
Arti logs events to help debugging. By default these logs are not available on iOS.
You can make Arti export its logs to OSLog by adding a couple dependencies and writing a bit of code:

```toml
# in [dependencies] in Cargo.toml
tracing-subscriber = "0.3.3"
tracing-oslog = "0.1.2"
```

```rust
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::prelude::*;

Subscriber::new()
  .with(tracing_oslog::OsLogger::layer("rust.arti")?)
  .init(); // this must be called only once, otherwise your app will probably crash
```

You should take great care about your rust code not unwinding into Swift Runtime: If it does, it will crash your app with no error message to help you.
If your code can panic, you should use `catch_unwind` to capture it before it reaches Swift.

## Async and Swift
Arti relies a lot on Rust futures. There is no easy way to use these futures from Swift. The easiest ways is probably to block on futures
if you are okay with it. Otherwise you have to pass callbacks from Swift to Rust, and make so they are called when the future completes.

Eventually, Arti will provide a set of blocking APIs for use for embedding;
please get in touch if you want to help design them.
