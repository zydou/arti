---
title: Compiling for iOS
---

# Compiling Arti for iOS

## Limitations
At the moment of writing this guide, Arti does not have a stable Rust API yet. For that reason, no proper bindings are provided. You'll need to write these bindings yourself by leveraging Rust FFI for C.

There are also rough edges, which will hopefully get polished over time. Most of these should be explained below.

This guide assumes you already have installed Cargo and XCode (but not that you used both together).

Apple requires to have MacOS installed to develop iOS apps, this guide won't work for Linux, Windows or other BSDs.

Finally, these guidelines are correct as far as we know, but they haven't been tested by many people. If you find any problems in them, please let us know!

## Installing the requirements

First install targets so Rust know how to compile to iOS

```sh
$ rustup target add aarch64-apple-ios \
	aarch64-apple-ios-sim \
	x86_64-apple-ios
```

## Configuring a Rust project

To create a new project in the directory you're in, run the command:

```sh
$ cargo init <project-name> --lib
```

You'll then need to add some content to the `Cargo.toml`.

First add the subcrates of arti you want to use to the `[dependencies]` section. You'll have to add `features=["static"]` to crates that support this feature (at the moment `tor-rtcompat`, `tor-dirmgr` and `arti-client`). Otherwise they will fail either to compile or to run.

Other dependencies, such as futures, can be included if needed, but they are not technically required.

Next, specify what kind of `lib` it is. By default, it's a Rust `lib` that can only be used in the rust ecosystem. To make it a static library:

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

After setting up your code, initiate the compilation process by executing this command. The compilation time may vary depending on the size of your project.

```sh
 ## build for 64bit iPhone/iPad (32bit is no longer supported since iOS 11)
$ cargo build --target aarch64-apple-ios
 ## build for M1 based Mac (emulator)
$ cargo build --target aarch64-apple-ios-sim
 ## build for x86 based Mac (emulator)
$ cargo build --target x86_64-apple-ios
```

You can add `--release` to each of this commands to build release libs that
are faster, but take longer to compile.
You can use `--profile=release-small` to prioritize size over speed.

## The Swift part

After setting up your [Rust project](#configuring-a-rust-project), you'll need to create a Swift project. Adjust your project's `build` settings and configure the Objective-C bridging header to point to the path of your C header file. This will add the native library and its header into your project. 

Close Xcode, then open your `project.pbxproj` file in a text editor. Navigate to the `LD_RUNPATH_SEARCH_PATHS` entry, which should appear twice, once under the "Debug" section and again under the "Release" section.

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

You are now able to invoke your Rust functions from Swift just like regular functions. Dealing with types might be a bit challenging; for instance, strings are transformed into `char*` at the FFI interface. In Swift, they are treated as `Optional<UnsafeMutablePointer<CChar>>`, requiring unwrapping and conversion before use. Additionally, remember to free such a pointer by passing it back to Rust and dropping the value there. Aside from these considerations, these functions should work almost like any other.

You can now build your application, and test it in an emulator or on your device. If you have any problems, check the [debugging](#debugging-and-stability) section below.

## Tips and caveats

The sample project [arti-mobile-example](https://gitlab.torproject.org/trinity-1686a/arti-mobile-example/) is a simple app that serves as a demo for compiling iOS apps with Arti. Additionally, it incorporates the majority of the provided tips below.

## Generating C headers from Rust code

Instead of writing C headers manually and hopping to not make mistakes, you can generate them automatically using `cbindgen`. To install it, run:

```sh
$ cargo install cbindgen
```

Then use `cbindgen` to generate the headers, after putting all functions you want to export in a single Rust file.

```sh
$ cbindgen src/lib.rs -l c > arti-mobile.h
```

### Debugging and stability
Arti logs events to help debugging. By default these logs are not available on iOS. You can make Arti export its logs to OSLog by adding a couple dependencies and writing a bit of code:

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

Take great care about your rust code not unwinding into Swift Runtime; if it does, it will crash your app with no error message to help you. If your code can panic, you should use `catch_unwind` to capture it before it reaches Swift.

## Async and Swift

Arti relies a lot on Rust futures. The easiest way to use these futures from Swift is to block on futures if you are okay with it. Otherwise you have to pass callbacks from Swift to Rust, and make sure they are called when the future completes.

Eventually, Arti will provide a set of blocking APIs for use for embedding. To help design these APIs, check out our [contributing guide](/contributing/).
