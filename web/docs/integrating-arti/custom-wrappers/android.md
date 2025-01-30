---
title: Compiling for Android
---

# Compiling Arti for Android

## Limitations
At the moment of writing this guide, Arti does not have a stable Rust API yet. For that reason, no proper bindings are provided.
You'll need to write these bindings yourself using the Java Native Interface. (If this doesn't sound like something you can do, you might be better off waiting until Arti is more stable.)

There are also rough edges, which will hopefully get polished over time. Most of these should be explained below.

This guide assumes you already have installed Cargo and Android Studio (but not that you used both together).

Finally, these guidelines are correct as far as we know, but they haven't been tested by many people. If you find any problems using them, please let us know!

## Installing the requirements

First you'll need to install targets so Rust knows how to compile to Android.

```sh
$ rustup target install armv7-linux-androideabi \
	aarch64-linux-android \
	i686-linux-android \
	x86_64-linux-android
```

You'll also need to get a NDK (you can skip this step if you already have one installed). As of now, NDK 23 is not supported yet.
You can download the NDK 22 [here](https://github.com/android/ndk/wiki/Unsupported-Downloads).

Choose the right NDK for your platform, unzip the archive and set the environment variable `NDK_HOME` to point to your newly installed NDK (you'll need to adjust the path to match your setup).

```sh
$ export NDK_HOME=/<path/to/where/you/unzipped>/android-ndk-r22b/
```

Install cargo-ndk. It's not technically required, but it make things easier.

```sh
$ cargo install cargo-ndk
```

## Configuring a Rust project

To create a new project in the directory you're in, run the command:

```sh
$ cargo init <project-name> --lib
```

Now, add some content to the `Cargo.toml`.

To set up the `Cargo.toml` add the subcrates of arti you want to use to the `[dependencies]` section. You will have to add `features=["static"]` to crates that support this feature (at the moment `tor-rtcompat`, `tor-dirmgr` and `arti-client`). Otherwise they will fail either to compile or to run.

You'll also need to add `jni`, to allow Rust and the Java in your app to work together.

```toml
jni = { version = "0.19", default-features = false }
```

Other dependencies, such as futures, can be included if needed, but they are not technically required.

Next, specify what kind of `lib` it is. By default, it's a Rust `lib` that can only be used in the rust ecosystem. To make it a dynamic library:

```toml
[lib]
crate-type = ["dylib"]
```

You are good to start programming in `src/lib.rs`.

To make your functions available to Java, you need to set certain modifiers on them, and to name them with a special convention. You should be familiar with this if you used the `JNI` before. If not, it's time to learn how to use it.

```rust
// defined the method "myMethod" on class "MyClass" in package "net.example"
#[no_mangle]
pub extern "C" fn Java_net_example_MyClass_myMethod( /* parameters omitted */ ) {..}
```

After setting up your code, initiate the compilation process by executing this command. The compilation time may vary depending on the size of your project.

```sh
 ## build for 32bit and 64bit, x86 (emulator) and arm (most devices).
$ cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 -o ./jniLibs build
 ## build for 64bit arm only (recent devices).
$ cargo ndk -t arm64-v8a -o ./jniLibs build
```

## The Java part

Note: You can also use Kotlin. The syntax is slightly different, but the following instructions should work either way.

After setting up your [Rust project](#configuring-a-rust-project), you'll need to create an Android project. Once you have done this, run the following command to copy your native library inside the Android project (or use a symlink).

```sh
$ cp -r path/to/rust/project/jniLibs path/to/android/project/app/src/main
```

If your application does not already require it, you have to request the permission to access Internet in your `AndroidManifest.xml`

```xml
    <uses-permission android:name="android.permission.INTERNET" />
```

Implement the class referred to in your Rust code along with the method it overrides, ensuring that the method is annotated as "native." Next, include a static block that loads the native library using the command:

```java
package org.example

class MyClass {
    native void myMethod();
    static {
        System.loadLibrary("<name of the rust project>");
    }
}
```

You can now build your application, and test it in an emulator or on your device. If you have any problems, check the [debugging](#debugging-and-stability) section below.

## Tips and caveats

The sample project [arti-mobile-example](https://gitlab.torproject.org/trinity-1686a/arti-mobile-example/) is a simple app that serves as a demo for compiling Android apps with Arti. Additionally, it incorporates the majority of the provided tips below.

### Platform support
By default, Arti runs only on Android 7.0 and above. Versions under Android 7.0 will get a runtime exception due to a missing symbol. If you want to support Android 5.0 and above, it is possible to implement `lockf` yourself, as it is a rather simple `libc` function.

It might be possible to support even lower Android version by implementing more of these methods (at least create\_epoll1). This has not been explored, as it seems to be harder, and with less possible gain.

An implementation of `lockf` is part of the sample project linked above. (It's a Rust translation of Musl implementation of this function.)

### Debugging and stability
Arti logs events to help debugging. By default these logs are not available on Android. You can make Arti export its logs to logcat by adding a couple dependencies and writing a bit of code:

```toml
# in [dependencies] in Cargo.toml
tracing-subscriber = "0.2.20"
tracing-android = "0.1.3"
```

```rust
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::prelude::*;

Subscriber::new()
  .with(tracing_android::layer("rust.arti")?)
  .init(); // this must be called only once, otherwise your app will probably crash
```

Take great care about your rust code not unwinding into Java Runtime; if it does, it will crash your app with no error message to help you.
If your code can panic, you should use `catch_unwind` to capture it before it reaches the Java Runtime.

### Async and Java
Arti relies a lot on Rust futures. The easiest way to use these futures from Java is to block on futures if you are okay with it. Otherwise you have to pass callbacks from Java to Rust, and make sure they are called when the future completes.

Eventually, Arti will provide a set of blocking APIs for use for embedding. To help design these APIs, check out our [contributing guide](/contributing/).
